--[=[
	ML-DSA Sampling
	
	Example usage:
		local Sampling = require(script)
		
		local Rho = buffer.create(32)
		local Matrix = buffer.create(4 * 4 * 256 * 4)
		Sampling.ExpandA(Rho, Matrix, 4, 4)
--]=]

--!strict
--!optimize 2
--!native

local SHA3 = require("./SHA3")
local XOF = require("./XOF")
local BitPacking = require("./Pack")
local Params = require("./Params")

local N = 256
local Q = 8380417

local Sampling = {}

local WORKSPACE_MSG_34 = buffer.create(34)
local WORKSPACE_MSG_66 = buffer.create(66)

function Sampling.ExpandA(Rho: buffer, Mat: buffer, K: number, L: number)
	buffer.copy(WORKSPACE_MSG_34, 0, Rho, 0, 32)
	
	local Message = WORKSPACE_MSG_34
	local Num = N
	local Modulus = Q
	
	for I = 0, K - 1 do
		for J = 0, L - 1 do
			local Offset = (I * L + J) * Num * 4

			buffer.writeu8(Message, 32, J)
			buffer.writeu8(Message, 33, I)

			local Xof = XOF.NewSHAKE128()
			Xof:Absorb(Message)
			Xof:Finalize()

			local CoeffCount = 0
			local ChunkSize = 504

			while CoeffCount < Num do
				local TotalOutput = Xof:Squeeze(ChunkSize)
				local ByteOffset = 0

				while CoeffCount < Num and ByteOffset + 2 < buffer.len(TotalOutput) do
					local T0 = bit32.band(buffer.readu8(TotalOutput, ByteOffset + 2), 0x7F)
					local T1 = buffer.readu8(TotalOutput, ByteOffset + 1)
					local T2 = buffer.readu8(TotalOutput, ByteOffset + 0)

					local T3 = bit32.bor(
						bit32.lshift(T0, 16),
						bit32.lshift(T1, 8),
						T2
					)

					if T3 < Modulus then
						buffer.writeu32(Mat, Offset + CoeffCount * 4, T3)
						CoeffCount += 1
					end

					ByteOffset += 3
				end
			end
		end
	end
end

function Sampling.ExpandS(RhoPrime: buffer, Vec: buffer, Eta: number, K: number, StartNonce: number)
	if not Params.CheckEta(Eta) or not Params.CheckNonce(StartNonce) then
		error("Invalid parameters for ExpandS")
	end

	buffer.copy(WORKSPACE_MSG_66, 0, RhoPrime, 0, 64)

	local Message = WORKSPACE_MSG_66
	local Num = N
	local Modulus = Q
	
	for I = 0, K - 1 do
		local Offset = I * Num * 4
		local NewNonce = StartNonce + I

		buffer.writeu8(Message, 64, bit32.band(NewNonce, 0xFF))
		buffer.writeu8(Message, 65, bit32.band(bit32.rshift(NewNonce, 8), 0xFF))

		local Xof = XOF.NewSHAKE256()
		Xof:Absorb(Message)
		Xof:Finalize()

		local CoeffCount = 0
		local ChunkSize = if Eta == 2 then 136 else 272

		while CoeffCount < Num do
			local TotalOutput = Xof:Squeeze(ChunkSize)
			local ByteOffset = 0

			while CoeffCount < Num and ByteOffset < buffer.len(TotalOutput) do
				local Byte = buffer.readu8(TotalOutput, ByteOffset)
				local T0 = bit32.band(Byte, 0x0F)
				local T1 = bit32.band(bit32.rshift(Byte, 4), 0x0F)

				if Eta == 2 then
					if T0 < 15 then
						local T2 = T0 % 5
						local Diff = Eta - T2
						local Value = if Diff < 0 then Diff + Modulus else Diff
						buffer.writeu32(Vec, Offset + CoeffCount * 4, Value)
						CoeffCount += 1
					end

					if CoeffCount < Num and T1 < 15 then
						local T3 = T1 % 5
						local Diff = Eta - T3
						local Value = if Diff < 0 then Diff + Modulus else Diff
						buffer.writeu32(Vec, Offset + CoeffCount * 4, Value)
						CoeffCount += 1
					end
				else 
					if T0 < 9 then
						local Diff = Eta - T0
						local Value = if Diff < 0 then Diff + Modulus else Diff
						buffer.writeu32(Vec, Offset + CoeffCount * 4, Value)
						CoeffCount += 1
					end

					if CoeffCount < Num and T1 < 9 then
						local Diff = Eta - T1
						local Value = if Diff < 0 then Diff + Modulus else Diff
						buffer.writeu32(Vec, Offset + CoeffCount * 4, Value)
						CoeffCount += 1
					end
				end

				ByteOffset += 1
			end
		end
	end
end

function Sampling.ExpandMask(Seed: buffer, Nonce: number, Vec: buffer, Gamma1: number, L: number)
	if not Params.CheckGamma1(Gamma1) then
		error("Invalid Gamma1 parameter")
	end

	local Gamma1BitWidth = 0
	local TempGamma1 = Gamma1
	while TempGamma1 > 0 do
		Gamma1BitWidth += 1
		TempGamma1 = bit32.rshift(TempGamma1, 1)
	end

	local BufSize = math.floor((N * Gamma1BitWidth) / 8)

	buffer.copy(WORKSPACE_MSG_66, 0, Seed, 0, 64)
	
	local Message = WORKSPACE_MSG_66
	local Num = N
	local Modulus = Q
	
	for I = 0, L - 1 do
		local Offset = I * Num * 4
		local NewNonce = Nonce + I

		buffer.writeu8(Message, 64, bit32.band(NewNonce, 0xFF))
		buffer.writeu8(Message, 65, bit32.band(bit32.rshift(NewNonce, 8), 0xFF))

		local Xof = XOF.NewSHAKE256()
		Xof:Absorb(Message)
		Xof:Finalize()

		local ShakeOutput = Xof:Squeeze(BufSize)

		local PolyBuffer = buffer.create(Num * 4)
		BitPacking.Decode(ShakeOutput, PolyBuffer, Gamma1BitWidth)

		for J = 0, Num - 1 do
			local Value = buffer.readu32(PolyBuffer, J * 4)
			local Diff = Gamma1 - Value
			local Centered = if Diff < 0 then Diff + Modulus else Diff

			buffer.writeu32(Vec, Offset + J * 4, Centered)
		end
	end
end

function Sampling.SampleInBall(Seed: buffer, Poly: buffer, Tau: number, Lambda: number)
	if not Params.CheckTau(Tau) then
		error("Invalid Tau parameter")
	end

	buffer.fill(Poly, 0, 0, N * 4)

	local Xof = XOF.NewSHAKE256()
	Xof:Absorb(Seed)
	Xof:Finalize()

	local TauBits = Xof:Squeeze(8)

	local From = N - Tau
	local I = From
	local ChunkSize = 136

	while I < N do
		local RandomBytes = Xof:Squeeze(ChunkSize)
		local ByteOffset = 0

		while I < N and ByteOffset < buffer.len(RandomBytes) do
			local TauBit = I - From
			local TauByteOffset = bit32.rshift(TauBit, 3)
			local TauBitOffset = bit32.band(TauBit, 7)

			local S = 0
			if TauByteOffset < 8 then
				S = bit32.band(
					bit32.rshift(buffer.readu8(TauBits, TauByteOffset), TauBitOffset),
					1
				)
			end

			local J = buffer.readu8(RandomBytes, ByteOffset)

			if J <= I then
				local PolyI = buffer.readu32(Poly, I * 4)
				local PolyJ = buffer.readu32(Poly, J * 4)

				buffer.writeu32(Poly, I * 4, PolyJ)

				local TwoS = S + S
				TwoS = if TwoS >= Q then TwoS - Q else TwoS

				local Diff = 1 - TwoS
				local SignedValue = if Diff < 0 then Diff + Q else Diff
				buffer.writeu32(Poly, J * 4, SignedValue)

				I += 1
			end

			ByteOffset += 1
		end
	end
end

return Sampling