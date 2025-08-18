--[=[
	Polynomial sampling routines for ML-DSA
	
	Deterministic sampling of matrices, secret vectors, masks, and challenge
	polynomials using SHAKE XOF functions.

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
local BitPacking = require("./Pack")
local Params = require("./Params")

local N = 256
local Q = 8380417

local Sampling = {}

function Sampling.ExpandA(Rho: buffer, Mat: buffer, K: number, L: number)
	local Msg = buffer.create(34)
	buffer.copy(Msg, 0, Rho, 0, 32)

	for I = 0, K - 1 do
		for J = 0, L - 1 do
			local Offset = (I * L + J) * N * 4

			buffer.writeu8(Msg, 32, J)
			buffer.writeu8(Msg, 33, I)

			local OutputSize = N * 3 * 2
			local TotalOutput = SHA3.SHAKE128(Msg, OutputSize)
			local CoeffCount = 0
			local ByteOffset = 0

			while CoeffCount < N do
				if ByteOffset + 2 >= buffer.len(TotalOutput) then
					OutputSize *= 2
					TotalOutput = SHA3.SHAKE128(Msg, OutputSize)
				end

				local T0 = bit32.band(buffer.readu8(TotalOutput, ByteOffset + 2), 0x7F)
				local T1 = buffer.readu8(TotalOutput, ByteOffset + 1)
				local T2 = buffer.readu8(TotalOutput, ByteOffset + 0)

				local T3 = bit32.bor(
					bit32.lshift(T0, 16),
					bit32.lshift(T1, 8),
					T2
				)

				if T3 < Q then
					buffer.writeu32(Mat, Offset + CoeffCount * 4, T3)
					CoeffCount += 1
				end

				ByteOffset += 3
			end
		end
	end
end

function Sampling.ExpandS(RhoPrime: buffer, Vec: buffer, Eta: number, K: number, StartNonce: number)
	if not Params.CheckEta(Eta) or not Params.CheckNonce(StartNonce) then
		error("Invalid parameters for ExpandS")
	end

	local Msg = buffer.create(66)
	buffer.copy(Msg, 0, RhoPrime, 0, 64)

	for I = 0, K - 1 do
		local Offset = I * N * 4
		local NewNonce = StartNonce + I

		buffer.writeu8(Msg, 64, bit32.band(NewNonce, 0xFF))
		buffer.writeu8(Msg, 65, bit32.band(bit32.rshift(NewNonce, 8), 0xFF))

		local OutputSize = if Eta == 2 then N * 2 else N * 3
		local TotalOutput = SHA3.SHAKE256(Msg, OutputSize)
		local CoeffCount = 0
		local ByteOffset = 0

		while CoeffCount < N do
			if ByteOffset >= buffer.len(TotalOutput) then
				OutputSize *= 2
				TotalOutput = SHA3.SHAKE256(Msg, OutputSize)
			end

			local Byte = buffer.readu8(TotalOutput, ByteOffset)
			local T0 = bit32.band(Byte, 0x0F)
			local T1 = bit32.band(bit32.rshift(Byte, 4), 0x0F)

			if Eta == 2 then
				if T0 < 15 then
					local T2 = T0 % 5
					local Value = if Eta >= T2 then Eta - T2 else Eta - T2 + Q
					buffer.writeu32(Vec, Offset + CoeffCount * 4, Value)
					CoeffCount += 1
				end

				if CoeffCount < N and T1 < 15 then
					local T3 = T1 % 5
					local Value = if Eta >= T3 then Eta - T3 else Eta - T3 + Q
					buffer.writeu32(Vec, Offset + CoeffCount * 4, Value)
					CoeffCount += 1
				end
			else 
				if T0 < 9 then
					local Value = if Eta >= T0 then Eta - T0 else Eta - T0 + Q
					buffer.writeu32(Vec, Offset + CoeffCount * 4, Value)
					CoeffCount += 1
				end

				if CoeffCount < N and T1 < 9 then
					local Value = if Eta >= T1 then Eta - T1 else Eta - T1 + Q
					buffer.writeu32(Vec, Offset + CoeffCount * 4, Value)
					CoeffCount += 1
				end
			end

			ByteOffset += 1
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
		Gamma1BitWidth = Gamma1BitWidth + 1
		TempGamma1 = bit32.rshift(TempGamma1, 1)
	end

	local Msg = buffer.create(66)
	local BufSize = math.floor((N * Gamma1BitWidth) / 8)

	buffer.copy(Msg, 0, Seed, 0, 64)

	for I = 0, L - 1 do
		local Offset = I * N * 4
		local NewNonce = Nonce + I

		buffer.writeu8(Msg, 64, bit32.band(NewNonce, 0xFF))
		buffer.writeu8(Msg, 65, bit32.band(bit32.rshift(NewNonce, 8), 0xFF))

		local ShakeOutput = SHA3.SHAKE256(Msg, BufSize)

		local PolyBuffer = buffer.create(N * 4)
		BitPacking.Decode(ShakeOutput, PolyBuffer, Gamma1BitWidth)

		for J = 0, N - 1 do
			local Value = buffer.readu32(PolyBuffer, J * 4)
			local Centered = if Gamma1 >= Value then Gamma1 - Value else Gamma1 - Value + Q
			
			buffer.writeu32(Vec, Offset + J * 4, Centered)
		end
	end
end

function Sampling.SampleInBall(Seed: buffer, Poly: buffer, Tau: number, Lambda: number)
	if not Params.CheckTau(Tau) then
		error("Invalid Tau parameter")
	end

	buffer.fill(Poly, 0, 0, N * 4)

	local TauBits = SHA3.SHAKE256(Seed, 8)

	local OutputSize = N * 2
	local RandomBytes = SHA3.SHAKE256(Seed, 8 + OutputSize)

	local From = N - Tau
	local I = From
	local ByteOffset = 8

	while I < N do
		if ByteOffset >= buffer.len(RandomBytes) then
			OutputSize *= 2
			RandomBytes = SHA3.SHAKE256(Seed, 8 + OutputSize)
		end

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
			local _PolyI = buffer.readu32(Poly, I * 4)
			local PolyJ = buffer.readu32(Poly, J * 4)

			buffer.writeu32(Poly, I * 4, PolyJ)

			local TwoS = S + S
			TwoS = if TwoS >= Q then TwoS - Q else TwoS

			local SignedValue = if 1 >= TwoS then 1 - TwoS else 1 - TwoS + Q
			buffer.writeu32(Poly, J * 4, SignedValue)

			I += 1
		end

		ByteOffset += 1
	end
end

return Sampling