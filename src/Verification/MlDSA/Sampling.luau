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
	local XOF = XOF

	for I = 0, K - 1 do
		for J = 0, L - 1 do
			local Offset = (I * L + J) * Num * 4

			buffer.writeu8(Message, 32, J)
			buffer.writeu8(Message, 33, I)

			XOF.Reset128()
			XOF.Absorb128(Message)

			local CoeffCount = 0
			local ChunkSize = 504

			while CoeffCount < Num do
				local TotalOutput = XOF.Squeeze128(ChunkSize)
				local ByteOffset = 0
				local OutputLen = buffer.len(TotalOutput)

				while CoeffCount < Num and ByteOffset + 5 < OutputLen do
					local Chunk = buffer.readu32(TotalOutput, ByteOffset)
					local B3 = buffer.readu8(TotalOutput, ByteOffset + 4)
					local B4 = buffer.readu8(TotalOutput, ByteOffset + 5)

					local T3 = bit32.band(Chunk, 0x7FFFFF)
					if T3 < Modulus then
						buffer.writeu32(Mat, Offset + CoeffCount * 4, T3)
						CoeffCount += 1
					end

					local T4 = bit32.bor(
						bit32.rshift(Chunk, 24),
						bit32.lshift(B3, 8),
						bit32.lshift(bit32.band(B4, 0x7F), 16)
					)
					if T4 < Modulus and CoeffCount < Num then
						buffer.writeu32(Mat, Offset + CoeffCount * 4, T4)
						CoeffCount += 1
					end

					ByteOffset += 6
				end

				while CoeffCount < Num and ByteOffset + 2 < OutputLen do
					local T0 = bit32.band(buffer.readu8(TotalOutput, ByteOffset + 2), 0x7F)
					local T1 = buffer.readu8(TotalOutput, ByteOffset + 1)
					local T2 = buffer.readu8(TotalOutput, ByteOffset)

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

		XOF.Reset256()
		XOF.Absorb256(Message)

		local CoeffCount = 0
		local ChunkSize = if Eta == 2 then 136 else 272

		while CoeffCount < Num do
			local TotalOutput = XOF.Squeeze256(ChunkSize)
			local ByteOffset = 0
			local OutputLen = buffer.len(TotalOutput)

			if Eta == 2 then
				while CoeffCount < Num and ByteOffset + 3 < OutputLen do
					local Chunk = buffer.readu32(TotalOutput, ByteOffset)

					local T0 = bit32.band(Chunk, 0x0F)
					local T1 = bit32.band(bit32.rshift(Chunk, 4), 0x0F)
					local T2 = bit32.band(bit32.rshift(Chunk, 8), 0x0F)
					local T3 = bit32.band(bit32.rshift(Chunk, 12), 0x0F)
					local T4 = bit32.band(bit32.rshift(Chunk, 16), 0x0F)
					local T5 = bit32.band(bit32.rshift(Chunk, 20), 0x0F)
					local T6 = bit32.band(bit32.rshift(Chunk, 24), 0x0F)
					local T7 = bit32.band(bit32.rshift(Chunk, 28), 0x0F)

					if T0 < 15 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 2 - (T0 % 5) + (if (T0 % 5) > 2 then Modulus else 0))
						CoeffCount += 1
					end
					if T1 < 15 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 2 - (T1 % 5) + (if (T1 % 5) > 2 then Modulus else 0))
						CoeffCount += 1
					end
					if T2 < 15 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 2 - (T2 % 5) + (if (T2 % 5) > 2 then Modulus else 0))
						CoeffCount += 1
					end
					if T3 < 15 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 2 - (T3 % 5) + (if (T3 % 5) > 2 then Modulus else 0))
						CoeffCount += 1
					end
					if T4 < 15 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 2 - (T4 % 5) + (if (T4 % 5) > 2 then Modulus else 0))
						CoeffCount += 1
					end
					if T5 < 15 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 2 - (T5 % 5) + (if (T5 % 5) > 2 then Modulus else 0))
						CoeffCount += 1
					end
					if T6 < 15 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 2 - (T6 % 5) + (if (T6 % 5) > 2 then Modulus else 0))
						CoeffCount += 1
					end
					if T7 < 15 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 2 - (T7 % 5) + (if (T7 % 5) > 2 then Modulus else 0))
						CoeffCount += 1
					end

					ByteOffset += 4
				end
			else
				while CoeffCount < Num and ByteOffset + 3 < OutputLen do
					local Chunk = buffer.readu32(TotalOutput, ByteOffset)

					local T0 = bit32.band(Chunk, 0x0F)
					local T1 = bit32.band(bit32.rshift(Chunk, 4), 0x0F)
					local T2 = bit32.band(bit32.rshift(Chunk, 8), 0x0F)
					local T3 = bit32.band(bit32.rshift(Chunk, 12), 0x0F)
					local T4 = bit32.band(bit32.rshift(Chunk, 16), 0x0F)
					local T5 = bit32.band(bit32.rshift(Chunk, 20), 0x0F)
					local T6 = bit32.band(bit32.rshift(Chunk, 24), 0x0F)
					local T7 = bit32.band(bit32.rshift(Chunk, 28), 0x0F)

					if T0 < 9 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 4 - T0 + (if T0 > 4 then Modulus else 0))
						CoeffCount += 1
					end
					if T1 < 9 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 4 - T1 + (if T1 > 4 then Modulus else 0))
						CoeffCount += 1
					end
					if T2 < 9 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 4 - T2 + (if T2 > 4 then Modulus else 0))
						CoeffCount += 1
					end
					if T3 < 9 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 4 - T3 + (if T3 > 4 then Modulus else 0))
						CoeffCount += 1
					end
					if T4 < 9 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 4 - T4 + (if T4 > 4 then Modulus else 0))
						CoeffCount += 1
					end
					if T5 < 9 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 4 - T5 + (if T5 > 4 then Modulus else 0))
						CoeffCount += 1
					end
					if T6 < 9 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 4 - T6 + (if T6 > 4 then Modulus else 0))
						CoeffCount += 1
					end
					if T7 < 9 and CoeffCount < Num then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 4 - T7 + (if T7 > 4 then Modulus else 0))
						CoeffCount += 1
					end

					ByteOffset += 4
				end
			end

			while CoeffCount < Num and ByteOffset < OutputLen do
				local Byte = buffer.readu8(TotalOutput, ByteOffset)
				local T0 = bit32.band(Byte, 0x0F)
				local T1 = bit32.band(bit32.rshift(Byte, 4), 0x0F)

				if Eta == 2 then
					if T0 < 15 then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 2 - (T0 % 5) + (if (T0 % 5) > 2 then Modulus else 0))
						CoeffCount += 1
					end
					if CoeffCount < Num and T1 < 15 then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 2 - (T1 % 5) + (if (T1 % 5) > 2 then Modulus else 0))
						CoeffCount += 1
					end
				else
					if T0 < 9 then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 4 - T0 + (if T0 > 4 then Modulus else 0))
						CoeffCount += 1
					end
					if CoeffCount < Num and T1 < 9 then
						buffer.writeu32(Vec, Offset + CoeffCount * 4, 4 - T1 + (if T1 > 4 then Modulus else 0))
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

	local Gamma1BitWidth = if Gamma1 == 131072 then 18 else 20
	local BufSize = math.floor((N * Gamma1BitWidth) / 8)

	buffer.copy(WORKSPACE_MSG_66, 0, Seed, 0, 64)

	local Message = WORKSPACE_MSG_66
	local Num = N
	local Modulus = Q
	local G1 = Gamma1

	for I = 0, L - 1 do
		local Offset = I * Num * 4
		local NewNonce = Nonce + I

		buffer.writeu8(Message, 64, bit32.band(NewNonce, 0xFF))
		buffer.writeu8(Message, 65, bit32.band(bit32.rshift(NewNonce, 8), 0xFF))

		XOF.Reset256()
		XOF.Absorb256(Message)

		local Src = XOF.Squeeze256(BufSize)

		if Gamma1BitWidth == 18 then
			for J = 0, 63 do
				local BOffset = J * 9
				local POffset = Offset + J * 16

				local B0 = buffer.readu8(Src, BOffset + 0)
				local B1 = buffer.readu8(Src, BOffset + 1)
				local B2 = buffer.readu8(Src, BOffset + 2)
				local B3 = buffer.readu8(Src, BOffset + 3)
				local B4 = buffer.readu8(Src, BOffset + 4)
				local B5 = buffer.readu8(Src, BOffset + 5)
				local B6 = buffer.readu8(Src, BOffset + 6)
				local B7 = buffer.readu8(Src, BOffset + 7)
				local B8 = buffer.readu8(Src, BOffset + 8)

				local V0 = bit32.bor(B0, bit32.lshift(B1, 8), bit32.lshift(bit32.band(B2, 0x3), 16))
				local V1 = bit32.bor(bit32.rshift(B2, 2), bit32.lshift(B3, 6), bit32.lshift(bit32.band(B4, 0xF), 14))
				local V2 = bit32.bor(bit32.rshift(B4, 4), bit32.lshift(B5, 4), bit32.lshift(bit32.band(B6, 0x3F), 12))
				local V3 = bit32.bor(bit32.rshift(B6, 6), bit32.lshift(B7, 2), bit32.lshift(B8, 10))

				local D0 = G1 - V0
				local D1 = G1 - V1
				local D2 = G1 - V2
				local D3 = G1 - V3

				buffer.writeu32(Vec, POffset + 0, if D0 < 0 then D0 + Modulus else D0)
				buffer.writeu32(Vec, POffset + 4, if D1 < 0 then D1 + Modulus else D1)
				buffer.writeu32(Vec, POffset + 8, if D2 < 0 then D2 + Modulus else D2)
				buffer.writeu32(Vec, POffset + 12, if D3 < 0 then D3 + Modulus else D3)
			end
		else
			for J = 0, 63 do
				local BOffset = J * 10
				local POffset = Offset + J * 16

				local B0 = buffer.readu8(Src, BOffset + 0)
				local B1 = buffer.readu8(Src, BOffset + 1)
				local B2 = buffer.readu8(Src, BOffset + 2)
				local B3 = buffer.readu8(Src, BOffset + 3)
				local B4 = buffer.readu8(Src, BOffset + 4)
				local B5 = buffer.readu8(Src, BOffset + 5)
				local B6 = buffer.readu8(Src, BOffset + 6)
				local B7 = buffer.readu8(Src, BOffset + 7)
				local B8 = buffer.readu8(Src, BOffset + 8)
				local B9 = buffer.readu8(Src, BOffset + 9)

				local V0 = bit32.bor(B0, bit32.lshift(B1, 8), bit32.lshift(bit32.band(B2, 0xF), 16))
				local V1 = bit32.bor(bit32.rshift(B2, 4), bit32.lshift(B3, 4), bit32.lshift(B4, 12))
				local V2 = bit32.bor(B5, bit32.lshift(B6, 8), bit32.lshift(bit32.band(B7, 0xF), 16))
				local V3 = bit32.bor(bit32.rshift(B7, 4), bit32.lshift(B8, 4), bit32.lshift(B9, 12))

				local D0 = G1 - V0
				local D1 = G1 - V1
				local D2 = G1 - V2
				local D3 = G1 - V3

				buffer.writeu32(Vec, POffset + 0, if D0 < 0 then D0 + Modulus else D0)
				buffer.writeu32(Vec, POffset + 4, if D1 < 0 then D1 + Modulus else D1)
				buffer.writeu32(Vec, POffset + 8, if D2 < 0 then D2 + Modulus else D2)
				buffer.writeu32(Vec, POffset + 12, if D3 < 0 then D3 + Modulus else D3)
			end
		end
	end
end

function Sampling.SampleInBall(Seed: buffer, Poly: buffer, Tau: number, Lambda: number)
	if not Params.CheckTau(Tau) then
		error("Invalid Tau parameter")
	end

	buffer.fill(Poly, 0, 0, N * 4)

	XOF.Reset256()
	XOF.Absorb256(Seed)

	local TauBits = XOF.Squeeze256(8)
	local TauBitsLow = buffer.readu32(TauBits, 0)
	local TauBitsHigh = buffer.readu32(TauBits, 4)

	local From = N - Tau
	local I = From
	local ChunkSize = 136
	local Modulus = Q

	while I < N do
		local RandomBytes = XOF.Squeeze256(ChunkSize)
		local ByteOffset = 0
		local OutputLen = buffer.len(RandomBytes)

		while I < N and ByteOffset + 3 < OutputLen do
			local Chunk = buffer.readu32(RandomBytes, ByteOffset)

			for B = 0, 3 do
				if I >= N then break end

				local J = bit32.band(bit32.rshift(Chunk, B * 8), 0xFF)

				if J <= I then
					local TauBit = I - From
					local S
					if TauBit < 32 then
						S = bit32.band(bit32.rshift(TauBitsLow, TauBit), 1)
					else
						S = bit32.band(bit32.rshift(TauBitsHigh, TauBit - 32), 1)
					end

					buffer.writeu32(Poly, I * 4, buffer.readu32(Poly, J * 4))
					buffer.writeu32(Poly, J * 4, if S == 0 then 1 else Modulus - 1)

					I += 1
				end
			end

			ByteOffset += 4
		end

		while I < N and ByteOffset < OutputLen do
			local J = buffer.readu8(RandomBytes, ByteOffset)

			if J <= I then
				local TauBit = I - From
				local S
				if TauBit < 32 then
					S = bit32.band(bit32.rshift(TauBitsLow, TauBit), 1)
				else
					S = bit32.band(bit32.rshift(TauBitsHigh, TauBit - 32), 1)
				end

				buffer.writeu32(Poly, I * 4, buffer.readu32(Poly, J * 4))
				buffer.writeu32(Poly, J * 4, if S == 0 then 1 else Modulus - 1)

				I += 1
			end

			ByteOffset += 1
		end
	end
end

return Sampling