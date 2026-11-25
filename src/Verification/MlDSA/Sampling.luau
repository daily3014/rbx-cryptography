--[=[
	ML-DSA Sampling
	
	Example usage:
		local Rho = buffer.create(32)
		local Matrix = buffer.create(4 * 4 * 256 * 4)
		Sampling.ExpandA(Rho, Matrix, 4, 4)
--]=]

--!strict
--!optimize 2
--!native

local XOF = require("../../Hashing/XOF")
local BitPack = require("./BitPack")
local Params = require("./Params")

local N = 256
local Q = 8380417
local POLY_SIZE = N * 4

local Sampling = {}

local WORKSPACE_MSG_34 = buffer.create(34)
local WORKSPACE_MSG_66 = buffer.create(66)

local EXPAND_A_CHUNK = buffer.create(172)
local EXPAND_A_OVERRUN = 224
local EXPAND_S_CHUNK = buffer.create(136)
local EXPAND_S_POLY = buffer.create(POLY_SIZE + 272 * 4)
local EXPAND_MASK_SQUEEZE = buffer.create(640)
local SAMPLE_BALL_TAU = buffer.create(8)
local SAMPLE_BALL_SQUEEZE = buffer.create(136)

local MATRIX_CACHE_RHO = buffer.create(32)
local MATRIX_CACHE_DIMENSIONS = 0
local MATRIX_CACHE_VALUE: buffer? = nil

local function SeedMatches(Cached: buffer, Rho: buffer, RhoOffset: number): boolean
	for Offset = 0, 28, 4 do
		if buffer.readu32(Cached, Offset) ~= buffer.readu32(Rho, RhoOffset + Offset) then
			return false
		end
	end

	return true
end

function Sampling.ExpandA(Rho: buffer, RhoOffset: number, K: number, L: number): buffer
	local Dimensions = K * 16 + L
	local Cached = MATRIX_CACHE_VALUE
	if Cached and MATRIX_CACHE_DIMENSIONS == Dimensions and SeedMatches(MATRIX_CACHE_RHO, Rho, RhoOffset) then
		return Cached
	end

	local Mat = buffer.create(K * L * POLY_SIZE + EXPAND_A_OVERRUN)
	local Message = WORKSPACE_MSG_34
	local Chunk = EXPAND_A_CHUNK
	local Modulus = Q
	buffer.copy(Message, 0, Rho, RhoOffset, 32)

	for I = 0, K - 1 do
		for J = 0, L - 1 do
			local Out = (I * L + J) * POLY_SIZE
			local Last = Out + POLY_SIZE

			buffer.writeu8(Message, 32, J)
			buffer.writeu8(Message, 33, I)
			XOF.Reset128()
			XOF.Absorb128(Message)

			while Out < Last do
				XOF.Squeeze128Into(Chunk, 168, 0)
				for Offset = 0, 144, 24 do
				do
					local Candidate = bit32.band(buffer.readu32(Chunk, Offset), 0x7FFFFF)
					buffer.writeu32(Mat, Out, Candidate)
					Out += bit32.rshift(Candidate - Modulus, 31) * 4
				end
				do
					local Candidate = bit32.band(buffer.readu32(Chunk, Offset + 3), 0x7FFFFF)
					buffer.writeu32(Mat, Out, Candidate)
					Out += bit32.rshift(Candidate - Modulus, 31) * 4
				end
				do
					local Candidate = bit32.band(buffer.readu32(Chunk, Offset + 6), 0x7FFFFF)
					buffer.writeu32(Mat, Out, Candidate)
					Out += bit32.rshift(Candidate - Modulus, 31) * 4
				end
				do
					local Candidate = bit32.band(buffer.readu32(Chunk, Offset + 9), 0x7FFFFF)
					buffer.writeu32(Mat, Out, Candidate)
					Out += bit32.rshift(Candidate - Modulus, 31) * 4
				end
				do
					local Candidate = bit32.band(buffer.readu32(Chunk, Offset + 12), 0x7FFFFF)
					buffer.writeu32(Mat, Out, Candidate)
					Out += bit32.rshift(Candidate - Modulus, 31) * 4
				end
				do
					local Candidate = bit32.band(buffer.readu32(Chunk, Offset + 15), 0x7FFFFF)
					buffer.writeu32(Mat, Out, Candidate)
					Out += bit32.rshift(Candidate - Modulus, 31) * 4
				end
				do
					local Candidate = bit32.band(buffer.readu32(Chunk, Offset + 18), 0x7FFFFF)
					buffer.writeu32(Mat, Out, Candidate)
					Out += bit32.rshift(Candidate - Modulus, 31) * 4
				end
				do
					local Candidate = bit32.band(buffer.readu32(Chunk, Offset + 21), 0x7FFFFF)
					buffer.writeu32(Mat, Out, Candidate)
					Out += bit32.rshift(Candidate - Modulus, 31) * 4
				end
				end
			end
		end
	end

	buffer.copy(MATRIX_CACHE_RHO, 0, Rho, RhoOffset, 32)
	MATRIX_CACHE_DIMENSIONS = Dimensions
	MATRIX_CACHE_VALUE = Mat

	return Mat
end

function Sampling.ExpandS(RhoPrime: buffer, RhoPrimeOffset: number, Vec: buffer, Eta: number, K: number, StartNonce: number)
	if not Params.CheckEta(Eta) or not Params.CheckNonce(StartNonce) then
		error("Invalid parameters for ExpandS")
	end

	local Message = WORKSPACE_MSG_66
	local Chunk = EXPAND_S_CHUNK
	local Poly = EXPAND_S_POLY
	local Modulus = Q
	buffer.copy(Message, 0, RhoPrime, RhoPrimeOffset, 64)

	for I = 0, K - 1 do
		buffer.writeu16(Message, 64, StartNonce + I)
		XOF.Reset256()
		XOF.Absorb256(Message)

		local Out = 0
		if Eta == 2 then
			while Out < POLY_SIZE do
				XOF.Squeeze256Into(Chunk, 136, 0)
				for Offset = 0, 132, 4 do
					local Word = buffer.readu32(Chunk, Offset)
					do
						local Nibble = bit32.band(Word, 15)
						local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
						local Remainder = Nibble - 5 * bit32.rshift(Times13, 6)
						local Value = 2 - Remainder
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 15, 31) * 4
					end
					do
						local Nibble = bit32.band(bit32.rshift(Word, 4), 15)
						local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
						local Remainder = Nibble - 5 * bit32.rshift(Times13, 6)
						local Value = 2 - Remainder
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 15, 31) * 4
					end
					do
						local Nibble = bit32.band(bit32.rshift(Word, 8), 15)
						local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
						local Remainder = Nibble - 5 * bit32.rshift(Times13, 6)
						local Value = 2 - Remainder
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 15, 31) * 4
					end
					do
						local Nibble = bit32.band(bit32.rshift(Word, 12), 15)
						local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
						local Remainder = Nibble - 5 * bit32.rshift(Times13, 6)
						local Value = 2 - Remainder
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 15, 31) * 4
					end
					do
						local Nibble = bit32.band(bit32.rshift(Word, 16), 15)
						local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
						local Remainder = Nibble - 5 * bit32.rshift(Times13, 6)
						local Value = 2 - Remainder
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 15, 31) * 4
					end
					do
						local Nibble = bit32.band(bit32.rshift(Word, 20), 15)
						local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
						local Remainder = Nibble - 5 * bit32.rshift(Times13, 6)
						local Value = 2 - Remainder
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 15, 31) * 4
					end
					do
						local Nibble = bit32.band(bit32.rshift(Word, 24), 15)
						local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
						local Remainder = Nibble - 5 * bit32.rshift(Times13, 6)
						local Value = 2 - Remainder
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 15, 31) * 4
					end
					do
						local Nibble = bit32.rshift(Word, 28)
						local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
						local Remainder = Nibble - 5 * bit32.rshift(Times13, 6)
						local Value = 2 - Remainder
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 15, 31) * 4
					end
				end
			end
		else
			while Out < POLY_SIZE do
				XOF.Squeeze256Into(Chunk, 136, 0)
				for Offset = 0, 132, 4 do
					local Word = buffer.readu32(Chunk, Offset)
					do
						local Nibble = bit32.band(Word, 15)
						local Value = 4 - Nibble
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 9, 31) * 4
					end
					do
						local Nibble = bit32.band(bit32.rshift(Word, 4), 15)
						local Value = 4 - Nibble
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 9, 31) * 4
					end
					do
						local Nibble = bit32.band(bit32.rshift(Word, 8), 15)
						local Value = 4 - Nibble
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 9, 31) * 4
					end
					do
						local Nibble = bit32.band(bit32.rshift(Word, 12), 15)
						local Value = 4 - Nibble
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 9, 31) * 4
					end
					do
						local Nibble = bit32.band(bit32.rshift(Word, 16), 15)
						local Value = 4 - Nibble
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 9, 31) * 4
					end
					do
						local Nibble = bit32.band(bit32.rshift(Word, 20), 15)
						local Value = 4 - Nibble
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 9, 31) * 4
					end
					do
						local Nibble = bit32.band(bit32.rshift(Word, 24), 15)
						local Value = 4 - Nibble
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 9, 31) * 4
					end
					do
						local Nibble = bit32.rshift(Word, 28)
						local Value = 4 - Nibble
						buffer.writeu32(Poly, Out, Value + bit32.band(Modulus, bit32.arshift(Value, 31)))
						Out += bit32.rshift(Nibble - 9, 31) * 4
					end
				end
			end
		end

		buffer.copy(Vec, I * POLY_SIZE, Poly, 0, POLY_SIZE)
	end
end

function Sampling.ExpandMask(Seed: buffer, Nonce: number, Vec: buffer, Gamma1: number, L: number)
	if not Params.CheckGamma1(Gamma1) then
		error("Invalid Gamma1 parameter")
	end

	local Bits = if Gamma1 == 131072 then 18 else 20
	local SqueezeBytes = N * Bits / 8
	local Message = WORKSPACE_MSG_66
	local Squeeze = EXPAND_MASK_SQUEEZE
	buffer.copy(Message, 0, Seed, 0, 64)

	for I = 0, L - 1 do
		buffer.writeu16(Message, 64, Nonce + I)
		XOF.Reset256()
		XOF.Absorb256(Message)
		XOF.Squeeze256Into(Squeeze, SqueezeBytes, 0)
		BitPack.DecodeCentered(Squeeze, 0, N, Gamma1, Bits, Vec, I * POLY_SIZE)
	end
end

function Sampling.SampleInBall(Seed: buffer, Poly: buffer, Tau: number)
	if not Params.CheckTau(Tau) then
		error("Invalid Tau parameter")
	end

	buffer.fill(Poly, 0, 0, N * 4)

	XOF.Reset256()
	XOF.Absorb256(Seed)

	XOF.Squeeze256Into(SAMPLE_BALL_TAU, 8, 0)
	local TauBitsLow = buffer.readu32(SAMPLE_BALL_TAU, 0)
	local TauBitsHigh = buffer.readu32(SAMPLE_BALL_TAU, 4)

	local From = N - Tau
	local I = From
	local ChunkSize = 136
	local Modulus = Q
	local Squeeze = SAMPLE_BALL_SQUEEZE

	while I < N do
		XOF.Squeeze256Into(Squeeze, ChunkSize, 0)
		local RandomBytes = Squeeze
		local ByteOffset = 0
		local OutputLen = ChunkSize

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