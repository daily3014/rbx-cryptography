--[=[
	ML-KEM Sampling Module
	
	Polynomial sampling operations for ML-KEM.
	 Uniform sampling from Rq and centered binomial distribution sampling.
	
	Example usage:
		local Rho = buffer.create(32)
		local Matrix = Sampling.GenerateMatrix(3, Rho, false)
		
		local Sigma = buffer.create(32)
		local Vector = Sampling.GenerateVector(3, 2, Sigma, 0)
		
		local PrfOutput = buffer.create(128)
		local NoisePoly = Sampling.SamplePolyCbd(PrfOutput, 2)
--]=]

--!strict
--!optimize 2
--!native

local XOF = require("../../Hashing/XOF")

local LOG2N = 8
local N = 2^LOG2N
local POLY_SIZE = N * 2 

local Q = 13 * 256 + 1

local SAMPLE_NTT_CHUNK = buffer.create(172)
local SAMPLE_NTT_OVERRUN = 224
local GEN_MATRIX_XOF_INPUT = buffer.create(34)
local GEN_VECTOR_PRF_OUTPUT = buffer.create(192)
local GEN_VECTOR_PRF_INPUT = buffer.create(33)

local MATRIX_CACHE_RHO = { buffer.create(32), buffer.create(32) }
local MATRIX_CACHE_K = { 0, 0 }
local MATRIX_CACHE_VALUE = {} :: { buffer }

local function SamplePolyCbd2(Prf: buffer, Poly: buffer, BaseOffset: number)
	local Modulus = Q
	for In = 0, 124, 4 do
		local Word = buffer.readu32(Prf, In)
		local Counts = bit32.bor(bit32.band(Word, 0x55555555) + bit32.band(bit32.rshift(Word, 1), 0x55555555), 0)
		local Out = BaseOffset + In * 4
		do
			local Low = bit32.band(Counts, 3) - bit32.band(bit32.rshift(Counts, 2), 3)
			local High = bit32.band(bit32.rshift(Counts, 4), 3) - bit32.band(bit32.rshift(Counts, 6), 3)
			buffer.writeu32(Poly, Out, bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), bit32.lshift(High + bit32.band(Modulus, bit32.arshift(High, 31)), 16)))
		end
		do
			local Low = bit32.band(bit32.rshift(Counts, 8), 3) - bit32.band(bit32.rshift(Counts, 10), 3)
			local High = bit32.band(bit32.rshift(Counts, 12), 3) - bit32.band(bit32.rshift(Counts, 14), 3)
			buffer.writeu32(Poly, Out + 4, bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), bit32.lshift(High + bit32.band(Modulus, bit32.arshift(High, 31)), 16)))
		end
		do
			local Low = bit32.band(bit32.rshift(Counts, 16), 3) - bit32.band(bit32.rshift(Counts, 18), 3)
			local High = bit32.band(bit32.rshift(Counts, 20), 3) - bit32.band(bit32.rshift(Counts, 22), 3)
			buffer.writeu32(Poly, Out + 8, bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), bit32.lshift(High + bit32.band(Modulus, bit32.arshift(High, 31)), 16)))
		end
		do
			local Low = bit32.band(bit32.rshift(Counts, 24), 3) - bit32.band(bit32.rshift(Counts, 26), 3)
			local High = bit32.band(bit32.rshift(Counts, 28), 3) - bit32.band(bit32.rshift(Counts, 30), 3)
			buffer.writeu32(Poly, Out + 12, bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), bit32.lshift(High + bit32.band(Modulus, bit32.arshift(High, 31)), 16)))
		end
	end
end

local function SamplePolyCbd3(Prf: buffer, Poly: buffer, BaseOffset: number)
	local Modulus = Q
	for In = 0, 180, 12 do
		local W0 = buffer.readu32(Prf, In)
		local W1 = buffer.readu32(Prf, In + 4)
		local W2 = buffer.readu32(Prf, In + 8)
		local Out = BaseOffset + In * 8 / 3
		do
			local Bits = bit32.band(W0, 0xFFFFFF)
			local Counts = bit32.bor(bit32.bor(bit32.band(Bits, 0x249249) + bit32.band(bit32.rshift(Bits, 1), 0x249249), 0) + bit32.band(bit32.rshift(Bits, 2), 0x249249), 0)
			do
				local Low = bit32.band(Counts, 7) - bit32.band(bit32.rshift(Counts, 3), 7)
				local High = bit32.band(bit32.rshift(Counts, 6), 7) - bit32.band(bit32.rshift(Counts, 9), 7)
				buffer.writeu32(Poly, Out, bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), bit32.lshift(High + bit32.band(Modulus, bit32.arshift(High, 31)), 16)))
			end
			do
				local Low = bit32.band(bit32.rshift(Counts, 12), 7) - bit32.band(bit32.rshift(Counts, 15), 7)
				local High = bit32.band(bit32.rshift(Counts, 18), 7) - bit32.band(bit32.rshift(Counts, 21), 7)
				buffer.writeu32(Poly, Out + 4, bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), bit32.lshift(High + bit32.band(Modulus, bit32.arshift(High, 31)), 16)))
			end
		end
		do
			local Bits = bit32.bor(bit32.rshift(W0, 24), bit32.lshift(bit32.band(W1, 0xFFFF), 8))
			local Counts = bit32.bor(bit32.bor(bit32.band(Bits, 0x249249) + bit32.band(bit32.rshift(Bits, 1), 0x249249), 0) + bit32.band(bit32.rshift(Bits, 2), 0x249249), 0)
			do
				local Low = bit32.band(Counts, 7) - bit32.band(bit32.rshift(Counts, 3), 7)
				local High = bit32.band(bit32.rshift(Counts, 6), 7) - bit32.band(bit32.rshift(Counts, 9), 7)
				buffer.writeu32(Poly, Out + 8, bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), bit32.lshift(High + bit32.band(Modulus, bit32.arshift(High, 31)), 16)))
			end
			do
				local Low = bit32.band(bit32.rshift(Counts, 12), 7) - bit32.band(bit32.rshift(Counts, 15), 7)
				local High = bit32.band(bit32.rshift(Counts, 18), 7) - bit32.band(bit32.rshift(Counts, 21), 7)
				buffer.writeu32(Poly, Out + 12, bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), bit32.lshift(High + bit32.band(Modulus, bit32.arshift(High, 31)), 16)))
			end
		end
		do
			local Bits = bit32.bor(bit32.rshift(W1, 16), bit32.lshift(bit32.band(W2, 0xFF), 16))
			local Counts = bit32.bor(bit32.bor(bit32.band(Bits, 0x249249) + bit32.band(bit32.rshift(Bits, 1), 0x249249), 0) + bit32.band(bit32.rshift(Bits, 2), 0x249249), 0)
			do
				local Low = bit32.band(Counts, 7) - bit32.band(bit32.rshift(Counts, 3), 7)
				local High = bit32.band(bit32.rshift(Counts, 6), 7) - bit32.band(bit32.rshift(Counts, 9), 7)
				buffer.writeu32(Poly, Out + 16, bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), bit32.lshift(High + bit32.band(Modulus, bit32.arshift(High, 31)), 16)))
			end
			do
				local Low = bit32.band(bit32.rshift(Counts, 12), 7) - bit32.band(bit32.rshift(Counts, 15), 7)
				local High = bit32.band(bit32.rshift(Counts, 18), 7) - bit32.band(bit32.rshift(Counts, 21), 7)
				buffer.writeu32(Poly, Out + 20, bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), bit32.lshift(High + bit32.band(Modulus, bit32.arshift(High, 31)), 16)))
			end
		end
		do
			local Bits = bit32.rshift(W2, 8)
			local Counts = bit32.bor(bit32.bor(bit32.band(Bits, 0x249249) + bit32.band(bit32.rshift(Bits, 1), 0x249249), 0) + bit32.band(bit32.rshift(Bits, 2), 0x249249), 0)
			do
				local Low = bit32.band(Counts, 7) - bit32.band(bit32.rshift(Counts, 3), 7)
				local High = bit32.band(bit32.rshift(Counts, 6), 7) - bit32.band(bit32.rshift(Counts, 9), 7)
				buffer.writeu32(Poly, Out + 24, bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), bit32.lshift(High + bit32.band(Modulus, bit32.arshift(High, 31)), 16)))
			end
			do
				local Low = bit32.band(bit32.rshift(Counts, 12), 7) - bit32.band(bit32.rshift(Counts, 15), 7)
				local High = bit32.band(bit32.rshift(Counts, 18), 7) - bit32.band(bit32.rshift(Counts, 21), 7)
				buffer.writeu32(Poly, Out + 28, bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), bit32.lshift(High + bit32.band(Modulus, bit32.arshift(High, 31)), 16)))
			end
		end
	end
end

local function SampleNtt(XofInput: buffer, Poly: buffer, PolyBase: number)
	local LQ = Q
	local Chunk = SAMPLE_NTT_CHUNK
	local Out = PolyBase
	local Last = PolyBase + POLY_SIZE

	XOF.Reset128()
	XOF.Absorb128(XofInput)

	while Out < Last do
		XOF.Squeeze128Into(Chunk, 168, 0)
		for Offset = 0, 144, 24 do
			do
				local Word = buffer.readu32(Chunk, Offset)
				local D1 = bit32.band(Word, 0xFFF)
				local D2 = bit32.band(bit32.rshift(Word, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.rshift(D1 - LQ, 31) * 2
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.rshift(D2 - LQ, 31) * 2
			end
			do
				local Word = buffer.readu32(Chunk, Offset + 3)
				local D1 = bit32.band(Word, 0xFFF)
				local D2 = bit32.band(bit32.rshift(Word, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.rshift(D1 - LQ, 31) * 2
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.rshift(D2 - LQ, 31) * 2
			end
			do
				local Word = buffer.readu32(Chunk, Offset + 6)
				local D1 = bit32.band(Word, 0xFFF)
				local D2 = bit32.band(bit32.rshift(Word, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.rshift(D1 - LQ, 31) * 2
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.rshift(D2 - LQ, 31) * 2
			end
			do
				local Word = buffer.readu32(Chunk, Offset + 9)
				local D1 = bit32.band(Word, 0xFFF)
				local D2 = bit32.band(bit32.rshift(Word, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.rshift(D1 - LQ, 31) * 2
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.rshift(D2 - LQ, 31) * 2
			end
			do
				local Word = buffer.readu32(Chunk, Offset + 12)
				local D1 = bit32.band(Word, 0xFFF)
				local D2 = bit32.band(bit32.rshift(Word, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.rshift(D1 - LQ, 31) * 2
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.rshift(D2 - LQ, 31) * 2
			end
			do
				local Word = buffer.readu32(Chunk, Offset + 15)
				local D1 = bit32.band(Word, 0xFFF)
				local D2 = bit32.band(bit32.rshift(Word, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.rshift(D1 - LQ, 31) * 2
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.rshift(D2 - LQ, 31) * 2
			end
			do
				local Word = buffer.readu32(Chunk, Offset + 18)
				local D1 = bit32.band(Word, 0xFFF)
				local D2 = bit32.band(bit32.rshift(Word, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.rshift(D1 - LQ, 31) * 2
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.rshift(D2 - LQ, 31) * 2
			end
			do
				local Word = buffer.readu32(Chunk, Offset + 21)
				local D1 = bit32.band(Word, 0xFFF)
				local D2 = bit32.band(bit32.rshift(Word, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.rshift(D1 - LQ, 31) * 2
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.rshift(D2 - LQ, 31) * 2
			end
		end
	end
end

local Sampling = {}

local function SeedMatches(Cached: buffer, Rho: buffer, RhoOffset: number): boolean
	for Offset = 0, 28, 4 do
		if buffer.readu32(Cached, Offset) ~= buffer.readu32(Rho, RhoOffset + Offset) then
			return false
		end
	end

	return true
end

function Sampling.GenerateMatrix(K: number, Rho: buffer, RhoOffset: number, Transpose: boolean): buffer
	local Slot = if Transpose then 2 else 1
	local Cached = MATRIX_CACHE_VALUE[Slot]
	if Cached and MATRIX_CACHE_K[Slot] == K and SeedMatches(MATRIX_CACHE_RHO[Slot], Rho, RhoOffset) then
		return Cached
	end

	local Matrix = buffer.create(K * K * POLY_SIZE + SAMPLE_NTT_OVERRUN)
	local PolySize = POLY_SIZE
	local Other = 3 - Slot
	local OtherMatrix = MATRIX_CACHE_VALUE[Other]

	if OtherMatrix and MATRIX_CACHE_K[Other] == K and SeedMatches(MATRIX_CACHE_RHO[Other], Rho, RhoOffset) then
		for I = 0, K - 1 do
			for J = 0, K - 1 do
				buffer.copy(Matrix, (I * K + J) * PolySize, OtherMatrix, (J * K + I) * PolySize, PolySize)
			end
		end
	else
		local XofInput = GEN_MATRIX_XOF_INPUT
		local Sample = SampleNtt
		buffer.copy(XofInput, 0, Rho, RhoOffset, 32)

		for I = 0, K - 1 do
			for J = 0, K - 1 do
				if Transpose then
					buffer.writeu8(XofInput, 32, I)
					buffer.writeu8(XofInput, 33, J)
				else
					buffer.writeu8(XofInput, 32, J)
					buffer.writeu8(XofInput, 33, I)
				end

				Sample(XofInput, Matrix, (I * K + J) * PolySize)
			end
		end
	end

	buffer.copy(MATRIX_CACHE_RHO[Slot], 0, Rho, RhoOffset, 32)
	MATRIX_CACHE_K[Slot] = K
	MATRIX_CACHE_VALUE[Slot] = Matrix

	return Matrix
end

function Sampling.GenerateVector(K: number, Eta: number, Seed: buffer, SeedOffset: number, Nonce: number, Output: buffer)
	local PrfInput = GEN_VECTOR_PRF_INPUT
	local PrfOutput = GEN_VECTOR_PRF_OUTPUT
	buffer.copy(PrfInput, 0, Seed, SeedOffset, 32)

	local PolySize = POLY_SIZE
	local PrfLen = 64 * Eta

	for I = 0, K - 1 do
		buffer.writeu8(PrfInput, 32, Nonce + I)

		XOF.Reset256()
		XOF.Absorb256(PrfInput)
		XOF.Squeeze256Into(PrfOutput, PrfLen, 0)

		local Offset = I * PolySize
		if Eta == 2 then
			SamplePolyCbd2(PrfOutput, Output, Offset)
		else
			SamplePolyCbd3(PrfOutput, Output, Offset)
		end
	end
end

return Sampling
