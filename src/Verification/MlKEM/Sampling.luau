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

local CBD2_LUT = buffer.create(256 * 4) do
	for B = 0, 255 do
		local T0 = bit32.band(B, 0x55)
		local T1 = bit32.band(bit32.rshift(B, 1), 0x55)
		local T2 = T0 + T1

		local A0 = bit32.band(T2, 0x3)
		local Bm0 = bit32.band(bit32.rshift(T2, 2), 0x3)
		local A1 = bit32.band(bit32.rshift(T2, 4), 0x3)
		local Bm1 = bit32.band(bit32.rshift(T2, 6), 0x3)

		local C0 = (A0 - Bm0) % Q
		local C1 = (A1 - Bm1) % Q

		buffer.writeu32(CBD2_LUT, B * 4, C0 + bit32.lshift(C1, 16))
	end
end

local function SamplePolyCbd2(Prf: buffer, Poly: buffer, BaseOffset: number)
	local Lut = CBD2_LUT

	for I = 0, 127 do
		buffer.writeu32(Poly, BaseOffset + I * 4, buffer.readu32(Lut, buffer.readu8(Prf, I) * 4))
	end
end

local CBD3_LUT = buffer.create(4096 * 4) do
	local Mask = 0x249
	for V = 0, 4095 do
		local T3 = bit32.band(V, Mask) + bit32.band(bit32.rshift(V, 1), Mask) + bit32.band(bit32.rshift(V, 2), Mask)

		local A0 = bit32.band(T3, 0x7)
		local B0 = bit32.band(bit32.rshift(T3, 3), 0x7)
		local A1 = bit32.band(bit32.rshift(T3, 6), 0x7)
		local B1 = bit32.band(bit32.rshift(T3, 9), 0x7)

		local C0 = (A0 - B0) % Q
		local C1 = (A1 - B1) % Q

		buffer.writeu32(CBD3_LUT, V * 4, C0 + bit32.lshift(C1, 16))
	end
end

local function SamplePolyCbd3(Prf: buffer, Poly: buffer, BaseOffset: number)
	local Lut = CBD3_LUT

	for I = 0, 63 do
		local ByteOffset = I * 3
		local PolyOffset = BaseOffset + I * 8

		local B0 = buffer.readu8(Prf, ByteOffset)
		local B1 = buffer.readu8(Prf, ByteOffset + 1)
		local B2 = buffer.readu8(Prf, ByteOffset + 2)
		local Word = bit32.bor(B0, bit32.lshift(B1, 8), bit32.lshift(B2, 16))

		local Lo = bit32.band(Word, 0xFFF)
		local Hi = bit32.rshift(Word, 12)

		buffer.writeu32(Poly, PolyOffset, buffer.readu32(Lut, Lo * 4))
		buffer.writeu32(Poly, PolyOffset + 4, buffer.readu32(Lut, Hi * 4))
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
	local XofInput = GEN_MATRIX_XOF_INPUT
	buffer.copy(XofInput, 0, Rho, RhoOffset, 32)

	local PolySize = POLY_SIZE
	local Sample = SampleNtt

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
