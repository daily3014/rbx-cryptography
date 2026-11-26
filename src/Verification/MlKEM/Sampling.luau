--[=[
	ML-KEM Sampling Module

	Provides cryptographic sampling functions for ML-KEM:
	- SampleNtt: Rejection sampling for uniform polynomials in NTT domain
	- SamplePolyCbd: Centered binomial distribution sampling for noise polynomials
	- GenerateMatrix: Generates k x k matrix A from seed rho using SHAKE128
	- GenerateVector: Generates noise vector from seed using SHAKE256
--]=]

--!strict
--!optimize 2
--!native

local SHA3 = require("../../Hashing/SHA3")
local Permute = SHA3.Permute_Internal
local Extract = SHA3.Extract_Internal

local POLY_SIZE = 512
local Q = 3329

local STATE_A: buffer = buffer.create(100)
local STATE_B: buffer = buffer.create(100)
local SAMPLE_NTT_CHUNK: buffer = buffer.create(172)
local SAMPLE_NTT_OVERRUN = 224
local GEN_VECTOR_PRF_OUTPUT: buffer = buffer.create(192)

local MATRIX_CACHE_RHO: { buffer } = { buffer.create(32), buffer.create(32) }
local MATRIX_CACHE_K = { 0, 0 }
local MATRIX_CACHE_VALUE = {} :: { buffer }

local function InterleaveLane(Lo: number, Hi: number): (number, number)
	local T: number
	T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222)
	Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
	T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C)
	Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
	T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0)
	Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
	T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00)
	Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
	T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222)
	Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
	T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C)
	Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
	T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0)
	Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
	T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00)
	Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
	return bit32.bor(bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)),
		bit32.bor(bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
end

local function ZeroTailState(StateA: buffer, StateB: buffer)
	buffer.writef64(StateA, 20, 0)
	buffer.writef64(StateA, 28, 0)
	buffer.writef64(StateA, 36, 0)
	buffer.writef64(StateA, 44, 0)
	buffer.writef64(StateA, 52, 0)
	buffer.writef64(StateA, 60, 0)
	buffer.writef64(StateA, 68, 0)
	buffer.writef64(StateA, 76, 0)
	buffer.writef64(StateA, 84, 0)
	buffer.writef64(StateA, 92, 0)
	buffer.writef64(StateB, 20, 0)
	buffer.writef64(StateB, 28, 0)
	buffer.writef64(StateB, 36, 0)
	buffer.writef64(StateB, 44, 0)
	buffer.writef64(StateB, 52, 0)
	buffer.writef64(StateB, 60, 0)
	buffer.writef64(StateB, 68, 0)
	buffer.writef64(StateB, 76, 0)
	buffer.writef64(StateB, 84, 0)
	buffer.writef64(StateB, 92, 0)
end

local function SamplePolyCbd2(Prf: buffer, Poly: buffer, BaseOffset: number)
	local Modulus = Q
	for In = 0, 124, 4 do
		local Word = buffer.readu32(Prf, In)
		local Counts = bit32.bor(bit32.band(Word, 0x55555555) + bit32.band(bit32.rshift(Word, 1), 0x55555555), 0)
		local Out = BaseOffset + In * 4
		do
			local Low = bit32.bor(bit32.band(Counts, 3) - bit32.band(bit32.rshift(Counts, 2), 3), 0)
			local High = bit32.bor(bit32.band(bit32.rshift(Counts, 4), 3) - bit32.band(bit32.rshift(Counts, 6), 3), 0)
			buffer.writeu32(Poly, Out, bit32.bor(bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), 0), bit32.lshift(bit32.bor(High + bit32.band(Modulus, bit32.arshift(High, 31)), 0), 16)))
		end
		do
			local Low = bit32.bor(bit32.band(bit32.rshift(Counts, 8), 3) - bit32.band(bit32.rshift(Counts, 10), 3), 0)
			local High = bit32.bor(bit32.band(bit32.rshift(Counts, 12), 3) - bit32.band(bit32.rshift(Counts, 14), 3), 0)
			buffer.writeu32(Poly, Out + 4, bit32.bor(bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), 0), bit32.lshift(bit32.bor(High + bit32.band(Modulus, bit32.arshift(High, 31)), 0), 16)))
		end
		do
			local Low = bit32.bor(bit32.band(bit32.rshift(Counts, 16), 3) - bit32.band(bit32.rshift(Counts, 18), 3), 0)
			local High = bit32.bor(bit32.band(bit32.rshift(Counts, 20), 3) - bit32.band(bit32.rshift(Counts, 22), 3), 0)
			buffer.writeu32(Poly, Out + 8, bit32.bor(bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), 0), bit32.lshift(bit32.bor(High + bit32.band(Modulus, bit32.arshift(High, 31)), 0), 16)))
		end
		do
			local Low = bit32.bor(bit32.band(bit32.rshift(Counts, 24), 3) - bit32.band(bit32.rshift(Counts, 26), 3), 0)
			local High = bit32.bor(bit32.band(bit32.rshift(Counts, 28), 3) - bit32.band(bit32.rshift(Counts, 30), 3), 0)
			buffer.writeu32(Poly, Out + 12, bit32.bor(bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), 0), bit32.lshift(bit32.bor(High + bit32.band(Modulus, bit32.arshift(High, 31)), 0), 16)))
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
				local Low = bit32.bor(bit32.band(Counts, 7) - bit32.band(bit32.rshift(Counts, 3), 7), 0)
				local High = bit32.bor(bit32.band(bit32.rshift(Counts, 6), 7) - bit32.band(bit32.rshift(Counts, 9), 7), 0)
				buffer.writeu32(Poly, Out, bit32.bor(bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), 0), bit32.lshift(bit32.bor(High + bit32.band(Modulus, bit32.arshift(High, 31)), 0), 16)))
			end
			do
				local Low = bit32.bor(bit32.band(bit32.rshift(Counts, 12), 7) - bit32.band(bit32.rshift(Counts, 15), 7), 0)
				local High = bit32.bor(bit32.band(bit32.rshift(Counts, 18), 7) - bit32.band(bit32.rshift(Counts, 21), 7), 0)
				buffer.writeu32(Poly, Out + 4, bit32.bor(bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), 0), bit32.lshift(bit32.bor(High + bit32.band(Modulus, bit32.arshift(High, 31)), 0), 16)))
			end
		end
		do
			local Bits = bit32.bor(bit32.rshift(W0, 24), bit32.lshift(bit32.band(W1, 0xFFFF), 8))
			local Counts = bit32.bor(bit32.bor(bit32.band(Bits, 0x249249) + bit32.band(bit32.rshift(Bits, 1), 0x249249), 0) + bit32.band(bit32.rshift(Bits, 2), 0x249249), 0)
			do
				local Low = bit32.bor(bit32.band(Counts, 7) - bit32.band(bit32.rshift(Counts, 3), 7), 0)
				local High = bit32.bor(bit32.band(bit32.rshift(Counts, 6), 7) - bit32.band(bit32.rshift(Counts, 9), 7), 0)
				buffer.writeu32(Poly, Out + 8, bit32.bor(bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), 0), bit32.lshift(bit32.bor(High + bit32.band(Modulus, bit32.arshift(High, 31)), 0), 16)))
			end
			do
				local Low = bit32.bor(bit32.band(bit32.rshift(Counts, 12), 7) - bit32.band(bit32.rshift(Counts, 15), 7), 0)
				local High = bit32.bor(bit32.band(bit32.rshift(Counts, 18), 7) - bit32.band(bit32.rshift(Counts, 21), 7), 0)
				buffer.writeu32(Poly, Out + 12, bit32.bor(bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), 0), bit32.lshift(bit32.bor(High + bit32.band(Modulus, bit32.arshift(High, 31)), 0), 16)))
			end
		end
		do
			local Bits = bit32.bor(bit32.rshift(W1, 16), bit32.lshift(bit32.band(W2, 0xFF), 16))
			local Counts = bit32.bor(bit32.bor(bit32.band(Bits, 0x249249) + bit32.band(bit32.rshift(Bits, 1), 0x249249), 0) + bit32.band(bit32.rshift(Bits, 2), 0x249249), 0)
			do
				local Low = bit32.bor(bit32.band(Counts, 7) - bit32.band(bit32.rshift(Counts, 3), 7), 0)
				local High = bit32.bor(bit32.band(bit32.rshift(Counts, 6), 7) - bit32.band(bit32.rshift(Counts, 9), 7), 0)
				buffer.writeu32(Poly, Out + 16, bit32.bor(bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), 0), bit32.lshift(bit32.bor(High + bit32.band(Modulus, bit32.arshift(High, 31)), 0), 16)))
			end
			do
				local Low = bit32.bor(bit32.band(bit32.rshift(Counts, 12), 7) - bit32.band(bit32.rshift(Counts, 15), 7), 0)
				local High = bit32.bor(bit32.band(bit32.rshift(Counts, 18), 7) - bit32.band(bit32.rshift(Counts, 21), 7), 0)
				buffer.writeu32(Poly, Out + 20, bit32.bor(bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), 0), bit32.lshift(bit32.bor(High + bit32.band(Modulus, bit32.arshift(High, 31)), 0), 16)))
			end
		end
		do
			local Bits = bit32.rshift(W2, 8)
			local Counts = bit32.bor(bit32.bor(bit32.band(Bits, 0x249249) + bit32.band(bit32.rshift(Bits, 1), 0x249249), 0) + bit32.band(bit32.rshift(Bits, 2), 0x249249), 0)
			do
				local Low = bit32.bor(bit32.band(Counts, 7) - bit32.band(bit32.rshift(Counts, 3), 7), 0)
				local High = bit32.bor(bit32.band(bit32.rshift(Counts, 6), 7) - bit32.band(bit32.rshift(Counts, 9), 7), 0)
				buffer.writeu32(Poly, Out + 24, bit32.bor(bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), 0), bit32.lshift(bit32.bor(High + bit32.band(Modulus, bit32.arshift(High, 31)), 0), 16)))
			end
			do
				local Low = bit32.bor(bit32.band(bit32.rshift(Counts, 12), 7) - bit32.band(bit32.rshift(Counts, 15), 7), 0)
				local High = bit32.bor(bit32.band(bit32.rshift(Counts, 18), 7) - bit32.band(bit32.rshift(Counts, 21), 7), 0)
				buffer.writeu32(Poly, Out + 28, bit32.bor(bit32.bor(Low + bit32.band(Modulus, bit32.arshift(Low, 31)), 0), bit32.lshift(bit32.bor(High + bit32.band(Modulus, bit32.arshift(High, 31)), 0), 16)))
			end
		end
	end
end

local function SampleNttFromState(StateA: buffer, StateB: buffer, Poly: buffer, PolyBase: number)
	local LQ = Q
	local Chunk = SAMPLE_NTT_CHUNK
	local Out = PolyBase
	local Last = PolyBase + POLY_SIZE

	while true do
		Permute(StateA, StateB)
		Extract(StateA, StateB, Chunk, 0, 168)
		for Offset = 0, 144, 24 do
			do
				local W = buffer.readu32(Chunk, Offset)
				local D1, D2 = bit32.band(W, 0xFFF), bit32.band(bit32.rshift(W, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.lshift(bit32.rshift(D1 - LQ, 31), 1)
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.lshift(bit32.rshift(D2 - LQ, 31), 1)
			end
			do
				local W = buffer.readu32(Chunk, Offset + 3)
				local D1, D2 = bit32.band(W, 0xFFF), bit32.band(bit32.rshift(W, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.lshift(bit32.rshift(D1 - LQ, 31), 1)
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.lshift(bit32.rshift(D2 - LQ, 31), 1)
			end
			do
				local W = buffer.readu32(Chunk, Offset + 6)
				local D1, D2 = bit32.band(W, 0xFFF), bit32.band(bit32.rshift(W, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.lshift(bit32.rshift(D1 - LQ, 31), 1)
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.lshift(bit32.rshift(D2 - LQ, 31), 1)
			end
			do
				local W = buffer.readu32(Chunk, Offset + 9)
				local D1, D2 = bit32.band(W, 0xFFF), bit32.band(bit32.rshift(W, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.lshift(bit32.rshift(D1 - LQ, 31), 1)
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.lshift(bit32.rshift(D2 - LQ, 31), 1)
			end
			do
				local W = buffer.readu32(Chunk, Offset + 12)
				local D1, D2 = bit32.band(W, 0xFFF), bit32.band(bit32.rshift(W, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.lshift(bit32.rshift(D1 - LQ, 31), 1)
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.lshift(bit32.rshift(D2 - LQ, 31), 1)
			end
			do
				local W = buffer.readu32(Chunk, Offset + 15)
				local D1, D2 = bit32.band(W, 0xFFF), bit32.band(bit32.rshift(W, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.lshift(bit32.rshift(D1 - LQ, 31), 1)
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.lshift(bit32.rshift(D2 - LQ, 31), 1)
			end
			do
				local W = buffer.readu32(Chunk, Offset + 18)
				local D1, D2 = bit32.band(W, 0xFFF), bit32.band(bit32.rshift(W, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.lshift(bit32.rshift(D1 - LQ, 31), 1)
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.lshift(bit32.rshift(D2 - LQ, 31), 1)
			end
			do
				local W = buffer.readu32(Chunk, Offset + 21)
				local D1, D2 = bit32.band(W, 0xFFF), bit32.band(bit32.rshift(W, 12), 0xFFF)
				buffer.writeu16(Poly, Out, D1)
				Out += bit32.lshift(bit32.rshift(D1 - LQ, 31), 1)
				buffer.writeu16(Poly, Out, D2)
				Out += bit32.lshift(bit32.rshift(D2 - LQ, 31), 1)
			end
		end
		if Out >= Last then
			break
		end
	end
end

local Sampling = {}

local function SeedMatches(Cached: buffer, Rho: buffer, RhoOffset: number): boolean
	return buffer.readu32(Cached, 0) == buffer.readu32(Rho, RhoOffset)
		and buffer.readu32(Cached, 4) == buffer.readu32(Rho, RhoOffset + 4)
		and buffer.readu32(Cached, 8) == buffer.readu32(Rho, RhoOffset + 8)
		and buffer.readu32(Cached, 12) == buffer.readu32(Rho, RhoOffset + 12)
		and buffer.readu32(Cached, 16) == buffer.readu32(Rho, RhoOffset + 16)
		and buffer.readu32(Cached, 20) == buffer.readu32(Rho, RhoOffset + 20)
		and buffer.readu32(Cached, 24) == buffer.readu32(Rho, RhoOffset + 24)
		and buffer.readu32(Cached, 28) == buffer.readu32(Rho, RhoOffset + 28)
end

function Sampling.GenerateMatrix(K: number, Rho: buffer, RhoOffset: number, Transpose: boolean): buffer
	local Slot = if Transpose then 2 else 1
	local Cached = MATRIX_CACHE_VALUE[Slot]
	if Cached and MATRIX_CACHE_K[Slot] == K and SeedMatches(MATRIX_CACHE_RHO[Slot], Rho, RhoOffset) then
		return Cached
	end

	local PolySize = POLY_SIZE
	local Needed = K * K * PolySize + SAMPLE_NTT_OVERRUN
	local Matrix = if Cached and buffer.len(Cached) >= Needed then Cached else buffer.create(Needed)
	local Other = 3 - Slot
	local OtherMatrix = MATRIX_CACHE_VALUE[Other]

	if OtherMatrix and MATRIX_CACHE_K[Other] == K and SeedMatches(MATRIX_CACHE_RHO[Other], Rho, RhoOffset) then
		for I = 0, K - 1 do
			for J = 0, K - 1 do
				buffer.copy(Matrix, (I * K + J) * PolySize, OtherMatrix, (J * K + I) * PolySize, PolySize)
			end
		end
	else
		local StateA, StateB = STATE_A, STATE_B
		local RA0, RB0 = InterleaveLane(buffer.readu32(Rho, RhoOffset), buffer.readu32(Rho, RhoOffset + 4))
		local RA1, RB1 = InterleaveLane(buffer.readu32(Rho, RhoOffset + 8), buffer.readu32(Rho, RhoOffset + 12))
		local RA2, RB2 = InterleaveLane(buffer.readu32(Rho, RhoOffset + 16), buffer.readu32(Rho, RhoOffset + 20))
		local RA3, RB3 = InterleaveLane(buffer.readu32(Rho, RhoOffset + 24), buffer.readu32(Rho, RhoOffset + 28))

		for I = 0, K - 1 do
			for J = 0, K - 1 do
				local B0 = if Transpose then I else J
				local B1 = if Transpose then J else I
				local Lo = bit32.bor(B0, bit32.lshift(B1, 8), 0x1F0000)
				local T: number
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222)
				Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C)
				Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0)
				Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00)
				Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))

				buffer.writeu32(StateA, 0, RA0)
				buffer.writeu32(StateB, 0, RB0)
				buffer.writeu32(StateA, 4, RA1)
				buffer.writeu32(StateB, 4, RB1)
				buffer.writeu32(StateA, 8, RA2)
				buffer.writeu32(StateB, 8, RB2)
				buffer.writeu32(StateA, 12, RA3)
				buffer.writeu32(StateB, 12, RB3)
				buffer.writeu32(StateA, 16, bit32.band(Lo, 0xFFFF))
				buffer.writeu32(StateB, 16, bit32.rshift(Lo, 16))
				ZeroTailState(StateA, StateB)
				buffer.writeu32(StateB, 80, 0x80000000)

				SampleNttFromState(StateA, StateB, Matrix, (I * K + J) * PolySize)
			end
		end
	end

	local CacheRho = MATRIX_CACHE_RHO[Slot]
	buffer.writef64(CacheRho, 0, buffer.readf64(Rho, RhoOffset))
	buffer.writef64(CacheRho, 8, buffer.readf64(Rho, RhoOffset + 8))
	buffer.writef64(CacheRho, 16, buffer.readf64(Rho, RhoOffset + 16))
	buffer.writef64(CacheRho, 24, buffer.readf64(Rho, RhoOffset + 24))
	MATRIX_CACHE_K[Slot] = K
	MATRIX_CACHE_VALUE[Slot] = Matrix

	return Matrix
end

function Sampling.GenerateVector(K: number, Eta: number, Seed: buffer, SeedOffset: number, Nonce: number, Output: buffer): ()
	local StateA, StateB = STATE_A, STATE_B
	local PrfOutput = GEN_VECTOR_PRF_OUTPUT
	local PolySize = POLY_SIZE

	local RA0, RB0 = InterleaveLane(buffer.readu32(Seed, SeedOffset), buffer.readu32(Seed, SeedOffset + 4))
	local RA1, RB1 = InterleaveLane(buffer.readu32(Seed, SeedOffset + 8), buffer.readu32(Seed, SeedOffset + 12))
	local RA2, RB2 = InterleaveLane(buffer.readu32(Seed, SeedOffset + 16), buffer.readu32(Seed, SeedOffset + 20))
	local RA3, RB3 = InterleaveLane(buffer.readu32(Seed, SeedOffset + 24), buffer.readu32(Seed, SeedOffset + 28))

	for I = 0, K - 1 do
		local Lo = bit32.bor(Nonce + I, 0x1F00)
		local T: number
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222)
		Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C)
		Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0)
		Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00)
		Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))

		buffer.writeu32(StateA, 0, RA0)
		buffer.writeu32(StateB, 0, RB0)
		buffer.writeu32(StateA, 4, RA1)
		buffer.writeu32(StateB, 4, RB1)
		buffer.writeu32(StateA, 8, RA2)
		buffer.writeu32(StateB, 8, RB2)
		buffer.writeu32(StateA, 12, RA3)
		buffer.writeu32(StateB, 12, RB3)
		buffer.writeu32(StateA, 16, bit32.band(Lo, 0xFFFF))
		buffer.writeu32(StateB, 16, bit32.rshift(Lo, 16))
		ZeroTailState(StateA, StateB)
		buffer.writeu32(StateB, 64, 0x80000000)

		Permute(StateA, StateB)
		if Eta == 2 then
			Extract(StateA, StateB, PrfOutput, 0, 128)
			SamplePolyCbd2(PrfOutput, Output, I * PolySize)
		else
			Extract(StateA, StateB, PrfOutput, 0, 136)
			Permute(StateA, StateB)
			Extract(StateA, StateB, PrfOutput, 136, 56)
			SamplePolyCbd3(PrfOutput, Output, I * PolySize)
		end
	end
end

function Sampling.ClearCaches(): ()
	buffer.fill(STATE_A, 0, 0)
	buffer.fill(STATE_B, 0, 0)
	buffer.fill(SAMPLE_NTT_CHUNK, 0, 0)
	buffer.fill(GEN_VECTOR_PRF_OUTPUT, 0, 0)
	MATRIX_CACHE_K[1] = 0
	MATRIX_CACHE_K[2] = 0
end

return Sampling
