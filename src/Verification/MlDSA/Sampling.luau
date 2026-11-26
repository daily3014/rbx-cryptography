--[=[
	Cryptographic sampling functions for ML-DSA

	Implements ExpandA (matrix sampling), ExpandS (secret polynomial sampling),
	ExpandMask (masking vector sampling), and SampleInBall (challenge polynomial)
	directly over the Keccak permutation.

	Example usage:
		local A = Sampling.ExpandA(Rho, 0, 4, 4)
		Sampling.SampleInBall(Seed, 0, 32, Poly, 39)
--]=]

--!strict
--!optimize 2
--!native

local SHA3 = require("../../Hashing/SHA3")
local BitPack = require("./BitPack")
local Permute = SHA3.Permute_Internal
local Extract = SHA3.Extract_Internal

local N = 256
local Q = 8380417
local POLY_SIZE = N * 4

local STATE_A: buffer = buffer.create(100)
local STATE_B: buffer = buffer.create(100)
local SEED_A: buffer = buffer.create(32)
local SEED_B: buffer = buffer.create(32)
local EXPAND_A_CHUNK: buffer = buffer.create(172)
local EXPAND_A_OVERRUN = 224
local EXPAND_S_CHUNK: buffer = buffer.create(136)
local EXPAND_S_POLY: buffer = buffer.create(POLY_SIZE + 272 * 4)
local EXPAND_MASK_SQUEEZE: buffer = buffer.create(640)
local SAMPLE_BALL_SQUEEZE: buffer = buffer.create(136)

local MATRIX_CACHE_RHO: buffer = buffer.create(32)
local MATRIX_CACHE_DIMENSIONS = 0
local MATRIX_CACHE_VALUE: buffer? = nil

local function InterleaveSeed(Src: buffer, SrcOffset: number, Lanes: number, DstA: buffer, DstB: buffer): ()
	for Lane = 0, Lanes - 1 do
		local Lo = buffer.readu32(Src, SrcOffset + Lane * 8)
		local Hi = buffer.readu32(Src, SrcOffset + Lane * 8 + 4)
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
		buffer.writeu32(DstA, Lane * 4, bit32.bor(bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
		buffer.writeu32(DstB, Lane * 4, bit32.bor(bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
	end
end

local function ZeroTailFrom20(StateA: buffer, StateB: buffer): ()
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

local function ZeroTailFrom36(StateA: buffer, StateB: buffer): ()
	buffer.writef64(StateA, 36, 0)
	buffer.writef64(StateA, 44, 0)
	buffer.writef64(StateA, 52, 0)
	buffer.writef64(StateA, 60, 0)
	buffer.writef64(StateA, 68, 0)
	buffer.writef64(StateA, 76, 0)
	buffer.writef64(StateA, 84, 0)
	buffer.writef64(StateA, 92, 0)
	buffer.writef64(StateB, 36, 0)
	buffer.writef64(StateB, 44, 0)
	buffer.writef64(StateB, 52, 0)
	buffer.writef64(StateB, 60, 0)
	buffer.writef64(StateB, 68, 0)
	buffer.writef64(StateB, 76, 0)
	buffer.writef64(StateB, 84, 0)
	buffer.writef64(StateB, 92, 0)
end

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

local Sampling = {}

function Sampling.ExpandA(Rho: buffer, RhoOffset: number, K: number, L: number): buffer
	local Dimensions = K * 16 + L
	local Cached = MATRIX_CACHE_VALUE
	if Cached and MATRIX_CACHE_DIMENSIONS == Dimensions and SeedMatches(MATRIX_CACHE_RHO, Rho, RhoOffset) then
		return Cached
	end

	local Needed = K * L * POLY_SIZE + EXPAND_A_OVERRUN
	local Mat: buffer
	if Cached and buffer.len(Cached) >= Needed then
		Mat = Cached
	else
		Mat = buffer.create(Needed)
	end

	local StateA = STATE_A
	local StateB = STATE_B
	local SeedA = SEED_A
	local SeedB = SEED_B
	local Chunk = EXPAND_A_CHUNK
	local Modulus = Q

	InterleaveSeed(Rho, RhoOffset, 4, SeedA, SeedB)
	local RA0, RA1 = buffer.readu32(SeedA, 0), buffer.readu32(SeedA, 4)
	local RA2, RA3 = buffer.readu32(SeedA, 8), buffer.readu32(SeedA, 12)
	local RB0, RB1 = buffer.readu32(SeedB, 0), buffer.readu32(SeedB, 4)
	local RB2, RB3 = buffer.readu32(SeedB, 8), buffer.readu32(SeedB, 12)

	for I = 0, K - 1 do
		for J = 0, L - 1 do
			local Lo = bit32.bor(J, bit32.lshift(I, 8), 0x1F0000)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222)
			Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C)
			Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0)
			Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00)
			Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))

			buffer.writeu32(StateA, 0, RA0); buffer.writeu32(StateB, 0, RB0)
			buffer.writeu32(StateA, 4, RA1); buffer.writeu32(StateB, 4, RB1)
			buffer.writeu32(StateA, 8, RA2); buffer.writeu32(StateB, 8, RB2)
			buffer.writeu32(StateA, 12, RA3); buffer.writeu32(StateB, 12, RB3)
			buffer.writeu32(StateA, 16, bit32.band(Lo, 0xFFFF))
			buffer.writeu32(StateB, 16, bit32.rshift(Lo, 16))
			ZeroTailFrom20(StateA, StateB)
			buffer.writeu32(StateB, 80, 0x80000000)

			local Out = (I * L + J) * POLY_SIZE
			local Last = Out + POLY_SIZE
			while Out < Last do
				Permute(StateA, StateB)
				Extract(StateA, StateB, Chunk, 0, 168)
				for Offset = 0, 144, 24 do
					do
						local Candidate = bit32.band(buffer.readu32(Chunk, Offset), 0x7FFFFF)
						buffer.writeu32(Mat, Out, Candidate)
						Out += bit32.lshift(bit32.rshift(Candidate - Modulus, 31), 2)
					end
					do
						local Candidate = bit32.band(buffer.readu32(Chunk, Offset + 3), 0x7FFFFF)
						buffer.writeu32(Mat, Out, Candidate)
						Out += bit32.lshift(bit32.rshift(Candidate - Modulus, 31), 2)
					end
					do
						local Candidate = bit32.band(buffer.readu32(Chunk, Offset + 6), 0x7FFFFF)
						buffer.writeu32(Mat, Out, Candidate)
						Out += bit32.lshift(bit32.rshift(Candidate - Modulus, 31), 2)
					end
					do
						local Candidate = bit32.band(buffer.readu32(Chunk, Offset + 9), 0x7FFFFF)
						buffer.writeu32(Mat, Out, Candidate)
						Out += bit32.lshift(bit32.rshift(Candidate - Modulus, 31), 2)
					end
					do
						local Candidate = bit32.band(buffer.readu32(Chunk, Offset + 12), 0x7FFFFF)
						buffer.writeu32(Mat, Out, Candidate)
						Out += bit32.lshift(bit32.rshift(Candidate - Modulus, 31), 2)
					end
					do
						local Candidate = bit32.band(buffer.readu32(Chunk, Offset + 15), 0x7FFFFF)
						buffer.writeu32(Mat, Out, Candidate)
						Out += bit32.lshift(bit32.rshift(Candidate - Modulus, 31), 2)
					end
					do
						local Candidate = bit32.band(buffer.readu32(Chunk, Offset + 18), 0x7FFFFF)
						buffer.writeu32(Mat, Out, Candidate)
						Out += bit32.lshift(bit32.rshift(Candidate - Modulus, 31), 2)
					end
					do
						local Candidate = bit32.band(buffer.readu32(Chunk, Offset + 21), 0x7FFFFF)
						buffer.writeu32(Mat, Out, Candidate)
						Out += bit32.lshift(bit32.rshift(Candidate - Modulus, 31), 2)
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

local function SampleS2FromState(StateA: buffer, StateB: buffer, Chunk: buffer, Poly: buffer): ()
	local Modulus = Q
	local Out = 0
	while Out < POLY_SIZE do
		Permute(StateA, StateB)
		Extract(StateA, StateB, Chunk, 0, 136)
		for Offset = 0, 132, 4 do
			local Word = buffer.readu32(Chunk, Offset)
			do
				local Nibble = bit32.band(Word, 15)
				local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
				local Q5 = bit32.rshift(Times13, 6)
				local FiveQ = bit32.bor(bit32.lshift(Q5, 2) + Q5, 0)
				local Value = bit32.bor(bit32.bor(2 - Nibble, 0) + FiveQ, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 15, 31), 2)
			end
			do
				local Nibble = bit32.band(bit32.rshift(Word, 4), 15)
				local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
				local Q5 = bit32.rshift(Times13, 6)
				local FiveQ = bit32.bor(bit32.lshift(Q5, 2) + Q5, 0)
				local Value = bit32.bor(bit32.bor(2 - Nibble, 0) + FiveQ, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 15, 31), 2)
			end
			do
				local Nibble = bit32.band(bit32.rshift(Word, 8), 15)
				local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
				local Q5 = bit32.rshift(Times13, 6)
				local FiveQ = bit32.bor(bit32.lshift(Q5, 2) + Q5, 0)
				local Value = bit32.bor(bit32.bor(2 - Nibble, 0) + FiveQ, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 15, 31), 2)
			end
			do
				local Nibble = bit32.band(bit32.rshift(Word, 12), 15)
				local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
				local Q5 = bit32.rshift(Times13, 6)
				local FiveQ = bit32.bor(bit32.lshift(Q5, 2) + Q5, 0)
				local Value = bit32.bor(bit32.bor(2 - Nibble, 0) + FiveQ, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 15, 31), 2)
			end
			do
				local Nibble = bit32.band(bit32.rshift(Word, 16), 15)
				local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
				local Q5 = bit32.rshift(Times13, 6)
				local FiveQ = bit32.bor(bit32.lshift(Q5, 2) + Q5, 0)
				local Value = bit32.bor(bit32.bor(2 - Nibble, 0) + FiveQ, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 15, 31), 2)
			end
			do
				local Nibble = bit32.band(bit32.rshift(Word, 20), 15)
				local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
				local Q5 = bit32.rshift(Times13, 6)
				local FiveQ = bit32.bor(bit32.lshift(Q5, 2) + Q5, 0)
				local Value = bit32.bor(bit32.bor(2 - Nibble, 0) + FiveQ, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 15, 31), 2)
			end
			do
				local Nibble = bit32.band(bit32.rshift(Word, 24), 15)
				local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
				local Q5 = bit32.rshift(Times13, 6)
				local FiveQ = bit32.bor(bit32.lshift(Q5, 2) + Q5, 0)
				local Value = bit32.bor(bit32.bor(2 - Nibble, 0) + FiveQ, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 15, 31), 2)
			end
			do
				local Nibble = bit32.rshift(Word, 28)
				local Times13 = bit32.bor(bit32.bor(bit32.lshift(Nibble, 3) + bit32.lshift(Nibble, 2), 0) + Nibble, 0)
				local Q5 = bit32.rshift(Times13, 6)
				local FiveQ = bit32.bor(bit32.lshift(Q5, 2) + Q5, 0)
				local Value = bit32.bor(bit32.bor(2 - Nibble, 0) + FiveQ, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 15, 31), 2)
			end
		end
	end
end

local function SampleS4FromState(StateA: buffer, StateB: buffer, Chunk: buffer, Poly: buffer): ()
	local Modulus = Q
	local Out = 0
	while Out < POLY_SIZE do
		Permute(StateA, StateB)
		Extract(StateA, StateB, Chunk, 0, 136)
		for Offset = 0, 132, 4 do
			local Word = buffer.readu32(Chunk, Offset)
			do
				local Nibble = bit32.band(Word, 15)
				local Value = bit32.bor(4 - Nibble, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 9, 31), 2)
			end
			do
				local Nibble = bit32.band(bit32.rshift(Word, 4), 15)
				local Value = bit32.bor(4 - Nibble, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 9, 31), 2)
			end
			do
				local Nibble = bit32.band(bit32.rshift(Word, 8), 15)
				local Value = bit32.bor(4 - Nibble, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 9, 31), 2)
			end
			do
				local Nibble = bit32.band(bit32.rshift(Word, 12), 15)
				local Value = bit32.bor(4 - Nibble, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 9, 31), 2)
			end
			do
				local Nibble = bit32.band(bit32.rshift(Word, 16), 15)
				local Value = bit32.bor(4 - Nibble, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 9, 31), 2)
			end
			do
				local Nibble = bit32.band(bit32.rshift(Word, 20), 15)
				local Value = bit32.bor(4 - Nibble, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 9, 31), 2)
			end
			do
				local Nibble = bit32.band(bit32.rshift(Word, 24), 15)
				local Value = bit32.bor(4 - Nibble, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 9, 31), 2)
			end
			do
				local Nibble = bit32.rshift(Word, 28)
				local Value = bit32.bor(4 - Nibble, 0)
				buffer.writeu32(Poly, Out, bit32.bor(Value + bit32.band(Modulus, bit32.arshift(Value, 31)), 0))
				Out += bit32.lshift(bit32.rshift(Nibble - 9, 31), 2)
			end
		end
	end
end

local function InitSeed64State(SeedA: buffer, SeedB: buffer, StateA: buffer, StateB: buffer, Nonce: number): ()
	local Lo = bit32.bor(Nonce, 0x1F0000)
	local T: number
	T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222)
	Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
	T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C)
	Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
	T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0)
	Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
	T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00)
	Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))

	buffer.copy(StateA, 0, SeedA, 0, 32)
	buffer.copy(StateB, 0, SeedB, 0, 32)
	buffer.writeu32(StateA, 32, bit32.band(Lo, 0xFFFF))
	buffer.writeu32(StateB, 32, bit32.rshift(Lo, 16))
	ZeroTailFrom36(StateA, StateB)
	buffer.writeu32(StateB, 64, 0x80000000)
end

function Sampling.ExpandS(RhoPrime: buffer, RhoPrimeOffset: number, Vec: buffer, Eta: number, K: number, StartNonce: number): ()
	local StateA = STATE_A
	local StateB = STATE_B
	local SeedA = SEED_A
	local SeedB = SEED_B
	local Chunk = EXPAND_S_CHUNK
	local Poly = EXPAND_S_POLY

	InterleaveSeed(RhoPrime, RhoPrimeOffset, 8, SeedA, SeedB)
	for I = 0, K - 1 do
		InitSeed64State(SeedA, SeedB, StateA, StateB, StartNonce + I)
		if Eta == 2 then
			SampleS2FromState(StateA, StateB, Chunk, Poly)
		else
			SampleS4FromState(StateA, StateB, Chunk, Poly)
		end
		buffer.copy(Vec, I * POLY_SIZE, Poly, 0, POLY_SIZE)
	end
end

function Sampling.ExpandMask(Seed: buffer, Nonce: number, Vec: buffer, Gamma1: number, L: number): ()
	local Bits = if Gamma1 == 131072 then 18 else 20
	local TailBytes = if Gamma1 == 131072 then 32 else 96
	local StateA = STATE_A
	local StateB = STATE_B
	local SeedA = SEED_A
	local SeedB = SEED_B
	local Squeeze = EXPAND_MASK_SQUEEZE

	InterleaveSeed(Seed, 0, 8, SeedA, SeedB)
	for I = 0, L - 1 do
		InitSeed64State(SeedA, SeedB, StateA, StateB, Nonce + I)
		for OutOffset = 0, 408, 136 do
			Permute(StateA, StateB)
			Extract(StateA, StateB, Squeeze, OutOffset, 136)
		end
		Permute(StateA, StateB)
		Extract(StateA, StateB, Squeeze, 544, TailBytes)
		BitPack.DecodeCentered(Squeeze, 0, N, Gamma1, Bits, Vec, I * POLY_SIZE)
	end
end

function Sampling.SampleInBall(Seed: buffer, SeedOffset: number, SeedLength: number, Poly: buffer, Tau: number): ()
	buffer.fill(Poly, 0, 0, POLY_SIZE)

	local StateA = STATE_A
	local StateB = STATE_B
	local Lanes = SeedLength // 8
	InterleaveSeed(Seed, SeedOffset, Lanes, StateA, StateB)
	for Off = Lanes * 4, 96, 4 do
		buffer.writeu32(StateA, Off, 0)
		buffer.writeu32(StateB, Off, 0)
	end
	buffer.writeu32(StateA, Lanes * 4, 7)
	buffer.writeu32(StateB, Lanes * 4, 3)
	buffer.writeu32(StateB, 64, 0x80000000)

	local Squeeze = SAMPLE_BALL_SQUEEZE
	Permute(StateA, StateB)
	Extract(StateA, StateB, Squeeze, 0, 136)

	local TauBitsLow = buffer.readu32(Squeeze, 0)
	local TauBitsHigh = buffer.readu32(Squeeze, 4)
	local From = N - Tau
	local I = From
	local Modulus = Q
	local ByteOffset = 8

	while true do
		while I < N and ByteOffset < 136 do
			local Word = buffer.readu32(Squeeze, ByteOffset)
			for Shift = 0, 24, 8 do
				if I >= N then
					break
				end
				local J = bit32.band(bit32.rshift(Word, Shift), 0xFF)
				if J <= I then
					local TauBit = I - From
					local S = if TauBit < 32
						then bit32.band(bit32.rshift(TauBitsLow, TauBit), 1)
						else bit32.band(bit32.rshift(TauBitsHigh, TauBit - 32), 1)
					buffer.writeu32(Poly, I * 4, buffer.readu32(Poly, J * 4))
					buffer.writeu32(Poly, J * 4, if S == 0 then 1 else Modulus - 1)
					I += 1
				end
			end
			ByteOffset += 4
		end
		if I >= N then
			break
		end
		Permute(StateA, StateB)
		Extract(StateA, StateB, Squeeze, 0, 136)
		ByteOffset = 0
	end
end

function Sampling.ClearCaches(): ()
	buffer.fill(STATE_A, 0, 0)
	buffer.fill(STATE_B, 0, 0)
	buffer.fill(SEED_A, 0, 0)
	buffer.fill(SEED_B, 0, 0)
	buffer.fill(EXPAND_A_CHUNK, 0, 0)
	buffer.fill(EXPAND_S_CHUNK, 0, 0)
	buffer.fill(EXPAND_S_POLY, 0, 0)
	buffer.fill(EXPAND_MASK_SQUEEZE, 0, 0)
	buffer.fill(SAMPLE_BALL_SQUEEZE, 0, 0)
	buffer.fill(MATRIX_CACHE_RHO, 0, 0)
	MATRIX_CACHE_DIMENSIONS = 0
	MATRIX_CACHE_VALUE = nil
end

return Sampling
