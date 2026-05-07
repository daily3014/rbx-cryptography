--[=[
	ML-KEM Sampling Module
	
	Polynomial sampling operations for ML-KEM.
	 Uniform sampling from Rq and centered binomial distribution sampling.
	
	Example usage:
		local Sampling = require(script.Sampling)
		
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

local PolyVec = require("./PolyVec")
local MlKemParams = require("./Params")
local SHA3 = require("./SHA3")
local XOF = require("./XOF")

local LOG2N = 8
local N = 2^LOG2N
local POLY_SIZE = N * 2 

local Q = 13 * 256 + 1

local SAMPLE_NTT_CHUNK = buffer.create(168)
local SAMPLE_NTT_POLY = buffer.create(N * 2)
local GEN_VECTOR_PRF_OUTPUT = buffer.create(192)
local GEN_VECTOR_PRF_INPUT = buffer.create(33)

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

local function SamplePolyCbd2(Prf: buffer, Poly: buffer, Offset: number?)
	local BaseOffset = Offset or 0
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

local function SamplePolyCbd3(Prf: buffer, Poly: buffer, Offset: number?)
	local BaseOffset = Offset or 0
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

local function SampleNtt(XofInput: buffer, Poly: buffer)
	local CoeffIndex = 0
	local Chunk = SAMPLE_NTT_CHUNK

	XOF.Reset128()
	XOF.Absorb128(XofInput)

	while CoeffIndex < N do
		XOF.Squeeze128Into(Chunk, 168, 0)
		local Offset = 0

		while Offset + 4 <= 168 and CoeffIndex < N do
			local Word = buffer.readu32(Chunk, Offset)
			local D1 = bit32.band(Word, 0xFFF)
			local D2 = bit32.band(bit32.rshift(Word, 12), 0xFFF)

			if D1 < Q then
				buffer.writeu16(Poly, CoeffIndex * 2, D1)
				CoeffIndex += 1
			end

			if D2 < Q and CoeffIndex < N then
				buffer.writeu16(Poly, CoeffIndex * 2, D2)
				CoeffIndex += 1
			end

			Offset += 3
		end

		while Offset + 2 < 168 and CoeffIndex < N do
			local B0 = buffer.readu8(Chunk, Offset)
			local B1 = buffer.readu8(Chunk, Offset + 1)
			local B2 = buffer.readu8(Chunk, Offset + 2)

			local D1 = bit32.bor(B0, bit32.lshift(bit32.band(B1, 0x0F), 8))
			local D2 = bit32.bor(bit32.rshift(B1, 4), bit32.lshift(B2, 4))

			if D1 < Q then
				buffer.writeu16(Poly, CoeffIndex * 2, D1)
				CoeffIndex += 1
			end

			if D2 < Q and CoeffIndex < N then
				buffer.writeu16(Poly, CoeffIndex * 2, D2)
				CoeffIndex += 1
			end

			Offset += 3
		end
	end
end

local Sampling = {}

function Sampling.GenerateMatrix(K: number, Rho: buffer, Transpose: boolean): buffer
	local Matrix = PolyVec.MatCreate(K, K)
	local XofInput = buffer.create(34)
	buffer.copy(XofInput, 0, Rho, 0, 32)

	local PolySize = POLY_SIZE
	local Poly = SAMPLE_NTT_POLY
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

			Sample(XofInput, Poly)
			local Index = (I * K + J) * PolySize
			buffer.copy(Matrix, Index, Poly, 0, PolySize)
		end
	end

	return Matrix
end

function Sampling.SamplePolyCbd(Prf: buffer, Eta: number): buffer
	local Poly = buffer.create(N * 2)

	if Eta == 2 then
		SamplePolyCbd2(Prf, Poly, 0)
	else
		SamplePolyCbd3(Prf, Poly, 0)
	end

	return Poly
end

function Sampling.GenerateVector(K: number, Eta: number, Sigma: buffer, Nonce: number): buffer
	local Vec = PolyVec.VecCreate(K)
	local PrfInput = GEN_VECTOR_PRF_INPUT
	local PrfOutput = GEN_VECTOR_PRF_OUTPUT
	buffer.copy(PrfInput, 0, Sigma, 0, 32)

	local PolySize = POLY_SIZE
	local PrfLen = 64 * Eta

	for I = 0, K - 1 do
		buffer.writeu8(PrfInput, 32, Nonce + I)

		XOF.Reset256()
		XOF.Absorb256(PrfInput)
		XOF.Squeeze256Into(PrfOutput, PrfLen, 0)

		local Offset = I * PolySize
		if Eta == 2 then
			SamplePolyCbd2(PrfOutput, Vec, Offset)
		else
			SamplePolyCbd3(PrfOutput, Vec, Offset)
		end
	end

	return Vec
end

function Sampling.GenerateNoisePoly(Eta: number, Sigma: buffer, Nonce: number): buffer
	if not MlKemParams.CheckEta(Eta) then
		error("Invalid eta parameter")
	end
	if buffer.len(Sigma) ~= 32 then
		error("Sigma must be 32 bytes")
	end

	local PrfInput = buffer.create(33)
	buffer.copy(PrfInput, 0, Sigma, 0, 32)
	buffer.writeu8(PrfInput, 32, Nonce)

	local PrfOutput = SHA3.SHAKE256(PrfInput, 64 * Eta)
	return Sampling.SamplePolyCbd(PrfOutput, Eta)
end

return Sampling