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
local XOF  = require("./XOF")

local LOG2N = 8
local N = 2^LOG2N
local POLY_SIZE = N * 2 

local Q = 13 * 256 + 1
local Q_BIT_WIDTH = 12
local WIDTH = (2^(2 * Q_BIT_WIDTH))
local R = math.floor((2^(2 * Q_BIT_WIDTH)) / Q)

local Sampling = {}

local function SampleNtt(XofInput: buffer, Poly: buffer)
	local CoeffIndex = 0
	local Xof = XOF.NewSHAKE128()

	Xof:Absorb(XofInput)
	Xof:Finalize()

	while CoeffIndex < N do
		local Chunk = Xof:Squeeze(168)
		local ChunkLen = buffer.len(Chunk)
		local Offset = 0

		while Offset + 2 < ChunkLen and CoeffIndex < N do
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

function Sampling.GenerateMatrix(K: number, Rho: buffer, Transpose: boolean): buffer
	if not MlKemParams.CheckK(K) then
		error("Invalid matrix dimension K")
	end
	if buffer.len(Rho) ~= 32 then
		error("Rho must be 32 bytes")
	end

	local Matrix = PolyVec.MatCreate(K, K)
	local XofInput = buffer.create(34)
	buffer.copy(XofInput, 0, Rho, 0, 32)

	local Num = N
	for I = 0, K - 1 do
		for J = 0, K - 1 do
			if Transpose then
				buffer.writeu8(XofInput, 32, I)
				buffer.writeu8(XofInput, 33, J)
			else
				buffer.writeu8(XofInput, 32, J)
				buffer.writeu8(XofInput, 33, I)
			end

			local Poly = buffer.create(Num * 2)
			SampleNtt(XofInput, Poly)
			PolyVec.MatSetPoly(Matrix, I, J, K, Poly)
		end
	end

	return Matrix
end

local function SamplePolyCbd2(Prf: buffer, Poly: buffer)
	local Mask2 = 0x03
	local Modulus = Q
	
	for I = 0, 127 do
		local PolyOffset = I * 2
		local Word = buffer.readu8(Prf, I)

		local T0 = bit32.band(Word, 0x55)
		local T1 = bit32.band(bit32.rshift(Word, 1), 0x55)
		local T2 = T0 + T1

		local A0 = bit32.band(T2, Mask2)
		local B0 = bit32.band(bit32.rshift(T2, 2), Mask2)
		local Diff0 = A0 - B0
		local Coeff0 = if Diff0 < 0 then Diff0 + Modulus else Diff0

		local A1 = bit32.band(bit32.rshift(T2, 4), Mask2)
		local B1 = bit32.band(bit32.rshift(T2, 6), Mask2)
		local Diff1 = A1 - B1
		local Coeff1 = if Diff1 < 0 then Diff1 + Modulus else Diff1

		buffer.writeu16(Poly, PolyOffset * 2, Coeff0)
		buffer.writeu16(Poly, (PolyOffset + 1) * 2, Coeff1)
	end
end

local function SamplePolyCbd3(Prf: buffer, Poly: buffer)
	local Mask24 = 0x249249
	local Mask3 = 0x07
	local Modulus = Q
	
	for I = 0, 63 do
		local ByteOffset = I * 3
		local PolyOffset = I * 4

		local B0 = buffer.readu8(Prf, ByteOffset)
		local B1 = buffer.readu8(Prf, ByteOffset + 1)
		local B2 = buffer.readu8(Prf, ByteOffset + 2)
		local Word = bit32.bor(B0, bit32.lshift(B1, 8), bit32.lshift(B2, 16))

		local T0 = bit32.band(Word, Mask24)
		local T1 = bit32.band(bit32.rshift(Word, 1), Mask24)
		local T2 = bit32.band(bit32.rshift(Word, 2), Mask24)
		local T3 = T0 + T1 + T2

		for J = 0, 3 do
			local Offset = J * 6
			local A = bit32.band(bit32.rshift(T3, Offset), Mask3)
			local B = bit32.band(bit32.rshift(T3, Offset + 3), Mask3)
			local Diff = A - B
			local Coeff = if Diff < 0 then Diff + Modulus else Diff

			buffer.writeu16(Poly, (PolyOffset + J) * 2, Coeff)
		end
	end
end

function Sampling.SamplePolyCbd(Prf: buffer, Eta: number): buffer
	if not MlKemParams.CheckEta(Eta) then
		error("Invalid eta parameter")
	end

	local Poly = buffer.create(N * 2)

	if Eta == 2 then
		SamplePolyCbd2(Prf, Poly)
	else
		SamplePolyCbd3(Prf, Poly)
	end

	return Poly
end

function Sampling.GenerateVector(K: number, Eta: number, Sigma: buffer, Nonce: number): buffer
	if not (MlKemParams.CheckK(K) or K == 1) then
		error("Invalid vector dimension K")
	end
	if not MlKemParams.CheckEta(Eta) then
		error("Invalid eta parameter")
	end
	if buffer.len(Sigma) ~= 32 then
		error("Sigma must be 32 bytes")
	end

	local Vec = PolyVec.VecCreate(K)
	local PrfInput = buffer.create(33)
	buffer.copy(PrfInput, 0, Sigma, 0, 32)

	local Shake = SHA3.SHAKE256
	local PolySize = POLY_SIZE
	for I = 0, K - 1 do
		buffer.writeu8(PrfInput, 32, Nonce + I)

		local PrfOutput = Shake(PrfInput, 64 * Eta)
		local Poly = Sampling.SamplePolyCbd(PrfOutput, Eta)

		local Offset = I * PolySize
		buffer.copy(Vec, Offset, Poly, 0, PolySize)
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