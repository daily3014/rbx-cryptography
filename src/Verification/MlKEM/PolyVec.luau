--[=[
	ML-KEM Polynomial Vector Module
	
	Polynomial vector and matrix operations for ML-KEM.
	Vector arithmetic, matrix multiplication, and encoding/decoding
	operations on vectors of degree-255 polynomials.
--]=]

--!strict
--!optimize 2
--!native

local Ntt = require("./NTT")
local MlKemParams = require("./Params")
local MlKemSerialize = require("./Serialize")
local Compression = require("./Compression")

local LOG2N = 8
local N = 2^LOG2N
local Q = 3329
local POLY_SIZE = N * 2

local TEMP_POLY_ENCODE = buffer.create(N * 2)
local TEMP_POLY_COMPRESS = buffer.create(N * 2)

local PolyVec = {}

function PolyVec.VecCreate(K: number): buffer
	return buffer.create(K * POLY_SIZE)
end

function PolyVec.MatCreate(Rows: number, Cols: number): buffer
	return buffer.create(Rows * Cols * POLY_SIZE)
end

function PolyVec.MatVecMultiply(A: buffer, B: buffer, C: buffer, ARows: number, ACols: number, BRows: number)
	local PolySize = POLY_SIZE
	local Modulus = Q
	local PolyMulAdd = Ntt.PolyMulAddAt
	local PolyMul = Ntt.PolyMulAt

	for I = 0, ARows - 1 do
		local COffset = I * PolySize

		PolyMul(A, I * ACols * PolySize, B, 0, C, COffset)
		for K = 1, ACols - 1 do
			PolyMulAdd(A, (I * ACols + K) * PolySize, B, K * PolySize, C, COffset)
		end

		for J = 0, N - 1 do
			local Off = COffset + J * 2
			buffer.writeu16(C, Off, buffer.readu16(C, Off) % Modulus)
		end
	end
end

function PolyVec.VecNtt(Vec: buffer, K: number)
	local PolySize = POLY_SIZE
	local NttAt = Ntt.NttAt
	for I = 0, K - 1 do
		NttAt(Vec, I * PolySize)
	end
end

function PolyVec.VecIntt(Vec: buffer, K: number)
	local PolySize = POLY_SIZE
	local InttAt = Ntt.InttAt
	
	for I = 0, K - 1 do
		InttAt(Vec, I * PolySize)
	end
end

function PolyVec.VecAddTo(Src: buffer, Dst: buffer, K: number)
	local Modulus = Q
	local Total = K * N * 2

	for Offset = 0, Total - 2, 2 do
		local SrcValue = buffer.readu16(Src, Offset)
		local DstValue = buffer.readu16(Dst, Offset)
		buffer.writeu16(Dst, Offset, (SrcValue + DstValue) % Modulus)
	end
end

function PolyVec.VecEncode(Vec: buffer, K: number, L: number): buffer
	local OutputSize = K * 32 * L
	local Output = buffer.create(OutputSize)
	local PolySize = POLY_SIZE
	local ChunkSize = 32 * L
	
	local EncodeAt = MlKemSerialize.EncodeAt
	local Encode = MlKemSerialize.Encode
	
	if L == 12 then
		for I = 0, K - 1 do
			EncodeAt(Vec, I * PolySize, Output, I * ChunkSize, 12)
		end
	else
		local Poly = TEMP_POLY_ENCODE
		for I = 0, K - 1 do
			buffer.copy(Poly, 0, Vec, I * PolySize, PolySize)
			local EncodedPoly = Encode(Poly, L)
			buffer.copy(Output, I * ChunkSize, EncodedPoly, 0, ChunkSize)
		end
	end

	return Output
end

function PolyVec.VecDecode(Data: buffer, K: number, L: number): buffer
	local Vec = buffer.create(K * POLY_SIZE)
	local PolySize = POLY_SIZE
	local ChunkSize = 32 * L
	
	local DecodeAt = MlKemSerialize.DecodeAt
	local Decode = MlKemSerialize.Decode
	
	if L == 12 then
		for I = 0, K - 1 do
			DecodeAt(Data, I * ChunkSize, Vec, I * PolySize, 12)
		end
	else
		local PolyData = buffer.create(ChunkSize)
		for I = 0, K - 1 do
			buffer.copy(PolyData, 0, Data, I * ChunkSize, ChunkSize)
			local DecodedPoly = Decode(PolyData, L)
			buffer.copy(Vec, I * PolySize, DecodedPoly, 0, PolySize)
		end
	end

	return Vec
end

function PolyVec.VecCompress(Vec: buffer, K: number, D: number)
	local Poly = TEMP_POLY_COMPRESS
	local PolySize = POLY_SIZE

	for I = 0, K - 1 do
		local Offset = I * PolySize
		buffer.copy(Poly, 0, Vec, Offset, PolySize)
		Compression.PolyCompress(Poly, D)
		buffer.copy(Vec, Offset, Poly, 0, PolySize)
	end
end

function PolyVec.VecDecompress(Vec: buffer, K: number, D: number)
	local Poly = TEMP_POLY_COMPRESS
	local PolySize = POLY_SIZE

	for I = 0, K - 1 do
		local Offset = I * PolySize
		buffer.copy(Poly, 0, Vec, Offset, PolySize)
		Compression.PolyDecompress(Poly, D)
		buffer.copy(Vec, Offset, Poly, 0, PolySize)
	end
end

return PolyVec