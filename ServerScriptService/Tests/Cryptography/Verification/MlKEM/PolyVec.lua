-- @ScriptType: ModuleScript
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

local TEMP_POLY_MUL = buffer.create(N * 2)
local TEMP_POLY_ACCUM = buffer.create(N * 2)
local TEMP_POLY_ENCODE = buffer.create(N * 2)
local TEMP_POLY_COMPRESS = buffer.create(N * 2)

local PolyVec = {}

function PolyVec.VecCreate(K: number): buffer
	return buffer.create(K * POLY_SIZE)
end

function PolyVec.MatCreate(Rows: number, Cols: number): buffer
	return buffer.create(Rows * Cols * POLY_SIZE)
end

function PolyVec.MatSetPoly(Mat: buffer, Row: number, Col: number, Cols: number, Poly: buffer)
	local Index = Row * Cols + Col
	local Offset = Index * POLY_SIZE

	buffer.copy(Mat, Offset, Poly, 0, POLY_SIZE)
end

function PolyVec.MatVecMultiply(A: buffer, B: buffer, C: buffer, ARows: number, ACols: number, BRows: number)
	local PolySize = POLY_SIZE
	local AccumPoly = TEMP_POLY_ACCUM
	local TempPoly = TEMP_POLY_MUL
	
	local PolyMul = Ntt.PolyMulAt
	local PolyAdd = Ntt.PolyAddAt
	
	for I = 0, ARows - 1 do
		local COffset = I * PolySize
		buffer.fill(AccumPoly, 0, 0, PolySize)

		for K = 0, ACols - 1 do
			local AOffset = (I * ACols + K) * PolySize
			local BOffset = K * PolySize

			PolyMul(A, AOffset, B, BOffset, TempPoly, 0)
			PolyAdd(AccumPoly, 0, TempPoly, 0, AccumPoly, 0)
		end

		buffer.copy(C, COffset, AccumPoly, 0, PolySize)
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
		local Sum = SrcValue + DstValue
		buffer.writeu16(Dst, Offset, if Sum >= Modulus then Sum - Modulus else Sum)
	end
end

function PolyVec.VecAdd(A: buffer, B: buffer, Result: buffer, K: number)
	if not (MlKemParams.CheckK(K) or K == 1) then
		error("Invalid vector dimension K")
	end

	local TotalCoeffs = K * N
	local Modulus = Q
	for Index = 0, TotalCoeffs - 1 do
		local Offset = Index * 2
		local AValue = buffer.readu16(A, Offset)
		local BValue = buffer.readu16(B, Offset)
		local Sum = AValue + BValue
		local AddResult = if Sum >= Modulus then Sum - Modulus else Sum
		buffer.writeu16(Result, Offset, AddResult)
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