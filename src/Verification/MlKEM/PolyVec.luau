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
	if not MlKemParams.CheckMatrixDim(ACols, BRows) then
		error("Incompatible matrix dimensions")
	end

	local TempPoly = buffer.create(N * 2)
	local AccumPoly = buffer.create(N * 2)
	local PolyA = buffer.create(N * 2)
	local PolyB = buffer.create(N * 2)

	local PolySize = POLY_SIZE

	for I = 0, ARows - 1 do
		buffer.fill(AccumPoly, 0, 0, N * 2)

		for K = 0, ACols - 1 do
			local AOffset = (I * ACols + K) * PolySize
			local BOffset = K * PolySize

			buffer.copy(PolyA, 0, A, AOffset, PolySize)
			buffer.copy(PolyB, 0, B, BOffset, PolySize)

			Ntt.PolyMul(PolyA, PolyB, TempPoly)
			Ntt.PolyAdd(AccumPoly, TempPoly, AccumPoly)
		end

		local COffset = I * PolySize
		buffer.copy(C, COffset, AccumPoly, 0, PolySize)
	end
end

function PolyVec.VecNtt(Vec: buffer, K: number)
	if not (MlKemParams.CheckK(K) or K == 1) then
		error("Invalid vector dimension K")
	end

	local Poly = buffer.create(N * 2)
	local PolySize = POLY_SIZE
	
	for I = 0, K - 1 do
		local Offset = I * PolySize
		buffer.copy(Poly, 0, Vec, Offset, PolySize)
		Ntt.Ntt(Poly)
		buffer.copy(Vec, Offset, Poly, 0, PolySize)
	end
end

function PolyVec.VecIntt(Vec: buffer, K: number)
	if not (MlKemParams.CheckK(K) or K == 1) then
		error("Invalid vector dimension K")
	end

	local Poly = buffer.create(N * 2)
	local PolySize = POLY_SIZE
	
	for I = 0, K - 1 do
		local Offset = I * PolySize
		buffer.copy(Poly, 0, Vec, Offset, PolySize)
		Ntt.Intt(Poly)
		buffer.copy(Vec, Offset, Poly, 0, PolySize)
	end
end

function PolyVec.VecAddTo(Src: buffer, Dst: buffer, K: number)
	if not (MlKemParams.CheckK(K) or K == 1) then
		error("Invalid vector dimension K")
	end

	local TotalCoeffs = K * N
	local Modulus = Q
	
	for Index = 0, TotalCoeffs - 1 do
		local Offset = Index * 2
		local SrcValue = buffer.readu16(Src, Offset)
		local DstValue = buffer.readu16(Dst, Offset)
		local Sum = SrcValue + DstValue
		local Result = if Sum >= Modulus then Sum - Modulus else Sum
		buffer.writeu16(Dst, Offset, Result)
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
	if not MlKemParams.CheckK(K) then
		error("Invalid vector dimension K")
	end
	if not MlKemParams.CheckL(L) then
		error("Invalid encoding parameter L")
	end

	local OutputSize = K * 32 * L
	local Output = buffer.create(OutputSize)
	local Poly = buffer.create(N * 2)
	local PolySize = POLY_SIZE
	
	for I = 0, K - 1 do
		local PolyOffset = I * PolySize
		local OutputOffset = I * 32 * L

		buffer.copy(Poly, 0, Vec, PolyOffset, PolySize)
		local EncodedPoly = MlKemSerialize.Encode(Poly, L)
		buffer.copy(Output, OutputOffset, EncodedPoly, 0, 32 * L)
	end

	return Output
end

function PolyVec.VecDecode(Data: buffer, K: number, L: number): buffer
	if not MlKemParams.CheckK(K) then
		error("Invalid vector dimension K")
	end
	if not MlKemParams.CheckL(L) then
		error("Invalid encoding parameter L")
	end

	local Vec = buffer.create(K * POLY_SIZE)
	local PolyData = buffer.create(32 * L)
	local PolySize = POLY_SIZE
	
	for I = 0, K - 1 do
		local DataOffset = I * 32 * L
		local VecOffset = I * PolySize

		buffer.copy(PolyData, 0, Data, DataOffset, 32 * L)
		local DecodedPoly = MlKemSerialize.Decode(PolyData, L)
		buffer.copy(Vec, VecOffset, DecodedPoly, 0, PolySize)
	end

	return Vec
end

function PolyVec.VecCompress(Vec: buffer, K: number, D: number)
	if not MlKemParams.CheckK(K) then
		error("Invalid vector dimension K")
	end
	if not MlKemParams.CheckD(D) then
		error("Invalid compression parameter D")
	end

	local Poly = buffer.create(N * 2)
	local PolySize = POLY_SIZE
	
	for I = 0, K - 1 do
		local Offset = I * PolySize
		buffer.copy(Poly, 0, Vec, Offset, PolySize)
		Compression.PolyCompress(Poly, D)
		buffer.copy(Vec, Offset, Poly, 0, PolySize)
	end
end

function PolyVec.VecDecompress(Vec: buffer, K: number, D: number)
	if not MlKemParams.CheckK(K) then
		error("Invalid vector dimension K")
	end
	if not MlKemParams.CheckD(D) then
		error("Invalid compression parameter D")
	end

	local Poly = buffer.create(N * 2)
	local PolySize = POLY_SIZE
	
	for I = 0, K - 1 do
		local Offset = I * PolySize
		buffer.copy(Poly, 0, Vec, Offset, PolySize)
		Compression.PolyDecompress(Poly, D)
		buffer.copy(Vec, Offset, Poly, 0, PolySize)
	end
end

return PolyVec