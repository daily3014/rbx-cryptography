--[=[
	ML-KEM Polynomial Vector Module
	
	Polynomial vector and matrix operations for ML-KEM.
	 Vector arithmetic, matrix multiplication, and encoding/decoding
	operations on vectors of degree-255 polynomials.
		
	Example usage:
		local PolyVec = require(script.PolyVec)
		
		local VecA = PolyVec.VecCreate(3)
		local VecB = PolyVec.VecCreate(3)
		local Result = PolyVec.VecCreate(3)
		
		PolyVec.VecAdd(VecA, VecB, Result, 3)
		PolyVec.VecNtt(VecA, 3)
		
		local Matrix = PolyVec.MatCreate(3, 3)
		PolyVec.MatVecMultiply(Matrix, VecA, Result, 3, 3, 3)
--]=]

--!strict
--!optimize 2
--!native

local Ntt = require("./NTT")
local MlKemParams = require("./Params")
local MlKemSerialize = require("./Serialize")
local MlKemCompression = require("./Compression")

local LOG2N = 8
local N = 2^LOG2N
local POLY_SIZE = N * 2 

local Q = 13 * 256 + 1

local PolyVec = {}

function PolyVec.VecCreate(K: number): buffer
	if not (MlKemParams.CheckK(K) or K == 1) then
		error("Invalid vector dimension K")
	end

	return buffer.create(K * POLY_SIZE)
end

function PolyVec.MatCreate(Rows: number, Cols: number): buffer
	if not (MlKemParams.CheckK(Rows) or Rows == 1) then
		error("Invalid matrix rows")
	end
	if not (MlKemParams.CheckK(Cols) or Cols == 1) then
		error("Invalid matrix cols")
	end

	return buffer.create(Rows * Cols * POLY_SIZE)
end

function PolyVec.VecGetPoly(Vec: buffer, I: number): buffer
	local Offset = I * POLY_SIZE
	local Poly = buffer.create(N * 2)
	buffer.copy(Poly, 0, Vec, Offset, POLY_SIZE)
	
	return Poly
end

function PolyVec.MatGetPoly(Mat: buffer, Row: number, Col: number, Cols: number): buffer
	local Index = Row * Cols + Col
	local Offset = Index * POLY_SIZE
	local Poly = buffer.create(N * 2)
	buffer.copy(Poly, 0, Mat, Offset, POLY_SIZE)

	return Poly
end

function PolyVec.MatSetPoly(Mat: buffer, Row: number, Col: number, Cols: number, Poly: buffer)
	local Index = Row * Cols + Col
	local Offset = Index * POLY_SIZE
	
	buffer.copy(Mat, Offset, Poly, 0, POLY_SIZE)
end

function PolyVec.MatMultiply(A: buffer, B: buffer, C: buffer, ARows: number, ACols: number, BRows: number, BCols: number)
	if not MlKemParams.CheckMatrixDim(ACols, BRows) then
		error("Incompatible matrix dimensions")
	end

	local TempPoly = buffer.create(N * 2)
	local AccumPoly = buffer.create(N * 2)

	local Num = N
	local PolySize = POLY_SIZE
	for I = 0, ARows - 1 do
		for J = 0, BCols - 1 do
			buffer.fill(AccumPoly, 0, 0, Num * 2)

			for K = 0, ACols - 1 do
				local AOffset = (I * ACols + K) * PolySize
				local BOffset = (K * BCols + J) * PolySize

				local PolyA = buffer.create(Num * 2)
				local PolyB = buffer.create(Num * 2)
				buffer.copy(PolyA, 0, A, AOffset, PolySize)
				buffer.copy(PolyB, 0, B, BOffset, PolySize)

				Ntt.PolyMul(PolyA, PolyB, TempPoly)

				Ntt.PolyAdd(AccumPoly, TempPoly, AccumPoly)
			end

			local COffset = (I * BCols + J) * POLY_SIZE
			buffer.copy(C, COffset, AccumPoly, 0, POLY_SIZE)
		end
	end
end

function PolyVec.MatVecMultiply(A: buffer, B: buffer, C: buffer, ARows: number, ACols: number, BRows: number)
	if ACols ~= BRows then
		error("Incompatible matrix-vector dimensions")
	end

	local TempPoly = buffer.create(N * 2)
	local AccumPoly = buffer.create(N * 2)

	local Num = N
	local PolySize = POLY_SIZE
	for I = 0, ARows - 1 do
		buffer.fill(AccumPoly, 0, 0, Num * 2)

		for K = 0, ACols - 1 do
			local AOffset = (I * ACols + K) * PolySize
			local BOffset = K * PolySize

			local PolyA = buffer.create(Num * 2)
			local PolyB = buffer.create(Num * 2)
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

	local Num = N
	local PolySize = POLY_SIZE
	for I = 0, K - 1 do
		local Offset = I * PolySize
		local Poly = buffer.create(Num * 2)
		buffer.copy(Poly, 0, Vec, Offset, PolySize)

		Ntt.Ntt(Poly)

		buffer.copy(Vec, Offset, Poly, 0, PolySize)
	end
end

function PolyVec.VecIntt(Vec: buffer, K: number)
	if not (MlKemParams.CheckK(K) or K == 1) then
		error("Invalid vector dimension K")
	end

	local Num = N
	local PolySize = POLY_SIZE
	for I = 0, K - 1 do
		local Offset = I * PolySize
		local Poly = buffer.create(Num * 2)
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
	for Index = 0, TotalCoeffs - 1 do
		local DstValue = buffer.readu16(Dst, Index * 2)
		local SrcValue = buffer.readu16(Src, Index * 2)

		local T0 = DstValue + SrcValue
		local T1 = T0 - Q
		local T2 = if T1 >= 0 then 0 else 0xFFFFFFFF
		local T3 = bit32.band(Q, T2)
		local AddResult = T1 + T3

		buffer.writeu16(Dst, Index * 2, AddResult)
	end
end

function PolyVec.VecSubFrom(Src: buffer, Dst: buffer, K: number)
	if not (MlKemParams.CheckK(K) or K == 1) then
		error("Invalid vector dimension K")
	end

	local TotalCoeffs = K * N
	for Index = 0, TotalCoeffs - 1 do
		local DstValue = buffer.readu16(Dst, Index * 2)
		local SrcValue = buffer.readu16(Src, Index * 2)

		local NegSrc = if SrcValue == 0 then 0 else Q - SrcValue
		local T0 = DstValue + NegSrc
		local T1 = T0 - Q
		local T2 = if T1 >= 0 then 0 else 0xFFFFFFFF
		local T3 = bit32.band(Q, T2)
		local SubResult = T1 + T3

		buffer.writeu16(Dst, Index * 2, SubResult)
	end
end

function PolyVec.VecAdd(A: buffer, B: buffer, Result: buffer, K: number)
	if not (MlKemParams.CheckK(K) or K == 1) then
		error("Invalid vector dimension K")
	end

	local TotalCoeffs = K * N
	for Index = 0, TotalCoeffs - 1 do
		local AValue = buffer.readu16(A, Index * 2)
		local BValue = buffer.readu16(B, Index * 2)

		local T0 = AValue + BValue
		local T1 = T0 - Q
		local T2 = if T1 >= 0 then 0 else 0xFFFFFFFF
		local T3 = bit32.band(Q, T2)
		local AddResult = T1 + T3

		buffer.writeu16(Result, Index * 2, AddResult)
	end
end

function PolyVec.VecSub(A: buffer, B: buffer, Result: buffer, K: number)
	if not (MlKemParams.CheckK(K) or K == 1) then
		error("Invalid vector dimension K")
	end

	local TotalCoeffs = K * N
	for Index = 0, TotalCoeffs - 1 do
		local AValue = buffer.readu16(A, Index * 2)
		local BValue = buffer.readu16(B, Index * 2)

		local NegB = if BValue == 0 then 0 else Q - BValue
		local T0 = AValue + NegB
		local T1 = T0 - Q
		local T2 = if T1 >= 0 then 0 else 0xFFFFFFFF
		local T3 = bit32.band(Q, T2)
		local SubResult = T1 + T3

		buffer.writeu16(Result, Index * 2, SubResult)
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

	local Num = N
	local PolySize = POLY_SIZE
	for I = 0, K - 1 do
		local PolyOffset = I * PolySize
		local OutputOffset = I * 32 * L

		local Poly = buffer.create(Num * 2)
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
	if buffer.len(Data) ~= K * 32 * L then
		error("Invalid data size")
	end

	local Vec = PolyVec.VecCreate(K)
	local PolySize = POLY_SIZE
	
	for I = 0, K - 1 do
		local DataOffset = I * 32 * L
		local VecOffset = I * PolySize

		local EncodedPoly = buffer.create(32 * L)
		buffer.copy(EncodedPoly, 0, Data, DataOffset, 32 * L)

		local Poly = MlKemSerialize.Decode(EncodedPoly, L)

		buffer.copy(Vec, VecOffset, Poly, 0, PolySize)
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

	local PolySize = POLY_SIZE
	for I = 0, K - 1 do
		local Offset = I * PolySize
		local Poly = buffer.create(N * 2)
		buffer.copy(Poly, 0, Vec, Offset, PolySize)

		MlKemCompression.PolyCompress(Poly, D)

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

	local PolySize = POLY_SIZE
	for I = 0, K - 1 do
		local Offset = I * PolySize
		local Poly = buffer.create(N * 2)
		buffer.copy(Poly, 0, Vec, Offset, PolySize)

		MlKemCompression.PolyDecompress(Poly, D)

		buffer.copy(Vec, Offset, Poly, 0, PolySize)
	end
end

return PolyVec