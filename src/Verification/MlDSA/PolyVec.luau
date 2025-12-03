--[=[
	Vector operations on degree-255 polynomials
	
	Works on vectors of polynomials including matrix multiplication,
	NTT transforms, and encoding/decoding for ML-DSA.

	Example usage:
		local PolyVec = require(script)
		
		local Vec = buffer.create(4 * 256 * 4)  -- 4 polynomials
		PolyVec.ForwardNTT(Vec, 4)
		local Norm = PolyVec.InfinityNorm(Vec, 4)
--]=]

--!strict
--!optimize 2
--!native

local Field = require("./Field")
local NTT = require("./NTT")
local BitPacking = require("./Pack")

local LOG2N = 8
local ZETA = 1753
local Q = 8380417

local N = 256
local INV_N = Field.Inverse(N)

local ZETA_EXP, ZETA_NEG_EXP = buffer.create(N * 4), buffer.create(N * 4) do
	for I = 0, N - 1 do
		local Reversed = 0
		local Value = I

		for J = 0, LOG2N - 1 do
			local Bit = bit32.band(bit32.rshift(Value, J), 1)
			Reversed = bit32.bxor(Reversed, bit32.lshift(Bit, LOG2N - 1 - J))
		end

		local ZetaExp = Field.Power(ZETA, Reversed)
		local ZetaNegExp = Field.Negate(ZetaExp)

		buffer.writeu32(ZETA_EXP, I * 4, ZetaExp)
		buffer.writeu32(ZETA_NEG_EXP, I * 4, ZetaNegExp)
	end
end

local PolyVec = {}

function PolyVec.ForwardNTT(Vec: buffer, K: number)
	local Num = N
	for I = 0, K - 1 do
		local Offset = I * Num * 4
		NTT.ForwardNTTWithOffset(Vec, Offset)
	end
end

function PolyVec.InverseNTT(Vec: buffer, K: number)
	local Zeta = ZETA_NEG_EXP
	local InvN = INV_N
	local Num = N
	local Modulus = Q
	
	for I = 0, K - 1 do
		local Offset = I * Num * 4

		for L = 0, 7 do
			local Len = bit32.lshift(1, L)
			local LenX2 = bit32.lshift(Len, 1)
			local KBeg = bit32.rshift(Num, L) - 1

			for Start = 0, Num - 1, LenX2 do
				local KNow = KBeg - bit32.rshift(Start, L + 1)
				local NegZetaExpValue = buffer.readu32(Zeta, KNow * 4)

				for J = Start, Start + Len - 1 do
					local JOffset = Offset + J * 4
					local JLenOffset = Offset + (J + Len) * 4

					local PolyJ = buffer.readu32(Vec, JOffset)
					local PolyJLen = buffer.readu32(Vec, JLenOffset)

					local Sum = PolyJ + PolyJLen
					Sum = if Sum >= Modulus then Sum - Modulus else Sum

					local Diff = if PolyJ >= PolyJLen then PolyJ - PolyJLen else PolyJ - PolyJLen + Modulus
					local Product = (Diff * NegZetaExpValue) % Modulus

					buffer.writeu32(Vec, JOffset, Sum)
					buffer.writeu32(Vec, JLenOffset, Product)
				end
			end
		end

		for J = 0, Num - 1 do
			local JOffset = Offset + J * 4
			local PolyValue = buffer.readu32(Vec, JOffset)
			local Result = (PolyValue * InvN) % Modulus
			buffer.writeu32(Vec, JOffset, Result)
		end
	end
end

function PolyVec.Power2Round(PolyVec: buffer, PolyHi: buffer, PolyLo: buffer, K: number, D: number)
	local Max = bit32.lshift(1, D - 1)
	local Num = N
	local Modulus = Q
	
	for I = 0, K - 1 do
		local Offset = I * Num * 4

		for J = 0, Num - 1 do
			local JOffset = Offset + J * 4
			local R = buffer.readu32(PolyVec, JOffset)

			local T1 = R + Max - 1
			local T2 = bit32.rshift(T1, D)
			local T3 = bit32.lshift(T2, D)

			local Hi = T2
			local Lo = if R >= T3 then R - T3 else R - T3 + Modulus

			buffer.writeu32(PolyHi, JOffset, Hi)
			buffer.writeu32(PolyLo, JOffset, Lo)
		end
	end
end

function PolyVec.MatrixMultiply(A: buffer, B: buffer, C: buffer, ARows: number, ACols: number, BRows: number, BCols: number)
	local Num = N
	local Modulus = Q
	
	buffer.fill(C, 0, 0, ARows * BCols * N * 4)

	for I = 0, ARows - 1 do
		for J = 0, BCols - 1 do
			local COffset = (I * BCols + J) * Num * 4

			for K = 0, ACols - 1 do
				local AOffset = (I * ACols + K) * Num * 4
				local BOffset = (K * BCols + J) * Num * 4

				for L = 0, Num - 1 do
					local ElementOffset = L * 4
					local AValue = buffer.readu32(A, AOffset + ElementOffset)
					local BValue = buffer.readu32(B, BOffset + ElementOffset)

					local Product = (AValue * BValue) % Modulus

					local CValue = buffer.readu32(C, COffset + ElementOffset)
					local Sum = CValue + Product
					Sum = if Sum >= Modulus then Sum - Modulus else Sum

					buffer.writeu32(C, COffset + ElementOffset, Sum)
				end
			end
		end
	end
end

function PolyVec.AddTo(Src: buffer, Dst: buffer, K: number)
	local TotalElements = K * N
	local Modulus = Q
	
	for I = 0, TotalElements - 1 do
		local Offset = I * 4
		local SrcValue = buffer.readu32(Src, Offset)
		local DstValue = buffer.readu32(Dst, Offset)

		local Sum = DstValue + SrcValue
		Sum = if Sum >= Modulus then Sum - Modulus else Sum

		buffer.writeu32(Dst, Offset, Sum)
	end
end

function PolyVec.Negate(Vec: buffer, K: number)
	local TotalElements = K * N
	local Modulus = Q
	
	for I = 0, TotalElements - 1 do
		local Offset = I * 4
		local Value = buffer.readu32(Vec, Offset)
		local Negated = if Value == 0 then 0 else Modulus - Value

		buffer.writeu32(Vec, Offset, Negated)
	end
end

function PolyVec.SubFromX(Vec: buffer, K: number, X: number)
	local Modulus = Q
	local Num = N
	for I = 0, K - 1 do
		local Offset = I * Num * 4

		for J = 0, Num - 1 do
			local JOffset = Offset + J * 4
			local PolyValue = buffer.readu32(Vec, JOffset)

			local Result = if X >= PolyValue then X - PolyValue else X - PolyValue + Modulus

			buffer.writeu32(Vec, JOffset, Result)
		end
	end
end

function PolyVec.Encode(Src: buffer, Dst: buffer, K: number, Sbw: number)
	local PolyByteLength = math.floor((N * Sbw) / 8)
	local Num = N

	for I = 0, K - 1 do
		local SrcOffset = I * Num * 4
		local DstOffset = I * PolyByteLength

		if Sbw == 3 then
			local ItrCnt = 32
			for J = 0, ItrCnt - 1 do
				local POffset = SrcOffset + J * 32
				local BOffset = DstOffset + J * 3

				local P0 = bit32.band(buffer.readu32(Src, POffset + 0), 0x7)
				local P1 = bit32.band(buffer.readu32(Src, POffset + 4), 0x7)
				local P2 = bit32.band(buffer.readu32(Src, POffset + 8), 0x7)
				local P3 = bit32.band(buffer.readu32(Src, POffset + 12), 0x7)
				local P4 = bit32.band(buffer.readu32(Src, POffset + 16), 0x7)
				local P5 = bit32.band(buffer.readu32(Src, POffset + 20), 0x7)
				local P6 = bit32.band(buffer.readu32(Src, POffset + 24), 0x7)
				local P7 = bit32.band(buffer.readu32(Src, POffset + 28), 0x7)

				buffer.writeu8(Dst, BOffset + 0, bit32.bor(bit32.lshift(bit32.band(P2, 0x3), 6), bit32.lshift(P1, 3), P0))
				buffer.writeu8(Dst, BOffset + 1, bit32.bor(bit32.lshift(bit32.band(P5, 0x1), 7), bit32.lshift(P4, 4), bit32.lshift(P3, 1), bit32.rshift(P2, 2)))
				buffer.writeu8(Dst, BOffset + 2, bit32.bor(bit32.lshift(P7, 5), bit32.lshift(P6, 2), bit32.rshift(P5, 1)))
			end
		elseif Sbw == 4 then
			for J = 0, 127 do
				local POffset = SrcOffset + J * 8
				local P0 = bit32.band(buffer.readu32(Src, POffset), 0xF)
				local P1 = bit32.band(buffer.readu32(Src, POffset + 4), 0xF)
				buffer.writeu8(Dst, DstOffset + J, bit32.bor(bit32.lshift(P1, 4), P0))
			end
		elseif Sbw == 6 then
			for J = 0, 63 do
				local POffset = SrcOffset + J * 16
				local BOffset = DstOffset + J * 3

				local P0 = bit32.band(buffer.readu32(Src, POffset + 0), 0x3F)
				local P1 = bit32.band(buffer.readu32(Src, POffset + 4), 0x3F)
				local P2 = bit32.band(buffer.readu32(Src, POffset + 8), 0x3F)
				local P3 = bit32.band(buffer.readu32(Src, POffset + 12), 0x3F)

				buffer.writeu8(Dst, BOffset + 0, bit32.bor(bit32.lshift(bit32.band(P1, 0x3), 6), P0))
				buffer.writeu8(Dst, BOffset + 1, bit32.bor(bit32.lshift(bit32.band(P2, 0xF), 4), bit32.rshift(P1, 2)))
				buffer.writeu8(Dst, BOffset + 2, bit32.bor(bit32.lshift(P3, 2), bit32.rshift(P2, 4)))
			end
		elseif Sbw == 10 then
			for J = 0, 63 do
				local POffset = SrcOffset + J * 16
				local BOffset = DstOffset + J * 5

				local P0 = bit32.band(buffer.readu32(Src, POffset + 0), 0x3FF)
				local P1 = bit32.band(buffer.readu32(Src, POffset + 4), 0x3FF)
				local P2 = bit32.band(buffer.readu32(Src, POffset + 8), 0x3FF)
				local P3 = bit32.band(buffer.readu32(Src, POffset + 12), 0x3FF)

				buffer.writeu8(Dst, BOffset + 0, bit32.band(P0, 0xFF))
				buffer.writeu8(Dst, BOffset + 1, bit32.bor(bit32.lshift(bit32.band(P1, 0x3F), 2), bit32.rshift(P0, 8)))
				buffer.writeu8(Dst, BOffset + 2, bit32.bor(bit32.lshift(bit32.band(P2, 0xF), 4), bit32.rshift(P1, 6)))
				buffer.writeu8(Dst, BOffset + 3, bit32.bor(bit32.lshift(bit32.band(P3, 0x3), 6), bit32.rshift(P2, 4)))
				buffer.writeu8(Dst, BOffset + 4, bit32.rshift(P3, 2))
			end
		elseif Sbw == 13 then
			for J = 0, 31 do
				local POffset = SrcOffset + J * 32
				local BOffset = DstOffset + J * 13

				local P0 = bit32.band(buffer.readu32(Src, POffset + 0), 0x1FFF)
				local P1 = bit32.band(buffer.readu32(Src, POffset + 4), 0x1FFF)
				local P2 = bit32.band(buffer.readu32(Src, POffset + 8), 0x1FFF)
				local P3 = bit32.band(buffer.readu32(Src, POffset + 12), 0x1FFF)
				local P4 = bit32.band(buffer.readu32(Src, POffset + 16), 0x1FFF)
				local P5 = bit32.band(buffer.readu32(Src, POffset + 20), 0x1FFF)
				local P6 = bit32.band(buffer.readu32(Src, POffset + 24), 0x1FFF)
				local P7 = bit32.band(buffer.readu32(Src, POffset + 28), 0x1FFF)

				buffer.writeu8(Dst, BOffset + 0, bit32.band(P0, 0xFF))
				buffer.writeu8(Dst, BOffset + 1, bit32.bor(bit32.lshift(bit32.band(P1, 0x7), 5), bit32.rshift(P0, 8)))
				buffer.writeu8(Dst, BOffset + 2, bit32.rshift(P1, 3))
				buffer.writeu8(Dst, BOffset + 3, bit32.bor(bit32.lshift(bit32.band(P2, 0x3F), 2), bit32.rshift(P1, 11)))
				buffer.writeu8(Dst, BOffset + 4, bit32.bor(bit32.lshift(bit32.band(P3, 0x1), 7), bit32.rshift(P2, 6)))
				buffer.writeu8(Dst, BOffset + 5, bit32.rshift(P3, 1))
				buffer.writeu8(Dst, BOffset + 6, bit32.bor(bit32.lshift(bit32.band(P4, 0xF), 4), bit32.rshift(P3, 9)))
				buffer.writeu8(Dst, BOffset + 7, bit32.rshift(P4, 4))
				buffer.writeu8(Dst, BOffset + 8, bit32.bor(bit32.lshift(bit32.band(P5, 0x7F), 1), bit32.rshift(P4, 12)))
				buffer.writeu8(Dst, BOffset + 9, bit32.bor(bit32.lshift(bit32.band(P6, 0x3), 6), bit32.rshift(P5, 7)))
				buffer.writeu8(Dst, BOffset + 10, bit32.rshift(P6, 2))
				buffer.writeu8(Dst, BOffset + 11, bit32.bor(bit32.lshift(bit32.band(P7, 0x1F), 3), bit32.rshift(P6, 10)))
				buffer.writeu8(Dst, BOffset + 12, bit32.rshift(P7, 5))
			end
		elseif Sbw == 18 then
			for J = 0, 63 do
				local POffset = SrcOffset + J * 16
				local BOffset = DstOffset + J * 9

				local P0 = bit32.band(buffer.readu32(Src, POffset + 0), 0x3FFFF)
				local P1 = bit32.band(buffer.readu32(Src, POffset + 4), 0x3FFFF)
				local P2 = bit32.band(buffer.readu32(Src, POffset + 8), 0x3FFFF)
				local P3 = bit32.band(buffer.readu32(Src, POffset + 12), 0x3FFFF)

				buffer.writeu8(Dst, BOffset + 0, bit32.band(P0, 0xFF))
				buffer.writeu8(Dst, BOffset + 1, bit32.band(bit32.rshift(P0, 8), 0xFF))
				buffer.writeu8(Dst, BOffset + 2, bit32.bor(bit32.rshift(P0, 16), bit32.lshift(bit32.band(P1, 0x3F), 2)))
				buffer.writeu8(Dst, BOffset + 3, bit32.band(bit32.rshift(P1, 6), 0xFF))
				buffer.writeu8(Dst, BOffset + 4, bit32.bor(bit32.rshift(P1, 14), bit32.lshift(bit32.band(P2, 0xF), 4)))
				buffer.writeu8(Dst, BOffset + 5, bit32.band(bit32.rshift(P2, 4), 0xFF))
				buffer.writeu8(Dst, BOffset + 6, bit32.bor(bit32.rshift(P2, 12), bit32.lshift(bit32.band(P3, 0x3), 6)))
				buffer.writeu8(Dst, BOffset + 7, bit32.band(bit32.rshift(P3, 2), 0xFF))
				buffer.writeu8(Dst, BOffset + 8, bit32.rshift(P3, 10))
			end
		elseif Sbw == 20 then
			for J = 0, 63 do
				local POffset = SrcOffset + J * 16
				local BOffset = DstOffset + J * 10

				local P0 = bit32.band(buffer.readu32(Src, POffset + 0), 0xFFFFF)
				local P1 = bit32.band(buffer.readu32(Src, POffset + 4), 0xFFFFF)
				local P2 = bit32.band(buffer.readu32(Src, POffset + 8), 0xFFFFF)
				local P3 = bit32.band(buffer.readu32(Src, POffset + 12), 0xFFFFF)

				buffer.writeu8(Dst, BOffset + 0, bit32.band(P0, 0xFF))
				buffer.writeu8(Dst, BOffset + 1, bit32.band(bit32.rshift(P0, 8), 0xFF))
				buffer.writeu8(Dst, BOffset + 2, bit32.bor(bit32.rshift(P0, 16), bit32.lshift(bit32.band(P1, 0xF), 4)))
				buffer.writeu8(Dst, BOffset + 3, bit32.band(bit32.rshift(P1, 4), 0xFF))
				buffer.writeu8(Dst, BOffset + 4, bit32.band(bit32.rshift(P1, 12), 0xFF))
				buffer.writeu8(Dst, BOffset + 5, bit32.band(P2, 0xFF))
				buffer.writeu8(Dst, BOffset + 6, bit32.band(bit32.rshift(P2, 8), 0xFF))
				buffer.writeu8(Dst, BOffset + 7, bit32.bor(bit32.rshift(P2, 16), bit32.lshift(bit32.band(P3, 0xF), 4)))
				buffer.writeu8(Dst, BOffset + 8, bit32.band(bit32.rshift(P3, 4), 0xFF))
				buffer.writeu8(Dst, BOffset + 9, bit32.rshift(P3, 12))
			end
		else
			local PolyBuffer = buffer.create(N * 4)
			local ByteBuffer = buffer.create(PolyByteLength)
			buffer.copy(PolyBuffer, 0, Src, SrcOffset, N * 4)
			BitPacking.Encode(PolyBuffer, ByteBuffer, Sbw)
			buffer.copy(Dst, DstOffset, ByteBuffer, 0, PolyByteLength)
		end
	end
end

function PolyVec.Decode(Src: buffer, Dst: buffer, K: number, Sbw: number)
	local PolyByteLength = math.floor((N * Sbw) / 8)
	local Num = N

	for I = 0, K - 1 do
		local SrcOffset = I * PolyByteLength
		local DstOffset = I * Num * 4

		if Sbw == 3 then
			for J = 0, 31 do
				local BOffset = SrcOffset + J * 3
				local POffset = DstOffset + J * 32

				local B0 = buffer.readu8(Src, BOffset + 0)
				local B1 = buffer.readu8(Src, BOffset + 1)
				local B2 = buffer.readu8(Src, BOffset + 2)

				buffer.writeu32(Dst, POffset + 0, bit32.band(B0, 0x7))
				buffer.writeu32(Dst, POffset + 4, bit32.band(bit32.rshift(B0, 3), 0x7))
				buffer.writeu32(Dst, POffset + 8, bit32.bor(bit32.rshift(B0, 6), bit32.lshift(bit32.band(B1, 0x1), 2)))
				buffer.writeu32(Dst, POffset + 12, bit32.band(bit32.rshift(B1, 1), 0x7))
				buffer.writeu32(Dst, POffset + 16, bit32.band(bit32.rshift(B1, 4), 0x7))
				buffer.writeu32(Dst, POffset + 20, bit32.bor(bit32.rshift(B1, 7), bit32.lshift(bit32.band(B2, 0x3), 1)))
				buffer.writeu32(Dst, POffset + 24, bit32.band(bit32.rshift(B2, 2), 0x7))
				buffer.writeu32(Dst, POffset + 28, bit32.rshift(B2, 5))
			end
		elseif Sbw == 4 then
			for J = 0, 127 do
				local B = buffer.readu8(Src, SrcOffset + J)
				local POffset = DstOffset + J * 8
				buffer.writeu32(Dst, POffset, bit32.band(B, 0xF))
				buffer.writeu32(Dst, POffset + 4, bit32.rshift(B, 4))
			end
		elseif Sbw == 6 then
			for J = 0, 63 do
				local BOffset = SrcOffset + J * 3
				local POffset = DstOffset + J * 16

				local B0 = buffer.readu8(Src, BOffset + 0)
				local B1 = buffer.readu8(Src, BOffset + 1)
				local B2 = buffer.readu8(Src, BOffset + 2)

				buffer.writeu32(Dst, POffset + 0, bit32.band(B0, 0x3F))
				buffer.writeu32(Dst, POffset + 4, bit32.bor(bit32.rshift(B0, 6), bit32.lshift(bit32.band(B1, 0xF), 2)))
				buffer.writeu32(Dst, POffset + 8, bit32.bor(bit32.rshift(B1, 4), bit32.lshift(bit32.band(B2, 0x3), 4)))
				buffer.writeu32(Dst, POffset + 12, bit32.rshift(B2, 2))
			end
		elseif Sbw == 10 then
			for J = 0, 63 do
				local BOffset = SrcOffset + J * 5
				local POffset = DstOffset + J * 16

				local B0 = buffer.readu8(Src, BOffset + 0)
				local B1 = buffer.readu8(Src, BOffset + 1)
				local B2 = buffer.readu8(Src, BOffset + 2)
				local B3 = buffer.readu8(Src, BOffset + 3)
				local B4 = buffer.readu8(Src, BOffset + 4)

				buffer.writeu32(Dst, POffset + 0, bit32.bor(B0, bit32.lshift(bit32.band(B1, 0x3), 8)))
				buffer.writeu32(Dst, POffset + 4, bit32.bor(bit32.rshift(B1, 2), bit32.lshift(bit32.band(B2, 0xF), 6)))
				buffer.writeu32(Dst, POffset + 8, bit32.bor(bit32.rshift(B2, 4), bit32.lshift(bit32.band(B3, 0x3F), 4)))
				buffer.writeu32(Dst, POffset + 12, bit32.bor(bit32.rshift(B3, 6), bit32.lshift(B4, 2)))
			end
		elseif Sbw == 13 then
			for J = 0, 31 do
				local BOffset = SrcOffset + J * 13
				local POffset = DstOffset + J * 32

				local B0 = buffer.readu8(Src, BOffset + 0)
				local B1 = buffer.readu8(Src, BOffset + 1)
				local B2 = buffer.readu8(Src, BOffset + 2)
				local B3 = buffer.readu8(Src, BOffset + 3)
				local B4 = buffer.readu8(Src, BOffset + 4)
				local B5 = buffer.readu8(Src, BOffset + 5)
				local B6 = buffer.readu8(Src, BOffset + 6)
				local B7 = buffer.readu8(Src, BOffset + 7)
				local B8 = buffer.readu8(Src, BOffset + 8)
				local B9 = buffer.readu8(Src, BOffset + 9)
				local B10 = buffer.readu8(Src, BOffset + 10)
				local B11 = buffer.readu8(Src, BOffset + 11)
				local B12 = buffer.readu8(Src, BOffset + 12)

				buffer.writeu32(Dst, POffset + 0, bit32.bor(B0, bit32.lshift(bit32.band(B1, 0x1F), 8)))
				buffer.writeu32(Dst, POffset + 4, bit32.bor(bit32.rshift(B1, 5), bit32.lshift(B2, 3), bit32.lshift(bit32.band(B3, 0x3), 11)))
				buffer.writeu32(Dst, POffset + 8, bit32.bor(bit32.rshift(B3, 2), bit32.lshift(bit32.band(B4, 0x7F), 6)))
				buffer.writeu32(Dst, POffset + 12, bit32.bor(bit32.rshift(B4, 7), bit32.lshift(B5, 1), bit32.lshift(bit32.band(B6, 0xF), 9)))
				buffer.writeu32(Dst, POffset + 16, bit32.bor(bit32.rshift(B6, 4), bit32.lshift(B7, 4), bit32.lshift(bit32.band(B8, 0x1), 12)))
				buffer.writeu32(Dst, POffset + 20, bit32.bor(bit32.rshift(B8, 1), bit32.lshift(bit32.band(B9, 0x3F), 7)))
				buffer.writeu32(Dst, POffset + 24, bit32.bor(bit32.rshift(B9, 6), bit32.lshift(B10, 2), bit32.lshift(bit32.band(B11, 0x7), 10)))
				buffer.writeu32(Dst, POffset + 28, bit32.bor(bit32.rshift(B11, 3), bit32.lshift(B12, 5)))
			end
		elseif Sbw == 18 then
			for J = 0, 63 do
				local BOffset = SrcOffset + J * 9
				local POffset = DstOffset + J * 16

				local B0 = buffer.readu8(Src, BOffset + 0)
				local B1 = buffer.readu8(Src, BOffset + 1)
				local B2 = buffer.readu8(Src, BOffset + 2)
				local B3 = buffer.readu8(Src, BOffset + 3)
				local B4 = buffer.readu8(Src, BOffset + 4)
				local B5 = buffer.readu8(Src, BOffset + 5)
				local B6 = buffer.readu8(Src, BOffset + 6)
				local B7 = buffer.readu8(Src, BOffset + 7)
				local B8 = buffer.readu8(Src, BOffset + 8)

				buffer.writeu32(Dst, POffset + 0, bit32.bor(B0, bit32.lshift(B1, 8), bit32.lshift(bit32.band(B2, 0x3), 16)))
				buffer.writeu32(Dst, POffset + 4, bit32.bor(bit32.rshift(B2, 2), bit32.lshift(B3, 6), bit32.lshift(bit32.band(B4, 0xF), 14)))
				buffer.writeu32(Dst, POffset + 8, bit32.bor(bit32.rshift(B4, 4), bit32.lshift(B5, 4), bit32.lshift(bit32.band(B6, 0x3F), 12)))
				buffer.writeu32(Dst, POffset + 12, bit32.bor(bit32.rshift(B6, 6), bit32.lshift(B7, 2), bit32.lshift(B8, 10)))
			end
		elseif Sbw == 20 then
			for J = 0, 63 do
				local BOffset = SrcOffset + J * 10
				local POffset = DstOffset + J * 16

				local B0 = buffer.readu8(Src, BOffset + 0)
				local B1 = buffer.readu8(Src, BOffset + 1)
				local B2 = buffer.readu8(Src, BOffset + 2)
				local B3 = buffer.readu8(Src, BOffset + 3)
				local B4 = buffer.readu8(Src, BOffset + 4)
				local B5 = buffer.readu8(Src, BOffset + 5)
				local B6 = buffer.readu8(Src, BOffset + 6)
				local B7 = buffer.readu8(Src, BOffset + 7)
				local B8 = buffer.readu8(Src, BOffset + 8)
				local B9 = buffer.readu8(Src, BOffset + 9)

				buffer.writeu32(Dst, POffset + 0, bit32.bor(B0, bit32.lshift(B1, 8), bit32.lshift(bit32.band(B2, 0xF), 16)))
				buffer.writeu32(Dst, POffset + 4, bit32.bor(bit32.rshift(B2, 4), bit32.lshift(B3, 4), bit32.lshift(B4, 12)))
				buffer.writeu32(Dst, POffset + 8, bit32.bor(B5, bit32.lshift(B6, 8), bit32.lshift(bit32.band(B7, 0xF), 16)))
				buffer.writeu32(Dst, POffset + 12, bit32.bor(bit32.rshift(B7, 4), bit32.lshift(B8, 4), bit32.lshift(B9, 12)))
			end
		else
			local ByteBuffer = buffer.create(PolyByteLength)
			local PolyBuffer = buffer.create(N * 4)
			buffer.copy(ByteBuffer, 0, Src, SrcOffset, PolyByteLength)
			BitPacking.Decode(ByteBuffer, PolyBuffer, Sbw)
			buffer.copy(Dst, DstOffset, PolyBuffer, 0, N * 4)
		end
	end
end

function PolyVec.HighBits(Src: buffer, Dst: buffer, K: number, Alpha: number)
	local T0 = bit32.rshift(Alpha, 1)
	local T1 = Q - 1
	local Modulus = Q
	local Num = N
	
	for I = 0, K - 1 do
		local Offset = I * Num * 4

		for J = 0, Num - 1 do
			local JOffset = Offset + J * 4
			local R = buffer.readu32(Src, JOffset)

			local T2 = R + T0 - 1
			local T3 = math.floor(T2 / Alpha)
			local T4 = T3 * Alpha

			local R0 = if R >= T4 then R - T4 else R - T4 + Modulus
			local T5 = if R >= R0 then R - R0 else R - R0 + Modulus

			local Flag = (T5 == T1)
			local R1 = if Flag then 0 else T3

			buffer.writeu32(Dst, JOffset, R1)
		end
	end
end

function PolyVec.LowBits(Src: buffer, Dst: buffer, K: number, Alpha: number)
	local T0 = bit32.rshift(Alpha, 1)
	local T1 = Q - 1
	
	local Modulus = Q
	local Num = N
	
	for I = 0, K - 1 do
		local Offset = I * Num * 4

		for J = 0, Num - 1 do
			local JOffset = Offset + J * 4
			local R = buffer.readu32(Src, JOffset)

			local T2 = R + T0 - 1
			local T3 = math.floor(T2 / Alpha)
			local T4 = T3 * Alpha

			local R0 = if R >= T4 then R - T4 else R - T4 + Modulus
			local T5 = if R >= R0 then R - R0 else R - R0 + Modulus

			local Flag = (T5 == T1)
			local R0_ = if Flag then (if R0 >= 1 then R0 - 1 else R0 - 1 + Modulus) else R0

			buffer.writeu32(Dst, JOffset, R0_)
		end
	end
end

function PolyVec.MultiplyByPoly(PolyBuffer: buffer, SrcVec: buffer, DstVec: buffer, K: number)
	local Modulus = Q
	local Num = N
	
	for I = 0, K - 1 do
		local Offset = I * Num * 4

		for J = 0, Num - 1 do
			local JOffset = Offset + J * 4
			local PolyValue = buffer.readu32(PolyBuffer, J * 4)
			local SrcValue = buffer.readu32(SrcVec, JOffset)

			local Product = (PolyValue * SrcValue) % Modulus

			buffer.writeu32(DstVec, JOffset, Product)
		end
	end
end

function PolyVec.InfinityNorm(Vec: buffer, K: number): number
	local Result = 0
	local QBy2 = math.floor(Q / 2)
	local Modulus = Q
	local Num = N
	
	for I = 0, K - 1 do
		local Offset = I * Num * 4

		for J = 0, Num - 1 do
			local JOffset = Offset + J * 4
			local PolyValue = buffer.readu32(Vec, JOffset)

			local CurrentValue = if PolyValue > QBy2 then (if PolyValue == 0 then 0 else Modulus - PolyValue) else PolyValue
			if CurrentValue > Result then
				Result = CurrentValue
			end
		end
	end

	return Result
end

function PolyVec.MakeHint(PolyA: buffer, PolyB: buffer, PolyC: buffer, K: number, Alpha: number)
	local T0 = bit32.rshift(Alpha, 1)
	local T1 = Q - 1

	local Num = N
	local Modulus = Q
	
	for I = 0, K - 1 do
		local Offset = I * Num * 4

		for J = 0, Num - 1 do
			local JOffset = Offset + J * 4
			local Z = buffer.readu32(PolyA, JOffset)
			local R = buffer.readu32(PolyB, JOffset)

			local T2_R = R + T0 - 1
			local T3_R = math.floor(T2_R / Alpha)
			local T4_R = T3_R * Alpha
			local R0_R = if R >= T4_R then R - T4_R else R - T4_R + Modulus
			local T5_R = if R >= R0_R then R - R0_R else R - R0_R + Modulus
			local Flag_R = (T5_R == T1)
			local R1 = if Flag_R then 0 else T3_R

			local Sum = R + Z
			Sum = if Sum >= Modulus then Sum - Modulus else Sum

			local T2_V = Sum + T0 - 1
			local T3_V = math.floor(T2_V / Alpha)
			local T4_V = T3_V * Alpha
			local R0_V = if Sum >= T4_V then Sum - T4_V else Sum - T4_V + Modulus
			local T5_V = if Sum >= R0_V then Sum - R0_V else Sum - R0_V + Modulus
			local Flag_V = (T5_V == T1)
			local V1 = if Flag_V then 0 else T3_V

			local Hint = if R1 ~= V1 then 1 else 0
			buffer.writeu32(PolyC, JOffset, Hint)
		end
	end
end

function PolyVec.UseHint(PolyH: buffer, PolyR: buffer, PolyRZ: buffer, K: number, Alpha: number)
	local M = math.floor((Q - 1) / Alpha)
	local T0 = bit32.rshift(Alpha, 1)
	local T1 = Q - T0
	local T1_Q = Q - 1
	local Modulus = Q

	for I = 0, K - 1 do
		local Offset = I * N * 4

		for J = 0, N - 1 do
			local JOffset = Offset + J * 4
			local H = buffer.readu32(PolyH, JOffset)
			local R = buffer.readu32(PolyR, JOffset)

			local T2 = R + T0 - 1
			local T3 = math.floor(T2 / Alpha)
			local T4 = T3 * Alpha
			
			local R0 = if R >= T4 then R - T4 else R - T4 + Modulus
			
			local T5 = if R >= R0 then R - R0 else R - R0 + Modulus
			local Flag = (T5 == T1_Q)
			
			local R1 = if Flag then 0 else T3
			local R0_ = if Flag then (if R0 >= 1 then R0 - 1 else R0 - 1 + Modulus) else R0

			if H == 1 then
				if R0_ > 0 and R0_ < T1 then
					R1 += 1
				else
					R1 -= 1
				end
			end

			buffer.writeu32(PolyRZ, JOffset, (R1 % M + M) % M)
		end
	end
end

function PolyVec.Count1s(Vec: buffer, K: number): number
	local Count = 0

	for I = 0, K * N - 1 do
		local Value = buffer.readu32(Vec, I * 4)
		Count += Value
	end

	return Count
end

function PolyVec.LeftShift(Vec: buffer, K: number, D: number)
	local Num = N
	local Modulus = Q
	
	for I = 0, K - 1 do
		local Offset = I * Num * 4

		for J = 0, Num - 1 do
			local JOffset = Offset + J * 4
			local PolyValue = buffer.readu32(Vec, JOffset)

			local Shifted = bit32.lshift(PolyValue, D)
			local Result = if Shifted >= Modulus then Shifted % Modulus else Shifted

			buffer.writeu32(Vec, JOffset, Result)
		end
	end
end

function PolyVec.Copy(Src: buffer, Dst: buffer, K: number)
	buffer.copy(Dst, 0, Src, 0, K * N * 4)
end

return PolyVec