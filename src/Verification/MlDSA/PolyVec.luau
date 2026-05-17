--[=[
	Vector operations on degree-255 polynomials
	
	Works on vectors of polynomials including matrix multiplication,
	NTT transforms, and encoding/decoding for ML-DSA.

	Example usage:
		local PolyVec = require(script)
		
		local Vec = buffer.create(4 * 256 * 4) -- 4 polynomials
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
	local NegZeta7 = (buffer.readu32(Zeta, 4) * InvN) % Modulus

	for I = 0, K - 1 do
		local Offset = I * Num * 4

		for L = 0, 6 do
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

					local Product = ((PolyJ - PolyJLen) * NegZetaExpValue) % Modulus

					buffer.writeu32(Vec, JOffset, (PolyJ + PolyJLen) % Modulus)
					buffer.writeu32(Vec, JLenOffset, Product)
				end
			end
		end

		for J = 0, 127 do
			local JOffset = Offset + J * 4
			local JLenOffset = Offset + (J + 128) * 4

			local PolyJ = buffer.readu32(Vec, JOffset)
			local PolyJLen = buffer.readu32(Vec, JLenOffset)

			buffer.writeu32(Vec, JOffset, ((PolyJ + PolyJLen) * InvN) % Modulus)
			buffer.writeu32(Vec, JLenOffset, ((PolyJ - PolyJLen) * NegZeta7) % Modulus)
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
			local Lo = (R - T3) % Modulus

			buffer.writeu32(PolyHi, JOffset, Hi)
			buffer.writeu32(PolyLo, JOffset, Lo)
		end
	end
end

function PolyVec.MatrixMultiply(A: buffer, B: buffer, C: buffer, ARows: number, ACols: number, BRows: number, BCols: number)
	local Num = N
	local Modulus = Q
	local PolyByteSize = Num * 4

	for I = 0, ARows - 1 do
		local ARowBase = I * ACols * PolyByteSize
		for J = 0, BCols - 1 do
			local COffset = (I * BCols + J) * PolyByteSize

			for L = 0, Num - 1 do
				local ElementOffset = L * 4
				local Acc = 0

				for K = 0, ACols - 1 do
					local AValue = buffer.readu32(A, ARowBase + K * PolyByteSize + ElementOffset)
					local BValue = buffer.readu32(B, (K * BCols + J) * PolyByteSize + ElementOffset)
					Acc += AValue * BValue
				end

				buffer.writeu32(C, COffset + ElementOffset, Acc % Modulus)
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
		buffer.writeu32(Dst, Offset, (DstValue + SrcValue) % Modulus)
	end
end

function PolyVec.Negate(Vec: buffer, K: number)
	local TotalElements = K * N
	local Modulus = Q

	for I = 0, TotalElements - 1 do
		local Offset = I * 4
		local Value = buffer.readu32(Vec, Offset)
		buffer.writeu32(Vec, Offset, (Modulus - Value) % Modulus)
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
			buffer.writeu32(Vec, JOffset, (X - PolyValue) % Modulus)
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
			for J = 0, 31 do
				local POffset = SrcOffset + J * 32
				local BOffset = DstOffset + J * 4

				local P0 = bit32.band(buffer.readu32(Src, POffset + 0), 0xF)
				local P1 = bit32.band(buffer.readu32(Src, POffset + 4), 0xF)
				local P2 = bit32.band(buffer.readu32(Src, POffset + 8), 0xF)
				local P3 = bit32.band(buffer.readu32(Src, POffset + 12), 0xF)
				local P4 = bit32.band(buffer.readu32(Src, POffset + 16), 0xF)
				local P5 = bit32.band(buffer.readu32(Src, POffset + 20), 0xF)
				local P6 = bit32.band(buffer.readu32(Src, POffset + 24), 0xF)
				local P7 = bit32.band(buffer.readu32(Src, POffset + 28), 0xF)

				buffer.writeu32(Dst, BOffset, bit32.bor(
					P0, bit32.lshift(P1, 4), bit32.lshift(P2, 8), bit32.lshift(P3, 12),
					bit32.lshift(P4, 16), bit32.lshift(P5, 20), bit32.lshift(P6, 24), bit32.lshift(P7, 28)
				))
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

				local Lo = bit32.bor(P0, bit32.lshift(P1, 10), bit32.lshift(P2, 20), bit32.lshift(bit32.band(P3, 0x3), 30))
				local Hi = bit32.rshift(P3, 2)

				buffer.writeu32(Dst, BOffset, Lo)
				buffer.writeu8(Dst, BOffset + 4, Hi)
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

				local W0 = bit32.bor(P0, bit32.lshift(P1, 13), bit32.lshift(P2, 26))
				local W1 = bit32.bor(bit32.rshift(P2, 6), bit32.lshift(P3, 7), bit32.lshift(P4, 20))
				local W2 = bit32.bor(bit32.rshift(P4, 12), bit32.lshift(P5, 1), bit32.lshift(P6, 14), bit32.lshift(P7, 27))
				local W3 = bit32.rshift(P7, 5)

				buffer.writeu32(Dst, BOffset, W0)
				buffer.writeu32(Dst, BOffset + 4, W1)
				buffer.writeu32(Dst, BOffset + 8, W2)
				buffer.writeu8(Dst, BOffset + 12, W3)
			end
		elseif Sbw == 18 then
			for J = 0, 63 do
				local POffset = SrcOffset + J * 16
				local BOffset = DstOffset + J * 9

				local P0 = bit32.band(buffer.readu32(Src, POffset + 0), 0x3FFFF)
				local P1 = bit32.band(buffer.readu32(Src, POffset + 4), 0x3FFFF)
				local P2 = bit32.band(buffer.readu32(Src, POffset + 8), 0x3FFFF)
				local P3 = bit32.band(buffer.readu32(Src, POffset + 12), 0x3FFFF)

				local W0 = bit32.bor(P0, bit32.lshift(P1, 18))
				local W1 = bit32.bor(bit32.rshift(P1, 14), bit32.lshift(P2, 4), bit32.lshift(P3, 22))
				local W2 = bit32.rshift(P3, 10)

				buffer.writeu32(Dst, BOffset, W0)
				buffer.writeu32(Dst, BOffset + 4, W1)
				buffer.writeu8(Dst, BOffset + 8, W2)
			end
		elseif Sbw == 20 then
			for J = 0, 63 do
				local POffset = SrcOffset + J * 16
				local BOffset = DstOffset + J * 10

				local P0 = bit32.band(buffer.readu32(Src, POffset + 0), 0xFFFFF)
				local P1 = bit32.band(buffer.readu32(Src, POffset + 4), 0xFFFFF)
				local P2 = bit32.band(buffer.readu32(Src, POffset + 8), 0xFFFFF)
				local P3 = bit32.band(buffer.readu32(Src, POffset + 12), 0xFFFFF)

				local W0 = bit32.bor(P0, bit32.lshift(P1, 20))
				local W1 = bit32.bor(bit32.rshift(P1, 12), bit32.lshift(P2, 8), bit32.lshift(P3, 28))
				local W2 = bit32.rshift(P3, 4)

				buffer.writeu32(Dst, BOffset, W0)
				buffer.writeu32(Dst, BOffset + 4, W1)
				buffer.writeu16(Dst, BOffset + 8, W2)
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
			for J = 0, 31 do
				local BOffset = SrcOffset + J * 4
				local POffset = DstOffset + J * 32

				local Word = buffer.readu32(Src, BOffset)

				buffer.writeu32(Dst, POffset + 0, bit32.band(Word, 0xF))
				buffer.writeu32(Dst, POffset + 4, bit32.band(bit32.rshift(Word, 4), 0xF))
				buffer.writeu32(Dst, POffset + 8, bit32.band(bit32.rshift(Word, 8), 0xF))
				buffer.writeu32(Dst, POffset + 12, bit32.band(bit32.rshift(Word, 12), 0xF))
				buffer.writeu32(Dst, POffset + 16, bit32.band(bit32.rshift(Word, 16), 0xF))
				buffer.writeu32(Dst, POffset + 20, bit32.band(bit32.rshift(Word, 20), 0xF))
				buffer.writeu32(Dst, POffset + 24, bit32.band(bit32.rshift(Word, 24), 0xF))
				buffer.writeu32(Dst, POffset + 28, bit32.rshift(Word, 28))
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

				local Lo = buffer.readu32(Src, BOffset)
				local Hi = buffer.readu8(Src, BOffset + 4)

				buffer.writeu32(Dst, POffset + 0, bit32.band(Lo, 0x3FF))
				buffer.writeu32(Dst, POffset + 4, bit32.band(bit32.rshift(Lo, 10), 0x3FF))
				buffer.writeu32(Dst, POffset + 8, bit32.band(bit32.rshift(Lo, 20), 0x3FF))
				buffer.writeu32(Dst, POffset + 12, bit32.bor(bit32.rshift(Lo, 30), bit32.lshift(Hi, 2)))
			end
		elseif Sbw == 13 then
			for J = 0, 31 do
				local BOffset = SrcOffset + J * 13
				local POffset = DstOffset + J * 32

				local W0 = buffer.readu32(Src, BOffset)
				local W1 = buffer.readu32(Src, BOffset + 4)
				local W2 = buffer.readu32(Src, BOffset + 8)
				local W3 = buffer.readu8(Src, BOffset + 12)

				buffer.writeu32(Dst, POffset + 0, bit32.band(W0, 0x1FFF))
				buffer.writeu32(Dst, POffset + 4, bit32.band(bit32.rshift(W0, 13), 0x1FFF))
				buffer.writeu32(Dst, POffset + 8, bit32.bor(bit32.rshift(W0, 26), bit32.lshift(bit32.band(W1, 0x7F), 6)))
				buffer.writeu32(Dst, POffset + 12, bit32.band(bit32.rshift(W1, 7), 0x1FFF))
				buffer.writeu32(Dst, POffset + 16, bit32.bor(bit32.rshift(W1, 20), bit32.lshift(bit32.band(W2, 0x1), 12)))
				buffer.writeu32(Dst, POffset + 20, bit32.band(bit32.rshift(W2, 1), 0x1FFF))
				buffer.writeu32(Dst, POffset + 24, bit32.band(bit32.rshift(W2, 14), 0x1FFF))
				buffer.writeu32(Dst, POffset + 28, bit32.bor(bit32.rshift(W2, 27), bit32.lshift(W3, 5)))
			end
		elseif Sbw == 18 then
			for J = 0, 63 do
				local BOffset = SrcOffset + J * 9
				local POffset = DstOffset + J * 16

				local W0 = buffer.readu32(Src, BOffset)
				local W1 = buffer.readu32(Src, BOffset + 4)
				local W2 = buffer.readu8(Src, BOffset + 8)

				buffer.writeu32(Dst, POffset + 0, bit32.band(W0, 0x3FFFF))
				buffer.writeu32(Dst, POffset + 4, bit32.bor(bit32.rshift(W0, 18), bit32.lshift(bit32.band(W1, 0xF), 14)))
				buffer.writeu32(Dst, POffset + 8, bit32.band(bit32.rshift(W1, 4), 0x3FFFF))
				buffer.writeu32(Dst, POffset + 12, bit32.bor(bit32.rshift(W1, 22), bit32.lshift(W2, 10)))
			end
		elseif Sbw == 20 then
			for J = 0, 63 do
				local BOffset = SrcOffset + J * 10
				local POffset = DstOffset + J * 16

				local W0 = buffer.readu32(Src, BOffset)
				local W1 = buffer.readu32(Src, BOffset + 4)
				local W2 = buffer.readu16(Src, BOffset + 8)

				buffer.writeu32(Dst, POffset + 0, bit32.band(W0, 0xFFFFF))
				buffer.writeu32(Dst, POffset + 4, bit32.bor(bit32.rshift(W0, 20), bit32.lshift(bit32.band(W1, 0xFF), 12)))
				buffer.writeu32(Dst, POffset + 8, bit32.band(bit32.rshift(W1, 8), 0xFFFFF))
				buffer.writeu32(Dst, POffset + 12, bit32.bor(bit32.rshift(W1, 28), bit32.lshift(W2, 4)))
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
	local M = math.floor((Q - 1) / Alpha)
	local Num = N

	for I = 0, K - 1 do
		local Offset = I * Num * 4

		for J = 0, Num - 1 do
			local JOffset = Offset + J * 4
			local R = buffer.readu32(Src, JOffset)

			local T3 = math.floor((R + T0 - 1) / Alpha)
			buffer.writeu32(Dst, JOffset, if T3 == M then 0 else T3)
		end
	end
end

function PolyVec.LowBits(Src: buffer, Dst: buffer, K: number, Alpha: number)
	local T0 = bit32.rshift(Alpha, 1)
	local M = math.floor((Q - 1) / Alpha)
	local Modulus = Q
	local Num = N

	for I = 0, K - 1 do
		local Offset = I * Num * 4

		for J = 0, Num - 1 do
			local JOffset = Offset + J * 4
			local R = buffer.readu32(Src, JOffset)

			local T3 = math.floor((R + T0 - 1) / Alpha)
			local R0 = (R - T3 * Alpha) % Modulus
			buffer.writeu32(Dst, JOffset, if T3 == M then (R0 - 1) % Modulus else R0)
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
	local M = math.floor((Q - 1) / Alpha)
	local Num = N
	local Modulus = Q

	for I = 0, K - 1 do
		local Offset = I * Num * 4

		for J = 0, Num - 1 do
			local JOffset = Offset + J * 4
			local Z = buffer.readu32(PolyA, JOffset)
			local R = buffer.readu32(PolyB, JOffset)

			local T3_R = math.floor((R + T0 - 1) / Alpha)
			local R1 = if T3_R == M then 0 else T3_R

			local Sum = (R + Z) % Modulus
			local T3_V = math.floor((Sum + T0 - 1) / Alpha)
			local V1 = if T3_V == M then 0 else T3_V

			buffer.writeu32(PolyC, JOffset, if R1 ~= V1 then 1 else 0)
		end
	end
end

function PolyVec.UseHint(PolyH: buffer, PolyR: buffer, PolyRZ: buffer, K: number, Alpha: number)
	local M = math.floor((Q - 1) / Alpha)
	local T0 = bit32.rshift(Alpha, 1)
	local T1 = Q - T0
	local Modulus = Q

	for I = 0, K - 1 do
		local Offset = I * N * 4

		for J = 0, N - 1 do
			local JOffset = Offset + J * 4
			local H = buffer.readu32(PolyH, JOffset)
			local R = buffer.readu32(PolyR, JOffset)

			local T3 = math.floor((R + T0 - 1) / Alpha)
			local R0 = (R - T3 * Alpha) % Modulus
			local Flag = T3 == M

			local R1 = if Flag then 0 else T3
			local R0_ = if Flag then (R0 - 1) % Modulus else R0

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