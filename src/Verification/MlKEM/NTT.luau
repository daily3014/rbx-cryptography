--[=[
	ML-KEM Number Theoretic Transform Module
	
	Number Theoretic Transform (NTT) operations for polynomial multiplication.
	Cooley-Tukey NTT and Gentleman-Sande inverse NTT algorithms
		
	Example usage:
		local NTT = require(script.NTT)
		
		local Poly = buffer.create(512) -- 256 coefficients * 2 bytes
		NTT.Ntt(Poly) -- Forward transform
		NTT.Intt(Poly) -- Inverse transform
		
		local Result = NTT.PolyMulComplete(PolyA, PolyB)
--]=]

--!strict
--!optimize 2
--!native

local Field = require("./Field")

local LOG2N = 8
local N = 2^LOG2N

local Q = 13 * 256 + 1
local ZETA = 17
local INV_N = Field.Invert(N / 2)

local Ntt = {}

local function BitReverse(Value: number, BitWidth: number): number
	local Reversed = 0
	for I = 0, BitWidth - 1 do
		local Bit = bit32.band(bit32.rshift(Value, I), 1)
		Reversed = bit32.bor(Reversed, bit32.lshift(Bit, BitWidth - 1 - I))
	end

	return Reversed
end

local NTT_ZETA_EXP = buffer.create((N / 2) * 2) do
	for I = 0, N / 2 - 1 do
		local BitRevIndex = BitReverse(I, LOG2N - 1)
		local ZetaExp = Field.Power(ZETA, BitRevIndex)
		buffer.writeu16(NTT_ZETA_EXP, I * 2, ZetaExp)
	end
end

local INTT_ZETA_EXP = buffer.create((N / 2) * 2) do
	for I = 0, N / 2 - 1 do
		local NttZeta = buffer.readu16(NTT_ZETA_EXP, I * 2)
		local NegZeta = if NttZeta == 0 then 0 else Q - NttZeta
		buffer.writeu16(INTT_ZETA_EXP, I * 2, NegZeta)
	end
end

local POLY_MUL_ZETA_EXP = buffer.create((N / 2) * 2) do
	for I = 0, N / 2 - 1 do
		local BitRevIndex = BitReverse(I, LOG2N - 1)
		local Exponent = bit32.bxor(bit32.lshift(BitRevIndex, 1), 1)
		local ZetaExp = Field.Power(ZETA, Exponent)
		buffer.writeu16(POLY_MUL_ZETA_EXP, I * 2, ZetaExp)
	end
end

function Ntt.Ntt(Poly: buffer)
	local Zeta = NTT_ZETA_EXP
	
	for L = LOG2N - 1, 1, -1 do
		local Len = 2^L
		local LenX2 = Len * 2
		local KBeg = bit32.rshift(N, L + 1)

		for Start = 0, N - 1, LenX2 do
			local KNow = KBeg + bit32.rshift(Start, L + 1)
			local ZetaExp = buffer.readu16(Zeta, KNow * 2)

			for I = Start, Start + Len - 1 do
				local PolyI = buffer.readu16(Poly, I * 2)
				local PolyILen = buffer.readu16(Poly, (I + Len) * 2)

				local Tmp = Field.Multiply(ZetaExp, PolyILen)

				local T0 = PolyI - Tmp
				local T1 = if T0 >= 0 then 0 else 0xFFFFFFFF
				local T2 = bit32.band(Q, T1)
				local SubResult = T0 + T2

				local AddResult
				local T3 = PolyI + Tmp
				local T4 = T3 - Q
				local T5 = if T4 >= 0 then 0 else 0xFFFFFFFF
				local T6 = bit32.band(Q, T5)
				AddResult = T4 + T6

				buffer.writeu16(Poly, (I + Len) * 2, SubResult)
				buffer.writeu16(Poly, I * 2, AddResult)
			end
		end
	end
end

function Ntt.Intt(Poly: buffer)
	local Zeta = INTT_ZETA_EXP
	local InvIN = INV_N
	for L = 1, LOG2N - 1 do
		local Len = 2^L
		local LenX2 = Len * 2
		local KBeg = bit32.rshift(N, L) - 1

		for Start = 0, N - 1, LenX2 do
			local KNow = KBeg - bit32.rshift(Start, L + 1)
			local NegZetaExp = buffer.readu16(Zeta, KNow * 2)

			for I = Start, Start + Len - 1 do
				local PolyI = buffer.readu16(Poly, I * 2)
				local PolyILen = buffer.readu16(Poly, (I + Len) * 2)

				local Tmp = PolyI

				local T0 = PolyI + PolyILen
				local T1 = T0 - Q
				local T2 = if T1 >= 0 then 0 else 0xFFFFFFFF
				local T3 = bit32.band(Q, T2)
				local AddResult = T1 + T3

				local SubTmp = Tmp - PolyILen
				local T4 = if SubTmp >= 0 then 0 else 0xFFFFFFFF
				local T5 = bit32.band(Q, T4)
				local SubResult = SubTmp + T5

				buffer.writeu16(Poly, I * 2, AddResult)
				buffer.writeu16(Poly, (I + Len) * 2, Field.Multiply(SubResult, NegZetaExp))
			end
		end
	end

	for I = 0, N - 1 do
		local Coeff = buffer.readu16(Poly, I * 2)
		buffer.writeu16(Poly, I * 2, Field.Multiply(Coeff, InvIN))
	end
end

local function BaseMul(F0: number, F1: number, G0: number, G1: number, Zeta: number): (number, number)
	local Mul1 = Field.Multiply(F0, G0)
	local Mul2 = Field.Multiply(F1, G1)
	local Mul3 = Field.Multiply(Mul2, Zeta)

	local T0 = Mul1 + Mul3
	local T1 = T0 - Q
	local T2 = if T1 >= 0 then 0 else 0xFFFFFFFF
	local T3 = bit32.band(Q, T2)
	local H0 = T1 + T3

	local Mul4 = Field.Multiply(F0, G1)
	local Mul5 = Field.Multiply(F1, G0)

	local T4 = Mul4 + Mul5
	local T5 = T4 - Q
	local T6 = if T5 >= 0 then 0 else 0xFFFFFFFF
	local T7 = bit32.band(Q, T6)
	local H1 = T5 + T7

	return H0, H1
end

function Ntt.PolyMul(F: buffer, G: buffer, H: buffer)
	local PolyZeta = POLY_MUL_ZETA_EXP
	for I = 0, N / 2 - 1 do
		local Offset = I * 4
		local ZetaExp = buffer.readu16(PolyZeta, I * 2)

		local F0 = buffer.readu16(F, Offset)
		local F1 = buffer.readu16(F, Offset + 2)
		local G0 = buffer.readu16(G, Offset)
		local G1 = buffer.readu16(G, Offset + 2)

		local H0, H1 = BaseMul(F0, F1, G0, G1, ZetaExp)

		buffer.writeu16(H, Offset, H0)
		buffer.writeu16(H, Offset + 2, H1)
	end
end

function Ntt.PolyMulComplete(F: buffer, G: buffer): buffer
	local FCopy = buffer.create(N * 2)
	local GCopy = buffer.create(N * 2)
	local Result = buffer.create(N * 2)

	buffer.copy(FCopy, 0, F, 0, N * 2)
	buffer.copy(GCopy, 0, G, 0, N * 2)

	Ntt.Ntt(FCopy)
	Ntt.Ntt(GCopy)

	Ntt.PolyMul(FCopy, GCopy, Result)
	Ntt.Intt(Result)

	return Result
end

function Ntt.PolyAdd(F: buffer, G: buffer, H: buffer)
	for Index = 0, N - 1 do
		local AValue = buffer.readu16(F, Index * 2)
		local BValue = buffer.readu16(G, Index * 2)

		local T0 = AValue + BValue
		local T1 = T0 - Q
		local T2 = if T1 >= 0 then 0 else 0xFFFFFFFF
		local T3 = bit32.band(Q, T2)
		local AddResult = T1 + T3

		buffer.writeu16(H, Index * 2, AddResult)
	end
end

function Ntt.PolySub(F: buffer, G: buffer, H: buffer)
	for Index = 0, N - 1 do
		local AValue = buffer.readu16(F, Index * 2)
		local BValue = buffer.readu16(G, Index * 2)

		local NegB = if BValue == 0 then 0 else Q - BValue
		local T0 = AValue + NegB
		local T1 = T0 - Q
		local T2 = if T1 >= 0 then 0 else 0xFFFFFFFF
		local T3 = bit32.band(Q, T2)
		local SubResult = T1 + T3

		buffer.writeu16(H, Index * 2, SubResult)
	end
end

return Ntt