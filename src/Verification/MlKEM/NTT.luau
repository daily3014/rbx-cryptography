--[=[
	ML-KEM Number Theoretic Transform Module
	
	Number Theoretic Transform (NTT) operations for polynomial multiplication.
	Cooley-Tukey NTT and Gentleman-Sande inverse NTT algorithms
		
	Example usage:
		local NTT = require(script.NTT)
		
		local Poly = buffer.create(512) -- 256 coefficients * 2 bytes
		NTT.Ntt(Poly) -- Forward transform
		NTT.Intt(Poly) -- Inverse transform
--]=]

--!strict
--!optimize 2
--!native

local Field = require("./Field")
local Utils = require("./Utils")

local LOG2N = 8
local N = 2^LOG2N

local Q = 3329
local ZETA = 17
local INV_N = Field.Invert(N / 2)

local Ntt = {}

local NTT_ZETA_EXP = buffer.create((N / 2) * 2) do
	for I = 0, N / 2 - 1 do
		local BitRevIndex = Utils.BitReverse(I, LOG2N - 1)
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
		local BitRevIndex = Utils.BitReverse(I, LOG2N - 1)
		local Exponent = bit32.bxor(bit32.lshift(BitRevIndex, 1), 1)
		local ZetaExp = Field.Power(ZETA, Exponent)
		buffer.writeu16(POLY_MUL_ZETA_EXP, I * 2, ZetaExp)
	end
end

local POWERS_OF_TWO = table.create(LOG2N)
for I = 0, LOG2N - 1 do
	POWERS_OF_TWO[I] = {2^I, (2^I) * 2}
end

function Ntt.Ntt(Poly: buffer)
	local Zeta = NTT_ZETA_EXP
	local Powers = POWERS_OF_TWO
	local Modulus = Q
	
	for L = LOG2N - 1, 1, -1 do
		local Len = Powers[L][1]
		local LenX2 = Powers[L][2]
		local KBeg = bit32.rshift(N, L + 1)

		for Start = 0, N - 1, LenX2 do
			local KNow = KBeg + bit32.rshift(Start, L + 1)
			local ZetaExp = buffer.readu16(Zeta, KNow * 2)

			for I = Start, Start + Len - 1 do
				local OffsetI = I * 2
				local OffsetILen = (I + Len) * 2

				local PolyI = buffer.readu16(Poly, OffsetI)
				local PolyILen = buffer.readu16(Poly, OffsetILen)

				local Tmp = (ZetaExp * PolyILen) % Modulus

				local SubResult = if PolyI >= Tmp then PolyI - Tmp else PolyI - Tmp + Modulus

				local Sum = PolyI + Tmp
				local AddResult = if Sum >= Modulus then Sum - Modulus else Sum

				buffer.writeu16(Poly, OffsetILen, SubResult)
				buffer.writeu16(Poly, OffsetI, AddResult)
			end
		end
	end
end

function Ntt.Intt(Poly: buffer)
	local Zeta = INTT_ZETA_EXP
	local InvN = INV_N
	local Powers = POWERS_OF_TWO
	local Modulus = Q
	
	for L = 1, LOG2N - 1 do
		local Len = Powers[L][1]
		local LenX2 = Powers[L][2]
		local KBeg = bit32.rshift(N, L) - 1

		for Start = 0, N - 1, LenX2 do
			local KNow = KBeg - bit32.rshift(Start, L + 1)
			local NegZetaExp = buffer.readu16(Zeta, KNow * 2)

			for I = Start, Start + Len - 1 do
				local OffsetI = I * 2
				local OffsetILen = (I + Len) * 2

				local PolyI = buffer.readu16(Poly, OffsetI)
				local PolyILen = buffer.readu16(Poly, OffsetILen)

				local Sum = PolyI + PolyILen
				
				local AddResult = if Sum >= Modulus then Sum - Modulus else Sum
				local SubResult = if PolyI >= PolyILen then PolyI - PolyILen else PolyI - PolyILen + Modulus

				local MulResult = (SubResult * NegZetaExp) % Modulus

				buffer.writeu16(Poly, OffsetI, AddResult)
				buffer.writeu16(Poly, OffsetILen, MulResult)
			end
		end
	end

	for I = 0, N - 1 do
		local Offset = I * 2
		local Coeff = buffer.readu16(Poly, Offset)

		local Scaled = (Coeff * InvN) % Q
		buffer.writeu16(Poly, Offset, Scaled)
	end
end

function Ntt.PolyMul(F: buffer, G: buffer, H: buffer)
	local PolyZeta = POLY_MUL_ZETA_EXP
	local Modulus = Q
	
	for I = 0, N / 2 - 1 do
		local Offset = I * 4
		local ZetaExp = buffer.readu16(PolyZeta, I * 2)

		local F0 = buffer.readu16(F, Offset)
		local F1 = buffer.readu16(F, Offset + 2)
		local G0 = buffer.readu16(G, Offset)
		local G1 = buffer.readu16(G, Offset + 2)

		local Mul1 = (F0 * G0) % Modulus
		local Mul2 = (F1 * G1) % Modulus
		local Mul3 = (Mul2 * ZetaExp) % Modulus

		local Sum0 = Mul1 + Mul3
		local H0 = if Sum0 >= Modulus then Sum0 - Modulus else Sum0

		local Mul4 = (F0 * G1) % Modulus
		local Mul5 = (F1 * G0) % Modulus

		local Sum1 = Mul4 + Mul5
		local H1 = if Sum1 >= Modulus then Sum1 - Modulus else Sum1

		buffer.writeu16(H, Offset, H0)
		buffer.writeu16(H, Offset + 2, H1)
	end
end

function Ntt.PolyAdd(F: buffer, G: buffer, H: buffer)
	local Modulus = Q
	for Index = 0, N - 1 do
		local Offset = Index * 2
		local AValue = buffer.readu16(F, Offset)
		local BValue = buffer.readu16(G, Offset)

		local Sum = AValue + BValue
		local Result = if Sum >= Modulus then Sum - Modulus else Sum
		buffer.writeu16(H, Offset, Result)
	end
end

function Ntt.PolySub(F: buffer, G: buffer, H: buffer)
	local Modulus = Q
	for Index = 0, N - 1 do
		local Offset = Index * 2
		local AValue = buffer.readu16(F, Offset)
		local BValue = buffer.readu16(G, Offset)
		
		local Diff = AValue - BValue
		local Result = if Diff < 0 then Diff + Modulus else Diff
		buffer.writeu16(H, Offset, Result)
	end
end

return Ntt