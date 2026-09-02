--[=[
	ML-KEM Number Theoretic Transform Module

	Number Theoretic Transform (NTT) operations for polynomial multiplication.
	Cooley-Tukey NTT and Gentleman-Sande inverse NTT algorithms
	
	Example usage:
		local Poly = buffer.create(512) -- 256 coefficients * 2 bytes
		NTT.NttAt(Poly, 0) -- Forward transform
		NTT.InttAt(Poly, 0) -- Inverse transform
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

local POWERS_OF_TWO = table.create(LOG2N) :: {{number}}
for I = 0, LOG2N - 1 do
	POWERS_OF_TWO[I] = {2^I, (2^I) * 2}
end

local function InttLevelsLazy(Poly: buffer, BaseOffset: number, LFrom: number, LTo: number)
	local Zeta = INTT_ZETA_EXP
	local Powers = POWERS_OF_TWO
	local Modulus = Q

	for L = LFrom, LTo do
		local Len = Powers[L][1]
		local LenX2 = Powers[L][2]
		local KBeg = bit32.rshift(N, L) - 1

		for Start = 0, N - 1, LenX2 do
			local KNow = KBeg - bit32.rshift(Start, L + 1)
			local NegZetaExp = buffer.readu16(Zeta, KNow * 2)

			for I = Start, Start + Len - 1, 2 do
				local OffsetA = BaseOffset + I * 2
				local OffsetALen = OffsetA + LenX2
				local OffsetB = OffsetA + 2
				local OffsetBLen = OffsetB + LenX2

				local PolyA = buffer.readu16(Poly, OffsetA)
				local PolyALen = buffer.readu16(Poly, OffsetALen)
				local PolyB = buffer.readu16(Poly, OffsetB)
				local PolyBLen = buffer.readu16(Poly, OffsetBLen)

				buffer.writeu16(Poly, OffsetALen, ((PolyA - PolyALen) * NegZetaExp) % Modulus)
				buffer.writeu16(Poly, OffsetBLen, ((PolyB - PolyBLen) * NegZetaExp) % Modulus)
				buffer.writeu16(Poly, OffsetA, PolyA + PolyALen)
				buffer.writeu16(Poly, OffsetB, PolyB + PolyBLen)
			end
		end
	end
end

local function InttLevelReduce(Poly: buffer, BaseOffset: number, L: number)
	local Zeta = INTT_ZETA_EXP
	local Powers = POWERS_OF_TWO
	local Modulus = Q

	local Len = Powers[L][1]
	local LenX2 = Powers[L][2]
	local KBeg = bit32.rshift(N, L) - 1

	for Start = 0, N - 1, LenX2 do
		local KNow = KBeg - bit32.rshift(Start, L + 1)
		local NegZetaExp = buffer.readu16(Zeta, KNow * 2)

		for I = Start, Start + Len - 1, 2 do
			local OffsetA = BaseOffset + I * 2
			local OffsetALen = OffsetA + LenX2
			local OffsetB = OffsetA + 2
			local OffsetBLen = OffsetB + LenX2

			local PolyA = buffer.readu16(Poly, OffsetA)
			local PolyALen = buffer.readu16(Poly, OffsetALen)
			local PolyB = buffer.readu16(Poly, OffsetB)
			local PolyBLen = buffer.readu16(Poly, OffsetBLen)

			buffer.writeu16(Poly, OffsetALen, ((PolyA - PolyALen) * NegZetaExp) % Modulus)
			buffer.writeu16(Poly, OffsetBLen, ((PolyB - PolyBLen) * NegZetaExp) % Modulus)
			buffer.writeu16(Poly, OffsetA, (PolyA + PolyALen) % Modulus)
			buffer.writeu16(Poly, OffsetB, (PolyB + PolyBLen) % Modulus)
		end
	end
end

local function PolyVecDot2At(F: buffer, FOffset: number, G: buffer, GOffset: number, H: buffer, HOffset: number)
	local PolyZeta = POLY_MUL_ZETA_EXP
	local Modulus = Q

	for I = 0, 127 do
		local LocalOffset = I * 4
		local ZetaExp = buffer.readu16(PolyZeta, I * 2)
		local FOff = FOffset + LocalOffset
		local GOff = GOffset + LocalOffset

		local F0 = buffer.readu16(F, FOff)
		local F1 = buffer.readu16(F, FOff + 2)
		local G0 = buffer.readu16(G, GOff)
		local G1 = buffer.readu16(G, GOff + 2)
		local Acc0 = F0 * G0 + F1 * G1 * ZetaExp
		local Acc1 = F0 * G1 + F1 * G0

		F0 = buffer.readu16(F, FOff + 512)
		F1 = buffer.readu16(F, FOff + 514)
		G0 = buffer.readu16(G, GOff + 512)
		G1 = buffer.readu16(G, GOff + 514)
		Acc0 += F0 * G0 + F1 * G1 * ZetaExp
		Acc1 += F0 * G1 + F1 * G0
		local HOff = HOffset + LocalOffset
		buffer.writeu16(H, HOff, Acc0 % Modulus)
		buffer.writeu16(H, HOff + 2, Acc1 % Modulus)
	end
end

local function PolyVecDot3At(F: buffer, FOffset: number, G: buffer, GOffset: number, H: buffer, HOffset: number)
	local PolyZeta = POLY_MUL_ZETA_EXP
	local Modulus = Q

	for I = 0, 127 do
		local LocalOffset = I * 4
		local ZetaExp = buffer.readu16(PolyZeta, I * 2)
		local FOff = FOffset + LocalOffset
		local GOff = GOffset + LocalOffset

		local F0 = buffer.readu16(F, FOff)
		local F1 = buffer.readu16(F, FOff + 2)
		local G0 = buffer.readu16(G, GOff)
		local G1 = buffer.readu16(G, GOff + 2)
		local Acc0 = F0 * G0 + F1 * G1 * ZetaExp
		local Acc1 = F0 * G1 + F1 * G0

		F0 = buffer.readu16(F, FOff + 512)
		F1 = buffer.readu16(F, FOff + 514)
		G0 = buffer.readu16(G, GOff + 512)
		G1 = buffer.readu16(G, GOff + 514)
		Acc0 += F0 * G0 + F1 * G1 * ZetaExp
		Acc1 += F0 * G1 + F1 * G0

		F0 = buffer.readu16(F, FOff + 1024)
		F1 = buffer.readu16(F, FOff + 1026)
		G0 = buffer.readu16(G, GOff + 1024)
		G1 = buffer.readu16(G, GOff + 1026)
		Acc0 += F0 * G0 + F1 * G1 * ZetaExp
		Acc1 += F0 * G1 + F1 * G0
		local HOff = HOffset + LocalOffset
		buffer.writeu16(H, HOff, Acc0 % Modulus)
		buffer.writeu16(H, HOff + 2, Acc1 % Modulus)
	end
end

local function PolyVecDot4At(F: buffer, FOffset: number, G: buffer, GOffset: number, H: buffer, HOffset: number)
	local PolyZeta = POLY_MUL_ZETA_EXP
	local Modulus = Q

	for I = 0, 127 do
		local LocalOffset = I * 4
		local ZetaExp = buffer.readu16(PolyZeta, I * 2)
		local FOff = FOffset + LocalOffset
		local GOff = GOffset + LocalOffset

		local F0 = buffer.readu16(F, FOff)
		local F1 = buffer.readu16(F, FOff + 2)
		local G0 = buffer.readu16(G, GOff)
		local G1 = buffer.readu16(G, GOff + 2)
		local Acc0 = F0 * G0 + F1 * G1 * ZetaExp
		local Acc1 = F0 * G1 + F1 * G0

		F0 = buffer.readu16(F, FOff + 512)
		F1 = buffer.readu16(F, FOff + 514)
		G0 = buffer.readu16(G, GOff + 512)
		G1 = buffer.readu16(G, GOff + 514)
		Acc0 += F0 * G0 + F1 * G1 * ZetaExp
		Acc1 += F0 * G1 + F1 * G0

		F0 = buffer.readu16(F, FOff + 1024)
		F1 = buffer.readu16(F, FOff + 1026)
		G0 = buffer.readu16(G, GOff + 1024)
		G1 = buffer.readu16(G, GOff + 1026)
		Acc0 += F0 * G0 + F1 * G1 * ZetaExp
		Acc1 += F0 * G1 + F1 * G0

		F0 = buffer.readu16(F, FOff + 1536)
		F1 = buffer.readu16(F, FOff + 1538)
		G0 = buffer.readu16(G, GOff + 1536)
		G1 = buffer.readu16(G, GOff + 1538)
		Acc0 += F0 * G0 + F1 * G1 * ZetaExp
		Acc1 += F0 * G1 + F1 * G0
		local HOff = HOffset + LocalOffset
		buffer.writeu16(H, HOff, Acc0 % Modulus)
		buffer.writeu16(H, HOff + 2, Acc1 % Modulus)
	end
end

function Ntt.NttAt(Poly: buffer, BaseOffset: number)
	local Zeta = NTT_ZETA_EXP
	local Powers = POWERS_OF_TWO
	local Modulus = Q

	for L = LOG2N - 1, 2, -1 do
		local Len = Powers[L][1]
		local LenX2 = Powers[L][2]
		local KBeg = bit32.rshift(N, L + 1)

		for Start = 0, N - 1, LenX2 do
			local KNow = KBeg + bit32.rshift(Start, L + 1)
			local ZetaExp = buffer.readu16(Zeta, KNow * 2)

			for I = Start, Start + Len - 1, 2 do
				local OffsetA = BaseOffset + I * 2
				local OffsetALen = OffsetA + LenX2
				local OffsetB = OffsetA + 2
				local OffsetBLen = OffsetB + LenX2

				local PolyA = buffer.readu16(Poly, OffsetA)
				local PolyALen = buffer.readu16(Poly, OffsetALen)
				local PolyB = buffer.readu16(Poly, OffsetB)
				local PolyBLen = buffer.readu16(Poly, OffsetBLen)

				local TmpA = (ZetaExp * PolyALen) % Modulus
				local TmpB = (ZetaExp * PolyBLen) % Modulus

				buffer.writeu16(Poly, OffsetALen, PolyA - TmpA + Modulus)
				buffer.writeu16(Poly, OffsetA, PolyA + TmpA)
				buffer.writeu16(Poly, OffsetBLen, PolyB - TmpB + Modulus)
				buffer.writeu16(Poly, OffsetB, PolyB + TmpB)
			end
		end
	end

	for Start = 0, N - 1, 4 do
		local KNow = 64 + bit32.rshift(Start, 2)
		local ZetaExp = buffer.readu16(Zeta, KNow * 2)

		for I = Start, Start + 1 do
			local OffsetI = BaseOffset + I * 2
			local OffsetILen = OffsetI + 4

			local PolyI = buffer.readu16(Poly, OffsetI)
			local PolyILen = buffer.readu16(Poly, OffsetILen)

			local Tmp = (ZetaExp * PolyILen) % Modulus

			buffer.writeu16(Poly, OffsetILen, (PolyI - Tmp + Modulus) % Modulus)
			buffer.writeu16(Poly, OffsetI, (PolyI + Tmp) % Modulus)
		end
	end
end

function Ntt.InttAt(Poly: buffer, BaseOffset: number)
	local Zeta = INTT_ZETA_EXP
	local InvN = INV_N
	local Modulus = Q

	InttLevelsLazy(Poly, BaseOffset, 1, 4)
	InttLevelReduce(Poly, BaseOffset, 5)
	InttLevelsLazy(Poly, BaseOffset, 6, 6)

	local NegZeta7 = (buffer.readu16(Zeta, 2) * InvN) % Modulus
	for I = 0, 127, 2 do
		local OffsetA = BaseOffset + I * 2
		local OffsetALen = OffsetA + 256
		local OffsetB = OffsetA + 2
		local OffsetBLen = OffsetB + 256

		local PolyA = buffer.readu16(Poly, OffsetA)
		local PolyALen = buffer.readu16(Poly, OffsetALen)
		local PolyB = buffer.readu16(Poly, OffsetB)
		local PolyBLen = buffer.readu16(Poly, OffsetBLen)

		buffer.writeu16(Poly, OffsetA, ((PolyA + PolyALen) * InvN) % Modulus)
		buffer.writeu16(Poly, OffsetB, ((PolyB + PolyBLen) * InvN) % Modulus)
		buffer.writeu16(Poly, OffsetALen, ((PolyA - PolyALen) * NegZeta7) % Modulus)
		buffer.writeu16(Poly, OffsetBLen, ((PolyB - PolyBLen) * NegZeta7) % Modulus)
	end
end

function Ntt.PolyVecDotAt(F: buffer, FOffset: number, G: buffer, GOffset: number, K: number, H: buffer, HOffset: number)
	if K == 2 then
		PolyVecDot2At(F, FOffset, G, GOffset, H, HOffset)
	elseif K == 3 then
		PolyVecDot3At(F, FOffset, G, GOffset, H, HOffset)
	else
		PolyVecDot4At(F, FOffset, G, GOffset, H, HOffset)
	end
end

function Ntt.PolyAdd(F: buffer, G: buffer, H: buffer)
	local Modulus = Q
	for Index = 0, N - 1 do
		local Offset = Index * 2
		local AValue = buffer.readu16(F, Offset)
		local BValue = buffer.readu16(G, Offset)
		buffer.writeu16(H, Offset, (AValue + BValue) % Modulus)
	end
end

function Ntt.PolySub(F: buffer, G: buffer, H: buffer)
	local Modulus = Q
	for Index = 0, N - 1 do
		local Offset = Index * 2
		local AValue = buffer.readu16(F, Offset)
		local BValue = buffer.readu16(G, Offset)
		buffer.writeu16(H, Offset, (AValue - BValue) % Modulus)
	end
end

return Ntt
