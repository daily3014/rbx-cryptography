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

local POWERS_OF_TWO = table.create(LOG2N) :: {{number}}
for I = 0, LOG2N - 1 do
	POWERS_OF_TWO[I] = {2^I, (2^I) * 2}
end

function Ntt.Ntt(Poly: buffer)
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

			for I = Start, Start + Len - 1 do
				local OffsetI = I * 2
				local OffsetILen = (I + Len) * 2

				local PolyI = buffer.readu16(Poly, OffsetI)
				local PolyILen = buffer.readu16(Poly, OffsetILen)

				local Tmp = (ZetaExp * PolyILen) % Modulus

				buffer.writeu16(Poly, OffsetILen, PolyI - Tmp + Modulus)
				buffer.writeu16(Poly, OffsetI, PolyI + Tmp)
			end
		end
	end

	for Start = 0, N - 1, 4 do
		local KNow = 64 + bit32.rshift(Start, 2)
		local ZetaExp = buffer.readu16(Zeta, KNow * 2)

		for I = Start, Start + 1 do
			local OffsetI = I * 2
			local OffsetILen = OffsetI + 4

			local PolyI = buffer.readu16(Poly, OffsetI)
			local PolyILen = buffer.readu16(Poly, OffsetILen)

			local Tmp = (ZetaExp * PolyILen) % Modulus

			buffer.writeu16(Poly, OffsetILen, (PolyI - Tmp + Modulus) % Modulus)
			buffer.writeu16(Poly, OffsetI, (PolyI + Tmp) % Modulus)
		end
	end
end

function Ntt.Intt(Poly: buffer)
	local Zeta = INTT_ZETA_EXP
	local InvN = INV_N
	local Powers = POWERS_OF_TWO
	local Modulus = Q

	for L = 1, LOG2N - 2 do
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

				local MulResult = ((PolyI - PolyILen) * NegZetaExp) % Modulus

				buffer.writeu16(Poly, OffsetI, (PolyI + PolyILen) % Modulus)
				buffer.writeu16(Poly, OffsetILen, MulResult)
			end
		end
	end

	local NegZeta7 = (buffer.readu16(Zeta, 2) * InvN) % Modulus
	for I = 0, 127 do
		local OffsetI = I * 2
		local OffsetILen = OffsetI + 256

		local PolyI = buffer.readu16(Poly, OffsetI)
		local PolyILen = buffer.readu16(Poly, OffsetILen)

		buffer.writeu16(Poly, OffsetI, ((PolyI + PolyILen) * InvN) % Modulus)
		buffer.writeu16(Poly, OffsetILen, ((PolyI - PolyILen) * NegZeta7) % Modulus)
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

			for I = Start, Start + Len - 1 do
				local OffsetI = BaseOffset + I * 2
				local OffsetILen = BaseOffset + (I + Len) * 2

				local PolyI = buffer.readu16(Poly, OffsetI)
				local PolyILen = buffer.readu16(Poly, OffsetILen)

				local Tmp = (ZetaExp * PolyILen) % Modulus

				buffer.writeu16(Poly, OffsetILen, PolyI - Tmp + Modulus)
				buffer.writeu16(Poly, OffsetI, PolyI + Tmp)
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
	local Powers = POWERS_OF_TWO
	local Modulus = Q

	for L = 1, LOG2N - 2 do
		local Len = Powers[L][1]
		local LenX2 = Powers[L][2]
		local KBeg = bit32.rshift(N, L) - 1

		for Start = 0, N - 1, LenX2 do
			local KNow = KBeg - bit32.rshift(Start, L + 1)
			local NegZetaExp = buffer.readu16(Zeta, KNow * 2)

			for I = Start, Start + Len - 1 do
				local OffsetI = BaseOffset + I * 2
				local OffsetILen = BaseOffset + (I + Len) * 2

				local PolyI = buffer.readu16(Poly, OffsetI)
				local PolyILen = buffer.readu16(Poly, OffsetILen)

				local MulResult = ((PolyI - PolyILen) * NegZetaExp) % Modulus

				buffer.writeu16(Poly, OffsetI, (PolyI + PolyILen) % Modulus)
				buffer.writeu16(Poly, OffsetILen, MulResult)
			end
		end
	end

	local NegZeta7 = (buffer.readu16(Zeta, 2) * InvN) % Modulus
	for I = 0, 127 do
		local OffsetI = BaseOffset + I * 2
		local OffsetILen = OffsetI + 256

		local PolyI = buffer.readu16(Poly, OffsetI)
		local PolyILen = buffer.readu16(Poly, OffsetILen)

		buffer.writeu16(Poly, OffsetI, ((PolyI + PolyILen) * InvN) % Modulus)
		buffer.writeu16(Poly, OffsetILen, ((PolyI - PolyILen) * NegZeta7) % Modulus)
	end
end

function Ntt.PolyMulAddAt(F: buffer, FOffset: number, G: buffer, GOffset: number, H: buffer, HOffset: number)
	local PolyZeta = POLY_MUL_ZETA_EXP
	local Modulus = Q

	for I = 0, 127 do
		local LocalOffset = I * 4
		local ZetaExp = buffer.readu16(PolyZeta, I * 2)

		local F0 = buffer.readu16(F, FOffset + LocalOffset)
		local F1 = buffer.readu16(F, FOffset + LocalOffset + 2)
		local G0 = buffer.readu16(G, GOffset + LocalOffset)
		local G1 = buffer.readu16(G, GOffset + LocalOffset + 2)

		local Mul3 = ((F1 * G1) % Modulus * ZetaExp) % Modulus
		local H0 = (F0 * G0 + Mul3) % Modulus
		local H1 = (F0 * G1 + F1 * G0) % Modulus

		local AccumOff0 = HOffset + LocalOffset
		local AccumOff1 = AccumOff0 + 2
		buffer.writeu16(H, AccumOff0, buffer.readu16(H, AccumOff0) + H0)
		buffer.writeu16(H, AccumOff1, buffer.readu16(H, AccumOff1) + H1)
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