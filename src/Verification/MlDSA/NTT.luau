--[=[
	Number Theoretic Transform for degree-255 polynomials
	
	 Forward and inverse NTT over Z_q for polynomial multiplication.
	Uses Cooley-Tukey and Gentleman-Sande algorithms with precomputed roots.

	Example usage:
		local Poly = buffer.create(256 * 4) -- 256 coefficients, 4 bytes each
		NTT.ForwardNTTWithOffset(Poly, 0)
--]=]

--!strict
--!optimize 2
--!native

local Field = require("./Field")

local LOG2N = 8
local ZETA = 1753
local Q = 8380417

local N = bit32.lshift(1, LOG2N)
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

local Ntt = {}

function Ntt.ForwardNTTWithOffset(Poly: buffer, BaseOffset: number)
	local Zeta = ZETA_EXP
	local Modulus = Q

	for L = LOG2N - 1, 1, -1 do
		local Len = bit32.lshift(1, L)
		local LenX2 = bit32.lshift(Len, 1)
		local LenBytes = Len * 4
		local KBeg = bit32.rshift(N, L + 1)

		for Start = 0, N - 1, LenX2 do
			local KNow = KBeg + bit32.rshift(Start, L + 1)
			local ZetaExpValue = buffer.readu32(Zeta, KNow * 4)

			for I = Start, Start + Len - 1, 2 do
				local OffsetA = BaseOffset + I * 4
				local OffsetALen = OffsetA + LenBytes
				local OffsetB = OffsetA + 4
				local OffsetBLen = OffsetB + LenBytes

				local PolyA = buffer.readu32(Poly, OffsetA)
				local PolyALen = buffer.readu32(Poly, OffsetALen)
				local PolyB = buffer.readu32(Poly, OffsetB)
				local PolyBLen = buffer.readu32(Poly, OffsetBLen)

				local TmpA = (ZetaExpValue * PolyALen) % Modulus
				local TmpB = (ZetaExpValue * PolyBLen) % Modulus

				buffer.writeu32(Poly, OffsetALen, PolyA - TmpA + Modulus)
				buffer.writeu32(Poly, OffsetA, PolyA + TmpA)
				buffer.writeu32(Poly, OffsetBLen, PolyB - TmpB + Modulus)
				buffer.writeu32(Poly, OffsetB, PolyB + TmpB)
			end
		end
	end

	for Start = 0, N - 1, 4 do
		local ZetaA = buffer.readu32(Zeta, (128 + bit32.rshift(Start, 1)) * 4)
		local ZetaB = buffer.readu32(Zeta, (129 + bit32.rshift(Start, 1)) * 4)

		local OffsetA = BaseOffset + Start * 4
		local OffsetB = OffsetA + 8

		local PolyA = buffer.readu32(Poly, OffsetA)
		local PolyALen = buffer.readu32(Poly, OffsetA + 4)
		local PolyB = buffer.readu32(Poly, OffsetB)
		local PolyBLen = buffer.readu32(Poly, OffsetB + 4)

		local TmpA = (ZetaA * PolyALen) % Modulus
		local TmpB = (ZetaB * PolyBLen) % Modulus

		buffer.writeu32(Poly, OffsetA + 4, (PolyA - TmpA + Modulus) % Modulus)
		buffer.writeu32(Poly, OffsetA, (PolyA + TmpA) % Modulus)
		buffer.writeu32(Poly, OffsetB + 4, (PolyB - TmpB + Modulus) % Modulus)
		buffer.writeu32(Poly, OffsetB, (PolyB + TmpB) % Modulus)
	end
end

Ntt.ZETA_NEG_EXP = ZETA_NEG_EXP
Ntt.INV_N = INV_N

return Ntt