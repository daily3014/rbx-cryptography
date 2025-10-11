--[=[
	Number Theoretic Transform for degree-255 polynomials
	
	 Forward and inverse NTT over Z_q for polynomial multiplication.
	Uses Cooley-Tukey and Gentleman-Sande algorithms with precomputed roots.

	Example usage:
		local NTT = require(script)
		
		local Poly = buffer.create(256 * 4)  -- 256 coefficients, 4 bytes each
		NTT.ForwardNTT(Poly)
		-- Perform operations in NTT domain
		NTT.InverseNTT(Poly)
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

function Ntt.ForwardNTT(Poly: buffer)
	local Zeta = ZETA_EXP
	local Modulus = Q
	
	for L = LOG2N - 1, 0, -1 do
		local Len = bit32.lshift(1, L)
		local LenX2 = bit32.lshift(Len, 1)
		local KBeg = bit32.rshift(N, L + 1)

		for Start = 0, N - 1, LenX2 do
			local KNow = KBeg + bit32.rshift(Start, L + 1)
			local ZetaExpValue = buffer.readu32(Zeta, KNow * 4)

			for I = Start, Start + Len - 1 do
				local IOffset = I * 4
				local ILenOffset = (I + Len) * 4

				local PolyI = buffer.readu32(Poly, IOffset)
				local PolyILen = buffer.readu32(Poly, ILenOffset)

				local Tmp = (ZetaExpValue * PolyILen) % Modulus

				local Sub = if PolyI >= Tmp then PolyI - Tmp else PolyI - Tmp + Modulus
				local Add = PolyI + Tmp
				Add = if Add >= Modulus then Add - Modulus else Add

				buffer.writeu32(Poly, ILenOffset, Sub)
				buffer.writeu32(Poly, IOffset, Add)
			end
		end
	end
end

function Ntt.ForwardNTTWithOffset(Poly: buffer, BaseOffset: number)
	local Zeta = ZETA_EXP
	local Modulus = Q
	
	for L = LOG2N - 1, 0, -1 do
		local Len = bit32.lshift(1, L)
		local LenX2 = bit32.lshift(Len, 1)
		local KBeg = bit32.rshift(N, L + 1)

		for Start = 0, N - 1, LenX2 do
			local KNow = KBeg + bit32.rshift(Start, L + 1)
			local ZetaExpValue = buffer.readu32(Zeta, KNow * 4)

			for I = Start, Start + Len - 1 do
				local IOffset = BaseOffset + I * 4
				local ILenOffset = BaseOffset + (I + Len) * 4

				local PolyI = buffer.readu32(Poly, IOffset)
				local PolyILen = buffer.readu32(Poly, ILenOffset)

				local Tmp = (ZetaExpValue * PolyILen) % Modulus

				local Sub = if PolyI >= Tmp then PolyI - Tmp else PolyI - Tmp + Modulus
				local Add = PolyI + Tmp
				Add = if Add >= Modulus then Add - Modulus else Add

				buffer.writeu32(Poly, ILenOffset, Sub)
				buffer.writeu32(Poly, IOffset, Add)
			end
		end
	end
end

function Ntt.InverseNTT(Poly: buffer)
	local Zeta = ZETA_NEG_EXP
	local Inv_n = INV_N
	local Modulus = Q
	
	for L = 0, LOG2N - 1 do
		local Len = bit32.lshift(1, L)
		local LenX2 = bit32.lshift(Len, 1)
		local KBeg = bit32.rshift(N, L) - 1

		for Start = 0, N - 1, LenX2 do
			local KNow = KBeg - bit32.rshift(Start, L + 1)
			local NegZetaExpValue = buffer.readu32(Zeta, KNow * 4)

			for I = Start, Start + Len - 1 do
				local IOffset = I * 4
				local ILenOffset = (I + Len) * 4

				local PolyI = buffer.readu32(Poly, IOffset)
				local PolyILen = buffer.readu32(Poly, ILenOffset)

				local Sum = PolyI + PolyILen
				Sum = if Sum >= Modulus then Sum - Modulus else Sum

				local Diff = if PolyI >= PolyILen then PolyI - PolyILen else PolyI - PolyILen + Modulus

				local Product = (Diff * NegZetaExpValue) % Modulus

				buffer.writeu32(Poly, IOffset, Sum)
				buffer.writeu32(Poly, ILenOffset, Product)
			end
		end
	end

	for I = 0, N - 1 do
		local Offset = I * 4
		local PolyValue = buffer.readu32(Poly, Offset)
		local Result = (PolyValue * Inv_n) % Modulus
		buffer.writeu32(Poly, Offset, Result)
	end
end

Ntt.ZETA_NEG_EXP = ZETA_NEG_EXP
Ntt.INV_N = INV_N

return Ntt