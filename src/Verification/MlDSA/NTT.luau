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
local INV_Q = 1 / Q

local function ModQ(Value: number): number
	return Value - math.floor(Value * INV_Q + 2 ^ -24) * Q
end

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
	local Z01 = buffer.readu32(Zeta, 4)
	local Z02 = buffer.readu32(Zeta, 8)
	local Z03 = buffer.readu32(Zeta, 12)
	local Z04 = buffer.readu32(Zeta, 16)
	local Z05 = buffer.readu32(Zeta, 20)
	local Z06 = buffer.readu32(Zeta, 24)
	local Z07 = buffer.readu32(Zeta, 28)
	local Z08 = buffer.readu32(Zeta, 32)
	local Z09 = buffer.readu32(Zeta, 36)
	local Z10 = buffer.readu32(Zeta, 40)
	local Z11 = buffer.readu32(Zeta, 44)
	local Z12 = buffer.readu32(Zeta, 48)
	local Z13 = buffer.readu32(Zeta, 52)
	local Z14 = buffer.readu32(Zeta, 56)
	local Z15 = buffer.readu32(Zeta, 60)
	for Group = 0, 60, 4 do
		local Base = BaseOffset + Group
		local C00 = buffer.readu32(Poly, Base + 0)
		local C01 = buffer.readu32(Poly, Base + 64)
		local C02 = buffer.readu32(Poly, Base + 128)
		local C03 = buffer.readu32(Poly, Base + 192)
		local C04 = buffer.readu32(Poly, Base + 256)
		local C05 = buffer.readu32(Poly, Base + 320)
		local C06 = buffer.readu32(Poly, Base + 384)
		local C07 = buffer.readu32(Poly, Base + 448)
		local C08 = buffer.readu32(Poly, Base + 512)
		local C09 = buffer.readu32(Poly, Base + 576)
		local C10 = buffer.readu32(Poly, Base + 640)
		local C11 = buffer.readu32(Poly, Base + 704)
		local C12 = buffer.readu32(Poly, Base + 768)
		local C13 = buffer.readu32(Poly, Base + 832)
		local C14 = buffer.readu32(Poly, Base + 896)
		local C15 = buffer.readu32(Poly, Base + 960)
		do
			local Tmp = ModQ(Z01 * C08)
			C08 = C00 - Tmp
			C00 += Tmp
		end
		do
			local Tmp = ModQ(Z01 * C09)
			C09 = C01 - Tmp
			C01 += Tmp
		end
		do
			local Tmp = ModQ(Z01 * C10)
			C10 = C02 - Tmp
			C02 += Tmp
		end
		do
			local Tmp = ModQ(Z01 * C11)
			C11 = C03 - Tmp
			C03 += Tmp
		end
		do
			local Tmp = ModQ(Z01 * C12)
			C12 = C04 - Tmp
			C04 += Tmp
		end
		do
			local Tmp = ModQ(Z01 * C13)
			C13 = C05 - Tmp
			C05 += Tmp
		end
		do
			local Tmp = ModQ(Z01 * C14)
			C14 = C06 - Tmp
			C06 += Tmp
		end
		do
			local Tmp = ModQ(Z01 * C15)
			C15 = C07 - Tmp
			C07 += Tmp
		end
		do
			local Tmp = ModQ(Z02 * C04)
			C04 = C00 - Tmp
			C00 += Tmp
		end
		do
			local Tmp = ModQ(Z02 * C05)
			C05 = C01 - Tmp
			C01 += Tmp
		end
		do
			local Tmp = ModQ(Z02 * C06)
			C06 = C02 - Tmp
			C02 += Tmp
		end
		do
			local Tmp = ModQ(Z02 * C07)
			C07 = C03 - Tmp
			C03 += Tmp
		end
		do
			local Tmp = ModQ(Z03 * C12)
			C12 = C08 - Tmp
			C08 += Tmp
		end
		do
			local Tmp = ModQ(Z03 * C13)
			C13 = C09 - Tmp
			C09 += Tmp
		end
		do
			local Tmp = ModQ(Z03 * C14)
			C14 = C10 - Tmp
			C10 += Tmp
		end
		do
			local Tmp = ModQ(Z03 * C15)
			C15 = C11 - Tmp
			C11 += Tmp
		end
		do
			local Tmp = ModQ(Z04 * C02)
			C02 = C00 - Tmp
			C00 += Tmp
		end
		do
			local Tmp = ModQ(Z04 * C03)
			C03 = C01 - Tmp
			C01 += Tmp
		end
		do
			local Tmp = ModQ(Z05 * C06)
			C06 = C04 - Tmp
			C04 += Tmp
		end
		do
			local Tmp = ModQ(Z05 * C07)
			C07 = C05 - Tmp
			C05 += Tmp
		end
		do
			local Tmp = ModQ(Z06 * C10)
			C10 = C08 - Tmp
			C08 += Tmp
		end
		do
			local Tmp = ModQ(Z06 * C11)
			C11 = C09 - Tmp
			C09 += Tmp
		end
		do
			local Tmp = ModQ(Z07 * C14)
			C14 = C12 - Tmp
			C12 += Tmp
		end
		do
			local Tmp = ModQ(Z07 * C15)
			C15 = C13 - Tmp
			C13 += Tmp
		end
		do
			local Tmp = ModQ(Z08 * C01)
			C01 = C00 - Tmp
			C00 += Tmp
		end
		do
			local Tmp = ModQ(Z09 * C03)
			C03 = C02 - Tmp
			C02 += Tmp
		end
		do
			local Tmp = ModQ(Z10 * C05)
			C05 = C04 - Tmp
			C04 += Tmp
		end
		do
			local Tmp = ModQ(Z11 * C07)
			C07 = C06 - Tmp
			C06 += Tmp
		end
		do
			local Tmp = ModQ(Z12 * C09)
			C09 = C08 - Tmp
			C08 += Tmp
		end
		do
			local Tmp = ModQ(Z13 * C11)
			C11 = C10 - Tmp
			C10 += Tmp
		end
		do
			local Tmp = ModQ(Z14 * C13)
			C13 = C12 - Tmp
			C12 += Tmp
		end
		do
			local Tmp = ModQ(Z15 * C15)
			C15 = C14 - Tmp
			C14 += Tmp
		end
		buffer.writeu32(Poly, Base + 0, ModQ(C00))
		buffer.writeu32(Poly, Base + 64, ModQ(C01))
		buffer.writeu32(Poly, Base + 128, ModQ(C02))
		buffer.writeu32(Poly, Base + 192, ModQ(C03))
		buffer.writeu32(Poly, Base + 256, ModQ(C04))
		buffer.writeu32(Poly, Base + 320, ModQ(C05))
		buffer.writeu32(Poly, Base + 384, ModQ(C06))
		buffer.writeu32(Poly, Base + 448, ModQ(C07))
		buffer.writeu32(Poly, Base + 512, ModQ(C08))
		buffer.writeu32(Poly, Base + 576, ModQ(C09))
		buffer.writeu32(Poly, Base + 640, ModQ(C10))
		buffer.writeu32(Poly, Base + 704, ModQ(C11))
		buffer.writeu32(Poly, Base + 768, ModQ(C12))
		buffer.writeu32(Poly, Base + 832, ModQ(C13))
		buffer.writeu32(Poly, Base + 896, ModQ(C14))
		buffer.writeu32(Poly, Base + 960, ModQ(C15))
	end
	for Block = 0, 15 do
		local Base = BaseOffset + Block * 64
		local Y0 = buffer.readu32(Zeta, 64 + Block * 4)
		local Y1 = buffer.readu32(Zeta, 128 + Block * 8)
		local Y2 = buffer.readu32(Zeta, 132 + Block * 8)
		local X0 = buffer.readu32(Zeta, 256 + Block * 16)
		local X1 = buffer.readu32(Zeta, 260 + Block * 16)
		local X2 = buffer.readu32(Zeta, 264 + Block * 16)
		local X3 = buffer.readu32(Zeta, 268 + Block * 16)
		local V0 = buffer.readu32(Zeta, 512 + Block * 32)
		local V1 = buffer.readu32(Zeta, 516 + Block * 32)
		local V2 = buffer.readu32(Zeta, 520 + Block * 32)
		local V3 = buffer.readu32(Zeta, 524 + Block * 32)
		local V4 = buffer.readu32(Zeta, 528 + Block * 32)
		local V5 = buffer.readu32(Zeta, 532 + Block * 32)
		local V6 = buffer.readu32(Zeta, 536 + Block * 32)
		local V7 = buffer.readu32(Zeta, 540 + Block * 32)
		local C00 = buffer.readu32(Poly, Base + 0)
		local C01 = buffer.readu32(Poly, Base + 4)
		local C02 = buffer.readu32(Poly, Base + 8)
		local C03 = buffer.readu32(Poly, Base + 12)
		local C04 = buffer.readu32(Poly, Base + 16)
		local C05 = buffer.readu32(Poly, Base + 20)
		local C06 = buffer.readu32(Poly, Base + 24)
		local C07 = buffer.readu32(Poly, Base + 28)
		local C08 = buffer.readu32(Poly, Base + 32)
		local C09 = buffer.readu32(Poly, Base + 36)
		local C10 = buffer.readu32(Poly, Base + 40)
		local C11 = buffer.readu32(Poly, Base + 44)
		local C12 = buffer.readu32(Poly, Base + 48)
		local C13 = buffer.readu32(Poly, Base + 52)
		local C14 = buffer.readu32(Poly, Base + 56)
		local C15 = buffer.readu32(Poly, Base + 60)
		do
			local Tmp = ModQ(Y0 * C08)
			C08 = C00 - Tmp
			C00 += Tmp
		end
		do
			local Tmp = ModQ(Y0 * C09)
			C09 = C01 - Tmp
			C01 += Tmp
		end
		do
			local Tmp = ModQ(Y0 * C10)
			C10 = C02 - Tmp
			C02 += Tmp
		end
		do
			local Tmp = ModQ(Y0 * C11)
			C11 = C03 - Tmp
			C03 += Tmp
		end
		do
			local Tmp = ModQ(Y0 * C12)
			C12 = C04 - Tmp
			C04 += Tmp
		end
		do
			local Tmp = ModQ(Y0 * C13)
			C13 = C05 - Tmp
			C05 += Tmp
		end
		do
			local Tmp = ModQ(Y0 * C14)
			C14 = C06 - Tmp
			C06 += Tmp
		end
		do
			local Tmp = ModQ(Y0 * C15)
			C15 = C07 - Tmp
			C07 += Tmp
		end
		do
			local Tmp = ModQ(Y1 * C04)
			C04 = C00 - Tmp
			C00 += Tmp
		end
		do
			local Tmp = ModQ(Y1 * C05)
			C05 = C01 - Tmp
			C01 += Tmp
		end
		do
			local Tmp = ModQ(Y1 * C06)
			C06 = C02 - Tmp
			C02 += Tmp
		end
		do
			local Tmp = ModQ(Y1 * C07)
			C07 = C03 - Tmp
			C03 += Tmp
		end
		do
			local Tmp = ModQ(Y2 * C12)
			C12 = C08 - Tmp
			C08 += Tmp
		end
		do
			local Tmp = ModQ(Y2 * C13)
			C13 = C09 - Tmp
			C09 += Tmp
		end
		do
			local Tmp = ModQ(Y2 * C14)
			C14 = C10 - Tmp
			C10 += Tmp
		end
		do
			local Tmp = ModQ(Y2 * C15)
			C15 = C11 - Tmp
			C11 += Tmp
		end
		do
			local Tmp = ModQ(X0 * C02)
			C02 = C00 - Tmp
			C00 += Tmp
		end
		do
			local Tmp = ModQ(X0 * C03)
			C03 = C01 - Tmp
			C01 += Tmp
		end
		do
			local Tmp = ModQ(X1 * C06)
			C06 = C04 - Tmp
			C04 += Tmp
		end
		do
			local Tmp = ModQ(X1 * C07)
			C07 = C05 - Tmp
			C05 += Tmp
		end
		do
			local Tmp = ModQ(X2 * C10)
			C10 = C08 - Tmp
			C08 += Tmp
		end
		do
			local Tmp = ModQ(X2 * C11)
			C11 = C09 - Tmp
			C09 += Tmp
		end
		do
			local Tmp = ModQ(X3 * C14)
			C14 = C12 - Tmp
			C12 += Tmp
		end
		do
			local Tmp = ModQ(X3 * C15)
			C15 = C13 - Tmp
			C13 += Tmp
		end
		do
			local Tmp = ModQ(V0 * C01)
			C01 = C00 - Tmp
			C00 += Tmp
		end
		do
			local Tmp = ModQ(V1 * C03)
			C03 = C02 - Tmp
			C02 += Tmp
		end
		do
			local Tmp = ModQ(V2 * C05)
			C05 = C04 - Tmp
			C04 += Tmp
		end
		do
			local Tmp = ModQ(V3 * C07)
			C07 = C06 - Tmp
			C06 += Tmp
		end
		do
			local Tmp = ModQ(V4 * C09)
			C09 = C08 - Tmp
			C08 += Tmp
		end
		do
			local Tmp = ModQ(V5 * C11)
			C11 = C10 - Tmp
			C10 += Tmp
		end
		do
			local Tmp = ModQ(V6 * C13)
			C13 = C12 - Tmp
			C12 += Tmp
		end
		do
			local Tmp = ModQ(V7 * C15)
			C15 = C14 - Tmp
			C14 += Tmp
		end
		buffer.writeu32(Poly, Base + 0, ModQ(C00))
		buffer.writeu32(Poly, Base + 4, ModQ(C01))
		buffer.writeu32(Poly, Base + 8, ModQ(C02))
		buffer.writeu32(Poly, Base + 12, ModQ(C03))
		buffer.writeu32(Poly, Base + 16, ModQ(C04))
		buffer.writeu32(Poly, Base + 20, ModQ(C05))
		buffer.writeu32(Poly, Base + 24, ModQ(C06))
		buffer.writeu32(Poly, Base + 28, ModQ(C07))
		buffer.writeu32(Poly, Base + 32, ModQ(C08))
		buffer.writeu32(Poly, Base + 36, ModQ(C09))
		buffer.writeu32(Poly, Base + 40, ModQ(C10))
		buffer.writeu32(Poly, Base + 44, ModQ(C11))
		buffer.writeu32(Poly, Base + 48, ModQ(C12))
		buffer.writeu32(Poly, Base + 52, ModQ(C13))
		buffer.writeu32(Poly, Base + 56, ModQ(C14))
		buffer.writeu32(Poly, Base + 60, ModQ(C15))
	end
end

function Ntt.InverseNTTWithOffset(Poly: buffer, BaseOffset: number)
	local Zeta = ZETA_NEG_EXP
	local Modulus = Q
	local InvN = INV_N
	local Z01 = buffer.readu32(Zeta, 4)
	local Z02 = buffer.readu32(Zeta, 8)
	local Z03 = buffer.readu32(Zeta, 12)
	local Z04 = buffer.readu32(Zeta, 16)
	local Z05 = buffer.readu32(Zeta, 20)
	local Z06 = buffer.readu32(Zeta, 24)
	local Z07 = buffer.readu32(Zeta, 28)
	local Z08 = buffer.readu32(Zeta, 32)
	local Z09 = buffer.readu32(Zeta, 36)
	local Z10 = buffer.readu32(Zeta, 40)
	local Z11 = buffer.readu32(Zeta, 44)
	local Z12 = buffer.readu32(Zeta, 48)
	local Z13 = buffer.readu32(Zeta, 52)
	local Z14 = buffer.readu32(Zeta, 56)
	local Z15 = buffer.readu32(Zeta, 60)
	local Z01Scaled = (Z01 * InvN) % Modulus
	for Block = 0, 15 do
		local Base = BaseOffset + Block * 64
		local V0 = buffer.readu32(Zeta, 1020 - Block * 32)
		local V1 = buffer.readu32(Zeta, 1016 - Block * 32)
		local V2 = buffer.readu32(Zeta, 1012 - Block * 32)
		local V3 = buffer.readu32(Zeta, 1008 - Block * 32)
		local V4 = buffer.readu32(Zeta, 1004 - Block * 32)
		local V5 = buffer.readu32(Zeta, 1000 - Block * 32)
		local V6 = buffer.readu32(Zeta, 996 - Block * 32)
		local V7 = buffer.readu32(Zeta, 992 - Block * 32)
		local X0 = buffer.readu32(Zeta, 508 - Block * 16)
		local X1 = buffer.readu32(Zeta, 504 - Block * 16)
		local X2 = buffer.readu32(Zeta, 500 - Block * 16)
		local X3 = buffer.readu32(Zeta, 496 - Block * 16)
		local Y1 = buffer.readu32(Zeta, 252 - Block * 8)
		local Y2 = buffer.readu32(Zeta, 248 - Block * 8)
		local Y0 = buffer.readu32(Zeta, 124 - Block * 4)
		local C00 = buffer.readu32(Poly, Base + 0)
		local C01 = buffer.readu32(Poly, Base + 4)
		local C02 = buffer.readu32(Poly, Base + 8)
		local C03 = buffer.readu32(Poly, Base + 12)
		local C04 = buffer.readu32(Poly, Base + 16)
		local C05 = buffer.readu32(Poly, Base + 20)
		local C06 = buffer.readu32(Poly, Base + 24)
		local C07 = buffer.readu32(Poly, Base + 28)
		local C08 = buffer.readu32(Poly, Base + 32)
		local C09 = buffer.readu32(Poly, Base + 36)
		local C10 = buffer.readu32(Poly, Base + 40)
		local C11 = buffer.readu32(Poly, Base + 44)
		local C12 = buffer.readu32(Poly, Base + 48)
		local C13 = buffer.readu32(Poly, Base + 52)
		local C14 = buffer.readu32(Poly, Base + 56)
		local C15 = buffer.readu32(Poly, Base + 60)
		do
			local Sum = C00 + C01
			C01 = ModQ((C00 - C01) * V0)
			C00 = Sum
		end
		do
			local Sum = C02 + C03
			C03 = ModQ((C02 - C03) * V1)
			C02 = Sum
		end
		do
			local Sum = C04 + C05
			C05 = ModQ((C04 - C05) * V2)
			C04 = Sum
		end
		do
			local Sum = C06 + C07
			C07 = ModQ((C06 - C07) * V3)
			C06 = Sum
		end
		do
			local Sum = C08 + C09
			C09 = ModQ((C08 - C09) * V4)
			C08 = Sum
		end
		do
			local Sum = C10 + C11
			C11 = ModQ((C10 - C11) * V5)
			C10 = Sum
		end
		do
			local Sum = C12 + C13
			C13 = ModQ((C12 - C13) * V6)
			C12 = Sum
		end
		do
			local Sum = C14 + C15
			C15 = ModQ((C14 - C15) * V7)
			C14 = Sum
		end
		do
			local Sum = C00 + C02
			C02 = ModQ((C00 - C02) * X0)
			C00 = Sum
		end
		do
			local Sum = C01 + C03
			C03 = ModQ((C01 - C03) * X0)
			C01 = Sum
		end
		do
			local Sum = C04 + C06
			C06 = ModQ((C04 - C06) * X1)
			C04 = Sum
		end
		do
			local Sum = C05 + C07
			C07 = ModQ((C05 - C07) * X1)
			C05 = Sum
		end
		do
			local Sum = C08 + C10
			C10 = ModQ((C08 - C10) * X2)
			C08 = Sum
		end
		do
			local Sum = C09 + C11
			C11 = ModQ((C09 - C11) * X2)
			C09 = Sum
		end
		do
			local Sum = C12 + C14
			C14 = ModQ((C12 - C14) * X3)
			C12 = Sum
		end
		do
			local Sum = C13 + C15
			C15 = ModQ((C13 - C15) * X3)
			C13 = Sum
		end
		do
			local Sum = C00 + C04
			C04 = ModQ((C00 - C04) * Y1)
			C00 = Sum
		end
		do
			local Sum = C01 + C05
			C05 = ModQ((C01 - C05) * Y1)
			C01 = Sum
		end
		do
			local Sum = C02 + C06
			C06 = ModQ((C02 - C06) * Y1)
			C02 = Sum
		end
		do
			local Sum = C03 + C07
			C07 = ModQ((C03 - C07) * Y1)
			C03 = Sum
		end
		do
			local Sum = C08 + C12
			C12 = ModQ((C08 - C12) * Y2)
			C08 = Sum
		end
		do
			local Sum = C09 + C13
			C13 = ModQ((C09 - C13) * Y2)
			C09 = Sum
		end
		do
			local Sum = C10 + C14
			C14 = ModQ((C10 - C14) * Y2)
			C10 = Sum
		end
		do
			local Sum = C11 + C15
			C15 = ModQ((C11 - C15) * Y2)
			C11 = Sum
		end
		do
			local Sum = C00 + C08
			C08 = ModQ((C00 - C08) * Y0)
			C00 = Sum
		end
		do
			local Sum = C01 + C09
			C09 = ModQ((C01 - C09) * Y0)
			C01 = Sum
		end
		do
			local Sum = C02 + C10
			C10 = ModQ((C02 - C10) * Y0)
			C02 = Sum
		end
		do
			local Sum = C03 + C11
			C11 = ModQ((C03 - C11) * Y0)
			C03 = Sum
		end
		do
			local Sum = C04 + C12
			C12 = ModQ((C04 - C12) * Y0)
			C04 = Sum
		end
		do
			local Sum = C05 + C13
			C13 = ModQ((C05 - C13) * Y0)
			C05 = Sum
		end
		do
			local Sum = C06 + C14
			C14 = ModQ((C06 - C14) * Y0)
			C06 = Sum
		end
		do
			local Sum = C07 + C15
			C15 = ModQ((C07 - C15) * Y0)
			C07 = Sum
		end
		buffer.writeu32(Poly, Base + 0, C00)
		buffer.writeu32(Poly, Base + 4, C01)
		buffer.writeu32(Poly, Base + 8, C02)
		buffer.writeu32(Poly, Base + 12, C03)
		buffer.writeu32(Poly, Base + 16, C04)
		buffer.writeu32(Poly, Base + 20, C05)
		buffer.writeu32(Poly, Base + 24, C06)
		buffer.writeu32(Poly, Base + 28, C07)
		buffer.writeu32(Poly, Base + 32, C08)
		buffer.writeu32(Poly, Base + 36, C09)
		buffer.writeu32(Poly, Base + 40, C10)
		buffer.writeu32(Poly, Base + 44, C11)
		buffer.writeu32(Poly, Base + 48, C12)
		buffer.writeu32(Poly, Base + 52, C13)
		buffer.writeu32(Poly, Base + 56, C14)
		buffer.writeu32(Poly, Base + 60, C15)
	end
	for Group = 0, 60, 4 do
		local Base = BaseOffset + Group
		local C00 = buffer.readu32(Poly, Base + 0)
		local C01 = buffer.readu32(Poly, Base + 64)
		local C02 = buffer.readu32(Poly, Base + 128)
		local C03 = buffer.readu32(Poly, Base + 192)
		local C04 = buffer.readu32(Poly, Base + 256)
		local C05 = buffer.readu32(Poly, Base + 320)
		local C06 = buffer.readu32(Poly, Base + 384)
		local C07 = buffer.readu32(Poly, Base + 448)
		local C08 = buffer.readu32(Poly, Base + 512)
		local C09 = buffer.readu32(Poly, Base + 576)
		local C10 = buffer.readu32(Poly, Base + 640)
		local C11 = buffer.readu32(Poly, Base + 704)
		local C12 = buffer.readu32(Poly, Base + 768)
		local C13 = buffer.readu32(Poly, Base + 832)
		local C14 = buffer.readu32(Poly, Base + 896)
		local C15 = buffer.readu32(Poly, Base + 960)
		do
			local Sum = C00 + C01
			C01 = ModQ((C00 - C01) * Z15)
			C00 = Sum
		end
		do
			local Sum = C02 + C03
			C03 = ModQ((C02 - C03) * Z14)
			C02 = Sum
		end
		do
			local Sum = C04 + C05
			C05 = ModQ((C04 - C05) * Z13)
			C04 = Sum
		end
		do
			local Sum = C06 + C07
			C07 = ModQ((C06 - C07) * Z12)
			C06 = Sum
		end
		do
			local Sum = C08 + C09
			C09 = ModQ((C08 - C09) * Z11)
			C08 = Sum
		end
		do
			local Sum = C10 + C11
			C11 = ModQ((C10 - C11) * Z10)
			C10 = Sum
		end
		do
			local Sum = C12 + C13
			C13 = ModQ((C12 - C13) * Z09)
			C12 = Sum
		end
		do
			local Sum = C14 + C15
			C15 = ModQ((C14 - C15) * Z08)
			C14 = Sum
		end
		do
			local Sum = C00 + C02
			C02 = ModQ((C00 - C02) * Z07)
			C00 = Sum
		end
		do
			local Sum = C01 + C03
			C03 = ModQ((C01 - C03) * Z07)
			C01 = Sum
		end
		do
			local Sum = C04 + C06
			C06 = ModQ((C04 - C06) * Z06)
			C04 = Sum
		end
		do
			local Sum = C05 + C07
			C07 = ModQ((C05 - C07) * Z06)
			C05 = Sum
		end
		do
			local Sum = C08 + C10
			C10 = ModQ((C08 - C10) * Z05)
			C08 = Sum
		end
		do
			local Sum = C09 + C11
			C11 = ModQ((C09 - C11) * Z05)
			C09 = Sum
		end
		do
			local Sum = C12 + C14
			C14 = ModQ((C12 - C14) * Z04)
			C12 = Sum
		end
		do
			local Sum = C13 + C15
			C15 = ModQ((C13 - C15) * Z04)
			C13 = Sum
		end
		do
			local Sum = C00 + C04
			C04 = ModQ((C00 - C04) * Z03)
			C00 = ModQ(Sum)
		end
		do
			local Sum = C01 + C05
			C05 = ModQ((C01 - C05) * Z03)
			C01 = ModQ(Sum)
		end
		do
			local Sum = C02 + C06
			C06 = ModQ((C02 - C06) * Z03)
			C02 = ModQ(Sum)
		end
		do
			local Sum = C03 + C07
			C07 = ModQ((C03 - C07) * Z03)
			C03 = ModQ(Sum)
		end
		do
			local Sum = C08 + C12
			C12 = ModQ((C08 - C12) * Z02)
			C08 = ModQ(Sum)
		end
		do
			local Sum = C09 + C13
			C13 = ModQ((C09 - C13) * Z02)
			C09 = ModQ(Sum)
		end
		do
			local Sum = C10 + C14
			C14 = ModQ((C10 - C14) * Z02)
			C10 = ModQ(Sum)
		end
		do
			local Sum = C11 + C15
			C15 = ModQ((C11 - C15) * Z02)
			C11 = ModQ(Sum)
		end
		do
			local Sum = C00 + C08
			C08 = ModQ((C00 - C08) * Z01Scaled)
			C00 = ModQ(Sum * InvN)
		end
		do
			local Sum = C01 + C09
			C09 = ModQ((C01 - C09) * Z01Scaled)
			C01 = ModQ(Sum * InvN)
		end
		do
			local Sum = C02 + C10
			C10 = ModQ((C02 - C10) * Z01Scaled)
			C02 = ModQ(Sum * InvN)
		end
		do
			local Sum = C03 + C11
			C11 = ModQ((C03 - C11) * Z01Scaled)
			C03 = ModQ(Sum * InvN)
		end
		do
			local Sum = C04 + C12
			C12 = ModQ((C04 - C12) * Z01Scaled)
			C04 = ModQ(Sum * InvN)
		end
		do
			local Sum = C05 + C13
			C13 = ModQ((C05 - C13) * Z01Scaled)
			C05 = ModQ(Sum * InvN)
		end
		do
			local Sum = C06 + C14
			C14 = ModQ((C06 - C14) * Z01Scaled)
			C06 = ModQ(Sum * InvN)
		end
		do
			local Sum = C07 + C15
			C15 = ModQ((C07 - C15) * Z01Scaled)
			C07 = ModQ(Sum * InvN)
		end
		buffer.writeu32(Poly, Base + 0, C00)
		buffer.writeu32(Poly, Base + 64, C01)
		buffer.writeu32(Poly, Base + 128, C02)
		buffer.writeu32(Poly, Base + 192, C03)
		buffer.writeu32(Poly, Base + 256, C04)
		buffer.writeu32(Poly, Base + 320, C05)
		buffer.writeu32(Poly, Base + 384, C06)
		buffer.writeu32(Poly, Base + 448, C07)
		buffer.writeu32(Poly, Base + 512, C08)
		buffer.writeu32(Poly, Base + 576, C09)
		buffer.writeu32(Poly, Base + 640, C10)
		buffer.writeu32(Poly, Base + 704, C11)
		buffer.writeu32(Poly, Base + 768, C12)
		buffer.writeu32(Poly, Base + 832, C13)
		buffer.writeu32(Poly, Base + 896, C14)
		buffer.writeu32(Poly, Base + 960, C15)
	end
end

function Ntt.InverseNTTProduct(Factor: buffer, Source: buffer, SourceOffset: number, Poly: buffer, BaseOffset: number)
	local Zeta = ZETA_NEG_EXP
	local Modulus = Q
	local InvN = INV_N
	local Z01 = buffer.readu32(Zeta, 4)
	local Z02 = buffer.readu32(Zeta, 8)
	local Z03 = buffer.readu32(Zeta, 12)
	local Z04 = buffer.readu32(Zeta, 16)
	local Z05 = buffer.readu32(Zeta, 20)
	local Z06 = buffer.readu32(Zeta, 24)
	local Z07 = buffer.readu32(Zeta, 28)
	local Z08 = buffer.readu32(Zeta, 32)
	local Z09 = buffer.readu32(Zeta, 36)
	local Z10 = buffer.readu32(Zeta, 40)
	local Z11 = buffer.readu32(Zeta, 44)
	local Z12 = buffer.readu32(Zeta, 48)
	local Z13 = buffer.readu32(Zeta, 52)
	local Z14 = buffer.readu32(Zeta, 56)
	local Z15 = buffer.readu32(Zeta, 60)
	local Z01Scaled = (Z01 * InvN) % Modulus
	for Block = 0, 15 do
		local Base = BaseOffset + Block * 64
		local FactorBase = Block * 64
		local SourceBase = SourceOffset + Block * 64
		local V0 = buffer.readu32(Zeta, 1020 - Block * 32)
		local V1 = buffer.readu32(Zeta, 1016 - Block * 32)
		local V2 = buffer.readu32(Zeta, 1012 - Block * 32)
		local V3 = buffer.readu32(Zeta, 1008 - Block * 32)
		local V4 = buffer.readu32(Zeta, 1004 - Block * 32)
		local V5 = buffer.readu32(Zeta, 1000 - Block * 32)
		local V6 = buffer.readu32(Zeta, 996 - Block * 32)
		local V7 = buffer.readu32(Zeta, 992 - Block * 32)
		local X0 = buffer.readu32(Zeta, 508 - Block * 16)
		local X1 = buffer.readu32(Zeta, 504 - Block * 16)
		local X2 = buffer.readu32(Zeta, 500 - Block * 16)
		local X3 = buffer.readu32(Zeta, 496 - Block * 16)
		local Y1 = buffer.readu32(Zeta, 252 - Block * 8)
		local Y2 = buffer.readu32(Zeta, 248 - Block * 8)
		local Y0 = buffer.readu32(Zeta, 124 - Block * 4)
		local C00 = ModQ(buffer.readu32(Factor, FactorBase) * buffer.readu32(Source, SourceBase))
		local C01 = ModQ(buffer.readu32(Factor, FactorBase + 4) * buffer.readu32(Source, SourceBase + 4))
		local C02 = ModQ(buffer.readu32(Factor, FactorBase + 8) * buffer.readu32(Source, SourceBase + 8))
		local C03 = ModQ(buffer.readu32(Factor, FactorBase + 12) * buffer.readu32(Source, SourceBase + 12))
		local C04 = ModQ(buffer.readu32(Factor, FactorBase + 16) * buffer.readu32(Source, SourceBase + 16))
		local C05 = ModQ(buffer.readu32(Factor, FactorBase + 20) * buffer.readu32(Source, SourceBase + 20))
		local C06 = ModQ(buffer.readu32(Factor, FactorBase + 24) * buffer.readu32(Source, SourceBase + 24))
		local C07 = ModQ(buffer.readu32(Factor, FactorBase + 28) * buffer.readu32(Source, SourceBase + 28))
		local C08 = ModQ(buffer.readu32(Factor, FactorBase + 32) * buffer.readu32(Source, SourceBase + 32))
		local C09 = ModQ(buffer.readu32(Factor, FactorBase + 36) * buffer.readu32(Source, SourceBase + 36))
		local C10 = ModQ(buffer.readu32(Factor, FactorBase + 40) * buffer.readu32(Source, SourceBase + 40))
		local C11 = ModQ(buffer.readu32(Factor, FactorBase + 44) * buffer.readu32(Source, SourceBase + 44))
		local C12 = ModQ(buffer.readu32(Factor, FactorBase + 48) * buffer.readu32(Source, SourceBase + 48))
		local C13 = ModQ(buffer.readu32(Factor, FactorBase + 52) * buffer.readu32(Source, SourceBase + 52))
		local C14 = ModQ(buffer.readu32(Factor, FactorBase + 56) * buffer.readu32(Source, SourceBase + 56))
		local C15 = ModQ(buffer.readu32(Factor, FactorBase + 60) * buffer.readu32(Source, SourceBase + 60))
		do
			local Sum = C00 + C01
			C01 = ModQ((C00 - C01) * V0)
			C00 = Sum
		end
		do
			local Sum = C02 + C03
			C03 = ModQ((C02 - C03) * V1)
			C02 = Sum
		end
		do
			local Sum = C04 + C05
			C05 = ModQ((C04 - C05) * V2)
			C04 = Sum
		end
		do
			local Sum = C06 + C07
			C07 = ModQ((C06 - C07) * V3)
			C06 = Sum
		end
		do
			local Sum = C08 + C09
			C09 = ModQ((C08 - C09) * V4)
			C08 = Sum
		end
		do
			local Sum = C10 + C11
			C11 = ModQ((C10 - C11) * V5)
			C10 = Sum
		end
		do
			local Sum = C12 + C13
			C13 = ModQ((C12 - C13) * V6)
			C12 = Sum
		end
		do
			local Sum = C14 + C15
			C15 = ModQ((C14 - C15) * V7)
			C14 = Sum
		end
		do
			local Sum = C00 + C02
			C02 = ModQ((C00 - C02) * X0)
			C00 = Sum
		end
		do
			local Sum = C01 + C03
			C03 = ModQ((C01 - C03) * X0)
			C01 = Sum
		end
		do
			local Sum = C04 + C06
			C06 = ModQ((C04 - C06) * X1)
			C04 = Sum
		end
		do
			local Sum = C05 + C07
			C07 = ModQ((C05 - C07) * X1)
			C05 = Sum
		end
		do
			local Sum = C08 + C10
			C10 = ModQ((C08 - C10) * X2)
			C08 = Sum
		end
		do
			local Sum = C09 + C11
			C11 = ModQ((C09 - C11) * X2)
			C09 = Sum
		end
		do
			local Sum = C12 + C14
			C14 = ModQ((C12 - C14) * X3)
			C12 = Sum
		end
		do
			local Sum = C13 + C15
			C15 = ModQ((C13 - C15) * X3)
			C13 = Sum
		end
		do
			local Sum = C00 + C04
			C04 = ModQ((C00 - C04) * Y1)
			C00 = Sum
		end
		do
			local Sum = C01 + C05
			C05 = ModQ((C01 - C05) * Y1)
			C01 = Sum
		end
		do
			local Sum = C02 + C06
			C06 = ModQ((C02 - C06) * Y1)
			C02 = Sum
		end
		do
			local Sum = C03 + C07
			C07 = ModQ((C03 - C07) * Y1)
			C03 = Sum
		end
		do
			local Sum = C08 + C12
			C12 = ModQ((C08 - C12) * Y2)
			C08 = Sum
		end
		do
			local Sum = C09 + C13
			C13 = ModQ((C09 - C13) * Y2)
			C09 = Sum
		end
		do
			local Sum = C10 + C14
			C14 = ModQ((C10 - C14) * Y2)
			C10 = Sum
		end
		do
			local Sum = C11 + C15
			C15 = ModQ((C11 - C15) * Y2)
			C11 = Sum
		end
		do
			local Sum = C00 + C08
			C08 = ModQ((C00 - C08) * Y0)
			C00 = Sum
		end
		do
			local Sum = C01 + C09
			C09 = ModQ((C01 - C09) * Y0)
			C01 = Sum
		end
		do
			local Sum = C02 + C10
			C10 = ModQ((C02 - C10) * Y0)
			C02 = Sum
		end
		do
			local Sum = C03 + C11
			C11 = ModQ((C03 - C11) * Y0)
			C03 = Sum
		end
		do
			local Sum = C04 + C12
			C12 = ModQ((C04 - C12) * Y0)
			C04 = Sum
		end
		do
			local Sum = C05 + C13
			C13 = ModQ((C05 - C13) * Y0)
			C05 = Sum
		end
		do
			local Sum = C06 + C14
			C14 = ModQ((C06 - C14) * Y0)
			C06 = Sum
		end
		do
			local Sum = C07 + C15
			C15 = ModQ((C07 - C15) * Y0)
			C07 = Sum
		end
		buffer.writeu32(Poly, Base + 0, C00)
		buffer.writeu32(Poly, Base + 4, C01)
		buffer.writeu32(Poly, Base + 8, C02)
		buffer.writeu32(Poly, Base + 12, C03)
		buffer.writeu32(Poly, Base + 16, C04)
		buffer.writeu32(Poly, Base + 20, C05)
		buffer.writeu32(Poly, Base + 24, C06)
		buffer.writeu32(Poly, Base + 28, C07)
		buffer.writeu32(Poly, Base + 32, C08)
		buffer.writeu32(Poly, Base + 36, C09)
		buffer.writeu32(Poly, Base + 40, C10)
		buffer.writeu32(Poly, Base + 44, C11)
		buffer.writeu32(Poly, Base + 48, C12)
		buffer.writeu32(Poly, Base + 52, C13)
		buffer.writeu32(Poly, Base + 56, C14)
		buffer.writeu32(Poly, Base + 60, C15)
	end
	for Group = 0, 60, 4 do
		local Base = BaseOffset + Group
		local C00 = buffer.readu32(Poly, Base + 0)
		local C01 = buffer.readu32(Poly, Base + 64)
		local C02 = buffer.readu32(Poly, Base + 128)
		local C03 = buffer.readu32(Poly, Base + 192)
		local C04 = buffer.readu32(Poly, Base + 256)
		local C05 = buffer.readu32(Poly, Base + 320)
		local C06 = buffer.readu32(Poly, Base + 384)
		local C07 = buffer.readu32(Poly, Base + 448)
		local C08 = buffer.readu32(Poly, Base + 512)
		local C09 = buffer.readu32(Poly, Base + 576)
		local C10 = buffer.readu32(Poly, Base + 640)
		local C11 = buffer.readu32(Poly, Base + 704)
		local C12 = buffer.readu32(Poly, Base + 768)
		local C13 = buffer.readu32(Poly, Base + 832)
		local C14 = buffer.readu32(Poly, Base + 896)
		local C15 = buffer.readu32(Poly, Base + 960)
		do
			local Sum = C00 + C01
			C01 = ModQ((C00 - C01) * Z15)
			C00 = Sum
		end
		do
			local Sum = C02 + C03
			C03 = ModQ((C02 - C03) * Z14)
			C02 = Sum
		end
		do
			local Sum = C04 + C05
			C05 = ModQ((C04 - C05) * Z13)
			C04 = Sum
		end
		do
			local Sum = C06 + C07
			C07 = ModQ((C06 - C07) * Z12)
			C06 = Sum
		end
		do
			local Sum = C08 + C09
			C09 = ModQ((C08 - C09) * Z11)
			C08 = Sum
		end
		do
			local Sum = C10 + C11
			C11 = ModQ((C10 - C11) * Z10)
			C10 = Sum
		end
		do
			local Sum = C12 + C13
			C13 = ModQ((C12 - C13) * Z09)
			C12 = Sum
		end
		do
			local Sum = C14 + C15
			C15 = ModQ((C14 - C15) * Z08)
			C14 = Sum
		end
		do
			local Sum = C00 + C02
			C02 = ModQ((C00 - C02) * Z07)
			C00 = Sum
		end
		do
			local Sum = C01 + C03
			C03 = ModQ((C01 - C03) * Z07)
			C01 = Sum
		end
		do
			local Sum = C04 + C06
			C06 = ModQ((C04 - C06) * Z06)
			C04 = Sum
		end
		do
			local Sum = C05 + C07
			C07 = ModQ((C05 - C07) * Z06)
			C05 = Sum
		end
		do
			local Sum = C08 + C10
			C10 = ModQ((C08 - C10) * Z05)
			C08 = Sum
		end
		do
			local Sum = C09 + C11
			C11 = ModQ((C09 - C11) * Z05)
			C09 = Sum
		end
		do
			local Sum = C12 + C14
			C14 = ModQ((C12 - C14) * Z04)
			C12 = Sum
		end
		do
			local Sum = C13 + C15
			C15 = ModQ((C13 - C15) * Z04)
			C13 = Sum
		end
		do
			local Sum = C00 + C04
			C04 = ModQ((C00 - C04) * Z03)
			C00 = ModQ(Sum)
		end
		do
			local Sum = C01 + C05
			C05 = ModQ((C01 - C05) * Z03)
			C01 = ModQ(Sum)
		end
		do
			local Sum = C02 + C06
			C06 = ModQ((C02 - C06) * Z03)
			C02 = ModQ(Sum)
		end
		do
			local Sum = C03 + C07
			C07 = ModQ((C03 - C07) * Z03)
			C03 = ModQ(Sum)
		end
		do
			local Sum = C08 + C12
			C12 = ModQ((C08 - C12) * Z02)
			C08 = ModQ(Sum)
		end
		do
			local Sum = C09 + C13
			C13 = ModQ((C09 - C13) * Z02)
			C09 = ModQ(Sum)
		end
		do
			local Sum = C10 + C14
			C14 = ModQ((C10 - C14) * Z02)
			C10 = ModQ(Sum)
		end
		do
			local Sum = C11 + C15
			C15 = ModQ((C11 - C15) * Z02)
			C11 = ModQ(Sum)
		end
		do
			local Sum = C00 + C08
			C08 = ModQ((C00 - C08) * Z01Scaled)
			C00 = ModQ(Sum * InvN)
		end
		do
			local Sum = C01 + C09
			C09 = ModQ((C01 - C09) * Z01Scaled)
			C01 = ModQ(Sum * InvN)
		end
		do
			local Sum = C02 + C10
			C10 = ModQ((C02 - C10) * Z01Scaled)
			C02 = ModQ(Sum * InvN)
		end
		do
			local Sum = C03 + C11
			C11 = ModQ((C03 - C11) * Z01Scaled)
			C03 = ModQ(Sum * InvN)
		end
		do
			local Sum = C04 + C12
			C12 = ModQ((C04 - C12) * Z01Scaled)
			C04 = ModQ(Sum * InvN)
		end
		do
			local Sum = C05 + C13
			C13 = ModQ((C05 - C13) * Z01Scaled)
			C05 = ModQ(Sum * InvN)
		end
		do
			local Sum = C06 + C14
			C14 = ModQ((C06 - C14) * Z01Scaled)
			C06 = ModQ(Sum * InvN)
		end
		do
			local Sum = C07 + C15
			C15 = ModQ((C07 - C15) * Z01Scaled)
			C07 = ModQ(Sum * InvN)
		end
		buffer.writeu32(Poly, Base + 0, C00)
		buffer.writeu32(Poly, Base + 64, C01)
		buffer.writeu32(Poly, Base + 128, C02)
		buffer.writeu32(Poly, Base + 192, C03)
		buffer.writeu32(Poly, Base + 256, C04)
		buffer.writeu32(Poly, Base + 320, C05)
		buffer.writeu32(Poly, Base + 384, C06)
		buffer.writeu32(Poly, Base + 448, C07)
		buffer.writeu32(Poly, Base + 512, C08)
		buffer.writeu32(Poly, Base + 576, C09)
		buffer.writeu32(Poly, Base + 640, C10)
		buffer.writeu32(Poly, Base + 704, C11)
		buffer.writeu32(Poly, Base + 768, C12)
		buffer.writeu32(Poly, Base + 832, C13)
		buffer.writeu32(Poly, Base + 896, C14)
		buffer.writeu32(Poly, Base + 960, C15)
	end
end


Ntt.ZETA_NEG_EXP = ZETA_NEG_EXP
Ntt.INV_N = INV_N

return Ntt
