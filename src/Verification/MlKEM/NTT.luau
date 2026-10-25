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
local INV_Q = 1 / Q

local function ModQ(Value: number): number
	return Value - math.floor(Value * INV_Q + 2 ^ -20) * Q
end

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
	local Z01 = buffer.readu16(Zeta, 2)
	local Z02 = buffer.readu16(Zeta, 4)
	local Z03 = buffer.readu16(Zeta, 6)
	local Z04 = buffer.readu16(Zeta, 8)
	local Z05 = buffer.readu16(Zeta, 10)
	local Z06 = buffer.readu16(Zeta, 12)
	local Z07 = buffer.readu16(Zeta, 14)
	local Z08 = buffer.readu16(Zeta, 16)
	local Z09 = buffer.readu16(Zeta, 18)
	local Z10 = buffer.readu16(Zeta, 20)
	local Z11 = buffer.readu16(Zeta, 22)
	local Z12 = buffer.readu16(Zeta, 24)
	local Z13 = buffer.readu16(Zeta, 26)
	local Z14 = buffer.readu16(Zeta, 28)
	local Z15 = buffer.readu16(Zeta, 30)
	for Group = 0, 30, 2 do
		local Base = BaseOffset + Group
		local C00 = buffer.readu16(Poly, Base + 0)
		local C01 = buffer.readu16(Poly, Base + 32)
		local C02 = buffer.readu16(Poly, Base + 64)
		local C03 = buffer.readu16(Poly, Base + 96)
		local C04 = buffer.readu16(Poly, Base + 128)
		local C05 = buffer.readu16(Poly, Base + 160)
		local C06 = buffer.readu16(Poly, Base + 192)
		local C07 = buffer.readu16(Poly, Base + 224)
		local C08 = buffer.readu16(Poly, Base + 256)
		local C09 = buffer.readu16(Poly, Base + 288)
		local C10 = buffer.readu16(Poly, Base + 320)
		local C11 = buffer.readu16(Poly, Base + 352)
		local C12 = buffer.readu16(Poly, Base + 384)
		local C13 = buffer.readu16(Poly, Base + 416)
		local C14 = buffer.readu16(Poly, Base + 448)
		local C15 = buffer.readu16(Poly, Base + 480)
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
		buffer.writeu16(Poly, Base + 0, ModQ(C00))
		buffer.writeu16(Poly, Base + 32, ModQ(C01))
		buffer.writeu16(Poly, Base + 64, ModQ(C02))
		buffer.writeu16(Poly, Base + 96, ModQ(C03))
		buffer.writeu16(Poly, Base + 128, ModQ(C04))
		buffer.writeu16(Poly, Base + 160, ModQ(C05))
		buffer.writeu16(Poly, Base + 192, ModQ(C06))
		buffer.writeu16(Poly, Base + 224, ModQ(C07))
		buffer.writeu16(Poly, Base + 256, ModQ(C08))
		buffer.writeu16(Poly, Base + 288, ModQ(C09))
		buffer.writeu16(Poly, Base + 320, ModQ(C10))
		buffer.writeu16(Poly, Base + 352, ModQ(C11))
		buffer.writeu16(Poly, Base + 384, ModQ(C12))
		buffer.writeu16(Poly, Base + 416, ModQ(C13))
		buffer.writeu16(Poly, Base + 448, ModQ(C14))
		buffer.writeu16(Poly, Base + 480, ModQ(C15))
	end
	for Block = 0, 15 do
		local Base = BaseOffset + Block * 32
		local Y0 = buffer.readu16(Zeta, 32 + Block * 2)
		local Y1 = buffer.readu16(Zeta, 64 + Block * 4)
		local Y2 = buffer.readu16(Zeta, 66 + Block * 4)
		local X0 = buffer.readu16(Zeta, 128 + Block * 8)
		local X1 = buffer.readu16(Zeta, 130 + Block * 8)
		local X2 = buffer.readu16(Zeta, 132 + Block * 8)
		local X3 = buffer.readu16(Zeta, 134 + Block * 8)
		local C00 = buffer.readu16(Poly, Base + 0)
		local C01 = buffer.readu16(Poly, Base + 2)
		local C02 = buffer.readu16(Poly, Base + 4)
		local C03 = buffer.readu16(Poly, Base + 6)
		local C04 = buffer.readu16(Poly, Base + 8)
		local C05 = buffer.readu16(Poly, Base + 10)
		local C06 = buffer.readu16(Poly, Base + 12)
		local C07 = buffer.readu16(Poly, Base + 14)
		local C08 = buffer.readu16(Poly, Base + 16)
		local C09 = buffer.readu16(Poly, Base + 18)
		local C10 = buffer.readu16(Poly, Base + 20)
		local C11 = buffer.readu16(Poly, Base + 22)
		local C12 = buffer.readu16(Poly, Base + 24)
		local C13 = buffer.readu16(Poly, Base + 26)
		local C14 = buffer.readu16(Poly, Base + 28)
		local C15 = buffer.readu16(Poly, Base + 30)
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
		buffer.writeu16(Poly, Base + 0, ModQ(C00))
		buffer.writeu16(Poly, Base + 2, ModQ(C01))
		buffer.writeu16(Poly, Base + 4, ModQ(C02))
		buffer.writeu16(Poly, Base + 6, ModQ(C03))
		buffer.writeu16(Poly, Base + 8, ModQ(C04))
		buffer.writeu16(Poly, Base + 10, ModQ(C05))
		buffer.writeu16(Poly, Base + 12, ModQ(C06))
		buffer.writeu16(Poly, Base + 14, ModQ(C07))
		buffer.writeu16(Poly, Base + 16, ModQ(C08))
		buffer.writeu16(Poly, Base + 18, ModQ(C09))
		buffer.writeu16(Poly, Base + 20, ModQ(C10))
		buffer.writeu16(Poly, Base + 22, ModQ(C11))
		buffer.writeu16(Poly, Base + 24, ModQ(C12))
		buffer.writeu16(Poly, Base + 26, ModQ(C13))
		buffer.writeu16(Poly, Base + 28, ModQ(C14))
		buffer.writeu16(Poly, Base + 30, ModQ(C15))
	end
end

function Ntt.InttAt(Poly: buffer, BaseOffset: number)
	local Zeta = INTT_ZETA_EXP
	local InvN = INV_N
	local Z01 = buffer.readu16(Zeta, 2)
	local Z02 = buffer.readu16(Zeta, 4)
	local Z03 = buffer.readu16(Zeta, 6)
	local Z04 = buffer.readu16(Zeta, 8)
	local Z05 = buffer.readu16(Zeta, 10)
	local Z06 = buffer.readu16(Zeta, 12)
	local Z07 = buffer.readu16(Zeta, 14)
	local Z08 = buffer.readu16(Zeta, 16)
	local Z09 = buffer.readu16(Zeta, 18)
	local Z10 = buffer.readu16(Zeta, 20)
	local Z11 = buffer.readu16(Zeta, 22)
	local Z12 = buffer.readu16(Zeta, 24)
	local Z13 = buffer.readu16(Zeta, 26)
	local Z14 = buffer.readu16(Zeta, 28)
	local Z15 = buffer.readu16(Zeta, 30)
	local Z01Scaled = ModQ(Z01 * InvN)
	for Block = 0, 15 do
		local Base = BaseOffset + Block * 32
		local X0 = buffer.readu16(Zeta, 254 - Block * 8)
		local X1 = buffer.readu16(Zeta, 252 - Block * 8)
		local X2 = buffer.readu16(Zeta, 250 - Block * 8)
		local X3 = buffer.readu16(Zeta, 248 - Block * 8)
		local Y1 = buffer.readu16(Zeta, 126 - Block * 4)
		local Y2 = buffer.readu16(Zeta, 124 - Block * 4)
		local Y0 = buffer.readu16(Zeta, 62 - Block * 2)
		local C00 = buffer.readu16(Poly, Base + 0)
		local C01 = buffer.readu16(Poly, Base + 2)
		local C02 = buffer.readu16(Poly, Base + 4)
		local C03 = buffer.readu16(Poly, Base + 6)
		local C04 = buffer.readu16(Poly, Base + 8)
		local C05 = buffer.readu16(Poly, Base + 10)
		local C06 = buffer.readu16(Poly, Base + 12)
		local C07 = buffer.readu16(Poly, Base + 14)
		local C08 = buffer.readu16(Poly, Base + 16)
		local C09 = buffer.readu16(Poly, Base + 18)
		local C10 = buffer.readu16(Poly, Base + 20)
		local C11 = buffer.readu16(Poly, Base + 22)
		local C12 = buffer.readu16(Poly, Base + 24)
		local C13 = buffer.readu16(Poly, Base + 26)
		local C14 = buffer.readu16(Poly, Base + 28)
		local C15 = buffer.readu16(Poly, Base + 30)
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
		buffer.writeu16(Poly, Base + 0, C00)
		buffer.writeu16(Poly, Base + 2, C01)
		buffer.writeu16(Poly, Base + 4, C02)
		buffer.writeu16(Poly, Base + 6, C03)
		buffer.writeu16(Poly, Base + 8, C04)
		buffer.writeu16(Poly, Base + 10, C05)
		buffer.writeu16(Poly, Base + 12, C06)
		buffer.writeu16(Poly, Base + 14, C07)
		buffer.writeu16(Poly, Base + 16, C08)
		buffer.writeu16(Poly, Base + 18, C09)
		buffer.writeu16(Poly, Base + 20, C10)
		buffer.writeu16(Poly, Base + 22, C11)
		buffer.writeu16(Poly, Base + 24, C12)
		buffer.writeu16(Poly, Base + 26, C13)
		buffer.writeu16(Poly, Base + 28, C14)
		buffer.writeu16(Poly, Base + 30, C15)
	end
	for Group = 0, 30, 2 do
		local Base = BaseOffset + Group
		local C00 = buffer.readu16(Poly, Base + 0)
		local C01 = buffer.readu16(Poly, Base + 32)
		local C02 = buffer.readu16(Poly, Base + 64)
		local C03 = buffer.readu16(Poly, Base + 96)
		local C04 = buffer.readu16(Poly, Base + 128)
		local C05 = buffer.readu16(Poly, Base + 160)
		local C06 = buffer.readu16(Poly, Base + 192)
		local C07 = buffer.readu16(Poly, Base + 224)
		local C08 = buffer.readu16(Poly, Base + 256)
		local C09 = buffer.readu16(Poly, Base + 288)
		local C10 = buffer.readu16(Poly, Base + 320)
		local C11 = buffer.readu16(Poly, Base + 352)
		local C12 = buffer.readu16(Poly, Base + 384)
		local C13 = buffer.readu16(Poly, Base + 416)
		local C14 = buffer.readu16(Poly, Base + 448)
		local C15 = buffer.readu16(Poly, Base + 480)
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
			C00 = Sum
		end
		do
			local Sum = C01 + C05
			C05 = ModQ((C01 - C05) * Z03)
			C01 = Sum
		end
		do
			local Sum = C02 + C06
			C06 = ModQ((C02 - C06) * Z03)
			C02 = Sum
		end
		do
			local Sum = C03 + C07
			C07 = ModQ((C03 - C07) * Z03)
			C03 = Sum
		end
		do
			local Sum = C08 + C12
			C12 = ModQ((C08 - C12) * Z02)
			C08 = Sum
		end
		do
			local Sum = C09 + C13
			C13 = ModQ((C09 - C13) * Z02)
			C09 = Sum
		end
		do
			local Sum = C10 + C14
			C14 = ModQ((C10 - C14) * Z02)
			C10 = Sum
		end
		do
			local Sum = C11 + C15
			C15 = ModQ((C11 - C15) * Z02)
			C11 = Sum
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
		buffer.writeu16(Poly, Base + 0, C00)
		buffer.writeu16(Poly, Base + 32, C01)
		buffer.writeu16(Poly, Base + 64, C02)
		buffer.writeu16(Poly, Base + 96, C03)
		buffer.writeu16(Poly, Base + 128, C04)
		buffer.writeu16(Poly, Base + 160, C05)
		buffer.writeu16(Poly, Base + 192, C06)
		buffer.writeu16(Poly, Base + 224, C07)
		buffer.writeu16(Poly, Base + 256, C08)
		buffer.writeu16(Poly, Base + 288, C09)
		buffer.writeu16(Poly, Base + 320, C10)
		buffer.writeu16(Poly, Base + 352, C11)
		buffer.writeu16(Poly, Base + 384, C12)
		buffer.writeu16(Poly, Base + 416, C13)
		buffer.writeu16(Poly, Base + 448, C14)
		buffer.writeu16(Poly, Base + 480, C15)
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
