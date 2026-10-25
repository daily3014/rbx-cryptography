--[=[
	Cryptography library: Keccak/SHA-3

	Sizes:
		SHA3-224 Digest: 28 bytes
		SHA3-256 Digest: 32 bytes
		SHA3-384 Digest: 48 bytes
		SHA3-512 Digest: 64 bytes
		SHAKE128 Digest: variable
		SHAKE256 Digest: variable

	Return type: (string, buffer)
	Example usage:
		local Message = buffer.fromstring("Hello World")

		local Hash1, HashBuffer1 = SHA3.SHA3_256(Message)
		local Hash2, HashBuffer2 = SHA3.SHAKE128(Message, 32)
--]=]

--!strict
--!optimize 2
--!native

local Conversions = require("../Utilities/Conversions")
local ToHex = Conversions.ToHex

local SHA3 = {}

local ROUND_A, ROUND_B = buffer.create(96), buffer.create(96) do
	buffer.writeu32(ROUND_A, 0, 0x00000001); buffer.writeu32(ROUND_B, 0, 0x00000000)
	buffer.writeu32(ROUND_A, 4, 0x00000000); buffer.writeu32(ROUND_B, 4, 0x00000089)
	buffer.writeu32(ROUND_A, 8, 0x00000000); buffer.writeu32(ROUND_B, 8, 0x8000008b)
	buffer.writeu32(ROUND_A, 12, 0x00000000); buffer.writeu32(ROUND_B, 12, 0x80008080)
	buffer.writeu32(ROUND_A, 16, 0x00000001); buffer.writeu32(ROUND_B, 16, 0x0000008b)
	buffer.writeu32(ROUND_A, 20, 0x00000001); buffer.writeu32(ROUND_B, 20, 0x00008000)
	buffer.writeu32(ROUND_A, 24, 0x00000001); buffer.writeu32(ROUND_B, 24, 0x80008088)
	buffer.writeu32(ROUND_A, 28, 0x00000001); buffer.writeu32(ROUND_B, 28, 0x80000082)
	buffer.writeu32(ROUND_A, 32, 0x00000000); buffer.writeu32(ROUND_B, 32, 0x0000000b)
	buffer.writeu32(ROUND_A, 36, 0x00000000); buffer.writeu32(ROUND_B, 36, 0x0000000a)
	buffer.writeu32(ROUND_A, 40, 0x00000001); buffer.writeu32(ROUND_B, 40, 0x00008082)
	buffer.writeu32(ROUND_A, 44, 0x00000000); buffer.writeu32(ROUND_B, 44, 0x00008003)
	buffer.writeu32(ROUND_A, 48, 0x00000001); buffer.writeu32(ROUND_B, 48, 0x0000808b)
	buffer.writeu32(ROUND_A, 52, 0x00000001); buffer.writeu32(ROUND_B, 52, 0x8000000b)
	buffer.writeu32(ROUND_A, 56, 0x00000001); buffer.writeu32(ROUND_B, 56, 0x8000008a)
	buffer.writeu32(ROUND_A, 60, 0x00000001); buffer.writeu32(ROUND_B, 60, 0x80000081)
	buffer.writeu32(ROUND_A, 64, 0x00000000); buffer.writeu32(ROUND_B, 64, 0x80000081)
	buffer.writeu32(ROUND_A, 68, 0x00000000); buffer.writeu32(ROUND_B, 68, 0x80000008)
	buffer.writeu32(ROUND_A, 72, 0x00000000); buffer.writeu32(ROUND_B, 72, 0x00000083)
	buffer.writeu32(ROUND_A, 76, 0x00000000); buffer.writeu32(ROUND_B, 76, 0x80008003)
	buffer.writeu32(ROUND_A, 80, 0x00000001); buffer.writeu32(ROUND_B, 80, 0x80008088)
	buffer.writeu32(ROUND_A, 84, 0x00000000); buffer.writeu32(ROUND_B, 84, 0x80000088)
	buffer.writeu32(ROUND_A, 88, 0x00000001); buffer.writeu32(ROUND_B, 88, 0x00008000)
	buffer.writeu32(ROUND_A, 92, 0x00000000); buffer.writeu32(ROUND_B, 92, 0x80008082)
end

local STATE_A = buffer.create(100)
local STATE_B = buffer.create(100)
local TAIL_BLOCK = buffer.create(168)

local function Permute(StateA: buffer, StateB: buffer)
	local A0, B0 = buffer.readu32(StateA, 0), buffer.readu32(StateB, 0)
	local A1, B1 = bit32.bnot(buffer.readu32(StateA, 4)), bit32.bnot(buffer.readu32(StateB, 4))
	local A2, B2 = bit32.bnot(buffer.readu32(StateA, 8)), bit32.bnot(buffer.readu32(StateB, 8))
	local A3, B3 = buffer.readu32(StateA, 12), buffer.readu32(StateB, 12)
	local A4, B4 = buffer.readu32(StateA, 16), buffer.readu32(StateB, 16)
	local A5, B5 = buffer.readu32(StateA, 20), buffer.readu32(StateB, 20)
	local A6, B6 = buffer.readu32(StateA, 24), buffer.readu32(StateB, 24)
	local A7, B7 = buffer.readu32(StateA, 28), buffer.readu32(StateB, 28)
	local A8, B8 = bit32.bnot(buffer.readu32(StateA, 32)), bit32.bnot(buffer.readu32(StateB, 32))
	local A9, B9 = buffer.readu32(StateA, 36), buffer.readu32(StateB, 36)
	local A10, B10 = buffer.readu32(StateA, 40), buffer.readu32(StateB, 40)
	local A11, B11 = buffer.readu32(StateA, 44), buffer.readu32(StateB, 44)
	local A12, B12 = bit32.bnot(buffer.readu32(StateA, 48)), bit32.bnot(buffer.readu32(StateB, 48))
	local A13, B13 = buffer.readu32(StateA, 52), buffer.readu32(StateB, 52)
	local A14, B14 = buffer.readu32(StateA, 56), buffer.readu32(StateB, 56)
	local A15, B15 = buffer.readu32(StateA, 60), buffer.readu32(StateB, 60)
	local A16, B16 = buffer.readu32(StateA, 64), buffer.readu32(StateB, 64)
	local A17, B17 = bit32.bnot(buffer.readu32(StateA, 68)), bit32.bnot(buffer.readu32(StateB, 68))
	local A18, B18 = buffer.readu32(StateA, 72), buffer.readu32(StateB, 72)
	local A19, B19 = buffer.readu32(StateA, 76), buffer.readu32(StateB, 76)
	local A20, B20 = bit32.bnot(buffer.readu32(StateA, 80)), bit32.bnot(buffer.readu32(StateB, 80))
	local A21, B21 = buffer.readu32(StateA, 84), buffer.readu32(StateB, 84)
	local A22, B22 = buffer.readu32(StateA, 88), buffer.readu32(StateB, 88)
	local A23, B23 = buffer.readu32(StateA, 92), buffer.readu32(StateB, 92)
	local A24, B24 = buffer.readu32(StateA, 96), buffer.readu32(StateB, 96)
	local RoundConstantsA, RoundConstantsB = ROUND_A, ROUND_B
	for RoundIndex = 0, 80, 16 do
		do
			local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex), buffer.readu32(RoundConstantsB, RoundIndex)
			local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
			local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
			local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
			local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
			local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
			local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
			local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
			local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
			local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
			local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
			local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
			local PA16, PB16
			do
				local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
				PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
			end
			local PA7, PB7
			do
				local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
				PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
			end
			local PA23, PB23
			do
				local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
				PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
			end
			local PA14, PB14
			do
				local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
				PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
			end
			local PA10, PB10
			do
				local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
				PA10, PB10 = bit32.lrotate(TB, 1), (TA)
			end
			local PA1, PB1
			do
				local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
				PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
			end
			local PA17, PB17
			do
				local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
				PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
			end
			local PA8, PB8
			do
				local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
				PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
			end
			local PA24, PB24
			do
				local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
				PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
			end
			local PA20, PB20
			do
				local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
				PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
			end
			local PA11, PB11
			do
				local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
				PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
			end
			local PA2, PB2
			do
				local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
				PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
			end
			local PA18, PB18
			do
				local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
				PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
			end
			local PA9, PB9
			do
				local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
				PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
			end
			local PA5, PB5
			do
				local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
				PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
			end
			local PA21, PB21
			do
				local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
				PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
			end
			local PA12, PB12
			do
				local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
				PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
			end
			local PA3, PB3
			do
				local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
				PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
			end
			local PA19, PB19
			do
				local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
				PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
			end
			local PA15, PB15
			do
				local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
				PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
			end
			local PA6, PB6
			do
				local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
				PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
			end
			local PA22, PB22
			do
				local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
				PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
			end
			local PA13, PB13
			do
				local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
				PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
			end
			local PA4, PB4
			do
				local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
				PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
			end
			A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
			B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
			A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
			B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
			A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
			B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
			A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
			B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
			A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
			B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
			A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
			B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
			A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
			B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
			A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
			B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
			A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
			B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
			A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
			B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
			A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
			B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
			A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
			B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
			A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
			B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
			A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
			B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
			A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
			B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
			A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
			B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
			A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
			B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
			A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
			B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
			A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
			B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
			A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
			B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
			A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
			B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
			A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
			B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
			A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
			B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
			A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
			B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
			A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
			B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
		end
		if RoundIndex < 0 then break end
		do
			local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 4), buffer.readu32(RoundConstantsB, RoundIndex + 4)
			local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
			local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
			local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
			local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
			local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
			local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
			local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
			local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
			local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
			local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
			local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
			local PA16, PB16
			do
				local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
				PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
			end
			local PA7, PB7
			do
				local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
				PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
			end
			local PA23, PB23
			do
				local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
				PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
			end
			local PA14, PB14
			do
				local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
				PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
			end
			local PA10, PB10
			do
				local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
				PA10, PB10 = bit32.lrotate(TB, 1), (TA)
			end
			local PA1, PB1
			do
				local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
				PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
			end
			local PA17, PB17
			do
				local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
				PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
			end
			local PA8, PB8
			do
				local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
				PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
			end
			local PA24, PB24
			do
				local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
				PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
			end
			local PA20, PB20
			do
				local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
				PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
			end
			local PA11, PB11
			do
				local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
				PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
			end
			local PA2, PB2
			do
				local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
				PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
			end
			local PA18, PB18
			do
				local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
				PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
			end
			local PA9, PB9
			do
				local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
				PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
			end
			local PA5, PB5
			do
				local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
				PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
			end
			local PA21, PB21
			do
				local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
				PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
			end
			local PA12, PB12
			do
				local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
				PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
			end
			local PA3, PB3
			do
				local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
				PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
			end
			local PA19, PB19
			do
				local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
				PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
			end
			local PA15, PB15
			do
				local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
				PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
			end
			local PA6, PB6
			do
				local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
				PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
			end
			local PA22, PB22
			do
				local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
				PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
			end
			local PA13, PB13
			do
				local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
				PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
			end
			local PA4, PB4
			do
				local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
				PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
			end
			A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
			B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
			A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
			B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
			A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
			B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
			A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
			B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
			A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
			B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
			A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
			B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
			A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
			B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
			A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
			B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
			A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
			B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
			A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
			B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
			A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
			B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
			A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
			B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
			A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
			B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
			A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
			B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
			A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
			B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
			A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
			B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
			A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
			B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
			A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
			B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
			A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
			B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
			A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
			B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
			A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
			B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
			A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
			B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
			A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
			B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
			A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
			B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
			A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
			B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
		end
		if RoundIndex < 0 then break end
		do
			local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 8), buffer.readu32(RoundConstantsB, RoundIndex + 8)
			local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
			local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
			local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
			local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
			local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
			local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
			local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
			local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
			local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
			local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
			local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
			local PA16, PB16
			do
				local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
				PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
			end
			local PA7, PB7
			do
				local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
				PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
			end
			local PA23, PB23
			do
				local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
				PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
			end
			local PA14, PB14
			do
				local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
				PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
			end
			local PA10, PB10
			do
				local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
				PA10, PB10 = bit32.lrotate(TB, 1), (TA)
			end
			local PA1, PB1
			do
				local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
				PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
			end
			local PA17, PB17
			do
				local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
				PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
			end
			local PA8, PB8
			do
				local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
				PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
			end
			local PA24, PB24
			do
				local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
				PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
			end
			local PA20, PB20
			do
				local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
				PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
			end
			local PA11, PB11
			do
				local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
				PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
			end
			local PA2, PB2
			do
				local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
				PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
			end
			local PA18, PB18
			do
				local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
				PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
			end
			local PA9, PB9
			do
				local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
				PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
			end
			local PA5, PB5
			do
				local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
				PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
			end
			local PA21, PB21
			do
				local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
				PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
			end
			local PA12, PB12
			do
				local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
				PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
			end
			local PA3, PB3
			do
				local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
				PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
			end
			local PA19, PB19
			do
				local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
				PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
			end
			local PA15, PB15
			do
				local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
				PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
			end
			local PA6, PB6
			do
				local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
				PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
			end
			local PA22, PB22
			do
				local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
				PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
			end
			local PA13, PB13
			do
				local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
				PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
			end
			local PA4, PB4
			do
				local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
				PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
			end
			A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
			B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
			A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
			B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
			A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
			B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
			A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
			B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
			A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
			B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
			A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
			B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
			A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
			B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
			A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
			B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
			A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
			B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
			A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
			B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
			A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
			B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
			A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
			B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
			A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
			B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
			A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
			B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
			A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
			B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
			A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
			B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
			A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
			B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
			A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
			B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
			A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
			B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
			A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
			B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
			A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
			B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
			A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
			B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
			A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
			B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
			A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
			B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
			A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
			B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
		end
		if RoundIndex < 0 then break end
		do
			local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 12), buffer.readu32(RoundConstantsB, RoundIndex + 12)
			local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
			local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
			local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
			local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
			local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
			local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
			local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
			local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
			local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
			local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
			local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
			local PA16, PB16
			do
				local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
				PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
			end
			local PA7, PB7
			do
				local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
				PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
			end
			local PA23, PB23
			do
				local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
				PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
			end
			local PA14, PB14
			do
				local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
				PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
			end
			local PA10, PB10
			do
				local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
				PA10, PB10 = bit32.lrotate(TB, 1), (TA)
			end
			local PA1, PB1
			do
				local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
				PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
			end
			local PA17, PB17
			do
				local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
				PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
			end
			local PA8, PB8
			do
				local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
				PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
			end
			local PA24, PB24
			do
				local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
				PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
			end
			local PA20, PB20
			do
				local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
				PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
			end
			local PA11, PB11
			do
				local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
				PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
			end
			local PA2, PB2
			do
				local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
				PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
			end
			local PA18, PB18
			do
				local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
				PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
			end
			local PA9, PB9
			do
				local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
				PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
			end
			local PA5, PB5
			do
				local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
				PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
			end
			local PA21, PB21
			do
				local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
				PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
			end
			local PA12, PB12
			do
				local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
				PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
			end
			local PA3, PB3
			do
				local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
				PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
			end
			local PA19, PB19
			do
				local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
				PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
			end
			local PA15, PB15
			do
				local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
				PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
			end
			local PA6, PB6
			do
				local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
				PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
			end
			local PA22, PB22
			do
				local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
				PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
			end
			local PA13, PB13
			do
				local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
				PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
			end
			local PA4, PB4
			do
				local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
				PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
			end
			A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
			B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
			A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
			B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
			A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
			B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
			A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
			B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
			A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
			B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
			A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
			B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
			A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
			B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
			A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
			B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
			A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
			B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
			A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
			B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
			A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
			B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
			A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
			B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
			A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
			B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
			A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
			B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
			A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
			B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
			A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
			B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
			A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
			B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
			A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
			B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
			A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
			B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
			A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
			B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
			A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
			B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
			A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
			B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
			A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
			B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
			A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
			B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
			A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
			B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
		end
	end
	buffer.writeu32(StateA, 0, A0); buffer.writeu32(StateB, 0, B0)
	buffer.writeu32(StateA, 4, bit32.bnot(A1)); buffer.writeu32(StateB, 4, bit32.bnot(B1))
	buffer.writeu32(StateA, 8, bit32.bnot(A2)); buffer.writeu32(StateB, 8, bit32.bnot(B2))
	buffer.writeu32(StateA, 12, A3); buffer.writeu32(StateB, 12, B3)
	buffer.writeu32(StateA, 16, A4); buffer.writeu32(StateB, 16, B4)
	buffer.writeu32(StateA, 20, A5); buffer.writeu32(StateB, 20, B5)
	buffer.writeu32(StateA, 24, A6); buffer.writeu32(StateB, 24, B6)
	buffer.writeu32(StateA, 28, A7); buffer.writeu32(StateB, 28, B7)
	buffer.writeu32(StateA, 32, bit32.bnot(A8)); buffer.writeu32(StateB, 32, bit32.bnot(B8))
	buffer.writeu32(StateA, 36, A9); buffer.writeu32(StateB, 36, B9)
	buffer.writeu32(StateA, 40, A10); buffer.writeu32(StateB, 40, B10)
	buffer.writeu32(StateA, 44, A11); buffer.writeu32(StateB, 44, B11)
	buffer.writeu32(StateA, 48, bit32.bnot(A12)); buffer.writeu32(StateB, 48, bit32.bnot(B12))
	buffer.writeu32(StateA, 52, A13); buffer.writeu32(StateB, 52, B13)
	buffer.writeu32(StateA, 56, A14); buffer.writeu32(StateB, 56, B14)
	buffer.writeu32(StateA, 60, A15); buffer.writeu32(StateB, 60, B15)
	buffer.writeu32(StateA, 64, A16); buffer.writeu32(StateB, 64, B16)
	buffer.writeu32(StateA, 68, bit32.bnot(A17)); buffer.writeu32(StateB, 68, bit32.bnot(B17))
	buffer.writeu32(StateA, 72, A18); buffer.writeu32(StateB, 72, B18)
	buffer.writeu32(StateA, 76, A19); buffer.writeu32(StateB, 76, B19)
	buffer.writeu32(StateA, 80, bit32.bnot(A20)); buffer.writeu32(StateB, 80, bit32.bnot(B20))
	buffer.writeu32(StateA, 84, A21); buffer.writeu32(StateB, 84, B21)
	buffer.writeu32(StateA, 88, A22); buffer.writeu32(StateB, 88, B22)
	buffer.writeu32(StateA, 92, A23); buffer.writeu32(StateB, 92, B23)
	buffer.writeu32(StateA, 96, A24); buffer.writeu32(StateB, 96, B24)
end

local function Absorb17(StateA: buffer, StateB: buffer, Input: buffer, Offset: number, Size: number, Fresh: boolean?)
	local A0, B0, A1, B1, A2, B2, A3, B3, A4, B4, A5, B5, A6, B6, A7, B7, A8, B8, A9, B9, A10, B10, A11, B11, A12, B12, A13, B13, A14, B14, A15, B15, A16, B16, A17, B17, A18, B18, A19, B19, A20, B20, A21, B21, A22, B22, A23, B23, A24, B24
	if Fresh then
		A0, B0 = 0, 0
		A1, B1 = 0xFFFFFFFF, 0xFFFFFFFF
		A2, B2 = 0xFFFFFFFF, 0xFFFFFFFF
		A3, B3 = 0, 0
		A4, B4 = 0, 0
		A5, B5 = 0, 0
		A6, B6 = 0, 0
		A7, B7 = 0, 0
		A8, B8 = 0xFFFFFFFF, 0xFFFFFFFF
		A9, B9 = 0, 0
		A10, B10 = 0, 0
		A11, B11 = 0, 0
		A12, B12 = 0xFFFFFFFF, 0xFFFFFFFF
		A13, B13 = 0, 0
		A14, B14 = 0, 0
		A15, B15 = 0, 0
		A16, B16 = 0, 0
		A17, B17 = 0xFFFFFFFF, 0xFFFFFFFF
		A18, B18 = 0, 0
		A19, B19 = 0, 0
		A20, B20 = 0xFFFFFFFF, 0xFFFFFFFF
		A21, B21 = 0, 0
		A22, B22 = 0, 0
		A23, B23 = 0, 0
		A24, B24 = 0, 0
	else
		A0, B0 = buffer.readu32(StateA, 0), (buffer.readu32(StateB, 0))
		A1, B1 = bit32.bnot(buffer.readu32(StateA, 4)), (bit32.bnot(buffer.readu32(StateB, 4)))
		A2, B2 = bit32.bnot(buffer.readu32(StateA, 8)), (bit32.bnot(buffer.readu32(StateB, 8)))
		A3, B3 = buffer.readu32(StateA, 12), (buffer.readu32(StateB, 12))
		A4, B4 = buffer.readu32(StateA, 16), (buffer.readu32(StateB, 16))
		A5, B5 = buffer.readu32(StateA, 20), (buffer.readu32(StateB, 20))
		A6, B6 = buffer.readu32(StateA, 24), (buffer.readu32(StateB, 24))
		A7, B7 = buffer.readu32(StateA, 28), (buffer.readu32(StateB, 28))
		A8, B8 = bit32.bnot(buffer.readu32(StateA, 32)), (bit32.bnot(buffer.readu32(StateB, 32)))
		A9, B9 = buffer.readu32(StateA, 36), (buffer.readu32(StateB, 36))
		A10, B10 = buffer.readu32(StateA, 40), (buffer.readu32(StateB, 40))
		A11, B11 = buffer.readu32(StateA, 44), (buffer.readu32(StateB, 44))
		A12, B12 = bit32.bnot(buffer.readu32(StateA, 48)), (bit32.bnot(buffer.readu32(StateB, 48)))
		A13, B13 = buffer.readu32(StateA, 52), (buffer.readu32(StateB, 52))
		A14, B14 = buffer.readu32(StateA, 56), (buffer.readu32(StateB, 56))
		A15, B15 = buffer.readu32(StateA, 60), (buffer.readu32(StateB, 60))
		A16, B16 = buffer.readu32(StateA, 64), (buffer.readu32(StateB, 64))
		A17, B17 = bit32.bnot(buffer.readu32(StateA, 68)), (bit32.bnot(buffer.readu32(StateB, 68)))
		A18, B18 = buffer.readu32(StateA, 72), (buffer.readu32(StateB, 72))
		A19, B19 = buffer.readu32(StateA, 76), (buffer.readu32(StateB, 76))
		A20, B20 = bit32.bnot(buffer.readu32(StateA, 80)), (bit32.bnot(buffer.readu32(StateB, 80)))
		A21, B21 = buffer.readu32(StateA, 84), (buffer.readu32(StateB, 84))
		A22, B22 = buffer.readu32(StateA, 88), (buffer.readu32(StateB, 88))
		A23, B23 = buffer.readu32(StateA, 92), (buffer.readu32(StateB, 92))
		A24, B24 = buffer.readu32(StateA, 96), (buffer.readu32(StateB, 96))
	end
	local RoundConstantsA, RoundConstantsB = ROUND_A, ROUND_B
	for Position = Offset, Offset + Size - 1, 136 do
		do
			local Lo, Hi = buffer.readu32(Input, Position + 0), buffer.readu32(Input, Position + 4)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A0 = bit32.bxor(A0, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B0 = bit32.bxor(B0, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 8), buffer.readu32(Input, Position + 12)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A1 = bit32.bxor(A1, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B1 = bit32.bxor(B1, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 16), buffer.readu32(Input, Position + 20)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A2 = bit32.bxor(A2, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B2 = bit32.bxor(B2, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 24), buffer.readu32(Input, Position + 28)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A3 = bit32.bxor(A3, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B3 = bit32.bxor(B3, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 32), buffer.readu32(Input, Position + 36)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A4 = bit32.bxor(A4, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B4 = bit32.bxor(B4, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 40), buffer.readu32(Input, Position + 44)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A5 = bit32.bxor(A5, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B5 = bit32.bxor(B5, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 48), buffer.readu32(Input, Position + 52)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A6 = bit32.bxor(A6, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B6 = bit32.bxor(B6, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 56), buffer.readu32(Input, Position + 60)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A7 = bit32.bxor(A7, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B7 = bit32.bxor(B7, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 64), buffer.readu32(Input, Position + 68)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A8 = bit32.bxor(A8, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B8 = bit32.bxor(B8, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 72), buffer.readu32(Input, Position + 76)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A9 = bit32.bxor(A9, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B9 = bit32.bxor(B9, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 80), buffer.readu32(Input, Position + 84)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A10 = bit32.bxor(A10, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B10 = bit32.bxor(B10, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 88), buffer.readu32(Input, Position + 92)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A11 = bit32.bxor(A11, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B11 = bit32.bxor(B11, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 96), buffer.readu32(Input, Position + 100)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A12 = bit32.bxor(A12, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B12 = bit32.bxor(B12, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 104), buffer.readu32(Input, Position + 108)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A13 = bit32.bxor(A13, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B13 = bit32.bxor(B13, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 112), buffer.readu32(Input, Position + 116)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A14 = bit32.bxor(A14, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B14 = bit32.bxor(B14, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 120), buffer.readu32(Input, Position + 124)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A15 = bit32.bxor(A15, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B15 = bit32.bxor(B15, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 128), buffer.readu32(Input, Position + 132)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A16 = bit32.bxor(A16, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B16 = bit32.bxor(B16, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		for RoundIndex = 0, 80, 16 do
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex), buffer.readu32(RoundConstantsB, RoundIndex)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 4), buffer.readu32(RoundConstantsB, RoundIndex + 4)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 8), buffer.readu32(RoundConstantsB, RoundIndex + 8)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 12), buffer.readu32(RoundConstantsB, RoundIndex + 12)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
		end
	end
	buffer.writeu32(StateA, 0, A0); buffer.writeu32(StateB, 0, B0)
	buffer.writeu32(StateA, 4, bit32.bnot(A1)); buffer.writeu32(StateB, 4, bit32.bnot(B1))
	buffer.writeu32(StateA, 8, bit32.bnot(A2)); buffer.writeu32(StateB, 8, bit32.bnot(B2))
	buffer.writeu32(StateA, 12, A3); buffer.writeu32(StateB, 12, B3)
	buffer.writeu32(StateA, 16, A4); buffer.writeu32(StateB, 16, B4)
	buffer.writeu32(StateA, 20, A5); buffer.writeu32(StateB, 20, B5)
	buffer.writeu32(StateA, 24, A6); buffer.writeu32(StateB, 24, B6)
	buffer.writeu32(StateA, 28, A7); buffer.writeu32(StateB, 28, B7)
	buffer.writeu32(StateA, 32, bit32.bnot(A8)); buffer.writeu32(StateB, 32, bit32.bnot(B8))
	buffer.writeu32(StateA, 36, A9); buffer.writeu32(StateB, 36, B9)
	buffer.writeu32(StateA, 40, A10); buffer.writeu32(StateB, 40, B10)
	buffer.writeu32(StateA, 44, A11); buffer.writeu32(StateB, 44, B11)
	buffer.writeu32(StateA, 48, bit32.bnot(A12)); buffer.writeu32(StateB, 48, bit32.bnot(B12))
	buffer.writeu32(StateA, 52, A13); buffer.writeu32(StateB, 52, B13)
	buffer.writeu32(StateA, 56, A14); buffer.writeu32(StateB, 56, B14)
	buffer.writeu32(StateA, 60, A15); buffer.writeu32(StateB, 60, B15)
	buffer.writeu32(StateA, 64, A16); buffer.writeu32(StateB, 64, B16)
	buffer.writeu32(StateA, 68, bit32.bnot(A17)); buffer.writeu32(StateB, 68, bit32.bnot(B17))
	buffer.writeu32(StateA, 72, A18); buffer.writeu32(StateB, 72, B18)
	buffer.writeu32(StateA, 76, A19); buffer.writeu32(StateB, 76, B19)
	buffer.writeu32(StateA, 80, bit32.bnot(A20)); buffer.writeu32(StateB, 80, bit32.bnot(B20))
	buffer.writeu32(StateA, 84, A21); buffer.writeu32(StateB, 84, B21)
	buffer.writeu32(StateA, 88, A22); buffer.writeu32(StateB, 88, B22)
	buffer.writeu32(StateA, 92, A23); buffer.writeu32(StateB, 92, B23)
	buffer.writeu32(StateA, 96, A24); buffer.writeu32(StateB, 96, B24)
end

local function Absorb21(StateA: buffer, StateB: buffer, Input: buffer, Offset: number, Size: number, Fresh: boolean?)
	local A0, B0, A1, B1, A2, B2, A3, B3, A4, B4, A5, B5, A6, B6, A7, B7, A8, B8, A9, B9, A10, B10, A11, B11, A12, B12, A13, B13, A14, B14, A15, B15, A16, B16, A17, B17, A18, B18, A19, B19, A20, B20, A21, B21, A22, B22, A23, B23, A24, B24
	if Fresh then
		A0, B0 = 0, 0
		A1, B1 = 0xFFFFFFFF, 0xFFFFFFFF
		A2, B2 = 0xFFFFFFFF, 0xFFFFFFFF
		A3, B3 = 0, 0
		A4, B4 = 0, 0
		A5, B5 = 0, 0
		A6, B6 = 0, 0
		A7, B7 = 0, 0
		A8, B8 = 0xFFFFFFFF, 0xFFFFFFFF
		A9, B9 = 0, 0
		A10, B10 = 0, 0
		A11, B11 = 0, 0
		A12, B12 = 0xFFFFFFFF, 0xFFFFFFFF
		A13, B13 = 0, 0
		A14, B14 = 0, 0
		A15, B15 = 0, 0
		A16, B16 = 0, 0
		A17, B17 = 0xFFFFFFFF, 0xFFFFFFFF
		A18, B18 = 0, 0
		A19, B19 = 0, 0
		A20, B20 = 0xFFFFFFFF, 0xFFFFFFFF
		A21, B21 = 0, 0
		A22, B22 = 0, 0
		A23, B23 = 0, 0
		A24, B24 = 0, 0
	else
		A0, B0 = buffer.readu32(StateA, 0), (buffer.readu32(StateB, 0))
		A1, B1 = bit32.bnot(buffer.readu32(StateA, 4)), (bit32.bnot(buffer.readu32(StateB, 4)))
		A2, B2 = bit32.bnot(buffer.readu32(StateA, 8)), (bit32.bnot(buffer.readu32(StateB, 8)))
		A3, B3 = buffer.readu32(StateA, 12), (buffer.readu32(StateB, 12))
		A4, B4 = buffer.readu32(StateA, 16), (buffer.readu32(StateB, 16))
		A5, B5 = buffer.readu32(StateA, 20), (buffer.readu32(StateB, 20))
		A6, B6 = buffer.readu32(StateA, 24), (buffer.readu32(StateB, 24))
		A7, B7 = buffer.readu32(StateA, 28), (buffer.readu32(StateB, 28))
		A8, B8 = bit32.bnot(buffer.readu32(StateA, 32)), (bit32.bnot(buffer.readu32(StateB, 32)))
		A9, B9 = buffer.readu32(StateA, 36), (buffer.readu32(StateB, 36))
		A10, B10 = buffer.readu32(StateA, 40), (buffer.readu32(StateB, 40))
		A11, B11 = buffer.readu32(StateA, 44), (buffer.readu32(StateB, 44))
		A12, B12 = bit32.bnot(buffer.readu32(StateA, 48)), (bit32.bnot(buffer.readu32(StateB, 48)))
		A13, B13 = buffer.readu32(StateA, 52), (buffer.readu32(StateB, 52))
		A14, B14 = buffer.readu32(StateA, 56), (buffer.readu32(StateB, 56))
		A15, B15 = buffer.readu32(StateA, 60), (buffer.readu32(StateB, 60))
		A16, B16 = buffer.readu32(StateA, 64), (buffer.readu32(StateB, 64))
		A17, B17 = bit32.bnot(buffer.readu32(StateA, 68)), (bit32.bnot(buffer.readu32(StateB, 68)))
		A18, B18 = buffer.readu32(StateA, 72), (buffer.readu32(StateB, 72))
		A19, B19 = buffer.readu32(StateA, 76), (buffer.readu32(StateB, 76))
		A20, B20 = bit32.bnot(buffer.readu32(StateA, 80)), (bit32.bnot(buffer.readu32(StateB, 80)))
		A21, B21 = buffer.readu32(StateA, 84), (buffer.readu32(StateB, 84))
		A22, B22 = buffer.readu32(StateA, 88), (buffer.readu32(StateB, 88))
		A23, B23 = buffer.readu32(StateA, 92), (buffer.readu32(StateB, 92))
		A24, B24 = buffer.readu32(StateA, 96), (buffer.readu32(StateB, 96))
	end
	local RoundConstantsA, RoundConstantsB = ROUND_A, ROUND_B
	for Position = Offset, Offset + Size - 1, 168 do
		do
			local Lo, Hi = buffer.readu32(Input, Position + 0), buffer.readu32(Input, Position + 4)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A0 = bit32.bxor(A0, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B0 = bit32.bxor(B0, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 8), buffer.readu32(Input, Position + 12)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A1 = bit32.bxor(A1, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B1 = bit32.bxor(B1, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 16), buffer.readu32(Input, Position + 20)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A2 = bit32.bxor(A2, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B2 = bit32.bxor(B2, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 24), buffer.readu32(Input, Position + 28)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A3 = bit32.bxor(A3, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B3 = bit32.bxor(B3, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 32), buffer.readu32(Input, Position + 36)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A4 = bit32.bxor(A4, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B4 = bit32.bxor(B4, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 40), buffer.readu32(Input, Position + 44)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A5 = bit32.bxor(A5, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B5 = bit32.bxor(B5, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 48), buffer.readu32(Input, Position + 52)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A6 = bit32.bxor(A6, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B6 = bit32.bxor(B6, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 56), buffer.readu32(Input, Position + 60)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A7 = bit32.bxor(A7, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B7 = bit32.bxor(B7, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 64), buffer.readu32(Input, Position + 68)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A8 = bit32.bxor(A8, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B8 = bit32.bxor(B8, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 72), buffer.readu32(Input, Position + 76)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A9 = bit32.bxor(A9, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B9 = bit32.bxor(B9, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 80), buffer.readu32(Input, Position + 84)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A10 = bit32.bxor(A10, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B10 = bit32.bxor(B10, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 88), buffer.readu32(Input, Position + 92)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A11 = bit32.bxor(A11, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B11 = bit32.bxor(B11, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 96), buffer.readu32(Input, Position + 100)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A12 = bit32.bxor(A12, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B12 = bit32.bxor(B12, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 104), buffer.readu32(Input, Position + 108)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A13 = bit32.bxor(A13, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B13 = bit32.bxor(B13, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 112), buffer.readu32(Input, Position + 116)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A14 = bit32.bxor(A14, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B14 = bit32.bxor(B14, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 120), buffer.readu32(Input, Position + 124)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A15 = bit32.bxor(A15, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B15 = bit32.bxor(B15, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 128), buffer.readu32(Input, Position + 132)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A16 = bit32.bxor(A16, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B16 = bit32.bxor(B16, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 136), buffer.readu32(Input, Position + 140)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A17 = bit32.bxor(A17, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B17 = bit32.bxor(B17, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 144), buffer.readu32(Input, Position + 148)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A18 = bit32.bxor(A18, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B18 = bit32.bxor(B18, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 152), buffer.readu32(Input, Position + 156)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A19 = bit32.bxor(A19, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B19 = bit32.bxor(B19, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 160), buffer.readu32(Input, Position + 164)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A20 = bit32.bxor(A20, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B20 = bit32.bxor(B20, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		for RoundIndex = 0, 80, 16 do
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex), buffer.readu32(RoundConstantsB, RoundIndex)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 4), buffer.readu32(RoundConstantsB, RoundIndex + 4)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 8), buffer.readu32(RoundConstantsB, RoundIndex + 8)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 12), buffer.readu32(RoundConstantsB, RoundIndex + 12)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
		end
	end
	buffer.writeu32(StateA, 0, A0); buffer.writeu32(StateB, 0, B0)
	buffer.writeu32(StateA, 4, bit32.bnot(A1)); buffer.writeu32(StateB, 4, bit32.bnot(B1))
	buffer.writeu32(StateA, 8, bit32.bnot(A2)); buffer.writeu32(StateB, 8, bit32.bnot(B2))
	buffer.writeu32(StateA, 12, A3); buffer.writeu32(StateB, 12, B3)
	buffer.writeu32(StateA, 16, A4); buffer.writeu32(StateB, 16, B4)
	buffer.writeu32(StateA, 20, A5); buffer.writeu32(StateB, 20, B5)
	buffer.writeu32(StateA, 24, A6); buffer.writeu32(StateB, 24, B6)
	buffer.writeu32(StateA, 28, A7); buffer.writeu32(StateB, 28, B7)
	buffer.writeu32(StateA, 32, bit32.bnot(A8)); buffer.writeu32(StateB, 32, bit32.bnot(B8))
	buffer.writeu32(StateA, 36, A9); buffer.writeu32(StateB, 36, B9)
	buffer.writeu32(StateA, 40, A10); buffer.writeu32(StateB, 40, B10)
	buffer.writeu32(StateA, 44, A11); buffer.writeu32(StateB, 44, B11)
	buffer.writeu32(StateA, 48, bit32.bnot(A12)); buffer.writeu32(StateB, 48, bit32.bnot(B12))
	buffer.writeu32(StateA, 52, A13); buffer.writeu32(StateB, 52, B13)
	buffer.writeu32(StateA, 56, A14); buffer.writeu32(StateB, 56, B14)
	buffer.writeu32(StateA, 60, A15); buffer.writeu32(StateB, 60, B15)
	buffer.writeu32(StateA, 64, A16); buffer.writeu32(StateB, 64, B16)
	buffer.writeu32(StateA, 68, bit32.bnot(A17)); buffer.writeu32(StateB, 68, bit32.bnot(B17))
	buffer.writeu32(StateA, 72, A18); buffer.writeu32(StateB, 72, B18)
	buffer.writeu32(StateA, 76, A19); buffer.writeu32(StateB, 76, B19)
	buffer.writeu32(StateA, 80, bit32.bnot(A20)); buffer.writeu32(StateB, 80, bit32.bnot(B20))
	buffer.writeu32(StateA, 84, A21); buffer.writeu32(StateB, 84, B21)
	buffer.writeu32(StateA, 88, A22); buffer.writeu32(StateB, 88, B22)
	buffer.writeu32(StateA, 92, A23); buffer.writeu32(StateB, 92, B23)
	buffer.writeu32(StateA, 96, A24); buffer.writeu32(StateB, 96, B24)
end

local function Absorb9(StateA: buffer, StateB: buffer, Input: buffer, Offset: number, Size: number, Fresh: boolean?)
	local A0, B0, A1, B1, A2, B2, A3, B3, A4, B4, A5, B5, A6, B6, A7, B7, A8, B8, A9, B9, A10, B10, A11, B11, A12, B12, A13, B13, A14, B14, A15, B15, A16, B16, A17, B17, A18, B18, A19, B19, A20, B20, A21, B21, A22, B22, A23, B23, A24, B24
	if Fresh then
		A0, B0 = 0, 0
		A1, B1 = 0xFFFFFFFF, 0xFFFFFFFF
		A2, B2 = 0xFFFFFFFF, 0xFFFFFFFF
		A3, B3 = 0, 0
		A4, B4 = 0, 0
		A5, B5 = 0, 0
		A6, B6 = 0, 0
		A7, B7 = 0, 0
		A8, B8 = 0xFFFFFFFF, 0xFFFFFFFF
		A9, B9 = 0, 0
		A10, B10 = 0, 0
		A11, B11 = 0, 0
		A12, B12 = 0xFFFFFFFF, 0xFFFFFFFF
		A13, B13 = 0, 0
		A14, B14 = 0, 0
		A15, B15 = 0, 0
		A16, B16 = 0, 0
		A17, B17 = 0xFFFFFFFF, 0xFFFFFFFF
		A18, B18 = 0, 0
		A19, B19 = 0, 0
		A20, B20 = 0xFFFFFFFF, 0xFFFFFFFF
		A21, B21 = 0, 0
		A22, B22 = 0, 0
		A23, B23 = 0, 0
		A24, B24 = 0, 0
	else
		A0, B0 = buffer.readu32(StateA, 0), (buffer.readu32(StateB, 0))
		A1, B1 = bit32.bnot(buffer.readu32(StateA, 4)), (bit32.bnot(buffer.readu32(StateB, 4)))
		A2, B2 = bit32.bnot(buffer.readu32(StateA, 8)), (bit32.bnot(buffer.readu32(StateB, 8)))
		A3, B3 = buffer.readu32(StateA, 12), (buffer.readu32(StateB, 12))
		A4, B4 = buffer.readu32(StateA, 16), (buffer.readu32(StateB, 16))
		A5, B5 = buffer.readu32(StateA, 20), (buffer.readu32(StateB, 20))
		A6, B6 = buffer.readu32(StateA, 24), (buffer.readu32(StateB, 24))
		A7, B7 = buffer.readu32(StateA, 28), (buffer.readu32(StateB, 28))
		A8, B8 = bit32.bnot(buffer.readu32(StateA, 32)), (bit32.bnot(buffer.readu32(StateB, 32)))
		A9, B9 = buffer.readu32(StateA, 36), (buffer.readu32(StateB, 36))
		A10, B10 = buffer.readu32(StateA, 40), (buffer.readu32(StateB, 40))
		A11, B11 = buffer.readu32(StateA, 44), (buffer.readu32(StateB, 44))
		A12, B12 = bit32.bnot(buffer.readu32(StateA, 48)), (bit32.bnot(buffer.readu32(StateB, 48)))
		A13, B13 = buffer.readu32(StateA, 52), (buffer.readu32(StateB, 52))
		A14, B14 = buffer.readu32(StateA, 56), (buffer.readu32(StateB, 56))
		A15, B15 = buffer.readu32(StateA, 60), (buffer.readu32(StateB, 60))
		A16, B16 = buffer.readu32(StateA, 64), (buffer.readu32(StateB, 64))
		A17, B17 = bit32.bnot(buffer.readu32(StateA, 68)), (bit32.bnot(buffer.readu32(StateB, 68)))
		A18, B18 = buffer.readu32(StateA, 72), (buffer.readu32(StateB, 72))
		A19, B19 = buffer.readu32(StateA, 76), (buffer.readu32(StateB, 76))
		A20, B20 = bit32.bnot(buffer.readu32(StateA, 80)), (bit32.bnot(buffer.readu32(StateB, 80)))
		A21, B21 = buffer.readu32(StateA, 84), (buffer.readu32(StateB, 84))
		A22, B22 = buffer.readu32(StateA, 88), (buffer.readu32(StateB, 88))
		A23, B23 = buffer.readu32(StateA, 92), (buffer.readu32(StateB, 92))
		A24, B24 = buffer.readu32(StateA, 96), (buffer.readu32(StateB, 96))
	end
	local RoundConstantsA, RoundConstantsB = ROUND_A, ROUND_B
	for Position = Offset, Offset + Size - 1, 72 do
		do
			local Lo, Hi = buffer.readu32(Input, Position + 0), buffer.readu32(Input, Position + 4)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A0 = bit32.bxor(A0, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B0 = bit32.bxor(B0, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 8), buffer.readu32(Input, Position + 12)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A1 = bit32.bxor(A1, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B1 = bit32.bxor(B1, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 16), buffer.readu32(Input, Position + 20)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A2 = bit32.bxor(A2, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B2 = bit32.bxor(B2, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 24), buffer.readu32(Input, Position + 28)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A3 = bit32.bxor(A3, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B3 = bit32.bxor(B3, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 32), buffer.readu32(Input, Position + 36)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A4 = bit32.bxor(A4, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B4 = bit32.bxor(B4, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 40), buffer.readu32(Input, Position + 44)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A5 = bit32.bxor(A5, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B5 = bit32.bxor(B5, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 48), buffer.readu32(Input, Position + 52)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A6 = bit32.bxor(A6, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B6 = bit32.bxor(B6, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 56), buffer.readu32(Input, Position + 60)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A7 = bit32.bxor(A7, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B7 = bit32.bxor(B7, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 64), buffer.readu32(Input, Position + 68)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A8 = bit32.bxor(A8, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B8 = bit32.bxor(B8, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		for RoundIndex = 0, 80, 16 do
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex), buffer.readu32(RoundConstantsB, RoundIndex)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 4), buffer.readu32(RoundConstantsB, RoundIndex + 4)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 8), buffer.readu32(RoundConstantsB, RoundIndex + 8)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 12), buffer.readu32(RoundConstantsB, RoundIndex + 12)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
		end
	end
	buffer.writeu32(StateA, 0, A0); buffer.writeu32(StateB, 0, B0)
	buffer.writeu32(StateA, 4, bit32.bnot(A1)); buffer.writeu32(StateB, 4, bit32.bnot(B1))
	buffer.writeu32(StateA, 8, bit32.bnot(A2)); buffer.writeu32(StateB, 8, bit32.bnot(B2))
	buffer.writeu32(StateA, 12, A3); buffer.writeu32(StateB, 12, B3)
	buffer.writeu32(StateA, 16, A4); buffer.writeu32(StateB, 16, B4)
	buffer.writeu32(StateA, 20, A5); buffer.writeu32(StateB, 20, B5)
	buffer.writeu32(StateA, 24, A6); buffer.writeu32(StateB, 24, B6)
	buffer.writeu32(StateA, 28, A7); buffer.writeu32(StateB, 28, B7)
	buffer.writeu32(StateA, 32, bit32.bnot(A8)); buffer.writeu32(StateB, 32, bit32.bnot(B8))
	buffer.writeu32(StateA, 36, A9); buffer.writeu32(StateB, 36, B9)
	buffer.writeu32(StateA, 40, A10); buffer.writeu32(StateB, 40, B10)
	buffer.writeu32(StateA, 44, A11); buffer.writeu32(StateB, 44, B11)
	buffer.writeu32(StateA, 48, bit32.bnot(A12)); buffer.writeu32(StateB, 48, bit32.bnot(B12))
	buffer.writeu32(StateA, 52, A13); buffer.writeu32(StateB, 52, B13)
	buffer.writeu32(StateA, 56, A14); buffer.writeu32(StateB, 56, B14)
	buffer.writeu32(StateA, 60, A15); buffer.writeu32(StateB, 60, B15)
	buffer.writeu32(StateA, 64, A16); buffer.writeu32(StateB, 64, B16)
	buffer.writeu32(StateA, 68, bit32.bnot(A17)); buffer.writeu32(StateB, 68, bit32.bnot(B17))
	buffer.writeu32(StateA, 72, A18); buffer.writeu32(StateB, 72, B18)
	buffer.writeu32(StateA, 76, A19); buffer.writeu32(StateB, 76, B19)
	buffer.writeu32(StateA, 80, bit32.bnot(A20)); buffer.writeu32(StateB, 80, bit32.bnot(B20))
	buffer.writeu32(StateA, 84, A21); buffer.writeu32(StateB, 84, B21)
	buffer.writeu32(StateA, 88, A22); buffer.writeu32(StateB, 88, B22)
	buffer.writeu32(StateA, 92, A23); buffer.writeu32(StateB, 92, B23)
	buffer.writeu32(StateA, 96, A24); buffer.writeu32(StateB, 96, B24)
end

local function Absorb13(StateA: buffer, StateB: buffer, Input: buffer, Offset: number, Size: number, Fresh: boolean?)
	local A0, B0, A1, B1, A2, B2, A3, B3, A4, B4, A5, B5, A6, B6, A7, B7, A8, B8, A9, B9, A10, B10, A11, B11, A12, B12, A13, B13, A14, B14, A15, B15, A16, B16, A17, B17, A18, B18, A19, B19, A20, B20, A21, B21, A22, B22, A23, B23, A24, B24
	if Fresh then
		A0, B0 = 0, 0
		A1, B1 = 0xFFFFFFFF, 0xFFFFFFFF
		A2, B2 = 0xFFFFFFFF, 0xFFFFFFFF
		A3, B3 = 0, 0
		A4, B4 = 0, 0
		A5, B5 = 0, 0
		A6, B6 = 0, 0
		A7, B7 = 0, 0
		A8, B8 = 0xFFFFFFFF, 0xFFFFFFFF
		A9, B9 = 0, 0
		A10, B10 = 0, 0
		A11, B11 = 0, 0
		A12, B12 = 0xFFFFFFFF, 0xFFFFFFFF
		A13, B13 = 0, 0
		A14, B14 = 0, 0
		A15, B15 = 0, 0
		A16, B16 = 0, 0
		A17, B17 = 0xFFFFFFFF, 0xFFFFFFFF
		A18, B18 = 0, 0
		A19, B19 = 0, 0
		A20, B20 = 0xFFFFFFFF, 0xFFFFFFFF
		A21, B21 = 0, 0
		A22, B22 = 0, 0
		A23, B23 = 0, 0
		A24, B24 = 0, 0
	else
		A0, B0 = buffer.readu32(StateA, 0), (buffer.readu32(StateB, 0))
		A1, B1 = bit32.bnot(buffer.readu32(StateA, 4)), (bit32.bnot(buffer.readu32(StateB, 4)))
		A2, B2 = bit32.bnot(buffer.readu32(StateA, 8)), (bit32.bnot(buffer.readu32(StateB, 8)))
		A3, B3 = buffer.readu32(StateA, 12), (buffer.readu32(StateB, 12))
		A4, B4 = buffer.readu32(StateA, 16), (buffer.readu32(StateB, 16))
		A5, B5 = buffer.readu32(StateA, 20), (buffer.readu32(StateB, 20))
		A6, B6 = buffer.readu32(StateA, 24), (buffer.readu32(StateB, 24))
		A7, B7 = buffer.readu32(StateA, 28), (buffer.readu32(StateB, 28))
		A8, B8 = bit32.bnot(buffer.readu32(StateA, 32)), (bit32.bnot(buffer.readu32(StateB, 32)))
		A9, B9 = buffer.readu32(StateA, 36), (buffer.readu32(StateB, 36))
		A10, B10 = buffer.readu32(StateA, 40), (buffer.readu32(StateB, 40))
		A11, B11 = buffer.readu32(StateA, 44), (buffer.readu32(StateB, 44))
		A12, B12 = bit32.bnot(buffer.readu32(StateA, 48)), (bit32.bnot(buffer.readu32(StateB, 48)))
		A13, B13 = buffer.readu32(StateA, 52), (buffer.readu32(StateB, 52))
		A14, B14 = buffer.readu32(StateA, 56), (buffer.readu32(StateB, 56))
		A15, B15 = buffer.readu32(StateA, 60), (buffer.readu32(StateB, 60))
		A16, B16 = buffer.readu32(StateA, 64), (buffer.readu32(StateB, 64))
		A17, B17 = bit32.bnot(buffer.readu32(StateA, 68)), (bit32.bnot(buffer.readu32(StateB, 68)))
		A18, B18 = buffer.readu32(StateA, 72), (buffer.readu32(StateB, 72))
		A19, B19 = buffer.readu32(StateA, 76), (buffer.readu32(StateB, 76))
		A20, B20 = bit32.bnot(buffer.readu32(StateA, 80)), (bit32.bnot(buffer.readu32(StateB, 80)))
		A21, B21 = buffer.readu32(StateA, 84), (buffer.readu32(StateB, 84))
		A22, B22 = buffer.readu32(StateA, 88), (buffer.readu32(StateB, 88))
		A23, B23 = buffer.readu32(StateA, 92), (buffer.readu32(StateB, 92))
		A24, B24 = buffer.readu32(StateA, 96), (buffer.readu32(StateB, 96))
	end
	local RoundConstantsA, RoundConstantsB = ROUND_A, ROUND_B
	for Position = Offset, Offset + Size - 1, 104 do
		do
			local Lo, Hi = buffer.readu32(Input, Position + 0), buffer.readu32(Input, Position + 4)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A0 = bit32.bxor(A0, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B0 = bit32.bxor(B0, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 8), buffer.readu32(Input, Position + 12)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A1 = bit32.bxor(A1, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B1 = bit32.bxor(B1, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 16), buffer.readu32(Input, Position + 20)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A2 = bit32.bxor(A2, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B2 = bit32.bxor(B2, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 24), buffer.readu32(Input, Position + 28)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A3 = bit32.bxor(A3, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B3 = bit32.bxor(B3, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 32), buffer.readu32(Input, Position + 36)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A4 = bit32.bxor(A4, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B4 = bit32.bxor(B4, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 40), buffer.readu32(Input, Position + 44)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A5 = bit32.bxor(A5, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B5 = bit32.bxor(B5, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 48), buffer.readu32(Input, Position + 52)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A6 = bit32.bxor(A6, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B6 = bit32.bxor(B6, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 56), buffer.readu32(Input, Position + 60)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A7 = bit32.bxor(A7, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B7 = bit32.bxor(B7, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 64), buffer.readu32(Input, Position + 68)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A8 = bit32.bxor(A8, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B8 = bit32.bxor(B8, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 72), buffer.readu32(Input, Position + 76)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A9 = bit32.bxor(A9, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B9 = bit32.bxor(B9, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 80), buffer.readu32(Input, Position + 84)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A10 = bit32.bxor(A10, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B10 = bit32.bxor(B10, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 88), buffer.readu32(Input, Position + 92)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A11 = bit32.bxor(A11, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B11 = bit32.bxor(B11, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 96), buffer.readu32(Input, Position + 100)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A12 = bit32.bxor(A12, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B12 = bit32.bxor(B12, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		for RoundIndex = 0, 80, 16 do
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex), buffer.readu32(RoundConstantsB, RoundIndex)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 4), buffer.readu32(RoundConstantsB, RoundIndex + 4)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 8), buffer.readu32(RoundConstantsB, RoundIndex + 8)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 12), buffer.readu32(RoundConstantsB, RoundIndex + 12)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
		end
	end
	buffer.writeu32(StateA, 0, A0); buffer.writeu32(StateB, 0, B0)
	buffer.writeu32(StateA, 4, bit32.bnot(A1)); buffer.writeu32(StateB, 4, bit32.bnot(B1))
	buffer.writeu32(StateA, 8, bit32.bnot(A2)); buffer.writeu32(StateB, 8, bit32.bnot(B2))
	buffer.writeu32(StateA, 12, A3); buffer.writeu32(StateB, 12, B3)
	buffer.writeu32(StateA, 16, A4); buffer.writeu32(StateB, 16, B4)
	buffer.writeu32(StateA, 20, A5); buffer.writeu32(StateB, 20, B5)
	buffer.writeu32(StateA, 24, A6); buffer.writeu32(StateB, 24, B6)
	buffer.writeu32(StateA, 28, A7); buffer.writeu32(StateB, 28, B7)
	buffer.writeu32(StateA, 32, bit32.bnot(A8)); buffer.writeu32(StateB, 32, bit32.bnot(B8))
	buffer.writeu32(StateA, 36, A9); buffer.writeu32(StateB, 36, B9)
	buffer.writeu32(StateA, 40, A10); buffer.writeu32(StateB, 40, B10)
	buffer.writeu32(StateA, 44, A11); buffer.writeu32(StateB, 44, B11)
	buffer.writeu32(StateA, 48, bit32.bnot(A12)); buffer.writeu32(StateB, 48, bit32.bnot(B12))
	buffer.writeu32(StateA, 52, A13); buffer.writeu32(StateB, 52, B13)
	buffer.writeu32(StateA, 56, A14); buffer.writeu32(StateB, 56, B14)
	buffer.writeu32(StateA, 60, A15); buffer.writeu32(StateB, 60, B15)
	buffer.writeu32(StateA, 64, A16); buffer.writeu32(StateB, 64, B16)
	buffer.writeu32(StateA, 68, bit32.bnot(A17)); buffer.writeu32(StateB, 68, bit32.bnot(B17))
	buffer.writeu32(StateA, 72, A18); buffer.writeu32(StateB, 72, B18)
	buffer.writeu32(StateA, 76, A19); buffer.writeu32(StateB, 76, B19)
	buffer.writeu32(StateA, 80, bit32.bnot(A20)); buffer.writeu32(StateB, 80, bit32.bnot(B20))
	buffer.writeu32(StateA, 84, A21); buffer.writeu32(StateB, 84, B21)
	buffer.writeu32(StateA, 88, A22); buffer.writeu32(StateB, 88, B22)
	buffer.writeu32(StateA, 92, A23); buffer.writeu32(StateB, 92, B23)
	buffer.writeu32(StateA, 96, A24); buffer.writeu32(StateB, 96, B24)
end

local function Absorb18(StateA: buffer, StateB: buffer, Input: buffer, Offset: number, Size: number, Fresh: boolean?)
	local A0, B0, A1, B1, A2, B2, A3, B3, A4, B4, A5, B5, A6, B6, A7, B7, A8, B8, A9, B9, A10, B10, A11, B11, A12, B12, A13, B13, A14, B14, A15, B15, A16, B16, A17, B17, A18, B18, A19, B19, A20, B20, A21, B21, A22, B22, A23, B23, A24, B24
	if Fresh then
		A0, B0 = 0, 0
		A1, B1 = 0xFFFFFFFF, 0xFFFFFFFF
		A2, B2 = 0xFFFFFFFF, 0xFFFFFFFF
		A3, B3 = 0, 0
		A4, B4 = 0, 0
		A5, B5 = 0, 0
		A6, B6 = 0, 0
		A7, B7 = 0, 0
		A8, B8 = 0xFFFFFFFF, 0xFFFFFFFF
		A9, B9 = 0, 0
		A10, B10 = 0, 0
		A11, B11 = 0, 0
		A12, B12 = 0xFFFFFFFF, 0xFFFFFFFF
		A13, B13 = 0, 0
		A14, B14 = 0, 0
		A15, B15 = 0, 0
		A16, B16 = 0, 0
		A17, B17 = 0xFFFFFFFF, 0xFFFFFFFF
		A18, B18 = 0, 0
		A19, B19 = 0, 0
		A20, B20 = 0xFFFFFFFF, 0xFFFFFFFF
		A21, B21 = 0, 0
		A22, B22 = 0, 0
		A23, B23 = 0, 0
		A24, B24 = 0, 0
	else
		A0, B0 = buffer.readu32(StateA, 0), (buffer.readu32(StateB, 0))
		A1, B1 = bit32.bnot(buffer.readu32(StateA, 4)), (bit32.bnot(buffer.readu32(StateB, 4)))
		A2, B2 = bit32.bnot(buffer.readu32(StateA, 8)), (bit32.bnot(buffer.readu32(StateB, 8)))
		A3, B3 = buffer.readu32(StateA, 12), (buffer.readu32(StateB, 12))
		A4, B4 = buffer.readu32(StateA, 16), (buffer.readu32(StateB, 16))
		A5, B5 = buffer.readu32(StateA, 20), (buffer.readu32(StateB, 20))
		A6, B6 = buffer.readu32(StateA, 24), (buffer.readu32(StateB, 24))
		A7, B7 = buffer.readu32(StateA, 28), (buffer.readu32(StateB, 28))
		A8, B8 = bit32.bnot(buffer.readu32(StateA, 32)), (bit32.bnot(buffer.readu32(StateB, 32)))
		A9, B9 = buffer.readu32(StateA, 36), (buffer.readu32(StateB, 36))
		A10, B10 = buffer.readu32(StateA, 40), (buffer.readu32(StateB, 40))
		A11, B11 = buffer.readu32(StateA, 44), (buffer.readu32(StateB, 44))
		A12, B12 = bit32.bnot(buffer.readu32(StateA, 48)), (bit32.bnot(buffer.readu32(StateB, 48)))
		A13, B13 = buffer.readu32(StateA, 52), (buffer.readu32(StateB, 52))
		A14, B14 = buffer.readu32(StateA, 56), (buffer.readu32(StateB, 56))
		A15, B15 = buffer.readu32(StateA, 60), (buffer.readu32(StateB, 60))
		A16, B16 = buffer.readu32(StateA, 64), (buffer.readu32(StateB, 64))
		A17, B17 = bit32.bnot(buffer.readu32(StateA, 68)), (bit32.bnot(buffer.readu32(StateB, 68)))
		A18, B18 = buffer.readu32(StateA, 72), (buffer.readu32(StateB, 72))
		A19, B19 = buffer.readu32(StateA, 76), (buffer.readu32(StateB, 76))
		A20, B20 = bit32.bnot(buffer.readu32(StateA, 80)), (bit32.bnot(buffer.readu32(StateB, 80)))
		A21, B21 = buffer.readu32(StateA, 84), (buffer.readu32(StateB, 84))
		A22, B22 = buffer.readu32(StateA, 88), (buffer.readu32(StateB, 88))
		A23, B23 = buffer.readu32(StateA, 92), (buffer.readu32(StateB, 92))
		A24, B24 = buffer.readu32(StateA, 96), (buffer.readu32(StateB, 96))
	end
	local RoundConstantsA, RoundConstantsB = ROUND_A, ROUND_B
	for Position = Offset, Offset + Size - 1, 144 do
		do
			local Lo, Hi = buffer.readu32(Input, Position + 0), buffer.readu32(Input, Position + 4)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A0 = bit32.bxor(A0, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B0 = bit32.bxor(B0, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 8), buffer.readu32(Input, Position + 12)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A1 = bit32.bxor(A1, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B1 = bit32.bxor(B1, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 16), buffer.readu32(Input, Position + 20)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A2 = bit32.bxor(A2, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B2 = bit32.bxor(B2, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 24), buffer.readu32(Input, Position + 28)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A3 = bit32.bxor(A3, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B3 = bit32.bxor(B3, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 32), buffer.readu32(Input, Position + 36)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A4 = bit32.bxor(A4, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B4 = bit32.bxor(B4, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 40), buffer.readu32(Input, Position + 44)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A5 = bit32.bxor(A5, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B5 = bit32.bxor(B5, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 48), buffer.readu32(Input, Position + 52)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A6 = bit32.bxor(A6, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B6 = bit32.bxor(B6, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 56), buffer.readu32(Input, Position + 60)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A7 = bit32.bxor(A7, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B7 = bit32.bxor(B7, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 64), buffer.readu32(Input, Position + 68)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A8 = bit32.bxor(A8, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B8 = bit32.bxor(B8, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 72), buffer.readu32(Input, Position + 76)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A9 = bit32.bxor(A9, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B9 = bit32.bxor(B9, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 80), buffer.readu32(Input, Position + 84)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A10 = bit32.bxor(A10, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B10 = bit32.bxor(B10, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 88), buffer.readu32(Input, Position + 92)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A11 = bit32.bxor(A11, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B11 = bit32.bxor(B11, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 96), buffer.readu32(Input, Position + 100)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A12 = bit32.bxor(A12, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B12 = bit32.bxor(B12, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 104), buffer.readu32(Input, Position + 108)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A13 = bit32.bxor(A13, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B13 = bit32.bxor(B13, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 112), buffer.readu32(Input, Position + 116)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A14 = bit32.bxor(A14, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B14 = bit32.bxor(B14, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 120), buffer.readu32(Input, Position + 124)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A15 = bit32.bxor(A15, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B15 = bit32.bxor(B15, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 128), buffer.readu32(Input, Position + 132)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A16 = bit32.bxor(A16, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B16 = bit32.bxor(B16, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		do
			local Lo, Hi = buffer.readu32(Input, Position + 136), buffer.readu32(Input, Position + 140)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			A17 = bit32.bxor(A17, bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16))
			B17 = bit32.bxor(B17, bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000))
		end
		for RoundIndex = 0, 80, 16 do
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex), buffer.readu32(RoundConstantsB, RoundIndex)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 4), buffer.readu32(RoundConstantsB, RoundIndex + 4)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 8), buffer.readu32(RoundConstantsB, RoundIndex + 8)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 12), buffer.readu32(RoundConstantsB, RoundIndex + 12)
				local CA0, CB0 = bit32.bxor(A0, A5, A10, A15, A20), bit32.bxor(B0, B5, B10, B15, B20)
				local CA1, CB1 = bit32.bxor(A1, A6, A11, A16, A21), bit32.bxor(B1, B6, B11, B16, B21)
				local CA2, CB2 = bit32.bxor(A2, A7, A12, A17, A22), bit32.bxor(B2, B7, B12, B17, B22)
				local CA3, CB3 = bit32.bxor(A3, A8, A13, A18, A23), bit32.bxor(B3, B8, B13, B18, B23)
				local CA4, CB4 = bit32.bxor(A4, A9, A14, A19, A24), bit32.bxor(B4, B9, B14, B19, B24)
				local DA0, DB0 = bit32.bxor(CA4, bit32.lrotate(CB1, 1)), bit32.bxor(CB4, CA1)
				local DA1, DB1 = bit32.bxor(CA0, bit32.lrotate(CB2, 1)), bit32.bxor(CB0, CA2)
				local DA2, DB2 = bit32.bxor(CA1, bit32.lrotate(CB3, 1)), bit32.bxor(CB1, CA3)
				local DA3, DB3 = bit32.bxor(CA2, bit32.lrotate(CB4, 1)), bit32.bxor(CB2, CA4)
				local DA4, DB4 = bit32.bxor(CA3, bit32.lrotate(CB0, 1)), bit32.bxor(CB3, CA0)
				local PA0, PB0 = bit32.bxor(A0, DA0), bit32.bxor(B0, DB0)
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(A5, DA0), bit32.bxor(B5, DB0)
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(A10, DA0), bit32.bxor(B10, DB0)
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(A15, DA0), bit32.bxor(B15, DB0)
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(A20, DA0), bit32.bxor(B20, DB0)
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(A1, DA1), bit32.bxor(B1, DB1)
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(A6, DA1), bit32.bxor(B6, DB1)
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(A11, DA1), bit32.bxor(B11, DB1)
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(A16, DA1), bit32.bxor(B16, DB1)
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(A21, DA1), bit32.bxor(B21, DB1)
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(A2, DA2), bit32.bxor(B2, DB2)
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(A7, DA2), bit32.bxor(B7, DB2)
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(A12, DA2), bit32.bxor(B12, DB2)
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(A17, DA2), bit32.bxor(B17, DB2)
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(A22, DA2), bit32.bxor(B22, DB2)
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(A3, DA3), bit32.bxor(B3, DB3)
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(A8, DA3), bit32.bxor(B8, DB3)
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(A13, DA3), bit32.bxor(B13, DB3)
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(A18, DA3), bit32.bxor(B18, DB3)
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(A23, DA3), bit32.bxor(B23, DB3)
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(A4, DA4), bit32.bxor(B4, DB4)
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(A9, DA4), bit32.bxor(B9, DB4)
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(A14, DA4), bit32.bxor(B14, DB4)
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(A19, DA4), bit32.bxor(B19, DB4)
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(A24, DA4), bit32.bxor(B24, DB4)
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				A0 = bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA)
				B0 = bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB)
				A1 = bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3))
				B1 = bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3))
				A2 = bit32.bxor(PA2, bit32.band(PA3, PA4))
				B2 = bit32.bxor(PB2, bit32.band(PB3, PB4))
				A3 = bit32.bxor(PA3, bit32.bor(PA4, PA0))
				B3 = bit32.bxor(PB3, bit32.bor(PB4, PB0))
				A4 = bit32.bxor(PA4, bit32.band(PA0, PA1))
				B4 = bit32.bxor(PB4, bit32.band(PB0, PB1))
				A5 = bit32.bxor(PA5, bit32.bor(PA6, PA7))
				B5 = bit32.bxor(PB5, bit32.bor(PB6, PB7))
				A6 = bit32.bxor(PA6, bit32.band(PA7, PA8))
				B6 = bit32.bxor(PB6, bit32.band(PB7, PB8))
				A7 = bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9)))
				B7 = bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9)))
				A8 = bit32.bxor(PA8, bit32.bor(PA9, PA5))
				B8 = bit32.bxor(PB8, bit32.bor(PB9, PB5))
				A9 = bit32.bxor(PA9, bit32.band(PA5, PA6))
				B9 = bit32.bxor(PB9, bit32.band(PB5, PB6))
				A10 = bit32.bxor(PA10, bit32.bor(PA11, PA12))
				B10 = bit32.bxor(PB10, bit32.bor(PB11, PB12))
				A11 = bit32.bxor(PA11, bit32.band(PA12, PA13))
				B11 = bit32.bxor(PB11, bit32.band(PB12, PB13))
				A12 = bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14))
				B12 = bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14))
				A13 = bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10))
				B13 = bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10))
				A14 = bit32.bxor(PA14, bit32.band(PA10, PA11))
				B14 = bit32.bxor(PB14, bit32.band(PB10, PB11))
				A15 = bit32.bxor(PA15, bit32.band(PA16, PA17))
				B15 = bit32.bxor(PB15, bit32.band(PB16, PB17))
				A16 = bit32.bxor(PA16, bit32.bor(PA17, PA18))
				B16 = bit32.bxor(PB16, bit32.bor(PB17, PB18))
				A17 = bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19))
				B17 = bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19))
				A18 = bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15))
				B18 = bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15))
				A19 = bit32.bxor(PA19, bit32.bor(PA15, PA16))
				B19 = bit32.bxor(PB19, bit32.bor(PB15, PB16))
				A20 = bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22))
				B20 = bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22))
				A21 = bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23))
				B21 = bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23))
				A22 = bit32.bxor(PA22, bit32.band(PA23, PA24))
				B22 = bit32.bxor(PB22, bit32.band(PB23, PB24))
				A23 = bit32.bxor(PA23, bit32.bor(PA24, PA20))
				B23 = bit32.bxor(PB23, bit32.bor(PB24, PB20))
				A24 = bit32.bxor(PA24, bit32.band(PA20, PA21))
				B24 = bit32.bxor(PB24, bit32.band(PB20, PB21))
			end
		end
	end
	buffer.writeu32(StateA, 0, A0); buffer.writeu32(StateB, 0, B0)
	buffer.writeu32(StateA, 4, bit32.bnot(A1)); buffer.writeu32(StateB, 4, bit32.bnot(B1))
	buffer.writeu32(StateA, 8, bit32.bnot(A2)); buffer.writeu32(StateB, 8, bit32.bnot(B2))
	buffer.writeu32(StateA, 12, A3); buffer.writeu32(StateB, 12, B3)
	buffer.writeu32(StateA, 16, A4); buffer.writeu32(StateB, 16, B4)
	buffer.writeu32(StateA, 20, A5); buffer.writeu32(StateB, 20, B5)
	buffer.writeu32(StateA, 24, A6); buffer.writeu32(StateB, 24, B6)
	buffer.writeu32(StateA, 28, A7); buffer.writeu32(StateB, 28, B7)
	buffer.writeu32(StateA, 32, bit32.bnot(A8)); buffer.writeu32(StateB, 32, bit32.bnot(B8))
	buffer.writeu32(StateA, 36, A9); buffer.writeu32(StateB, 36, B9)
	buffer.writeu32(StateA, 40, A10); buffer.writeu32(StateB, 40, B10)
	buffer.writeu32(StateA, 44, A11); buffer.writeu32(StateB, 44, B11)
	buffer.writeu32(StateA, 48, bit32.bnot(A12)); buffer.writeu32(StateB, 48, bit32.bnot(B12))
	buffer.writeu32(StateA, 52, A13); buffer.writeu32(StateB, 52, B13)
	buffer.writeu32(StateA, 56, A14); buffer.writeu32(StateB, 56, B14)
	buffer.writeu32(StateA, 60, A15); buffer.writeu32(StateB, 60, B15)
	buffer.writeu32(StateA, 64, A16); buffer.writeu32(StateB, 64, B16)
	buffer.writeu32(StateA, 68, bit32.bnot(A17)); buffer.writeu32(StateB, 68, bit32.bnot(B17))
	buffer.writeu32(StateA, 72, A18); buffer.writeu32(StateB, 72, B18)
	buffer.writeu32(StateA, 76, A19); buffer.writeu32(StateB, 76, B19)
	buffer.writeu32(StateA, 80, bit32.bnot(A20)); buffer.writeu32(StateB, 80, bit32.bnot(B20))
	buffer.writeu32(StateA, 84, A21); buffer.writeu32(StateB, 84, B21)
	buffer.writeu32(StateA, 88, A22); buffer.writeu32(StateB, 88, B22)
	buffer.writeu32(StateA, 92, A23); buffer.writeu32(StateB, 92, B23)
	buffer.writeu32(StateA, 96, A24); buffer.writeu32(StateB, 96, B24)
end

local function Keccak(StateA: buffer, StateB: buffer, Input: buffer, Offset: number, Size: number, BlockSizeInBytes: number, Fresh: boolean?)
	if BlockSizeInBytes == 136 then
		Absorb17(StateA, StateB, Input, Offset, Size, Fresh)
	elseif BlockSizeInBytes == 168 then
		Absorb21(StateA, StateB, Input, Offset, Size, Fresh)
	elseif BlockSizeInBytes == 72 then
		Absorb9(StateA, StateB, Input, Offset, Size, Fresh)
	elseif BlockSizeInBytes == 104 then
		Absorb13(StateA, StateB, Input, Offset, Size, Fresh)
	else
		Absorb18(StateA, StateB, Input, Offset, Size, Fresh)
	end
end

local function Extract(StateA: buffer, StateB: buffer, Output: buffer, OutputOffset: number, ByteCount: number)
	local FullLanes = ByteCount // 8
	for Lane = 0, FullLanes - 1 do
		local A, B = buffer.readu32(StateA, Lane * 4), buffer.readu32(StateB, Lane * 4)
		local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
		local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
		local T
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
		buffer.writeu32(Output, OutputOffset + Lane * 8, Lo)
		buffer.writeu32(Output, OutputOffset + Lane * 8 + 4, Hi)
	end

	local Remaining = ByteCount - FullLanes * 8
	if Remaining > 0 then
		local A, B = buffer.readu32(StateA, FullLanes * 4), buffer.readu32(StateB, FullLanes * 4)
		local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
		local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
		local T
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
		local Base = OutputOffset + FullLanes * 8
		for Index = 0, Remaining - 1 do
			local Word = if Index < 4 then Lo else Hi
			buffer.writeu8(Output, Base + Index, bit32.extract(Word, (Index % 4) * 8, 8))
		end
	end
end

local function ProcessSponge(Message: buffer, CapacityBits: number, OutputBytes: number, DomainSeparator: number): buffer
	local RateBytes = (1600 - CapacityBits) // 8
	local StateA, StateB = STATE_A, STATE_B

	local MessageLength = buffer.len(Message)
	local TailLength = MessageLength % RateBytes
	local FullBytes = MessageLength - TailLength
	local Fresh = FullBytes == 0

	if not Fresh then
		Keccak(StateA, StateB, Message, 0, FullBytes, RateBytes, true)
	end

	local Tail = TAIL_BLOCK
	buffer.fill(Tail, 0, 0, RateBytes)
	if TailLength > 0 then
		buffer.copy(Tail, 0, Message, FullBytes, TailLength)
	end
	buffer.writeu8(Tail, TailLength, DomainSeparator)
	buffer.writeu8(Tail, RateBytes - 1, bit32.bor(buffer.readu8(Tail, RateBytes - 1), 0x80))
	Keccak(StateA, StateB, Tail, 0, RateBytes, RateBytes, Fresh)

	local Output = buffer.create(OutputBytes)
	local OutputOffset = 0

	while true do
		local BytesThisRound = math.min(RateBytes, OutputBytes - OutputOffset)
		Extract(StateA, StateB, Output, OutputOffset, BytesThisRound)
		OutputOffset += BytesThisRound

		if OutputOffset >= OutputBytes then
			break
		end

		Permute(StateA, StateB)
	end

	return Output
end

SHA3.Keccak_Internal = Keccak
SHA3.Permute_Internal = Permute
SHA3.Extract_Internal = Extract

function SHA3.SHA3_256_Internal(Message: buffer): buffer
	return ProcessSponge(Message, 512, 32, 0x06)
end

function SHA3.SHA3_512_Internal(Message: buffer): buffer
	return ProcessSponge(Message, 1024, 64, 0x06)
end

function SHA3.SHAKE256_Internal(Message: buffer, OutputBytes: number): buffer
	return ProcessSponge(Message, 512, OutputBytes, 0x1F)
end

function SHA3.SHA3_224(Message: buffer): (string, buffer)
	local Buf = ProcessSponge(Message, 448, 28, 0x06)
	return ToHex(Buf), Buf
end

function SHA3.SHA3_256(Message: buffer): (string, buffer)
	local Buf = ProcessSponge(Message, 512, 32, 0x06)
	return ToHex(Buf), Buf
end

function SHA3.SHA3_384(Message: buffer): (string, buffer)
	local Buf = ProcessSponge(Message, 768, 48, 0x06)
	return ToHex(Buf), Buf
end

function SHA3.SHA3_512(Message: buffer): (string, buffer)
	local Buf = ProcessSponge(Message, 1024, 64, 0x06)
	return ToHex(Buf), Buf
end

function SHA3.SHAKE128(Message: buffer, OutputBytes: number): (string, buffer)
	local Buf = ProcessSponge(Message, 256, OutputBytes, 0x1F)
	return ToHex(Buf), Buf
end

function SHA3.SHAKE256(Message: buffer, OutputBytes: number): (string, buffer)
	local Buf = ProcessSponge(Message, 512, OutputBytes, 0x1F)
	return ToHex(Buf), Buf
end

return SHA3
