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

local SCRATCH_A = buffer.create(100)
local SCRATCH_B = buffer.create(100)
local SCRATCH_D = buffer.create(40)

local function Permute(StateA: buffer, StateB: buffer)
	local ScratchA, ScratchB = SCRATCH_A, SCRATCH_B
	local ScratchD = SCRATCH_D
	local RoundConstantsA, RoundConstantsB = ROUND_A, ROUND_B
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
	for RoundIndex = 0, 88, 8 do
		do
			local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex), buffer.readu32(RoundConstantsB, RoundIndex)
			local CA0, CB0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(StateA, 20), buffer.readu32(StateA, 40), buffer.readu32(StateA, 60), buffer.readu32(StateA, 80)), bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(StateB, 20), buffer.readu32(StateB, 40), buffer.readu32(StateB, 60), buffer.readu32(StateB, 80))
			local CA1, CB1 = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(StateA, 24), buffer.readu32(StateA, 44), buffer.readu32(StateA, 64), buffer.readu32(StateA, 84)), bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(StateB, 24), buffer.readu32(StateB, 44), buffer.readu32(StateB, 64), buffer.readu32(StateB, 84))
			local CA2, CB2 = bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(StateA, 28), buffer.readu32(StateA, 48), buffer.readu32(StateA, 68), buffer.readu32(StateA, 88)), bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(StateB, 28), buffer.readu32(StateB, 48), buffer.readu32(StateB, 68), buffer.readu32(StateB, 88))
			local CA3, CB3 = bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(StateA, 32), buffer.readu32(StateA, 52), buffer.readu32(StateA, 72), buffer.readu32(StateA, 92)), bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(StateB, 32), buffer.readu32(StateB, 52), buffer.readu32(StateB, 72), buffer.readu32(StateB, 92))
			local CA4, CB4 = bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(StateA, 36), buffer.readu32(StateA, 56), buffer.readu32(StateA, 76), buffer.readu32(StateA, 96)), bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(StateB, 36), buffer.readu32(StateB, 56), buffer.readu32(StateB, 76), buffer.readu32(StateB, 96))
			buffer.writeu32(ScratchD, 0, bit32.bxor(CA4, bit32.lrotate(CB1, 1))); buffer.writeu32(ScratchD, 20, bit32.bxor(CB4, CA1))
			buffer.writeu32(ScratchD, 4, bit32.bxor(CA0, bit32.lrotate(CB2, 1))); buffer.writeu32(ScratchD, 24, bit32.bxor(CB0, CA2))
			buffer.writeu32(ScratchD, 8, bit32.bxor(CA1, bit32.lrotate(CB3, 1))); buffer.writeu32(ScratchD, 28, bit32.bxor(CB1, CA3))
			buffer.writeu32(ScratchD, 12, bit32.bxor(CA2, bit32.lrotate(CB4, 1))); buffer.writeu32(ScratchD, 32, bit32.bxor(CB2, CA4))
			buffer.writeu32(ScratchD, 16, bit32.bxor(CA3, bit32.lrotate(CB0, 1))); buffer.writeu32(ScratchD, 36, bit32.bxor(CB3, CA0))
			if RoundIndex < 0 then break end
			do
				local PA0, PB0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(ScratchD, 20))
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 24), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 24), buffer.readu32(ScratchD, 24))
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 48), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 48), buffer.readu32(ScratchD, 28))
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 72), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 72), buffer.readu32(ScratchD, 32))
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 96), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 96), buffer.readu32(ScratchD, 36))
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				buffer.writeu32(ScratchA, 0, bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA))
				buffer.writeu32(ScratchB, 0, bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB))
				buffer.writeu32(ScratchA, 4, bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3)))
				buffer.writeu32(ScratchB, 4, bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3)))
				buffer.writeu32(ScratchA, 8, bit32.bxor(PA2, bit32.band(PA3, PA4)))
				buffer.writeu32(ScratchB, 8, bit32.bxor(PB2, bit32.band(PB3, PB4)))
				buffer.writeu32(ScratchA, 12, bit32.bxor(PA3, bit32.bor(PA4, PA0)))
				buffer.writeu32(ScratchB, 12, bit32.bxor(PB3, bit32.bor(PB4, PB0)))
				buffer.writeu32(ScratchA, 16, bit32.bxor(PA4, bit32.band(PA0, PA1)))
				buffer.writeu32(ScratchB, 16, bit32.bxor(PB4, bit32.band(PB0, PB1)))
			end
			do
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(ScratchD, 32))
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 36), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 36), buffer.readu32(ScratchD, 36))
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 40), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 40), buffer.readu32(ScratchD, 20))
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 64), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 64), buffer.readu32(ScratchD, 24))
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 88), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 88), buffer.readu32(ScratchD, 28))
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				buffer.writeu32(ScratchA, 20, bit32.bxor(PA5, bit32.bor(PA6, PA7)))
				buffer.writeu32(ScratchB, 20, bit32.bxor(PB5, bit32.bor(PB6, PB7)))
				buffer.writeu32(ScratchA, 24, bit32.bxor(PA6, bit32.band(PA7, PA8)))
				buffer.writeu32(ScratchB, 24, bit32.bxor(PB6, bit32.band(PB7, PB8)))
				buffer.writeu32(ScratchA, 28, bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9))))
				buffer.writeu32(ScratchB, 28, bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9))))
				buffer.writeu32(ScratchA, 32, bit32.bxor(PA8, bit32.bor(PA9, PA5)))
				buffer.writeu32(ScratchB, 32, bit32.bxor(PB8, bit32.bor(PB9, PB5)))
				buffer.writeu32(ScratchA, 36, bit32.bxor(PA9, bit32.band(PA5, PA6)))
				buffer.writeu32(ScratchB, 36, bit32.bxor(PB9, bit32.band(PB5, PB6)))
			end
			do
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(ScratchD, 24))
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 28), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 28), buffer.readu32(ScratchD, 28))
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 52), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 52), buffer.readu32(ScratchD, 32))
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 76), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 76), buffer.readu32(ScratchD, 36))
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 80), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 80), buffer.readu32(ScratchD, 20))
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				buffer.writeu32(ScratchA, 40, bit32.bxor(PA10, bit32.bor(PA11, PA12)))
				buffer.writeu32(ScratchB, 40, bit32.bxor(PB10, bit32.bor(PB11, PB12)))
				buffer.writeu32(ScratchA, 44, bit32.bxor(PA11, bit32.band(PA12, PA13)))
				buffer.writeu32(ScratchB, 44, bit32.bxor(PB11, bit32.band(PB12, PB13)))
				buffer.writeu32(ScratchA, 48, bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14)))
				buffer.writeu32(ScratchB, 48, bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14)))
				buffer.writeu32(ScratchA, 52, bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10)))
				buffer.writeu32(ScratchB, 52, bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10)))
				buffer.writeu32(ScratchA, 56, bit32.bxor(PA14, bit32.band(PA10, PA11)))
				buffer.writeu32(ScratchB, 56, bit32.bxor(PB14, bit32.band(PB10, PB11)))
			end
			do
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(ScratchD, 36))
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 20), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 20), buffer.readu32(ScratchD, 20))
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 44), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 44), buffer.readu32(ScratchD, 24))
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 68), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 68), buffer.readu32(ScratchD, 28))
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 92), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 92), buffer.readu32(ScratchD, 32))
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				buffer.writeu32(ScratchA, 60, bit32.bxor(PA15, bit32.band(PA16, PA17)))
				buffer.writeu32(ScratchB, 60, bit32.bxor(PB15, bit32.band(PB16, PB17)))
				buffer.writeu32(ScratchA, 64, bit32.bxor(PA16, bit32.bor(PA17, PA18)))
				buffer.writeu32(ScratchB, 64, bit32.bxor(PB16, bit32.bor(PB17, PB18)))
				buffer.writeu32(ScratchA, 68, bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19)))
				buffer.writeu32(ScratchB, 68, bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19)))
				buffer.writeu32(ScratchA, 72, bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15)))
				buffer.writeu32(ScratchB, 72, bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15)))
				buffer.writeu32(ScratchA, 76, bit32.bxor(PA19, bit32.bor(PA15, PA16)))
				buffer.writeu32(ScratchB, 76, bit32.bxor(PB19, bit32.bor(PB15, PB16)))
			end
			do
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(ScratchD, 28))
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 32), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 32), buffer.readu32(ScratchD, 32))
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 56), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 56), buffer.readu32(ScratchD, 36))
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 60), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 60), buffer.readu32(ScratchD, 20))
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(buffer.readu32(StateA, 84), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 84), buffer.readu32(ScratchD, 24))
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				buffer.writeu32(ScratchA, 80, bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22)))
				buffer.writeu32(ScratchB, 80, bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22)))
				buffer.writeu32(ScratchA, 84, bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23)))
				buffer.writeu32(ScratchB, 84, bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23)))
				buffer.writeu32(ScratchA, 88, bit32.bxor(PA22, bit32.band(PA23, PA24)))
				buffer.writeu32(ScratchB, 88, bit32.bxor(PB22, bit32.band(PB23, PB24)))
				buffer.writeu32(ScratchA, 92, bit32.bxor(PA23, bit32.bor(PA24, PA20)))
				buffer.writeu32(ScratchB, 92, bit32.bxor(PB23, bit32.bor(PB24, PB20)))
				buffer.writeu32(ScratchA, 96, bit32.bxor(PA24, bit32.band(PA20, PA21)))
				buffer.writeu32(ScratchB, 96, bit32.bxor(PB24, bit32.band(PB20, PB21)))
			end
		end
		if RoundIndex < 0 then break end
		do
			local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 4), buffer.readu32(RoundConstantsB, RoundIndex + 4)
			local CA0, CB0 = bit32.bxor(buffer.readu32(ScratchA, 0), buffer.readu32(ScratchA, 20), buffer.readu32(ScratchA, 40), buffer.readu32(ScratchA, 60), buffer.readu32(ScratchA, 80)), bit32.bxor(buffer.readu32(ScratchB, 0), buffer.readu32(ScratchB, 20), buffer.readu32(ScratchB, 40), buffer.readu32(ScratchB, 60), buffer.readu32(ScratchB, 80))
			local CA1, CB1 = bit32.bxor(buffer.readu32(ScratchA, 4), buffer.readu32(ScratchA, 24), buffer.readu32(ScratchA, 44), buffer.readu32(ScratchA, 64), buffer.readu32(ScratchA, 84)), bit32.bxor(buffer.readu32(ScratchB, 4), buffer.readu32(ScratchB, 24), buffer.readu32(ScratchB, 44), buffer.readu32(ScratchB, 64), buffer.readu32(ScratchB, 84))
			local CA2, CB2 = bit32.bxor(buffer.readu32(ScratchA, 8), buffer.readu32(ScratchA, 28), buffer.readu32(ScratchA, 48), buffer.readu32(ScratchA, 68), buffer.readu32(ScratchA, 88)), bit32.bxor(buffer.readu32(ScratchB, 8), buffer.readu32(ScratchB, 28), buffer.readu32(ScratchB, 48), buffer.readu32(ScratchB, 68), buffer.readu32(ScratchB, 88))
			local CA3, CB3 = bit32.bxor(buffer.readu32(ScratchA, 12), buffer.readu32(ScratchA, 32), buffer.readu32(ScratchA, 52), buffer.readu32(ScratchA, 72), buffer.readu32(ScratchA, 92)), bit32.bxor(buffer.readu32(ScratchB, 12), buffer.readu32(ScratchB, 32), buffer.readu32(ScratchB, 52), buffer.readu32(ScratchB, 72), buffer.readu32(ScratchB, 92))
			local CA4, CB4 = bit32.bxor(buffer.readu32(ScratchA, 16), buffer.readu32(ScratchA, 36), buffer.readu32(ScratchA, 56), buffer.readu32(ScratchA, 76), buffer.readu32(ScratchA, 96)), bit32.bxor(buffer.readu32(ScratchB, 16), buffer.readu32(ScratchB, 36), buffer.readu32(ScratchB, 56), buffer.readu32(ScratchB, 76), buffer.readu32(ScratchB, 96))
			buffer.writeu32(ScratchD, 0, bit32.bxor(CA4, bit32.lrotate(CB1, 1))); buffer.writeu32(ScratchD, 20, bit32.bxor(CB4, CA1))
			buffer.writeu32(ScratchD, 4, bit32.bxor(CA0, bit32.lrotate(CB2, 1))); buffer.writeu32(ScratchD, 24, bit32.bxor(CB0, CA2))
			buffer.writeu32(ScratchD, 8, bit32.bxor(CA1, bit32.lrotate(CB3, 1))); buffer.writeu32(ScratchD, 28, bit32.bxor(CB1, CA3))
			buffer.writeu32(ScratchD, 12, bit32.bxor(CA2, bit32.lrotate(CB4, 1))); buffer.writeu32(ScratchD, 32, bit32.bxor(CB2, CA4))
			buffer.writeu32(ScratchD, 16, bit32.bxor(CA3, bit32.lrotate(CB0, 1))); buffer.writeu32(ScratchD, 36, bit32.bxor(CB3, CA0))
			if RoundIndex < 0 then break end
			do
				local PA0, PB0 = bit32.bxor(buffer.readu32(ScratchA, 0), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 0), buffer.readu32(ScratchD, 20))
				local PA1, PB1
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 24), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 24), buffer.readu32(ScratchD, 24))
					PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
				end
				local PA2, PB2
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 48), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 48), buffer.readu32(ScratchD, 28))
					PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
				end
				local PA3, PB3
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 72), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 72), buffer.readu32(ScratchD, 32))
					PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
				end
				local PA4, PB4
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 96), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 96), buffer.readu32(ScratchD, 36))
					PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
				end
				buffer.writeu32(StateA, 0, bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA))
				buffer.writeu32(StateB, 0, bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB))
				buffer.writeu32(StateA, 4, bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3)))
				buffer.writeu32(StateB, 4, bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3)))
				buffer.writeu32(StateA, 8, bit32.bxor(PA2, bit32.band(PA3, PA4)))
				buffer.writeu32(StateB, 8, bit32.bxor(PB2, bit32.band(PB3, PB4)))
				buffer.writeu32(StateA, 12, bit32.bxor(PA3, bit32.bor(PA4, PA0)))
				buffer.writeu32(StateB, 12, bit32.bxor(PB3, bit32.bor(PB4, PB0)))
				buffer.writeu32(StateA, 16, bit32.bxor(PA4, bit32.band(PA0, PA1)))
				buffer.writeu32(StateB, 16, bit32.bxor(PB4, bit32.band(PB0, PB1)))
			end
			do
				local PA5, PB5
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 12), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 12), buffer.readu32(ScratchD, 32))
					PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
				end
				local PA6, PB6
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 36), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 36), buffer.readu32(ScratchD, 36))
					PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
				end
				local PA7, PB7
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 40), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 40), buffer.readu32(ScratchD, 20))
					PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
				end
				local PA8, PB8
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 64), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 64), buffer.readu32(ScratchD, 24))
					PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
				end
				local PA9, PB9
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 88), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 88), buffer.readu32(ScratchD, 28))
					PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
				end
				buffer.writeu32(StateA, 20, bit32.bxor(PA5, bit32.bor(PA6, PA7)))
				buffer.writeu32(StateB, 20, bit32.bxor(PB5, bit32.bor(PB6, PB7)))
				buffer.writeu32(StateA, 24, bit32.bxor(PA6, bit32.band(PA7, PA8)))
				buffer.writeu32(StateB, 24, bit32.bxor(PB6, bit32.band(PB7, PB8)))
				buffer.writeu32(StateA, 28, bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9))))
				buffer.writeu32(StateB, 28, bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9))))
				buffer.writeu32(StateA, 32, bit32.bxor(PA8, bit32.bor(PA9, PA5)))
				buffer.writeu32(StateB, 32, bit32.bxor(PB8, bit32.bor(PB9, PB5)))
				buffer.writeu32(StateA, 36, bit32.bxor(PA9, bit32.band(PA5, PA6)))
				buffer.writeu32(StateB, 36, bit32.bxor(PB9, bit32.band(PB5, PB6)))
			end
			do
				local PA10, PB10
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 4), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 4), buffer.readu32(ScratchD, 24))
					PA10, PB10 = bit32.lrotate(TB, 1), (TA)
				end
				local PA11, PB11
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 28), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 28), buffer.readu32(ScratchD, 28))
					PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
				end
				local PA12, PB12
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 52), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 52), buffer.readu32(ScratchD, 32))
					PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
				end
				local PA13, PB13
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 76), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 76), buffer.readu32(ScratchD, 36))
					PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
				end
				local PA14, PB14
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 80), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 80), buffer.readu32(ScratchD, 20))
					PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
				end
				buffer.writeu32(StateA, 40, bit32.bxor(PA10, bit32.bor(PA11, PA12)))
				buffer.writeu32(StateB, 40, bit32.bxor(PB10, bit32.bor(PB11, PB12)))
				buffer.writeu32(StateA, 44, bit32.bxor(PA11, bit32.band(PA12, PA13)))
				buffer.writeu32(StateB, 44, bit32.bxor(PB11, bit32.band(PB12, PB13)))
				buffer.writeu32(StateA, 48, bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14)))
				buffer.writeu32(StateB, 48, bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14)))
				buffer.writeu32(StateA, 52, bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10)))
				buffer.writeu32(StateB, 52, bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10)))
				buffer.writeu32(StateA, 56, bit32.bxor(PA14, bit32.band(PA10, PA11)))
				buffer.writeu32(StateB, 56, bit32.bxor(PB14, bit32.band(PB10, PB11)))
			end
			do
				local PA15, PB15
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 16), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 16), buffer.readu32(ScratchD, 36))
					PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
				end
				local PA16, PB16
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 20), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 20), buffer.readu32(ScratchD, 20))
					PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
				end
				local PA17, PB17
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 44), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 44), buffer.readu32(ScratchD, 24))
					PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
				end
				local PA18, PB18
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 68), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 68), buffer.readu32(ScratchD, 28))
					PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
				end
				local PA19, PB19
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 92), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 92), buffer.readu32(ScratchD, 32))
					PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
				end
				buffer.writeu32(StateA, 60, bit32.bxor(PA15, bit32.band(PA16, PA17)))
				buffer.writeu32(StateB, 60, bit32.bxor(PB15, bit32.band(PB16, PB17)))
				buffer.writeu32(StateA, 64, bit32.bxor(PA16, bit32.bor(PA17, PA18)))
				buffer.writeu32(StateB, 64, bit32.bxor(PB16, bit32.bor(PB17, PB18)))
				buffer.writeu32(StateA, 68, bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19)))
				buffer.writeu32(StateB, 68, bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19)))
				buffer.writeu32(StateA, 72, bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15)))
				buffer.writeu32(StateB, 72, bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15)))
				buffer.writeu32(StateA, 76, bit32.bxor(PA19, bit32.bor(PA15, PA16)))
				buffer.writeu32(StateB, 76, bit32.bxor(PB19, bit32.bor(PB15, PB16)))
			end
			do
				local PA20, PB20
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 8), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 8), buffer.readu32(ScratchD, 28))
					PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
				end
				local PA21, PB21
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 32), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 32), buffer.readu32(ScratchD, 32))
					PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
				end
				local PA22, PB22
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 56), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 56), buffer.readu32(ScratchD, 36))
					PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
				end
				local PA23, PB23
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 60), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 60), buffer.readu32(ScratchD, 20))
					PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
				end
				local PA24, PB24
				do
					local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 84), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 84), buffer.readu32(ScratchD, 24))
					PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
				end
				buffer.writeu32(StateA, 80, bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22)))
				buffer.writeu32(StateB, 80, bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22)))
				buffer.writeu32(StateA, 84, bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23)))
				buffer.writeu32(StateB, 84, bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23)))
				buffer.writeu32(StateA, 88, bit32.bxor(PA22, bit32.band(PA23, PA24)))
				buffer.writeu32(StateB, 88, bit32.bxor(PB22, bit32.band(PB23, PB24)))
				buffer.writeu32(StateA, 92, bit32.bxor(PA23, bit32.bor(PA24, PA20)))
				buffer.writeu32(StateB, 92, bit32.bxor(PB23, bit32.bor(PB24, PB20)))
				buffer.writeu32(StateA, 96, bit32.bxor(PA24, bit32.band(PA20, PA21)))
				buffer.writeu32(StateB, 96, bit32.bxor(PB24, bit32.band(PB20, PB21)))
			end
		end
	end
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
end

local function Absorb17(StateA: buffer, StateB: buffer, Input: buffer, Offset: number, Size: number, Fresh: boolean?)
	local ScratchA, ScratchB = SCRATCH_A, SCRATCH_B
	local ScratchD = SCRATCH_D
	local RoundConstantsA, RoundConstantsB = ROUND_A, ROUND_B
	if Fresh then
		buffer.fill(StateA, 0, 0, 100)
		buffer.fill(StateB, 0, 0, 100)
	end
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
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
			buffer.writeu32(StateA, 0, bit32.bxor(buffer.readu32(StateA, 0), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 0, bit32.bxor(buffer.readu32(StateB, 0), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 4, bit32.bxor(buffer.readu32(StateA, 4), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 4, bit32.bxor(buffer.readu32(StateB, 4), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 8, bit32.bxor(buffer.readu32(StateA, 8), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 8, bit32.bxor(buffer.readu32(StateB, 8), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 12, bit32.bxor(buffer.readu32(StateA, 12), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 12, bit32.bxor(buffer.readu32(StateB, 12), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 16, bit32.bxor(buffer.readu32(StateA, 16), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 16, bit32.bxor(buffer.readu32(StateB, 16), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 20, bit32.bxor(buffer.readu32(StateA, 20), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 20, bit32.bxor(buffer.readu32(StateB, 20), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 24, bit32.bxor(buffer.readu32(StateA, 24), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 24, bit32.bxor(buffer.readu32(StateB, 24), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 28, bit32.bxor(buffer.readu32(StateA, 28), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 28, bit32.bxor(buffer.readu32(StateB, 28), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 32, bit32.bxor(buffer.readu32(StateA, 32), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 32, bit32.bxor(buffer.readu32(StateB, 32), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 36, bit32.bxor(buffer.readu32(StateA, 36), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 36, bit32.bxor(buffer.readu32(StateB, 36), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 40, bit32.bxor(buffer.readu32(StateA, 40), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 40, bit32.bxor(buffer.readu32(StateB, 40), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 44, bit32.bxor(buffer.readu32(StateA, 44), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 44, bit32.bxor(buffer.readu32(StateB, 44), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 48, bit32.bxor(buffer.readu32(StateA, 48), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 48, bit32.bxor(buffer.readu32(StateB, 48), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 52, bit32.bxor(buffer.readu32(StateA, 52), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 52, bit32.bxor(buffer.readu32(StateB, 52), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 56, bit32.bxor(buffer.readu32(StateA, 56), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 56, bit32.bxor(buffer.readu32(StateB, 56), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 60, bit32.bxor(buffer.readu32(StateA, 60), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 60, bit32.bxor(buffer.readu32(StateB, 60), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 64, bit32.bxor(buffer.readu32(StateA, 64), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 64, bit32.bxor(buffer.readu32(StateB, 64), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
		end
		for RoundIndex = 0, 88, 8 do
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex), buffer.readu32(RoundConstantsB, RoundIndex)
				local CA0, CB0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(StateA, 20), buffer.readu32(StateA, 40), buffer.readu32(StateA, 60), buffer.readu32(StateA, 80)), bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(StateB, 20), buffer.readu32(StateB, 40), buffer.readu32(StateB, 60), buffer.readu32(StateB, 80))
				local CA1, CB1 = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(StateA, 24), buffer.readu32(StateA, 44), buffer.readu32(StateA, 64), buffer.readu32(StateA, 84)), bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(StateB, 24), buffer.readu32(StateB, 44), buffer.readu32(StateB, 64), buffer.readu32(StateB, 84))
				local CA2, CB2 = bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(StateA, 28), buffer.readu32(StateA, 48), buffer.readu32(StateA, 68), buffer.readu32(StateA, 88)), bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(StateB, 28), buffer.readu32(StateB, 48), buffer.readu32(StateB, 68), buffer.readu32(StateB, 88))
				local CA3, CB3 = bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(StateA, 32), buffer.readu32(StateA, 52), buffer.readu32(StateA, 72), buffer.readu32(StateA, 92)), bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(StateB, 32), buffer.readu32(StateB, 52), buffer.readu32(StateB, 72), buffer.readu32(StateB, 92))
				local CA4, CB4 = bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(StateA, 36), buffer.readu32(StateA, 56), buffer.readu32(StateA, 76), buffer.readu32(StateA, 96)), bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(StateB, 36), buffer.readu32(StateB, 56), buffer.readu32(StateB, 76), buffer.readu32(StateB, 96))
				buffer.writeu32(ScratchD, 0, bit32.bxor(CA4, bit32.lrotate(CB1, 1))); buffer.writeu32(ScratchD, 20, bit32.bxor(CB4, CA1))
				buffer.writeu32(ScratchD, 4, bit32.bxor(CA0, bit32.lrotate(CB2, 1))); buffer.writeu32(ScratchD, 24, bit32.bxor(CB0, CA2))
				buffer.writeu32(ScratchD, 8, bit32.bxor(CA1, bit32.lrotate(CB3, 1))); buffer.writeu32(ScratchD, 28, bit32.bxor(CB1, CA3))
				buffer.writeu32(ScratchD, 12, bit32.bxor(CA2, bit32.lrotate(CB4, 1))); buffer.writeu32(ScratchD, 32, bit32.bxor(CB2, CA4))
				buffer.writeu32(ScratchD, 16, bit32.bxor(CA3, bit32.lrotate(CB0, 1))); buffer.writeu32(ScratchD, 36, bit32.bxor(CB3, CA0))
				if RoundIndex < 0 then break end
				do
					local PA0, PB0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(ScratchD, 20))
					local PA1, PB1
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 24), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 24), buffer.readu32(ScratchD, 24))
						PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
					end
					local PA2, PB2
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 48), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 48), buffer.readu32(ScratchD, 28))
						PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
					end
					local PA3, PB3
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 72), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 72), buffer.readu32(ScratchD, 32))
						PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
					end
					local PA4, PB4
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 96), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 96), buffer.readu32(ScratchD, 36))
						PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
					end
					buffer.writeu32(ScratchA, 0, bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA))
					buffer.writeu32(ScratchB, 0, bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB))
					buffer.writeu32(ScratchA, 4, bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3)))
					buffer.writeu32(ScratchB, 4, bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3)))
					buffer.writeu32(ScratchA, 8, bit32.bxor(PA2, bit32.band(PA3, PA4)))
					buffer.writeu32(ScratchB, 8, bit32.bxor(PB2, bit32.band(PB3, PB4)))
					buffer.writeu32(ScratchA, 12, bit32.bxor(PA3, bit32.bor(PA4, PA0)))
					buffer.writeu32(ScratchB, 12, bit32.bxor(PB3, bit32.bor(PB4, PB0)))
					buffer.writeu32(ScratchA, 16, bit32.bxor(PA4, bit32.band(PA0, PA1)))
					buffer.writeu32(ScratchB, 16, bit32.bxor(PB4, bit32.band(PB0, PB1)))
				end
				do
					local PA5, PB5
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(ScratchD, 32))
						PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
					end
					local PA6, PB6
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 36), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 36), buffer.readu32(ScratchD, 36))
						PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
					end
					local PA7, PB7
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 40), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 40), buffer.readu32(ScratchD, 20))
						PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
					end
					local PA8, PB8
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 64), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 64), buffer.readu32(ScratchD, 24))
						PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
					end
					local PA9, PB9
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 88), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 88), buffer.readu32(ScratchD, 28))
						PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
					end
					buffer.writeu32(ScratchA, 20, bit32.bxor(PA5, bit32.bor(PA6, PA7)))
					buffer.writeu32(ScratchB, 20, bit32.bxor(PB5, bit32.bor(PB6, PB7)))
					buffer.writeu32(ScratchA, 24, bit32.bxor(PA6, bit32.band(PA7, PA8)))
					buffer.writeu32(ScratchB, 24, bit32.bxor(PB6, bit32.band(PB7, PB8)))
					buffer.writeu32(ScratchA, 28, bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9))))
					buffer.writeu32(ScratchB, 28, bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9))))
					buffer.writeu32(ScratchA, 32, bit32.bxor(PA8, bit32.bor(PA9, PA5)))
					buffer.writeu32(ScratchB, 32, bit32.bxor(PB8, bit32.bor(PB9, PB5)))
					buffer.writeu32(ScratchA, 36, bit32.bxor(PA9, bit32.band(PA5, PA6)))
					buffer.writeu32(ScratchB, 36, bit32.bxor(PB9, bit32.band(PB5, PB6)))
				end
				do
					local PA10, PB10
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(ScratchD, 24))
						PA10, PB10 = bit32.lrotate(TB, 1), (TA)
					end
					local PA11, PB11
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 28), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 28), buffer.readu32(ScratchD, 28))
						PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
					end
					local PA12, PB12
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 52), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 52), buffer.readu32(ScratchD, 32))
						PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
					end
					local PA13, PB13
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 76), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 76), buffer.readu32(ScratchD, 36))
						PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
					end
					local PA14, PB14
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 80), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 80), buffer.readu32(ScratchD, 20))
						PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
					end
					buffer.writeu32(ScratchA, 40, bit32.bxor(PA10, bit32.bor(PA11, PA12)))
					buffer.writeu32(ScratchB, 40, bit32.bxor(PB10, bit32.bor(PB11, PB12)))
					buffer.writeu32(ScratchA, 44, bit32.bxor(PA11, bit32.band(PA12, PA13)))
					buffer.writeu32(ScratchB, 44, bit32.bxor(PB11, bit32.band(PB12, PB13)))
					buffer.writeu32(ScratchA, 48, bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14)))
					buffer.writeu32(ScratchB, 48, bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14)))
					buffer.writeu32(ScratchA, 52, bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10)))
					buffer.writeu32(ScratchB, 52, bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10)))
					buffer.writeu32(ScratchA, 56, bit32.bxor(PA14, bit32.band(PA10, PA11)))
					buffer.writeu32(ScratchB, 56, bit32.bxor(PB14, bit32.band(PB10, PB11)))
				end
				do
					local PA15, PB15
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(ScratchD, 36))
						PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
					end
					local PA16, PB16
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 20), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 20), buffer.readu32(ScratchD, 20))
						PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
					end
					local PA17, PB17
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 44), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 44), buffer.readu32(ScratchD, 24))
						PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
					end
					local PA18, PB18
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 68), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 68), buffer.readu32(ScratchD, 28))
						PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
					end
					local PA19, PB19
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 92), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 92), buffer.readu32(ScratchD, 32))
						PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
					end
					buffer.writeu32(ScratchA, 60, bit32.bxor(PA15, bit32.band(PA16, PA17)))
					buffer.writeu32(ScratchB, 60, bit32.bxor(PB15, bit32.band(PB16, PB17)))
					buffer.writeu32(ScratchA, 64, bit32.bxor(PA16, bit32.bor(PA17, PA18)))
					buffer.writeu32(ScratchB, 64, bit32.bxor(PB16, bit32.bor(PB17, PB18)))
					buffer.writeu32(ScratchA, 68, bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19)))
					buffer.writeu32(ScratchB, 68, bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19)))
					buffer.writeu32(ScratchA, 72, bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15)))
					buffer.writeu32(ScratchB, 72, bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15)))
					buffer.writeu32(ScratchA, 76, bit32.bxor(PA19, bit32.bor(PA15, PA16)))
					buffer.writeu32(ScratchB, 76, bit32.bxor(PB19, bit32.bor(PB15, PB16)))
				end
				do
					local PA20, PB20
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(ScratchD, 28))
						PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
					end
					local PA21, PB21
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 32), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 32), buffer.readu32(ScratchD, 32))
						PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
					end
					local PA22, PB22
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 56), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 56), buffer.readu32(ScratchD, 36))
						PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
					end
					local PA23, PB23
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 60), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 60), buffer.readu32(ScratchD, 20))
						PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
					end
					local PA24, PB24
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 84), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 84), buffer.readu32(ScratchD, 24))
						PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
					end
					buffer.writeu32(ScratchA, 80, bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22)))
					buffer.writeu32(ScratchB, 80, bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22)))
					buffer.writeu32(ScratchA, 84, bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23)))
					buffer.writeu32(ScratchB, 84, bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23)))
					buffer.writeu32(ScratchA, 88, bit32.bxor(PA22, bit32.band(PA23, PA24)))
					buffer.writeu32(ScratchB, 88, bit32.bxor(PB22, bit32.band(PB23, PB24)))
					buffer.writeu32(ScratchA, 92, bit32.bxor(PA23, bit32.bor(PA24, PA20)))
					buffer.writeu32(ScratchB, 92, bit32.bxor(PB23, bit32.bor(PB24, PB20)))
					buffer.writeu32(ScratchA, 96, bit32.bxor(PA24, bit32.band(PA20, PA21)))
					buffer.writeu32(ScratchB, 96, bit32.bxor(PB24, bit32.band(PB20, PB21)))
				end
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 4), buffer.readu32(RoundConstantsB, RoundIndex + 4)
				local CA0, CB0 = bit32.bxor(buffer.readu32(ScratchA, 0), buffer.readu32(ScratchA, 20), buffer.readu32(ScratchA, 40), buffer.readu32(ScratchA, 60), buffer.readu32(ScratchA, 80)), bit32.bxor(buffer.readu32(ScratchB, 0), buffer.readu32(ScratchB, 20), buffer.readu32(ScratchB, 40), buffer.readu32(ScratchB, 60), buffer.readu32(ScratchB, 80))
				local CA1, CB1 = bit32.bxor(buffer.readu32(ScratchA, 4), buffer.readu32(ScratchA, 24), buffer.readu32(ScratchA, 44), buffer.readu32(ScratchA, 64), buffer.readu32(ScratchA, 84)), bit32.bxor(buffer.readu32(ScratchB, 4), buffer.readu32(ScratchB, 24), buffer.readu32(ScratchB, 44), buffer.readu32(ScratchB, 64), buffer.readu32(ScratchB, 84))
				local CA2, CB2 = bit32.bxor(buffer.readu32(ScratchA, 8), buffer.readu32(ScratchA, 28), buffer.readu32(ScratchA, 48), buffer.readu32(ScratchA, 68), buffer.readu32(ScratchA, 88)), bit32.bxor(buffer.readu32(ScratchB, 8), buffer.readu32(ScratchB, 28), buffer.readu32(ScratchB, 48), buffer.readu32(ScratchB, 68), buffer.readu32(ScratchB, 88))
				local CA3, CB3 = bit32.bxor(buffer.readu32(ScratchA, 12), buffer.readu32(ScratchA, 32), buffer.readu32(ScratchA, 52), buffer.readu32(ScratchA, 72), buffer.readu32(ScratchA, 92)), bit32.bxor(buffer.readu32(ScratchB, 12), buffer.readu32(ScratchB, 32), buffer.readu32(ScratchB, 52), buffer.readu32(ScratchB, 72), buffer.readu32(ScratchB, 92))
				local CA4, CB4 = bit32.bxor(buffer.readu32(ScratchA, 16), buffer.readu32(ScratchA, 36), buffer.readu32(ScratchA, 56), buffer.readu32(ScratchA, 76), buffer.readu32(ScratchA, 96)), bit32.bxor(buffer.readu32(ScratchB, 16), buffer.readu32(ScratchB, 36), buffer.readu32(ScratchB, 56), buffer.readu32(ScratchB, 76), buffer.readu32(ScratchB, 96))
				buffer.writeu32(ScratchD, 0, bit32.bxor(CA4, bit32.lrotate(CB1, 1))); buffer.writeu32(ScratchD, 20, bit32.bxor(CB4, CA1))
				buffer.writeu32(ScratchD, 4, bit32.bxor(CA0, bit32.lrotate(CB2, 1))); buffer.writeu32(ScratchD, 24, bit32.bxor(CB0, CA2))
				buffer.writeu32(ScratchD, 8, bit32.bxor(CA1, bit32.lrotate(CB3, 1))); buffer.writeu32(ScratchD, 28, bit32.bxor(CB1, CA3))
				buffer.writeu32(ScratchD, 12, bit32.bxor(CA2, bit32.lrotate(CB4, 1))); buffer.writeu32(ScratchD, 32, bit32.bxor(CB2, CA4))
				buffer.writeu32(ScratchD, 16, bit32.bxor(CA3, bit32.lrotate(CB0, 1))); buffer.writeu32(ScratchD, 36, bit32.bxor(CB3, CA0))
				if RoundIndex < 0 then break end
				do
					local PA0, PB0 = bit32.bxor(buffer.readu32(ScratchA, 0), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 0), buffer.readu32(ScratchD, 20))
					local PA1, PB1
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 24), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 24), buffer.readu32(ScratchD, 24))
						PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
					end
					local PA2, PB2
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 48), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 48), buffer.readu32(ScratchD, 28))
						PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
					end
					local PA3, PB3
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 72), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 72), buffer.readu32(ScratchD, 32))
						PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
					end
					local PA4, PB4
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 96), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 96), buffer.readu32(ScratchD, 36))
						PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
					end
					buffer.writeu32(StateA, 0, bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA))
					buffer.writeu32(StateB, 0, bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB))
					buffer.writeu32(StateA, 4, bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3)))
					buffer.writeu32(StateB, 4, bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3)))
					buffer.writeu32(StateA, 8, bit32.bxor(PA2, bit32.band(PA3, PA4)))
					buffer.writeu32(StateB, 8, bit32.bxor(PB2, bit32.band(PB3, PB4)))
					buffer.writeu32(StateA, 12, bit32.bxor(PA3, bit32.bor(PA4, PA0)))
					buffer.writeu32(StateB, 12, bit32.bxor(PB3, bit32.bor(PB4, PB0)))
					buffer.writeu32(StateA, 16, bit32.bxor(PA4, bit32.band(PA0, PA1)))
					buffer.writeu32(StateB, 16, bit32.bxor(PB4, bit32.band(PB0, PB1)))
				end
				do
					local PA5, PB5
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 12), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 12), buffer.readu32(ScratchD, 32))
						PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
					end
					local PA6, PB6
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 36), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 36), buffer.readu32(ScratchD, 36))
						PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
					end
					local PA7, PB7
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 40), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 40), buffer.readu32(ScratchD, 20))
						PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
					end
					local PA8, PB8
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 64), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 64), buffer.readu32(ScratchD, 24))
						PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
					end
					local PA9, PB9
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 88), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 88), buffer.readu32(ScratchD, 28))
						PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
					end
					buffer.writeu32(StateA, 20, bit32.bxor(PA5, bit32.bor(PA6, PA7)))
					buffer.writeu32(StateB, 20, bit32.bxor(PB5, bit32.bor(PB6, PB7)))
					buffer.writeu32(StateA, 24, bit32.bxor(PA6, bit32.band(PA7, PA8)))
					buffer.writeu32(StateB, 24, bit32.bxor(PB6, bit32.band(PB7, PB8)))
					buffer.writeu32(StateA, 28, bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9))))
					buffer.writeu32(StateB, 28, bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9))))
					buffer.writeu32(StateA, 32, bit32.bxor(PA8, bit32.bor(PA9, PA5)))
					buffer.writeu32(StateB, 32, bit32.bxor(PB8, bit32.bor(PB9, PB5)))
					buffer.writeu32(StateA, 36, bit32.bxor(PA9, bit32.band(PA5, PA6)))
					buffer.writeu32(StateB, 36, bit32.bxor(PB9, bit32.band(PB5, PB6)))
				end
				do
					local PA10, PB10
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 4), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 4), buffer.readu32(ScratchD, 24))
						PA10, PB10 = bit32.lrotate(TB, 1), (TA)
					end
					local PA11, PB11
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 28), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 28), buffer.readu32(ScratchD, 28))
						PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
					end
					local PA12, PB12
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 52), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 52), buffer.readu32(ScratchD, 32))
						PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
					end
					local PA13, PB13
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 76), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 76), buffer.readu32(ScratchD, 36))
						PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
					end
					local PA14, PB14
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 80), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 80), buffer.readu32(ScratchD, 20))
						PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
					end
					buffer.writeu32(StateA, 40, bit32.bxor(PA10, bit32.bor(PA11, PA12)))
					buffer.writeu32(StateB, 40, bit32.bxor(PB10, bit32.bor(PB11, PB12)))
					buffer.writeu32(StateA, 44, bit32.bxor(PA11, bit32.band(PA12, PA13)))
					buffer.writeu32(StateB, 44, bit32.bxor(PB11, bit32.band(PB12, PB13)))
					buffer.writeu32(StateA, 48, bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14)))
					buffer.writeu32(StateB, 48, bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14)))
					buffer.writeu32(StateA, 52, bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10)))
					buffer.writeu32(StateB, 52, bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10)))
					buffer.writeu32(StateA, 56, bit32.bxor(PA14, bit32.band(PA10, PA11)))
					buffer.writeu32(StateB, 56, bit32.bxor(PB14, bit32.band(PB10, PB11)))
				end
				do
					local PA15, PB15
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 16), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 16), buffer.readu32(ScratchD, 36))
						PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
					end
					local PA16, PB16
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 20), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 20), buffer.readu32(ScratchD, 20))
						PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
					end
					local PA17, PB17
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 44), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 44), buffer.readu32(ScratchD, 24))
						PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
					end
					local PA18, PB18
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 68), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 68), buffer.readu32(ScratchD, 28))
						PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
					end
					local PA19, PB19
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 92), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 92), buffer.readu32(ScratchD, 32))
						PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
					end
					buffer.writeu32(StateA, 60, bit32.bxor(PA15, bit32.band(PA16, PA17)))
					buffer.writeu32(StateB, 60, bit32.bxor(PB15, bit32.band(PB16, PB17)))
					buffer.writeu32(StateA, 64, bit32.bxor(PA16, bit32.bor(PA17, PA18)))
					buffer.writeu32(StateB, 64, bit32.bxor(PB16, bit32.bor(PB17, PB18)))
					buffer.writeu32(StateA, 68, bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19)))
					buffer.writeu32(StateB, 68, bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19)))
					buffer.writeu32(StateA, 72, bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15)))
					buffer.writeu32(StateB, 72, bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15)))
					buffer.writeu32(StateA, 76, bit32.bxor(PA19, bit32.bor(PA15, PA16)))
					buffer.writeu32(StateB, 76, bit32.bxor(PB19, bit32.bor(PB15, PB16)))
				end
				do
					local PA20, PB20
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 8), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 8), buffer.readu32(ScratchD, 28))
						PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
					end
					local PA21, PB21
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 32), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 32), buffer.readu32(ScratchD, 32))
						PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
					end
					local PA22, PB22
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 56), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 56), buffer.readu32(ScratchD, 36))
						PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
					end
					local PA23, PB23
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 60), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 60), buffer.readu32(ScratchD, 20))
						PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
					end
					local PA24, PB24
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 84), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 84), buffer.readu32(ScratchD, 24))
						PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
					end
					buffer.writeu32(StateA, 80, bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22)))
					buffer.writeu32(StateB, 80, bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22)))
					buffer.writeu32(StateA, 84, bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23)))
					buffer.writeu32(StateB, 84, bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23)))
					buffer.writeu32(StateA, 88, bit32.bxor(PA22, bit32.band(PA23, PA24)))
					buffer.writeu32(StateB, 88, bit32.bxor(PB22, bit32.band(PB23, PB24)))
					buffer.writeu32(StateA, 92, bit32.bxor(PA23, bit32.bor(PA24, PA20)))
					buffer.writeu32(StateB, 92, bit32.bxor(PB23, bit32.bor(PB24, PB20)))
					buffer.writeu32(StateA, 96, bit32.bxor(PA24, bit32.band(PA20, PA21)))
					buffer.writeu32(StateB, 96, bit32.bxor(PB24, bit32.band(PB20, PB21)))
				end
			end
		end
	end
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
end

local function Absorb21(StateA: buffer, StateB: buffer, Input: buffer, Offset: number, Size: number, Fresh: boolean?)
	local ScratchA, ScratchB = SCRATCH_A, SCRATCH_B
	local ScratchD = SCRATCH_D
	local RoundConstantsA, RoundConstantsB = ROUND_A, ROUND_B
	if Fresh then
		buffer.fill(StateA, 0, 0, 100)
		buffer.fill(StateB, 0, 0, 100)
	end
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
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
			buffer.writeu32(StateA, 0, bit32.bxor(buffer.readu32(StateA, 0), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 0, bit32.bxor(buffer.readu32(StateB, 0), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 4, bit32.bxor(buffer.readu32(StateA, 4), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 4, bit32.bxor(buffer.readu32(StateB, 4), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 8, bit32.bxor(buffer.readu32(StateA, 8), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 8, bit32.bxor(buffer.readu32(StateB, 8), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 12, bit32.bxor(buffer.readu32(StateA, 12), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 12, bit32.bxor(buffer.readu32(StateB, 12), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 16, bit32.bxor(buffer.readu32(StateA, 16), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 16, bit32.bxor(buffer.readu32(StateB, 16), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 20, bit32.bxor(buffer.readu32(StateA, 20), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 20, bit32.bxor(buffer.readu32(StateB, 20), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 24, bit32.bxor(buffer.readu32(StateA, 24), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 24, bit32.bxor(buffer.readu32(StateB, 24), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 28, bit32.bxor(buffer.readu32(StateA, 28), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 28, bit32.bxor(buffer.readu32(StateB, 28), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 32, bit32.bxor(buffer.readu32(StateA, 32), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 32, bit32.bxor(buffer.readu32(StateB, 32), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 36, bit32.bxor(buffer.readu32(StateA, 36), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 36, bit32.bxor(buffer.readu32(StateB, 36), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 40, bit32.bxor(buffer.readu32(StateA, 40), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 40, bit32.bxor(buffer.readu32(StateB, 40), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 44, bit32.bxor(buffer.readu32(StateA, 44), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 44, bit32.bxor(buffer.readu32(StateB, 44), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 48, bit32.bxor(buffer.readu32(StateA, 48), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 48, bit32.bxor(buffer.readu32(StateB, 48), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 52, bit32.bxor(buffer.readu32(StateA, 52), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 52, bit32.bxor(buffer.readu32(StateB, 52), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 56, bit32.bxor(buffer.readu32(StateA, 56), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 56, bit32.bxor(buffer.readu32(StateB, 56), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 60, bit32.bxor(buffer.readu32(StateA, 60), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 60, bit32.bxor(buffer.readu32(StateB, 60), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 64, bit32.bxor(buffer.readu32(StateA, 64), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 64, bit32.bxor(buffer.readu32(StateB, 64), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 68, bit32.bxor(buffer.readu32(StateA, 68), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 68, bit32.bxor(buffer.readu32(StateB, 68), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 72, bit32.bxor(buffer.readu32(StateA, 72), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 72, bit32.bxor(buffer.readu32(StateB, 72), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 76, bit32.bxor(buffer.readu32(StateA, 76), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 76, bit32.bxor(buffer.readu32(StateB, 76), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 80, bit32.bxor(buffer.readu32(StateA, 80), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 80, bit32.bxor(buffer.readu32(StateB, 80), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
		end
		for RoundIndex = 0, 88, 8 do
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex), buffer.readu32(RoundConstantsB, RoundIndex)
				local CA0, CB0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(StateA, 20), buffer.readu32(StateA, 40), buffer.readu32(StateA, 60), buffer.readu32(StateA, 80)), bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(StateB, 20), buffer.readu32(StateB, 40), buffer.readu32(StateB, 60), buffer.readu32(StateB, 80))
				local CA1, CB1 = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(StateA, 24), buffer.readu32(StateA, 44), buffer.readu32(StateA, 64), buffer.readu32(StateA, 84)), bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(StateB, 24), buffer.readu32(StateB, 44), buffer.readu32(StateB, 64), buffer.readu32(StateB, 84))
				local CA2, CB2 = bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(StateA, 28), buffer.readu32(StateA, 48), buffer.readu32(StateA, 68), buffer.readu32(StateA, 88)), bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(StateB, 28), buffer.readu32(StateB, 48), buffer.readu32(StateB, 68), buffer.readu32(StateB, 88))
				local CA3, CB3 = bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(StateA, 32), buffer.readu32(StateA, 52), buffer.readu32(StateA, 72), buffer.readu32(StateA, 92)), bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(StateB, 32), buffer.readu32(StateB, 52), buffer.readu32(StateB, 72), buffer.readu32(StateB, 92))
				local CA4, CB4 = bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(StateA, 36), buffer.readu32(StateA, 56), buffer.readu32(StateA, 76), buffer.readu32(StateA, 96)), bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(StateB, 36), buffer.readu32(StateB, 56), buffer.readu32(StateB, 76), buffer.readu32(StateB, 96))
				buffer.writeu32(ScratchD, 0, bit32.bxor(CA4, bit32.lrotate(CB1, 1))); buffer.writeu32(ScratchD, 20, bit32.bxor(CB4, CA1))
				buffer.writeu32(ScratchD, 4, bit32.bxor(CA0, bit32.lrotate(CB2, 1))); buffer.writeu32(ScratchD, 24, bit32.bxor(CB0, CA2))
				buffer.writeu32(ScratchD, 8, bit32.bxor(CA1, bit32.lrotate(CB3, 1))); buffer.writeu32(ScratchD, 28, bit32.bxor(CB1, CA3))
				buffer.writeu32(ScratchD, 12, bit32.bxor(CA2, bit32.lrotate(CB4, 1))); buffer.writeu32(ScratchD, 32, bit32.bxor(CB2, CA4))
				buffer.writeu32(ScratchD, 16, bit32.bxor(CA3, bit32.lrotate(CB0, 1))); buffer.writeu32(ScratchD, 36, bit32.bxor(CB3, CA0))
				if RoundIndex < 0 then break end
				do
					local PA0, PB0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(ScratchD, 20))
					local PA1, PB1
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 24), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 24), buffer.readu32(ScratchD, 24))
						PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
					end
					local PA2, PB2
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 48), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 48), buffer.readu32(ScratchD, 28))
						PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
					end
					local PA3, PB3
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 72), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 72), buffer.readu32(ScratchD, 32))
						PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
					end
					local PA4, PB4
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 96), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 96), buffer.readu32(ScratchD, 36))
						PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
					end
					buffer.writeu32(ScratchA, 0, bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA))
					buffer.writeu32(ScratchB, 0, bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB))
					buffer.writeu32(ScratchA, 4, bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3)))
					buffer.writeu32(ScratchB, 4, bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3)))
					buffer.writeu32(ScratchA, 8, bit32.bxor(PA2, bit32.band(PA3, PA4)))
					buffer.writeu32(ScratchB, 8, bit32.bxor(PB2, bit32.band(PB3, PB4)))
					buffer.writeu32(ScratchA, 12, bit32.bxor(PA3, bit32.bor(PA4, PA0)))
					buffer.writeu32(ScratchB, 12, bit32.bxor(PB3, bit32.bor(PB4, PB0)))
					buffer.writeu32(ScratchA, 16, bit32.bxor(PA4, bit32.band(PA0, PA1)))
					buffer.writeu32(ScratchB, 16, bit32.bxor(PB4, bit32.band(PB0, PB1)))
				end
				do
					local PA5, PB5
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(ScratchD, 32))
						PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
					end
					local PA6, PB6
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 36), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 36), buffer.readu32(ScratchD, 36))
						PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
					end
					local PA7, PB7
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 40), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 40), buffer.readu32(ScratchD, 20))
						PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
					end
					local PA8, PB8
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 64), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 64), buffer.readu32(ScratchD, 24))
						PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
					end
					local PA9, PB9
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 88), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 88), buffer.readu32(ScratchD, 28))
						PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
					end
					buffer.writeu32(ScratchA, 20, bit32.bxor(PA5, bit32.bor(PA6, PA7)))
					buffer.writeu32(ScratchB, 20, bit32.bxor(PB5, bit32.bor(PB6, PB7)))
					buffer.writeu32(ScratchA, 24, bit32.bxor(PA6, bit32.band(PA7, PA8)))
					buffer.writeu32(ScratchB, 24, bit32.bxor(PB6, bit32.band(PB7, PB8)))
					buffer.writeu32(ScratchA, 28, bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9))))
					buffer.writeu32(ScratchB, 28, bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9))))
					buffer.writeu32(ScratchA, 32, bit32.bxor(PA8, bit32.bor(PA9, PA5)))
					buffer.writeu32(ScratchB, 32, bit32.bxor(PB8, bit32.bor(PB9, PB5)))
					buffer.writeu32(ScratchA, 36, bit32.bxor(PA9, bit32.band(PA5, PA6)))
					buffer.writeu32(ScratchB, 36, bit32.bxor(PB9, bit32.band(PB5, PB6)))
				end
				do
					local PA10, PB10
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(ScratchD, 24))
						PA10, PB10 = bit32.lrotate(TB, 1), (TA)
					end
					local PA11, PB11
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 28), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 28), buffer.readu32(ScratchD, 28))
						PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
					end
					local PA12, PB12
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 52), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 52), buffer.readu32(ScratchD, 32))
						PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
					end
					local PA13, PB13
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 76), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 76), buffer.readu32(ScratchD, 36))
						PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
					end
					local PA14, PB14
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 80), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 80), buffer.readu32(ScratchD, 20))
						PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
					end
					buffer.writeu32(ScratchA, 40, bit32.bxor(PA10, bit32.bor(PA11, PA12)))
					buffer.writeu32(ScratchB, 40, bit32.bxor(PB10, bit32.bor(PB11, PB12)))
					buffer.writeu32(ScratchA, 44, bit32.bxor(PA11, bit32.band(PA12, PA13)))
					buffer.writeu32(ScratchB, 44, bit32.bxor(PB11, bit32.band(PB12, PB13)))
					buffer.writeu32(ScratchA, 48, bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14)))
					buffer.writeu32(ScratchB, 48, bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14)))
					buffer.writeu32(ScratchA, 52, bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10)))
					buffer.writeu32(ScratchB, 52, bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10)))
					buffer.writeu32(ScratchA, 56, bit32.bxor(PA14, bit32.band(PA10, PA11)))
					buffer.writeu32(ScratchB, 56, bit32.bxor(PB14, bit32.band(PB10, PB11)))
				end
				do
					local PA15, PB15
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(ScratchD, 36))
						PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
					end
					local PA16, PB16
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 20), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 20), buffer.readu32(ScratchD, 20))
						PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
					end
					local PA17, PB17
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 44), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 44), buffer.readu32(ScratchD, 24))
						PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
					end
					local PA18, PB18
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 68), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 68), buffer.readu32(ScratchD, 28))
						PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
					end
					local PA19, PB19
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 92), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 92), buffer.readu32(ScratchD, 32))
						PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
					end
					buffer.writeu32(ScratchA, 60, bit32.bxor(PA15, bit32.band(PA16, PA17)))
					buffer.writeu32(ScratchB, 60, bit32.bxor(PB15, bit32.band(PB16, PB17)))
					buffer.writeu32(ScratchA, 64, bit32.bxor(PA16, bit32.bor(PA17, PA18)))
					buffer.writeu32(ScratchB, 64, bit32.bxor(PB16, bit32.bor(PB17, PB18)))
					buffer.writeu32(ScratchA, 68, bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19)))
					buffer.writeu32(ScratchB, 68, bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19)))
					buffer.writeu32(ScratchA, 72, bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15)))
					buffer.writeu32(ScratchB, 72, bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15)))
					buffer.writeu32(ScratchA, 76, bit32.bxor(PA19, bit32.bor(PA15, PA16)))
					buffer.writeu32(ScratchB, 76, bit32.bxor(PB19, bit32.bor(PB15, PB16)))
				end
				do
					local PA20, PB20
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(ScratchD, 28))
						PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
					end
					local PA21, PB21
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 32), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 32), buffer.readu32(ScratchD, 32))
						PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
					end
					local PA22, PB22
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 56), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 56), buffer.readu32(ScratchD, 36))
						PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
					end
					local PA23, PB23
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 60), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 60), buffer.readu32(ScratchD, 20))
						PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
					end
					local PA24, PB24
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 84), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 84), buffer.readu32(ScratchD, 24))
						PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
					end
					buffer.writeu32(ScratchA, 80, bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22)))
					buffer.writeu32(ScratchB, 80, bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22)))
					buffer.writeu32(ScratchA, 84, bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23)))
					buffer.writeu32(ScratchB, 84, bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23)))
					buffer.writeu32(ScratchA, 88, bit32.bxor(PA22, bit32.band(PA23, PA24)))
					buffer.writeu32(ScratchB, 88, bit32.bxor(PB22, bit32.band(PB23, PB24)))
					buffer.writeu32(ScratchA, 92, bit32.bxor(PA23, bit32.bor(PA24, PA20)))
					buffer.writeu32(ScratchB, 92, bit32.bxor(PB23, bit32.bor(PB24, PB20)))
					buffer.writeu32(ScratchA, 96, bit32.bxor(PA24, bit32.band(PA20, PA21)))
					buffer.writeu32(ScratchB, 96, bit32.bxor(PB24, bit32.band(PB20, PB21)))
				end
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 4), buffer.readu32(RoundConstantsB, RoundIndex + 4)
				local CA0, CB0 = bit32.bxor(buffer.readu32(ScratchA, 0), buffer.readu32(ScratchA, 20), buffer.readu32(ScratchA, 40), buffer.readu32(ScratchA, 60), buffer.readu32(ScratchA, 80)), bit32.bxor(buffer.readu32(ScratchB, 0), buffer.readu32(ScratchB, 20), buffer.readu32(ScratchB, 40), buffer.readu32(ScratchB, 60), buffer.readu32(ScratchB, 80))
				local CA1, CB1 = bit32.bxor(buffer.readu32(ScratchA, 4), buffer.readu32(ScratchA, 24), buffer.readu32(ScratchA, 44), buffer.readu32(ScratchA, 64), buffer.readu32(ScratchA, 84)), bit32.bxor(buffer.readu32(ScratchB, 4), buffer.readu32(ScratchB, 24), buffer.readu32(ScratchB, 44), buffer.readu32(ScratchB, 64), buffer.readu32(ScratchB, 84))
				local CA2, CB2 = bit32.bxor(buffer.readu32(ScratchA, 8), buffer.readu32(ScratchA, 28), buffer.readu32(ScratchA, 48), buffer.readu32(ScratchA, 68), buffer.readu32(ScratchA, 88)), bit32.bxor(buffer.readu32(ScratchB, 8), buffer.readu32(ScratchB, 28), buffer.readu32(ScratchB, 48), buffer.readu32(ScratchB, 68), buffer.readu32(ScratchB, 88))
				local CA3, CB3 = bit32.bxor(buffer.readu32(ScratchA, 12), buffer.readu32(ScratchA, 32), buffer.readu32(ScratchA, 52), buffer.readu32(ScratchA, 72), buffer.readu32(ScratchA, 92)), bit32.bxor(buffer.readu32(ScratchB, 12), buffer.readu32(ScratchB, 32), buffer.readu32(ScratchB, 52), buffer.readu32(ScratchB, 72), buffer.readu32(ScratchB, 92))
				local CA4, CB4 = bit32.bxor(buffer.readu32(ScratchA, 16), buffer.readu32(ScratchA, 36), buffer.readu32(ScratchA, 56), buffer.readu32(ScratchA, 76), buffer.readu32(ScratchA, 96)), bit32.bxor(buffer.readu32(ScratchB, 16), buffer.readu32(ScratchB, 36), buffer.readu32(ScratchB, 56), buffer.readu32(ScratchB, 76), buffer.readu32(ScratchB, 96))
				buffer.writeu32(ScratchD, 0, bit32.bxor(CA4, bit32.lrotate(CB1, 1))); buffer.writeu32(ScratchD, 20, bit32.bxor(CB4, CA1))
				buffer.writeu32(ScratchD, 4, bit32.bxor(CA0, bit32.lrotate(CB2, 1))); buffer.writeu32(ScratchD, 24, bit32.bxor(CB0, CA2))
				buffer.writeu32(ScratchD, 8, bit32.bxor(CA1, bit32.lrotate(CB3, 1))); buffer.writeu32(ScratchD, 28, bit32.bxor(CB1, CA3))
				buffer.writeu32(ScratchD, 12, bit32.bxor(CA2, bit32.lrotate(CB4, 1))); buffer.writeu32(ScratchD, 32, bit32.bxor(CB2, CA4))
				buffer.writeu32(ScratchD, 16, bit32.bxor(CA3, bit32.lrotate(CB0, 1))); buffer.writeu32(ScratchD, 36, bit32.bxor(CB3, CA0))
				if RoundIndex < 0 then break end
				do
					local PA0, PB0 = bit32.bxor(buffer.readu32(ScratchA, 0), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 0), buffer.readu32(ScratchD, 20))
					local PA1, PB1
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 24), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 24), buffer.readu32(ScratchD, 24))
						PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
					end
					local PA2, PB2
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 48), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 48), buffer.readu32(ScratchD, 28))
						PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
					end
					local PA3, PB3
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 72), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 72), buffer.readu32(ScratchD, 32))
						PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
					end
					local PA4, PB4
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 96), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 96), buffer.readu32(ScratchD, 36))
						PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
					end
					buffer.writeu32(StateA, 0, bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA))
					buffer.writeu32(StateB, 0, bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB))
					buffer.writeu32(StateA, 4, bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3)))
					buffer.writeu32(StateB, 4, bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3)))
					buffer.writeu32(StateA, 8, bit32.bxor(PA2, bit32.band(PA3, PA4)))
					buffer.writeu32(StateB, 8, bit32.bxor(PB2, bit32.band(PB3, PB4)))
					buffer.writeu32(StateA, 12, bit32.bxor(PA3, bit32.bor(PA4, PA0)))
					buffer.writeu32(StateB, 12, bit32.bxor(PB3, bit32.bor(PB4, PB0)))
					buffer.writeu32(StateA, 16, bit32.bxor(PA4, bit32.band(PA0, PA1)))
					buffer.writeu32(StateB, 16, bit32.bxor(PB4, bit32.band(PB0, PB1)))
				end
				do
					local PA5, PB5
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 12), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 12), buffer.readu32(ScratchD, 32))
						PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
					end
					local PA6, PB6
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 36), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 36), buffer.readu32(ScratchD, 36))
						PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
					end
					local PA7, PB7
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 40), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 40), buffer.readu32(ScratchD, 20))
						PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
					end
					local PA8, PB8
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 64), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 64), buffer.readu32(ScratchD, 24))
						PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
					end
					local PA9, PB9
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 88), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 88), buffer.readu32(ScratchD, 28))
						PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
					end
					buffer.writeu32(StateA, 20, bit32.bxor(PA5, bit32.bor(PA6, PA7)))
					buffer.writeu32(StateB, 20, bit32.bxor(PB5, bit32.bor(PB6, PB7)))
					buffer.writeu32(StateA, 24, bit32.bxor(PA6, bit32.band(PA7, PA8)))
					buffer.writeu32(StateB, 24, bit32.bxor(PB6, bit32.band(PB7, PB8)))
					buffer.writeu32(StateA, 28, bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9))))
					buffer.writeu32(StateB, 28, bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9))))
					buffer.writeu32(StateA, 32, bit32.bxor(PA8, bit32.bor(PA9, PA5)))
					buffer.writeu32(StateB, 32, bit32.bxor(PB8, bit32.bor(PB9, PB5)))
					buffer.writeu32(StateA, 36, bit32.bxor(PA9, bit32.band(PA5, PA6)))
					buffer.writeu32(StateB, 36, bit32.bxor(PB9, bit32.band(PB5, PB6)))
				end
				do
					local PA10, PB10
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 4), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 4), buffer.readu32(ScratchD, 24))
						PA10, PB10 = bit32.lrotate(TB, 1), (TA)
					end
					local PA11, PB11
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 28), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 28), buffer.readu32(ScratchD, 28))
						PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
					end
					local PA12, PB12
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 52), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 52), buffer.readu32(ScratchD, 32))
						PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
					end
					local PA13, PB13
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 76), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 76), buffer.readu32(ScratchD, 36))
						PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
					end
					local PA14, PB14
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 80), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 80), buffer.readu32(ScratchD, 20))
						PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
					end
					buffer.writeu32(StateA, 40, bit32.bxor(PA10, bit32.bor(PA11, PA12)))
					buffer.writeu32(StateB, 40, bit32.bxor(PB10, bit32.bor(PB11, PB12)))
					buffer.writeu32(StateA, 44, bit32.bxor(PA11, bit32.band(PA12, PA13)))
					buffer.writeu32(StateB, 44, bit32.bxor(PB11, bit32.band(PB12, PB13)))
					buffer.writeu32(StateA, 48, bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14)))
					buffer.writeu32(StateB, 48, bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14)))
					buffer.writeu32(StateA, 52, bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10)))
					buffer.writeu32(StateB, 52, bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10)))
					buffer.writeu32(StateA, 56, bit32.bxor(PA14, bit32.band(PA10, PA11)))
					buffer.writeu32(StateB, 56, bit32.bxor(PB14, bit32.band(PB10, PB11)))
				end
				do
					local PA15, PB15
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 16), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 16), buffer.readu32(ScratchD, 36))
						PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
					end
					local PA16, PB16
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 20), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 20), buffer.readu32(ScratchD, 20))
						PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
					end
					local PA17, PB17
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 44), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 44), buffer.readu32(ScratchD, 24))
						PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
					end
					local PA18, PB18
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 68), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 68), buffer.readu32(ScratchD, 28))
						PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
					end
					local PA19, PB19
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 92), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 92), buffer.readu32(ScratchD, 32))
						PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
					end
					buffer.writeu32(StateA, 60, bit32.bxor(PA15, bit32.band(PA16, PA17)))
					buffer.writeu32(StateB, 60, bit32.bxor(PB15, bit32.band(PB16, PB17)))
					buffer.writeu32(StateA, 64, bit32.bxor(PA16, bit32.bor(PA17, PA18)))
					buffer.writeu32(StateB, 64, bit32.bxor(PB16, bit32.bor(PB17, PB18)))
					buffer.writeu32(StateA, 68, bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19)))
					buffer.writeu32(StateB, 68, bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19)))
					buffer.writeu32(StateA, 72, bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15)))
					buffer.writeu32(StateB, 72, bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15)))
					buffer.writeu32(StateA, 76, bit32.bxor(PA19, bit32.bor(PA15, PA16)))
					buffer.writeu32(StateB, 76, bit32.bxor(PB19, bit32.bor(PB15, PB16)))
				end
				do
					local PA20, PB20
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 8), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 8), buffer.readu32(ScratchD, 28))
						PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
					end
					local PA21, PB21
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 32), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 32), buffer.readu32(ScratchD, 32))
						PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
					end
					local PA22, PB22
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 56), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 56), buffer.readu32(ScratchD, 36))
						PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
					end
					local PA23, PB23
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 60), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 60), buffer.readu32(ScratchD, 20))
						PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
					end
					local PA24, PB24
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 84), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 84), buffer.readu32(ScratchD, 24))
						PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
					end
					buffer.writeu32(StateA, 80, bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22)))
					buffer.writeu32(StateB, 80, bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22)))
					buffer.writeu32(StateA, 84, bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23)))
					buffer.writeu32(StateB, 84, bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23)))
					buffer.writeu32(StateA, 88, bit32.bxor(PA22, bit32.band(PA23, PA24)))
					buffer.writeu32(StateB, 88, bit32.bxor(PB22, bit32.band(PB23, PB24)))
					buffer.writeu32(StateA, 92, bit32.bxor(PA23, bit32.bor(PA24, PA20)))
					buffer.writeu32(StateB, 92, bit32.bxor(PB23, bit32.bor(PB24, PB20)))
					buffer.writeu32(StateA, 96, bit32.bxor(PA24, bit32.band(PA20, PA21)))
					buffer.writeu32(StateB, 96, bit32.bxor(PB24, bit32.band(PB20, PB21)))
				end
			end
		end
	end
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
end

local function Absorb9(StateA: buffer, StateB: buffer, Input: buffer, Offset: number, Size: number, Fresh: boolean?)
	local ScratchA, ScratchB = SCRATCH_A, SCRATCH_B
	local ScratchD = SCRATCH_D
	local RoundConstantsA, RoundConstantsB = ROUND_A, ROUND_B
	if Fresh then
		buffer.fill(StateA, 0, 0, 100)
		buffer.fill(StateB, 0, 0, 100)
	end
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
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
			buffer.writeu32(StateA, 0, bit32.bxor(buffer.readu32(StateA, 0), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 0, bit32.bxor(buffer.readu32(StateB, 0), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 4, bit32.bxor(buffer.readu32(StateA, 4), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 4, bit32.bxor(buffer.readu32(StateB, 4), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 8, bit32.bxor(buffer.readu32(StateA, 8), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 8, bit32.bxor(buffer.readu32(StateB, 8), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 12, bit32.bxor(buffer.readu32(StateA, 12), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 12, bit32.bxor(buffer.readu32(StateB, 12), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 16, bit32.bxor(buffer.readu32(StateA, 16), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 16, bit32.bxor(buffer.readu32(StateB, 16), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 20, bit32.bxor(buffer.readu32(StateA, 20), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 20, bit32.bxor(buffer.readu32(StateB, 20), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 24, bit32.bxor(buffer.readu32(StateA, 24), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 24, bit32.bxor(buffer.readu32(StateB, 24), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 28, bit32.bxor(buffer.readu32(StateA, 28), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 28, bit32.bxor(buffer.readu32(StateB, 28), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 32, bit32.bxor(buffer.readu32(StateA, 32), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 32, bit32.bxor(buffer.readu32(StateB, 32), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
		end
		for RoundIndex = 0, 88, 8 do
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex), buffer.readu32(RoundConstantsB, RoundIndex)
				local CA0, CB0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(StateA, 20), buffer.readu32(StateA, 40), buffer.readu32(StateA, 60), buffer.readu32(StateA, 80)), bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(StateB, 20), buffer.readu32(StateB, 40), buffer.readu32(StateB, 60), buffer.readu32(StateB, 80))
				local CA1, CB1 = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(StateA, 24), buffer.readu32(StateA, 44), buffer.readu32(StateA, 64), buffer.readu32(StateA, 84)), bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(StateB, 24), buffer.readu32(StateB, 44), buffer.readu32(StateB, 64), buffer.readu32(StateB, 84))
				local CA2, CB2 = bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(StateA, 28), buffer.readu32(StateA, 48), buffer.readu32(StateA, 68), buffer.readu32(StateA, 88)), bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(StateB, 28), buffer.readu32(StateB, 48), buffer.readu32(StateB, 68), buffer.readu32(StateB, 88))
				local CA3, CB3 = bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(StateA, 32), buffer.readu32(StateA, 52), buffer.readu32(StateA, 72), buffer.readu32(StateA, 92)), bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(StateB, 32), buffer.readu32(StateB, 52), buffer.readu32(StateB, 72), buffer.readu32(StateB, 92))
				local CA4, CB4 = bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(StateA, 36), buffer.readu32(StateA, 56), buffer.readu32(StateA, 76), buffer.readu32(StateA, 96)), bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(StateB, 36), buffer.readu32(StateB, 56), buffer.readu32(StateB, 76), buffer.readu32(StateB, 96))
				buffer.writeu32(ScratchD, 0, bit32.bxor(CA4, bit32.lrotate(CB1, 1))); buffer.writeu32(ScratchD, 20, bit32.bxor(CB4, CA1))
				buffer.writeu32(ScratchD, 4, bit32.bxor(CA0, bit32.lrotate(CB2, 1))); buffer.writeu32(ScratchD, 24, bit32.bxor(CB0, CA2))
				buffer.writeu32(ScratchD, 8, bit32.bxor(CA1, bit32.lrotate(CB3, 1))); buffer.writeu32(ScratchD, 28, bit32.bxor(CB1, CA3))
				buffer.writeu32(ScratchD, 12, bit32.bxor(CA2, bit32.lrotate(CB4, 1))); buffer.writeu32(ScratchD, 32, bit32.bxor(CB2, CA4))
				buffer.writeu32(ScratchD, 16, bit32.bxor(CA3, bit32.lrotate(CB0, 1))); buffer.writeu32(ScratchD, 36, bit32.bxor(CB3, CA0))
				if RoundIndex < 0 then break end
				do
					local PA0, PB0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(ScratchD, 20))
					local PA1, PB1
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 24), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 24), buffer.readu32(ScratchD, 24))
						PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
					end
					local PA2, PB2
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 48), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 48), buffer.readu32(ScratchD, 28))
						PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
					end
					local PA3, PB3
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 72), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 72), buffer.readu32(ScratchD, 32))
						PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
					end
					local PA4, PB4
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 96), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 96), buffer.readu32(ScratchD, 36))
						PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
					end
					buffer.writeu32(ScratchA, 0, bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA))
					buffer.writeu32(ScratchB, 0, bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB))
					buffer.writeu32(ScratchA, 4, bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3)))
					buffer.writeu32(ScratchB, 4, bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3)))
					buffer.writeu32(ScratchA, 8, bit32.bxor(PA2, bit32.band(PA3, PA4)))
					buffer.writeu32(ScratchB, 8, bit32.bxor(PB2, bit32.band(PB3, PB4)))
					buffer.writeu32(ScratchA, 12, bit32.bxor(PA3, bit32.bor(PA4, PA0)))
					buffer.writeu32(ScratchB, 12, bit32.bxor(PB3, bit32.bor(PB4, PB0)))
					buffer.writeu32(ScratchA, 16, bit32.bxor(PA4, bit32.band(PA0, PA1)))
					buffer.writeu32(ScratchB, 16, bit32.bxor(PB4, bit32.band(PB0, PB1)))
				end
				do
					local PA5, PB5
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(ScratchD, 32))
						PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
					end
					local PA6, PB6
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 36), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 36), buffer.readu32(ScratchD, 36))
						PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
					end
					local PA7, PB7
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 40), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 40), buffer.readu32(ScratchD, 20))
						PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
					end
					local PA8, PB8
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 64), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 64), buffer.readu32(ScratchD, 24))
						PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
					end
					local PA9, PB9
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 88), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 88), buffer.readu32(ScratchD, 28))
						PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
					end
					buffer.writeu32(ScratchA, 20, bit32.bxor(PA5, bit32.bor(PA6, PA7)))
					buffer.writeu32(ScratchB, 20, bit32.bxor(PB5, bit32.bor(PB6, PB7)))
					buffer.writeu32(ScratchA, 24, bit32.bxor(PA6, bit32.band(PA7, PA8)))
					buffer.writeu32(ScratchB, 24, bit32.bxor(PB6, bit32.band(PB7, PB8)))
					buffer.writeu32(ScratchA, 28, bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9))))
					buffer.writeu32(ScratchB, 28, bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9))))
					buffer.writeu32(ScratchA, 32, bit32.bxor(PA8, bit32.bor(PA9, PA5)))
					buffer.writeu32(ScratchB, 32, bit32.bxor(PB8, bit32.bor(PB9, PB5)))
					buffer.writeu32(ScratchA, 36, bit32.bxor(PA9, bit32.band(PA5, PA6)))
					buffer.writeu32(ScratchB, 36, bit32.bxor(PB9, bit32.band(PB5, PB6)))
				end
				do
					local PA10, PB10
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(ScratchD, 24))
						PA10, PB10 = bit32.lrotate(TB, 1), (TA)
					end
					local PA11, PB11
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 28), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 28), buffer.readu32(ScratchD, 28))
						PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
					end
					local PA12, PB12
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 52), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 52), buffer.readu32(ScratchD, 32))
						PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
					end
					local PA13, PB13
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 76), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 76), buffer.readu32(ScratchD, 36))
						PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
					end
					local PA14, PB14
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 80), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 80), buffer.readu32(ScratchD, 20))
						PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
					end
					buffer.writeu32(ScratchA, 40, bit32.bxor(PA10, bit32.bor(PA11, PA12)))
					buffer.writeu32(ScratchB, 40, bit32.bxor(PB10, bit32.bor(PB11, PB12)))
					buffer.writeu32(ScratchA, 44, bit32.bxor(PA11, bit32.band(PA12, PA13)))
					buffer.writeu32(ScratchB, 44, bit32.bxor(PB11, bit32.band(PB12, PB13)))
					buffer.writeu32(ScratchA, 48, bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14)))
					buffer.writeu32(ScratchB, 48, bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14)))
					buffer.writeu32(ScratchA, 52, bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10)))
					buffer.writeu32(ScratchB, 52, bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10)))
					buffer.writeu32(ScratchA, 56, bit32.bxor(PA14, bit32.band(PA10, PA11)))
					buffer.writeu32(ScratchB, 56, bit32.bxor(PB14, bit32.band(PB10, PB11)))
				end
				do
					local PA15, PB15
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(ScratchD, 36))
						PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
					end
					local PA16, PB16
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 20), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 20), buffer.readu32(ScratchD, 20))
						PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
					end
					local PA17, PB17
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 44), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 44), buffer.readu32(ScratchD, 24))
						PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
					end
					local PA18, PB18
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 68), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 68), buffer.readu32(ScratchD, 28))
						PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
					end
					local PA19, PB19
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 92), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 92), buffer.readu32(ScratchD, 32))
						PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
					end
					buffer.writeu32(ScratchA, 60, bit32.bxor(PA15, bit32.band(PA16, PA17)))
					buffer.writeu32(ScratchB, 60, bit32.bxor(PB15, bit32.band(PB16, PB17)))
					buffer.writeu32(ScratchA, 64, bit32.bxor(PA16, bit32.bor(PA17, PA18)))
					buffer.writeu32(ScratchB, 64, bit32.bxor(PB16, bit32.bor(PB17, PB18)))
					buffer.writeu32(ScratchA, 68, bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19)))
					buffer.writeu32(ScratchB, 68, bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19)))
					buffer.writeu32(ScratchA, 72, bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15)))
					buffer.writeu32(ScratchB, 72, bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15)))
					buffer.writeu32(ScratchA, 76, bit32.bxor(PA19, bit32.bor(PA15, PA16)))
					buffer.writeu32(ScratchB, 76, bit32.bxor(PB19, bit32.bor(PB15, PB16)))
				end
				do
					local PA20, PB20
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(ScratchD, 28))
						PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
					end
					local PA21, PB21
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 32), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 32), buffer.readu32(ScratchD, 32))
						PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
					end
					local PA22, PB22
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 56), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 56), buffer.readu32(ScratchD, 36))
						PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
					end
					local PA23, PB23
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 60), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 60), buffer.readu32(ScratchD, 20))
						PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
					end
					local PA24, PB24
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 84), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 84), buffer.readu32(ScratchD, 24))
						PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
					end
					buffer.writeu32(ScratchA, 80, bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22)))
					buffer.writeu32(ScratchB, 80, bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22)))
					buffer.writeu32(ScratchA, 84, bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23)))
					buffer.writeu32(ScratchB, 84, bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23)))
					buffer.writeu32(ScratchA, 88, bit32.bxor(PA22, bit32.band(PA23, PA24)))
					buffer.writeu32(ScratchB, 88, bit32.bxor(PB22, bit32.band(PB23, PB24)))
					buffer.writeu32(ScratchA, 92, bit32.bxor(PA23, bit32.bor(PA24, PA20)))
					buffer.writeu32(ScratchB, 92, bit32.bxor(PB23, bit32.bor(PB24, PB20)))
					buffer.writeu32(ScratchA, 96, bit32.bxor(PA24, bit32.band(PA20, PA21)))
					buffer.writeu32(ScratchB, 96, bit32.bxor(PB24, bit32.band(PB20, PB21)))
				end
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 4), buffer.readu32(RoundConstantsB, RoundIndex + 4)
				local CA0, CB0 = bit32.bxor(buffer.readu32(ScratchA, 0), buffer.readu32(ScratchA, 20), buffer.readu32(ScratchA, 40), buffer.readu32(ScratchA, 60), buffer.readu32(ScratchA, 80)), bit32.bxor(buffer.readu32(ScratchB, 0), buffer.readu32(ScratchB, 20), buffer.readu32(ScratchB, 40), buffer.readu32(ScratchB, 60), buffer.readu32(ScratchB, 80))
				local CA1, CB1 = bit32.bxor(buffer.readu32(ScratchA, 4), buffer.readu32(ScratchA, 24), buffer.readu32(ScratchA, 44), buffer.readu32(ScratchA, 64), buffer.readu32(ScratchA, 84)), bit32.bxor(buffer.readu32(ScratchB, 4), buffer.readu32(ScratchB, 24), buffer.readu32(ScratchB, 44), buffer.readu32(ScratchB, 64), buffer.readu32(ScratchB, 84))
				local CA2, CB2 = bit32.bxor(buffer.readu32(ScratchA, 8), buffer.readu32(ScratchA, 28), buffer.readu32(ScratchA, 48), buffer.readu32(ScratchA, 68), buffer.readu32(ScratchA, 88)), bit32.bxor(buffer.readu32(ScratchB, 8), buffer.readu32(ScratchB, 28), buffer.readu32(ScratchB, 48), buffer.readu32(ScratchB, 68), buffer.readu32(ScratchB, 88))
				local CA3, CB3 = bit32.bxor(buffer.readu32(ScratchA, 12), buffer.readu32(ScratchA, 32), buffer.readu32(ScratchA, 52), buffer.readu32(ScratchA, 72), buffer.readu32(ScratchA, 92)), bit32.bxor(buffer.readu32(ScratchB, 12), buffer.readu32(ScratchB, 32), buffer.readu32(ScratchB, 52), buffer.readu32(ScratchB, 72), buffer.readu32(ScratchB, 92))
				local CA4, CB4 = bit32.bxor(buffer.readu32(ScratchA, 16), buffer.readu32(ScratchA, 36), buffer.readu32(ScratchA, 56), buffer.readu32(ScratchA, 76), buffer.readu32(ScratchA, 96)), bit32.bxor(buffer.readu32(ScratchB, 16), buffer.readu32(ScratchB, 36), buffer.readu32(ScratchB, 56), buffer.readu32(ScratchB, 76), buffer.readu32(ScratchB, 96))
				buffer.writeu32(ScratchD, 0, bit32.bxor(CA4, bit32.lrotate(CB1, 1))); buffer.writeu32(ScratchD, 20, bit32.bxor(CB4, CA1))
				buffer.writeu32(ScratchD, 4, bit32.bxor(CA0, bit32.lrotate(CB2, 1))); buffer.writeu32(ScratchD, 24, bit32.bxor(CB0, CA2))
				buffer.writeu32(ScratchD, 8, bit32.bxor(CA1, bit32.lrotate(CB3, 1))); buffer.writeu32(ScratchD, 28, bit32.bxor(CB1, CA3))
				buffer.writeu32(ScratchD, 12, bit32.bxor(CA2, bit32.lrotate(CB4, 1))); buffer.writeu32(ScratchD, 32, bit32.bxor(CB2, CA4))
				buffer.writeu32(ScratchD, 16, bit32.bxor(CA3, bit32.lrotate(CB0, 1))); buffer.writeu32(ScratchD, 36, bit32.bxor(CB3, CA0))
				if RoundIndex < 0 then break end
				do
					local PA0, PB0 = bit32.bxor(buffer.readu32(ScratchA, 0), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 0), buffer.readu32(ScratchD, 20))
					local PA1, PB1
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 24), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 24), buffer.readu32(ScratchD, 24))
						PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
					end
					local PA2, PB2
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 48), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 48), buffer.readu32(ScratchD, 28))
						PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
					end
					local PA3, PB3
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 72), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 72), buffer.readu32(ScratchD, 32))
						PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
					end
					local PA4, PB4
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 96), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 96), buffer.readu32(ScratchD, 36))
						PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
					end
					buffer.writeu32(StateA, 0, bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA))
					buffer.writeu32(StateB, 0, bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB))
					buffer.writeu32(StateA, 4, bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3)))
					buffer.writeu32(StateB, 4, bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3)))
					buffer.writeu32(StateA, 8, bit32.bxor(PA2, bit32.band(PA3, PA4)))
					buffer.writeu32(StateB, 8, bit32.bxor(PB2, bit32.band(PB3, PB4)))
					buffer.writeu32(StateA, 12, bit32.bxor(PA3, bit32.bor(PA4, PA0)))
					buffer.writeu32(StateB, 12, bit32.bxor(PB3, bit32.bor(PB4, PB0)))
					buffer.writeu32(StateA, 16, bit32.bxor(PA4, bit32.band(PA0, PA1)))
					buffer.writeu32(StateB, 16, bit32.bxor(PB4, bit32.band(PB0, PB1)))
				end
				do
					local PA5, PB5
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 12), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 12), buffer.readu32(ScratchD, 32))
						PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
					end
					local PA6, PB6
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 36), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 36), buffer.readu32(ScratchD, 36))
						PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
					end
					local PA7, PB7
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 40), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 40), buffer.readu32(ScratchD, 20))
						PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
					end
					local PA8, PB8
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 64), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 64), buffer.readu32(ScratchD, 24))
						PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
					end
					local PA9, PB9
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 88), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 88), buffer.readu32(ScratchD, 28))
						PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
					end
					buffer.writeu32(StateA, 20, bit32.bxor(PA5, bit32.bor(PA6, PA7)))
					buffer.writeu32(StateB, 20, bit32.bxor(PB5, bit32.bor(PB6, PB7)))
					buffer.writeu32(StateA, 24, bit32.bxor(PA6, bit32.band(PA7, PA8)))
					buffer.writeu32(StateB, 24, bit32.bxor(PB6, bit32.band(PB7, PB8)))
					buffer.writeu32(StateA, 28, bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9))))
					buffer.writeu32(StateB, 28, bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9))))
					buffer.writeu32(StateA, 32, bit32.bxor(PA8, bit32.bor(PA9, PA5)))
					buffer.writeu32(StateB, 32, bit32.bxor(PB8, bit32.bor(PB9, PB5)))
					buffer.writeu32(StateA, 36, bit32.bxor(PA9, bit32.band(PA5, PA6)))
					buffer.writeu32(StateB, 36, bit32.bxor(PB9, bit32.band(PB5, PB6)))
				end
				do
					local PA10, PB10
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 4), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 4), buffer.readu32(ScratchD, 24))
						PA10, PB10 = bit32.lrotate(TB, 1), (TA)
					end
					local PA11, PB11
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 28), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 28), buffer.readu32(ScratchD, 28))
						PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
					end
					local PA12, PB12
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 52), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 52), buffer.readu32(ScratchD, 32))
						PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
					end
					local PA13, PB13
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 76), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 76), buffer.readu32(ScratchD, 36))
						PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
					end
					local PA14, PB14
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 80), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 80), buffer.readu32(ScratchD, 20))
						PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
					end
					buffer.writeu32(StateA, 40, bit32.bxor(PA10, bit32.bor(PA11, PA12)))
					buffer.writeu32(StateB, 40, bit32.bxor(PB10, bit32.bor(PB11, PB12)))
					buffer.writeu32(StateA, 44, bit32.bxor(PA11, bit32.band(PA12, PA13)))
					buffer.writeu32(StateB, 44, bit32.bxor(PB11, bit32.band(PB12, PB13)))
					buffer.writeu32(StateA, 48, bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14)))
					buffer.writeu32(StateB, 48, bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14)))
					buffer.writeu32(StateA, 52, bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10)))
					buffer.writeu32(StateB, 52, bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10)))
					buffer.writeu32(StateA, 56, bit32.bxor(PA14, bit32.band(PA10, PA11)))
					buffer.writeu32(StateB, 56, bit32.bxor(PB14, bit32.band(PB10, PB11)))
				end
				do
					local PA15, PB15
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 16), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 16), buffer.readu32(ScratchD, 36))
						PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
					end
					local PA16, PB16
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 20), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 20), buffer.readu32(ScratchD, 20))
						PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
					end
					local PA17, PB17
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 44), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 44), buffer.readu32(ScratchD, 24))
						PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
					end
					local PA18, PB18
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 68), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 68), buffer.readu32(ScratchD, 28))
						PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
					end
					local PA19, PB19
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 92), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 92), buffer.readu32(ScratchD, 32))
						PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
					end
					buffer.writeu32(StateA, 60, bit32.bxor(PA15, bit32.band(PA16, PA17)))
					buffer.writeu32(StateB, 60, bit32.bxor(PB15, bit32.band(PB16, PB17)))
					buffer.writeu32(StateA, 64, bit32.bxor(PA16, bit32.bor(PA17, PA18)))
					buffer.writeu32(StateB, 64, bit32.bxor(PB16, bit32.bor(PB17, PB18)))
					buffer.writeu32(StateA, 68, bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19)))
					buffer.writeu32(StateB, 68, bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19)))
					buffer.writeu32(StateA, 72, bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15)))
					buffer.writeu32(StateB, 72, bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15)))
					buffer.writeu32(StateA, 76, bit32.bxor(PA19, bit32.bor(PA15, PA16)))
					buffer.writeu32(StateB, 76, bit32.bxor(PB19, bit32.bor(PB15, PB16)))
				end
				do
					local PA20, PB20
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 8), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 8), buffer.readu32(ScratchD, 28))
						PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
					end
					local PA21, PB21
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 32), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 32), buffer.readu32(ScratchD, 32))
						PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
					end
					local PA22, PB22
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 56), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 56), buffer.readu32(ScratchD, 36))
						PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
					end
					local PA23, PB23
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 60), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 60), buffer.readu32(ScratchD, 20))
						PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
					end
					local PA24, PB24
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 84), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 84), buffer.readu32(ScratchD, 24))
						PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
					end
					buffer.writeu32(StateA, 80, bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22)))
					buffer.writeu32(StateB, 80, bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22)))
					buffer.writeu32(StateA, 84, bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23)))
					buffer.writeu32(StateB, 84, bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23)))
					buffer.writeu32(StateA, 88, bit32.bxor(PA22, bit32.band(PA23, PA24)))
					buffer.writeu32(StateB, 88, bit32.bxor(PB22, bit32.band(PB23, PB24)))
					buffer.writeu32(StateA, 92, bit32.bxor(PA23, bit32.bor(PA24, PA20)))
					buffer.writeu32(StateB, 92, bit32.bxor(PB23, bit32.bor(PB24, PB20)))
					buffer.writeu32(StateA, 96, bit32.bxor(PA24, bit32.band(PA20, PA21)))
					buffer.writeu32(StateB, 96, bit32.bxor(PB24, bit32.band(PB20, PB21)))
				end
			end
		end
	end
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
end

local function Absorb13(StateA: buffer, StateB: buffer, Input: buffer, Offset: number, Size: number, Fresh: boolean?)
	local ScratchA, ScratchB = SCRATCH_A, SCRATCH_B
	local ScratchD = SCRATCH_D
	local RoundConstantsA, RoundConstantsB = ROUND_A, ROUND_B
	if Fresh then
		buffer.fill(StateA, 0, 0, 100)
		buffer.fill(StateB, 0, 0, 100)
	end
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
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
			buffer.writeu32(StateA, 0, bit32.bxor(buffer.readu32(StateA, 0), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 0, bit32.bxor(buffer.readu32(StateB, 0), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 4, bit32.bxor(buffer.readu32(StateA, 4), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 4, bit32.bxor(buffer.readu32(StateB, 4), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 8, bit32.bxor(buffer.readu32(StateA, 8), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 8, bit32.bxor(buffer.readu32(StateB, 8), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 12, bit32.bxor(buffer.readu32(StateA, 12), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 12, bit32.bxor(buffer.readu32(StateB, 12), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 16, bit32.bxor(buffer.readu32(StateA, 16), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 16, bit32.bxor(buffer.readu32(StateB, 16), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 20, bit32.bxor(buffer.readu32(StateA, 20), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 20, bit32.bxor(buffer.readu32(StateB, 20), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 24, bit32.bxor(buffer.readu32(StateA, 24), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 24, bit32.bxor(buffer.readu32(StateB, 24), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 28, bit32.bxor(buffer.readu32(StateA, 28), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 28, bit32.bxor(buffer.readu32(StateB, 28), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 32, bit32.bxor(buffer.readu32(StateA, 32), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 32, bit32.bxor(buffer.readu32(StateB, 32), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 36, bit32.bxor(buffer.readu32(StateA, 36), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 36, bit32.bxor(buffer.readu32(StateB, 36), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 40, bit32.bxor(buffer.readu32(StateA, 40), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 40, bit32.bxor(buffer.readu32(StateB, 40), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 44, bit32.bxor(buffer.readu32(StateA, 44), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 44, bit32.bxor(buffer.readu32(StateB, 44), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 48, bit32.bxor(buffer.readu32(StateA, 48), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 48, bit32.bxor(buffer.readu32(StateB, 48), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
		end
		for RoundIndex = 0, 88, 8 do
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex), buffer.readu32(RoundConstantsB, RoundIndex)
				local CA0, CB0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(StateA, 20), buffer.readu32(StateA, 40), buffer.readu32(StateA, 60), buffer.readu32(StateA, 80)), bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(StateB, 20), buffer.readu32(StateB, 40), buffer.readu32(StateB, 60), buffer.readu32(StateB, 80))
				local CA1, CB1 = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(StateA, 24), buffer.readu32(StateA, 44), buffer.readu32(StateA, 64), buffer.readu32(StateA, 84)), bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(StateB, 24), buffer.readu32(StateB, 44), buffer.readu32(StateB, 64), buffer.readu32(StateB, 84))
				local CA2, CB2 = bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(StateA, 28), buffer.readu32(StateA, 48), buffer.readu32(StateA, 68), buffer.readu32(StateA, 88)), bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(StateB, 28), buffer.readu32(StateB, 48), buffer.readu32(StateB, 68), buffer.readu32(StateB, 88))
				local CA3, CB3 = bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(StateA, 32), buffer.readu32(StateA, 52), buffer.readu32(StateA, 72), buffer.readu32(StateA, 92)), bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(StateB, 32), buffer.readu32(StateB, 52), buffer.readu32(StateB, 72), buffer.readu32(StateB, 92))
				local CA4, CB4 = bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(StateA, 36), buffer.readu32(StateA, 56), buffer.readu32(StateA, 76), buffer.readu32(StateA, 96)), bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(StateB, 36), buffer.readu32(StateB, 56), buffer.readu32(StateB, 76), buffer.readu32(StateB, 96))
				buffer.writeu32(ScratchD, 0, bit32.bxor(CA4, bit32.lrotate(CB1, 1))); buffer.writeu32(ScratchD, 20, bit32.bxor(CB4, CA1))
				buffer.writeu32(ScratchD, 4, bit32.bxor(CA0, bit32.lrotate(CB2, 1))); buffer.writeu32(ScratchD, 24, bit32.bxor(CB0, CA2))
				buffer.writeu32(ScratchD, 8, bit32.bxor(CA1, bit32.lrotate(CB3, 1))); buffer.writeu32(ScratchD, 28, bit32.bxor(CB1, CA3))
				buffer.writeu32(ScratchD, 12, bit32.bxor(CA2, bit32.lrotate(CB4, 1))); buffer.writeu32(ScratchD, 32, bit32.bxor(CB2, CA4))
				buffer.writeu32(ScratchD, 16, bit32.bxor(CA3, bit32.lrotate(CB0, 1))); buffer.writeu32(ScratchD, 36, bit32.bxor(CB3, CA0))
				if RoundIndex < 0 then break end
				do
					local PA0, PB0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(ScratchD, 20))
					local PA1, PB1
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 24), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 24), buffer.readu32(ScratchD, 24))
						PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
					end
					local PA2, PB2
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 48), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 48), buffer.readu32(ScratchD, 28))
						PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
					end
					local PA3, PB3
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 72), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 72), buffer.readu32(ScratchD, 32))
						PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
					end
					local PA4, PB4
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 96), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 96), buffer.readu32(ScratchD, 36))
						PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
					end
					buffer.writeu32(ScratchA, 0, bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA))
					buffer.writeu32(ScratchB, 0, bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB))
					buffer.writeu32(ScratchA, 4, bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3)))
					buffer.writeu32(ScratchB, 4, bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3)))
					buffer.writeu32(ScratchA, 8, bit32.bxor(PA2, bit32.band(PA3, PA4)))
					buffer.writeu32(ScratchB, 8, bit32.bxor(PB2, bit32.band(PB3, PB4)))
					buffer.writeu32(ScratchA, 12, bit32.bxor(PA3, bit32.bor(PA4, PA0)))
					buffer.writeu32(ScratchB, 12, bit32.bxor(PB3, bit32.bor(PB4, PB0)))
					buffer.writeu32(ScratchA, 16, bit32.bxor(PA4, bit32.band(PA0, PA1)))
					buffer.writeu32(ScratchB, 16, bit32.bxor(PB4, bit32.band(PB0, PB1)))
				end
				do
					local PA5, PB5
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(ScratchD, 32))
						PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
					end
					local PA6, PB6
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 36), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 36), buffer.readu32(ScratchD, 36))
						PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
					end
					local PA7, PB7
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 40), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 40), buffer.readu32(ScratchD, 20))
						PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
					end
					local PA8, PB8
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 64), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 64), buffer.readu32(ScratchD, 24))
						PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
					end
					local PA9, PB9
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 88), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 88), buffer.readu32(ScratchD, 28))
						PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
					end
					buffer.writeu32(ScratchA, 20, bit32.bxor(PA5, bit32.bor(PA6, PA7)))
					buffer.writeu32(ScratchB, 20, bit32.bxor(PB5, bit32.bor(PB6, PB7)))
					buffer.writeu32(ScratchA, 24, bit32.bxor(PA6, bit32.band(PA7, PA8)))
					buffer.writeu32(ScratchB, 24, bit32.bxor(PB6, bit32.band(PB7, PB8)))
					buffer.writeu32(ScratchA, 28, bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9))))
					buffer.writeu32(ScratchB, 28, bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9))))
					buffer.writeu32(ScratchA, 32, bit32.bxor(PA8, bit32.bor(PA9, PA5)))
					buffer.writeu32(ScratchB, 32, bit32.bxor(PB8, bit32.bor(PB9, PB5)))
					buffer.writeu32(ScratchA, 36, bit32.bxor(PA9, bit32.band(PA5, PA6)))
					buffer.writeu32(ScratchB, 36, bit32.bxor(PB9, bit32.band(PB5, PB6)))
				end
				do
					local PA10, PB10
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(ScratchD, 24))
						PA10, PB10 = bit32.lrotate(TB, 1), (TA)
					end
					local PA11, PB11
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 28), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 28), buffer.readu32(ScratchD, 28))
						PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
					end
					local PA12, PB12
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 52), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 52), buffer.readu32(ScratchD, 32))
						PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
					end
					local PA13, PB13
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 76), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 76), buffer.readu32(ScratchD, 36))
						PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
					end
					local PA14, PB14
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 80), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 80), buffer.readu32(ScratchD, 20))
						PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
					end
					buffer.writeu32(ScratchA, 40, bit32.bxor(PA10, bit32.bor(PA11, PA12)))
					buffer.writeu32(ScratchB, 40, bit32.bxor(PB10, bit32.bor(PB11, PB12)))
					buffer.writeu32(ScratchA, 44, bit32.bxor(PA11, bit32.band(PA12, PA13)))
					buffer.writeu32(ScratchB, 44, bit32.bxor(PB11, bit32.band(PB12, PB13)))
					buffer.writeu32(ScratchA, 48, bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14)))
					buffer.writeu32(ScratchB, 48, bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14)))
					buffer.writeu32(ScratchA, 52, bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10)))
					buffer.writeu32(ScratchB, 52, bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10)))
					buffer.writeu32(ScratchA, 56, bit32.bxor(PA14, bit32.band(PA10, PA11)))
					buffer.writeu32(ScratchB, 56, bit32.bxor(PB14, bit32.band(PB10, PB11)))
				end
				do
					local PA15, PB15
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(ScratchD, 36))
						PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
					end
					local PA16, PB16
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 20), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 20), buffer.readu32(ScratchD, 20))
						PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
					end
					local PA17, PB17
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 44), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 44), buffer.readu32(ScratchD, 24))
						PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
					end
					local PA18, PB18
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 68), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 68), buffer.readu32(ScratchD, 28))
						PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
					end
					local PA19, PB19
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 92), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 92), buffer.readu32(ScratchD, 32))
						PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
					end
					buffer.writeu32(ScratchA, 60, bit32.bxor(PA15, bit32.band(PA16, PA17)))
					buffer.writeu32(ScratchB, 60, bit32.bxor(PB15, bit32.band(PB16, PB17)))
					buffer.writeu32(ScratchA, 64, bit32.bxor(PA16, bit32.bor(PA17, PA18)))
					buffer.writeu32(ScratchB, 64, bit32.bxor(PB16, bit32.bor(PB17, PB18)))
					buffer.writeu32(ScratchA, 68, bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19)))
					buffer.writeu32(ScratchB, 68, bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19)))
					buffer.writeu32(ScratchA, 72, bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15)))
					buffer.writeu32(ScratchB, 72, bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15)))
					buffer.writeu32(ScratchA, 76, bit32.bxor(PA19, bit32.bor(PA15, PA16)))
					buffer.writeu32(ScratchB, 76, bit32.bxor(PB19, bit32.bor(PB15, PB16)))
				end
				do
					local PA20, PB20
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(ScratchD, 28))
						PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
					end
					local PA21, PB21
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 32), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 32), buffer.readu32(ScratchD, 32))
						PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
					end
					local PA22, PB22
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 56), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 56), buffer.readu32(ScratchD, 36))
						PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
					end
					local PA23, PB23
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 60), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 60), buffer.readu32(ScratchD, 20))
						PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
					end
					local PA24, PB24
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 84), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 84), buffer.readu32(ScratchD, 24))
						PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
					end
					buffer.writeu32(ScratchA, 80, bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22)))
					buffer.writeu32(ScratchB, 80, bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22)))
					buffer.writeu32(ScratchA, 84, bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23)))
					buffer.writeu32(ScratchB, 84, bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23)))
					buffer.writeu32(ScratchA, 88, bit32.bxor(PA22, bit32.band(PA23, PA24)))
					buffer.writeu32(ScratchB, 88, bit32.bxor(PB22, bit32.band(PB23, PB24)))
					buffer.writeu32(ScratchA, 92, bit32.bxor(PA23, bit32.bor(PA24, PA20)))
					buffer.writeu32(ScratchB, 92, bit32.bxor(PB23, bit32.bor(PB24, PB20)))
					buffer.writeu32(ScratchA, 96, bit32.bxor(PA24, bit32.band(PA20, PA21)))
					buffer.writeu32(ScratchB, 96, bit32.bxor(PB24, bit32.band(PB20, PB21)))
				end
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 4), buffer.readu32(RoundConstantsB, RoundIndex + 4)
				local CA0, CB0 = bit32.bxor(buffer.readu32(ScratchA, 0), buffer.readu32(ScratchA, 20), buffer.readu32(ScratchA, 40), buffer.readu32(ScratchA, 60), buffer.readu32(ScratchA, 80)), bit32.bxor(buffer.readu32(ScratchB, 0), buffer.readu32(ScratchB, 20), buffer.readu32(ScratchB, 40), buffer.readu32(ScratchB, 60), buffer.readu32(ScratchB, 80))
				local CA1, CB1 = bit32.bxor(buffer.readu32(ScratchA, 4), buffer.readu32(ScratchA, 24), buffer.readu32(ScratchA, 44), buffer.readu32(ScratchA, 64), buffer.readu32(ScratchA, 84)), bit32.bxor(buffer.readu32(ScratchB, 4), buffer.readu32(ScratchB, 24), buffer.readu32(ScratchB, 44), buffer.readu32(ScratchB, 64), buffer.readu32(ScratchB, 84))
				local CA2, CB2 = bit32.bxor(buffer.readu32(ScratchA, 8), buffer.readu32(ScratchA, 28), buffer.readu32(ScratchA, 48), buffer.readu32(ScratchA, 68), buffer.readu32(ScratchA, 88)), bit32.bxor(buffer.readu32(ScratchB, 8), buffer.readu32(ScratchB, 28), buffer.readu32(ScratchB, 48), buffer.readu32(ScratchB, 68), buffer.readu32(ScratchB, 88))
				local CA3, CB3 = bit32.bxor(buffer.readu32(ScratchA, 12), buffer.readu32(ScratchA, 32), buffer.readu32(ScratchA, 52), buffer.readu32(ScratchA, 72), buffer.readu32(ScratchA, 92)), bit32.bxor(buffer.readu32(ScratchB, 12), buffer.readu32(ScratchB, 32), buffer.readu32(ScratchB, 52), buffer.readu32(ScratchB, 72), buffer.readu32(ScratchB, 92))
				local CA4, CB4 = bit32.bxor(buffer.readu32(ScratchA, 16), buffer.readu32(ScratchA, 36), buffer.readu32(ScratchA, 56), buffer.readu32(ScratchA, 76), buffer.readu32(ScratchA, 96)), bit32.bxor(buffer.readu32(ScratchB, 16), buffer.readu32(ScratchB, 36), buffer.readu32(ScratchB, 56), buffer.readu32(ScratchB, 76), buffer.readu32(ScratchB, 96))
				buffer.writeu32(ScratchD, 0, bit32.bxor(CA4, bit32.lrotate(CB1, 1))); buffer.writeu32(ScratchD, 20, bit32.bxor(CB4, CA1))
				buffer.writeu32(ScratchD, 4, bit32.bxor(CA0, bit32.lrotate(CB2, 1))); buffer.writeu32(ScratchD, 24, bit32.bxor(CB0, CA2))
				buffer.writeu32(ScratchD, 8, bit32.bxor(CA1, bit32.lrotate(CB3, 1))); buffer.writeu32(ScratchD, 28, bit32.bxor(CB1, CA3))
				buffer.writeu32(ScratchD, 12, bit32.bxor(CA2, bit32.lrotate(CB4, 1))); buffer.writeu32(ScratchD, 32, bit32.bxor(CB2, CA4))
				buffer.writeu32(ScratchD, 16, bit32.bxor(CA3, bit32.lrotate(CB0, 1))); buffer.writeu32(ScratchD, 36, bit32.bxor(CB3, CA0))
				if RoundIndex < 0 then break end
				do
					local PA0, PB0 = bit32.bxor(buffer.readu32(ScratchA, 0), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 0), buffer.readu32(ScratchD, 20))
					local PA1, PB1
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 24), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 24), buffer.readu32(ScratchD, 24))
						PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
					end
					local PA2, PB2
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 48), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 48), buffer.readu32(ScratchD, 28))
						PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
					end
					local PA3, PB3
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 72), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 72), buffer.readu32(ScratchD, 32))
						PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
					end
					local PA4, PB4
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 96), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 96), buffer.readu32(ScratchD, 36))
						PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
					end
					buffer.writeu32(StateA, 0, bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA))
					buffer.writeu32(StateB, 0, bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB))
					buffer.writeu32(StateA, 4, bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3)))
					buffer.writeu32(StateB, 4, bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3)))
					buffer.writeu32(StateA, 8, bit32.bxor(PA2, bit32.band(PA3, PA4)))
					buffer.writeu32(StateB, 8, bit32.bxor(PB2, bit32.band(PB3, PB4)))
					buffer.writeu32(StateA, 12, bit32.bxor(PA3, bit32.bor(PA4, PA0)))
					buffer.writeu32(StateB, 12, bit32.bxor(PB3, bit32.bor(PB4, PB0)))
					buffer.writeu32(StateA, 16, bit32.bxor(PA4, bit32.band(PA0, PA1)))
					buffer.writeu32(StateB, 16, bit32.bxor(PB4, bit32.band(PB0, PB1)))
				end
				do
					local PA5, PB5
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 12), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 12), buffer.readu32(ScratchD, 32))
						PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
					end
					local PA6, PB6
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 36), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 36), buffer.readu32(ScratchD, 36))
						PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
					end
					local PA7, PB7
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 40), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 40), buffer.readu32(ScratchD, 20))
						PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
					end
					local PA8, PB8
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 64), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 64), buffer.readu32(ScratchD, 24))
						PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
					end
					local PA9, PB9
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 88), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 88), buffer.readu32(ScratchD, 28))
						PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
					end
					buffer.writeu32(StateA, 20, bit32.bxor(PA5, bit32.bor(PA6, PA7)))
					buffer.writeu32(StateB, 20, bit32.bxor(PB5, bit32.bor(PB6, PB7)))
					buffer.writeu32(StateA, 24, bit32.bxor(PA6, bit32.band(PA7, PA8)))
					buffer.writeu32(StateB, 24, bit32.bxor(PB6, bit32.band(PB7, PB8)))
					buffer.writeu32(StateA, 28, bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9))))
					buffer.writeu32(StateB, 28, bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9))))
					buffer.writeu32(StateA, 32, bit32.bxor(PA8, bit32.bor(PA9, PA5)))
					buffer.writeu32(StateB, 32, bit32.bxor(PB8, bit32.bor(PB9, PB5)))
					buffer.writeu32(StateA, 36, bit32.bxor(PA9, bit32.band(PA5, PA6)))
					buffer.writeu32(StateB, 36, bit32.bxor(PB9, bit32.band(PB5, PB6)))
				end
				do
					local PA10, PB10
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 4), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 4), buffer.readu32(ScratchD, 24))
						PA10, PB10 = bit32.lrotate(TB, 1), (TA)
					end
					local PA11, PB11
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 28), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 28), buffer.readu32(ScratchD, 28))
						PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
					end
					local PA12, PB12
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 52), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 52), buffer.readu32(ScratchD, 32))
						PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
					end
					local PA13, PB13
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 76), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 76), buffer.readu32(ScratchD, 36))
						PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
					end
					local PA14, PB14
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 80), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 80), buffer.readu32(ScratchD, 20))
						PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
					end
					buffer.writeu32(StateA, 40, bit32.bxor(PA10, bit32.bor(PA11, PA12)))
					buffer.writeu32(StateB, 40, bit32.bxor(PB10, bit32.bor(PB11, PB12)))
					buffer.writeu32(StateA, 44, bit32.bxor(PA11, bit32.band(PA12, PA13)))
					buffer.writeu32(StateB, 44, bit32.bxor(PB11, bit32.band(PB12, PB13)))
					buffer.writeu32(StateA, 48, bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14)))
					buffer.writeu32(StateB, 48, bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14)))
					buffer.writeu32(StateA, 52, bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10)))
					buffer.writeu32(StateB, 52, bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10)))
					buffer.writeu32(StateA, 56, bit32.bxor(PA14, bit32.band(PA10, PA11)))
					buffer.writeu32(StateB, 56, bit32.bxor(PB14, bit32.band(PB10, PB11)))
				end
				do
					local PA15, PB15
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 16), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 16), buffer.readu32(ScratchD, 36))
						PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
					end
					local PA16, PB16
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 20), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 20), buffer.readu32(ScratchD, 20))
						PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
					end
					local PA17, PB17
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 44), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 44), buffer.readu32(ScratchD, 24))
						PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
					end
					local PA18, PB18
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 68), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 68), buffer.readu32(ScratchD, 28))
						PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
					end
					local PA19, PB19
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 92), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 92), buffer.readu32(ScratchD, 32))
						PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
					end
					buffer.writeu32(StateA, 60, bit32.bxor(PA15, bit32.band(PA16, PA17)))
					buffer.writeu32(StateB, 60, bit32.bxor(PB15, bit32.band(PB16, PB17)))
					buffer.writeu32(StateA, 64, bit32.bxor(PA16, bit32.bor(PA17, PA18)))
					buffer.writeu32(StateB, 64, bit32.bxor(PB16, bit32.bor(PB17, PB18)))
					buffer.writeu32(StateA, 68, bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19)))
					buffer.writeu32(StateB, 68, bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19)))
					buffer.writeu32(StateA, 72, bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15)))
					buffer.writeu32(StateB, 72, bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15)))
					buffer.writeu32(StateA, 76, bit32.bxor(PA19, bit32.bor(PA15, PA16)))
					buffer.writeu32(StateB, 76, bit32.bxor(PB19, bit32.bor(PB15, PB16)))
				end
				do
					local PA20, PB20
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 8), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 8), buffer.readu32(ScratchD, 28))
						PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
					end
					local PA21, PB21
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 32), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 32), buffer.readu32(ScratchD, 32))
						PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
					end
					local PA22, PB22
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 56), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 56), buffer.readu32(ScratchD, 36))
						PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
					end
					local PA23, PB23
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 60), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 60), buffer.readu32(ScratchD, 20))
						PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
					end
					local PA24, PB24
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 84), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 84), buffer.readu32(ScratchD, 24))
						PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
					end
					buffer.writeu32(StateA, 80, bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22)))
					buffer.writeu32(StateB, 80, bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22)))
					buffer.writeu32(StateA, 84, bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23)))
					buffer.writeu32(StateB, 84, bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23)))
					buffer.writeu32(StateA, 88, bit32.bxor(PA22, bit32.band(PA23, PA24)))
					buffer.writeu32(StateB, 88, bit32.bxor(PB22, bit32.band(PB23, PB24)))
					buffer.writeu32(StateA, 92, bit32.bxor(PA23, bit32.bor(PA24, PA20)))
					buffer.writeu32(StateB, 92, bit32.bxor(PB23, bit32.bor(PB24, PB20)))
					buffer.writeu32(StateA, 96, bit32.bxor(PA24, bit32.band(PA20, PA21)))
					buffer.writeu32(StateB, 96, bit32.bxor(PB24, bit32.band(PB20, PB21)))
				end
			end
		end
	end
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
end

local function Absorb18(StateA: buffer, StateB: buffer, Input: buffer, Offset: number, Size: number, Fresh: boolean?)
	local ScratchA, ScratchB = SCRATCH_A, SCRATCH_B
	local ScratchD = SCRATCH_D
	local RoundConstantsA, RoundConstantsB = ROUND_A, ROUND_B
	if Fresh then
		buffer.fill(StateA, 0, 0, 100)
		buffer.fill(StateB, 0, 0, 100)
	end
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
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
			buffer.writeu32(StateA, 0, bit32.bxor(buffer.readu32(StateA, 0), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 0, bit32.bxor(buffer.readu32(StateB, 0), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 4, bit32.bxor(buffer.readu32(StateA, 4), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 4, bit32.bxor(buffer.readu32(StateB, 4), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 8, bit32.bxor(buffer.readu32(StateA, 8), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 8, bit32.bxor(buffer.readu32(StateB, 8), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 12, bit32.bxor(buffer.readu32(StateA, 12), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 12, bit32.bxor(buffer.readu32(StateB, 12), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 16, bit32.bxor(buffer.readu32(StateA, 16), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 16, bit32.bxor(buffer.readu32(StateB, 16), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 20, bit32.bxor(buffer.readu32(StateA, 20), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 20, bit32.bxor(buffer.readu32(StateB, 20), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 24, bit32.bxor(buffer.readu32(StateA, 24), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 24, bit32.bxor(buffer.readu32(StateB, 24), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 28, bit32.bxor(buffer.readu32(StateA, 28), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 28, bit32.bxor(buffer.readu32(StateB, 28), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 32, bit32.bxor(buffer.readu32(StateA, 32), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 32, bit32.bxor(buffer.readu32(StateB, 32), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 36, bit32.bxor(buffer.readu32(StateA, 36), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 36, bit32.bxor(buffer.readu32(StateB, 36), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 40, bit32.bxor(buffer.readu32(StateA, 40), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 40, bit32.bxor(buffer.readu32(StateB, 40), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 44, bit32.bxor(buffer.readu32(StateA, 44), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 44, bit32.bxor(buffer.readu32(StateB, 44), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 48, bit32.bxor(buffer.readu32(StateA, 48), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 48, bit32.bxor(buffer.readu32(StateB, 48), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 52, bit32.bxor(buffer.readu32(StateA, 52), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 52, bit32.bxor(buffer.readu32(StateB, 52), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 56, bit32.bxor(buffer.readu32(StateA, 56), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 56, bit32.bxor(buffer.readu32(StateB, 56), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 60, bit32.bxor(buffer.readu32(StateA, 60), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 60, bit32.bxor(buffer.readu32(StateB, 60), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 64, bit32.bxor(buffer.readu32(StateA, 64), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 64, bit32.bxor(buffer.readu32(StateB, 64), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
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
			buffer.writeu32(StateA, 68, bit32.bxor(buffer.readu32(StateA, 68), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, 68, bit32.bxor(buffer.readu32(StateB, 68), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
		end
		for RoundIndex = 0, 88, 8 do
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex), buffer.readu32(RoundConstantsB, RoundIndex)
				local CA0, CB0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(StateA, 20), buffer.readu32(StateA, 40), buffer.readu32(StateA, 60), buffer.readu32(StateA, 80)), bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(StateB, 20), buffer.readu32(StateB, 40), buffer.readu32(StateB, 60), buffer.readu32(StateB, 80))
				local CA1, CB1 = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(StateA, 24), buffer.readu32(StateA, 44), buffer.readu32(StateA, 64), buffer.readu32(StateA, 84)), bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(StateB, 24), buffer.readu32(StateB, 44), buffer.readu32(StateB, 64), buffer.readu32(StateB, 84))
				local CA2, CB2 = bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(StateA, 28), buffer.readu32(StateA, 48), buffer.readu32(StateA, 68), buffer.readu32(StateA, 88)), bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(StateB, 28), buffer.readu32(StateB, 48), buffer.readu32(StateB, 68), buffer.readu32(StateB, 88))
				local CA3, CB3 = bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(StateA, 32), buffer.readu32(StateA, 52), buffer.readu32(StateA, 72), buffer.readu32(StateA, 92)), bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(StateB, 32), buffer.readu32(StateB, 52), buffer.readu32(StateB, 72), buffer.readu32(StateB, 92))
				local CA4, CB4 = bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(StateA, 36), buffer.readu32(StateA, 56), buffer.readu32(StateA, 76), buffer.readu32(StateA, 96)), bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(StateB, 36), buffer.readu32(StateB, 56), buffer.readu32(StateB, 76), buffer.readu32(StateB, 96))
				buffer.writeu32(ScratchD, 0, bit32.bxor(CA4, bit32.lrotate(CB1, 1))); buffer.writeu32(ScratchD, 20, bit32.bxor(CB4, CA1))
				buffer.writeu32(ScratchD, 4, bit32.bxor(CA0, bit32.lrotate(CB2, 1))); buffer.writeu32(ScratchD, 24, bit32.bxor(CB0, CA2))
				buffer.writeu32(ScratchD, 8, bit32.bxor(CA1, bit32.lrotate(CB3, 1))); buffer.writeu32(ScratchD, 28, bit32.bxor(CB1, CA3))
				buffer.writeu32(ScratchD, 12, bit32.bxor(CA2, bit32.lrotate(CB4, 1))); buffer.writeu32(ScratchD, 32, bit32.bxor(CB2, CA4))
				buffer.writeu32(ScratchD, 16, bit32.bxor(CA3, bit32.lrotate(CB0, 1))); buffer.writeu32(ScratchD, 36, bit32.bxor(CB3, CA0))
				if RoundIndex < 0 then break end
				do
					local PA0, PB0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(ScratchD, 20))
					local PA1, PB1
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 24), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 24), buffer.readu32(ScratchD, 24))
						PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
					end
					local PA2, PB2
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 48), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 48), buffer.readu32(ScratchD, 28))
						PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
					end
					local PA3, PB3
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 72), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 72), buffer.readu32(ScratchD, 32))
						PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
					end
					local PA4, PB4
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 96), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 96), buffer.readu32(ScratchD, 36))
						PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
					end
					buffer.writeu32(ScratchA, 0, bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA))
					buffer.writeu32(ScratchB, 0, bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB))
					buffer.writeu32(ScratchA, 4, bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3)))
					buffer.writeu32(ScratchB, 4, bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3)))
					buffer.writeu32(ScratchA, 8, bit32.bxor(PA2, bit32.band(PA3, PA4)))
					buffer.writeu32(ScratchB, 8, bit32.bxor(PB2, bit32.band(PB3, PB4)))
					buffer.writeu32(ScratchA, 12, bit32.bxor(PA3, bit32.bor(PA4, PA0)))
					buffer.writeu32(ScratchB, 12, bit32.bxor(PB3, bit32.bor(PB4, PB0)))
					buffer.writeu32(ScratchA, 16, bit32.bxor(PA4, bit32.band(PA0, PA1)))
					buffer.writeu32(ScratchB, 16, bit32.bxor(PB4, bit32.band(PB0, PB1)))
				end
				do
					local PA5, PB5
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(ScratchD, 32))
						PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
					end
					local PA6, PB6
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 36), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 36), buffer.readu32(ScratchD, 36))
						PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
					end
					local PA7, PB7
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 40), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 40), buffer.readu32(ScratchD, 20))
						PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
					end
					local PA8, PB8
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 64), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 64), buffer.readu32(ScratchD, 24))
						PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
					end
					local PA9, PB9
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 88), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 88), buffer.readu32(ScratchD, 28))
						PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
					end
					buffer.writeu32(ScratchA, 20, bit32.bxor(PA5, bit32.bor(PA6, PA7)))
					buffer.writeu32(ScratchB, 20, bit32.bxor(PB5, bit32.bor(PB6, PB7)))
					buffer.writeu32(ScratchA, 24, bit32.bxor(PA6, bit32.band(PA7, PA8)))
					buffer.writeu32(ScratchB, 24, bit32.bxor(PB6, bit32.band(PB7, PB8)))
					buffer.writeu32(ScratchA, 28, bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9))))
					buffer.writeu32(ScratchB, 28, bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9))))
					buffer.writeu32(ScratchA, 32, bit32.bxor(PA8, bit32.bor(PA9, PA5)))
					buffer.writeu32(ScratchB, 32, bit32.bxor(PB8, bit32.bor(PB9, PB5)))
					buffer.writeu32(ScratchA, 36, bit32.bxor(PA9, bit32.band(PA5, PA6)))
					buffer.writeu32(ScratchB, 36, bit32.bxor(PB9, bit32.band(PB5, PB6)))
				end
				do
					local PA10, PB10
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(ScratchD, 24))
						PA10, PB10 = bit32.lrotate(TB, 1), (TA)
					end
					local PA11, PB11
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 28), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 28), buffer.readu32(ScratchD, 28))
						PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
					end
					local PA12, PB12
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 52), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 52), buffer.readu32(ScratchD, 32))
						PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
					end
					local PA13, PB13
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 76), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 76), buffer.readu32(ScratchD, 36))
						PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
					end
					local PA14, PB14
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 80), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 80), buffer.readu32(ScratchD, 20))
						PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
					end
					buffer.writeu32(ScratchA, 40, bit32.bxor(PA10, bit32.bor(PA11, PA12)))
					buffer.writeu32(ScratchB, 40, bit32.bxor(PB10, bit32.bor(PB11, PB12)))
					buffer.writeu32(ScratchA, 44, bit32.bxor(PA11, bit32.band(PA12, PA13)))
					buffer.writeu32(ScratchB, 44, bit32.bxor(PB11, bit32.band(PB12, PB13)))
					buffer.writeu32(ScratchA, 48, bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14)))
					buffer.writeu32(ScratchB, 48, bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14)))
					buffer.writeu32(ScratchA, 52, bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10)))
					buffer.writeu32(ScratchB, 52, bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10)))
					buffer.writeu32(ScratchA, 56, bit32.bxor(PA14, bit32.band(PA10, PA11)))
					buffer.writeu32(ScratchB, 56, bit32.bxor(PB14, bit32.band(PB10, PB11)))
				end
				do
					local PA15, PB15
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(ScratchD, 36))
						PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
					end
					local PA16, PB16
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 20), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 20), buffer.readu32(ScratchD, 20))
						PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
					end
					local PA17, PB17
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 44), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 44), buffer.readu32(ScratchD, 24))
						PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
					end
					local PA18, PB18
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 68), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 68), buffer.readu32(ScratchD, 28))
						PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
					end
					local PA19, PB19
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 92), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 92), buffer.readu32(ScratchD, 32))
						PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
					end
					buffer.writeu32(ScratchA, 60, bit32.bxor(PA15, bit32.band(PA16, PA17)))
					buffer.writeu32(ScratchB, 60, bit32.bxor(PB15, bit32.band(PB16, PB17)))
					buffer.writeu32(ScratchA, 64, bit32.bxor(PA16, bit32.bor(PA17, PA18)))
					buffer.writeu32(ScratchB, 64, bit32.bxor(PB16, bit32.bor(PB17, PB18)))
					buffer.writeu32(ScratchA, 68, bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19)))
					buffer.writeu32(ScratchB, 68, bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19)))
					buffer.writeu32(ScratchA, 72, bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15)))
					buffer.writeu32(ScratchB, 72, bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15)))
					buffer.writeu32(ScratchA, 76, bit32.bxor(PA19, bit32.bor(PA15, PA16)))
					buffer.writeu32(ScratchB, 76, bit32.bxor(PB19, bit32.bor(PB15, PB16)))
				end
				do
					local PA20, PB20
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(ScratchD, 28))
						PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
					end
					local PA21, PB21
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 32), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(StateB, 32), buffer.readu32(ScratchD, 32))
						PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
					end
					local PA22, PB22
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 56), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(StateB, 56), buffer.readu32(ScratchD, 36))
						PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
					end
					local PA23, PB23
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 60), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(StateB, 60), buffer.readu32(ScratchD, 20))
						PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
					end
					local PA24, PB24
					do
						local TA, TB = bit32.bxor(buffer.readu32(StateA, 84), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(StateB, 84), buffer.readu32(ScratchD, 24))
						PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
					end
					buffer.writeu32(ScratchA, 80, bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22)))
					buffer.writeu32(ScratchB, 80, bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22)))
					buffer.writeu32(ScratchA, 84, bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23)))
					buffer.writeu32(ScratchB, 84, bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23)))
					buffer.writeu32(ScratchA, 88, bit32.bxor(PA22, bit32.band(PA23, PA24)))
					buffer.writeu32(ScratchB, 88, bit32.bxor(PB22, bit32.band(PB23, PB24)))
					buffer.writeu32(ScratchA, 92, bit32.bxor(PA23, bit32.bor(PA24, PA20)))
					buffer.writeu32(ScratchB, 92, bit32.bxor(PB23, bit32.bor(PB24, PB20)))
					buffer.writeu32(ScratchA, 96, bit32.bxor(PA24, bit32.band(PA20, PA21)))
					buffer.writeu32(ScratchB, 96, bit32.bxor(PB24, bit32.band(PB20, PB21)))
				end
			end
			if RoundIndex < 0 then break end
			do
				local RoundA, RoundB = buffer.readu32(RoundConstantsA, RoundIndex + 4), buffer.readu32(RoundConstantsB, RoundIndex + 4)
				local CA0, CB0 = bit32.bxor(buffer.readu32(ScratchA, 0), buffer.readu32(ScratchA, 20), buffer.readu32(ScratchA, 40), buffer.readu32(ScratchA, 60), buffer.readu32(ScratchA, 80)), bit32.bxor(buffer.readu32(ScratchB, 0), buffer.readu32(ScratchB, 20), buffer.readu32(ScratchB, 40), buffer.readu32(ScratchB, 60), buffer.readu32(ScratchB, 80))
				local CA1, CB1 = bit32.bxor(buffer.readu32(ScratchA, 4), buffer.readu32(ScratchA, 24), buffer.readu32(ScratchA, 44), buffer.readu32(ScratchA, 64), buffer.readu32(ScratchA, 84)), bit32.bxor(buffer.readu32(ScratchB, 4), buffer.readu32(ScratchB, 24), buffer.readu32(ScratchB, 44), buffer.readu32(ScratchB, 64), buffer.readu32(ScratchB, 84))
				local CA2, CB2 = bit32.bxor(buffer.readu32(ScratchA, 8), buffer.readu32(ScratchA, 28), buffer.readu32(ScratchA, 48), buffer.readu32(ScratchA, 68), buffer.readu32(ScratchA, 88)), bit32.bxor(buffer.readu32(ScratchB, 8), buffer.readu32(ScratchB, 28), buffer.readu32(ScratchB, 48), buffer.readu32(ScratchB, 68), buffer.readu32(ScratchB, 88))
				local CA3, CB3 = bit32.bxor(buffer.readu32(ScratchA, 12), buffer.readu32(ScratchA, 32), buffer.readu32(ScratchA, 52), buffer.readu32(ScratchA, 72), buffer.readu32(ScratchA, 92)), bit32.bxor(buffer.readu32(ScratchB, 12), buffer.readu32(ScratchB, 32), buffer.readu32(ScratchB, 52), buffer.readu32(ScratchB, 72), buffer.readu32(ScratchB, 92))
				local CA4, CB4 = bit32.bxor(buffer.readu32(ScratchA, 16), buffer.readu32(ScratchA, 36), buffer.readu32(ScratchA, 56), buffer.readu32(ScratchA, 76), buffer.readu32(ScratchA, 96)), bit32.bxor(buffer.readu32(ScratchB, 16), buffer.readu32(ScratchB, 36), buffer.readu32(ScratchB, 56), buffer.readu32(ScratchB, 76), buffer.readu32(ScratchB, 96))
				buffer.writeu32(ScratchD, 0, bit32.bxor(CA4, bit32.lrotate(CB1, 1))); buffer.writeu32(ScratchD, 20, bit32.bxor(CB4, CA1))
				buffer.writeu32(ScratchD, 4, bit32.bxor(CA0, bit32.lrotate(CB2, 1))); buffer.writeu32(ScratchD, 24, bit32.bxor(CB0, CA2))
				buffer.writeu32(ScratchD, 8, bit32.bxor(CA1, bit32.lrotate(CB3, 1))); buffer.writeu32(ScratchD, 28, bit32.bxor(CB1, CA3))
				buffer.writeu32(ScratchD, 12, bit32.bxor(CA2, bit32.lrotate(CB4, 1))); buffer.writeu32(ScratchD, 32, bit32.bxor(CB2, CA4))
				buffer.writeu32(ScratchD, 16, bit32.bxor(CA3, bit32.lrotate(CB0, 1))); buffer.writeu32(ScratchD, 36, bit32.bxor(CB3, CA0))
				if RoundIndex < 0 then break end
				do
					local PA0, PB0 = bit32.bxor(buffer.readu32(ScratchA, 0), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 0), buffer.readu32(ScratchD, 20))
					local PA1, PB1
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 24), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 24), buffer.readu32(ScratchD, 24))
						PA1, PB1 = bit32.lrotate(TA, 22), (bit32.lrotate(TB, 22))
					end
					local PA2, PB2
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 48), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 48), buffer.readu32(ScratchD, 28))
						PA2, PB2 = bit32.lrotate(TB, 22), (bit32.lrotate(TA, 21))
					end
					local PA3, PB3
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 72), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 72), buffer.readu32(ScratchD, 32))
						PA3, PB3 = bit32.lrotate(TB, 11), (bit32.lrotate(TA, 10))
					end
					local PA4, PB4
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 96), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 96), buffer.readu32(ScratchD, 36))
						PA4, PB4 = bit32.lrotate(TA, 7), (bit32.lrotate(TB, 7))
					end
					buffer.writeu32(StateA, 0, bit32.bxor(PA0, bit32.bor(PA1, PA2), RoundA))
					buffer.writeu32(StateB, 0, bit32.bxor(PB0, bit32.bor(PB1, PB2), RoundB))
					buffer.writeu32(StateA, 4, bit32.bxor(PA1, bit32.bor(bit32.bnot(PA2), PA3)))
					buffer.writeu32(StateB, 4, bit32.bxor(PB1, bit32.bor(bit32.bnot(PB2), PB3)))
					buffer.writeu32(StateA, 8, bit32.bxor(PA2, bit32.band(PA3, PA4)))
					buffer.writeu32(StateB, 8, bit32.bxor(PB2, bit32.band(PB3, PB4)))
					buffer.writeu32(StateA, 12, bit32.bxor(PA3, bit32.bor(PA4, PA0)))
					buffer.writeu32(StateB, 12, bit32.bxor(PB3, bit32.bor(PB4, PB0)))
					buffer.writeu32(StateA, 16, bit32.bxor(PA4, bit32.band(PA0, PA1)))
					buffer.writeu32(StateB, 16, bit32.bxor(PB4, bit32.band(PB0, PB1)))
				end
				do
					local PA5, PB5
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 12), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 12), buffer.readu32(ScratchD, 32))
						PA5, PB5 = bit32.lrotate(TA, 14), (bit32.lrotate(TB, 14))
					end
					local PA6, PB6
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 36), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 36), buffer.readu32(ScratchD, 36))
						PA6, PB6 = bit32.lrotate(TA, 10), (bit32.lrotate(TB, 10))
					end
					local PA7, PB7
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 40), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 40), buffer.readu32(ScratchD, 20))
						PA7, PB7 = bit32.lrotate(TB, 2), (bit32.lrotate(TA, 1))
					end
					local PA8, PB8
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 64), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 64), buffer.readu32(ScratchD, 24))
						PA8, PB8 = bit32.lrotate(TB, 23), (bit32.lrotate(TA, 22))
					end
					local PA9, PB9
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 88), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 88), buffer.readu32(ScratchD, 28))
						PA9, PB9 = bit32.lrotate(TB, 31), (bit32.lrotate(TA, 30))
					end
					buffer.writeu32(StateA, 20, bit32.bxor(PA5, bit32.bor(PA6, PA7)))
					buffer.writeu32(StateB, 20, bit32.bxor(PB5, bit32.bor(PB6, PB7)))
					buffer.writeu32(StateA, 24, bit32.bxor(PA6, bit32.band(PA7, PA8)))
					buffer.writeu32(StateB, 24, bit32.bxor(PB6, bit32.band(PB7, PB8)))
					buffer.writeu32(StateA, 28, bit32.bxor(PA7, bit32.bor(PA8, bit32.bnot(PA9))))
					buffer.writeu32(StateB, 28, bit32.bxor(PB7, bit32.bor(PB8, bit32.bnot(PB9))))
					buffer.writeu32(StateA, 32, bit32.bxor(PA8, bit32.bor(PA9, PA5)))
					buffer.writeu32(StateB, 32, bit32.bxor(PB8, bit32.bor(PB9, PB5)))
					buffer.writeu32(StateA, 36, bit32.bxor(PA9, bit32.band(PA5, PA6)))
					buffer.writeu32(StateB, 36, bit32.bxor(PB9, bit32.band(PB5, PB6)))
				end
				do
					local PA10, PB10
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 4), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 4), buffer.readu32(ScratchD, 24))
						PA10, PB10 = bit32.lrotate(TB, 1), (TA)
					end
					local PA11, PB11
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 28), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 28), buffer.readu32(ScratchD, 28))
						PA11, PB11 = bit32.lrotate(TA, 3), (bit32.lrotate(TB, 3))
					end
					local PA12, PB12
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 52), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 52), buffer.readu32(ScratchD, 32))
						PA12, PB12 = bit32.lrotate(TB, 13), (bit32.lrotate(TA, 12))
					end
					local PA13, PB13
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 76), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 76), buffer.readu32(ScratchD, 36))
						PA13, PB13 = bit32.lrotate(TA, 4), (bit32.lrotate(TB, 4))
					end
					local PA14, PB14
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 80), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 80), buffer.readu32(ScratchD, 20))
						PA14, PB14 = bit32.lrotate(TA, 9), (bit32.lrotate(TB, 9))
					end
					buffer.writeu32(StateA, 40, bit32.bxor(PA10, bit32.bor(PA11, PA12)))
					buffer.writeu32(StateB, 40, bit32.bxor(PB10, bit32.bor(PB11, PB12)))
					buffer.writeu32(StateA, 44, bit32.bxor(PA11, bit32.band(PA12, PA13)))
					buffer.writeu32(StateB, 44, bit32.bxor(PB11, bit32.band(PB12, PB13)))
					buffer.writeu32(StateA, 48, bit32.bxor(PA12, bit32.band(bit32.bnot(PA13), PA14)))
					buffer.writeu32(StateB, 48, bit32.bxor(PB12, bit32.band(bit32.bnot(PB13), PB14)))
					buffer.writeu32(StateA, 52, bit32.bxor(bit32.bnot(PA13), bit32.bor(PA14, PA10)))
					buffer.writeu32(StateB, 52, bit32.bxor(bit32.bnot(PB13), bit32.bor(PB14, PB10)))
					buffer.writeu32(StateA, 56, bit32.bxor(PA14, bit32.band(PA10, PA11)))
					buffer.writeu32(StateB, 56, bit32.bxor(PB14, bit32.band(PB10, PB11)))
				end
				do
					local PA15, PB15
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 16), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 16), buffer.readu32(ScratchD, 36))
						PA15, PB15 = bit32.lrotate(TB, 14), (bit32.lrotate(TA, 13))
					end
					local PA16, PB16
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 20), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 20), buffer.readu32(ScratchD, 20))
						PA16, PB16 = bit32.lrotate(TA, 18), (bit32.lrotate(TB, 18))
					end
					local PA17, PB17
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 44), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 44), buffer.readu32(ScratchD, 24))
						PA17, PB17 = bit32.lrotate(TA, 5), (bit32.lrotate(TB, 5))
					end
					local PA18, PB18
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 68), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 68), buffer.readu32(ScratchD, 28))
						PA18, PB18 = bit32.lrotate(TB, 8), (bit32.lrotate(TA, 7))
					end
					local PA19, PB19
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 92), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 92), buffer.readu32(ScratchD, 32))
						PA19, PB19 = bit32.lrotate(TA, 28), (bit32.lrotate(TB, 28))
					end
					buffer.writeu32(StateA, 60, bit32.bxor(PA15, bit32.band(PA16, PA17)))
					buffer.writeu32(StateB, 60, bit32.bxor(PB15, bit32.band(PB16, PB17)))
					buffer.writeu32(StateA, 64, bit32.bxor(PA16, bit32.bor(PA17, PA18)))
					buffer.writeu32(StateB, 64, bit32.bxor(PB16, bit32.bor(PB17, PB18)))
					buffer.writeu32(StateA, 68, bit32.bxor(PA17, bit32.bor(bit32.bnot(PA18), PA19)))
					buffer.writeu32(StateB, 68, bit32.bxor(PB17, bit32.bor(bit32.bnot(PB18), PB19)))
					buffer.writeu32(StateA, 72, bit32.bxor(bit32.bnot(PA18), bit32.band(PA19, PA15)))
					buffer.writeu32(StateB, 72, bit32.bxor(bit32.bnot(PB18), bit32.band(PB19, PB15)))
					buffer.writeu32(StateA, 76, bit32.bxor(PA19, bit32.bor(PA15, PA16)))
					buffer.writeu32(StateB, 76, bit32.bxor(PB19, bit32.bor(PB15, PB16)))
				end
				do
					local PA20, PB20
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 8), buffer.readu32(ScratchD, 8)), bit32.bxor(buffer.readu32(ScratchB, 8), buffer.readu32(ScratchD, 28))
						PA20, PB20 = bit32.lrotate(TA, 31), (bit32.lrotate(TB, 31))
					end
					local PA21, PB21
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 32), buffer.readu32(ScratchD, 12)), bit32.bxor(buffer.readu32(ScratchB, 32), buffer.readu32(ScratchD, 32))
						PA21, PB21 = bit32.lrotate(TB, 28), (bit32.lrotate(TA, 27))
					end
					local PA22, PB22
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 56), buffer.readu32(ScratchD, 16)), bit32.bxor(buffer.readu32(ScratchB, 56), buffer.readu32(ScratchD, 36))
						PA22, PB22 = bit32.lrotate(TB, 20), (bit32.lrotate(TA, 19))
					end
					local PA23, PB23
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 60), buffer.readu32(ScratchD, 0)), bit32.bxor(buffer.readu32(ScratchB, 60), buffer.readu32(ScratchD, 20))
						PA23, PB23 = bit32.lrotate(TB, 21), (bit32.lrotate(TA, 20))
					end
					local PA24, PB24
					do
						local TA, TB = bit32.bxor(buffer.readu32(ScratchA, 84), buffer.readu32(ScratchD, 4)), bit32.bxor(buffer.readu32(ScratchB, 84), buffer.readu32(ScratchD, 24))
						PA24, PB24 = bit32.lrotate(TA, 1), (bit32.lrotate(TB, 1))
					end
					buffer.writeu32(StateA, 80, bit32.bxor(PA20, bit32.band(bit32.bnot(PA21), PA22)))
					buffer.writeu32(StateB, 80, bit32.bxor(PB20, bit32.band(bit32.bnot(PB21), PB22)))
					buffer.writeu32(StateA, 84, bit32.bxor(bit32.bnot(PA21), bit32.bor(PA22, PA23)))
					buffer.writeu32(StateB, 84, bit32.bxor(bit32.bnot(PB21), bit32.bor(PB22, PB23)))
					buffer.writeu32(StateA, 88, bit32.bxor(PA22, bit32.band(PA23, PA24)))
					buffer.writeu32(StateB, 88, bit32.bxor(PB22, bit32.band(PB23, PB24)))
					buffer.writeu32(StateA, 92, bit32.bxor(PA23, bit32.bor(PA24, PA20)))
					buffer.writeu32(StateB, 92, bit32.bxor(PB23, bit32.bor(PB24, PB20)))
					buffer.writeu32(StateA, 96, bit32.bxor(PA24, bit32.band(PA20, PA21)))
					buffer.writeu32(StateB, 96, bit32.bxor(PB24, bit32.band(PB20, PB21)))
				end
			end
		end
	end
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
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

local function ExtractLanes21(StateA: buffer, StateB: buffer, Output: buffer, OutputOffset: number)
	do
		local A, B = buffer.readu32(StateA, 0), buffer.readu32(StateB, 0)
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
		buffer.writeu32(Output, OutputOffset, Lo)
		buffer.writeu32(Output, OutputOffset + 4, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 4), buffer.readu32(StateB, 4)
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
		buffer.writeu32(Output, OutputOffset + 8, Lo)
		buffer.writeu32(Output, OutputOffset + 12, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 8), buffer.readu32(StateB, 8)
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
		buffer.writeu32(Output, OutputOffset + 16, Lo)
		buffer.writeu32(Output, OutputOffset + 20, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 12), buffer.readu32(StateB, 12)
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
		buffer.writeu32(Output, OutputOffset + 24, Lo)
		buffer.writeu32(Output, OutputOffset + 28, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 16), buffer.readu32(StateB, 16)
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
		buffer.writeu32(Output, OutputOffset + 32, Lo)
		buffer.writeu32(Output, OutputOffset + 36, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 20), buffer.readu32(StateB, 20)
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
		buffer.writeu32(Output, OutputOffset + 40, Lo)
		buffer.writeu32(Output, OutputOffset + 44, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 24), buffer.readu32(StateB, 24)
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
		buffer.writeu32(Output, OutputOffset + 48, Lo)
		buffer.writeu32(Output, OutputOffset + 52, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 28), buffer.readu32(StateB, 28)
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
		buffer.writeu32(Output, OutputOffset + 56, Lo)
		buffer.writeu32(Output, OutputOffset + 60, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 32), buffer.readu32(StateB, 32)
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
		buffer.writeu32(Output, OutputOffset + 64, Lo)
		buffer.writeu32(Output, OutputOffset + 68, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 36), buffer.readu32(StateB, 36)
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
		buffer.writeu32(Output, OutputOffset + 72, Lo)
		buffer.writeu32(Output, OutputOffset + 76, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 40), buffer.readu32(StateB, 40)
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
		buffer.writeu32(Output, OutputOffset + 80, Lo)
		buffer.writeu32(Output, OutputOffset + 84, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 44), buffer.readu32(StateB, 44)
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
		buffer.writeu32(Output, OutputOffset + 88, Lo)
		buffer.writeu32(Output, OutputOffset + 92, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 48), buffer.readu32(StateB, 48)
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
		buffer.writeu32(Output, OutputOffset + 96, Lo)
		buffer.writeu32(Output, OutputOffset + 100, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 52), buffer.readu32(StateB, 52)
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
		buffer.writeu32(Output, OutputOffset + 104, Lo)
		buffer.writeu32(Output, OutputOffset + 108, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 56), buffer.readu32(StateB, 56)
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
		buffer.writeu32(Output, OutputOffset + 112, Lo)
		buffer.writeu32(Output, OutputOffset + 116, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 60), buffer.readu32(StateB, 60)
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
		buffer.writeu32(Output, OutputOffset + 120, Lo)
		buffer.writeu32(Output, OutputOffset + 124, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 64), buffer.readu32(StateB, 64)
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
		buffer.writeu32(Output, OutputOffset + 128, Lo)
		buffer.writeu32(Output, OutputOffset + 132, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 68), buffer.readu32(StateB, 68)
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
		buffer.writeu32(Output, OutputOffset + 136, Lo)
		buffer.writeu32(Output, OutputOffset + 140, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 72), buffer.readu32(StateB, 72)
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
		buffer.writeu32(Output, OutputOffset + 144, Lo)
		buffer.writeu32(Output, OutputOffset + 148, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 76), buffer.readu32(StateB, 76)
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
		buffer.writeu32(Output, OutputOffset + 152, Lo)
		buffer.writeu32(Output, OutputOffset + 156, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 80), buffer.readu32(StateB, 80)
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
		buffer.writeu32(Output, OutputOffset + 160, Lo)
		buffer.writeu32(Output, OutputOffset + 164, Hi)
	end
end

local function ExtractLanes17(StateA: buffer, StateB: buffer, Output: buffer, OutputOffset: number)
	do
		local A, B = buffer.readu32(StateA, 0), buffer.readu32(StateB, 0)
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
		buffer.writeu32(Output, OutputOffset, Lo)
		buffer.writeu32(Output, OutputOffset + 4, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 4), buffer.readu32(StateB, 4)
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
		buffer.writeu32(Output, OutputOffset + 8, Lo)
		buffer.writeu32(Output, OutputOffset + 12, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 8), buffer.readu32(StateB, 8)
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
		buffer.writeu32(Output, OutputOffset + 16, Lo)
		buffer.writeu32(Output, OutputOffset + 20, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 12), buffer.readu32(StateB, 12)
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
		buffer.writeu32(Output, OutputOffset + 24, Lo)
		buffer.writeu32(Output, OutputOffset + 28, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 16), buffer.readu32(StateB, 16)
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
		buffer.writeu32(Output, OutputOffset + 32, Lo)
		buffer.writeu32(Output, OutputOffset + 36, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 20), buffer.readu32(StateB, 20)
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
		buffer.writeu32(Output, OutputOffset + 40, Lo)
		buffer.writeu32(Output, OutputOffset + 44, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 24), buffer.readu32(StateB, 24)
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
		buffer.writeu32(Output, OutputOffset + 48, Lo)
		buffer.writeu32(Output, OutputOffset + 52, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 28), buffer.readu32(StateB, 28)
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
		buffer.writeu32(Output, OutputOffset + 56, Lo)
		buffer.writeu32(Output, OutputOffset + 60, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 32), buffer.readu32(StateB, 32)
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
		buffer.writeu32(Output, OutputOffset + 64, Lo)
		buffer.writeu32(Output, OutputOffset + 68, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 36), buffer.readu32(StateB, 36)
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
		buffer.writeu32(Output, OutputOffset + 72, Lo)
		buffer.writeu32(Output, OutputOffset + 76, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 40), buffer.readu32(StateB, 40)
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
		buffer.writeu32(Output, OutputOffset + 80, Lo)
		buffer.writeu32(Output, OutputOffset + 84, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 44), buffer.readu32(StateB, 44)
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
		buffer.writeu32(Output, OutputOffset + 88, Lo)
		buffer.writeu32(Output, OutputOffset + 92, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 48), buffer.readu32(StateB, 48)
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
		buffer.writeu32(Output, OutputOffset + 96, Lo)
		buffer.writeu32(Output, OutputOffset + 100, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 52), buffer.readu32(StateB, 52)
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
		buffer.writeu32(Output, OutputOffset + 104, Lo)
		buffer.writeu32(Output, OutputOffset + 108, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 56), buffer.readu32(StateB, 56)
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
		buffer.writeu32(Output, OutputOffset + 112, Lo)
		buffer.writeu32(Output, OutputOffset + 116, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 60), buffer.readu32(StateB, 60)
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
		buffer.writeu32(Output, OutputOffset + 120, Lo)
		buffer.writeu32(Output, OutputOffset + 124, Hi)
	end
	do
		local A, B = buffer.readu32(StateA, 64), buffer.readu32(StateB, 64)
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
		buffer.writeu32(Output, OutputOffset + 128, Lo)
		buffer.writeu32(Output, OutputOffset + 132, Hi)
	end
end

local function Extract(StateA: buffer, StateB: buffer, Output: buffer, OutputOffset: number, ByteCount: number)
	if ByteCount == 168 then
		ExtractLanes21(StateA, StateB, Output, OutputOffset)
		return
	elseif ByteCount == 136 then
		ExtractLanes17(StateA, StateB, Output, OutputOffset)
		return
	end

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
	if type(OutputBytes) ~= "number" or OutputBytes < 0 or OutputBytes ~= math.floor(OutputBytes) then
		error(`OutputBytes must be a non-negative integer, got {OutputBytes}`, 2)
	end

	local Buf = ProcessSponge(Message, 256, OutputBytes, 0x1F)
	return ToHex(Buf), Buf
end

function SHA3.SHAKE256(Message: buffer, OutputBytes: number): (string, buffer)
	if type(OutputBytes) ~= "number" or OutputBytes < 0 or OutputBytes ~= math.floor(OutputBytes) then
		error(`OutputBytes must be a non-negative integer, got {OutputBytes}`, 2)
	end

	local Buf = ProcessSponge(Message, 512, OutputBytes, 0x1F)
	return ToHex(Buf), Buf
end

function SHA3.ClearCaches()
	buffer.fill(STATE_A, 0, 0)
	buffer.fill(STATE_B, 0, 0)
	buffer.fill(TAIL_BLOCK, 0, 0)
	buffer.fill(SCRATCH_A, 0, 0)
	buffer.fill(SCRATCH_B, 0, 0)
	buffer.fill(SCRATCH_D, 0, 0)
end

return SHA3
