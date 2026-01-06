-- @ScriptType: ModuleScript
--[=[
	Cryptography library: BLAKE2b
	
	Return type: string
	Example usage:
		local Message = buffer.fromstring("Hello World")
		
		-- BLAKE2b-128 (128-bit output)
		local Result128 = BLAKE2b(Message, 16)
		
		-- BLAKE2b-256 (256-bit output)
		local Result256 = BLAKE2b(Message, 32)
		
		-- BLAKE2b-384 (384-bit output)
		local Result384 = BLAKE2b(Message, 48)
		
		-- BLAKE2b-512 (512-bit output, default)
		local Result512 = BLAKE2b(Message, 64)
		-- or simply: local Result512 = BLAKE2b(Message)
		
		-- With optional key
		local OptionalKey = buffer.fromstring("MyKey")
		local Result = BLAKE2b(Message, 64, OptionalKey)
--]=]

--!native
--!optimize 2
--!strict

local BLOCK_SIZE_BYTES = 128
local DEFAULT_OUTPUT_BYTES = 64

local BLAKE2B_MIN_OUTPUT_BYTES = 1
local BLAKE2B_MAX_OUTPUT_BYTES = 64
local BLAKE2B_MAX_KEY_BYTES = 64

local InitVectors = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1, 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179
}

local PERMUTATION_TABLE = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	15, 11, 5, 9, 10, 16, 14, 7, 2, 13, 1, 3, 12, 8, 6, 4,
	12, 9, 13, 1, 6, 3, 16, 14, 11, 15, 4, 7, 8, 2, 10, 5,
	8, 10, 4, 2, 14, 13, 12, 15, 3, 7, 6, 11, 5, 1, 16, 9,
	10, 1, 6, 8, 3, 5, 11, 16, 15, 2, 12, 13, 7, 9, 4, 14,
	3, 13, 7, 11, 1, 12, 9, 4, 5, 14, 8, 6, 16, 15, 2, 10,
	13, 6, 2, 16, 15, 14, 5, 11, 1, 8, 7, 4, 10, 3, 9, 12,
	14, 12, 8, 15, 13, 2, 4, 10, 6, 1, 16, 5, 9, 7, 3, 11,
	7, 16, 15, 10, 12, 4, 1, 9, 13, 3, 14, 8, 2, 5, 11, 6,
	11, 3, 9, 5, 8, 7, 2, 6, 16, 12, 10, 15, 4, 13, 14, 1,
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	15, 11, 5, 9, 10, 16, 14, 7, 2, 13, 1, 3, 12, 8, 6, 4
}

local WH9, WH10, WH11, WH12, WH13, WH14, WH15, WH16 = InitVectors[1], InitVectors[2], InitVectors[3], InitVectors[4], InitVectors[5], InitVectors[6], InitVectors[7], InitVectors[8]
local WL9, WL10, WL11, WL12, WL13, WL14, WL15, WL16 = InitVectors[9], InitVectors[10], InitVectors[11], InitVectors[12], InitVectors[13], InitVectors[14], InitVectors[15], InitVectors[16]

local function ExtractWordsFromBlock(InputBuffer: buffer, StartOffset: number, HighWords: {number}, LowWords: {number})
	for WordIdx = 1, 16 do
		local BytePos = StartOffset + (WordIdx - 1) * 8
		LowWords[WordIdx] = buffer.readu32(InputBuffer, BytePos)
		HighWords[WordIdx] = buffer.readu32(InputBuffer, BytePos + 4)
	end
end

local function ProcessCompressionRound(HighWords: {number}, LowWords: {number}, ByteCounter: number, FinalBlock: boolean, StateHigh: {number}, StateLow: {number})
	local WH1, WH2, WH3, WH4, WH5, WH6, WH7, WH8 = StateHigh[1], StateHigh[2], StateHigh[3], StateHigh[4], StateHigh[5], StateHigh[6], StateHigh[7], StateHigh[8]
	local WL1, WL2, WL3, WL4, WL5, WL6, WL7, WL8 = StateLow[1], StateLow[2], StateLow[3], StateLow[4], StateLow[5], StateLow[6], StateLow[7], StateLow[8]

	local WorkH9, WorkH10, WorkH11, WorkH12, WorkH13, WorkH14, WorkH15, WorkH16 = WH9, WH10, WH11, WH12, WH13, WH14, WH15, WH16
	local WorkL9, WorkL10, WorkL11, WorkL12, WorkL13, WorkL14, WorkL15, WorkL16 = WL9, WL10, WL11, WL12, WL13, WL14, WL15, WL16

	local XOR = bit32.bxor
	local ShiftLeft = bit32.lshift
	local ShiftRight = bit32.rshift
	local BOR = bit32.bor

	WorkH13 = XOR(WorkH13, ByteCounter // 0x100000000)
	WorkL13 = XOR(WorkL13, BOR(ByteCounter, 0))
	if FinalBlock then
		WorkH15 = bit32.bnot(WorkH15)
		WorkL15 = bit32.bnot(WorkL15)
	end

	local CarryBits, MsgHighX, MsgLowX, MsgHighY, MsgLowY = 0, 0, 0, 0, 0
	local Permutation = PERMUTATION_TABLE

	for RoundNum = 1, 12 do
		local ScheduleBase = (RoundNum - 1) * 16

		local S1, S2 = Permutation[ScheduleBase + 1], Permutation[ScheduleBase + 2]
		MsgHighX, MsgLowX = HighWords[S1], LowWords[S1]
		MsgHighY, MsgLowY = HighWords[S2], LowWords[S2]

		CarryBits = WL1 + WL5 + MsgLowX
		WH1 += WH5 + MsgHighX + CarryBits // 0x100000000
		WL1 = BOR(CarryBits, 0)

		CarryBits = WorkH13
		WorkH13 = XOR(WorkL13, WL1)
		WorkL13 = XOR(CarryBits, WH1)

		CarryBits = WorkL9 + WorkL13
		WorkH9 += WorkH13 + CarryBits // 0x100000000
		WorkL9 = BOR(CarryBits, 0)

		CarryBits = WH5
		WH5 = XOR(ShiftRight(WH5, 24), ShiftLeft(WL5, 8), ShiftRight(WorkH9, 24), ShiftLeft(WorkL9, 8))
		WL5 = XOR(ShiftRight(WL5, 24), ShiftLeft(CarryBits, 8), ShiftRight(WorkL9, 24), ShiftLeft(WorkH9, 8))

		CarryBits = WL1 + WL5 + MsgLowY
		WH1 += WH5 + MsgHighY + CarryBits // 0x100000000
		WL1 = BOR(CarryBits, 0)

		CarryBits = WorkH13
		WorkH13 = XOR(ShiftRight(WorkH13, 16), ShiftLeft(WorkL13, 16), ShiftRight(WH1, 16), ShiftLeft(WL1, 16))
		WorkL13 = XOR(ShiftRight(WorkL13, 16), ShiftLeft(CarryBits, 16), ShiftRight(WL1, 16), ShiftLeft(WH1, 16))

		CarryBits = WorkL9 + WorkL13
		WorkH9 += WorkH13 + CarryBits // 0x100000000
		WorkL9 = BOR(CarryBits, 0)

		CarryBits = WH5
		WH5 = XOR(ShiftLeft(WH5, 1), ShiftRight(WL5, 31), ShiftLeft(WorkH9, 1), ShiftRight(WorkL9, 31))
		WL5 = XOR(ShiftLeft(WL5, 1), ShiftRight(CarryBits, 31), ShiftLeft(WorkL9, 1), ShiftRight(WorkH9, 31))

		local S3, S4 = Permutation[ScheduleBase + 3], Permutation[ScheduleBase + 4]
		MsgHighX, MsgLowX = HighWords[S3], LowWords[S3]
		MsgHighY, MsgLowY = HighWords[S4], LowWords[S4]

		CarryBits = WL2 + WL6 + MsgLowX
		WH2 += WH6 + MsgHighX + CarryBits // 0x100000000
		WL2 = BOR(CarryBits, 0)

		CarryBits = WorkH14
		WorkH14 = XOR(WorkL14, WL2)
		WorkL14 = XOR(CarryBits, WH2)

		CarryBits = WorkL10 + WorkL14
		WorkH10 += WorkH14 + CarryBits // 0x100000000
		WorkL10 = BOR(CarryBits, 0)

		CarryBits = WH6
		WH6 = XOR(ShiftRight(WH6, 24), ShiftLeft(WL6, 8), ShiftRight(WorkH10, 24), ShiftLeft(WorkL10, 8))
		WL6 = XOR(ShiftRight(WL6, 24), ShiftLeft(CarryBits, 8), ShiftRight(WorkL10, 24), ShiftLeft(WorkH10, 8))

		CarryBits = WL2 + WL6 + MsgLowY
		WH2 += WH6 + MsgHighY + CarryBits // 0x100000000
		WL2 = BOR(CarryBits, 0)

		CarryBits = WorkH14
		WorkH14 = XOR(ShiftRight(WorkH14, 16), ShiftLeft(WorkL14, 16), ShiftRight(WH2, 16), ShiftLeft(WL2, 16))
		WorkL14 = XOR(ShiftRight(WorkL14, 16), ShiftLeft(CarryBits, 16), ShiftRight(WL2, 16), ShiftLeft(WH2, 16))

		CarryBits = WorkL10 + WorkL14
		WorkH10 += WorkH14 + CarryBits // 0x100000000
		WorkL10 = BOR(CarryBits, 0)

		CarryBits = WH6
		WH6 = XOR(ShiftLeft(WH6, 1), ShiftRight(WL6, 31), ShiftLeft(WorkH10, 1), ShiftRight(WorkL10, 31))
		WL6 = XOR(ShiftLeft(WL6, 1), ShiftRight(CarryBits, 31), ShiftLeft(WorkL10, 1), ShiftRight(WorkH10, 31))

		local S5, S6 = Permutation[ScheduleBase + 5], Permutation[ScheduleBase + 6]
		MsgHighX, MsgLowX = HighWords[S5], LowWords[S5]
		MsgHighY, MsgLowY = HighWords[S6], LowWords[S6]

		CarryBits = WL3 + WL7 + MsgLowX
		WH3 += WH7 + MsgHighX + CarryBits // 0x100000000
		WL3 = BOR(CarryBits, 0)

		CarryBits = WorkH15
		WorkH15 = XOR(WorkL15, WL3)
		WorkL15 = XOR(CarryBits, WH3)

		CarryBits = WorkL11 + WorkL15
		WorkH11 += WorkH15 + CarryBits // 0x100000000
		WorkL11 = BOR(CarryBits, 0)

		CarryBits = WH7
		WH7 = XOR(ShiftRight(WH7, 24), ShiftLeft(WL7, 8), ShiftRight(WorkH11, 24), ShiftLeft(WorkL11, 8))
		WL7 = XOR(ShiftRight(WL7, 24), ShiftLeft(CarryBits, 8), ShiftRight(WorkL11, 24), ShiftLeft(WorkH11, 8))

		CarryBits = WL3 + WL7 + MsgLowY
		WH3 += WH7 + MsgHighY + CarryBits // 0x100000000
		WL3 = BOR(CarryBits, 0)

		CarryBits = WorkH15
		WorkH15 = XOR(ShiftRight(WorkH15, 16), ShiftLeft(WorkL15, 16), ShiftRight(WH3, 16), ShiftLeft(WL3, 16))
		WorkL15 = XOR(ShiftRight(WorkL15, 16), ShiftLeft(CarryBits, 16), ShiftRight(WL3, 16), ShiftLeft(WH3, 16))

		CarryBits = WorkL11 + WorkL15
		WorkH11 += WorkH15 + CarryBits // 0x100000000
		WorkL11 = BOR(CarryBits, 0)

		CarryBits = WH7
		WH7 = XOR(ShiftLeft(WH7, 1), ShiftRight(WL7, 31), ShiftLeft(WorkH11, 1), ShiftRight(WorkL11, 31))
		WL7 = XOR(ShiftLeft(WL7, 1), ShiftRight(CarryBits, 31), ShiftLeft(WorkL11, 1), ShiftRight(WorkH11, 31))

		local S7, S8 = Permutation[ScheduleBase + 7], Permutation[ScheduleBase + 8]
		MsgHighX, MsgLowX = HighWords[S7], LowWords[S7]
		MsgHighY, MsgLowY = HighWords[S8], LowWords[S8]

		CarryBits = WL4 + WL8 + MsgLowX
		WH4 += WH8 + MsgHighX + CarryBits // 0x100000000
		WL4 = BOR(CarryBits, 0)

		CarryBits = WorkH16
		WorkH16 = XOR(WorkL16, WL4)
		WorkL16 = XOR(CarryBits, WH4)

		CarryBits = WorkL12 + WorkL16
		WorkH12 += WorkH16 + CarryBits // 0x100000000
		WorkL12 = BOR(CarryBits, 0)

		CarryBits = WH8
		WH8 = XOR(ShiftRight(WH8, 24), ShiftLeft(WL8, 8), ShiftRight(WorkH12, 24), ShiftLeft(WorkL12, 8))
		WL8 = XOR(ShiftRight(WL8, 24), ShiftLeft(CarryBits, 8), ShiftRight(WorkL12, 24), ShiftLeft(WorkH12, 8))

		CarryBits = WL4 + WL8 + MsgLowY
		WH4 += WH8 + MsgHighY + CarryBits // 0x100000000
		WL4 = BOR(CarryBits, 0)

		CarryBits = WorkH16
		WorkH16 = XOR(ShiftRight(WorkH16, 16), ShiftLeft(WorkL16, 16), ShiftRight(WH4, 16), ShiftLeft(WL4, 16))
		WorkL16 = XOR(ShiftRight(WorkL16, 16), ShiftLeft(CarryBits, 16), ShiftRight(WL4, 16), ShiftLeft(WH4, 16))

		CarryBits = WorkL12 + WorkL16
		WorkH12 += WorkH16 + CarryBits // 0x100000000
		WorkL12 = BOR(CarryBits, 0)

		CarryBits = WH8
		WH8 = XOR(ShiftLeft(WH8, 1), ShiftRight(WL8, 31), ShiftLeft(WorkH12, 1), ShiftRight(WorkL12, 31))
		WL8 = XOR(ShiftLeft(WL8, 1), ShiftRight(CarryBits, 31), ShiftLeft(WorkL12, 1), ShiftRight(WorkH12, 31))

		local S9, S10 = Permutation[ScheduleBase + 9], Permutation[ScheduleBase + 10]
		MsgHighX, MsgLowX = HighWords[S9], LowWords[S9]
		MsgHighY, MsgLowY = HighWords[S10], LowWords[S10]

		CarryBits = WL1 + WL6 + MsgLowX
		WH1 += WH6 + MsgHighX + CarryBits // 0x100000000
		WL1 = BOR(CarryBits, 0)

		CarryBits = WorkH16
		WorkH16 = XOR(WorkL16, WL1)
		WorkL16 = XOR(CarryBits, WH1)

		CarryBits = WorkL11 + WorkL16
		WorkH11 += WorkH16 + CarryBits // 0x100000000
		WorkL11 = BOR(CarryBits, 0)

		CarryBits = WH6
		WH6 = XOR(ShiftRight(WH6, 24), ShiftLeft(WL6, 8), ShiftRight(WorkH11, 24), ShiftLeft(WorkL11, 8))
		WL6 = XOR(ShiftRight(WL6, 24), ShiftLeft(CarryBits, 8), ShiftRight(WorkL11, 24), ShiftLeft(WorkH11, 8))

		CarryBits = WL1 + WL6 + MsgLowY
		WH1 += WH6 + MsgHighY + CarryBits // 0x100000000
		WL1 = BOR(CarryBits, 0)

		CarryBits = WorkH16
		WorkH16 = XOR(ShiftRight(WorkH16, 16), ShiftLeft(WorkL16, 16), ShiftRight(WH1, 16), ShiftLeft(WL1, 16))
		WorkL16 = XOR(ShiftRight(WorkL16, 16), ShiftLeft(CarryBits, 16), ShiftRight(WL1, 16), ShiftLeft(WH1, 16))

		CarryBits = WorkL11 + WorkL16
		WorkH11 += WorkH16 + CarryBits // 0x100000000
		WorkL11 = BOR(CarryBits, 0)

		CarryBits = WH6
		WH6 = XOR(ShiftLeft(WH6, 1), ShiftRight(WL6, 31), ShiftLeft(WorkH11, 1), ShiftRight(WorkL11, 31))
		WL6 = XOR(ShiftLeft(WL6, 1), ShiftRight(CarryBits, 31), ShiftLeft(WorkL11, 1), ShiftRight(WorkH11, 31))

		local S11, S12 = Permutation[ScheduleBase + 11], Permutation[ScheduleBase + 12]
		MsgHighX, MsgLowX = HighWords[S11], LowWords[S11]
		MsgHighY, MsgLowY = HighWords[S12], LowWords[S12]

		CarryBits = WL2 + WL7 + MsgLowX
		WH2 += WH7 + MsgHighX + CarryBits // 0x100000000
		WL2 = BOR(CarryBits, 0)

		CarryBits = WorkH13
		WorkH13 = XOR(WorkL13, WL2)
		WorkL13 = XOR(CarryBits, WH2)

		CarryBits = WorkL12 + WorkL13
		WorkH12 += WorkH13 + CarryBits // 0x100000000
		WorkL12 = BOR(CarryBits, 0)

		CarryBits = WH7
		WH7 = XOR(ShiftRight(WH7, 24), ShiftLeft(WL7, 8), ShiftRight(WorkH12, 24), ShiftLeft(WorkL12, 8))
		WL7 = XOR(ShiftRight(WL7, 24), ShiftLeft(CarryBits, 8), ShiftRight(WorkL12, 24), ShiftLeft(WorkH12, 8))

		CarryBits = WL2 + WL7 + MsgLowY
		WH2 += WH7 + MsgHighY + CarryBits // 0x100000000
		WL2 = BOR(CarryBits, 0)

		CarryBits = WorkH13
		WorkH13 = XOR(ShiftRight(WorkH13, 16), ShiftLeft(WorkL13, 16), ShiftRight(WH2, 16), ShiftLeft(WL2, 16))
		WorkL13 = XOR(ShiftRight(WorkL13, 16), ShiftLeft(CarryBits, 16), ShiftRight(WL2, 16), ShiftLeft(WH2, 16))

		CarryBits = WorkL12 + WorkL13
		WorkH12 += WorkH13 + CarryBits // 0x100000000
		WorkL12 = BOR(CarryBits, 0)

		CarryBits = WH7
		WH7 = XOR(ShiftLeft(WH7, 1), ShiftRight(WL7, 31), ShiftLeft(WorkH12, 1), ShiftRight(WorkL12, 31))
		WL7 = XOR(ShiftLeft(WL7, 1), ShiftRight(CarryBits, 31), ShiftLeft(WorkL12, 1), ShiftRight(WorkH12, 31))

		local S13, S14 = Permutation[ScheduleBase + 13], Permutation[ScheduleBase + 14]
		MsgHighX, MsgLowX = HighWords[S13], LowWords[S13]
		MsgHighY, MsgLowY = HighWords[S14], LowWords[S14]

		CarryBits = WL3 + WL8 + MsgLowX
		WH3 += WH8 + MsgHighX + CarryBits // 0x100000000
		WL3 = BOR(CarryBits, 0)

		CarryBits = WorkH14
		WorkH14 = XOR(WorkL14, WL3)
		WorkL14 = XOR(CarryBits, WH3)

		CarryBits = WorkL9 + WorkL14
		WorkH9 += WorkH14 + CarryBits // 0x100000000
		WorkL9 = BOR(CarryBits, 0)

		CarryBits = WH8
		WH8 = XOR(ShiftRight(WH8, 24), ShiftLeft(WL8, 8), ShiftRight(WorkH9, 24), ShiftLeft(WorkL9, 8))
		WL8 = XOR(ShiftRight(WL8, 24), ShiftLeft(CarryBits, 8), ShiftRight(WorkL9, 24), ShiftLeft(WorkH9, 8))

		CarryBits = WL3 + WL8 + MsgLowY
		WH3 += WH8 + MsgHighY + CarryBits // 0x100000000
		WL3 = BOR(CarryBits, 0)

		CarryBits = WorkH14
		WorkH14 = XOR(ShiftRight(WorkH14, 16), ShiftLeft(WorkL14, 16), ShiftRight(WH3, 16), ShiftLeft(WL3, 16))
		WorkL14 = XOR(ShiftRight(WorkL14, 16), ShiftLeft(CarryBits, 16), ShiftRight(WL3, 16), ShiftLeft(WH3, 16))

		CarryBits = WorkL9 + WorkL14
		WorkH9 += WorkH14 + CarryBits // 0x100000000
		WorkL9 = BOR(CarryBits, 0)

		CarryBits = WH8
		WH8 = XOR(ShiftLeft(WH8, 1), ShiftRight(WL8, 31), ShiftLeft(WorkH9, 1), ShiftRight(WorkL9, 31))
		WL8 = XOR(ShiftLeft(WL8, 1), ShiftRight(CarryBits, 31), ShiftLeft(WorkL9, 1), ShiftRight(WorkH9, 31))

		local S15, S16 = Permutation[ScheduleBase + 15], Permutation[ScheduleBase + 16]
		MsgHighX, MsgLowX = HighWords[S15], LowWords[S15]
		MsgHighY, MsgLowY = HighWords[S16], LowWords[S16]

		CarryBits = WL4 + WL5 + MsgLowX
		WH4 += WH5 + MsgHighX + CarryBits // 0x100000000
		WL4 = BOR(CarryBits, 0)

		CarryBits = WorkH15
		WorkH15 = XOR(WorkL15, WL4)
		WorkL15 = XOR(CarryBits, WH4)

		CarryBits = WorkL10 + WorkL15
		WorkH10 += WorkH15 + CarryBits // 0x100000000
		WorkL10 = BOR(CarryBits, 0)

		CarryBits = WH5
		WH5 = XOR(ShiftRight(WH5, 24), ShiftLeft(WL5, 8), ShiftRight(WorkH10, 24), ShiftLeft(WorkL10, 8))
		WL5 = XOR(ShiftRight(WL5, 24), ShiftLeft(CarryBits, 8), ShiftRight(WorkL10, 24), ShiftLeft(WorkH10, 8))

		CarryBits = WL4 + WL5 + MsgLowY
		WH4 += WH5 + MsgHighY + CarryBits // 0x100000000
		WL4 = BOR(CarryBits, 0)

		CarryBits = WorkH15
		WorkH15 = XOR(ShiftRight(WorkH15, 16), ShiftLeft(WorkL15, 16), ShiftRight(WH4, 16), ShiftLeft(WL4, 16))
		WorkL15 = XOR(ShiftRight(WorkL15, 16), ShiftLeft(CarryBits, 16), ShiftRight(WL4, 16), ShiftLeft(WH4, 16))

		CarryBits = WorkL10 + WorkL15
		WorkH10 += WorkH15 + CarryBits // 0x100000000
		WorkL10 = BOR(CarryBits, 0)

		CarryBits = WH5
		WH5 = XOR(ShiftLeft(WH5, 1), ShiftRight(WL5, 31), ShiftLeft(WorkH10, 1), ShiftRight(WorkL10, 31))
		WL5 = XOR(ShiftLeft(WL5, 1), ShiftRight(CarryBits, 31), ShiftLeft(WorkL10, 1), ShiftRight(WorkH10, 31))
	end

	StateHigh[1] = XOR(StateHigh[1], WH1, WorkH9)
	StateLow[1] = XOR(StateLow[1], WL1, WorkL9)
	StateHigh[2] = XOR(StateHigh[2], WH2, WorkH10)
	StateLow[2] = XOR(StateLow[2], WL2, WorkL10)
	StateHigh[3] = XOR(StateHigh[3], WH3, WorkH11)
	StateLow[3] = XOR(StateLow[3], WL3, WorkL11)
	StateHigh[4] = XOR(StateHigh[4], WH4, WorkH12)
	StateLow[4] = XOR(StateLow[4], WL4, WorkL12)
	StateHigh[5] = XOR(StateHigh[5], WH5, WorkH13)
	StateLow[5] = XOR(StateLow[5], WL5, WorkL13)
	StateHigh[6] = XOR(StateHigh[6], WH6, WorkH14)
	StateLow[6] = XOR(StateLow[6], WL6, WorkL14)
	StateHigh[7] = XOR(StateHigh[7], WH7, WorkH15)
	StateLow[7] = XOR(StateLow[7], WL7, WorkL15)
	StateHigh[8] = XOR(StateHigh[8], WH8, WorkH16)
	StateLow[8] = XOR(StateLow[8], WL8, WorkL16)
end

local function HashDigest(InputData: buffer, OutputLength: number, KeyData: buffer?): (string, buffer)
	local KeyLength = KeyData and buffer.len(KeyData) or 0
	local DataLength = buffer.len(InputData)

	local StateHigh = { WH9, WH10, WH11, WH12, WH13, WH14, WH15, WH16 }
	local StateLow = { WL9, WL10, WL11, WL12, WL13, WL14, WL15, WL16 }

	StateLow[1] = bit32.bxor(StateLow[1], 0x01010000, bit32.lshift(KeyLength, 8), OutputLength)

	local BlockHigh = table.create(16) :: {number}
	local BlockLow = table.create(16) :: {number}
	local ProcessedBytes = KeyLength > 0 and 128 or 0

	if KeyLength > 0 and KeyData then
		local KeyPadding = buffer.create(BLOCK_SIZE_BYTES)
		buffer.copy(KeyPadding, 0, KeyData)
		ExtractWordsFromBlock(KeyPadding, 0, BlockHigh, BlockLow)
		ProcessCompressionRound(BlockHigh, BlockLow, ProcessedBytes, DataLength == 0, StateHigh, StateLow)
	end

	local RemainingBytes = DataLength % BLOCK_SIZE_BYTES
	local FinalBlockSize = RemainingBytes == 0 and BLOCK_SIZE_BYTES or RemainingBytes

	for BlockStart = 0, DataLength - FinalBlockSize - 1, BLOCK_SIZE_BYTES do
		ExtractWordsFromBlock(InputData, BlockStart, BlockHigh, BlockLow)
		ProcessedBytes += BLOCK_SIZE_BYTES
		ProcessCompressionRound(BlockHigh, BlockLow, ProcessedBytes, false, StateHigh, StateLow)
	end

	if KeyLength == 0 or DataLength > 0 then
		local PaddedBlock = buffer.create(BLOCK_SIZE_BYTES)
		local CopyBytes = math.min(FinalBlockSize, DataLength)
		local CopyStart = math.max(0, DataLength - FinalBlockSize)
		if CopyBytes > 0 then
			buffer.copy(PaddedBlock, 0, InputData, CopyStart, CopyBytes)
		end

		ExtractWordsFromBlock(PaddedBlock, 0, BlockHigh, BlockLow)
		ProcessCompressionRound(BlockHigh, BlockLow, ProcessedBytes + CopyBytes, true, StateHigh, StateLow)
	end

	local Digest = buffer.create(OutputLength)
	local Offset = 0

	for Index = 1, 8 do
		if Offset + 4 <= OutputLength then
			buffer.writeu32(Digest, Offset, StateLow[Index])
			Offset += 4
		end

		if Offset + 4 <= OutputLength then
			buffer.writeu32(Digest, Offset, StateHigh[Index])
			Offset += 4
		end

		if Offset >= OutputLength then
			break
		end
	end

	local FinalDigest = string.format(
		"%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		bit32.byteswap(StateLow[1]), bit32.byteswap(StateHigh[1]),
		bit32.byteswap(StateLow[2]), bit32.byteswap(StateHigh[2]),
		bit32.byteswap(StateLow[3]), bit32.byteswap(StateHigh[3]),
		bit32.byteswap(StateLow[4]), bit32.byteswap(StateHigh[4]),
		bit32.byteswap(StateLow[5]), bit32.byteswap(StateHigh[5]),
		bit32.byteswap(StateLow[6]), bit32.byteswap(StateHigh[6]),
		bit32.byteswap(StateLow[7]), bit32.byteswap(StateHigh[7]),
		bit32.byteswap(StateLow[8]), bit32.byteswap(StateHigh[8])
	)

	return string.sub(FinalDigest, 1, OutputLength * 2), Digest
end

local function BLAKE2b(InputData: buffer, OutputLength: number?, KeyData: buffer?): (string, buffer)
	if InputData == nil then
		error("InputData cannot be nil", 2)
	end

	if typeof(InputData) ~= "buffer" then
		error(`InputData must be a buffer, got {typeof(InputData)}`, 2)
	end

	if OutputLength then
		if typeof(OutputLength) ~= "number" then
			error(`OutputLength must be a number, got {typeof(OutputLength)}`, 2)
		end

		if OutputLength ~= math.floor(OutputLength) then
			error(`OutputLength must be an integer, got {OutputLength}`, 2)
		end

		if OutputLength < BLAKE2B_MIN_OUTPUT_BYTES or OutputLength > BLAKE2B_MAX_OUTPUT_BYTES then
			error(`OutputLength must be between {BLAKE2B_MIN_OUTPUT_BYTES} and {BLAKE2B_MAX_OUTPUT_BYTES} bytes, got {OutputLength} bytes`, 2)
		end
	end

	if KeyData then
		if typeof(KeyData) ~= "buffer" then
			error(`KeyData must be a buffer, got {typeof(KeyData)}`, 2)
		end

		local KeyLength = buffer.len(KeyData)
		if KeyLength == 0 then
			error("KeyData cannot be empty", 2)
		end

		if KeyLength > BLAKE2B_MAX_KEY_BYTES then
			error(`KeyData must be at most {BLAKE2B_MAX_KEY_BYTES} bytes long, got {KeyLength} bytes`, 2)
		end
	end

	return HashDigest(InputData, OutputLength or DEFAULT_OUTPUT_BYTES, KeyData)
end

return BLAKE2b