--[=[
	Cryptography library: Base64

	Return type: buffer
	Example usage:
		local Input = buffer.fromstring("Hello World")
		local Encoded = Base64.Encode(Input)
		local Decoded = Base64.Decode(Encoded)
--]=]

--!strict
--!optimize 2
--!native

local PADDING_CHARACTER = 61
local ALPHABET_BYTES = buffer.create(64) do
	local Characters = {
		65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
		81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
		97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
		113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
		48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
		43, 47
	}

	for Index = 1, 64 do
		buffer.writeu8(ALPHABET_BYTES, Index - 1, Characters[Index])
	end
end

local INVALID_SEXTET = 255

local DECODE_TET = buffer.create(256) do
	buffer.fill(DECODE_TET, 0, INVALID_SEXTET)
	for Index = 1, 64 do
		buffer.writeu8(DECODE_TET, buffer.readu8(ALPHABET_BYTES, Index - 1), Index - 1)
	end
end

local PAIR_A_BYTE1_HIGH = buffer.create(4096)
local PAIR_B_BYTE1_LOW = buffer.create(4096)

local PAIR_A_BYTE0, PAIR_B_BYTE2 = buffer.create(4096), buffer.create(4096) do
	for PairA = 0, 4095 do
		local Sextet0 = PairA // 64
		local Sextet1 = PairA % 64
		buffer.writeu8(PAIR_A_BYTE0, PairA, Sextet0 * 4 + (Sextet1 // 16))
		buffer.writeu8(PAIR_A_BYTE1_HIGH, PairA, (Sextet1 % 16) * 16)
	end

	for PairB = 0, 4095 do
		local Sextet2 = PairB // 64
		local Sextet3 = PairB % 64
		buffer.writeu8(PAIR_B_BYTE1_LOW, PairB, Sextet2 // 4)
		buffer.writeu8(PAIR_B_BYTE2, PairB, (Sextet2 % 4) * 64 + Sextet3)
	end
end

local DECODE_HIGH, DECODE_LOW = buffer.create(262144), buffer.create(262144) do
	for Char0 = 0, 255 do
		local Sextet0 = buffer.readu8(DECODE_TET, Char0)
		for Char1 = 0, 255 do
			local Sextet1 = buffer.readu8(DECODE_TET, Char1)
			local Key = (Char0 + Char1 * 256) * 4
			if Sextet0 < 64 and Sextet1 < 64 then
				buffer.writeu32(DECODE_HIGH, Key, Sextet0 * 4 + Sextet1 // 16 + (Sextet1 % 16) * 16 * 256)
				buffer.writeu32(DECODE_LOW, Key, Sextet0 // 4 * 256 + ((Sextet0 % 4) * 64 + Sextet1) * 65536)
			else
				buffer.writeu32(DECODE_HIGH, Key, 0x80000000)
				buffer.writeu32(DECODE_LOW, Key, 0x80000000)
			end
		end
	end
end

local ENCODE_12 = buffer.create(8192) do
	for Pair = 0, 4095 do
		buffer.writeu16(ENCODE_12, Pair * 2,
			buffer.readu8(ALPHABET_BYTES, Pair // 64) + buffer.readu8(ALPHABET_BYTES, Pair % 64) * 256)
	end
end

local function Encode(Input: buffer): buffer
	local InputLength = buffer.len(Input)
	if InputLength == 0 then
		return buffer.create(0)
	end

	local Output = buffer.create(((InputLength + 2) // 3) * 4)
	local Table = ENCODE_12
	local AlphabetBytes = ALPHABET_BYTES
	local InputIndex = 0
	local OutputIndex = 0

	local UnrollStop = InputLength - 97
	while InputIndex <= UnrollStop do
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 93))
			buffer.writeu16(Output, OutputIndex + 126, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 124, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 90))
			buffer.writeu16(Output, OutputIndex + 122, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 120, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 87))
			buffer.writeu16(Output, OutputIndex + 118, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 116, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 84))
			buffer.writeu16(Output, OutputIndex + 114, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 112, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 81))
			buffer.writeu16(Output, OutputIndex + 110, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 108, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 78))
			buffer.writeu16(Output, OutputIndex + 106, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 104, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 75))
			buffer.writeu16(Output, OutputIndex + 102, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 100, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 72))
			buffer.writeu16(Output, OutputIndex + 98, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 96, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 69))
			buffer.writeu16(Output, OutputIndex + 94, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 92, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 66))
			buffer.writeu16(Output, OutputIndex + 90, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 88, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 63))
			buffer.writeu16(Output, OutputIndex + 86, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 84, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 60))
			buffer.writeu16(Output, OutputIndex + 82, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 80, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 57))
			buffer.writeu16(Output, OutputIndex + 78, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 76, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 54))
			buffer.writeu16(Output, OutputIndex + 74, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 72, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 51))
			buffer.writeu16(Output, OutputIndex + 70, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 68, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 48))
			buffer.writeu16(Output, OutputIndex + 66, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 64, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 45))
			buffer.writeu16(Output, OutputIndex + 62, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 60, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 42))
			buffer.writeu16(Output, OutputIndex + 58, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 56, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 39))
			buffer.writeu16(Output, OutputIndex + 54, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 52, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 36))
			buffer.writeu16(Output, OutputIndex + 50, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 48, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 33))
			buffer.writeu16(Output, OutputIndex + 46, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 44, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 30))
			buffer.writeu16(Output, OutputIndex + 42, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 40, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 27))
			buffer.writeu16(Output, OutputIndex + 38, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 36, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 24))
			buffer.writeu16(Output, OutputIndex + 34, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 32, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 21))
			buffer.writeu16(Output, OutputIndex + 30, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 28, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 18))
			buffer.writeu16(Output, OutputIndex + 26, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 24, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 15))
			buffer.writeu16(Output, OutputIndex + 22, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 20, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 12))
			buffer.writeu16(Output, OutputIndex + 18, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 16, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 9))
			buffer.writeu16(Output, OutputIndex + 14, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 12, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 6))
			buffer.writeu16(Output, OutputIndex + 10, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 8, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 3))
			buffer.writeu16(Output, OutputIndex + 6, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 4, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 0))
			buffer.writeu16(Output, OutputIndex + 2, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end

		InputIndex += 96
		OutputIndex += 128
	end

	while InputIndex <= InputLength - 13 do
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 9))
			buffer.writeu16(Output, OutputIndex + 14, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 12, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 6))
			buffer.writeu16(Output, OutputIndex + 10, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 8, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 3))
			buffer.writeu16(Output, OutputIndex + 6, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex + 4, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 0))
			buffer.writeu16(Output, OutputIndex + 2, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end

		InputIndex += 12
		OutputIndex += 16
	end

	while InputIndex <= InputLength - 4 do
		do
			local S = bit32.byteswap(buffer.readu32(Input, InputIndex + 0))
			buffer.writeu16(Output, OutputIndex + 2, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
			buffer.writeu16(Output, OutputIndex, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		end

		InputIndex += 3
		OutputIndex += 4
	end

	local Remainder = InputLength - InputIndex
	if Remainder == 3 then
		local S = bit32.bor(
			bit32.lshift(buffer.readu8(Input, InputIndex), 24),
			bit32.lshift(buffer.readu8(Input, InputIndex + 1), 16),
			bit32.lshift(buffer.readu8(Input, InputIndex + 2), 8))
		buffer.writeu16(Output, OutputIndex + 2, buffer.readu16(Table, bit32.band(bit32.rshift(S, 7), 0x1ffe)))
		buffer.writeu16(Output, OutputIndex, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
	elseif Remainder == 2 then
		local Byte0 = buffer.readu8(Input, InputIndex)
		local Byte1 = buffer.readu8(Input, InputIndex + 1)
		local S = bit32.bor(bit32.lshift(Byte0, 24), bit32.lshift(Byte1, 16))
		buffer.writeu16(Output, OutputIndex, buffer.readu16(Table, bit32.band(bit32.rshift(S, 19), 0x1ffe)))
		buffer.writeu8(Output, OutputIndex + 2, buffer.readu8(AlphabetBytes, (Byte1 % 16) * 4))
		buffer.writeu8(Output, OutputIndex + 3, PADDING_CHARACTER)
	elseif Remainder == 1 then
		local Byte0 = buffer.readu8(Input, InputIndex)
		buffer.writeu8(Output, OutputIndex, buffer.readu8(AlphabetBytes, Byte0 // 4))
		buffer.writeu8(Output, OutputIndex + 1, buffer.readu8(AlphabetBytes, (Byte0 % 4) * 16))
		buffer.writeu8(Output, OutputIndex + 2, PADDING_CHARACTER)
		buffer.writeu8(Output, OutputIndex + 3, PADDING_CHARACTER)
	end

	return Output
end

local function Decode(Input: buffer): buffer
	local InputLength = buffer.len(Input)
	if InputLength == 0 then
		return buffer.create(0)
	end

	if InputLength % 4 ~= 0 then
		error(`Base64 input length must be a multiple of 4, got {InputLength} bytes`, 2)
	end

	local Padding = 0
	if buffer.readu8(Input, InputLength - 1) == PADDING_CHARACTER then
		Padding = 1
		if buffer.readu8(Input, InputLength - 2) == PADDING_CHARACTER then
			Padding = 2
		end
	end

	local Output = buffer.create((InputLength // 4) * 3 - Padding)
	local InputIndex = 0
	local OutputIndex = 0
	local BodyEnd = InputLength - 4
	local UnrollStop = BodyEnd - 64

	local High = DECODE_HIGH
	local Low = DECODE_LOW
	local Pair0 = PAIR_A_BYTE0
	local PairAHigh = PAIR_A_BYTE1_HIGH
	local PairBLow = PAIR_B_BYTE1_LOW
	local Pair2 = PAIR_B_BYTE2
	local Dtet = DECODE_TET
	local Invalid = 0

	while InputIndex <= UnrollStop do
		do
			local Word = buffer.readu32(Input, InputIndex + 0)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 0, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 4)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 3, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 8)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 6, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 12)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 9, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 16)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 12, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 20)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 15, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 24)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 18, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 28)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 21, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 32)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 24, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 36)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 27, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 40)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 30, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 44)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 33, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 48)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 36, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 52)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 39, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 56)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 42, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 60)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 45, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end

		InputIndex += 64
		OutputIndex += 48
	end

	while InputIndex <= BodyEnd - 8 do
		do
			local Word = buffer.readu32(Input, InputIndex + 0)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 0, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end
		do
			local Word = buffer.readu32(Input, InputIndex + 4)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 3, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end

		InputIndex += 8
		OutputIndex += 6
	end

	while InputIndex <= BodyEnd - 4 do
		do
			local Word = buffer.readu32(Input, InputIndex + 0)
			local Bytes = bit32.bor(
				buffer.readu32(High, bit32.lshift(bit32.band(Word, 0xffff), 2)),
				buffer.readu32(Low, bit32.band(bit32.rshift(Word, 14), 0x3fffc)))
			buffer.writeu32(Output, OutputIndex + 0, Bytes)
			Invalid = bit32.bor(Invalid, Bytes)
		end

		InputIndex += 4
		OutputIndex += 3
	end

	local Char0 = buffer.readu8(Input, InputIndex)
	local Char1 = buffer.readu8(Input, InputIndex + 1)
	local Char2 = buffer.readu8(Input, InputIndex + 2)
	local Char3 = buffer.readu8(Input, InputIndex + 3)
	local Decoded0 = buffer.readu8(Dtet, Char0)
	local Decoded1 = buffer.readu8(Dtet, Char1)
	local Decoded2, Decoded3, Spare = 0, 0, 0
	if Padding == 0 then
		Decoded2 = buffer.readu8(Dtet, Char2)
		Decoded3 = buffer.readu8(Dtet, Char3)
	elseif Padding == 1 then
		Decoded2 = buffer.readu8(Dtet, Char2)
		Spare = bit32.band(Decoded2, 0x03)
	else
		Spare = bit32.band(Decoded1, 0x0F)
	end

	if Invalid >= 0x80000000 or bit32.bor(Decoded0, Decoded1, Decoded2, Decoded3) >= 64 then
		error("Base64 input contains an invalid character", 2)
	end

	if Spare ~= 0 then
		error("Base64 input has non-zero bits before its padding", 2)
	end

	local PairA = Decoded0 * 64 + Decoded1
	local PairB = Decoded2 * 64 + Decoded3
	buffer.writeu8(Output, OutputIndex, buffer.readu8(Pair0, PairA))
	if Padding < 2 then
		buffer.writeu8(Output, OutputIndex + 1, buffer.readu8(PairAHigh, PairA) + buffer.readu8(PairBLow, PairB))
	end
	if Padding == 0 then
		buffer.writeu8(Output, OutputIndex + 2, buffer.readu8(Pair2, PairB))
	end

	return Output
end

return {
	Encode = Encode,
	Decode = Decode
}
