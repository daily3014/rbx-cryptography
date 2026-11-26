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
local INVALID_ENTRY = 0x80000000
local MAX_VALID_ASCII = 122
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

local DECODE_TABLE_SIZE = (MAX_VALID_ASCII * 256 + MAX_VALID_ASCII + 1) * 4
local DECODE_HIGH = buffer.create(DECODE_TABLE_SIZE)
local DECODE_LOW = buffer.create(DECODE_TABLE_SIZE)
do
	for Key = 0, DECODE_TABLE_SIZE - 4, 4 do
		buffer.writeu32(DECODE_HIGH, Key, INVALID_ENTRY)
		buffer.writeu32(DECODE_LOW, Key, INVALID_ENTRY)
	end

	for Char1 = 0, MAX_VALID_ASCII do
		local Sextet1 = buffer.readu8(DECODE_TET, Char1)
		if Sextet1 < 64 then
			for Char0 = 0, MAX_VALID_ASCII do
				local Sextet0 = buffer.readu8(DECODE_TET, Char0)
				if Sextet0 < 64 then
					local Key = (Char0 + Char1 * 256) * 4
					buffer.writeu32(DECODE_HIGH, Key, Sextet0 * 4 + Sextet1 // 16 + (Sextet1 % 16) * 16 * 256)
					buffer.writeu32(DECODE_LOW, Key, (Sextet0 // 4) * 256 + ((Sextet0 % 4) * 64 + Sextet1) * 65536)
				end
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

local function DecodeQuartetHL(
	Input: buffer,
	Output: buffer,
	High: buffer,
	Low: buffer,
	InOff: number,
	OutOff: number
): number
	local Bytes = bit32.bor(
		buffer.readu32(High, bit32.lshift(buffer.readu16(Input, InOff), 2)),
		buffer.readu32(Low, bit32.lshift(buffer.readu16(Input, InOff + 2), 2))
	)
	buffer.writeu32(Output, OutOff, Bytes)
	return Bytes
end

local function DecodeQuartetLH(
	Input: buffer,
	Output: buffer,
	High: buffer,
	Low: buffer,
	InOff: number,
	OutOff: number
): number
	local Bytes = bit32.bor(
		buffer.readu32(Low, bit32.lshift(buffer.readu16(Input, InOff + 2), 2)),
		buffer.readu32(High, bit32.lshift(buffer.readu16(Input, InOff), 2))
	)
	buffer.writeu32(Output, OutOff, Bytes)
	return Bytes
end

local function DecodeBlocks(Input: buffer, Output: buffer, High: buffer, Low: buffer, StopIn: number): boolean
	for InputIndex = 0, StopIn, 128 do
		local OutputIndex = InputIndex * 0.75
		local Invalid = DecodeQuartetHL(Input, Output, High, Low, InputIndex + 0, OutputIndex + 0)
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 4, OutputIndex + 3))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 8, OutputIndex + 6))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 12, OutputIndex + 9))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 16, OutputIndex + 12))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 20, OutputIndex + 15))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 24, OutputIndex + 18))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 28, OutputIndex + 21))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 32, OutputIndex + 24))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 36, OutputIndex + 27))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 40, OutputIndex + 30))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 44, OutputIndex + 33))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 48, OutputIndex + 36))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 52, OutputIndex + 39))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 56, OutputIndex + 42))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 60, OutputIndex + 45))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 64, OutputIndex + 48))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 68, OutputIndex + 51))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 72, OutputIndex + 54))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 76, OutputIndex + 57))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 80, OutputIndex + 60))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 84, OutputIndex + 63))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 88, OutputIndex + 66))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 92, OutputIndex + 69))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 96, OutputIndex + 72))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 100, OutputIndex + 75))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 104, OutputIndex + 78))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 108, OutputIndex + 81))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 112, OutputIndex + 84))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 116, OutputIndex + 87))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 120, OutputIndex + 90))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 124, OutputIndex + 93))

		if bit32.btest(Invalid, INVALID_ENTRY) then
			return false
		end
	end

	return true
end

local function DecodeBody(Input: buffer, Output: buffer, High: buffer, Low: buffer, BodyEnd: number): boolean
	local InputIndex = 0
	local OutputIndex = 0

	if BodyEnd >= 128 then
		local StopIn = ((BodyEnd - 128) // 128) * 128
		if not DecodeBlocks(Input, Output, High, Low, StopIn) then
			return false
		end

		InputIndex = StopIn + 128
		OutputIndex = InputIndex * 0.75
	end

	local Invalid = 0

	while InputIndex <= BodyEnd - 16 do
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 0, OutputIndex + 0))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 4, OutputIndex + 3))
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex + 8, OutputIndex + 6))
		Invalid = bit32.bor(Invalid, DecodeQuartetLH(Input, Output, High, Low, InputIndex + 12, OutputIndex + 9))
		InputIndex += 16
		OutputIndex += 12
	end

	while InputIndex <= BodyEnd - 4 do
		Invalid = bit32.bor(Invalid, DecodeQuartetHL(Input, Output, High, Low, InputIndex, OutputIndex))
		InputIndex += 4
		OutputIndex += 3
	end

	return not bit32.btest(Invalid, INVALID_ENTRY)
end

local function Decode(Input: buffer): buffer?
	if typeof(Input) ~= "buffer" then
		return nil
	end

	local InputLength = buffer.len(Input)
	if InputLength == 0 then
		return buffer.create(0)
	end

	if InputLength % 4 ~= 0 then
		return nil
	end

	local Padding = 0
	if buffer.readu8(Input, InputLength - 1) == PADDING_CHARACTER then
		Padding = 1
		if buffer.readu8(Input, InputLength - 2) == PADDING_CHARACTER then
			Padding = 2
		end
	end

	local OutputLength = (InputLength // 4) * 3 - Padding
	local Output = buffer.create(OutputLength)
	local BodyEnd = InputLength - 4

	if BodyEnd > 0 then
		local Ok, Valid = pcall(DecodeBody, Input, Output, DECODE_HIGH, DECODE_LOW, BodyEnd)
		if not Ok or not Valid then
			return nil
		end
	end

	local DecodeTet = DECODE_TET
	local Decoded0 = buffer.readu8(DecodeTet, buffer.readu8(Input, BodyEnd))
	local Decoded1 = buffer.readu8(DecodeTet, buffer.readu8(Input, BodyEnd + 1))
	local Decoded2 = 0
	local Decoded3 = 0
	local Spare = 0

	if Padding == 0 then
		Decoded2 = buffer.readu8(DecodeTet, buffer.readu8(Input, BodyEnd + 2))
		Decoded3 = buffer.readu8(DecodeTet, buffer.readu8(Input, BodyEnd + 3))
	elseif Padding == 1 then
		Decoded2 = buffer.readu8(DecodeTet, buffer.readu8(Input, BodyEnd + 2))
		Spare = bit32.band(Decoded2, 0x03)
	else
		Spare = bit32.band(Decoded1, 0x0f)
	end

	if bit32.bor(Decoded0, Decoded1, Decoded2, Decoded3) >= 64 or Spare ~= 0 then
		return nil
	end

	local OutputIndex = (BodyEnd // 4) * 3
	buffer.writeu8(Output, OutputIndex, bit32.bor(bit32.lshift(Decoded0, 2), bit32.rshift(Decoded1, 4)))
	if Padding < 2 then
		buffer.writeu8(Output, OutputIndex + 1, bit32.bor(bit32.lshift(Decoded1, 4), bit32.rshift(Decoded2, 2)))
	end
	if Padding == 0 then
		buffer.writeu8(Output, OutputIndex + 2, bit32.bor(bit32.lshift(Decoded2, 6), Decoded3))
	end

	return Output
end

return {
	Encode = Encode,
	Decode = Decode
}
