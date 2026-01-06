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

local ENCODE_A, ENCODE_B = buffer.create(131072), buffer.create(131072) do
	for Byte0 = 0, 255 do
		local Sextet0 = Byte0 // 4
		local Sextet0Char = buffer.readu8(ALPHABET_BYTES, Sextet0)
		local Byte0Low = Byte0 % 4
		for Byte1 = 0, 255 do
			local Sextet1 = Byte0Low * 16 + (Byte1 // 16)
			local Index = (Byte0 + Byte1 * 256) * 2
			buffer.writeu16(ENCODE_A, Index, Sextet0Char + buffer.readu8(ALPHABET_BYTES, Sextet1) * 256)
		end
	end

	for Byte1 = 0, 255 do
		local Nibble = (Byte1 % 16) * 4
		for Byte2 = 0, 255 do
			local Sextet2 = Nibble + (Byte2 // 64)
			local Sextet3 = Byte2 % 64
			local Index = (Byte1 + Byte2 * 256) * 2
			buffer.writeu16(ENCODE_B, Index, buffer.readu8(ALPHABET_BYTES, Sextet2) + buffer.readu8(ALPHABET_BYTES, Sextet3) * 256)
		end
	end
end

local DECODE_TET = buffer.create(256) do
	for Index = 1, 64 do
		buffer.writeu8(DECODE_TET, buffer.readu8(ALPHABET_BYTES, Index - 1), Index - 1)
	end

	buffer.writeu8(DECODE_TET, PADDING_CHARACTER, 254)
end

local DECODE_PAIR = buffer.create(131072) do
	for Char0 = 0, 255 do
		local Decoded0 = buffer.readu8(DECODE_TET, Char0)
		for Char1 = 0, 255 do
			local Decoded1 = buffer.readu8(DECODE_TET, Char1)
			local Key = (Char0 + Char1 * 256) * 2
			if Decoded0 < 64 and Decoded1 < 64 then
				buffer.writeu16(DECODE_PAIR, Key, Decoded0 * 64 + Decoded1)
			elseif Decoded0 == 254 or Decoded1 == 254 then
				buffer.writeu16(DECODE_PAIR, Key, 254)
			end
		end
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

local function Encode(Input: buffer): buffer
	local InputLength = buffer.len(Input)
	if InputLength == 0 then
		return buffer.create(0)
	end

	local Output = buffer.create(((InputLength + 2) // 3) * 4)
	local InputIndex = 0
	local OutputIndex = 0
	local FullTripletEnd = InputLength - (InputLength % 3)
	local UnrollStop = InputLength - 13

	local EncodeA = ENCODE_A
	local EncodeB = ENCODE_B
	local AlphabetBytes = ALPHABET_BYTES

	while InputIndex <= UnrollStop do
		local Word0 = buffer.readu32(Input, InputIndex)
		local Word1 = buffer.readu32(Input, InputIndex + 3)
		local Word2 = buffer.readu32(Input, InputIndex + 6)
		local Word3 = buffer.readu32(Input, InputIndex + 9)

		local KeyA0 = Word0 % 65536
		local KeyB0 = (Word0 // 256) % 65536
		buffer.writeu32(Output, OutputIndex, buffer.readu16(EncodeA, KeyA0 * 2) + buffer.readu16(EncodeB, KeyB0 * 2) * 0x10000)

		local KeyA1 = Word1 % 65536
		local KeyB1 = (Word1 // 256) % 65536
		buffer.writeu32(Output, OutputIndex + 4, buffer.readu16(EncodeA, KeyA1 * 2) + buffer.readu16(EncodeB, KeyB1 * 2) * 0x10000)

		local KeyA2 = Word2 % 65536
		local KeyB2 = (Word2 // 256) % 65536
		buffer.writeu32(Output, OutputIndex + 8, buffer.readu16(EncodeA, KeyA2 * 2) + buffer.readu16(EncodeB, KeyB2 * 2) * 0x10000)

		local KeyA3 = Word3 % 65536
		local KeyB3 = (Word3 // 256) % 65536
		buffer.writeu32(Output, OutputIndex + 12, buffer.readu16(EncodeA, KeyA3 * 2) + buffer.readu16(EncodeB, KeyB3 * 2) * 0x10000)

		InputIndex += 12
		OutputIndex += 16
	end

	while InputIndex < FullTripletEnd do
		local KeyA = buffer.readu16(Input, InputIndex)
		local Byte2 = buffer.readu8(Input, InputIndex + 2)
		local KeyB = (KeyA // 256) + Byte2 * 256
		buffer.writeu32(Output, OutputIndex, buffer.readu16(EncodeA, KeyA * 2) + buffer.readu16(EncodeB, KeyB * 2) * 0x10000)
		InputIndex += 3
		OutputIndex += 4
	end

	local Remainder = InputLength - InputIndex
	if Remainder == 1 then
		local Byte0 = buffer.readu8(Input, InputIndex)
		local Sextet0 = Byte0 // 4
		local Sextet1 = (Byte0 % 4) * 16
		local Pair = buffer.readu8(AlphabetBytes, Sextet0) + buffer.readu8(AlphabetBytes, Sextet1) * 256
		buffer.writeu16(Output, OutputIndex, Pair)
		buffer.writeu8(Output, OutputIndex + 2, PADDING_CHARACTER)
		buffer.writeu8(Output, OutputIndex + 3, PADDING_CHARACTER)
	elseif Remainder == 2 then
		local Byte0 = buffer.readu8(Input, InputIndex)
		local Byte1 = buffer.readu8(Input, InputIndex + 1)
		local KeyA = Byte0 + Byte1 * 256
		buffer.writeu16(Output, OutputIndex, buffer.readu16(EncodeA, KeyA * 2))
		local Sextet2 = (Byte1 % 16) * 4
		buffer.writeu8(Output, OutputIndex + 2, buffer.readu8(AlphabetBytes, Sextet2))
		buffer.writeu8(Output, OutputIndex + 3, PADDING_CHARACTER)
	end

	return Output
end

local function Decode(Input: buffer): buffer
	local InputLength = buffer.len(Input)
	if InputLength == 0 then
		return buffer.create(0)
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
	local UnrollStop = BodyEnd - 8

	local DecodePair = DECODE_PAIR
	local Pair0 = PAIR_A_BYTE0
	local PairAHigh = PAIR_A_BYTE1_HIGH
	local PairBLow = PAIR_B_BYTE1_LOW
	local Pair2 = PAIR_B_BYTE2
	local Dtet = DECODE_TET

	while InputIndex <= UnrollStop do
		local Word0 = buffer.readu32(Input, InputIndex)
		local Word1 = buffer.readu32(Input, InputIndex + 4)

		local PairA0 = buffer.readu16(DecodePair, (Word0 % 65536) * 2)
		local PairB0 = buffer.readu16(DecodePair, (Word0 // 65536) * 2)
		buffer.writeu8(Output, OutputIndex, buffer.readu8(Pair0, PairA0))
		buffer.writeu8(Output, OutputIndex + 1, buffer.readu8(PairAHigh, PairA0) + buffer.readu8(PairBLow, PairB0))
		buffer.writeu8(Output, OutputIndex + 2, buffer.readu8(Pair2, PairB0))

		local PairA1 = buffer.readu16(DecodePair, (Word1 % 65536) * 2)
		local PairB1 = buffer.readu16(DecodePair, (Word1 // 65536) * 2)
		buffer.writeu8(Output, OutputIndex + 3, buffer.readu8(Pair0, PairA1))
		buffer.writeu8(Output, OutputIndex + 4, buffer.readu8(PairAHigh, PairA1) + buffer.readu8(PairBLow, PairB1))
		buffer.writeu8(Output, OutputIndex + 5, buffer.readu8(Pair2, PairB1))

		InputIndex += 8
		OutputIndex += 6
	end

	while InputIndex <= BodyEnd - 4 do
		local Word = buffer.readu32(Input, InputIndex)
		local PairA = buffer.readu16(DecodePair, (Word % 65536) * 2)
		local PairB = buffer.readu16(DecodePair, (Word // 65536) * 2)
		buffer.writeu8(Output, OutputIndex, buffer.readu8(Pair0, PairA))
		buffer.writeu8(Output, OutputIndex + 1, buffer.readu8(PairAHigh, PairA) + buffer.readu8(PairBLow, PairB))
		buffer.writeu8(Output, OutputIndex + 2, buffer.readu8(Pair2, PairB))
		InputIndex += 4
		OutputIndex += 3
	end

	do
		local Char0 = buffer.readu8(Input, InputIndex)
		local Char1 = buffer.readu8(Input, InputIndex + 1)
		local Char2 = buffer.readu8(Input, InputIndex + 2)
		local Char3 = buffer.readu8(Input, InputIndex + 3)
		local Decoded0 = buffer.readu8(Dtet, Char0)
		local Decoded1 = buffer.readu8(Dtet, Char1)

		if Char2 == PADDING_CHARACTER then
			local PairA = Decoded0 * 64 + Decoded1
			buffer.writeu8(Output, OutputIndex, buffer.readu8(Pair0, PairA))
		elseif Char3 == PADDING_CHARACTER then
			local Decoded2 = buffer.readu8(Dtet, Char2)
			local PairA = Decoded0 * 64 + Decoded1
			local PairB = Decoded2 * 64
			buffer.writeu8(Output, OutputIndex, buffer.readu8(Pair0, PairA))
			buffer.writeu8(Output, OutputIndex + 1, buffer.readu8(PairAHigh, PairA) + (PairB // 256))
		else
			local Decoded2 = buffer.readu8(Dtet, Char2)
			local Decoded3 = buffer.readu8(Dtet, Char3)
			local PairA = Decoded0 * 64 + Decoded1
			local PairB = Decoded2 * 64 + Decoded3
			buffer.writeu8(Output, OutputIndex, buffer.readu8(Pair0, PairA))
			buffer.writeu8(Output, OutputIndex + 1, buffer.readu8(PairAHigh, PairA) + buffer.readu8(PairBLow, PairB))
			buffer.writeu8(Output, OutputIndex + 2, buffer.readu8(Pair2, PairB))
		end
	end

	return Output
end

return {
	Encode = Encode,
	Decode = Decode
}