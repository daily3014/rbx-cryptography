--[=[
	Cryptography library: Base64
	
	Return type: string
	Example Usage:
		local Message = buffer.fromstring("Hello World")
		
		--------Usage Case 1--------
		local Encoded = Base64.Encode(Message)
		
		--------Usage Case 2--------
		local Decoded = Base64.Decode("SGVsbG8gV29ybGQ=")
--]=]


--!optimize 2
--!native
--!strict

local PADDING_CHARACTER = 61

local ALPHABET_INDEX = buffer.create(64) do
	local Characters = {
		65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
		81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
		97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
		113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
		48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
		43, 47 
	}

	for Index = 0, 63 do
		buffer.writeu8(ALPHABET_INDEX, Index, Characters[Index + 1])
	end
end

local DECODE_TABLE = buffer.create(256) do
	for Index = 0, 255 do
		buffer.writeu8(DECODE_TABLE, Index, 255)
	end

	for Index = 65, 90 do
		buffer.writeu8(DECODE_TABLE, Index, Index - 65)
	end

	for Index = 97, 122 do
		buffer.writeu8(DECODE_TABLE, Index, Index - 97 + 26)
	end

	for Index = 48, 57 do
		buffer.writeu8(DECODE_TABLE, Index, Index - 48 + 52)
	end

	buffer.writeu8(DECODE_TABLE, 43, 62)
	buffer.writeu8(DECODE_TABLE, 47, 63)
end

local function Encode(Input: buffer): string
	local InputLength = buffer.len(Input)
	local OutputLength = math.ceil(InputLength / 3) * 4
	local Output = buffer.create(OutputLength)
	local OutputIndex = 0
	local Index = 0

	while Index < InputLength - 2 do
		local Byte1 = buffer.readu8(Input, Index)
		local Byte2 = buffer.readu8(Input, Index + 1)
		local Byte3 = buffer.readu8(Input, Index + 2)
		local Combined = bit32.lshift(Byte1, 16) + bit32.lshift(Byte2, 8) + Byte3

		buffer.writeu8(Output, OutputIndex, buffer.readu8(ALPHABET_INDEX, bit32.rshift(Combined, 18)))
		buffer.writeu8(Output, OutputIndex + 1, buffer.readu8(ALPHABET_INDEX, bit32.band(bit32.rshift(Combined, 12), 63)))
		buffer.writeu8(Output, OutputIndex + 2, buffer.readu8(ALPHABET_INDEX, bit32.band(bit32.rshift(Combined, 6), 63)))
		buffer.writeu8(Output, OutputIndex + 3, buffer.readu8(ALPHABET_INDEX, bit32.band(Combined, 63)))

		Index += 3
		OutputIndex += 4
	end

	if Index < InputLength then
		local Byte1 = buffer.readu8(Input, Index)
		local Byte2 = Index + 1 < InputLength and buffer.readu8(Input, Index + 1) or 0
		local Combined = bit32.lshift(Byte1, 16) + bit32.lshift(Byte2, 8)

		buffer.writeu8(Output, OutputIndex, buffer.readu8(ALPHABET_INDEX, bit32.rshift(Combined, 18)))
		buffer.writeu8(Output, OutputIndex + 1, buffer.readu8(ALPHABET_INDEX, bit32.band(bit32.rshift(Combined, 12), 63)))

		if Index + 1 < InputLength then
			buffer.writeu8(Output, OutputIndex + 2, buffer.readu8(ALPHABET_INDEX, bit32.band(bit32.rshift(Combined, 6), 63)))
		else
			buffer.writeu8(Output, OutputIndex + 2, PADDING_CHARACTER)
		end

		buffer.writeu8(Output, OutputIndex + 3, PADDING_CHARACTER)
	end

	return buffer.readstring(Output, 0, OutputLength)
end

local function Decode(Input: buffer): string
	local InputLength = buffer.len(Input)

	local PaddingCount = 0
	if InputLength > 0 and buffer.readu8(Input, InputLength - 1) == PADDING_CHARACTER then
		PaddingCount = 1
		if InputLength > 1 and buffer.readu8(Input, InputLength - 2) == PADDING_CHARACTER then
			PaddingCount = 2
		end
	end

	local OutputLength = (InputLength / 4) * 3 - PaddingCount
	local Output = buffer.create(OutputLength)
	local OutputIndex = 0
	local Index = 0

	while Index < InputLength do
		local Char1 = buffer.readu8(Input, Index)
		local Char2 = buffer.readu8(Input, Index + 1)
		local Char3 = buffer.readu8(Input, Index + 2)
		local Char4 = buffer.readu8(Input, Index + 3)

		local Value1 = buffer.readu8(DECODE_TABLE, Char1)
		local Value2 = buffer.readu8(DECODE_TABLE, Char2)
		local Value3 = Char3 == PADDING_CHARACTER and 0 or buffer.readu8(DECODE_TABLE, Char3)
		local Value4 = Char4 == PADDING_CHARACTER and 0 or buffer.readu8(DECODE_TABLE, Char4)

		local Combined = bit32.lshift(Value1, 18) + bit32.lshift(Value2, 12) + bit32.lshift(Value3, 6) + Value4

		if OutputIndex < OutputLength then
			buffer.writeu8(Output, OutputIndex, bit32.band(bit32.rshift(Combined, 16), 255))
			OutputIndex += 1
		end

		if OutputIndex < OutputLength then
			buffer.writeu8(Output, OutputIndex, bit32.band(bit32.rshift(Combined, 8), 255))
			OutputIndex += 1
		end

		if OutputIndex < OutputLength then
			buffer.writeu8(Output, OutputIndex, bit32.band(Combined, 255))
			OutputIndex += 1
		end

		Index += 4
	end

	return buffer.tostring(Output)
end

return {
	Encode = Encode,
	Decode = Decode,
}