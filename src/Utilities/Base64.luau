--[=[
	Cryptography library: Base64
	
	Return type: string
	Example Usage:
		local Message = buffer.fromstring("Hello World")
		
		local Encoded = Base64.Encode(Message)
		local Decoded = Base64.Decode("SGVsbG8gV29ybGQ=")
--]=]

--!strict
--!optimize 2
--!native

local PADDING_CHARACTER = 61

local ALPHABET_LOOKUP = {} do
	local Characters = {
		65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
		81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
		97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
		113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
		48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
		43, 47 
	}

	for Index = 0, 63 do
		ALPHABET_LOOKUP[Index] = Characters[Index + 1]
	end
end

local DIRECT_LOOKUP = {} do
	for Index = 0, 255 do
		DIRECT_LOOKUP[Index] = ALPHABET_LOOKUP[bit32.band(Index, 63)]
	end
end

local DECODE_LOOKUP = {} do
	for Index = 0, 255 do
		DECODE_LOOKUP[Index] = 255
	end

	for Index = 65, 90 do
		DECODE_LOOKUP[Index] = Index - 65
	end

	for Index = 97, 122 do
		DECODE_LOOKUP[Index] = Index - 97 + 26
	end

	for Index = 48, 57 do
		DECODE_LOOKUP[Index] = Index - 48 + 52
	end

	DECODE_LOOKUP[43] = 62
	DECODE_LOOKUP[47] = 63
end

local Base64 = {}

function Base64.Encode(Input: buffer): buffer
	local Padding = PADDING_CHARACTER
	local Lookup = DIRECT_LOOKUP
	local InputLength = buffer.len(Input)
	if InputLength == 0 then
		return buffer.create(0)
	end

	local Chunks = math.ceil(InputLength / 3)
	local OutputLength = Chunks * 4
	local Output = buffer.create(OutputLength)

	local DoubleChunks = math.floor((Chunks - 1) / 2)
	for ChunkIndex = 1, DoubleChunks do
		local InputIndex = (ChunkIndex - 1) * 6
		local OutputIndex = (ChunkIndex - 1) * 8

		local Word1 = bit32.byteswap(buffer.readu32(Input, InputIndex))
		local Octet1_1 = bit32.rshift(Word1, 26)
		local Octet1_2 = bit32.rshift(Word1, 20)
		local Octet1_3 = bit32.rshift(Word1, 14)
		local Octet1_4 = bit32.rshift(Word1, 8)

		local Word2 = bit32.byteswap(buffer.readu32(Input, InputIndex + 3))
		local Octet2_1 = bit32.rshift(Word2, 26)
		local Octet2_2 = bit32.rshift(Word2, 20)
		local Octet2_3 = bit32.rshift(Word2, 14)
		local Octet2_4 = bit32.rshift(Word2, 8)

		buffer.writeu32(Output, OutputIndex, bit32.bor(
			Lookup[bit32.band(Octet1_1, 255)],
			Lookup[bit32.band(Octet1_2, 255)] * 256,
			Lookup[bit32.band(Octet1_3, 255)] * 65536,
			Lookup[bit32.band(Octet1_4, 255)] * 16777216
			))

		buffer.writeu32(Output, OutputIndex + 4, bit32.bor(
			Lookup[bit32.band(Octet2_1, 255)],
			Lookup[bit32.band(Octet2_2, 255)] * 256,
			Lookup[bit32.band(Octet2_3, 255)] * 65536,
			Lookup[bit32.band(Octet2_4, 255)] * 16777216
			))
	end

	local ProcessedChunks = DoubleChunks * 2
	if ProcessedChunks < Chunks - 1 then
		local InputIndex = ProcessedChunks * 3
		local OutputIndex = ProcessedChunks * 4

		local Word = bit32.byteswap(buffer.readu32(Input, InputIndex))
		local Octet1 = bit32.rshift(Word, 26)
		local Octet2 = bit32.rshift(Word, 20)
		local Octet3 = bit32.rshift(Word, 14)
		local Octet4 = bit32.rshift(Word, 8)

		buffer.writeu32(Output, OutputIndex, bit32.bor(
			Lookup[bit32.band(Octet1, 255)],
			Lookup[bit32.band(Octet2, 255)] * 256,
			Lookup[bit32.band(Octet3, 255)] * 65536,
			Lookup[bit32.band(Octet4, 255)] * 16777216
			))
	end

	if InputLength > 0 then
		local TotalProcessedChunks = DoubleChunks * 2 + (ProcessedChunks < Chunks - 1 and 1 or 0)
		local ProcessedBytes = TotalProcessedChunks * 3
		local RemainingBytes = InputLength - ProcessedBytes
		local LastOutputIndex = OutputLength - 4

		if RemainingBytes == 3 then
			if ProcessedBytes + 4 <= InputLength then
				local Word = bit32.byteswap(buffer.readu32(Input, ProcessedBytes))
				local Octet1 = bit32.rshift(Word, 26)
				local Octet2 = bit32.rshift(Word, 20)
				local Octet3 = bit32.rshift(Word, 14)
				local Octet4 = bit32.rshift(Word, 8)

				buffer.writeu32(Output, LastOutputIndex, bit32.bor(
					Lookup[bit32.band(Octet1, 255)],
					Lookup[bit32.band(Octet2, 255)] * 256,
					Lookup[bit32.band(Octet3, 255)] * 65536,
					Lookup[bit32.band(Octet4, 255)] * 16777216
					))
			else
				local Byte1 = buffer.readu8(Input, ProcessedBytes)
				local Byte2 = buffer.readu8(Input, ProcessedBytes + 1)
				local Byte3 = buffer.readu8(Input, ProcessedBytes + 2)
				local Combined = bit32.bor(bit32.lshift(Byte1, 16), bit32.lshift(Byte2, 8), Byte3)

				local Octet1 = bit32.rshift(Combined, 18)
				local Octet2 = bit32.band(bit32.rshift(Combined, 12), 63)
				local Octet3 = bit32.band(bit32.rshift(Combined, 6), 63)
				local Octet4 = bit32.band(Combined, 63)

				buffer.writeu32(Output, LastOutputIndex, bit32.bor(
					Lookup[Octet1],
					Lookup[Octet2] * 256,
					Lookup[Octet3] * 65536,
					Lookup[Octet4] * 16777216
					))
			end

		elseif RemainingBytes == 2 then
			local Byte1 = buffer.readu8(Input, ProcessedBytes)
			local Byte2 = buffer.readu8(Input, ProcessedBytes + 1)
			local Combined = bit32.bor(bit32.lshift(Byte1, 16), bit32.lshift(Byte2, 8))

			local Octet1 = bit32.rshift(Combined, 18)
			local Octet2 = bit32.rshift(Combined, 12)
			local Octet3 = bit32.rshift(Combined, 6)

			buffer.writeu32(Output, LastOutputIndex, bit32.bor(
				Lookup[bit32.band(Octet1, 255)],
				Lookup[bit32.band(Octet2, 255)] * 256,
				Lookup[bit32.band(Octet3, 255)] * 65536,
				Padding * 16777216
				))

		elseif RemainingBytes == 1 then
			local Byte1 = buffer.readu8(Input, ProcessedBytes)
			local Combined = bit32.lshift(Byte1, 16)

			local Octet1 = bit32.rshift(Combined, 18)
			local Octet2 = bit32.rshift(Combined, 12)

			buffer.writeu32(Output, LastOutputIndex, bit32.bor(
				Lookup[bit32.band(Octet1, 255)],
				Lookup[bit32.band(Octet2, 255)] * 256,
				Padding * 65536,
				Padding * 16777216
				))
		end
	end

	return Output
end

function Base64.Decode(Input: buffer): string
	local Padding = PADDING_CHARACTER
	local Lookup = DECODE_LOOKUP
	local InputLength = buffer.len(Input)

	if InputLength == 0 then
		return ""
	end

	local PaddingCount = 0
	if InputLength > 0 and buffer.readu8(Input, InputLength - 1) == Padding then
		PaddingCount = 1
		if InputLength > 1 and buffer.readu8(Input, InputLength - 2) == Padding then
			PaddingCount = 2
		end
	end

	local OutputLength = (InputLength / 4) * 3 - PaddingCount
	local Output = buffer.create(OutputLength)
	local InputChunks = InputLength // 4

	local DoubleChunks = (InputChunks - 1) // 2
	for ChunkIndex = 1, DoubleChunks do
		local InputIndex = (ChunkIndex - 1) * 8
		local OutputIndex = (ChunkIndex - 1) * 6

		local Value1_1 = Lookup[buffer.readu8(Input, InputIndex)]
		local Value1_2 = Lookup[buffer.readu8(Input, InputIndex + 1)]
		local Value1_3 = Lookup[buffer.readu8(Input, InputIndex + 2)]
		local Value1_4 = Lookup[buffer.readu8(Input, InputIndex + 3)]

		local Combined1 = bit32.bor(
			bit32.lshift(Value1_1, 18),
			bit32.lshift(Value1_2, 12),
			bit32.lshift(Value1_3, 6),
			Value1_4
		)

		local Value2_1 = Lookup[buffer.readu8(Input, InputIndex + 4)]
		local Value2_2 = Lookup[buffer.readu8(Input, InputIndex + 5)]
		local Value2_3 = Lookup[buffer.readu8(Input, InputIndex + 6)]
		local Value2_4 = Lookup[buffer.readu8(Input, InputIndex + 7)]

		local Combined2 = bit32.bor(
			bit32.lshift(Value2_1, 18),
			bit32.lshift(Value2_2, 12),
			bit32.lshift(Value2_3, 6),
			Value2_4
		)

		buffer.writeu32(Output, OutputIndex, bit32.bor(
			bit32.band(bit32.rshift(Combined1, 16), 255),
			bit32.band(bit32.rshift(Combined1, 8), 255) * 256,
			bit32.band(Combined1, 255) * 65536,
			bit32.band(bit32.rshift(Combined2, 16), 255) * 16777216
			))

		buffer.writeu8(Output, OutputIndex + 4, bit32.band(bit32.rshift(Combined2, 8), 255))
		buffer.writeu8(Output, OutputIndex + 5, bit32.band(Combined2, 255))
	end

	local ProcessedChunks = DoubleChunks * 2
	for ChunkIndex = ProcessedChunks + 1, InputChunks do
		local InputIndex = (ChunkIndex - 1) * 4
		local OutputIndex = (ChunkIndex - 1) * 3

		local Char1 = buffer.readu8(Input, InputIndex)
		local Char2 = buffer.readu8(Input, InputIndex + 1)
		local Char3 = buffer.readu8(Input, InputIndex + 2)
		local Char4 = buffer.readu8(Input, InputIndex + 3)

		local Value1 = Lookup[Char1]
		local Value2 = Lookup[Char2]
		local Value3 = Char3 == Padding and 0 or Lookup[Char3]
		local Value4 = Char4 == Padding and 0 or Lookup[Char4]

		local Combined = bit32.bor(
			bit32.lshift(Value1, 18),
			bit32.lshift(Value2, 12),
			bit32.lshift(Value3, 6),
			Value4
		)

		local BytesToWrite = math.min(3, OutputLength - OutputIndex)

		if BytesToWrite >= 1 then
			buffer.writeu8(Output, OutputIndex, bit32.band(bit32.rshift(Combined, 16), 255))
		end
		if BytesToWrite >= 2 then
			buffer.writeu8(Output, OutputIndex + 1, bit32.band(bit32.rshift(Combined, 8), 255))
		end
		if BytesToWrite >= 3 then
			buffer.writeu8(Output, OutputIndex + 2, bit32.band(Combined, 255))
		end
	end

	return buffer.tostring(Output)
end

return Base64