--!native
--!optimize 2

local PaddingSchemes = {}

local function CreateOutputBuffer(OutputBuffer, RequiredLength, ErrorMessage)
	if OutputBuffer then
		return OutputBuffer
	else
		return buffer.create(RequiredLength)
	end
end

local function CalculatePaddingLength(InputLength, SegmentSize)
	return SegmentSize - InputLength % SegmentSize
end

local function CopyAndPadBuffer(InputBuffer, OutputBuffer, InputLength, PaddingStart)
	buffer.copy(OutputBuffer, 0, InputBuffer, 0, InputLength)
	return PaddingStart
end

local function NoPaddingFunction(InputBuffer)
	return InputBuffer
end

PaddingSchemes.None = table.freeze({
	Pad = NoPaddingFunction,
	Unpad = NoPaddingFunction,
	Overwrite = false
})

PaddingSchemes.AnsiX923 = {
	Pad = function(InputBuffer, OutputBuffer, SegmentSize)
		local InputLength = buffer.len(InputBuffer)
		local PaddingLength = CalculatePaddingLength(InputLength, SegmentSize)
		local RequiredLength = InputLength + PaddingLength

		OutputBuffer = CreateOutputBuffer(OutputBuffer, RequiredLength)
		local PaddingStart = CopyAndPadBuffer(InputBuffer, OutputBuffer, InputLength, InputLength)

		buffer.fill(OutputBuffer, PaddingStart, 0, PaddingLength - 1)
		buffer.writeu8(OutputBuffer, RequiredLength - 1, PaddingLength)

		return OutputBuffer
	end,

	Unpad = function(InputBuffer, OutputBuffer, SegmentSize)
		local InputLength = buffer.len(InputBuffer)
		local PaddingLength = buffer.readu8(InputBuffer, InputLength - 1)
		local UnpaddedLength = InputLength - PaddingLength

		OutputBuffer = CreateOutputBuffer(OutputBuffer, UnpaddedLength)
		buffer.copy(OutputBuffer, 0, InputBuffer, 0, UnpaddedLength)
		return OutputBuffer
	end,

	Overwrite = nil
}

PaddingSchemes.Iso10126 = {
	Pad = function(InputBuffer, OutputBuffer, SegmentSize)
		local InputLength = buffer.len(InputBuffer)
		local PaddingLength = CalculatePaddingLength(InputLength, SegmentSize)
		local RequiredLength = InputLength + PaddingLength

		OutputBuffer = CreateOutputBuffer(OutputBuffer, RequiredLength)
		local PaddingStart = CopyAndPadBuffer(InputBuffer, OutputBuffer, InputLength, InputLength)

		for ByteOffset = PaddingStart, RequiredLength - 2 do
			buffer.writeu8(OutputBuffer, ByteOffset, math.random(0, 255))
		end
		buffer.writeu8(OutputBuffer, RequiredLength - 1, PaddingLength)

		return OutputBuffer
	end,

	Unpad = function(InputBuffer, OutputBuffer, SegmentSize)
		local InputLength = buffer.len(InputBuffer)
		local PaddingLength = buffer.readu8(InputBuffer, InputLength - 1)
		local UnpaddedLength = InputLength - PaddingLength

		OutputBuffer = CreateOutputBuffer(OutputBuffer, UnpaddedLength)
		buffer.copy(OutputBuffer, 0, InputBuffer, 0, UnpaddedLength)
		return OutputBuffer
	end,

	Overwrite = nil
}

PaddingSchemes.Pkcs7 = {
	Pad = function(InputBuffer, OutputBuffer, SegmentSize)
		local InputLength = buffer.len(InputBuffer)
		local PaddingLength = CalculatePaddingLength(InputLength, SegmentSize)
		local RequiredLength = InputLength + PaddingLength

		OutputBuffer = CreateOutputBuffer(OutputBuffer, RequiredLength)
		local PaddingStart = CopyAndPadBuffer(InputBuffer, OutputBuffer, InputLength, InputLength)

		buffer.fill(OutputBuffer, PaddingStart, PaddingLength, PaddingLength)

		return OutputBuffer
	end,

	Unpad = function(InputBuffer, OutputBuffer, SegmentSize)
		local InputLength = buffer.len(InputBuffer)
		local PaddingLength = buffer.readu8(InputBuffer, InputLength - 1)
		local UnpaddedLength = InputLength - PaddingLength

		OutputBuffer = CreateOutputBuffer(OutputBuffer, UnpaddedLength)
		buffer.copy(OutputBuffer, 0, InputBuffer, 0, UnpaddedLength)
		return OutputBuffer
	end,

	Overwrite = nil
}

PaddingSchemes.Iso7816_4 = {
	Pad = function(InputBuffer, OutputBuffer, SegmentSize)
		local InputLength = buffer.len(InputBuffer)
		local PaddingLength = CalculatePaddingLength(InputLength, SegmentSize)
		local RequiredLength = InputLength + PaddingLength

		OutputBuffer = CreateOutputBuffer(OutputBuffer, RequiredLength)
		CopyAndPadBuffer(InputBuffer, OutputBuffer, InputLength, InputLength)

		buffer.writeu8(OutputBuffer, InputLength, 128)
		buffer.fill(OutputBuffer, InputLength + 1, 0, PaddingLength - 1)

		return OutputBuffer
	end,

	Unpad = function(InputBuffer, OutputBuffer, SegmentSize)
		local InputLength = buffer.len(InputBuffer)
		local SearchStart = InputLength - 1

		for ByteOffset = SearchStart, SearchStart - SegmentSize, -1 do
			local CurrentByte = buffer.readu8(InputBuffer, ByteOffset)
			if CurrentByte == 128 then
				OutputBuffer = CreateOutputBuffer(OutputBuffer, ByteOffset)
				buffer.copy(OutputBuffer, 0, InputBuffer, 0, ByteOffset)
				return OutputBuffer
			end
		end

		return buffer.create(0)
	end,

	Overwrite = nil
}

PaddingSchemes.Zero = {
	Pad = function(InputBuffer, OutputBuffer, SegmentSize)
		local InputLength = buffer.len(InputBuffer)
		local PaddingLength = CalculatePaddingLength(InputLength, SegmentSize)
		local RequiredLength = InputLength + PaddingLength

		OutputBuffer = CreateOutputBuffer(OutputBuffer, RequiredLength)
		local PaddingStart = CopyAndPadBuffer(InputBuffer, OutputBuffer, InputLength, InputLength)

		buffer.fill(OutputBuffer, PaddingStart, 0, PaddingLength)

		return OutputBuffer
	end,

	Unpad = function(InputBuffer, OutputBuffer, SegmentSize)
		local InputLength = buffer.len(InputBuffer)
		local SearchStart = InputLength - 1

		for ByteOffset = SearchStart, SearchStart - SegmentSize, -1 do
			local CurrentByte = buffer.readu8(InputBuffer, ByteOffset)
			if CurrentByte ~= 0 then
				local UnpaddedLength = ByteOffset + 1
				OutputBuffer = CreateOutputBuffer(OutputBuffer, UnpaddedLength)
				buffer.copy(OutputBuffer, 0, InputBuffer, 0, UnpaddedLength)
				return OutputBuffer
			end
		end

		local UnpaddedLength = SearchStart - SegmentSize
		OutputBuffer = CreateOutputBuffer(OutputBuffer, UnpaddedLength)
		buffer.copy(OutputBuffer, 0, InputBuffer, 0, UnpaddedLength)
		return OutputBuffer
	end,

	Overwrite = nil
}

return table.freeze(PaddingSchemes)