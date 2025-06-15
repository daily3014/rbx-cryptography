--!strict
--!native
--!optimize 2

export type PadFunction = (InputBuffer: buffer, OutputBuffer: buffer?, SegmentSize: number) -> buffer
export type Struct = {Pad: PadFunction, Unpad: PadFunction, Overwrite: nil | boolean}

local PaddingSchemes = {}

local function CreateOutputBuffer(OutputBuffer: buffer?, RequiredLength: number): buffer
	if OutputBuffer then
		return OutputBuffer
	else
		return buffer.create(RequiredLength)
	end
end

local function CalculatePaddingLength(InputLength: number, SegmentSize: number): number
	return SegmentSize - InputLength % SegmentSize
end

local function CopyAndPadBuffer(InputBuffer: buffer, OutputBuffer: buffer, InputLength: number, PaddingStart: number)
	buffer.copy(OutputBuffer, 0, InputBuffer, 0, InputLength)
	return PaddingStart
end

local function NoPaddingFunction(InputBuffer: buffer)
	return InputBuffer
end

PaddingSchemes.None = table.freeze({
	Pad = NoPaddingFunction,
	Unpad = NoPaddingFunction,
	Overwrite = false
})

local AnsiX923_Pad: PadFunction = function(InputBuffer, OutBuffer, SegmentSize)
	local InputLength = buffer.len(InputBuffer)
	local PaddingLength = CalculatePaddingLength(InputLength, SegmentSize)
	local RequiredLength = InputLength + PaddingLength

	local OutputBuffer = CreateOutputBuffer(OutBuffer, RequiredLength)
	local PaddingStart = CopyAndPadBuffer(InputBuffer, OutputBuffer, InputLength, InputLength)

	buffer.fill(OutputBuffer, PaddingStart, 0, PaddingLength - 1)
	buffer.writeu8(OutputBuffer, RequiredLength - 1, PaddingLength)

	return OutputBuffer
end

local AnsiX923_Unpad: PadFunction = function(InputBuffer, OutBuffer, SegmentSize)
	local InputLength = buffer.len(InputBuffer)
	local PaddingLength = buffer.readu8(InputBuffer, InputLength - 1)
	local UnpaddedLength = InputLength - PaddingLength

	local OutputBuffer = CreateOutputBuffer(OutBuffer, UnpaddedLength)
	buffer.copy(OutputBuffer, 0, InputBuffer, 0, UnpaddedLength)
	return OutputBuffer
end

local Iso10126_Pad: PadFunction = function(InputBuffer, OutBuffer, SegmentSize)
	local InputLength = buffer.len(InputBuffer)
	local PaddingLength = CalculatePaddingLength(InputLength, SegmentSize)
	local RequiredLength = InputLength + PaddingLength

	local OutputBuffer = CreateOutputBuffer(OutBuffer, RequiredLength)
	local PaddingStart = CopyAndPadBuffer(InputBuffer, OutputBuffer, InputLength, InputLength)

	for ByteOffset = PaddingStart, RequiredLength - 2 do
		buffer.writeu8(OutputBuffer, ByteOffset, math.random(0, 255))
	end
	buffer.writeu8(OutputBuffer, RequiredLength - 1, PaddingLength)

	return OutputBuffer
end

local Iso10126_Unpad: PadFunction = function(InputBuffer, OutBuffer, SegmentSize)
	local InputLength = buffer.len(InputBuffer)
	local PaddingLength = buffer.readu8(InputBuffer, InputLength - 1)
	local UnpaddedLength = InputLength - PaddingLength

	local OutputBuffer = CreateOutputBuffer(OutBuffer, UnpaddedLength)
	buffer.copy(OutputBuffer, 0, InputBuffer, 0, UnpaddedLength)
	return OutputBuffer
end

local Pkcs7_Pad: PadFunction = function(InputBuffer, OutBuffer, SegmentSize)
	local InputLength = buffer.len(InputBuffer)
	local PaddingLength = CalculatePaddingLength(InputLength, SegmentSize)
	local RequiredLength = InputLength + PaddingLength

	local OutputBuffer = CreateOutputBuffer(OutBuffer, RequiredLength)
	local PaddingStart = CopyAndPadBuffer(InputBuffer, OutputBuffer, InputLength, InputLength)

	buffer.fill(OutputBuffer, PaddingStart, PaddingLength, PaddingLength)

	return OutputBuffer
end

local Pkcs7_Unpad: PadFunction = function(InputBuffer, OutBuffer, SegmentSize)
	local InputLength = buffer.len(InputBuffer)
	local PaddingLength = buffer.readu8(InputBuffer, InputLength - 1)
	local UnpaddedLength = InputLength - PaddingLength

	local OutputBuffer = CreateOutputBuffer(OutBuffer, UnpaddedLength)
	buffer.copy(OutputBuffer, 0, InputBuffer, 0, UnpaddedLength)
	return OutputBuffer
end

local Iso7816_4_Pad: PadFunction = function(InputBuffer, OutBuffer, SegmentSize)
	local InputLength = buffer.len(InputBuffer)
	local PaddingLength = CalculatePaddingLength(InputLength, SegmentSize)
	local RequiredLength = InputLength + PaddingLength

	local OutputBuffer = CreateOutputBuffer(OutBuffer, RequiredLength)
	CopyAndPadBuffer(InputBuffer, OutputBuffer, InputLength, InputLength)

	buffer.writeu8(OutputBuffer, InputLength, 128)
	buffer.fill(OutputBuffer, InputLength + 1, 0, PaddingLength - 1)

	return OutputBuffer
end

local Iso7816_4_Unpad: PadFunction = function(InputBuffer, OutBuffer, SegmentSize)
	local InputLength = buffer.len(InputBuffer)
	local SearchStart = InputLength - 1

	for ByteOffset = SearchStart, SearchStart - SegmentSize, -1 do
		local CurrentByte = buffer.readu8(InputBuffer, ByteOffset)
		if CurrentByte == 128 then
			local OutputBuffer = CreateOutputBuffer(OutBuffer, ByteOffset)
			buffer.copy(OutputBuffer, 0, InputBuffer, 0, ByteOffset)
			return OutputBuffer
		end
	end

	return buffer.create(0)
end

local Zero_Pad: PadFunction = function(InputBuffer, OutBuffer, SegmentSize)
	local InputLength = buffer.len(InputBuffer)
	local PaddingLength = CalculatePaddingLength(InputLength, SegmentSize)
	local RequiredLength = InputLength + PaddingLength

	local OutputBuffer = CreateOutputBuffer(OutBuffer, RequiredLength)
	local PaddingStart = CopyAndPadBuffer(InputBuffer, OutputBuffer, InputLength, InputLength)

	buffer.fill(OutputBuffer, PaddingStart, 0, PaddingLength)

	return OutputBuffer
end

local Zero_Unpad: PadFunction = function(InputBuffer, OutBuffer, SegmentSize)
	local InputLength = buffer.len(InputBuffer)
	local SearchStart = InputLength - 1

	for ByteOffset = SearchStart, SearchStart - SegmentSize, -1 do
		local CurrentByte = buffer.readu8(InputBuffer, ByteOffset)
		if CurrentByte ~= 0 then
			local UnpaddedLength = ByteOffset + 1
			local OutputBuffer = CreateOutputBuffer(OutBuffer, UnpaddedLength)
			buffer.copy(OutputBuffer, 0, InputBuffer, 0, UnpaddedLength)
			return OutputBuffer
		end
	end

	local UnpaddedLength = SearchStart - SegmentSize
	local OutputBuffer = CreateOutputBuffer(OutBuffer, UnpaddedLength)
	buffer.copy(OutputBuffer, 0, InputBuffer, 0, UnpaddedLength)
	return OutputBuffer
end

do
	local function Index(_, index: "AnsiX923" | "Iso10126" | "Pkcs7" | "Iso7816_4" | "Zero"): {}?
		if index == "AnsiX923" then 
			return {
				Pad = AnsiX923_Pad,
				Unpad = AnsiX923_Unpad,
				Overwrite = nil
			} 
		elseif index == "Iso10126" then
			return {
				Pad = Iso10126_Pad,
				Unpad = Iso10126_Unpad,
				Overwrite = nil
			} 
		elseif index == "Pkcs7" then
			return {
				Pad = Pkcs7_Pad,
				Unpad = Pkcs7_Unpad,
				Overwrite = nil
			} 
		elseif index == "Iso7816_4" then
			return {
				Pad = Iso7816_4_Pad,
				Unpad = Iso7816_4_Unpad,
				Overwrite = nil
			} 
		elseif index == "Zero" then
			return {
				Pad = Zero_Pad,
				Unpad = Zero_Unpad,
				Overwrite = nil
			} 
		else
			return nil
		end
	end
	
	local Metatable = { __index = Index, __newindex = function() end }
	setmetatable(PaddingSchemes, Metatable)
	
	PaddingSchemes.AnsiX923 = {} :: {Pad: PadFunction, Unpad: PadFunction, Overwrite: nil | boolean}
	PaddingSchemes.Iso10126 = {} :: {Pad: PadFunction, Unpad: PadFunction, Overwrite: nil | boolean}
	PaddingSchemes.Pkcs7 = {} :: {Pad: PadFunction, Unpad: PadFunction, Overwrite: nil | boolean}
	PaddingSchemes.Iso7816_4 = {} :: {Pad: PadFunction, Unpad: PadFunction, Overwrite: nil | boolean}
	PaddingSchemes.Zero = {} :: {Pad: PadFunction, Unpad: PadFunction, Overwrite: nil | boolean}
end

return table.freeze(PaddingSchemes)