--[=[
	Stateful SHAKE XOF (Extensible Output Function)
	
	Non-OOP implementation with reusable state buffers.
	For ML-DSA sampling functions that use rejection sampling.
	
	Example usage:
		XOF.Reset128()
		XOF.Absorb128(message)
		local Chunk1 = XOF.Squeeze128(168)
		local Chunk2 = XOF.Squeeze128(168)
--]=]

--!strict
--!optimize 2
--!native

local Keccak = require("./SHA3").Keccak_Internal

local RATE_128 = 168
local RATE_256 = 136

local LanesLow128 = buffer.create(100)
local LanesHigh128 = buffer.create(100)
local SqueezeOffset128 = 0

local LanesLow256 = buffer.create(100)
local LanesHigh256 = buffer.create(100)
local SqueezeOffset256 = 0

local ZeroBuffer128 = buffer.create(RATE_128)
local ZeroBuffer256 = buffer.create(RATE_256)

local PaddedBuffer128 = buffer.create(RATE_128)
local PaddedBuffer256 = buffer.create(RATE_256)

local SqueezeBuffer128_168 = buffer.create(168)
local SqueezeBuffer256_128 = buffer.create(128)
local SqueezeBuffer256_192 = buffer.create(192)

local XOF = {}

function XOF.Reset128()
	buffer.fill(LanesLow128, 0, 0, 100)
	buffer.fill(LanesHigh128, 0, 0, 100)
	SqueezeOffset128 = 0
end

function XOF.Reset256()
	buffer.fill(LanesLow256, 0, 0, 100)
	buffer.fill(LanesHigh256, 0, 0, 100)
	SqueezeOffset256 = 0
end

function XOF.Absorb128(Message: buffer)
	local MessageLength = buffer.len(Message)
	local RateBytes = RATE_128

	local PaddedMessage = PaddedBuffer128
	buffer.fill(PaddedMessage, 0, 0, RateBytes)

	if MessageLength > 0 then
		buffer.copy(PaddedMessage, 0, Message, 0, MessageLength)
	end

	if RateBytes - MessageLength == 1 then
		buffer.writeu8(PaddedMessage, MessageLength, 0x9F)
	else
		buffer.writeu8(PaddedMessage, MessageLength, 0x1F)
		buffer.writeu8(PaddedMessage, RateBytes - 1, 0x80)
	end

	Keccak(LanesLow128, LanesHigh128, PaddedMessage, 0, RateBytes, RateBytes)
end

function XOF.Absorb256(Message: buffer)
	local MessageLength = buffer.len(Message)
	local RateBytes = RATE_256

	local PaddedMessage = PaddedBuffer256
	buffer.fill(PaddedMessage, 0, 0, RateBytes)

	if MessageLength > 0 then
		buffer.copy(PaddedMessage, 0, Message, 0, MessageLength)
	end

	if RateBytes - MessageLength == 1 then
		buffer.writeu8(PaddedMessage, MessageLength, 0x9F)
	else
		buffer.writeu8(PaddedMessage, MessageLength, 0x1F)
		buffer.writeu8(PaddedMessage, RateBytes - 1, 0x80)
	end

	Keccak(LanesLow256, LanesHigh256, PaddedMessage, 0, RateBytes, RateBytes)
end

function XOF.Squeeze128Into(Output: buffer, OutputBytes: number, OutputOffset: number?)
	local OutOffset = OutputOffset or 0
	local RateBytes = RATE_128
	local LanesLow = LanesLow128
	local LanesHigh = LanesHigh128
	local SqueezeOffset = SqueezeOffset128
	local ZeroBuffer = ZeroBuffer128

	local Written = 0
	while Written < OutputBytes do
		if SqueezeOffset >= RateBytes then
			Keccak(LanesLow, LanesHigh, ZeroBuffer, 0, RateBytes, RateBytes)
			SqueezeOffset = 0
		end

		local BytesThisRound = RateBytes - SqueezeOffset
		if BytesThisRound > OutputBytes - Written then
			BytesThisRound = OutputBytes - Written
		end

		local ByteIndex = 0
		while ByteIndex < BytesThisRound do
			local AbsoluteIndex = SqueezeOffset + ByteIndex
			local Lane = bit32.rshift(AbsoluteIndex, 3)
			local ByteInLane = bit32.band(AbsoluteIndex, 7)
			local LaneOffset = bit32.lshift(Lane, 2)

			if ByteInLane == 0 and ByteIndex + 8 <= BytesThisRound then
				buffer.writeu32(Output, OutOffset + Written + ByteIndex, buffer.readu32(LanesLow, LaneOffset))
				buffer.writeu32(Output, OutOffset + Written + ByteIndex + 4, buffer.readu32(LanesHigh, LaneOffset))
				ByteIndex += 8
			elseif ByteInLane == 0 and ByteIndex + 4 <= BytesThisRound then
				buffer.writeu32(Output, OutOffset + Written + ByteIndex, buffer.readu32(LanesLow, LaneOffset))
				ByteIndex += 4
			elseif ByteInLane == 4 and ByteIndex + 4 <= BytesThisRound then
				buffer.writeu32(Output, OutOffset + Written + ByteIndex, buffer.readu32(LanesHigh, LaneOffset))
				ByteIndex += 4
			else
				local Value
				if ByteInLane < 4 then
					Value = bit32.extract(buffer.readu32(LanesLow, LaneOffset), bit32.lshift(ByteInLane, 3), 8)
				else
					Value = bit32.extract(buffer.readu32(LanesHigh, LaneOffset), bit32.lshift(ByteInLane - 4, 3), 8)
				end
				buffer.writeu8(Output, OutOffset + Written + ByteIndex, Value)
				ByteIndex += 1
			end
		end

		Written += BytesThisRound
		SqueezeOffset += BytesThisRound
	end

	SqueezeOffset128 = SqueezeOffset
end

function XOF.Squeeze128(OutputBytes: number): buffer
	local Output = if OutputBytes == 168 then SqueezeBuffer128_168 else buffer.create(OutputBytes)
	XOF.Squeeze128Into(Output, OutputBytes, 0)
	return Output
end

function XOF.Squeeze256Into(Output: buffer, OutputBytes: number, OutputOffset: number?)
	local OutOffset = OutputOffset or 0
	local RateBytes = RATE_256
	local LanesLow = LanesLow256
	local LanesHigh = LanesHigh256
	local SqueezeOffset = SqueezeOffset256
	local ZeroBuffer = ZeroBuffer256

	local Written = 0
	while Written < OutputBytes do
		if SqueezeOffset >= RateBytes then
			Keccak(LanesLow, LanesHigh, ZeroBuffer, 0, RateBytes, RateBytes)
			SqueezeOffset = 0
		end

		local BytesThisRound = RateBytes - SqueezeOffset
		if BytesThisRound > OutputBytes - Written then
			BytesThisRound = OutputBytes - Written
		end

		local ByteIndex = 0
		while ByteIndex < BytesThisRound do
			local AbsoluteIndex = SqueezeOffset + ByteIndex
			local Lane = bit32.rshift(AbsoluteIndex, 3)
			local ByteInLane = bit32.band(AbsoluteIndex, 7)
			local LaneOffset = bit32.lshift(Lane, 2)

			if ByteInLane == 0 and ByteIndex + 8 <= BytesThisRound then
				buffer.writeu32(Output, OutOffset + Written + ByteIndex, buffer.readu32(LanesLow, LaneOffset))
				buffer.writeu32(Output, OutOffset + Written + ByteIndex + 4, buffer.readu32(LanesHigh, LaneOffset))
				ByteIndex += 8
			elseif ByteInLane == 0 and ByteIndex + 4 <= BytesThisRound then
				buffer.writeu32(Output, OutOffset + Written + ByteIndex, buffer.readu32(LanesLow, LaneOffset))
				ByteIndex += 4
			elseif ByteInLane == 4 and ByteIndex + 4 <= BytesThisRound then
				buffer.writeu32(Output, OutOffset + Written + ByteIndex, buffer.readu32(LanesHigh, LaneOffset))
				ByteIndex += 4
			else
				local Value
				if ByteInLane < 4 then
					Value = bit32.extract(buffer.readu32(LanesLow, LaneOffset), bit32.lshift(ByteInLane, 3), 8)
				else
					Value = bit32.extract(buffer.readu32(LanesHigh, LaneOffset), bit32.lshift(ByteInLane - 4, 3), 8)
				end
				buffer.writeu8(Output, OutOffset + Written + ByteIndex, Value)
				ByteIndex += 1
			end
		end

		Written += BytesThisRound
		SqueezeOffset += BytesThisRound
	end

	SqueezeOffset256 = SqueezeOffset
end

function XOF.Squeeze256(OutputBytes: number): buffer
	local Output = if OutputBytes == 128 then SqueezeBuffer256_128 
		elseif OutputBytes == 192 then SqueezeBuffer256_192 
		else buffer.create(OutputBytes)
	XOF.Squeeze256Into(Output, OutputBytes, 0)
	return Output
end

return XOF
