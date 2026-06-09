--[=[
	Stateful SHAKE XOF (Extensible Output Function)
	
	Non-OOP implementation with reusable state buffers.
	For ML-DSA sampling functions that use rejection sampling.
	
	Example usage:
		local XOF = require(script)
		
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

local Lanes128 = buffer.create(200)
local SqueezeOffset128 = 0

local Lanes256 = buffer.create(200)
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
	buffer.fill(Lanes128, 0, 0)
	SqueezeOffset128 = 0
end

function XOF.Reset256()
	buffer.fill(Lanes256, 0, 0)
	SqueezeOffset256 = 0
end

function XOF.Absorb128(Message: buffer)
	local MessageLength = buffer.len(Message)
	local RateBytes = RATE_128

	if MessageLength >= RateBytes then
		error(`Absorb128 supports messages up to {RateBytes - 1} bytes, got {MessageLength}`, 2)
	end

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

	Keccak(Lanes128, PaddedMessage, 0, RateBytes, RateBytes)
end

function XOF.Absorb256(Message: buffer)
	local MessageLength = buffer.len(Message)
	local RateBytes = RATE_256

	if MessageLength >= RateBytes then
		error(`Absorb256 supports messages up to {RateBytes - 1} bytes, got {MessageLength}`, 2)
	end

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

	Keccak(Lanes256, PaddedMessage, 0, RateBytes, RateBytes)
end

function XOF.Squeeze128Into(Output: buffer, OutputBytes: number, OutputOffset: number?)
	local OutOffset = OutputOffset or 0
	local RateBytes = RATE_128
	local Lanes = Lanes128
	local SqueezeOffset = SqueezeOffset128
	local ZeroBuffer = ZeroBuffer128

	local Written = 0
	while Written < OutputBytes do
		if SqueezeOffset >= RateBytes then
			Keccak(Lanes, ZeroBuffer, 0, RateBytes, RateBytes)
			SqueezeOffset = 0
		end

		local BytesThisRound = RateBytes - SqueezeOffset
		if BytesThisRound > OutputBytes - Written then
			BytesThisRound = OutputBytes - Written
		end

		buffer.copy(Output, OutOffset + Written, Lanes, SqueezeOffset, BytesThisRound)
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
	local Lanes = Lanes256
	local SqueezeOffset = SqueezeOffset256
	local ZeroBuffer = ZeroBuffer256

	local Written = 0
	while Written < OutputBytes do
		if SqueezeOffset >= RateBytes then
			Keccak(Lanes, ZeroBuffer, 0, RateBytes, RateBytes)
			SqueezeOffset = 0
		end

		local BytesThisRound = RateBytes - SqueezeOffset
		if BytesThisRound > OutputBytes - Written then
			BytesThisRound = OutputBytes - Written
		end

		buffer.copy(Output, OutOffset + Written, Lanes, SqueezeOffset, BytesThisRound)
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
