--[=[
	Stateful SHAKE XOF (Extensible Output Function)

	Non-OOP implementation with reusable state buffers.
	For ML-DSA sampling functions that use rejection sampling.

	Each stream is one shot: call Reset, then Absorb exactly once with the
	whole message, then Squeeze as many times as needed.

	Example usage:
		XOF.Reset128()
		XOF.Absorb128(message)
		local Chunk1 = XOF.Squeeze128(168)
		local Chunk2 = XOF.Squeeze128(168)
--]=]

--!strict
--!optimize 2
--!native

local SHA3 = require("./SHA3")
local Keccak = SHA3.Keccak_Internal
local Permute = SHA3.Permute_Internal
local Extract = SHA3.Extract_Internal

local RATE_128 = 168
local RATE_256 = 136

local StateA128 = buffer.create(100)
local StateB128 = buffer.create(100)
local Block128 = buffer.create(RATE_128)
local SqueezeOffset128 = 0
local Fresh128 = false

local StateA256 = buffer.create(100)
local StateB256 = buffer.create(100)
local Block256 = buffer.create(RATE_256)
local SqueezeOffset256 = 0
local Fresh256 = false

local PaddedBuffer128 = buffer.create(RATE_128)
local PaddedBuffer256 = buffer.create(RATE_256)

local XOF = {}

function XOF.Reset128()
	buffer.fill(StateA128, 0, 0, 100)
	buffer.fill(StateB128, 0, 0, 100)
	SqueezeOffset128 = 0
	Fresh128 = true
end

function XOF.Reset256()
	buffer.fill(StateA256, 0, 0, 100)
	buffer.fill(StateB256, 0, 0, 100)
	SqueezeOffset256 = 0
	Fresh256 = true
end

function XOF.Absorb128(Message: buffer)
	if not Fresh128 then
		error("Absorb128 must be called exactly once after Reset128", 2)
	end

	local MessageLength = buffer.len(Message)
	local RateBytes = RATE_128
	local TailLength = MessageLength % RateBytes
	local FullBytes = MessageLength - TailLength

	if FullBytes > 0 then
		Keccak(StateA128, StateB128, Message, 0, FullBytes, RateBytes, true)
	end

	local PaddedMessage = PaddedBuffer128
	buffer.fill(PaddedMessage, 0, 0, RateBytes)

	if TailLength > 0 then
		buffer.copy(PaddedMessage, 0, Message, FullBytes, TailLength)
	end

	if RateBytes - TailLength == 1 then
		buffer.writeu8(PaddedMessage, TailLength, 0x9F)
	else
		buffer.writeu8(PaddedMessage, TailLength, 0x1F)
		buffer.writeu8(PaddedMessage, RateBytes - 1, 0x80)
	end

	Keccak(StateA128, StateB128, PaddedMessage, 0, RateBytes, RateBytes, FullBytes == 0)
	Fresh128 = false
	SqueezeOffset128 = 0
	Extract(StateA128, StateB128, Block128, 0, RateBytes)
end


function XOF.Absorb256(Message: buffer)
	if not Fresh256 then
		error("Absorb256 must be called exactly once after Reset256", 2)
	end

	local MessageLength = buffer.len(Message)
	local RateBytes = RATE_256
	local TailLength = MessageLength % RateBytes
	local FullBytes = MessageLength - TailLength

	if FullBytes > 0 then
		Keccak(StateA256, StateB256, Message, 0, FullBytes, RateBytes, true)
	end

	local PaddedMessage = PaddedBuffer256
	buffer.fill(PaddedMessage, 0, 0, RateBytes)

	if TailLength > 0 then
		buffer.copy(PaddedMessage, 0, Message, FullBytes, TailLength)
	end

	if RateBytes - TailLength == 1 then
		buffer.writeu8(PaddedMessage, TailLength, 0x9F)
	else
		buffer.writeu8(PaddedMessage, TailLength, 0x1F)
		buffer.writeu8(PaddedMessage, RateBytes - 1, 0x80)
	end

	Keccak(StateA256, StateB256, PaddedMessage, 0, RateBytes, RateBytes, FullBytes == 0)
	Fresh256 = false
	SqueezeOffset256 = 0
	Extract(StateA256, StateB256, Block256, 0, RateBytes)
end


function XOF.Squeeze128Into(Output: buffer, OutputBytes: number, OutputOffset: number?)
	local OutOffset = OutputOffset or 0
	local SqueezeOffset = SqueezeOffset128
	local Block = Block128

	local Written = 0
	while Written < OutputBytes do
		if SqueezeOffset >= RATE_128 then
			Permute(StateA128, StateB128)
			Extract(StateA128, StateB128, Block, 0, RATE_128)
			SqueezeOffset = 0
		end

		local BytesThisRound = math.min(RATE_128 - SqueezeOffset, OutputBytes - Written)
		buffer.copy(Output, OutOffset + Written, Block, SqueezeOffset, BytesThisRound)

		Written += BytesThisRound
		SqueezeOffset += BytesThisRound
	end

	SqueezeOffset128 = SqueezeOffset
end

function XOF.Squeeze128(OutputBytes: number): buffer
	local Output = buffer.create(OutputBytes)
	XOF.Squeeze128Into(Output, OutputBytes, 0)
	return Output
end

function XOF.Squeeze256Into(Output: buffer, OutputBytes: number, OutputOffset: number?)
	local OutOffset = OutputOffset or 0
	local SqueezeOffset = SqueezeOffset256
	local Block = Block256

	local Written = 0
	while Written < OutputBytes do
		if SqueezeOffset >= RATE_256 then
			Permute(StateA256, StateB256)
			Extract(StateA256, StateB256, Block, 0, RATE_256)
			SqueezeOffset = 0
		end

		local BytesThisRound = math.min(RATE_256 - SqueezeOffset, OutputBytes - Written)
		buffer.copy(Output, OutOffset + Written, Block, SqueezeOffset, BytesThisRound)

		Written += BytesThisRound
		SqueezeOffset += BytesThisRound
	end

	SqueezeOffset256 = SqueezeOffset
end

function XOF.Squeeze256(OutputBytes: number): buffer
	local Output = buffer.create(OutputBytes)
	XOF.Squeeze256Into(Output, OutputBytes, 0)
	return Output
end

return XOF
