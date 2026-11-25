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

type Stream = {
	StateA: buffer,
	StateB: buffer,
	Block: buffer,
	Padded: buffer,
	Rate: number,
	Name: string,
	CanAbsorb: boolean,
	HasUnreadState: boolean,
	SqueezeOffset: number,
}

local function NewStream(Rate: number, Name: string): Stream
	return {
		StateA = buffer.create(100),
		StateB = buffer.create(100),
		Block = buffer.create(Rate),
		Padded = buffer.create(Rate),
		Rate = Rate,
		Name = Name,
		CanAbsorb = false,
		HasUnreadState = false,
		SqueezeOffset = Rate,
	}
end

local STREAM_128 = NewStream(168, "128")
local STREAM_256 = NewStream(136, "256")

local function Reset(Stream: Stream)
	Stream.CanAbsorb = true
	Stream.HasUnreadState = false
	Stream.SqueezeOffset = Stream.Rate
end

local function AbsorbShort(Stream: Stream, Message: buffer, Length: number)
	local StateA, StateB = Stream.StateA, Stream.StateB
	local Padded = Stream.Padded
	local Rate = Stream.Rate
	local Lanes = bit32.rshift(Length, 3) + 1
	local LastLane = Rate / 8 - 1

	buffer.fill(StateA, 0, 0, 100)
	buffer.fill(StateB, 0, 0, 100)
	buffer.fill(Padded, 0, 0, Lanes * 8)
	buffer.fill(Padded, Rate - 8, 0, 8)
	buffer.copy(Padded, 0, Message, 0, Length)
	buffer.writeu8(Padded, Length, 0x1F)
	buffer.writeu8(Padded, Rate - 1, bit32.bor(buffer.readu8(Padded, Rate - 1), 0x80))

	for Lane = 0, LastLane do
		if Lane < Lanes or Lane == LastLane then
			local Lo, Hi = buffer.readu32(Padded, Lane * 8), buffer.readu32(Padded, Lane * 8 + 4)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			buffer.writeu32(StateA, Lane * 4, bit32.bor(bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, Lane * 4, bit32.bor(bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
		end
	end

	Permute(StateA, StateB)
end

local function AbsorbLong(Stream: Stream, Message: buffer, Length: number)
	local Rate = Stream.Rate
	local TailLength = Length % Rate
	local FullBytes = Length - TailLength
	Keccak(Stream.StateA, Stream.StateB, Message, 0, FullBytes, Rate, true)

	local Padded = Stream.Padded
	buffer.fill(Padded, 0, 0, Rate)
	buffer.copy(Padded, 0, Message, FullBytes, TailLength)
	buffer.writeu8(Padded, TailLength, 0x1F)
	buffer.writeu8(Padded, Rate - 1, bit32.bor(buffer.readu8(Padded, Rate - 1), 0x80))
	Keccak(Stream.StateA, Stream.StateB, Padded, 0, Rate, Rate, false)
end

local function Absorb(Stream: Stream, Message: buffer)
	if not Stream.CanAbsorb then
		error(`Absorb{Stream.Name} must be called exactly once after Reset{Stream.Name}`, 3)
	end

	local Length = buffer.len(Message)
	if Length < Stream.Rate then
		AbsorbShort(Stream, Message, Length)
	else
		AbsorbLong(Stream, Message, Length)
	end

	Stream.CanAbsorb = false
	Stream.HasUnreadState = true
	Stream.SqueezeOffset = Stream.Rate
end

local function SqueezeInto(Stream: Stream, Output: buffer, OutputBytes: number, OutputOffset: number)
	local StateA, StateB = Stream.StateA, Stream.StateB
	local Block = Stream.Block
	local Rate = Stream.Rate
	local SqueezeOffset = Stream.SqueezeOffset
	local Written = 0

	while Written < OutputBytes do
		if SqueezeOffset >= Rate then
			if Stream.HasUnreadState then
				Stream.HasUnreadState = false
			else
				Permute(StateA, StateB)
			end

			if OutputBytes - Written >= Rate then
				Extract(StateA, StateB, Output, OutputOffset + Written, Rate)
				Written += Rate
				continue
			end

			Extract(StateA, StateB, Block, 0, Rate)
			SqueezeOffset = 0
		end

		local BytesThisRound = math.min(Rate - SqueezeOffset, OutputBytes - Written)
		buffer.copy(Output, OutputOffset + Written, Block, SqueezeOffset, BytesThisRound)
		Written += BytesThisRound
		SqueezeOffset += BytesThisRound
	end

	Stream.SqueezeOffset = SqueezeOffset
end

local XOF = {}

function XOF.Reset128()
	Reset(STREAM_128)
end

function XOF.Reset256()
	Reset(STREAM_256)
end

function XOF.Absorb128(Message: buffer)
	Absorb(STREAM_128, Message)
end

function XOF.Absorb256(Message: buffer)
	Absorb(STREAM_256, Message)
end

function XOF.Squeeze128Into(Output: buffer, OutputBytes: number, OutputOffset: number?)
	SqueezeInto(STREAM_128, Output, OutputBytes, OutputOffset or 0)
end

function XOF.Squeeze128(OutputBytes: number): buffer
	local Output = buffer.create(OutputBytes)
	SqueezeInto(STREAM_128, Output, OutputBytes, 0)
	return Output
end

function XOF.Squeeze256Into(Output: buffer, OutputBytes: number, OutputOffset: number?)
	SqueezeInto(STREAM_256, Output, OutputBytes, OutputOffset or 0)
end

function XOF.Squeeze256(OutputBytes: number): buffer
	local Output = buffer.create(OutputBytes)
	SqueezeInto(STREAM_256, Output, OutputBytes, 0)
	return Output
end

return XOF
