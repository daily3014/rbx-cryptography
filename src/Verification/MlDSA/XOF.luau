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

local ROUND_CONSTANTS = buffer.create(192) do
	local ShiftRegister = 29
	local function GetNextBit(): number
		local Result = ShiftRegister % 2
		ShiftRegister = bit32.bxor((ShiftRegister - Result) // 2, 142 * Result)
		return Result
	end

	local BitPositions = {0i, 1i, 3i, 7i, 15i, 31i, 63i}
	for Index = 0, 23 do
		local Value = 0i

		for j = 1, 7 do
			if GetNextBit() == 1 then
				Value = integer.bor(Value, integer.lshift(1i, BitPositions[j]))
			end
		end

		buffer.writeinteger(ROUND_CONSTANTS, Index * 8, Value)
	end
end

local function Keccak(Lanes: buffer, InputBuffer: buffer, Offset: number, Size: number, BlockSizeInBytes: number): ()
	local QuadWordsQuantity = BlockSizeInBytes // 8
	local RC = ROUND_CONSTANTS

	for Position = Offset, Offset + Size - 1, BlockSizeInBytes do
		for Index = 0, (QuadWordsQuantity - 1) * 8, 8 do
			local BufferPos = Position + Index

			buffer.writeinteger(Lanes, Index, integer.bxor(
				buffer.readinteger(Lanes, Index),
				buffer.readinteger(InputBuffer, BufferPos)
			))
		end

		local Lane01, Lane02, Lane03 = buffer.readinteger(Lanes, 0), buffer.readinteger(Lanes, 8), buffer.readinteger(Lanes, 16)
		local Lane04, Lane05, Lane06 = buffer.readinteger(Lanes, 24), buffer.readinteger(Lanes, 32), buffer.readinteger(Lanes, 40)
		local Lane07, Lane08, Lane09 = buffer.readinteger(Lanes, 48), buffer.readinteger(Lanes, 56), buffer.readinteger(Lanes, 64)
		local Lane10, Lane11, Lane12 = buffer.readinteger(Lanes, 72), buffer.readinteger(Lanes, 80), buffer.readinteger(Lanes, 88)
		local Lane13, Lane14, Lane15 = buffer.readinteger(Lanes, 96), buffer.readinteger(Lanes, 104), buffer.readinteger(Lanes, 112)
		local Lane16, Lane17, Lane18 = buffer.readinteger(Lanes, 120), buffer.readinteger(Lanes, 128), buffer.readinteger(Lanes, 136)
		local Lane19, Lane20, Lane21 = buffer.readinteger(Lanes, 144), buffer.readinteger(Lanes, 152), buffer.readinteger(Lanes, 160)
		local Lane22, Lane23, Lane24 = buffer.readinteger(Lanes, 168), buffer.readinteger(Lanes, 176), buffer.readinteger(Lanes, 184)
		local Lane25 = buffer.readinteger(Lanes, 192)

		for RoundIndex = 0, 184, 8 do
			local Column1 = integer.bxor(Lane01, Lane06, Lane11, Lane16, Lane21)
			local Column2 = integer.bxor(Lane02, Lane07, Lane12, Lane17, Lane22)
			local Column3 = integer.bxor(Lane03, Lane08, Lane13, Lane18, Lane23)
			local Column4 = integer.bxor(Lane04, Lane09, Lane14, Lane19, Lane24)
			local Column5 = integer.bxor(Lane05, Lane10, Lane15, Lane20, Lane25)

			local Delta = integer.bxor(Column1, integer.lrotate(Column3, 1i))

			local Temp0, Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane02), integer.bxor(Delta, Lane07), integer.bxor(Delta, Lane12), integer.bxor(Delta, Lane17), integer.bxor(Delta, Lane22)
			Lane02, Lane07, Lane12, Lane17, Lane22 = integer.rrotate(Temp1, 20i), integer.rrotate(Temp3, 19i), integer.rrotate(Temp0, 63i), integer.rrotate(Temp2, 54i), integer.rrotate(Temp4, 62i)
			Delta = integer.bxor(Column2, integer.rrotate(Column4, 63i))

			
			-- TYPE ERROR: type solver infers Temp4 to be nil after the theta step
			Temp0, Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane03), integer.bxor(Delta, Lane08), integer.bxor(Delta, Lane13), integer.bxor(Delta, Lane18), integer.bxor(Delta, Lane23) :: integer
			Lane03, Lane08, Lane13, Lane18, Lane23 = integer.rrotate(Temp2, 21i), integer.rrotate(Temp4, 3i), integer.rrotate(Temp1, 58i), integer.rrotate(Temp3, 49i), integer.rrotate(Temp0, 2i)
			Delta = integer.bxor(Column3, integer.rrotate(Column5, 63i))

			Temp0, Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane04), integer.bxor(Delta, Lane09), integer.bxor(Delta, Lane14), integer.bxor(Delta, Lane19), integer.bxor(Delta, Lane24) :: integer
			Lane04, Lane09, Lane14, Lane19, Lane24 = integer.rrotate(Temp3, 43i), integer.rrotate(Temp0, 36i), integer.rrotate(Temp2, 39i), integer.rrotate(Temp4, 8i), integer.rrotate(Temp1, 9i)
			Delta = integer.bxor(Column4, integer.rrotate(Column1, 63i))

			Temp0, Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane05), integer.bxor(Delta, Lane10), integer.bxor(Delta, Lane15), integer.bxor(Delta, Lane20), integer.bxor(Delta, Lane25) :: integer
			Lane05, Lane10, Lane15, Lane20, Lane25 = integer.rrotate(Temp4, 50i), integer.rrotate(Temp1, 44i), integer.rrotate(Temp3, 56i), integer.rrotate(Temp0, 37i), integer.rrotate(Temp2, 25i)
			Delta = integer.bxor(Column5, integer.rrotate(Column2, 63i))

			Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane06), integer.bxor(Delta, Lane11), integer.bxor(Delta, Lane16), integer.bxor(Delta, Lane21) :: integer
			Lane06, Lane11, Lane16, Lane21 = integer.rrotate(Temp2, 61i), integer.rrotate(Temp4, 46i), integer.rrotate(Temp1, 28i), integer.rrotate(Temp3, 23i)
			Lane01 = integer.bxor(Delta, Lane01)

			Lane01, Lane02, Lane03, Lane04, Lane05 =
				integer.bxor(Lane01, integer.band(integer.bnot(Lane02), Lane03)),
				integer.bxor(Lane02, integer.band(integer.bnot(Lane03), Lane04)),
				integer.bxor(Lane03, integer.band(integer.bnot(Lane04), Lane05)),
				integer.bxor(Lane04, integer.band(integer.bnot(Lane05), Lane01)),
				integer.bxor(Lane05, integer.band(integer.bnot(Lane01), Lane02))
			
			Lane06, Lane07, Lane08, Lane09, Lane10 =
				integer.bxor(Lane09, integer.band(integer.bnot(Lane10), Lane06)),
				integer.bxor(Lane10, integer.band(integer.bnot(Lane06), Lane07)),
				integer.bxor(Lane06, integer.band(integer.bnot(Lane07), Lane08)),
				integer.bxor(Lane07, integer.band(integer.bnot(Lane08), Lane09)),
				integer.bxor(Lane08, integer.band(integer.bnot(Lane09), Lane10))

			Lane11, Lane12, Lane13, Lane14, Lane15 =
				integer.bxor(Lane12, integer.band(integer.bnot(Lane13), Lane14)),
				integer.bxor(Lane13, integer.band(integer.bnot(Lane14), Lane15)),
				integer.bxor(Lane14, integer.band(integer.bnot(Lane15), Lane11)),
				integer.bxor(Lane15, integer.band(integer.bnot(Lane11), Lane12)),
				integer.bxor(Lane11, integer.band(integer.bnot(Lane12), Lane13))

			Lane16, Lane17, Lane18, Lane19, Lane20 =
				integer.bxor(Lane20, integer.band(integer.bnot(Lane16), Lane17)),	
				integer.bxor(Lane16, integer.band(integer.bnot(Lane17), Lane18)),
				integer.bxor(Lane17, integer.band(integer.bnot(Lane18), Lane19)),
				integer.bxor(Lane18, integer.band(integer.bnot(Lane19), Lane20)),
				integer.bxor(Lane19, integer.band(integer.bnot(Lane20), Lane16))

			-- TYPE ERROR: type solver infers Lane21-Lane25 to be integer? after this point
			Lane21, Lane22, Lane23, Lane24, Lane25 =
				(Lane21 :: any) :: integer,
				(Lane22 :: any) :: integer,
				(Lane23 :: any) :: integer,
				(Lane24 :: any) :: integer,
				(Lane25 :: any) :: integer

			Lane21, Lane22, Lane23, Lane24, Lane25 =
				integer.bxor(Lane23, integer.band(integer.bnot(Lane24), Lane25)),
				integer.bxor(Lane24, integer.band(integer.bnot(Lane25), Lane21)),
				integer.bxor(Lane25, integer.band(integer.bnot(Lane21), Lane22)),
				integer.bxor(Lane21, integer.band(integer.bnot(Lane22), Lane23)),
				integer.bxor(Lane22, integer.band(integer.bnot(Lane23), Lane24))

			Lane01 = integer.bxor(Lane01, buffer.readinteger(RC, RoundIndex))
		end

		-- TYPE ERROR: type solver infers Lane 5n to be integer? after this point
		Lane05, Lane10, Lane15, Lane20, Lane25 =
			(Lane05 :: any) :: integer,
			(Lane10 :: any) :: integer,
			(Lane15 :: any) :: integer,
			(Lane20 :: any) :: integer,
			(Lane25 :: any) :: integer

		buffer.writeinteger(Lanes, 0, Lane01)
		buffer.writeinteger(Lanes, 8, Lane02)
		buffer.writeinteger(Lanes, 16, Lane03)
		buffer.writeinteger(Lanes, 24, Lane04)
		buffer.writeinteger(Lanes, 32, Lane05)
		buffer.writeinteger(Lanes, 40, Lane06)
		buffer.writeinteger(Lanes, 48, Lane07)
		buffer.writeinteger(Lanes, 56, Lane08)
		buffer.writeinteger(Lanes, 64, Lane09)
		buffer.writeinteger(Lanes, 72, Lane10)
		buffer.writeinteger(Lanes, 80, Lane11)
		buffer.writeinteger(Lanes, 88, Lane12)
		buffer.writeinteger(Lanes, 96, Lane13)
		buffer.writeinteger(Lanes, 104, Lane14)
		buffer.writeinteger(Lanes, 112, Lane15)
		buffer.writeinteger(Lanes, 120, Lane16)
		buffer.writeinteger(Lanes, 128, Lane17)
		buffer.writeinteger(Lanes, 136, Lane18)
		buffer.writeinteger(Lanes, 144, Lane19)
		buffer.writeinteger(Lanes, 152, Lane20)
		buffer.writeinteger(Lanes, 160, Lane21)
		buffer.writeinteger(Lanes, 168, Lane22)
		buffer.writeinteger(Lanes, 176, Lane23)
		buffer.writeinteger(Lanes, 184, Lane24)
		buffer.writeinteger(Lanes, 192, Lane25)
	end
end

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

		local ByteIndex = 0
		while ByteIndex < BytesThisRound do
			local AbsoluteIndex = SqueezeOffset + ByteIndex
			local Lane = bit32.rshift(AbsoluteIndex, 3)
			local ByteInLane = bit32.band(AbsoluteIndex, 7)
			local LaneOffset = bit32.lshift(Lane, 3)

			local Value = buffer.readinteger(Lanes, LaneOffset)
			if ByteInLane == 0 and ByteIndex + 8 <= BytesThisRound then
				buffer.writeinteger(Output, OutOffset + Written + ByteIndex, Value)
				ByteIndex += 8
			elseif ByteInLane == 0 and ByteIndex + 4 <= BytesThisRound then
				buffer.writeu32(Output, OutOffset + Written + ByteIndex, integer.tonumber(integer.band(Value, 0xFFFFFFFFi)))
				ByteIndex += 4
			elseif ByteInLane == 4 and ByteIndex + 4 <= BytesThisRound then
				buffer.writeu32(Output, OutOffset + Written + ByteIndex, integer.tonumber(integer.rshift(Value, 32i)))
				ByteIndex += 4
			else
				local LaneValue = integer.extract(buffer.readinteger(Lanes, LaneOffset), integer.create(ByteInLane * 8), 8i)
				buffer.writeu8(Output, OutOffset + Written + ByteIndex, integer.tonumber(LaneValue))
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

		local ByteIndex = 0
		while ByteIndex < BytesThisRound do
			local AbsoluteIndex = SqueezeOffset + ByteIndex
			local Lane = bit32.rshift(AbsoluteIndex, 3)
			local ByteInLane = bit32.band(AbsoluteIndex, 7)
			local LaneOffset = bit32.lshift(Lane, 3)

			local Value = buffer.readinteger(Lanes, LaneOffset)
			if ByteInLane == 0 and ByteIndex + 8 <= BytesThisRound then
				buffer.writeinteger(Output, OutOffset + Written + ByteIndex, Value)
				ByteIndex += 8
			elseif ByteInLane == 0 and ByteIndex + 4 <= BytesThisRound then
				buffer.writeu32(Output, OutOffset + Written + ByteIndex, integer.tonumber(integer.band(Value, 0xFFFFFFFFi)))
				--buffer.writeu32(Output, OutOffset + Written + ByteIndex, integer.tonumber(integer.rshift(Value, 32i)))
				ByteIndex += 4
			elseif ByteInLane == 4 and ByteIndex + 4 <= BytesThisRound then
				buffer.writeu32(Output, OutOffset + Written + ByteIndex, integer.tonumber(integer.rshift(Value, 32i)))
				--buffer.writeu32(Output, OutOffset + Written + ByteIndex, integer.tonumber(integer.band(Value, 0xFFFFFFFFi)))
				ByteIndex += 4
			else
				local LaneValue = integer.extract(buffer.readinteger(Lanes, LaneOffset), integer.create(ByteInLane * 8), 8i)
				buffer.writeu8(Output, OutOffset + Written + ByteIndex, integer.tonumber(LaneValue))
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