--[=[
	Cryptography library: Keccak/SHA-3
	
	Sizes:
		SHA3-224 Digest: 28 bytes
		SHA3-256 Digest: 32 bytes
		SHA3-384 Digest: 48 bytes
		SHA3-512 Digest: 64 bytes
		SHAKE128 Digest: variable
		SHAKE256 Digest: variable

	Return type: string
	Example usage:
		local Message = buffer.fromstring("Hello World")
		
		local Result1 = SHA3_256(Message)
		local Result2 = SHAKE128(Message, 32)
--]=]

--!strict
--!optimize 2
--!native

local SHA3 = {}

local ENCODE_LOOKUP = buffer.create(256 * 2) do
	local HexChars = "0123456789abcdef"
	for Byte = 0, 255 do
		local HighNibble = bit32.rshift(Byte, 4)
		local LowNibble = Byte % 16

		local HighChar = string.byte(HexChars, HighNibble + 1)
		local LowChar = string.byte(HexChars, LowNibble + 1)

		local Combined = HighChar + bit32.lshift(LowChar, 8)
		buffer.writeu16(ENCODE_LOOKUP, Byte * 2, Combined)
	end
end

local LOW_ROUND, HIGH_ROUND = buffer.create(96), buffer.create(96) do
	local HighFactorKeccak = 0
	local ShiftRegister = 29
	local function GetNextBit(): number
		local Result = ShiftRegister % 2
		ShiftRegister = bit32.bxor((ShiftRegister - Result) // 2, 142 * Result)

		return Result
	end

	for Index = 0, 23 do
		local LowValue = 0
		local Multiplier: number

		for _ = 1, 6 do
			Multiplier = if Multiplier then Multiplier * Multiplier * 2 else 1
			LowValue += GetNextBit() * Multiplier
		end

		local HighValue = GetNextBit() * Multiplier
		buffer.writeu32(HIGH_ROUND, Index * 4, HighValue)
		buffer.writeu32(LOW_ROUND, Index * 4, LowValue + HighValue * HighFactorKeccak)
	end
end

local LANES_LOW = buffer.create(100)
local LANES_HIGH = buffer.create(100)

local function Keccak(LanesLow: buffer, LanesHigh: buffer, InputBuffer: buffer, Offset: number, Size: number, BlockSizeInBytes: number): ()
	local QuadWordsQuantity = BlockSizeInBytes // 8
	local RCHigh, RCLow = HIGH_ROUND, LOW_ROUND
	local XOR = bit32.bxor

	for Position = Offset, Offset + Size - 1, BlockSizeInBytes do
		for Index = 0, (QuadWordsQuantity - 1) * 4, 4 do
			local BufferPos = Position + Index * 2

			buffer.writeu32(LanesLow, Index, XOR(
				buffer.readu32(LanesLow, Index),
				buffer.readu32(InputBuffer, BufferPos)
				))

			buffer.writeu32(LanesHigh, Index, XOR(
				buffer.readu32(LanesHigh, Index),
				buffer.readu32(InputBuffer, BufferPos + 4)
				))
		end

		local Lane01Low, Lane01High = buffer.readu32(LanesLow, 0), buffer.readu32(LanesHigh, 0)
		local Lane02Low, Lane02High = buffer.readu32(LanesLow, 4), buffer.readu32(LanesHigh, 4)
		local Lane03Low, Lane03High = buffer.readu32(LanesLow, 8), buffer.readu32(LanesHigh, 8)

		local Lane04Low, Lane04High = buffer.readu32(LanesLow, 12), buffer.readu32(LanesHigh, 12)
		local Lane05Low, Lane05High = buffer.readu32(LanesLow, 16), buffer.readu32(LanesHigh, 16)
		local Lane06Low, Lane06High = buffer.readu32(LanesLow, 20), buffer.readu32(LanesHigh, 20)

		local Lane07Low, Lane07High = buffer.readu32(LanesLow, 24), buffer.readu32(LanesHigh, 24)
		local Lane08Low, Lane08High = buffer.readu32(LanesLow, 28), buffer.readu32(LanesHigh, 28)
		local Lane09Low, Lane09High = buffer.readu32(LanesLow, 32), buffer.readu32(LanesHigh, 32)

		local Lane10Low, Lane10High = buffer.readu32(LanesLow, 36), buffer.readu32(LanesHigh, 36)
		local Lane11Low, Lane11High = buffer.readu32(LanesLow, 40), buffer.readu32(LanesHigh, 40)
		local Lane12Low, Lane12High = buffer.readu32(LanesLow, 44), buffer.readu32(LanesHigh, 44)

		local Lane13Low, Lane13High = buffer.readu32(LanesLow, 48), buffer.readu32(LanesHigh, 48)
		local Lane14Low, Lane14High = buffer.readu32(LanesLow, 52), buffer.readu32(LanesHigh, 52)
		local Lane15Low, Lane15High = buffer.readu32(LanesLow, 56), buffer.readu32(LanesHigh, 56)

		local Lane16Low, Lane16High = buffer.readu32(LanesLow, 60), buffer.readu32(LanesHigh, 60)
		local Lane17Low, Lane17High = buffer.readu32(LanesLow, 64), buffer.readu32(LanesHigh, 64)
		local Lane18Low, Lane18High = buffer.readu32(LanesLow, 68), buffer.readu32(LanesHigh, 68)

		local Lane19Low, Lane19High = buffer.readu32(LanesLow, 72), buffer.readu32(LanesHigh, 72)
		local Lane20Low, Lane20High = buffer.readu32(LanesLow, 76), buffer.readu32(LanesHigh, 76)
		local Lane21Low, Lane21High = buffer.readu32(LanesLow, 80), buffer.readu32(LanesHigh, 80)

		local Lane22Low, Lane22High = buffer.readu32(LanesLow, 84), buffer.readu32(LanesHigh, 84)
		local Lane23Low, Lane23High = buffer.readu32(LanesLow, 88), buffer.readu32(LanesHigh, 88)
		local Lane24Low, Lane24High = buffer.readu32(LanesLow, 92), buffer.readu32(LanesHigh, 92)

		local Lane25Low, Lane25High = buffer.readu32(LanesLow, 96), buffer.readu32(LanesHigh, 96)

		for RoundIndex = 0, 92, 4 do
			local Column1Low, Column1High = XOR(Lane01Low, Lane06Low, Lane11Low, Lane16Low, Lane21Low), XOR(Lane01High, Lane06High, Lane11High, Lane16High, Lane21High)
			local Column2Low, Column2High = XOR(Lane02Low, Lane07Low, Lane12Low, Lane17Low, Lane22Low), XOR(Lane02High, Lane07High, Lane12High, Lane17High, Lane22High)
			local Column3Low, Column3High = XOR(Lane03Low, Lane08Low, Lane13Low, Lane18Low, Lane23Low), XOR(Lane03High, Lane08High, Lane13High, Lane18High, Lane23High)
			local Column4Low, Column4High = XOR(Lane04Low, Lane09Low, Lane14Low, Lane19Low, Lane24Low), XOR(Lane04High, Lane09High, Lane14High, Lane19High, Lane24High)
			local Column5Low, Column5High = XOR(Lane05Low, Lane10Low, Lane15Low, Lane20Low, Lane25Low), XOR(Lane05High, Lane10High, Lane15High, Lane20High, Lane25High)

			local DeltaLow, DeltaHigh = XOR(Column1Low, Column3Low * 2 + Column3High // 2147483648), XOR(Column1High, Column3High * 2 + Column3Low // 2147483648)
			local Temp0Low, Temp0High = XOR(DeltaLow, Lane02Low), XOR(DeltaHigh, Lane02High)
			local Temp1Low, Temp1High = XOR(DeltaLow, Lane07Low), XOR(DeltaHigh, Lane07High)
			local Temp2Low, Temp2High = XOR(DeltaLow, Lane12Low), XOR(DeltaHigh, Lane12High)
			local Temp3Low, Temp3High = XOR(DeltaLow, Lane17Low), XOR(DeltaHigh, Lane17High)
			local Temp4Low, Temp4High = XOR(DeltaLow, Lane22Low), XOR(DeltaHigh, Lane22High)

			Lane02Low = Temp1Low // 1048576 + (Temp1High * 4096); Lane02High = Temp1High // 1048576 + (Temp1Low * 4096)
			Lane07Low = Temp3Low // 524288 + (Temp3High * 8192); Lane07High = Temp3High // 524288 + (Temp3Low * 8192)
			Lane12Low = Temp0Low * 2 + Temp0High // 2147483648; Lane12High = Temp0High * 2 + Temp0Low // 2147483648
			Lane17Low = Temp2Low * 1024 + Temp2High // 4194304; Lane17High = Temp2High * 1024 + Temp2Low // 4194304
			Lane22Low = Temp4Low * 4 + Temp4High // 1073741824; Lane22High = Temp4High * 4 + Temp4Low // 1073741824

			DeltaLow = XOR(Column2Low, Column4Low * 2 + Column4High // 2147483648); DeltaHigh = XOR(Column2High, Column4High * 2 + Column4Low // 2147483648)
			Temp0Low = XOR(DeltaLow, Lane03Low); Temp0High = XOR(DeltaHigh, Lane03High)
			Temp1Low = XOR(DeltaLow, Lane08Low); Temp1High = XOR(DeltaHigh, Lane08High)
			Temp2Low = XOR(DeltaLow, Lane13Low); Temp2High = XOR(DeltaHigh, Lane13High)
			Temp3Low = XOR(DeltaLow, Lane18Low); Temp3High = XOR(DeltaHigh, Lane18High)
			Temp4Low = XOR(DeltaLow, Lane23Low); Temp4High = XOR(DeltaHigh, Lane23High)

			Lane03Low = Temp2Low // 2097152 + (Temp2High * 2048); Lane03High = Temp2High // 2097152 + (Temp2Low * 2048)
			Lane08Low = Temp4Low // 8 + bit32.bor(Temp4High * 536870912, 0); Lane08High = Temp4High // 8 + bit32.bor(Temp4Low * 536870912, 0)
			Lane13Low = Temp1Low * 64 + Temp1High // 67108864; Lane13High = Temp1High * 64 + Temp1Low // 67108864
			Lane18Low = (Temp3Low * 32768) + Temp3High // 131072; Lane18High = (Temp3High * 32768) + Temp3Low // 131072
			Lane23Low = Temp0Low // 4 + bit32.bor(Temp0High * 1073741824, 0); Lane23High = Temp0High // 4 + bit32.bor(Temp0Low * 1073741824, 0)

			DeltaLow = XOR(Column3Low, Column5Low * 2 + Column5High // 2147483648); DeltaHigh = XOR(Column3High, Column5High * 2 + Column5Low // 2147483648)
			Temp0Low = XOR(DeltaLow, Lane04Low); Temp0High = XOR(DeltaHigh, Lane04High)
			Temp1Low = XOR(DeltaLow, Lane09Low); Temp1High = XOR(DeltaHigh, Lane09High)
			Temp2Low = XOR(DeltaLow, Lane14Low); Temp2High = XOR(DeltaHigh, Lane14High)
			Temp3Low = XOR(DeltaLow, Lane19Low); Temp3High = XOR(DeltaHigh, Lane19High)
			Temp4Low = XOR(DeltaLow, Lane24Low); Temp4High = XOR(DeltaHigh, Lane24High)

			Lane04Low = bit32.bor(Temp3Low * 2097152, 0) + Temp3High // 2048; Lane04High = bit32.bor(Temp3High * 2097152, 0) + Temp3Low // 2048
			Lane09Low = bit32.bor(Temp0Low * 268435456, 0) + Temp0High // 16; Lane09High = bit32.bor(Temp0High * 268435456, 0) + Temp0Low // 16
			Lane14Low = bit32.bor(Temp2Low * 33554432, 0) + Temp2High // 128; Lane14High = bit32.bor(Temp2High * 33554432, 0) + Temp2Low // 128
			Lane19Low = Temp4Low // 256 + bit32.bor(Temp4High * 16777216, 0); Lane19High = Temp4High // 256 + bit32.bor(Temp4Low * 16777216, 0)
			Lane24Low = Temp1Low // 512 + bit32.bor(Temp1High * 8388608, 0); Lane24High = Temp1High // 512 + bit32.bor(Temp1Low * 8388608, 0)
			DeltaLow = XOR(Column4Low, Column1Low * 2 + Column1High // 2147483648); DeltaHigh = XOR(Column4High, Column1High * 2 + Column1Low // 2147483648)

			Temp0Low = XOR(DeltaLow, Lane05Low); Temp0High = XOR(DeltaHigh, Lane05High)
			Temp1Low = XOR(DeltaLow, Lane10Low); Temp1High = XOR(DeltaHigh, Lane10High)
			Temp2Low = XOR(DeltaLow, Lane15Low); Temp2High = XOR(DeltaHigh, Lane15High)
			Temp3Low = XOR(DeltaLow, Lane20Low); Temp3High = XOR(DeltaHigh, Lane20High)
			Temp4Low = XOR(DeltaLow, Lane25Low); Temp4High = XOR(DeltaHigh, Lane25High)

			Lane05Low = (Temp4Low * 16384) + Temp4High // 262144; Lane05High = (Temp4High * 16384) + Temp4Low // 262144
			Lane10Low = bit32.bor(Temp1Low * 1048576, 0) + Temp1High // 4096; Lane10High = bit32.bor(Temp1High * 1048576, 0) + Temp1Low // 4096
			Lane15Low = Temp3Low * 256 + Temp3High // 16777216; Lane15High = Temp3High * 256 + Temp3Low // 16777216
			Lane20Low = bit32.bor(Temp0Low * 134217728, 0) + Temp0High // 32; Lane20High = bit32.bor(Temp0High * 134217728, 0) + Temp0Low // 32
			Lane25Low = Temp2Low // 33554432 + Temp2High * 128; Lane25High = Temp2High // 33554432 + Temp2Low * 128

			DeltaLow = XOR(Column5Low, Column2Low * 2 + Column2High // 2147483648); DeltaHigh = XOR(Column5High, Column2High * 2 + Column2Low // 2147483648)
			Temp1Low = XOR(DeltaLow, Lane06Low); Temp1High = XOR(DeltaHigh, Lane06High)
			Temp2Low = XOR(DeltaLow, Lane11Low); Temp2High = XOR(DeltaHigh, Lane11High)
			Temp3Low = XOR(DeltaLow, Lane16Low); Temp3High = XOR(DeltaHigh, Lane16High)
			Temp4Low = XOR(DeltaLow, Lane21Low); Temp4High = XOR(DeltaHigh, Lane21High)
			Lane06Low = Temp2Low * 8 + Temp2High // 536870912; Lane06High = Temp2High * 8 + Temp2Low // 536870912
			Lane11Low = (Temp4Low * 262144) + Temp4High // 16384; Lane11High = (Temp4High * 262144) + Temp4Low // 16384
			Lane16Low = Temp1Low // 268435456 + Temp1High * 16; Lane16High = Temp1High // 268435456 + Temp1Low * 16
			Lane21Low = Temp3Low // 8388608 + Temp3High * 512; Lane21High = Temp3High // 8388608 + Temp3Low * 512
			Lane01Low = XOR(DeltaLow, Lane01Low); Lane01High = XOR(DeltaHigh, Lane01High)

			Lane01Low, Lane02Low, Lane03Low, Lane04Low, Lane05Low = XOR(Lane01Low, bit32.band(-1 - Lane02Low, Lane03Low)), XOR(Lane02Low, bit32.band(-1 - Lane03Low, Lane04Low)), XOR(Lane03Low, bit32.band(-1 - Lane04Low, Lane05Low)), XOR(Lane04Low, bit32.band(-1 - Lane05Low, Lane01Low)), XOR(Lane05Low, bit32.band(-1 - Lane01Low, Lane02Low)) :: number
			Lane01High, Lane02High, Lane03High, Lane04High, Lane05High = XOR(Lane01High, bit32.band(-1 - Lane02High, Lane03High)), XOR(Lane02High, bit32.band(-1 - Lane03High, Lane04High)), XOR(Lane03High, bit32.band(-1 - Lane04High, Lane05High)), XOR(Lane04High, bit32.band(-1 - Lane05High, Lane01High)), XOR(Lane05High, bit32.band(-1 - Lane01High, Lane02High)) :: number
			Lane06Low, Lane07Low, Lane08Low, Lane09Low, Lane10Low = XOR(Lane09Low, bit32.band(-1 - Lane10Low, Lane06Low)), XOR(Lane10Low, bit32.band(-1 - Lane06Low, Lane07Low)), XOR(Lane06Low, bit32.band(-1 - Lane07Low, Lane08Low)), XOR(Lane07Low, bit32.band(-1 - Lane08Low, Lane09Low)), XOR(Lane08Low, bit32.band(-1 - Lane09Low, Lane10Low)) :: number
			Lane06High, Lane07High, Lane08High, Lane09High, Lane10High = XOR(Lane09High, bit32.band(-1 - Lane10High, Lane06High)), XOR(Lane10High, bit32.band(-1 - Lane06High, Lane07High)), XOR(Lane06High, bit32.band(-1 - Lane07High, Lane08High)), XOR(Lane07High, bit32.band(-1 - Lane08High, Lane09High)), XOR(Lane08High, bit32.band(-1 - Lane09High, Lane10High)) :: number
			Lane11Low, Lane12Low, Lane13Low, Lane14Low, Lane15Low = XOR(Lane12Low, bit32.band(-1 - Lane13Low, Lane14Low)), XOR(Lane13Low, bit32.band(-1 - Lane14Low, Lane15Low)), XOR(Lane14Low, bit32.band(-1 - Lane15Low, Lane11Low)), XOR(Lane15Low, bit32.band(-1 - Lane11Low, Lane12Low)), XOR(Lane11Low, bit32.band(-1 - Lane12Low, Lane13Low)) :: number
			Lane11High, Lane12High, Lane13High, Lane14High, Lane15High = XOR(Lane12High, bit32.band(-1 - Lane13High, Lane14High)), XOR(Lane13High, bit32.band(-1 - Lane14High, Lane15High)), XOR(Lane14High, bit32.band(-1 - Lane15High, Lane11High)), XOR(Lane15High, bit32.band(-1 - Lane11High, Lane12High)), XOR(Lane11High, bit32.band(-1 - Lane12High, Lane13High)) :: number
			Lane16Low, Lane17Low, Lane18Low, Lane19Low, Lane20Low = XOR(Lane20Low, bit32.band(-1 - Lane16Low, Lane17Low)), XOR(Lane16Low, bit32.band(-1 - Lane17Low, Lane18Low)), XOR(Lane17Low, bit32.band(-1 - Lane18Low, Lane19Low)), XOR(Lane18Low, bit32.band(-1 - Lane19Low, Lane20Low)), XOR(Lane19Low, bit32.band(-1 - Lane20Low, Lane16Low)) :: number
			Lane16High, Lane17High, Lane18High, Lane19High, Lane20High = XOR(Lane20High, bit32.band(-1 - Lane16High, Lane17High)), XOR(Lane16High, bit32.band(-1 - Lane17High, Lane18High)), XOR(Lane17High, bit32.band(-1 - Lane18High, Lane19High)), XOR(Lane18High, bit32.band(-1 - Lane19High, Lane20High)), XOR(Lane19High, bit32.band(-1 - Lane20High, Lane16High)) :: number
			Lane21Low, Lane22Low, Lane23Low, Lane24Low, Lane25Low = XOR(Lane23Low, bit32.band(-1 - Lane24Low, Lane25Low)), XOR(Lane24Low, bit32.band(-1 - Lane25Low, Lane21Low)), XOR(Lane25Low, bit32.band(-1 - Lane21Low, Lane22Low)), XOR(Lane21Low, bit32.band(-1 - Lane22Low, Lane23Low)), XOR(Lane22Low, bit32.band(-1 - Lane23Low, Lane24Low)) :: number
			Lane21High, Lane22High, Lane23High, Lane24High, Lane25High = XOR(Lane23High, bit32.band(-1 - Lane24High, Lane25High)), XOR(Lane24High, bit32.band(-1 - Lane25High, Lane21High)), XOR(Lane25High, bit32.band(-1 - Lane21High, Lane22High)), XOR(Lane21High, bit32.band(-1 - Lane22High, Lane23High)), XOR(Lane22High, bit32.band(-1 - Lane23High, Lane24High)) :: number

			Lane01Low = XOR(Lane01Low, buffer.readu32(RCLow, RoundIndex))
			Lane01High = XOR(Lane01High, buffer.readu32(RCHigh, RoundIndex))
		end

		buffer.writeu32(LanesLow, 0, Lane01Low); buffer.writeu32(LanesHigh, 0, Lane01High)
		buffer.writeu32(LanesLow, 4, Lane02Low); buffer.writeu32(LanesHigh, 4, Lane02High)
		buffer.writeu32(LanesLow, 8, Lane03Low); buffer.writeu32(LanesHigh, 8, Lane03High)
		buffer.writeu32(LanesLow, 12, Lane04Low); buffer.writeu32(LanesHigh, 12, Lane04High)
		buffer.writeu32(LanesLow, 16, Lane05Low); buffer.writeu32(LanesHigh, 16, Lane05High)
		buffer.writeu32(LanesLow, 20, Lane06Low); buffer.writeu32(LanesHigh, 20, Lane06High)
		buffer.writeu32(LanesLow, 24, Lane07Low); buffer.writeu32(LanesHigh, 24, Lane07High)
		buffer.writeu32(LanesLow, 28, Lane08Low); buffer.writeu32(LanesHigh, 28, Lane08High)
		buffer.writeu32(LanesLow, 32, Lane09Low); buffer.writeu32(LanesHigh, 32, Lane09High)
		buffer.writeu32(LanesLow, 36, Lane10Low); buffer.writeu32(LanesHigh, 36, Lane10High)
		buffer.writeu32(LanesLow, 40, Lane11Low); buffer.writeu32(LanesHigh, 40, Lane11High)
		buffer.writeu32(LanesLow, 44, Lane12Low); buffer.writeu32(LanesHigh, 44, Lane12High)
		buffer.writeu32(LanesLow, 48, Lane13Low); buffer.writeu32(LanesHigh, 48, Lane13High)
		buffer.writeu32(LanesLow, 52, Lane14Low); buffer.writeu32(LanesHigh, 52, Lane14High)
		buffer.writeu32(LanesLow, 56, Lane15Low); buffer.writeu32(LanesHigh, 56, Lane15High)
		buffer.writeu32(LanesLow, 60, Lane16Low); buffer.writeu32(LanesHigh, 60, Lane16High)
		buffer.writeu32(LanesLow, 64, Lane17Low); buffer.writeu32(LanesHigh, 64, Lane17High)
		buffer.writeu32(LanesLow, 68, Lane18Low); buffer.writeu32(LanesHigh, 68, Lane18High)
		buffer.writeu32(LanesLow, 72, Lane19Low); buffer.writeu32(LanesHigh, 72, Lane19High)
		buffer.writeu32(LanesLow, 76, Lane20Low); buffer.writeu32(LanesHigh, 76, Lane20High)
		buffer.writeu32(LanesLow, 80, Lane21Low); buffer.writeu32(LanesHigh, 80, Lane21High)
		buffer.writeu32(LanesLow, 84, Lane22Low); buffer.writeu32(LanesHigh, 84, Lane22High)
		buffer.writeu32(LanesLow, 88, Lane23Low); buffer.writeu32(LanesHigh, 88, Lane23High)
		buffer.writeu32(LanesLow, 92, Lane24Low); buffer.writeu32(LanesHigh, 92, Lane24High)
		buffer.writeu32(LanesLow, 96, Lane25Low); buffer.writeu32(LanesHigh, 96, Lane25High)
	end
end

local function ProcessSponge(Message: buffer, CapacityBits: number, OutputBytes: number, DomainSeparator: number): (string, buffer)
	local RateBytes = (1600 - CapacityBits) // 8
	buffer.fill(LANES_LOW, 0, 0, 100)
	buffer.fill(LANES_HIGH, 0, 0, 100)

	local LanesLow = LANES_LOW
	local LanesHigh = LANES_HIGH

	local MessageLength: number = buffer.len(Message)
	local PaddedLength: number = MessageLength + 1

	local Remainder = PaddedLength % RateBytes
	if Remainder ~= 0 then
		PaddedLength += (RateBytes - Remainder)
	end

	local PaddedMessage = buffer.create(PaddedLength)

	if MessageLength > 0 then
		buffer.copy(PaddedMessage, 0, Message, 0, MessageLength)
	end

	if PaddedLength - MessageLength == 1 then
		buffer.writeu8(PaddedMessage, MessageLength, bit32.bor(DomainSeparator, 0x80))
	else
		buffer.writeu8(PaddedMessage, MessageLength, DomainSeparator)
		if PaddedLength - MessageLength > 2 then
			buffer.fill(PaddedMessage, MessageLength + 1, 0, PaddedLength - MessageLength - 2)
		end
		buffer.writeu8(PaddedMessage, PaddedLength - 1, 0x80)
	end

	Keccak(LanesLow, LanesHigh, PaddedMessage, 0, PaddedLength, RateBytes)

	local Output = buffer.create(OutputBytes)
	local Length = buffer.len(Output)
	local Hex = buffer.create(Length * 2)

	local Lookup = ENCODE_LOOKUP

	local Leftover = Length % 8
	local HexCursor = 0
	local OutputOffset = 0

	local ZeroBuffer = buffer.create(RateBytes)
	while OutputOffset < OutputBytes do
		local BytesThisRound = math.min(RateBytes, OutputBytes - OutputOffset)

		for ByteIndex = 0, BytesThisRound - 1 do
			local AbsoluteIndex = OutputOffset + ByteIndex
			if AbsoluteIndex < OutputBytes then
				local Lane = ByteIndex // 8
				local ByteInLane = ByteIndex % 8
				local LaneOffset = Lane * 4

				local Value
				if ByteInLane < 4 then
					Value = bit32.extract(buffer.readu32(LanesLow, LaneOffset), ByteInLane * 8, 8)
				else
					Value = bit32.extract(buffer.readu32(LanesHigh, LaneOffset), (ByteInLane - 4) * 8, 8)
				end
				buffer.writeu8(Output, AbsoluteIndex, Value)
			end
		end

		OutputOffset += BytesThisRound

		if OutputOffset < OutputBytes then
			Keccak(LanesLow, LanesHigh, ZeroBuffer, 0, RateBytes, RateBytes)
		end
	end

	for Index = 0, Length - Leftover - 1, 8 do
		local Hex1 = buffer.readu16(Lookup, buffer.readu8(Output, Index) * 2)
		local Hex2 = buffer.readu16(Lookup, buffer.readu8(Output, Index + 1) * 2)
		local Hex3 = buffer.readu16(Lookup, buffer.readu8(Output, Index + 2) * 2)
		local Hex4 = buffer.readu16(Lookup, buffer.readu8(Output, Index + 3) * 2)
		local Hex5 = buffer.readu16(Lookup, buffer.readu8(Output, Index + 4) * 2)
		local Hex6 = buffer.readu16(Lookup, buffer.readu8(Output, Index + 5) * 2)
		local Hex7 = buffer.readu16(Lookup, buffer.readu8(Output, Index + 6) * 2)
		local Hex8 = buffer.readu16(Lookup, buffer.readu8(Output, Index + 7) * 2)

		buffer.writeu16(Hex, HexCursor, Hex1)
		buffer.writeu16(Hex, HexCursor + 2, Hex2)
		buffer.writeu16(Hex, HexCursor + 4, Hex3)
		buffer.writeu16(Hex, HexCursor + 6, Hex4)
		buffer.writeu16(Hex, HexCursor + 8, Hex5)
		buffer.writeu16(Hex, HexCursor + 10, Hex6)
		buffer.writeu16(Hex, HexCursor + 12, Hex7)
		buffer.writeu16(Hex, HexCursor + 14, Hex8)

		HexCursor += 16
	end

	for Index = Length - Leftover, Length - 1 do
		local HexPair = buffer.readu16(Lookup, buffer.readu8(Output, Index) * 2)
		buffer.writeu16(Hex, HexCursor, HexPair)
		HexCursor += 2
	end
	
	return buffer.tostring(Hex), Output
end

function SHA3.SHA3_224(Message: buffer): (string, buffer)
	return ProcessSponge(Message, 448, 28, 0x06)
end

function SHA3.SHA3_256(Message: buffer): (string, buffer)
	return ProcessSponge(Message, 512, 32, 0x06)
end

function SHA3.SHA3_384(Message: buffer): (string, buffer)
	return ProcessSponge(Message, 768, 48, 0x06)
end

function SHA3.SHA3_512(Message: buffer): (string, buffer)
	return ProcessSponge(Message, 1024, 64, 0x06)
end

function SHA3.SHAKE128(Message: buffer, OutputBytes: number): (string, buffer)
	return ProcessSponge(Message, 256, OutputBytes, 0x1F)
end

function SHA3.SHAKE256(Message: buffer, OutputBytes: number): (string, buffer)
	return ProcessSponge(Message, 512, OutputBytes, 0x1F)
end

return SHA3