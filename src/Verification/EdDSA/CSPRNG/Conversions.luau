--[=[
	Cryptography library: Conversions
	
	Return type: string / buffer
	Example Usage:
		local HexString = Conversions.ToHex(buffer.fromstring("Hello World"))
		local OriginalBuffer = Conversions.FromHex("48656c6c6f20576f726c64")
--]=]

--!strict
--!optimize 2
--!native

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


local DECODE_LOOKUP = buffer.create(65536 * 2) do
	for High = 0, 255 do
		for Low = 0, 255 do
			local HighNibble = 0
			local LowNibble = 0

			if High >= 48 and High <= 57 then
				HighNibble = High - 48
			elseif High >= 65 and High <= 70 then
				HighNibble = High - 55
			elseif High >= 97 and High <= 102 then
				HighNibble = High - 87
			else
				HighNibble = 0
			end

			if Low >= 48 and Low <= 57 then
				LowNibble = Low - 48
			elseif Low >= 65 and Low <= 70 then
				LowNibble = Low - 55
			elseif Low >= 97 and Low <= 102 then
				LowNibble = Low - 87
			else
				LowNibble = 0
			end

			local Combined = bit32.lshift(HighNibble, 4) + LowNibble
			local Index = bit32.lshift(Low, 8) + High
			buffer.writeu16(DECODE_LOOKUP, Index * 2, Combined)
		end
	end
end

local Conversions = {}

function Conversions.ToHex(Buffer: buffer): string
	local Length = buffer.len(Buffer)
	local Hex = buffer.create(Length * 2)

	local Leftover = Length % 8
	local HexCursor = 0

	for Index = 0, Length - Leftover - 1, 8 do
		local Hex1 = buffer.readu16(ENCODE_LOOKUP, buffer.readu8(Buffer, Index) * 2)
		local Hex2 = buffer.readu16(ENCODE_LOOKUP, buffer.readu8(Buffer, Index + 1) * 2)
		local Hex3 = buffer.readu16(ENCODE_LOOKUP, buffer.readu8(Buffer, Index + 2) * 2)
		local Hex4 = buffer.readu16(ENCODE_LOOKUP, buffer.readu8(Buffer, Index + 3) * 2)
		local Hex5 = buffer.readu16(ENCODE_LOOKUP, buffer.readu8(Buffer, Index + 4) * 2)
		local Hex6 = buffer.readu16(ENCODE_LOOKUP, buffer.readu8(Buffer, Index + 5) * 2)
		local Hex7 = buffer.readu16(ENCODE_LOOKUP, buffer.readu8(Buffer, Index + 6) * 2)
		local Hex8 = buffer.readu16(ENCODE_LOOKUP, buffer.readu8(Buffer, Index + 7) * 2)

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
		local HexPair = buffer.readu16(ENCODE_LOOKUP, buffer.readu8(Buffer, Index) * 2)
		buffer.writeu16(Hex, HexCursor, HexPair)
		HexCursor += 2
	end

	return buffer.tostring(Hex)
end

function Conversions.FromHex(Hex: string | buffer): buffer
	local BufferHex = if type(Hex) == "string" then buffer.fromstring(Hex) else Hex
	local Length = buffer.len(BufferHex)
	local Buffer = buffer.create(bit32.rshift(Length, 1))
	local Leftover = Length % 16
	local BufferCursor = 0

	for Index = 0, Length - Leftover - 1, 16 do
		local Pair1 = buffer.readu16(BufferHex, Index)
		local Pair2 = buffer.readu16(BufferHex, Index + 2)
		local Pair3 = buffer.readu16(BufferHex, Index + 4)
		local Pair4 = buffer.readu16(BufferHex, Index + 6)
		local Pair5 = buffer.readu16(BufferHex, Index + 8)
		local Pair6 = buffer.readu16(BufferHex, Index + 10)
		local Pair7 = buffer.readu16(BufferHex, Index + 12)
		local Pair8 = buffer.readu16(BufferHex, Index + 14)

		local Byte1 = buffer.readu16(DECODE_LOOKUP, Pair1 * 2)
		local Byte2 = buffer.readu16(DECODE_LOOKUP, Pair2 * 2)
		local Byte3 = buffer.readu16(DECODE_LOOKUP, Pair3 * 2)
		local Byte4 = buffer.readu16(DECODE_LOOKUP, Pair4 * 2)
		local Byte5 = buffer.readu16(DECODE_LOOKUP, Pair5 * 2)
		local Byte6 = buffer.readu16(DECODE_LOOKUP, Pair6 * 2)
		local Byte7 = buffer.readu16(DECODE_LOOKUP, Pair7 * 2)
		local Byte8 = buffer.readu16(DECODE_LOOKUP, Pair8 * 2)

		local Chunk1 = bit32.lshift(Byte4, 24) + bit32.lshift(Byte3, 16) + 
			bit32.lshift(Byte2, 8) + Byte1
		local Chunk2 = bit32.lshift(Byte8, 24) + bit32.lshift(Byte7, 16) + 
			bit32.lshift(Byte6, 8) + Byte5

		buffer.writeu32(Buffer, BufferCursor, Chunk1)
		buffer.writeu32(Buffer, BufferCursor + 4, Chunk2)
		BufferCursor += 8
	end

	for Index = Length - Leftover, Length - 1, 2 do
		local Pair = buffer.readu16(BufferHex, Index)
		local Byte = buffer.readu16(DECODE_LOOKUP, Pair * 2)
		buffer.writeu8(Buffer, BufferCursor, Byte)
		BufferCursor += 1
	end

	return Buffer
end

return Conversions