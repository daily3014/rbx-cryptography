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

local ENCODE_PAIR = buffer.create(65536 * 4)
local ENCODE_LOOKUP = buffer.create(256 * 2) do
	local HexChars = "0123456789abcdef"
	for Byte = 0, 255 do
		local HighChar = string.byte(HexChars, bit32.rshift(Byte, 4) + 1)
		local LowChar = string.byte(HexChars, bit32.band(Byte, 15) + 1)
		buffer.writeu16(ENCODE_LOOKUP, Byte * 2, bit32.bor(HighChar, bit32.lshift(LowChar, 8)))
	end

	for High = 0, 255 do
		local HighPair = bit32.lshift(buffer.readu16(ENCODE_LOOKUP, High * 2), 16)
		for Low = 0, 255 do
			buffer.writeu32(ENCODE_PAIR, (High * 256 + Low) * 4, bit32.bor(buffer.readu16(ENCODE_LOOKUP, Low * 2), HighPair))
		end
	end
end

local DECODE_LOOKUP = buffer.create(65536) do
	local Nibbles = buffer.create(256)
	for Char = 48, 57 do
		buffer.writeu8(Nibbles, Char, Char - 48)
	end
	for Char = 65, 70 do
		buffer.writeu8(Nibbles, Char, Char - 55)
	end
	for Char = 97, 102 do
		buffer.writeu8(Nibbles, Char, Char - 87)
	end

	for Second = 0, 255 do
		local Low = buffer.readu8(Nibbles, Second)
		for First = 0, 255 do
			buffer.writeu8(DECODE_LOOKUP, Second * 256 + First, buffer.readu8(Nibbles, First) * 16 + Low)
		end
	end
end

local Conversions = {}

function Conversions.ToHex(Buffer: buffer): string
	local Length = buffer.len(Buffer)
	local Hex = buffer.create(Length * 2)
	local Pairs = ENCODE_PAIR

	local Leftover = Length % 16
	local Body = Length - Leftover

	for Index = 0, Body - 16, 16 do
		local Word0 = buffer.readu32(Buffer, Index)
		local Word1 = buffer.readu32(Buffer, Index + 4)
		local Word2 = buffer.readu32(Buffer, Index + 8)
		local Word3 = buffer.readu32(Buffer, Index + 12)
		local Cursor = Index * 2

		buffer.writeu32(Hex, Cursor, buffer.readu32(Pairs, bit32.lshift(bit32.band(Word0, 0xffff), 2)))
		buffer.writeu32(Hex, Cursor + 4, buffer.readu32(Pairs, bit32.band(bit32.rshift(Word0, 14), 0x3fffc)))
		buffer.writeu32(Hex, Cursor + 8, buffer.readu32(Pairs, bit32.lshift(bit32.band(Word1, 0xffff), 2)))
		buffer.writeu32(Hex, Cursor + 12, buffer.readu32(Pairs, bit32.band(bit32.rshift(Word1, 14), 0x3fffc)))
		buffer.writeu32(Hex, Cursor + 16, buffer.readu32(Pairs, bit32.lshift(bit32.band(Word2, 0xffff), 2)))
		buffer.writeu32(Hex, Cursor + 20, buffer.readu32(Pairs, bit32.band(bit32.rshift(Word2, 14), 0x3fffc)))
		buffer.writeu32(Hex, Cursor + 24, buffer.readu32(Pairs, bit32.lshift(bit32.band(Word3, 0xffff), 2)))
		buffer.writeu32(Hex, Cursor + 28, buffer.readu32(Pairs, bit32.band(bit32.rshift(Word3, 14), 0x3fffc)))
	end

	local Lookup = ENCODE_LOOKUP
	for Index = Body, Length - 1 do
		buffer.writeu16(Hex, Index * 2, buffer.readu16(Lookup, bit32.lshift(buffer.readu8(Buffer, Index), 1)))
	end

	return buffer.tostring(Hex)
end

function Conversions.FromHex(Hex: string | buffer): buffer
	local BufferHex = if type(Hex) == "string" then buffer.fromstring(Hex) else Hex
	local Length = buffer.len(BufferHex)
	if Length % 2 ~= 0 then
		error(`Length must be even, got {Length}`)
	end

	local Buffer = buffer.create(bit32.rshift(Length, 1))
	local Leftover = Length % 16
	local Body = Length - Leftover
	local Lookup = DECODE_LOOKUP

	for Index = 0, Body - 16, 16 do
		local Word0 = buffer.readu32(BufferHex, Index)
		local Word1 = buffer.readu32(BufferHex, Index + 4)
		local Word2 = buffer.readu32(BufferHex, Index + 8)
		local Word3 = buffer.readu32(BufferHex, Index + 12)
		local Cursor = bit32.rshift(Index, 1)

		buffer.writeu32(Buffer, Cursor, bit32.bor(
			buffer.readu8(Lookup, bit32.band(Word0, 0xffff)),
			bit32.lshift(buffer.readu8(Lookup, bit32.rshift(Word0, 16)), 8),
			bit32.lshift(buffer.readu8(Lookup, bit32.band(Word1, 0xffff)), 16),
			bit32.lshift(buffer.readu8(Lookup, bit32.rshift(Word1, 16)), 24)
		))
		buffer.writeu32(Buffer, Cursor + 4, bit32.bor(
			buffer.readu8(Lookup, bit32.band(Word2, 0xffff)),
			bit32.lshift(buffer.readu8(Lookup, bit32.rshift(Word2, 16)), 8),
			bit32.lshift(buffer.readu8(Lookup, bit32.band(Word3, 0xffff)), 16),
			bit32.lshift(buffer.readu8(Lookup, bit32.rshift(Word3, 16)), 24)
		))
	end

	for Index = Body, Length - 2, 2 do
		buffer.writeu8(Buffer, bit32.rshift(Index, 1), buffer.readu8(Lookup, buffer.readu16(BufferHex, Index)))
	end

	return Buffer
end

return Conversions
