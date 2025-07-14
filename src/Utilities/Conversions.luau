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

local Conversions = {}

function Conversions.ToHex(Buffer: buffer): string
	local Length = buffer.len(Buffer)
	local Hex = buffer.create(Length * 2)

	local Leftover = Length % 4

	for Index = 0, Length - Leftover - 1, 4 do
		buffer.writestring(Hex, Index * 2, string.format("%08x", bit32.byteswap(buffer.readu32(Buffer, Index))))
	end

	for Index = Length - Leftover, Length - 1 do
		buffer.writestring(Hex, Index * 2, string.format("%02x", buffer.readu8(Buffer, Index)))
	end

	return buffer.tostring(Hex)
end

function Conversions.FromHex(Hex: string): buffer
	local Length = #Hex
	local Buffer = buffer.create(Length / 2)
	local Leftover = Length % 8

	for Index = 0, Length - Leftover - 1, 8 do
		local HexChunk = string.sub(Hex, Index + 1, Index + 8)
		local Value = tonumber(HexChunk, 16) :: number
		buffer.writeu32(Buffer, Index / 2, bit32.byteswap(Value))
	end

	for Index = Length - Leftover, Length - 2, 2 do
		buffer.writeu8(Buffer, Index / 2, tonumber(string.sub(Hex, Index + 1, Index + 2), 16) :: number)
	end

	return Buffer
end

return Conversions