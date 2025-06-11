--!strict
--!native
--!optimize 2

local Conversions = {}

function Conversions.ToHex(Buffer: buffer): string
	local Hex = table.create(buffer.len(Buffer))
	for Index = 0, buffer.len(Buffer) - 1 do
		table.insert(Hex, string.format("%02x", buffer.readu8(Buffer, Index)))
	end

	return table.concat(Hex)
end

function Conversions.FromHex(Hex: string): buffer
	local Length = #Hex
	local Buffer = buffer.create(Length / 2)
	for Index = 0, Length - 2, 2 do
		buffer.writeu8(Buffer, Index / 2, tonumber(string.sub(Hex, Index + 1, Index + 2), 16) :: number)
	end

	return Buffer
end

function Conversions.BytesStrToHex(BytesStr: string): string
	local hex = table.create(#BytesStr)
	for i = 1, #BytesStr do
		hex[i] = string.format("%02x", string.byte(BytesStr, i))
	end
	return table.concat(hex)
end

function Conversions.HexToBytesStr(Hex: string): string
	Hex = string.gsub(Hex, "^0x", "")
	Hex = string.gsub(Hex, " ", "")

	assert(#Hex % 2 == 0, "Hex string must have even length")

	local BytesStr = table.create(#Hex / 2)
	for i = 1, #Hex, 2 do
		local byte = tonumber(string.sub(Hex, i, i + 1), 16)
		assert(byte, "Invalid hex string")
		table.insert(BytesStr, string.char(byte))
	end

	return table.concat(BytesStr)
end

return Conversions
