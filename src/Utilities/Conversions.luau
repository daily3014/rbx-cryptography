--[=[
	Cryptography library: Conversions
	
	Return type: string (ToHex) / buffer (FromHex)
	Example Usage:
		local Message = buffer.fromstring("Hello World")
		
		--------Usage Case 1--------
		local HexString = Conversions.ToHex(Message)
		
		--------Usage Case 2--------
		local OriginalBuffer = Conversions.FromHex("48656c6c6f20576f726c64")
--]=]

--!optimize 2
--!native
--!strict

local Conversions = {}

function Conversions.ToHex(Buffer: buffer): string
	local Hex = ""
	for Index = 0, buffer.len(Buffer) - 1 do
		Hex ..= string.format("%02x", buffer.readu8(Buffer, Index))
	end
	
	return Hex
end

function Conversions.FromHex(Hex: string): buffer
	local Length = #Hex
	local Buffer = buffer.create(Length / 2)
	for Index = 0, Length - 2, 2 do
		buffer.writeu8(Buffer, Index / 2, tonumber(string.sub(Hex, Index + 1, Index + 2), 16) :: number)
	end
	
	return Buffer
end

return Conversions