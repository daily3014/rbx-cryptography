--[=[
	Cryptography library: CRC32
	Function can return JAM or ISO-HDLC CRC32 checksums.
	
	Return type: number in regular mode, string in hex mode
	Example Usage:
		local Message = buffer.fromstring("Hello World")
		
		--------Usage Case 1--------
		local Hash = CRC32(Message)
		ISO-HDLC by default
		
		--------Usage Case 2--------
		local Hash = CRC32(Message, "Jam")
		JAM Version
		
		--------Usage Case 3--------
		local Hash = CRC32(Message, "Jam", true)
		Hash is returned as the hexadecimal representation (string)
--]=]

--!strict
--!optimize 2
--!native

local CRC32_LOOKUP = table.create(256)
for Index = 0, 255 do
	local CRC = Index
	for _ = 1, 8 do
		if bit32.band(CRC, 1) == 1 then
			CRC = bit32.bxor(bit32.rshift(CRC, 1), 0xEDB88320)
		else
			CRC = bit32.rshift(CRC, 1)
		end
	end

	CRC32_LOOKUP[Index + 1] = CRC
end

local function CRC32(Message: buffer, Mode: "Jam" | "Iso"?, Hex: boolean?): number | string
	local Lookup = CRC32_LOOKUP
	local Hash = 0xFFFFFFFF

	local Leftover = buffer.len(Message) % 4
	
	for Index = 0, Leftover - 1 do
		local Value = buffer.readu8(Message, Index)
		local TableIndex = bit32.band(bit32.bxor(Hash, Value), 0xFF) + 1

		Hash = bit32.bxor(
			Lookup[TableIndex],
			bit32.rshift(Hash, 8)
		)
	end
	
	for Index = Leftover, buffer.len(Message) - 1, 4 do
		local TableIndex = bit32.band(bit32.bxor(Hash, buffer.readu8(Message, Index)), 0xFF) + 1
		Hash = bit32.bxor(Lookup[TableIndex], bit32.rshift(Hash, 8))
		
		TableIndex = bit32.band(bit32.bxor(Hash, buffer.readu8(Message, Index + 1)), 0xFF) + 1
		Hash = bit32.bxor(Lookup[TableIndex], bit32.rshift(Hash, 8))
		
		TableIndex = bit32.band(bit32.bxor(Hash, buffer.readu8(Message, Index + 2)), 0xFF) + 1
		Hash = bit32.bxor(Lookup[TableIndex], bit32.rshift(Hash, 8))

		TableIndex = bit32.band(bit32.bxor(Hash, buffer.readu8(Message, Index + 3)), 0xFF) + 1
		Hash = bit32.bxor(Lookup[TableIndex], bit32.rshift(Hash, 8))
	end

	if Mode == "Jam" then
		return Hex == true and string.format("%08x", Hash) or Hash
	end

	Hash = bit32.bxor(Hash, 0xFFFFFFFF)
	return Hex == true and string.format("%08x", Hash) or Hash
end

return CRC32