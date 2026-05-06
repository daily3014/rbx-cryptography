--[=[
	Cryptography library: CRC32
	
	Specifications:
		Polynomial: 0xEDB88320 (reversed)
		Output: 32-bit unsigned integer
		Method: Slicing-by-8 algorithm with precomputed tables
	
	Return type: number
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Hash = CRC32(Message)
--]=]

--!strict
--!optimize 2
--!native

local TABLE_0 = buffer.create(1024)
local TABLE_1 = buffer.create(1024)
local TABLE_2 = buffer.create(1024)
local TABLE_3 = buffer.create(1024)
local TABLE_4 = buffer.create(1024)
local TABLE_5 = buffer.create(1024)
local TABLE_6 = buffer.create(1024)
local TABLE_7 = buffer.create(1024)

do
	for Index = 0, 255 do
		local CRC = Index
		for _ = 1, 8 do
			if bit32.band(CRC, 1) == 1 then
				CRC = bit32.bxor(bit32.rshift(CRC, 1), 0xEDB88320)
			else
				CRC = bit32.rshift(CRC, 1)
			end
		end
		buffer.writeu32(TABLE_0, Index * 4, CRC)
	end

	for Index = 0, 255 do
		local CRC = buffer.readu32(TABLE_0, Index * 4)
		CRC = bit32.bxor(buffer.readu32(TABLE_0, bit32.band(CRC, 0xFF) * 4), bit32.rshift(CRC, 8))
		buffer.writeu32(TABLE_1, Index * 4, CRC)
		CRC = bit32.bxor(buffer.readu32(TABLE_0, bit32.band(CRC, 0xFF) * 4), bit32.rshift(CRC, 8))
		buffer.writeu32(TABLE_2, Index * 4, CRC)
		CRC = bit32.bxor(buffer.readu32(TABLE_0, bit32.band(CRC, 0xFF) * 4), bit32.rshift(CRC, 8))
		buffer.writeu32(TABLE_3, Index * 4, CRC)
		CRC = bit32.bxor(buffer.readu32(TABLE_0, bit32.band(CRC, 0xFF) * 4), bit32.rshift(CRC, 8))
		buffer.writeu32(TABLE_4, Index * 4, CRC)
		CRC = bit32.bxor(buffer.readu32(TABLE_0, bit32.band(CRC, 0xFF) * 4), bit32.rshift(CRC, 8))
		buffer.writeu32(TABLE_5, Index * 4, CRC)
		CRC = bit32.bxor(buffer.readu32(TABLE_0, bit32.band(CRC, 0xFF) * 4), bit32.rshift(CRC, 8))
		buffer.writeu32(TABLE_6, Index * 4, CRC)
		CRC = bit32.bxor(buffer.readu32(TABLE_0, bit32.band(CRC, 0xFF) * 4), bit32.rshift(CRC, 8))
		buffer.writeu32(TABLE_7, Index * 4, CRC)
	end
end

local function CRC32(Buffer: buffer): number
	local Length = buffer.len(Buffer)
	local CRC = 0xFFFFFFFF
	local Index = 0
	local Aligned = Length - 7

	local T0 = TABLE_0
	local T1 = TABLE_1
	local T2 = TABLE_2
	local T3 = TABLE_3
	local T4 = TABLE_4
	local T5 = TABLE_5
	local T6 = TABLE_6
	local T7 = TABLE_7

	while Index < Aligned do
		local Word0 = bit32.bxor(CRC, buffer.readu32(Buffer, Index))
		local Word1 = buffer.readu32(Buffer, Index + 4)

		CRC = bit32.bxor(
			buffer.readu32(T7, bit32.band(Word0, 0xFF) * 4),
			buffer.readu32(T6, bit32.band(bit32.rshift(Word0, 8), 0xFF) * 4),
			buffer.readu32(T5, bit32.band(bit32.rshift(Word0, 16), 0xFF) * 4),
			buffer.readu32(T4, bit32.rshift(Word0, 24) * 4),
			buffer.readu32(T3, bit32.band(Word1, 0xFF) * 4),
			buffer.readu32(T2, bit32.band(bit32.rshift(Word1, 8), 0xFF) * 4),
			buffer.readu32(T1, bit32.band(bit32.rshift(Word1, 16), 0xFF) * 4),
			buffer.readu32(T0, bit32.rshift(Word1, 24) * 4)
		)

		Index += 8
	end

	while Index < Length do
		local Byte = buffer.readu8(Buffer, Index)
		CRC = bit32.bxor(buffer.readu32(T0, bit32.band(bit32.bxor(CRC, Byte), 0xFF) * 4), bit32.rshift(CRC, 8))
		Index += 1
	end

	return bit32.bxor(CRC, 0xFFFFFFFF)
end

return CRC32