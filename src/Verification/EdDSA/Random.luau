--!strict
--!native
--!optimize 2

local function RandomString(Length: number): buffer
	local FixedLength = Length + ((4 - Length % 4) % 4) 
	local Characters = buffer.create(FixedLength)
	local Packs = bit32.rshift(FixedLength, 2)

	for Index = 0, Packs * 4 - 1, 4 do
		local u32 = bit32.bor(
			bit32.lshift(math.random(0, 255), 0),
			bit32.lshift(math.random(0, 255), 8),
			bit32.lshift(math.random(0, 255), 16),
			bit32.lshift(math.random(0, 255), 24)
		)
		buffer.writeu32(Characters, Index, u32)
	end
	
	local Buf = buffer.create(Length)
	buffer.copy(Buf, 0, Characters, 0, Length)
	return Buf
end

return {
	Random = RandomString,
}