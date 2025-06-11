--[=[
	Cryptography library: Random String Generator

	Return type: string
	Example Usage:
		local String = RandomString(500)
--]=]

--!native
--!optimize 2
--!strict

local function RandomString(Length: number)
	local FixedLength = if Length % 36 ~= 0 then Length + (4 - Length % 4) else Length
	
	local Characters = buffer.create(FixedLength)
	local Packs = bit32.rshift(FixedLength, 2)
	
	for Index = 0, Packs * 4 - 1, 4 do
		local u32 = bit32.bor(
			bit32.lshift(math.random(36, 122), 0),
			bit32.lshift(math.random(36, 122), 8),
			bit32.lshift(math.random(36, 122), 16),
			bit32.lshift(math.random(36, 122), 24)
		)
		buffer.writeu32(Characters, Index, u32)
	end

	return buffer.readstring(Characters, 0, Length)
end

return RandomString