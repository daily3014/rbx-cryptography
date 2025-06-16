--!strict
--!native
--!optimize 2

local function RandomBytes(): buffer
	local Output = buffer.create(32)

	for Index = 0, 31 do
		local RandomByte = math.random(1, 254)
		buffer.writeu8(Output, Index, RandomByte)
	end

	local FirstByte = buffer.readu8(Output, 0)
	FirstByte = bit32.band(FirstByte, 0xF8)
	buffer.writeu8(Output, 0, FirstByte)

	local LastByte = buffer.readu8(Output, 31)
	LastByte = bit32.band(LastByte, 0x7F)
	LastByte = bit32.bor(LastByte, 0x40)
	buffer.writeu8(Output, 31, LastByte)


	local HasVariation = false
	local FirstMiddleByte = buffer.readu8(Output, 1)

	for Index = 2, 30 do
		if buffer.readu8(Output, Index) ~= FirstMiddleByte then
			HasVariation = true
			break
		end
	end

	if not HasVariation then
		buffer.writeu8(Output, 15, bit32.bxor(FirstMiddleByte, 0x55))
	end

	return Output
end

return {
	Random = RandomBytes,
}