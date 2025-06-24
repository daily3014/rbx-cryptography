--!strict
--!native
--!optimize 2

local Random = {}

function RandomBytes(): buffer
	local Output = buffer.create(32)

	for Index = 0, 31, 4 do
		buffer.writeu32(Output, Index, bit32.bor(
			bit32.lshift(math.random(0, 255), 0),
			bit32.lshift(math.random(0, 255), 8),
			bit32.lshift(math.random(0, 255), 16),
			bit32.lshift(math.random(0, 255), 24)
		))
	end

	return Output
end

function Random.Clamp(Input: buffer): buffer
	local Output = buffer.create(32)
	buffer.copy(Output, 0, Input, 0, 32)

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

function Random.Random(): buffer
	return Random.Clamp(RandomBytes())
end

return Random
