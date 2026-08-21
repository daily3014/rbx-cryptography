--!strict
--!optimize 2
--!native

local Functions = {}

--- Compares two buffers in constant time, only exiting early if they have mismatching lengths
function Functions.CtCompare(Buffer1: buffer, Buffer2: buffer): boolean
	local Length = buffer.len(Buffer1)
	if Length ~= buffer.len(Buffer2) then
		return false
	end

	local Difference = 0
	for Index = 0, Length - 1 do
		Difference = bit32.bor(Difference, bit32.bxor(buffer.readu8(Buffer1, Index), buffer.readu8(Buffer2, Index)))
	end

	return Difference == 0
end

--- Concatenates multiple buffers into a single buffer
function Functions.Concatenate(...: buffer): buffer
	local Buffers = {...}
	local TotalLength = 0

	for _, Buffer in Buffers do
		TotalLength += buffer.len(Buffer)
	end

	local Result = buffer.create(TotalLength)
	local Offset = 0

	for _, Buffer in Buffers do
		buffer.copy(Result, Offset, Buffer)
		Offset += buffer.len(Buffer)
	end

	return Result
end

return Functions