--!strict
--!optimize 2
--!native

local Functions = {}

--- Compares two buffers in constant time, only exiting early if they have mismatching lengths
function Functions.CtCompare(BufferA: buffer, BufferB: buffer): boolean
	local Length = buffer.len(BufferA)
	if Length ~= buffer.len(BufferB) then
		return false
	end

	local Difference = 0
	for Index = 0, Length - 1 do
		Difference = bit32.bor(Difference, bit32.bxor(buffer.readu8(BufferA, Index), buffer.readu8(BufferB, Index)))
	end

	return Difference == 0
end

--- Checks if a buffer is all zeroes in constant time
function Functions.CtIsAllZero(Buffer: buffer): boolean
	local Length = buffer.len(Buffer)
	local Words = Length // 4
	local Remainder = Length % 4
	local Acc = 0

	for Index = 0, Words - 1 do
		Acc = bit32.bor(Acc, buffer.readu32(Buffer, Index * 4))
	end

	local ByteOffset = Words * 4
	for Index = 0, Remainder - 1 do
		Acc = bit32.bor(Acc, buffer.readu8(Buffer, ByteOffset + Index))
	end

	return Acc == 0
end

--- Swaps contents of BufferA and BufferB in constant time if ConditionBit == 1 (or non-zero)
function Functions.CtSwapBuffers(ConditionBit: number, BufferA: buffer, BufferB: buffer)
	local Mask = if ConditionBit ~= 0 then 0xFFFFFFFF else 0
	local Length = buffer.len(BufferA)
	local Words = Length // 4
	local Remainder = Length % 4

	for Index = 0, Words - 1 do
		local Offset = Index * 4
		local A = buffer.readu32(BufferA, Offset)
		local B = buffer.readu32(BufferB, Offset)
		local Delta = bit32.band(Mask, bit32.bxor(A, B))
		buffer.writeu32(BufferA, Offset, bit32.bxor(A, Delta))
		buffer.writeu32(BufferB, Offset, bit32.bxor(B, Delta))
	end

	local ByteOffset = Words * 4
	for Index = 0, Remainder - 1 do
		local Offset = ByteOffset + Index
		local A = buffer.readu8(BufferA, Offset)
		local B = buffer.readu8(BufferB, Offset)
		local Delta = bit32.band(Mask, bit32.bxor(A, B))
		buffer.writeu8(BufferA, Offset, bit32.bxor(A, Delta))
		buffer.writeu8(BufferB, Offset, bit32.bxor(B, Delta))
	end
end

--- Copies Source into Destination in constant time if ConditionBit == 1 (or non-zero)
function Functions.CtCopyIf(ConditionBit: number, Destination: buffer, Source: buffer)
	local Mask = if ConditionBit ~= 0 then 0xFFFFFFFF else 0
	local Length = buffer.len(Destination)
	local Words = Length // 4
	local Remainder = Length % 4

	for Index = 0, Words - 1 do
		local Offset = Index * 4
		local DestValue = buffer.readu32(Destination, Offset)
		local SrcValue = buffer.readu32(Source, Offset)
		local Delta = bit32.band(Mask, bit32.bxor(DestValue, SrcValue))
		buffer.writeu32(Destination, Offset, bit32.bxor(DestValue, Delta))
	end

	local ByteOffset = Words * 4
	for Index = 0, Remainder - 1 do
		local Offset = ByteOffset + Index
		local DestValue = buffer.readu8(Destination, Offset)
		local SrcValue = buffer.readu8(Source, Offset)
		local Delta = bit32.band(Mask, bit32.bxor(DestValue, SrcValue))
		buffer.writeu8(Destination, Offset, bit32.bxor(DestValue, Delta))
	end
end

--- Selects between SourceTrue and SourceFalse into Destination in constant time via ConditionBit
function Functions.CtSelectBuffer(ConditionBit: number, Destination: buffer, SourceTrue: buffer, SourceFalse: buffer)
	local Mask = if ConditionBit ~= 0 then 0xFFFFFFFF else 0
	local InvMask = bit32.bnot(Mask)
	local Length = buffer.len(Destination)
	local Words = Length // 4
	local Remainder = Length % 4

	for Index = 0, Words - 1 do
		local Offset = Index * 4
		local WordTrue = buffer.readu32(SourceTrue, Offset)
		local WordFalse = buffer.readu32(SourceFalse, Offset)
		local Selected = bit32.bor(bit32.band(WordTrue, Mask), bit32.band(WordFalse, InvMask))
		buffer.writeu32(Destination, Offset, Selected)
	end

	local ByteOffset = Words * 4
	for Index = 0, Remainder - 1 do
		local Offset = ByteOffset + Index
		local ByteTrue = buffer.readu8(SourceTrue, Offset)
		local ByteFalse = buffer.readu8(SourceFalse, Offset)
		local Selected = bit32.bor(bit32.band(ByteTrue, Mask), bit32.band(ByteFalse, InvMask))
		buffer.writeu8(Destination, Offset, Selected)
	end
end

--- Returns 0xFFFFFFFF if X == 0, else 0x00000000
function Functions.CtIsZeroMask(X: number): number
	local Diff = bit32.bor(X, -X)
	return bit32.bnot(bit32.arshift(Diff, 31))
end

--- Returns 0xFFFFFFFF if A == B, else 0x00000000
function Functions.CtEqMask(A: number, B: number): number
	return Functions.CtIsZeroMask(bit32.bxor(A, B))
end

--- Returns 0xFFFFFFFF if A < B, else 0x00000000
function Functions.CtLtMask(A: number, B: number): number
	local Diff = bit32.bxor(A, bit32.bor(bit32.bxor(A, B), bit32.bxor(A - B, B)))
	return bit32.arshift(Diff, 31)
end

--- Returns A if Mask == 0xFFFFFFFF, or B if Mask == 0x00000000
function Functions.CtSelect(Mask: number, A: number, B: number): number
	return bit32.bxor(B, bit32.band(Mask, bit32.bxor(A, B)))
end

--- Swaps A and B if ConditionBit == 1 (or non-zero)
function Functions.CtSwap(ConditionBit: number, A: number, B: number): (number, number)
	local Mask = if ConditionBit ~= 0 then 0xFFFFFFFF else 0
	local Delta = bit32.band(Mask, bit32.bxor(A, B))
	return bit32.bxor(A, Delta), bit32.bxor(B, Delta)
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