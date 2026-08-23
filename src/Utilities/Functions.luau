--[=[
	Cryptography library: Constant Time Utilities

	Every Ct function is branch free on its condition. Conditions take either a
	0 or 1 bit or a full 0xFFFFFFFF mask, so a mask returning compare feeds a
	select with nothing in between. Both compares are branch free inside, a
	comparison lowers to setcc rather than a jump, but a boolean exists to be
	branched on by the caller, so reach for CtCompareMask whenever the answer
	itself is secret and CtCompare only where the caller branches anyway.

	Build masks with arithmetic. `if C ~= 0 then 0xFFFFFFFF else 0` reads as a
	cmov and is not one, a ternary lowers to a real jump on the secret.

	Example usage:
		-- ML-KEM implicit rejection, nothing branches on the secret
		local ValidMask = Functions.CtCompareMask(Ciphertext, Recomputed)
		Functions.CtSelectBuffer(ValidMask, SharedSecret, KPrime, JOutput)
--]=]

--!strict
--!optimize 2
--!native

local Functions = {}

local function CtNonZeroMask(X: number): number
	return bit32.arshift(bit32.bor(X, -X), 31)
end

local function CtIsZeroMask(X: number): number
	return bit32.bnot(CtNonZeroMask(X))
end

local function CtCompareMask(BufferA: buffer, BufferB: buffer): number
	local Length = buffer.len(BufferA)
	if Length ~= buffer.len(BufferB) then
		return 0x00000000
	end

	local WordBytes = Length - bit32.band(Length, 3)
	local Difference = 0

	for Offset = 0, WordBytes - 4, 4 do
		Difference = bit32.bor(Difference, bit32.bxor(buffer.readu32(BufferA, Offset), buffer.readu32(BufferB, Offset)))
	end

	for Offset = WordBytes, Length - 1 do
		Difference = bit32.bor(Difference, bit32.bxor(buffer.readu8(BufferA, Offset), buffer.readu8(BufferB, Offset)))
	end

	return CtIsZeroMask(Difference)
end

local function CtCompare(BufferA: buffer, BufferB: buffer): boolean
	return CtCompareMask(BufferA, BufferB) ~= 0
end

local function CtIsAllZero(Buffer: buffer): boolean
	local Length = buffer.len(Buffer)
	local WordBytes = Length - bit32.band(Length, 3)
	local Acc = 0

	for Offset = 0, WordBytes - 4, 4 do
		Acc = bit32.bor(Acc, buffer.readu32(Buffer, Offset))
	end

	for Offset = WordBytes, Length - 1 do
		Acc = bit32.bor(Acc, buffer.readu8(Buffer, Offset))
	end

	return Acc == 0
end

local function CtSwapBuffers(ConditionBit: number, BufferA: buffer, BufferB: buffer)
	local Length = buffer.len(BufferA)
	local LengthB = buffer.len(BufferB)
	if LengthB ~= Length then
		error(`BufferB must be {Length} bytes, got {LengthB} bytes`, 2)
	end

	local Mask = CtNonZeroMask(ConditionBit)
	local WordBytes = Length - bit32.band(Length, 3)

	for Offset = 0, WordBytes - 4, 4 do
		local A = buffer.readu32(BufferA, Offset)
		local B = buffer.readu32(BufferB, Offset)
		local Delta = bit32.band(Mask, bit32.bxor(A, B))
		buffer.writeu32(BufferA, Offset, bit32.bxor(A, Delta))
		buffer.writeu32(BufferB, Offset, bit32.bxor(B, Delta))
	end

	for Offset = WordBytes, Length - 1 do
		local A = buffer.readu8(BufferA, Offset)
		local B = buffer.readu8(BufferB, Offset)
		local Delta = bit32.band(Mask, bit32.bxor(A, B))
		buffer.writeu8(BufferA, Offset, bit32.bxor(A, Delta))
		buffer.writeu8(BufferB, Offset, bit32.bxor(B, Delta))
	end
end

local function CtCopyIf(ConditionBit: number, Destination: buffer, Source: buffer)
	local Length = buffer.len(Destination)
	local SourceLength = buffer.len(Source)
	if SourceLength ~= Length then
		error(`Source must be {Length} bytes, got {SourceLength} bytes`, 2)
	end

	local Mask = CtNonZeroMask(ConditionBit)
	local WordBytes = Length - bit32.band(Length, 3)

	for Offset = 0, WordBytes - 4, 4 do
		local DestValue = buffer.readu32(Destination, Offset)
		local SrcValue = buffer.readu32(Source, Offset)
		local Delta = bit32.band(Mask, bit32.bxor(DestValue, SrcValue))
		buffer.writeu32(Destination, Offset, bit32.bxor(DestValue, Delta))
	end

	for Offset = WordBytes, Length - 1 do
		local DestValue = buffer.readu8(Destination, Offset)
		local SrcValue = buffer.readu8(Source, Offset)
		local Delta = bit32.band(Mask, bit32.bxor(DestValue, SrcValue))
		buffer.writeu8(Destination, Offset, bit32.bxor(DestValue, Delta))
	end
end

local function CtSelectBuffer(ConditionBit: number, Destination: buffer, SourceTrue: buffer, SourceFalse: buffer)
	local Length = buffer.len(Destination)
	local TrueLength = buffer.len(SourceTrue)
	local FalseLength = buffer.len(SourceFalse)
	if TrueLength ~= Length then
		error(`SourceTrue must be {Length} bytes, got {TrueLength} bytes`, 2)
	end

	if FalseLength ~= Length then
		error(`SourceFalse must be {Length} bytes, got {FalseLength} bytes`, 2)
	end

	local Mask = CtNonZeroMask(ConditionBit)
	local InvMask = bit32.bnot(Mask)
	local WordBytes = Length - bit32.band(Length, 3)

	for Offset = 0, WordBytes - 4, 4 do
		local WordTrue = buffer.readu32(SourceTrue, Offset)
		local WordFalse = buffer.readu32(SourceFalse, Offset)
		buffer.writeu32(Destination, Offset, bit32.bor(bit32.band(WordTrue, Mask), bit32.band(WordFalse, InvMask)))
	end

	for Offset = WordBytes, Length - 1 do
		local ByteTrue = buffer.readu8(SourceTrue, Offset)
		local ByteFalse = buffer.readu8(SourceFalse, Offset)
		buffer.writeu8(Destination, Offset, bit32.bor(bit32.band(ByteTrue, Mask), bit32.band(ByteFalse, InvMask)))
	end
end

local function CtEqMask(A: number, B: number): number
	return CtIsZeroMask(bit32.bxor(A, B))
end

local function CtLtMask(A: number, B: number): number
	local Diff = bit32.bxor(A, bit32.bor(bit32.bxor(A, B), bit32.bxor(A - B, B)))
	return bit32.arshift(Diff, 31)
end

local function CtSelect(Mask: number, A: number, B: number): number
	return bit32.bxor(B, bit32.band(Mask, bit32.bxor(A, B)))
end

local function CtSwap(ConditionBit: number, A: number, B: number): (number, number)
	local Delta = bit32.band(CtNonZeroMask(ConditionBit), bit32.bxor(A, B))
	return bit32.bxor(A, Delta), bit32.bxor(B, Delta)
end

local function Concatenate(...: buffer): buffer
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

Functions.CtNonZeroMask = CtNonZeroMask
Functions.CtIsZeroMask = CtIsZeroMask
Functions.CtCompareMask = CtCompareMask
Functions.CtCompare = CtCompare
Functions.CtIsAllZero = CtIsAllZero
Functions.CtSwapBuffers = CtSwapBuffers
Functions.CtCopyIf = CtCopyIf
Functions.CtSelectBuffer = CtSelectBuffer
Functions.CtEqMask = CtEqMask
Functions.CtLtMask = CtLtMask
Functions.CtSelect = CtSelect
Functions.CtSwap = CtSwap
Functions.Concatenate = Concatenate

return Functions
