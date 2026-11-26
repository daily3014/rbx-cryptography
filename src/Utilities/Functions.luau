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

local function CtCompareMask(BufferA: buffer, BufferB: buffer, Length: number?): number
	local Count: number
	if Length ~= nil then
		if buffer.len(BufferA) < Length or buffer.len(BufferB) < Length then
			return 0x00000000
		end
		Count = Length
	else
		Count = buffer.len(BufferA)
		if Count ~= buffer.len(BufferB) then
			return 0x00000000
		end
	end

	local D0, D1, D2, D3 = 0, 0, 0, 0
	local Offset = 0
	while Offset <= Count - 16 do
		D0 = bit32.bor(D0, bit32.bxor(buffer.readu32(BufferA, Offset), buffer.readu32(BufferB, Offset)))
		D1 = bit32.bor(D1, bit32.bxor(buffer.readu32(BufferA, Offset + 4), buffer.readu32(BufferB, Offset + 4)))
		D2 = bit32.bor(D2, bit32.bxor(buffer.readu32(BufferA, Offset + 8), buffer.readu32(BufferB, Offset + 8)))
		D3 = bit32.bor(D3, bit32.bxor(buffer.readu32(BufferA, Offset + 12), buffer.readu32(BufferB, Offset + 12)))
		Offset += 16
	end
	while Offset <= Count - 4 do
		D0 = bit32.bor(D0, bit32.bxor(buffer.readu32(BufferA, Offset), buffer.readu32(BufferB, Offset)))
		Offset += 4
	end
	while Offset < Count do
		D1 = bit32.bor(D1, bit32.bxor(buffer.readu8(BufferA, Offset), buffer.readu8(BufferB, Offset)))
		Offset += 1
	end

	return CtIsZeroMask(bit32.bor(D0, D1, D2, D3))
end

local function CtCompare(BufferA: buffer, BufferB: buffer): boolean
	return CtCompareMask(BufferA, BufferB) ~= 0
end

local function CtIsAllZero(Buffer: buffer): boolean
	local Length = buffer.len(Buffer)
	local A0, A1, A2, A3 = 0, 0, 0, 0
	local Offset = 0
	while Offset <= Length - 16 do
		A0 = bit32.bor(A0, buffer.readu32(Buffer, Offset))
		A1 = bit32.bor(A1, buffer.readu32(Buffer, Offset + 4))
		A2 = bit32.bor(A2, buffer.readu32(Buffer, Offset + 8))
		A3 = bit32.bor(A3, buffer.readu32(Buffer, Offset + 12))
		Offset += 16
	end
	while Offset <= Length - 4 do
		A0 = bit32.bor(A0, buffer.readu32(Buffer, Offset))
		Offset += 4
	end
	while Offset < Length do
		A1 = bit32.bor(A1, buffer.readu8(Buffer, Offset))
		Offset += 1
	end

	return bit32.bor(A0, A1, A2, A3) == 0
end

local function CtSwapBuffers(ConditionBit: number, BufferA: buffer, BufferB: buffer): ()
	local Length = buffer.len(BufferA)
	local LengthB = buffer.len(BufferB)
	if LengthB ~= Length then
		error(`BufferB must be {Length} bytes, got {LengthB} bytes`, 2)
	end

	local Mask = CtNonZeroMask(ConditionBit)
	local Offset = 0
	while Offset <= Length - 16 do
		local A0, B0 = buffer.readu32(BufferA, Offset), buffer.readu32(BufferB, Offset)
		local A1, B1 = buffer.readu32(BufferA, Offset + 4), buffer.readu32(BufferB, Offset + 4)
		local A2, B2 = buffer.readu32(BufferA, Offset + 8), buffer.readu32(BufferB, Offset + 8)
		local A3, B3 = buffer.readu32(BufferA, Offset + 12), buffer.readu32(BufferB, Offset + 12)
		local E0 = bit32.band(Mask, bit32.bxor(A0, B0))
		local E1 = bit32.band(Mask, bit32.bxor(A1, B1))
		local E2 = bit32.band(Mask, bit32.bxor(A2, B2))
		local E3 = bit32.band(Mask, bit32.bxor(A3, B3))
		buffer.writeu32(BufferA, Offset, bit32.bxor(A0, E0))
		buffer.writeu32(BufferB, Offset, bit32.bxor(B0, E0))
		buffer.writeu32(BufferA, Offset + 4, bit32.bxor(A1, E1))
		buffer.writeu32(BufferB, Offset + 4, bit32.bxor(B1, E1))
		buffer.writeu32(BufferA, Offset + 8, bit32.bxor(A2, E2))
		buffer.writeu32(BufferB, Offset + 8, bit32.bxor(B2, E2))
		buffer.writeu32(BufferA, Offset + 12, bit32.bxor(A3, E3))
		buffer.writeu32(BufferB, Offset + 12, bit32.bxor(B3, E3))
		Offset += 16
	end
	while Offset <= Length - 4 do
		local A, B = buffer.readu32(BufferA, Offset), buffer.readu32(BufferB, Offset)
		local Delta = bit32.band(Mask, bit32.bxor(A, B))
		buffer.writeu32(BufferA, Offset, bit32.bxor(A, Delta))
		buffer.writeu32(BufferB, Offset, bit32.bxor(B, Delta))
		Offset += 4
	end
	while Offset < Length do
		local A, B = buffer.readu8(BufferA, Offset), buffer.readu8(BufferB, Offset)
		local Delta = bit32.band(Mask, bit32.bxor(A, B))
		buffer.writeu8(BufferA, Offset, bit32.bxor(A, Delta))
		buffer.writeu8(BufferB, Offset, bit32.bxor(B, Delta))
		Offset += 1
	end
end

local function CtCopyIf(ConditionBit: number, Destination: buffer, Source: buffer): ()
	local Length = buffer.len(Destination)
	local SourceLength = buffer.len(Source)
	if SourceLength ~= Length then
		error(`Source must be {Length} bytes, got {SourceLength} bytes`, 2)
	end

	local Mask = CtNonZeroMask(ConditionBit)
	local Offset = 0
	while Offset <= Length - 16 do
		local D0, D1 = buffer.readu32(Destination, Offset), buffer.readu32(Destination, Offset + 4)
		local D2, D3 = buffer.readu32(Destination, Offset + 8), buffer.readu32(Destination, Offset + 12)
		local S0, S1 = buffer.readu32(Source, Offset), buffer.readu32(Source, Offset + 4)
		local S2, S3 = buffer.readu32(Source, Offset + 8), buffer.readu32(Source, Offset + 12)
		buffer.writeu32(Destination, Offset, bit32.bxor(D0, bit32.band(Mask, bit32.bxor(D0, S0))))
		buffer.writeu32(Destination, Offset + 4, bit32.bxor(D1, bit32.band(Mask, bit32.bxor(D1, S1))))
		buffer.writeu32(Destination, Offset + 8, bit32.bxor(D2, bit32.band(Mask, bit32.bxor(D2, S2))))
		buffer.writeu32(Destination, Offset + 12, bit32.bxor(D3, bit32.band(Mask, bit32.bxor(D3, S3))))
		Offset += 16
	end
	while Offset <= Length - 4 do
		local D, S = buffer.readu32(Destination, Offset), buffer.readu32(Source, Offset)
		buffer.writeu32(Destination, Offset, bit32.bxor(D, bit32.band(Mask, bit32.bxor(D, S))))
		Offset += 4
	end
	while Offset < Length do
		local D, S = buffer.readu8(Destination, Offset), buffer.readu8(Source, Offset)
		buffer.writeu8(Destination, Offset, bit32.bxor(D, bit32.band(Mask, bit32.bxor(D, S))))
		Offset += 1
	end
end

local function CtSelectBuffer(ConditionBit: number, Destination: buffer, SourceTrue: buffer, SourceFalse: buffer, Length: number?): ()
	local DestLength = buffer.len(Destination)
	local TrueLength = buffer.len(SourceTrue)
	local FalseLength = buffer.len(SourceFalse)
	local Count: number
	if Length ~= nil then
		if DestLength < Length then
			error(`Destination must be at least {Length} bytes, got {DestLength} bytes`, 2)
		end
		if TrueLength < Length then
			error(`SourceTrue must be at least {Length} bytes, got {TrueLength} bytes`, 2)
		end
		if FalseLength < Length then
			error(`SourceFalse must be at least {Length} bytes, got {FalseLength} bytes`, 2)
		end
		Count = Length
	else
		Count = DestLength
		if TrueLength ~= Count then
			error(`SourceTrue must be {Count} bytes, got {TrueLength} bytes`, 2)
		end
		if FalseLength ~= Count then
			error(`SourceFalse must be {Count} bytes, got {FalseLength} bytes`, 2)
		end
	end

	local Mask = CtNonZeroMask(ConditionBit)
	local Offset = 0
	while Offset <= Count - 16 do
		local T0, T1 = buffer.readu32(SourceTrue, Offset), buffer.readu32(SourceTrue, Offset + 4)
		local T2, T3 = buffer.readu32(SourceTrue, Offset + 8), buffer.readu32(SourceTrue, Offset + 12)
		local F0, F1 = buffer.readu32(SourceFalse, Offset), buffer.readu32(SourceFalse, Offset + 4)
		local F2, F3 = buffer.readu32(SourceFalse, Offset + 8), buffer.readu32(SourceFalse, Offset + 12)
		buffer.writeu32(Destination, Offset, bit32.bxor(F0, bit32.band(Mask, bit32.bxor(T0, F0))))
		buffer.writeu32(Destination, Offset + 4, bit32.bxor(F1, bit32.band(Mask, bit32.bxor(T1, F1))))
		buffer.writeu32(Destination, Offset + 8, bit32.bxor(F2, bit32.band(Mask, bit32.bxor(T2, F2))))
		buffer.writeu32(Destination, Offset + 12, bit32.bxor(F3, bit32.band(Mask, bit32.bxor(T3, F3))))
		Offset += 16
	end
	while Offset <= Count - 4 do
		local T, F = buffer.readu32(SourceTrue, Offset), buffer.readu32(SourceFalse, Offset)
		buffer.writeu32(Destination, Offset, bit32.bxor(F, bit32.band(Mask, bit32.bxor(T, F))))
		Offset += 4
	end
	while Offset < Count do
		local T, F = buffer.readu8(SourceTrue, Offset), buffer.readu8(SourceFalse, Offset)
		buffer.writeu8(Destination, Offset, bit32.bxor(F, bit32.band(Mask, bit32.bxor(T, F))))
		Offset += 1
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
	return bit32.bxor(B, bit32.band(CtNonZeroMask(Mask), bit32.bxor(A, B)))
end

local function CtSwap(ConditionBit: number, A: number, B: number): (number, number)
	local Delta = bit32.band(CtNonZeroMask(ConditionBit), bit32.bxor(A, B))
	return bit32.bxor(A, Delta), bit32.bxor(B, Delta)
end

local function Concatenate(...: buffer): buffer
	local Given = select("#", ...)
	local Buffers = {...}
	local TotalLength = 0

	for Index = 1, Given do
		local Held = Buffers[Index]
		if not Held then
			error(`Concatenate argument {Index} of {Given} is {typeof(Held)}, expected a buffer`, 2)
		end

		TotalLength += buffer.len(Held)
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
