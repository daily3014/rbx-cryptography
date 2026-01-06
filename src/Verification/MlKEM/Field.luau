--[=[
	ML-KEM Field Arithmetic Module
	
	Prime field Zq arithmetic operations for ML-KEM.
	Modular arithmetic over the field Z_q where q = 3329.
	
	Example usage:
		local Field = require(script.Field)
		
		local Sum = Field.Add(1234, 567)
		local Product = Field.Multiply(1234, 567)
		local Inverse = Field.Invert(1234)
		
		local Buffer = Field.BufferCreate(256)
		Field.BufferReduce(Buffer, 256)
		
		local Sum = Field.BufferAdd(BufferA, BufferB, Result, 256)
--]=]

--!strict
--!optimize 2
--!native

local Q = 13 * 256 + 1

local Field = {}

function Field.BarrettReduce(Value: number): number
	return Value % Q
end

local function ReducedAdd(A: number, B: number): number
	local Sum = A + B
	return if Sum >= Q then Sum - Q else Sum
end

local function ReducedSub(A: number, B: number): number
	local Diff = A - B
	return if Diff < 0 then Diff + Q else Diff
end

function Field.Add(A: number, B: number): number
	return ReducedAdd(A, B)
end

function Field.Subtract(A: number, B: number): number
	return ReducedSub(A, B)
end

function Field.Multiply(A: number, B: number): number
	return (A * B) % Q
end

function Field.Negate(A: number): number
	return if A == 0 then 0 else Q - A
end

function Field.Power(Base: number, Exponent: number): number
	local Result = if bit32.band(Exponent, 1) == 1 then Base else 1
	local CurrentBase = Base

	local Exp = Exponent
	while Exp > 1 do
		Exp = bit32.rshift(Exp, 1)
		CurrentBase = Field.Multiply(CurrentBase, CurrentBase)

		if bit32.band(Exp, 1) == 1 then
			Result = Field.Multiply(Result, CurrentBase)
		end
	end

	return Result
end

function Field.Invert(A: number): number
	if A == 0 then
		return 0
	end

	return Field.Power(A, Q - 2)
end

function Field.Divide(A: number, B: number): number
	return Field.Multiply(A, Field.Invert(B))
end

function Field.BufferReduce(Buffer: buffer, Count: number)
	local Modulus = Q
	for Index = 0, Count - 1 do
		local Value = buffer.readu16(Buffer, Index * 2)
		buffer.writeu16(Buffer, Index * 2, (Value % Modulus))
	end
end

function Field.BufferSubtract(A: buffer, B: buffer, Result: buffer, Count: number)
	for Index = 0, Count - 1 do
		local AValue = buffer.readu16(A, Index * 2)
		local BValue = buffer.readu16(B, Index * 2)
		buffer.writeu16(Result, Index * 2, Field.Subtract(AValue, BValue))
	end
end

return Field