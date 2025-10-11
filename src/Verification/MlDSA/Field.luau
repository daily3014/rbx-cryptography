--[=[
	Finite field arithmetic modulo Q = 8380417
	
	Arithmetic operations over the prime field Z_q where q = 2^23 - 2^13 + 1.
	All operations maintain elements in canonical form [0, Q).

	Example usage:
		local Field = require(script)
		
		local A = 12345
		local B = 67890
		local Sum = Field.Add(A, B)
		local Product = Field.Multiply(A, B)
		local Inverse = Field.Inverse(A)
--]=]

--!strict
--!optimize 2
--!native

local Q = 8380417
local Q_INV_32 = 58728449

local Field = {}

function Field.Add(A: number, B: number): number
	local Sum = A + B
	return if Sum >= Q then Sum - Q else Sum
end

function Field.Negate(A: number): number
	return if A == 0 then 0 else Q - A
end

function Field.Subtract(A: number, B: number): number
	local Diff = A - B
	return if Diff < 0 then Diff + Q else Diff
end

function Field.Multiply(A: number, B: number): number
	return (A * B) % Q
end

function Field.Power(Base: number, Exponent: number): number
	if Exponent == 0 then
		return 1
	end

	if Exponent == 1 then
		return Base % Q
	end

	local Result = 1
	local CurrentBase = Base % Q 
	local Exp = Exponent

	while Exp > 0 do
		if bit32.band(Exp, 1) == 1 then
			Result = Field.Multiply(Result, CurrentBase)
		end

		CurrentBase = Field.Multiply(CurrentBase, CurrentBase)
		Exp = bit32.rshift(Exp, 1)
	end

	return Result
end

function Field.Inverse(A: number): number
	return Field.Power(A, Q - 2)
end

function Field.Divide(A: number, B: number): number
	return Field.Multiply(A, Field.Inverse(B))
end

return Field