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
local POW_24 = 2^24
local POW_24_M1 = 2^24-1
local POW_24_INV = 2^-24

local Field = {}

function Field.FromNonReduced(Value: number): number
	return Value % Q
end

function Field.Add(A: number, B: number): number
	local Sum = A + B
	
	return if Sum >= Q then Sum - Q else Sum
end

function Field.Negate(A: number): number
	return if A == 0 then 0 else Q - A
end

function Field.Subtract(A: number, B: number): number
	return if A >= B then A - B else A - B + Q
end

function Field.Multiply(A: number, B: number): number
	if A < 4096 and B < 4096 then
		return (A * B) % Q
	end

	local Product = A * B
	local Low0 = bit32.band(Product, POW_24_M1)
	local High = (Product - Low0) * POW_24_INV
	local Low1 = bit32.band(High, POW_24_M1)

	return (Low0 + Low1 * POW_24) % Q
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

function Field.LeftShift(A: number, L: number): number
	local Shifted = bit32.lshift(A, L)
	return if Shifted >= Q then Shifted % Q else Shifted
end

return Field