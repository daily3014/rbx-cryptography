--[=[
	Degree-255 polynomial arithmetic
	
	Operations on single polynomials including power2round, bit extraction,
	infinity norm computation, and hint generation.

	Example usage:
		local Poly = require(script)
		
		local Input = buffer.create(256 * 4)
		local High = buffer.create(256 * 4)
		local Low = buffer.create(256 * 4)
		Poly.Power2Round(Input, High, Low, 13)
--]=]

--!strict
--!optimize 2
--!native

local N = 256
local Q = 8380417
local Q_BY_2 = math.floor(Q / 2)

local MPoly = {}

function MPoly.Power2Round(Poly: buffer, PolyHi: buffer, PolyLo: buffer, D: number)
	local Max = bit32.lshift(1, D - 1)
	local Modulus = Q
	
	for I = 0, N - 1 do
		local Offset = I * 4
		local R = buffer.readu32(Poly, Offset)

		local T1 = R + Max - 1
		local T2 = bit32.rshift(T1, D)
		local T3 = bit32.lshift(T2, D)

		local Hi = T2
		local Diff = R - T3
		local Lo = if Diff < 0 then Diff + Modulus else Diff

		buffer.writeu32(PolyHi, Offset, Hi)
		buffer.writeu32(PolyLo, Offset, Lo)
	end
end

function MPoly.Multiply(PolyA: buffer, PolyB: buffer, PolyC: buffer)
	local Modulus = Q
	
	for I = 0, N - 1 do
		local Offset = I * 4
		local AValue = buffer.readu32(PolyA, Offset)
		local BValue = buffer.readu32(PolyB, Offset)

		local Product = (AValue * BValue) % Modulus
		buffer.writeu32(PolyC, Offset, Product)
	end
end

function MPoly.SubFromX(Poly: buffer, X: number)
	local Modulus = Q
	for I = 0, N - 1 do
		local Offset = I * 4
		local PolyValue = buffer.readu32(Poly, Offset)

		local Diff = X - PolyValue
		local Result = if Diff < 0 then Diff + Modulus else Diff
		buffer.writeu32(Poly, Offset, Result)
	end
end

function MPoly.InfinityNorm(Poly: buffer): number
	local Result = 0
	local Modulus = Q
	local Modulus2 = Q_BY_2
	
	for I = 0, N - 1 do
		local Offset = I * 4
		local PolyValue = buffer.readu32(Poly, Offset)

		local CurrentValue = if PolyValue > Modulus2 then Modulus - PolyValue else PolyValue
		if CurrentValue > Result then
			Result = CurrentValue
		end
	end

	return Result
end

return MPoly