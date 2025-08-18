--[=[
	Modular reduction and bit extraction utilities
	
	power2round, decompose, and hint operations for extracting
	high/low order bits from field elements.

	Example usage:
		local Reduction = require(script)
		
		local R = 12345
		local Alpha = 190464  -- 2 * Gamma2
		local High = Reduction.HighBits(R, Alpha)
		local Low = Reduction.LowBits(R, Alpha)
--]=]

--!strict
--!optimize 2
--!native

local Q = 8380417

local Reduction = {}

function Reduction.Power2Round(R: number, D: number): (number, number)
	local Max = bit32.lshift(1, D - 1)
	local T1 = R + Max - 1
	local T2 = bit32.rshift(T1, D)
	local T3 = bit32.lshift(T2, D)

	local Hi = T2
	local Lo = if R >= T3 then R - T3 else R - T3 + Q

	return Hi, Lo
end

function Reduction.Decompose(R: number, Alpha: number): (number, number)
	local T0 = bit32.rshift(Alpha, 1)
	local T1 = Q - 1
	local T2 = R + T0 - 1

	local T3 = (T2 / Alpha)
	local T4 = T3 * Alpha

	local R0 = if R >= T4 then R - T4 else R - T4 + Q
	local T5 = if R >= R0 then R - R0 else R - R0 + Q

	local Flag = (T5 == T1)
	local R1 = if Flag then 0 else T3

	local R0_ = if Flag then (if R0 >= 1 then R0 - 1 else R0 - 1 + Q) else R0

	return R1, R0_
end

function Reduction.HighBits(R: number, Alpha: number): number
	local T0 = bit32.rshift(Alpha, 1)
	local T2 = R + T0 - 1
	local T3 = (T2 / Alpha)
	local T4 = T3 * Alpha

	local R0 = (R - T4) % Q
	local T5 = (R - R0) % Q

	local Flag = (T5 == (Q - 1))
	
	return if Flag then 0 else T3
end

function Reduction.LowBits(R: number, Alpha: number): number
	local T0 = bit32.rshift(Alpha, 1)
	local T2 = R + T0 - 1
	local T3 = (T2 / Alpha)
	local T4 = T3 * Alpha

	local R0 = (R - T4) % Q
	local T5 = (R - R0) % Q

	local Flag = (T5 == (Q - 1))
	
	return if Flag then (R0 - 1 + Q) % Q else R0
end

function Reduction.MakeHint(Z: number, R: number, Alpha: number): number
	local T0 = bit32.rshift(Alpha, 1)
	local T2_R = R + T0 - 1
	local T3_R = (T2_R / Alpha)
	local T4_R = T3_R * Alpha
	
	local R0_R = (R - T4_R) % Q
	local T5_R = (R - R0_R) % Q
	local Flag_R = (T5_R == (Q - 1))
	
	local R1 = if Flag_R then 0 else T3_R

	local Sum = (R + Z) % Q
	local T2_V = Sum + T0 - 1
	local T3_V = (T2_V / Alpha)
	local T4_V = T3_V * Alpha
	
	local R0_V = (Sum - T4_V) % Q
	local T5_V = (Sum - R0_V) % Q
	local Flag_V = (T5_V == (Q - 1))
	local V1 = if Flag_V then 0 else T3_V

	return if R1 ~= V1 then 1 else 0
end

function Reduction.UseHint(H: number, R: number, Alpha: number): number
	if H ~= 1 then
		local T0 = bit32.rshift(Alpha, 1)
		local T2 = R + T0 - 1
		local T3 = (T2 / Alpha)
		local T4 = T3 * Alpha
		local R0 = (R - T4) % Q
		local T5 = (R - R0) % Q
		local Flag = (T5 == (Q - 1))

		return if Flag then 0 else T3
	end

	local T0 = bit32.rshift(Alpha, 1)
	local T2 = R + T0 - 1
	local T3 = (T2 / Alpha)
	local T4 = T3 * Alpha
	
	local R0 = (R - T4) % Q
	local T5 = (R - R0) % Q
	
	local Flag = (T5 == (Q - 1))
	local R1 = if Flag then 0 else T3
	local R0_ = if Flag then (R0 - 1 + Q) % Q else R0

	local T1 = Q - T0 
	local M = ((Q - 1) / Alpha)

	if R0_ > 0 and R0_ < T1 then
		if R1 == (M - 1) then
			return 0
		else
			return (R1 + 1) % Q
		end
	elseif R0_ >= T1 then
		if R1 == 0 then
			return M - 1
		else
			return (R1 - 1 + Q) % Q 
		end
	else
		return R1
	end
end

return Reduction