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

	for I = 0, N - 1 do
		local Offset = I * 4
		local R = buffer.readu32(Poly, Offset)

		local T1 = R + Max - 1
		local T2 = bit32.rshift(T1, D)
		local T3 = bit32.lshift(T2, D)

		local Hi = T2
		local Lo = if R >= T3 then R - T3 else R - T3 + Q

		buffer.writeu32(PolyHi, Offset, Hi)
		buffer.writeu32(PolyLo, Offset, Lo)
	end
end

function MPoly.Multiply(PolyA: buffer, PolyB: buffer, PolyC: buffer)
	for I = 0, N - 1 do
		local Offset = I * 4
		local AValue = buffer.readu32(PolyA, Offset)
		local BValue = buffer.readu32(PolyB, Offset)

		local Product = (AValue * BValue) % Q
		buffer.writeu32(PolyC, Offset, Product)
	end
end

function MPoly.SubFromX(Poly: buffer, X: number)
	for I = 0, N - 1 do
		local Offset = I * 4
		local PolyValue = buffer.readu32(Poly, Offset)

		local Result = if X >= PolyValue then X - PolyValue else X - PolyValue + Q
		buffer.writeu32(Poly, Offset, Result)
	end
end

function MPoly.HighBits(Src: buffer, Dst: buffer, Alpha: number)
	local T0 = bit32.rshift(Alpha, 1)
	local T1 = Q - 1

	for I = 0, N - 1 do
		local Offset = I * 4
		local R = buffer.readu32(Src, Offset)

		local T2 = R + T0 - 1
		local T3 = math.floor(T2 / Alpha)
		local T4 = T3 * Alpha

		local R0 = if R >= T4 then R - T4 else R - T4 + Q
		local T5 = if R >= R0 then R - R0 else R - R0 + Q

		local Flag = (T5 == T1)
		local R1 = if Flag then 0 else T3

		buffer.writeu32(Dst, Offset, R1)
	end
end

function MPoly.LowBits(Src: buffer, Dst: buffer, Alpha: number)
	local T0 = bit32.rshift(Alpha, 1)
	local T1 = Q - 1

	for I = 0, N - 1 do
		local Offset = I * 4
		local R = buffer.readu32(Src, Offset)

		local T2 = R + T0 - 1
		local T3 = math.floor(T2 / Alpha)
		local T4 = T3 * Alpha

		local R0 = if R >= T4 then R - T4 else R - T4 + Q
		local T5 = if R >= R0 then R - R0 else R - R0 + Q

		local Flag = (T5 == T1)
		local R0_ = if Flag then (if R0 >= 1 then R0 - 1 else R0 - 1 + Q) else R0

		buffer.writeu32(Dst, Offset, R0_)
	end
end

function MPoly.InfinityNorm(Poly: buffer): number
	local Result = 0

	for I = 0, N - 1 do
		local PolyValue = buffer.readu32(Poly, I * 4)
		local CurrentValue = if PolyValue > Q_BY_2 then (if PolyValue == 0 then 0 else Q - PolyValue) else PolyValue

		if CurrentValue > Result then
			Result = CurrentValue
		end
	end

	return Result
end

function MPoly.MakeHint(PolyA: buffer, PolyB: buffer, PolyC: buffer, Alpha: number)
	local T0 = bit32.rshift(Alpha, 1)
	local T1 = Q - 1

	for I = 0, N - 1 do
		local Offset = I * 4
		local Z = buffer.readu32(PolyA, Offset)
		local R = buffer.readu32(PolyB, Offset)

		local T2_R = R + T0 - 1
		local T3_R = math.floor(T2_R / Alpha)
		local T4_R = T3_R * Alpha
		local R0_R = if R >= T4_R then R - T4_R else R - T4_R + Q
		local T5_R = if R >= R0_R then R - R0_R else R - R0_R + Q
		local Flag_R = (T5_R == T1)
		local R1 = if Flag_R then 0 else T3_R

		local Sum = R + Z
		Sum = if Sum >= Q then Sum - Q else Sum

		local T2_V = Sum + T0 - 1
		local T3_V = math.floor(T2_V / Alpha)
		local T4_V = T3_V * Alpha
		local R0_V = if Sum >= T4_V then Sum - T4_V else Sum - T4_V + Q
		local T5_V = if Sum >= R0_V then Sum - R0_V else Sum - R0_V + Q
		local Flag_V = (T5_V == T1)
		local V1 = if Flag_V then 0 else T3_V

		local Hint = if R1 ~= V1 then 1 else 0
		buffer.writeu32(PolyC, Offset, Hint)
	end
end

function MPoly.UseHint(PolyH: buffer, PolyR: buffer, PolyRZ: buffer, Alpha: number)
	local M = math.floor((Q - 1) / Alpha)
	local T0 = bit32.rshift(Alpha, 1)
	local T1 = Q - T0
	local T1_Q = Q - 1

	for I = 0, N - 1 do
		local Offset = I * 4
		local H = buffer.readu32(PolyH, Offset)
		local R = buffer.readu32(PolyR, Offset)

		local T2 = R + T0 - 1
		local T3 = math.floor(T2 / Alpha)
		local T4 = T3 * Alpha
		local R0 = if R >= T4 then R - T4 else R - T4 + Q
		local T5 = if R >= R0 then R - R0 else R - R0 + Q
		local Flag = (T5 == T1_Q)
		local R1 = if Flag then 0 else T3
		local R0_ = if Flag then (if R0 >= 1 then R0 - 1 else R0 - 1 + Q) else R0

		local Result
		if H == 1 then
			if R0_ > 0 and R0_ < T1 then
				if R1 == (M - 1) then
					Result = 0
				else
					Result = R1 + 1
				end
			elseif R0_ >= T1 then
				if R1 == 0 then
					Result = M - 1
				else
					Result = R1 - 1
				end
			else
				Result = R1
			end
		else
			Result = R1
		end

		buffer.writeu32(PolyRZ, Offset, Result)
	end
end

function MPoly.Count1s(Poly: buffer): number
	local Count = 0

	for I = 0, N - 1 do
		local PolyValue = buffer.readu32(Poly, I * 4)
		Count += PolyValue
	end

	return Count
end

function MPoly.LeftShift(Poly: buffer, D: number)
	for I = 0, N - 1 do
		local Offset = I * 4
		local PolyValue = buffer.readu32(Poly, Offset)

		local Shifted = bit32.lshift(PolyValue, D)
		local Result = if Shifted >= Q then Shifted % Q else Shifted

		buffer.writeu32(Poly, Offset, Result)
	end
end

function MPoly.Add(PolyA: buffer, PolyB: buffer, PolyC: buffer)
	for I = 0, N - 1 do
		local Offset = I * 4
		local AValue = buffer.readu32(PolyA, Offset)
		local BValue = buffer.readu32(PolyB, Offset)

		local Sum = AValue + BValue
		local Result = if Sum >= Q then Sum - Q else Sum

		buffer.writeu32(PolyC, Offset, Result)
	end
end

function MPoly.Subtract(PolyA: buffer, PolyB: buffer, PolyC: buffer)
	for I = 0, N - 1 do
		local Offset = I * 4
		local AValue = buffer.readu32(PolyA, Offset)
		local BValue = buffer.readu32(PolyB, Offset)

		local Difference = if AValue >= BValue then AValue - BValue else AValue - BValue + Q

		buffer.writeu32(PolyC, Offset, Difference)
	end
end

function MPoly.Negate(Poly: buffer)
	for I = 0, N - 1 do
		local Offset = I * 4
		local PolyValue = buffer.readu32(Poly, Offset)
		local Negated = if PolyValue == 0 then 0 else Q - PolyValue

		buffer.writeu32(Poly, Offset, Negated)
	end
end

function MPoly.Copy(Src: buffer, Dst: buffer)
	buffer.copy(Dst, 0, Src, 0, N * 4)
end

function MPoly.Zero(Poly: buffer)
	buffer.fill(Poly, 0, 0, N * 4)
end

function MPoly.Fill(Poly: buffer, Value: number)
	for I = 0, N - 1 do
		buffer.writeu32(Poly, I * 4, Value)
	end
end

function MPoly.Equal(PolyA: buffer, PolyB: buffer): boolean
	for I = 0, N - 1 do
		local AValue = buffer.readu32(PolyA, I * 4)
		local BValue = buffer.readu32(PolyB, I * 4)
		if AValue ~= BValue then
			return false
		end
	end

	return true
end

return MPoly