--[=[
	ScalarSplit: c and d below 2^127 with c = d * k mod L, from extended Euclid on (L, k) stopped once
	the remainder is below 2^126 (Pornin, ePrint 2020/454). Verify checks [d*s]B = [d]R + [c]A, which
	needs half the doublings of [s]B = R + [k]A. Only public values pass through here.

	Example usage:
		local Negative = ScalarSplit.Split(ChallengeLimbs, Output)
--]=]

--!strict
--!optimize 2

local SLOW: buffer = buffer.create(384)
local ScalarSplit = {}

@native
local function Approx(Buf: buffer, Base: number): number
	local Value = 0
	for Index = 11, 0, -1 do
		Value = Value * 16777216 + buffer.readf64(Buf, Base + Index * 8)
	end
	return Value
end

@native
local function SlowFinish(Buf: buffer): ()
	while true do
		local Ratio = Approx(Buf, 0) / Approx(Buf, 96) * (1 - 2 ^ -40)
		if Ratio < 1 then
			local Carry = 0
			for Index = 0, 11 do
				local X = buffer.readf64(Buf, Index * 8) - buffer.readf64(Buf, 96 + Index * 8) + Carry
				Carry = math.floor(X * 2 ^ -24)
			end
			if Carry < 0 then
				return
			end
			Ratio = 1
		end
		local Shift = 0
		while Ratio >= 16777216 do
			Ratio *= 2 ^ -24
			Shift += 1
		end
		local Q = math.floor(Ratio)
		local Carry = 0
		local TCarry = 0
		for Index = Shift, 11 do
			local X = buffer.readf64(Buf, Index * 8) - Q * buffer.readf64(Buf, 96 + (Index - Shift) * 8) + Carry
			Carry = math.floor(X * 2 ^ -24)
			buffer.writef64(Buf, Index * 8, X - Carry * 16777216)
			local Y = buffer.readf64(Buf, 192 + Index * 8) + Q * buffer.readf64(Buf, 288 + (Index - Shift) * 8) + TCarry
			TCarry = math.floor(Y * 2 ^ -24)
			buffer.writef64(Buf, 192 + Index * 8, Y - TCarry * 16777216)
		end
	end
end

@native
function ScalarSplit.Split(K: buffer, Out: buffer): boolean
	local A0, A1, A2, A3, A4, A5 = 16110573, 6494812, 14047250, 10680220, 14612958, 20
	local A6, A7, A8, A9, A10 = 0, 0, 0, 0, 4096
	local B0, B1, B2, B3, B4, B5 = buffer.readf64(K, 0), buffer.readf64(K, 8), buffer.readf64(K, 16), buffer.readf64(K, 24), buffer.readf64(K, 32), buffer.readf64(K, 40)
	local B6, B7, B8, B9, B10 = buffer.readf64(K, 48), buffer.readf64(K, 56), buffer.readf64(K, 64), buffer.readf64(K, 72), buffer.readf64(K, 80)
	local S0, S1, S2, S3, S4, S5 = 0, 0, 0, 0, 0, 0
	local U0, U1, U2, U3, U4, U5 = 1, 0, 0, 0, 0, 0
	local Negative = false
	local Approx0 = (((A0 + A1 * 2 ^ 24) + (A2 * 2 ^ 48 + A3 * 2 ^ 72)) + ((A4 * 2 ^ 96 + A5 * 2 ^ 120) + (A6 * 2 ^ 144 + A7 * 2 ^ 168))) + ((A8 * 2 ^ 192 + A9 * 2 ^ 216) + A10 * 2 ^ 240)
	local Approx1 = (((B0 + B1 * 2 ^ 24) + (B2 * 2 ^ 48 + B3 * 2 ^ 72)) + ((B4 * 2 ^ 96 + B5 * 2 ^ 120) + (B6 * 2 ^ 144 + B7 * 2 ^ 168))) + ((B8 * 2 ^ 192 + B9 * 2 ^ 216) + B10 * 2 ^ 240)
	local Magic = 1.5 * 2 ^ 76
	local Inv24 = 2 ^ -24
	local Scale = 1 - 2 ^ -40

	while Approx1 >= 2 ^ 126 do
		local Q = math.min(math.floor(Approx0 / Approx1 * Scale), 16777215)
		local X0 = A0 - Q * B0
		local X1 = A1 - Q * B1
		local X2 = A2 - Q * B2
		local X3 = A3 - Q * B3
		local X4 = A4 - Q * B4
		local X5 = A5 - Q * B5
		local X6 = A6 - Q * B6
		local X7 = A7 - Q * B7
		local X8 = A8 - Q * B8
		local X9 = A9 - Q * B9
		local X10 = A10 - Q * B10
		local Y0 = S0 + Q * U0
		local Y1 = S1 + Q * U1
		local Y2 = S2 + Q * U2
		local Y3 = S3 + Q * U3
		local Y4 = S4 + Q * U4
		local Y5 = S5 + Q * U5

		local C: number
		C = X0 + Magic - Magic; X0 -= C; X1 += C * Inv24
		C = X5 + Magic - Magic; X5 -= C; X6 += C * Inv24
		C = Y0 + Magic - Magic; Y0 -= C; Y1 += C * Inv24
		C = X1 + Magic - Magic; X1 -= C; X2 += C * Inv24
		C = X6 + Magic - Magic; X6 -= C; X7 += C * Inv24
		C = Y1 + Magic - Magic; Y1 -= C; Y2 += C * Inv24
		C = X2 + Magic - Magic; X2 -= C; X3 += C * Inv24
		C = X7 + Magic - Magic; X7 -= C; X8 += C * Inv24
		C = Y2 + Magic - Magic; Y2 -= C; Y3 += C * Inv24
		C = X3 + Magic - Magic; X3 -= C; X4 += C * Inv24
		C = X8 + Magic - Magic; X8 -= C; X9 += C * Inv24
		C = Y3 + Magic - Magic; Y3 -= C; Y4 += C * Inv24
		C = X4 + Magic - Magic; X4 -= C; X5 += C * Inv24
		C = X9 + Magic - Magic; X9 -= C; X10 += C * Inv24
		C = Y4 + Magic - Magic; Y4 -= C; Y5 += C * Inv24
		C = X5 + Magic - Magic; X5 -= C; X6 += C * Inv24

		local Approx2 = (((X0 + X1 * 2 ^ 24) + (X2 * 2 ^ 48 + X3 * 2 ^ 72)) + ((X4 * 2 ^ 96 + X5 * 2 ^ 120) + (X6 * 2 ^ 144 + X7 * 2 ^ 168))) + ((X8 * 2 ^ 192 + X9 * 2 ^ 216) + X10 * 2 ^ 240)
		if Approx2 >= Approx1 * Scale then
			local Slow = SLOW
			buffer.fill(Slow, 0, 0)
			buffer.writef64(Slow, 0, X0); buffer.writef64(Slow, 96, B0)
			buffer.writef64(Slow, 8, X1); buffer.writef64(Slow, 104, B1)
			buffer.writef64(Slow, 16, X2); buffer.writef64(Slow, 112, B2)
			buffer.writef64(Slow, 24, X3); buffer.writef64(Slow, 120, B3)
			buffer.writef64(Slow, 32, X4); buffer.writef64(Slow, 128, B4)
			buffer.writef64(Slow, 40, X5); buffer.writef64(Slow, 136, B5)
			buffer.writef64(Slow, 48, X6); buffer.writef64(Slow, 144, B6)
			buffer.writef64(Slow, 56, X7); buffer.writef64(Slow, 152, B7)
			buffer.writef64(Slow, 64, X8); buffer.writef64(Slow, 160, B8)
			buffer.writef64(Slow, 72, X9); buffer.writef64(Slow, 168, B9)
			buffer.writef64(Slow, 80, X10); buffer.writef64(Slow, 176, B10)
			buffer.writef64(Slow, 192, Y0); buffer.writef64(Slow, 288, U0)
			buffer.writef64(Slow, 200, Y1); buffer.writef64(Slow, 296, U1)
			buffer.writef64(Slow, 208, Y2); buffer.writef64(Slow, 304, U2)
			buffer.writef64(Slow, 216, Y3); buffer.writef64(Slow, 312, U3)
			buffer.writef64(Slow, 224, Y4); buffer.writef64(Slow, 320, U4)
			buffer.writef64(Slow, 232, Y5); buffer.writef64(Slow, 328, U5)
			SlowFinish(Slow)
			X0, X1, X2, X3, X4, X5 = buffer.readf64(Slow, 0), buffer.readf64(Slow, 8), buffer.readf64(Slow, 16), buffer.readf64(Slow, 24), buffer.readf64(Slow, 32), buffer.readf64(Slow, 40)
			X6, X7, X8, X9, X10 = buffer.readf64(Slow, 48), buffer.readf64(Slow, 56), buffer.readf64(Slow, 64), buffer.readf64(Slow, 72), buffer.readf64(Slow, 80)
			Y0, Y1, Y2, Y3, Y4, Y5 = buffer.readf64(Slow, 192), buffer.readf64(Slow, 200), buffer.readf64(Slow, 208), buffer.readf64(Slow, 216), buffer.readf64(Slow, 224), buffer.readf64(Slow, 232)
			Approx2 = (((X0 + X1 * 2 ^ 24) + (X2 * 2 ^ 48 + X3 * 2 ^ 72)) + ((X4 * 2 ^ 96 + X5 * 2 ^ 120) + (X6 * 2 ^ 144 + X7 * 2 ^ 168))) + ((X8 * 2 ^ 192 + X9 * 2 ^ 216) + X10 * 2 ^ 240)
		end

		A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10 = B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10
		B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10 = X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10
		S0, S1, S2, S3, S4, S5 = U0, U1, U2, U3, U4, U5
		U0, U1, U2, U3, U4, U5 = Y0, Y1, Y2, Y3, Y4, Y5
		Approx0, Approx1 = Approx1, Approx2
		Negative = not Negative
	end

	local Carry: number
	Carry = math.floor(B0 * Inv24); B0 -= Carry * 16777216; B1 += Carry
	Carry = math.floor(B1 * Inv24); B1 -= Carry * 16777216; B2 += Carry
	Carry = math.floor(B2 * Inv24); B2 -= Carry * 16777216; B3 += Carry
	Carry = math.floor(B3 * Inv24); B3 -= Carry * 16777216; B4 += Carry
	Carry = math.floor(B4 * Inv24); B4 -= Carry * 16777216; B5 += Carry
	Carry = math.floor(B5 * Inv24); B5 -= Carry * 16777216

	Carry = math.floor(U0 * Inv24); U0 -= Carry * 16777216; U1 += Carry
	Carry = math.floor(U1 * Inv24); U1 -= Carry * 16777216; U2 += Carry
	Carry = math.floor(U2 * Inv24); U2 -= Carry * 16777216; U3 += Carry
	Carry = math.floor(U3 * Inv24); U3 -= Carry * 16777216; U4 += Carry
	Carry = math.floor(U4 * Inv24); U4 -= Carry * 16777216; U5 += Carry
	Carry = math.floor(U5 * Inv24); U5 -= Carry * 16777216

	buffer.writef64(Out, 0, B0); buffer.writef64(Out, 8, B1); buffer.writef64(Out, 16, B2)
	buffer.writef64(Out, 24, B3); buffer.writef64(Out, 32, B4); buffer.writef64(Out, 40, B5)
	buffer.writef64(Out, 48, U0); buffer.writef64(Out, 56, U1); buffer.writef64(Out, 64, U2)
	buffer.writef64(Out, 72, U3); buffer.writef64(Out, 80, U4); buffer.writef64(Out, 88, U5)
	buffer.writeu32(Out, 96, B0); buffer.writeu32(Out, 99, B1); buffer.writeu32(Out, 102, B2)
	buffer.writeu32(Out, 105, B3); buffer.writeu32(Out, 108, B4); buffer.writeu32(Out, 111, B5)
	buffer.writeu32(Out, 120, U0); buffer.writeu32(Out, 123, U1); buffer.writeu32(Out, 126, U2)
	buffer.writeu32(Out, 129, U3); buffer.writeu32(Out, 132, U4); buffer.writeu32(Out, 135, U5)
	return Negative
end

function ScalarSplit.ClearCaches(): ()
	buffer.fill(SLOW, 0, 0)
end

return ScalarSplit
