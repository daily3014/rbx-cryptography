--[=[
	ScalarSplit: c and d below 2^127 with c = d * k mod L, from extended Euclid on (L, k) stopped once
	the remainder is below 2^126 (Pornin, ePrint 2020/454). Verify checks [d*s]B = [d]R + [c]A, which
	needs half the doublings of [s]B = R + [k]A. Split writes c and |d| as 6 limbs of 24 bits at
	offsets 0 and 48, again as little endian bytes at 96 and 120, and returns whether d is negative.
	A quotient estimate never overshoots, and a quotient of 2^24 or more, which a ground challenge
	hash can force, finishes in SlowFinish within a few rounds. Limbs are carried in two parallel
	passes and stay within about 2^23 of zero, so a value below 2^(24n - 2) has nothing above limb
	n; each step runs the body sized for the limbs the remainder and |d| can still use. Only public
	values pass through here

	Example usage:
		local Negative = ScalarSplit.Split(ChallengeLimbs, Output)
--]=]

--!strict
--!optimize 2
--!native

local SLOW = buffer.create(384)

local ScalarSplit = {}

local function Approx(Buf: buffer, Base: number): number
	local Value = 0
	for Index = 11, 0, -1 do
		Value = Value * 16777216 + buffer.readf64(Buf, Base + Index * 8)
	end
	return Value
end

local function SlowFinish(Buf: buffer)
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

function ScalarSplit.Split(K: buffer, Out: buffer): boolean
	local A0 = 16110573
	local A1 = 6494812
	local A2 = 14047250
	local A3 = 10680220
	local A4 = 14612958
	local A5 = 20
	local A6 = 0
	local A7 = 0
	local A8 = 0
	local A9 = 0
	local A10 = 4096
	local B0 = buffer.readf64(K, 0)
	local B1 = buffer.readf64(K, 8)
	local B2 = buffer.readf64(K, 16)
	local B3 = buffer.readf64(K, 24)
	local B4 = buffer.readf64(K, 32)
	local B5 = buffer.readf64(K, 40)
	local B6 = buffer.readf64(K, 48)
	local B7 = buffer.readf64(K, 56)
	local B8 = buffer.readf64(K, 64)
	local B9 = buffer.readf64(K, 72)
	local B10 = buffer.readf64(K, 80)
	local S0 = 0
	local S1 = 0
	local S2 = 0
	local S3 = 0
	local S4 = 0
	local S5 = 0
	local U0 = 1
	local U1 = 0
	local U2 = 0
	local U3 = 0
	local U4 = 0
	local U5 = 0
	local Negative = false
	local Approx0 = ((((A0 + A1 * 2 ^ 24) + (A2 * 2 ^ 48 + A3 * 2 ^ 72)) + ((A4 * 2 ^ 96 + A5 * 2 ^ 120) + (A6 * 2 ^ 144 + A7 * 2 ^ 168))) + ((A8 * 2 ^ 192 + A9 * 2 ^ 216) + A10 * 2 ^ 240))
	local Approx1 = ((((B0 + B1 * 2 ^ 24) + (B2 * 2 ^ 48 + B3 * 2 ^ 72)) + ((B4 * 2 ^ 96 + B5 * 2 ^ 120) + (B6 * 2 ^ 144 + B7 * 2 ^ 168))) + ((B8 * 2 ^ 192 + B9 * 2 ^ 216) + B10 * 2 ^ 240))
	while Approx1 >= 2 ^ 126 do
		if Approx0 < 2 ^ 166 and Approx1 >= 2 ^ 112 then
			local Q = math.min(math.floor(Approx0 / Approx1 * (1 - 2 ^ -40)), 16777215)
			local X0 = A0 - Q * B0
			local X1 = A1 - Q * B1
			local X2 = A2 - Q * B2
			local X3 = A3 - Q * B3
			local X4 = A4 - Q * B4
			local X5 = A5 - Q * B5
			local X6 = A6 - Q * B6
			local Y0 = S0 + Q * U0
			local Y1 = S1 + Q * U1
			local Y2 = S2 + Q * U2
			local Y3 = S3 + Q * U3
			local Y4 = S4 + Q * U4
			local Y5 = S5 + Q * U5
			local XC0 = X0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC1 = X1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC2 = X2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC3 = X3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC4 = X4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC5 = X5 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			X0 -= XC0
			X1 = X1 - XC1 + XC0 * 2 ^ -24
			X2 = X2 - XC2 + XC1 * 2 ^ -24
			X3 = X3 - XC3 + XC2 * 2 ^ -24
			X4 = X4 - XC4 + XC3 * 2 ^ -24
			X5 = X5 - XC5 + XC4 * 2 ^ -24
			X6 += XC5 * 2 ^ -24
			local YC0 = Y0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YC1 = Y1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YC2 = Y2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YC3 = Y3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YC4 = Y4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			Y0 -= YC0
			Y1 = Y1 - YC1 + YC0 * 2 ^ -24
			Y2 = Y2 - YC2 + YC1 * 2 ^ -24
			Y3 = Y3 - YC3 + YC2 * 2 ^ -24
			Y4 = Y4 - YC4 + YC3 * 2 ^ -24
			Y5 += YC4 * 2 ^ -24
			local XD0 = X0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD1 = X1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD2 = X2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD3 = X3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD4 = X4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD5 = X5 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			X0 -= XD0
			X1 = X1 - XD1 + XD0 * 2 ^ -24
			X2 = X2 - XD2 + XD1 * 2 ^ -24
			X3 = X3 - XD3 + XD2 * 2 ^ -24
			X4 = X4 - XD4 + XD3 * 2 ^ -24
			X5 = X5 - XD5 + XD4 * 2 ^ -24
			X6 += XD5 * 2 ^ -24
			local YD0 = Y0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YD1 = Y1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YD2 = Y2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YD3 = Y3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YD4 = Y4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			Y0 -= YD0
			Y1 = Y1 - YD1 + YD0 * 2 ^ -24
			Y2 = Y2 - YD2 + YD1 * 2 ^ -24
			Y3 = Y3 - YD3 + YD2 * 2 ^ -24
			Y4 = Y4 - YD4 + YD3 * 2 ^ -24
			Y5 += YD4 * 2 ^ -24
			local Approx2 = (((X0 + X1 * 2 ^ 24) + (X2 * 2 ^ 48 + X3 * 2 ^ 72)) + ((X4 * 2 ^ 96 + X5 * 2 ^ 120) + X6 * 2 ^ 144))
			if Approx2 >= Approx1 * (1 - 2 ^ -40) then
				local Slow = SLOW
				buffer.fill(Slow, 0, 0)
				buffer.writef64(Slow, 0, X0)
				buffer.writef64(Slow, 96, B0)
				buffer.writef64(Slow, 8, X1)
				buffer.writef64(Slow, 104, B1)
				buffer.writef64(Slow, 16, X2)
				buffer.writef64(Slow, 112, B2)
				buffer.writef64(Slow, 24, X3)
				buffer.writef64(Slow, 120, B3)
				buffer.writef64(Slow, 32, X4)
				buffer.writef64(Slow, 128, B4)
				buffer.writef64(Slow, 40, X5)
				buffer.writef64(Slow, 136, B5)
				buffer.writef64(Slow, 48, X6)
				buffer.writef64(Slow, 144, B6)
				buffer.writef64(Slow, 192, Y0)
				buffer.writef64(Slow, 288, U0)
				buffer.writef64(Slow, 200, Y1)
				buffer.writef64(Slow, 296, U1)
				buffer.writef64(Slow, 208, Y2)
				buffer.writef64(Slow, 304, U2)
				buffer.writef64(Slow, 216, Y3)
				buffer.writef64(Slow, 312, U3)
				buffer.writef64(Slow, 224, Y4)
				buffer.writef64(Slow, 320, U4)
				buffer.writef64(Slow, 232, Y5)
				buffer.writef64(Slow, 328, U5)
				SlowFinish(Slow)
				X0 = buffer.readf64(Slow, 0)
				X1 = buffer.readf64(Slow, 8)
				X2 = buffer.readf64(Slow, 16)
				X3 = buffer.readf64(Slow, 24)
				X4 = buffer.readf64(Slow, 32)
				X5 = buffer.readf64(Slow, 40)
				X6 = buffer.readf64(Slow, 48)
				Y0 = buffer.readf64(Slow, 192)
				Y1 = buffer.readf64(Slow, 200)
				Y2 = buffer.readf64(Slow, 208)
				Y3 = buffer.readf64(Slow, 216)
				Y4 = buffer.readf64(Slow, 224)
				Y5 = buffer.readf64(Slow, 232)
				Approx2 = (((X0 + X1 * 2 ^ 24) + (X2 * 2 ^ 48 + X3 * 2 ^ 72)) + ((X4 * 2 ^ 96 + X5 * 2 ^ 120) + X6 * 2 ^ 144))
			end
			A0, A1, A2, A3, A4, A5, A6 = B0, B1, B2, B3, B4, B5, B6
			B0, B1, B2, B3, B4, B5, B6 = X0, X1, X2, X3, X4, X5, X6
			S0, S1, S2, S3, S4, S5 = U0, U1, U2, U3, U4, U5
			U0, U1, U2, U3, U4, U5 = Y0, Y1, Y2, Y3, Y4, Y5
			Approx0, Approx1 = Approx1, Approx2
		elseif Approx0 < 2 ^ 190 and Approx1 >= 2 ^ 136 then
			local Q = math.min(math.floor(Approx0 / Approx1 * (1 - 2 ^ -40)), 16777215)
			local X0 = A0 - Q * B0
			local X1 = A1 - Q * B1
			local X2 = A2 - Q * B2
			local X3 = A3 - Q * B3
			local X4 = A4 - Q * B4
			local X5 = A5 - Q * B5
			local X6 = A6 - Q * B6
			local X7 = A7 - Q * B7
			local Y0 = S0 + Q * U0
			local Y1 = S1 + Q * U1
			local Y2 = S2 + Q * U2
			local Y3 = S3 + Q * U3
			local Y4 = S4 + Q * U4
			local XC0 = X0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC1 = X1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC2 = X2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC3 = X3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC4 = X4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC5 = X5 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC6 = X6 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			X0 -= XC0
			X1 = X1 - XC1 + XC0 * 2 ^ -24
			X2 = X2 - XC2 + XC1 * 2 ^ -24
			X3 = X3 - XC3 + XC2 * 2 ^ -24
			X4 = X4 - XC4 + XC3 * 2 ^ -24
			X5 = X5 - XC5 + XC4 * 2 ^ -24
			X6 = X6 - XC6 + XC5 * 2 ^ -24
			X7 += XC6 * 2 ^ -24
			local YC0 = Y0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YC1 = Y1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YC2 = Y2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YC3 = Y3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			Y0 -= YC0
			Y1 = Y1 - YC1 + YC0 * 2 ^ -24
			Y2 = Y2 - YC2 + YC1 * 2 ^ -24
			Y3 = Y3 - YC3 + YC2 * 2 ^ -24
			Y4 += YC3 * 2 ^ -24
			local XD0 = X0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD1 = X1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD2 = X2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD3 = X3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD4 = X4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD5 = X5 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD6 = X6 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			X0 -= XD0
			X1 = X1 - XD1 + XD0 * 2 ^ -24
			X2 = X2 - XD2 + XD1 * 2 ^ -24
			X3 = X3 - XD3 + XD2 * 2 ^ -24
			X4 = X4 - XD4 + XD3 * 2 ^ -24
			X5 = X5 - XD5 + XD4 * 2 ^ -24
			X6 = X6 - XD6 + XD5 * 2 ^ -24
			X7 += XD6 * 2 ^ -24
			local YD0 = Y0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YD1 = Y1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YD2 = Y2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YD3 = Y3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			Y0 -= YD0
			Y1 = Y1 - YD1 + YD0 * 2 ^ -24
			Y2 = Y2 - YD2 + YD1 * 2 ^ -24
			Y3 = Y3 - YD3 + YD2 * 2 ^ -24
			Y4 += YD3 * 2 ^ -24
			local Approx2 = (((X0 + X1 * 2 ^ 24) + (X2 * 2 ^ 48 + X3 * 2 ^ 72)) + ((X4 * 2 ^ 96 + X5 * 2 ^ 120) + (X6 * 2 ^ 144 + X7 * 2 ^ 168)))
			if Approx2 >= Approx1 * (1 - 2 ^ -40) then
				local Slow = SLOW
				buffer.fill(Slow, 0, 0)
				buffer.writef64(Slow, 0, X0)
				buffer.writef64(Slow, 96, B0)
				buffer.writef64(Slow, 8, X1)
				buffer.writef64(Slow, 104, B1)
				buffer.writef64(Slow, 16, X2)
				buffer.writef64(Slow, 112, B2)
				buffer.writef64(Slow, 24, X3)
				buffer.writef64(Slow, 120, B3)
				buffer.writef64(Slow, 32, X4)
				buffer.writef64(Slow, 128, B4)
				buffer.writef64(Slow, 40, X5)
				buffer.writef64(Slow, 136, B5)
				buffer.writef64(Slow, 48, X6)
				buffer.writef64(Slow, 144, B6)
				buffer.writef64(Slow, 56, X7)
				buffer.writef64(Slow, 152, B7)
				buffer.writef64(Slow, 192, Y0)
				buffer.writef64(Slow, 288, U0)
				buffer.writef64(Slow, 200, Y1)
				buffer.writef64(Slow, 296, U1)
				buffer.writef64(Slow, 208, Y2)
				buffer.writef64(Slow, 304, U2)
				buffer.writef64(Slow, 216, Y3)
				buffer.writef64(Slow, 312, U3)
				buffer.writef64(Slow, 224, Y4)
				buffer.writef64(Slow, 320, U4)
				SlowFinish(Slow)
				X0 = buffer.readf64(Slow, 0)
				X1 = buffer.readf64(Slow, 8)
				X2 = buffer.readf64(Slow, 16)
				X3 = buffer.readf64(Slow, 24)
				X4 = buffer.readf64(Slow, 32)
				X5 = buffer.readf64(Slow, 40)
				X6 = buffer.readf64(Slow, 48)
				X7 = buffer.readf64(Slow, 56)
				Y0 = buffer.readf64(Slow, 192)
				Y1 = buffer.readf64(Slow, 200)
				Y2 = buffer.readf64(Slow, 208)
				Y3 = buffer.readf64(Slow, 216)
				Y4 = buffer.readf64(Slow, 224)
				Approx2 = (((X0 + X1 * 2 ^ 24) + (X2 * 2 ^ 48 + X3 * 2 ^ 72)) + ((X4 * 2 ^ 96 + X5 * 2 ^ 120) + (X6 * 2 ^ 144 + X7 * 2 ^ 168)))
			end
			A0, A1, A2, A3, A4, A5, A6, A7 = B0, B1, B2, B3, B4, B5, B6, B7
			B0, B1, B2, B3, B4, B5, B6, B7 = X0, X1, X2, X3, X4, X5, X6, X7
			S0, S1, S2, S3, S4 = U0, U1, U2, U3, U4
			U0, U1, U2, U3, U4 = Y0, Y1, Y2, Y3, Y4
			Approx0, Approx1 = Approx1, Approx2
		elseif Approx0 < 2 ^ 214 and Approx1 >= 2 ^ 160 then
			local Q = math.min(math.floor(Approx0 / Approx1 * (1 - 2 ^ -40)), 16777215)
			local X0 = A0 - Q * B0
			local X1 = A1 - Q * B1
			local X2 = A2 - Q * B2
			local X3 = A3 - Q * B3
			local X4 = A4 - Q * B4
			local X5 = A5 - Q * B5
			local X6 = A6 - Q * B6
			local X7 = A7 - Q * B7
			local X8 = A8 - Q * B8
			local Y0 = S0 + Q * U0
			local Y1 = S1 + Q * U1
			local Y2 = S2 + Q * U2
			local Y3 = S3 + Q * U3
			local XC0 = X0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC1 = X1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC2 = X2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC3 = X3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC4 = X4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC5 = X5 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC6 = X6 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC7 = X7 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			X0 -= XC0
			X1 = X1 - XC1 + XC0 * 2 ^ -24
			X2 = X2 - XC2 + XC1 * 2 ^ -24
			X3 = X3 - XC3 + XC2 * 2 ^ -24
			X4 = X4 - XC4 + XC3 * 2 ^ -24
			X5 = X5 - XC5 + XC4 * 2 ^ -24
			X6 = X6 - XC6 + XC5 * 2 ^ -24
			X7 = X7 - XC7 + XC6 * 2 ^ -24
			X8 += XC7 * 2 ^ -24
			local YC0 = Y0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YC1 = Y1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YC2 = Y2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			Y0 -= YC0
			Y1 = Y1 - YC1 + YC0 * 2 ^ -24
			Y2 = Y2 - YC2 + YC1 * 2 ^ -24
			Y3 += YC2 * 2 ^ -24
			local XD0 = X0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD1 = X1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD2 = X2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD3 = X3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD4 = X4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD5 = X5 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD6 = X6 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD7 = X7 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			X0 -= XD0
			X1 = X1 - XD1 + XD0 * 2 ^ -24
			X2 = X2 - XD2 + XD1 * 2 ^ -24
			X3 = X3 - XD3 + XD2 * 2 ^ -24
			X4 = X4 - XD4 + XD3 * 2 ^ -24
			X5 = X5 - XD5 + XD4 * 2 ^ -24
			X6 = X6 - XD6 + XD5 * 2 ^ -24
			X7 = X7 - XD7 + XD6 * 2 ^ -24
			X8 += XD7 * 2 ^ -24
			local YD0 = Y0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YD1 = Y1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YD2 = Y2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			Y0 -= YD0
			Y1 = Y1 - YD1 + YD0 * 2 ^ -24
			Y2 = Y2 - YD2 + YD1 * 2 ^ -24
			Y3 += YD2 * 2 ^ -24
			local Approx2 = ((((X0 + X1 * 2 ^ 24) + (X2 * 2 ^ 48 + X3 * 2 ^ 72)) + ((X4 * 2 ^ 96 + X5 * 2 ^ 120) + (X6 * 2 ^ 144 + X7 * 2 ^ 168))) + X8 * 2 ^ 192)
			if Approx2 >= Approx1 * (1 - 2 ^ -40) then
				local Slow = SLOW
				buffer.fill(Slow, 0, 0)
				buffer.writef64(Slow, 0, X0)
				buffer.writef64(Slow, 96, B0)
				buffer.writef64(Slow, 8, X1)
				buffer.writef64(Slow, 104, B1)
				buffer.writef64(Slow, 16, X2)
				buffer.writef64(Slow, 112, B2)
				buffer.writef64(Slow, 24, X3)
				buffer.writef64(Slow, 120, B3)
				buffer.writef64(Slow, 32, X4)
				buffer.writef64(Slow, 128, B4)
				buffer.writef64(Slow, 40, X5)
				buffer.writef64(Slow, 136, B5)
				buffer.writef64(Slow, 48, X6)
				buffer.writef64(Slow, 144, B6)
				buffer.writef64(Slow, 56, X7)
				buffer.writef64(Slow, 152, B7)
				buffer.writef64(Slow, 64, X8)
				buffer.writef64(Slow, 160, B8)
				buffer.writef64(Slow, 192, Y0)
				buffer.writef64(Slow, 288, U0)
				buffer.writef64(Slow, 200, Y1)
				buffer.writef64(Slow, 296, U1)
				buffer.writef64(Slow, 208, Y2)
				buffer.writef64(Slow, 304, U2)
				buffer.writef64(Slow, 216, Y3)
				buffer.writef64(Slow, 312, U3)
				SlowFinish(Slow)
				X0 = buffer.readf64(Slow, 0)
				X1 = buffer.readf64(Slow, 8)
				X2 = buffer.readf64(Slow, 16)
				X3 = buffer.readf64(Slow, 24)
				X4 = buffer.readf64(Slow, 32)
				X5 = buffer.readf64(Slow, 40)
				X6 = buffer.readf64(Slow, 48)
				X7 = buffer.readf64(Slow, 56)
				X8 = buffer.readf64(Slow, 64)
				Y0 = buffer.readf64(Slow, 192)
				Y1 = buffer.readf64(Slow, 200)
				Y2 = buffer.readf64(Slow, 208)
				Y3 = buffer.readf64(Slow, 216)
				Approx2 = ((((X0 + X1 * 2 ^ 24) + (X2 * 2 ^ 48 + X3 * 2 ^ 72)) + ((X4 * 2 ^ 96 + X5 * 2 ^ 120) + (X6 * 2 ^ 144 + X7 * 2 ^ 168))) + X8 * 2 ^ 192)
			end
			A0, A1, A2, A3, A4, A5, A6, A7, A8 = B0, B1, B2, B3, B4, B5, B6, B7, B8
			B0, B1, B2, B3, B4, B5, B6, B7, B8 = X0, X1, X2, X3, X4, X5, X6, X7, X8
			S0, S1, S2, S3 = U0, U1, U2, U3
			U0, U1, U2, U3 = Y0, Y1, Y2, Y3
			Approx0, Approx1 = Approx1, Approx2
		elseif Approx0 < 2 ^ 238 and Approx1 >= 2 ^ 184 then
			local Q = math.min(math.floor(Approx0 / Approx1 * (1 - 2 ^ -40)), 16777215)
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
			local Y0 = S0 + Q * U0
			local Y1 = S1 + Q * U1
			local Y2 = S2 + Q * U2
			local XC0 = X0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC1 = X1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC2 = X2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC3 = X3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC4 = X4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC5 = X5 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC6 = X6 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC7 = X7 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC8 = X8 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			X0 -= XC0
			X1 = X1 - XC1 + XC0 * 2 ^ -24
			X2 = X2 - XC2 + XC1 * 2 ^ -24
			X3 = X3 - XC3 + XC2 * 2 ^ -24
			X4 = X4 - XC4 + XC3 * 2 ^ -24
			X5 = X5 - XC5 + XC4 * 2 ^ -24
			X6 = X6 - XC6 + XC5 * 2 ^ -24
			X7 = X7 - XC7 + XC6 * 2 ^ -24
			X8 = X8 - XC8 + XC7 * 2 ^ -24
			X9 += XC8 * 2 ^ -24
			local YC0 = Y0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YC1 = Y1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			Y0 -= YC0
			Y1 = Y1 - YC1 + YC0 * 2 ^ -24
			Y2 += YC1 * 2 ^ -24
			local XD0 = X0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD1 = X1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD2 = X2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD3 = X3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD4 = X4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD5 = X5 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD6 = X6 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD7 = X7 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD8 = X8 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			X0 -= XD0
			X1 = X1 - XD1 + XD0 * 2 ^ -24
			X2 = X2 - XD2 + XD1 * 2 ^ -24
			X3 = X3 - XD3 + XD2 * 2 ^ -24
			X4 = X4 - XD4 + XD3 * 2 ^ -24
			X5 = X5 - XD5 + XD4 * 2 ^ -24
			X6 = X6 - XD6 + XD5 * 2 ^ -24
			X7 = X7 - XD7 + XD6 * 2 ^ -24
			X8 = X8 - XD8 + XD7 * 2 ^ -24
			X9 += XD8 * 2 ^ -24
			local YD0 = Y0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YD1 = Y1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			Y0 -= YD0
			Y1 = Y1 - YD1 + YD0 * 2 ^ -24
			Y2 += YD1 * 2 ^ -24
			local Approx2 = ((((X0 + X1 * 2 ^ 24) + (X2 * 2 ^ 48 + X3 * 2 ^ 72)) + ((X4 * 2 ^ 96 + X5 * 2 ^ 120) + (X6 * 2 ^ 144 + X7 * 2 ^ 168))) + (X8 * 2 ^ 192 + X9 * 2 ^ 216))
			if Approx2 >= Approx1 * (1 - 2 ^ -40) then
				local Slow = SLOW
				buffer.fill(Slow, 0, 0)
				buffer.writef64(Slow, 0, X0)
				buffer.writef64(Slow, 96, B0)
				buffer.writef64(Slow, 8, X1)
				buffer.writef64(Slow, 104, B1)
				buffer.writef64(Slow, 16, X2)
				buffer.writef64(Slow, 112, B2)
				buffer.writef64(Slow, 24, X3)
				buffer.writef64(Slow, 120, B3)
				buffer.writef64(Slow, 32, X4)
				buffer.writef64(Slow, 128, B4)
				buffer.writef64(Slow, 40, X5)
				buffer.writef64(Slow, 136, B5)
				buffer.writef64(Slow, 48, X6)
				buffer.writef64(Slow, 144, B6)
				buffer.writef64(Slow, 56, X7)
				buffer.writef64(Slow, 152, B7)
				buffer.writef64(Slow, 64, X8)
				buffer.writef64(Slow, 160, B8)
				buffer.writef64(Slow, 72, X9)
				buffer.writef64(Slow, 168, B9)
				buffer.writef64(Slow, 192, Y0)
				buffer.writef64(Slow, 288, U0)
				buffer.writef64(Slow, 200, Y1)
				buffer.writef64(Slow, 296, U1)
				buffer.writef64(Slow, 208, Y2)
				buffer.writef64(Slow, 304, U2)
				SlowFinish(Slow)
				X0 = buffer.readf64(Slow, 0)
				X1 = buffer.readf64(Slow, 8)
				X2 = buffer.readf64(Slow, 16)
				X3 = buffer.readf64(Slow, 24)
				X4 = buffer.readf64(Slow, 32)
				X5 = buffer.readf64(Slow, 40)
				X6 = buffer.readf64(Slow, 48)
				X7 = buffer.readf64(Slow, 56)
				X8 = buffer.readf64(Slow, 64)
				X9 = buffer.readf64(Slow, 72)
				Y0 = buffer.readf64(Slow, 192)
				Y1 = buffer.readf64(Slow, 200)
				Y2 = buffer.readf64(Slow, 208)
				Approx2 = ((((X0 + X1 * 2 ^ 24) + (X2 * 2 ^ 48 + X3 * 2 ^ 72)) + ((X4 * 2 ^ 96 + X5 * 2 ^ 120) + (X6 * 2 ^ 144 + X7 * 2 ^ 168))) + (X8 * 2 ^ 192 + X9 * 2 ^ 216))
			end
			A0, A1, A2, A3, A4, A5, A6, A7, A8, A9 = B0, B1, B2, B3, B4, B5, B6, B7, B8, B9
			B0, B1, B2, B3, B4, B5, B6, B7, B8, B9 = X0, X1, X2, X3, X4, X5, X6, X7, X8, X9
			S0, S1, S2 = U0, U1, U2
			U0, U1, U2 = Y0, Y1, Y2
			Approx0, Approx1 = Approx1, Approx2
		elseif Approx1 >= 2 ^ 208 then
			local Q = math.min(math.floor(Approx0 / Approx1 * (1 - 2 ^ -40)), 16777215)
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
			local XC0 = X0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC1 = X1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC2 = X2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC3 = X3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC4 = X4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC5 = X5 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC6 = X6 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC7 = X7 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC8 = X8 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC9 = X9 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			X0 -= XC0
			X1 = X1 - XC1 + XC0 * 2 ^ -24
			X2 = X2 - XC2 + XC1 * 2 ^ -24
			X3 = X3 - XC3 + XC2 * 2 ^ -24
			X4 = X4 - XC4 + XC3 * 2 ^ -24
			X5 = X5 - XC5 + XC4 * 2 ^ -24
			X6 = X6 - XC6 + XC5 * 2 ^ -24
			X7 = X7 - XC7 + XC6 * 2 ^ -24
			X8 = X8 - XC8 + XC7 * 2 ^ -24
			X9 = X9 - XC9 + XC8 * 2 ^ -24
			X10 += XC9 * 2 ^ -24
			local YC0 = Y0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			Y0 -= YC0
			Y1 += YC0 * 2 ^ -24
			local XD0 = X0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD1 = X1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD2 = X2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD3 = X3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD4 = X4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD5 = X5 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD6 = X6 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD7 = X7 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD8 = X8 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD9 = X9 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			X0 -= XD0
			X1 = X1 - XD1 + XD0 * 2 ^ -24
			X2 = X2 - XD2 + XD1 * 2 ^ -24
			X3 = X3 - XD3 + XD2 * 2 ^ -24
			X4 = X4 - XD4 + XD3 * 2 ^ -24
			X5 = X5 - XD5 + XD4 * 2 ^ -24
			X6 = X6 - XD6 + XD5 * 2 ^ -24
			X7 = X7 - XD7 + XD6 * 2 ^ -24
			X8 = X8 - XD8 + XD7 * 2 ^ -24
			X9 = X9 - XD9 + XD8 * 2 ^ -24
			X10 += XD9 * 2 ^ -24
			local YD0 = Y0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			Y0 -= YD0
			Y1 += YD0 * 2 ^ -24
			local Approx2 = ((((X0 + X1 * 2 ^ 24) + (X2 * 2 ^ 48 + X3 * 2 ^ 72)) + ((X4 * 2 ^ 96 + X5 * 2 ^ 120) + (X6 * 2 ^ 144 + X7 * 2 ^ 168))) + ((X8 * 2 ^ 192 + X9 * 2 ^ 216) + X10 * 2 ^ 240))
			if Approx2 >= Approx1 * (1 - 2 ^ -40) then
				local Slow = SLOW
				buffer.fill(Slow, 0, 0)
				buffer.writef64(Slow, 0, X0)
				buffer.writef64(Slow, 96, B0)
				buffer.writef64(Slow, 8, X1)
				buffer.writef64(Slow, 104, B1)
				buffer.writef64(Slow, 16, X2)
				buffer.writef64(Slow, 112, B2)
				buffer.writef64(Slow, 24, X3)
				buffer.writef64(Slow, 120, B3)
				buffer.writef64(Slow, 32, X4)
				buffer.writef64(Slow, 128, B4)
				buffer.writef64(Slow, 40, X5)
				buffer.writef64(Slow, 136, B5)
				buffer.writef64(Slow, 48, X6)
				buffer.writef64(Slow, 144, B6)
				buffer.writef64(Slow, 56, X7)
				buffer.writef64(Slow, 152, B7)
				buffer.writef64(Slow, 64, X8)
				buffer.writef64(Slow, 160, B8)
				buffer.writef64(Slow, 72, X9)
				buffer.writef64(Slow, 168, B9)
				buffer.writef64(Slow, 80, X10)
				buffer.writef64(Slow, 176, B10)
				buffer.writef64(Slow, 192, Y0)
				buffer.writef64(Slow, 288, U0)
				buffer.writef64(Slow, 200, Y1)
				buffer.writef64(Slow, 296, U1)
				SlowFinish(Slow)
				X0 = buffer.readf64(Slow, 0)
				X1 = buffer.readf64(Slow, 8)
				X2 = buffer.readf64(Slow, 16)
				X3 = buffer.readf64(Slow, 24)
				X4 = buffer.readf64(Slow, 32)
				X5 = buffer.readf64(Slow, 40)
				X6 = buffer.readf64(Slow, 48)
				X7 = buffer.readf64(Slow, 56)
				X8 = buffer.readf64(Slow, 64)
				X9 = buffer.readf64(Slow, 72)
				X10 = buffer.readf64(Slow, 80)
				Y0 = buffer.readf64(Slow, 192)
				Y1 = buffer.readf64(Slow, 200)
				Approx2 = ((((X0 + X1 * 2 ^ 24) + (X2 * 2 ^ 48 + X3 * 2 ^ 72)) + ((X4 * 2 ^ 96 + X5 * 2 ^ 120) + (X6 * 2 ^ 144 + X7 * 2 ^ 168))) + ((X8 * 2 ^ 192 + X9 * 2 ^ 216) + X10 * 2 ^ 240))
			end
			A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10 = B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10
			B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10 = X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10
			S0, S1 = U0, U1
			U0, U1 = Y0, Y1
			Approx0, Approx1 = Approx1, Approx2
		else
			local Q = math.min(math.floor(Approx0 / Approx1 * (1 - 2 ^ -40)), 16777215)
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
			local XC0 = X0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC1 = X1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC2 = X2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC3 = X3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC4 = X4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC5 = X5 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC6 = X6 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC7 = X7 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC8 = X8 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XC9 = X9 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			X0 -= XC0
			X1 = X1 - XC1 + XC0 * 2 ^ -24
			X2 = X2 - XC2 + XC1 * 2 ^ -24
			X3 = X3 - XC3 + XC2 * 2 ^ -24
			X4 = X4 - XC4 + XC3 * 2 ^ -24
			X5 = X5 - XC5 + XC4 * 2 ^ -24
			X6 = X6 - XC6 + XC5 * 2 ^ -24
			X7 = X7 - XC7 + XC6 * 2 ^ -24
			X8 = X8 - XC8 + XC7 * 2 ^ -24
			X9 = X9 - XC9 + XC8 * 2 ^ -24
			X10 += XC9 * 2 ^ -24
			local YC0 = Y0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YC1 = Y1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YC2 = Y2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YC3 = Y3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YC4 = Y4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			Y0 -= YC0
			Y1 = Y1 - YC1 + YC0 * 2 ^ -24
			Y2 = Y2 - YC2 + YC1 * 2 ^ -24
			Y3 = Y3 - YC3 + YC2 * 2 ^ -24
			Y4 = Y4 - YC4 + YC3 * 2 ^ -24
			Y5 += YC4 * 2 ^ -24
			local XD0 = X0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD1 = X1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD2 = X2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD3 = X3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD4 = X4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD5 = X5 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD6 = X6 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD7 = X7 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD8 = X8 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local XD9 = X9 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			X0 -= XD0
			X1 = X1 - XD1 + XD0 * 2 ^ -24
			X2 = X2 - XD2 + XD1 * 2 ^ -24
			X3 = X3 - XD3 + XD2 * 2 ^ -24
			X4 = X4 - XD4 + XD3 * 2 ^ -24
			X5 = X5 - XD5 + XD4 * 2 ^ -24
			X6 = X6 - XD6 + XD5 * 2 ^ -24
			X7 = X7 - XD7 + XD6 * 2 ^ -24
			X8 = X8 - XD8 + XD7 * 2 ^ -24
			X9 = X9 - XD9 + XD8 * 2 ^ -24
			X10 += XD9 * 2 ^ -24
			local YD0 = Y0 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YD1 = Y1 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YD2 = Y2 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YD3 = Y3 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			local YD4 = Y4 + 1.5 * 2 ^ 76 - 1.5 * 2 ^ 76
			Y0 -= YD0
			Y1 = Y1 - YD1 + YD0 * 2 ^ -24
			Y2 = Y2 - YD2 + YD1 * 2 ^ -24
			Y3 = Y3 - YD3 + YD2 * 2 ^ -24
			Y4 = Y4 - YD4 + YD3 * 2 ^ -24
			Y5 += YD4 * 2 ^ -24
			local Approx2 = ((((X0 + X1 * 2 ^ 24) + (X2 * 2 ^ 48 + X3 * 2 ^ 72)) + ((X4 * 2 ^ 96 + X5 * 2 ^ 120) + (X6 * 2 ^ 144 + X7 * 2 ^ 168))) + ((X8 * 2 ^ 192 + X9 * 2 ^ 216) + X10 * 2 ^ 240))
			if Approx2 >= Approx1 * (1 - 2 ^ -40) then
				local Slow = SLOW
				buffer.fill(Slow, 0, 0)
				buffer.writef64(Slow, 0, X0)
				buffer.writef64(Slow, 96, B0)
				buffer.writef64(Slow, 8, X1)
				buffer.writef64(Slow, 104, B1)
				buffer.writef64(Slow, 16, X2)
				buffer.writef64(Slow, 112, B2)
				buffer.writef64(Slow, 24, X3)
				buffer.writef64(Slow, 120, B3)
				buffer.writef64(Slow, 32, X4)
				buffer.writef64(Slow, 128, B4)
				buffer.writef64(Slow, 40, X5)
				buffer.writef64(Slow, 136, B5)
				buffer.writef64(Slow, 48, X6)
				buffer.writef64(Slow, 144, B6)
				buffer.writef64(Slow, 56, X7)
				buffer.writef64(Slow, 152, B7)
				buffer.writef64(Slow, 64, X8)
				buffer.writef64(Slow, 160, B8)
				buffer.writef64(Slow, 72, X9)
				buffer.writef64(Slow, 168, B9)
				buffer.writef64(Slow, 80, X10)
				buffer.writef64(Slow, 176, B10)
				buffer.writef64(Slow, 192, Y0)
				buffer.writef64(Slow, 288, U0)
				buffer.writef64(Slow, 200, Y1)
				buffer.writef64(Slow, 296, U1)
				buffer.writef64(Slow, 208, Y2)
				buffer.writef64(Slow, 304, U2)
				buffer.writef64(Slow, 216, Y3)
				buffer.writef64(Slow, 312, U3)
				buffer.writef64(Slow, 224, Y4)
				buffer.writef64(Slow, 320, U4)
				buffer.writef64(Slow, 232, Y5)
				buffer.writef64(Slow, 328, U5)
				SlowFinish(Slow)
				X0 = buffer.readf64(Slow, 0)
				X1 = buffer.readf64(Slow, 8)
				X2 = buffer.readf64(Slow, 16)
				X3 = buffer.readf64(Slow, 24)
				X4 = buffer.readf64(Slow, 32)
				X5 = buffer.readf64(Slow, 40)
				X6 = buffer.readf64(Slow, 48)
				X7 = buffer.readf64(Slow, 56)
				X8 = buffer.readf64(Slow, 64)
				X9 = buffer.readf64(Slow, 72)
				X10 = buffer.readf64(Slow, 80)
				Y0 = buffer.readf64(Slow, 192)
				Y1 = buffer.readf64(Slow, 200)
				Y2 = buffer.readf64(Slow, 208)
				Y3 = buffer.readf64(Slow, 216)
				Y4 = buffer.readf64(Slow, 224)
				Y5 = buffer.readf64(Slow, 232)
				Approx2 = ((((X0 + X1 * 2 ^ 24) + (X2 * 2 ^ 48 + X3 * 2 ^ 72)) + ((X4 * 2 ^ 96 + X5 * 2 ^ 120) + (X6 * 2 ^ 144 + X7 * 2 ^ 168))) + ((X8 * 2 ^ 192 + X9 * 2 ^ 216) + X10 * 2 ^ 240))
			end
			A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10 = B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10
			B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10 = X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10
			S0, S1, S2, S3, S4, S5 = U0, U1, U2, U3, U4, U5
			U0, U1, U2, U3, U4, U5 = Y0, Y1, Y2, Y3, Y4, Y5
			Approx0, Approx1 = Approx1, Approx2
		end
		Negative = not Negative
	end
	local Carry
	Carry = 0
	B0 += Carry
	Carry = math.floor(B0 * 2 ^ -24)
	B0 -= Carry * 16777216
	B1 += Carry
	Carry = math.floor(B1 * 2 ^ -24)
	B1 -= Carry * 16777216
	B2 += Carry
	Carry = math.floor(B2 * 2 ^ -24)
	B2 -= Carry * 16777216
	B3 += Carry
	Carry = math.floor(B3 * 2 ^ -24)
	B3 -= Carry * 16777216
	B4 += Carry
	Carry = math.floor(B4 * 2 ^ -24)
	B4 -= Carry * 16777216
	B5 += Carry
	Carry = math.floor(B5 * 2 ^ -24)
	B5 -= Carry * 16777216
	B6 += Carry
	Carry = math.floor(B6 * 2 ^ -24)
	B6 -= Carry * 16777216
	B7 += Carry
	Carry = math.floor(B7 * 2 ^ -24)
	B7 -= Carry * 16777216
	B8 += Carry
	Carry = math.floor(B8 * 2 ^ -24)
	B8 -= Carry * 16777216
	B9 += Carry
	Carry = math.floor(B9 * 2 ^ -24)
	B9 -= Carry * 16777216
	B10 += Carry
	Carry = math.floor(B10 * 2 ^ -24)
	B10 -= Carry * 16777216
	Carry = 0
	U0 += Carry
	Carry = math.floor(U0 * 2 ^ -24)
	U0 -= Carry * 16777216
	U1 += Carry
	Carry = math.floor(U1 * 2 ^ -24)
	U1 -= Carry * 16777216
	U2 += Carry
	Carry = math.floor(U2 * 2 ^ -24)
	U2 -= Carry * 16777216
	U3 += Carry
	Carry = math.floor(U3 * 2 ^ -24)
	U3 -= Carry * 16777216
	U4 += Carry
	Carry = math.floor(U4 * 2 ^ -24)
	U4 -= Carry * 16777216
	U5 += Carry
	Carry = math.floor(U5 * 2 ^ -24)
	U5 -= Carry * 16777216
	buffer.writef64(Out, 0, B0)
	buffer.writef64(Out, 8, B1)
	buffer.writef64(Out, 16, B2)
	buffer.writef64(Out, 24, B3)
	buffer.writef64(Out, 32, B4)
	buffer.writef64(Out, 40, B5)
	buffer.writef64(Out, 48, U0)
	buffer.writef64(Out, 56, U1)
	buffer.writef64(Out, 64, U2)
	buffer.writef64(Out, 72, U3)
	buffer.writef64(Out, 80, U4)
	buffer.writef64(Out, 88, U5)
	buffer.writeu32(Out, 96, B0)
	buffer.writeu32(Out, 99, B1)
	buffer.writeu32(Out, 102, B2)
	buffer.writeu32(Out, 105, B3)
	buffer.writeu32(Out, 108, B4)
	buffer.writeu32(Out, 111, B5)
	buffer.writeu32(Out, 120, U0)
	buffer.writeu32(Out, 123, U1)
	buffer.writeu32(Out, 126, U2)
	buffer.writeu32(Out, 129, U3)
	buffer.writeu32(Out, 132, U4)
	buffer.writeu32(Out, 135, U5)
	return Negative
end

return ScalarSplit
