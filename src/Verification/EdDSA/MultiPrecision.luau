--[=[
	Cryptography library: Multi-Precision Arithmetic (264-bit integers)

	Return type: varies by function
	Example usage:
		local MultiPrecision = require("MultiPrecision")

		--------Usage Case 1: Basic arithmetic--------
		local NumberA = MultiPrecision.Num(42)
		local NumberB = MultiPrecision.Num(17)
		local Sum = MultiPrecision.Add(NumberA, NumberB)
		local Product = MultiPrecision.Mul(NumberA, NumberB)

		--------Usage Case 2: Carry operations--------
		local LargeSum = MultiPrecision.Add(Sum, Product)
		local Normalized = MultiPrecision.Carry(LargeSum)
--]=]

--!strict
--!native
--!optimize 2

local CARRY = 88
local SIZE = 96

local function CarryWeak(LargeNumber: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(LargeNumber, 0), buffer.readf64(LargeNumber, 8),
		buffer.readf64(LargeNumber, 16), buffer.readf64(LargeNumber, 24),
		buffer.readf64(LargeNumber, 32), buffer.readf64(LargeNumber, 40),
		buffer.readf64(LargeNumber, 48), buffer.readf64(LargeNumber, 56),
		buffer.readf64(LargeNumber, 64), buffer.readf64(LargeNumber, 72),
		buffer.readf64(LargeNumber, 80)

	local Carry00 = A00 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A01 = A01 + Carry00 * 2 ^ -24
	local Carry01 = A01 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A02 = A02 + Carry01 * 2 ^ -24
	local Carry02 = A02 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A03 = A03 + Carry02 * 2 ^ -24
	local Carry03 = A03 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A04 = A04 + Carry03 * 2 ^ -24
	local Carry04 = A04 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A05 = A05 + Carry04 * 2 ^ -24
	local Carry05 = A05 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A06 = A06 + Carry05 * 2 ^ -24
	local Carry06 = A06 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A07 = A07 + Carry06 * 2 ^ -24
	local Carry07 = A07 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A08 = A08 + Carry07 * 2 ^ -24
	local Carry08 = A08 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A09 = A09 + Carry08 * 2 ^ -24
	local Carry09 = A09 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A10 = A10 + Carry09 * 2 ^ -24
	local Carry10 = A10 + 3 * 2 ^ 75 - 3 * 2 ^ 75

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 - Carry00)
	buffer.writef64(Buf, 8, A01 - Carry01)
	buffer.writef64(Buf, 16, A02 - Carry02)
	buffer.writef64(Buf, 24, A03 - Carry03)
	buffer.writef64(Buf, 32, A04 - Carry04)
	buffer.writef64(Buf, 40, A05 - Carry05)
	buffer.writef64(Buf, 48, A06 - Carry06)
	buffer.writef64(Buf, 56, A07 - Carry07)
	buffer.writef64(Buf, 64, A08 - Carry08)
	buffer.writef64(Buf, 72, A09 - Carry09)
	buffer.writef64(Buf, 80, A10 - Carry10)
	buffer.writef64(Buf, 88, Carry10 * 2 ^ -24)

	return Buf
end

local function Carry(LargeNumber: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(LargeNumber, 0), buffer.readf64(LargeNumber, 8),
		buffer.readf64(LargeNumber, 16), buffer.readf64(LargeNumber, 24),
		buffer.readf64(LargeNumber, 32), buffer.readf64(LargeNumber, 40),
		buffer.readf64(LargeNumber, 48), buffer.readf64(LargeNumber, 56),
		buffer.readf64(LargeNumber, 64), buffer.readf64(LargeNumber, 72),
		buffer.readf64(LargeNumber, 80)

	local Low00 = A00 % 2 ^ 24; A01 = A01 + (A00 - Low00) * 2 ^ -24
	local Low01 = A01 % 2 ^ 24; A02 = A02 + (A01 - Low01) * 2 ^ -24
	local Low02 = A02 % 2 ^ 24; A03 = A03 + (A02 - Low02) * 2 ^ -24
	local Low03 = A03 % 2 ^ 24; A04 = A04 + (A03 - Low03) * 2 ^ -24
	local Low04 = A04 % 2 ^ 24; A05 = A05 + (A04 - Low04) * 2 ^ -24
	local Low05 = A05 % 2 ^ 24; A06 = A06 + (A05 - Low05) * 2 ^ -24
	local Low06 = A06 % 2 ^ 24; A07 = A07 + (A06 - Low06) * 2 ^ -24
	local Low07 = A07 % 2 ^ 24; A08 = A08 + (A07 - Low07) * 2 ^ -24
	local Low08 = A08 % 2 ^ 24; A09 = A09 + (A08 - Low08) * 2 ^ -24
	local Low09 = A09 % 2 ^ 24; A10 = A10 + (A09 - Low09) * 2 ^ -24
	local Low10 = A10 % 2 ^ 24

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, Low00)
	buffer.writef64(Buf, 8, Low01)
	buffer.writef64(Buf, 16, Low02)
	buffer.writef64(Buf, 24, Low03)
	buffer.writef64(Buf, 32, Low04)
	buffer.writef64(Buf, 40, Low05)
	buffer.writef64(Buf, 48, Low06)
	buffer.writef64(Buf, 56, Low07)
	buffer.writef64(Buf, 64, Low08)
	buffer.writef64(Buf, 72, Low09)
	buffer.writef64(Buf, 80, Low10)
	buffer.writef64(Buf, 88, (A10 - Low10) * 2 ^ -24)

	return Buf
end

local function Add(NumberA: buffer, NumberB: buffer): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(NumberA, 0), buffer.readf64(NumberA, 8),
		buffer.readf64(NumberA, 16), buffer.readf64(NumberA, 24),
		buffer.readf64(NumberA, 32), buffer.readf64(NumberA, 40),
		buffer.readf64(NumberA, 48), buffer.readf64(NumberA, 56),
		buffer.readf64(NumberA, 64), buffer.readf64(NumberA, 72),
		buffer.readf64(NumberA, 80)

	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 = 
		buffer.readf64(NumberB, 0), buffer.readf64(NumberB, 8),
		buffer.readf64(NumberB, 16), buffer.readf64(NumberB, 24),
		buffer.readf64(NumberB, 32), buffer.readf64(NumberB, 40),
		buffer.readf64(NumberB, 48), buffer.readf64(NumberB, 56),
		buffer.readf64(NumberB, 64), buffer.readf64(NumberB, 72),
		buffer.readf64(NumberB, 80)

	local Buf = buffer.create(SIZE)
	buffer.writef64(Buf, 0, A00 + B00)
	buffer.writef64(Buf, 8, A01 + B01)
	buffer.writef64(Buf, 16, A02 + B02)
	buffer.writef64(Buf, 24, A03 + B03)
	buffer.writef64(Buf, 32, A04 + B04)
	buffer.writef64(Buf, 40, A05 + B05)
	buffer.writef64(Buf, 48, A06 + B06)
	buffer.writef64(Buf, 56, A07 + B07)
	buffer.writef64(Buf, 64, A08 + B08)
	buffer.writef64(Buf, 72, A09 + B09)
	buffer.writef64(Buf, 80, A10 + B10)

	return Buf
end

local function Sub(NumberA: buffer, NumberB: buffer): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(NumberA, 0), buffer.readf64(NumberA, 8),
		buffer.readf64(NumberA, 16), buffer.readf64(NumberA, 24),
		buffer.readf64(NumberA, 32), buffer.readf64(NumberA, 40),
		buffer.readf64(NumberA, 48), buffer.readf64(NumberA, 56),
		buffer.readf64(NumberA, 64), buffer.readf64(NumberA, 72),
		buffer.readf64(NumberA, 80)

	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 = 
		buffer.readf64(NumberB, 0), buffer.readf64(NumberB, 8),
		buffer.readf64(NumberB, 16), buffer.readf64(NumberB, 24),
		buffer.readf64(NumberB, 32), buffer.readf64(NumberB, 40),
		buffer.readf64(NumberB, 48), buffer.readf64(NumberB, 56),
		buffer.readf64(NumberB, 64), buffer.readf64(NumberB, 72),
		buffer.readf64(NumberB, 80)

	local Buf = buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 - B00)
	buffer.writef64(Buf, 8, A01 - B01)
	buffer.writef64(Buf, 16, A02 - B02)
	buffer.writef64(Buf, 24, A03 - B03)
	buffer.writef64(Buf, 32, A04 - B04)
	buffer.writef64(Buf, 40, A05 - B05)
	buffer.writef64(Buf, 48, A06 - B06)
	buffer.writef64(Buf, 56, A07 - B07)
	buffer.writef64(Buf, 64, A08 - B08)
	buffer.writef64(Buf, 72, A09 - B09)
	buffer.writef64(Buf, 80, A10 - B10)

	return Buf
end

local function LMul(NumberA: buffer, NumberB: buffer): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(NumberA, 0), buffer.readf64(NumberA, 8),
		buffer.readf64(NumberA, 16), buffer.readf64(NumberA, 24),
		buffer.readf64(NumberA, 32), buffer.readf64(NumberA, 40),
		buffer.readf64(NumberA, 48), buffer.readf64(NumberA, 56),
		buffer.readf64(NumberA, 64), buffer.readf64(NumberA, 72),
		buffer.readf64(NumberA, 80)

	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 = 
		buffer.readf64(NumberB, 0), buffer.readf64(NumberB, 8),
		buffer.readf64(NumberB, 16), buffer.readf64(NumberB, 24),
		buffer.readf64(NumberB, 32), buffer.readf64(NumberB, 40),
		buffer.readf64(NumberB, 48), buffer.readf64(NumberB, 56),
		buffer.readf64(NumberB, 64), buffer.readf64(NumberB, 72),
		buffer.readf64(NumberB, 80)

	local Buf = buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 * B00)
	buffer.writef64(Buf, 8, A01 * B00 + A00 * B01)
	buffer.writef64(Buf, 16, A02 * B00 + A01 * B01 + A00 * B02)
	buffer.writef64(Buf, 24, A03 * B00 + A02 * B01 + A01 * B02 + A00 * B03)
	buffer.writef64(Buf, 32, A04 * B00 + A03 * B01 + A02 * B02 + A01 * B03 + A00 * B04)
	buffer.writef64(Buf, 40, A05 * B00 + A04 * B01 + A03 * B02 + A02 * B03 + A01 * B04 + A00 * B05)
	buffer.writef64(Buf, 48, A06 * B00 + A05 * B01 + A04 * B02 + A03 * B03 + A02 * B04 + A01 * B05 + A00 * B06)
	buffer.writef64(Buf, 56, A07 * B00 + A06 * B01 + A05 * B02 + A04 * B03 + A03 * B04 + A02 * B05 + A01 * B06 + A00 * B07)
	buffer.writef64(Buf, 64, A08 * B00 + A07 * B01 + A06 * B02 + A05 * B03 + A04 * B04 + A03 * B05 + A02 * B06 + A01 * B07 + A00 * B08)
	buffer.writef64(Buf, 72, A09 * B00 + A08 * B01 + A07 * B02 + A06 * B03 + A05 * B04 + A04 * B05 + A03 * B06 + A02 * B07 + A01 * B08 + A00 * B09)
	buffer.writef64(Buf, 80, A10 * B00 + A09 * B01 + A08 * B02 + A07 * B03 + A06 * B04 + A05 * B05 + A04 * B06 + A03 * B07 + A02 * B08 + A01 * B09 + A00 * B10)

	return Carry(Buf, Buf)
end

local function Mul(NumberA: buffer, NumberB: buffer): (buffer, buffer)
	local LowResult = LMul(NumberA, NumberB)
	local Overflow = buffer.readf64(LowResult, CARRY)

	local A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(NumberA, 8), buffer.readf64(NumberA, 16), 
		buffer.readf64(NumberA, 24), buffer.readf64(NumberA, 32),
		buffer.readf64(NumberA, 40), buffer.readf64(NumberA, 48),
		buffer.readf64(NumberA, 56), buffer.readf64(NumberA, 64), 
		buffer.readf64(NumberA, 72), buffer.readf64(NumberA, 80)

	local B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 =
		buffer.readf64(NumberB, 8), buffer.readf64(NumberB, 16), 
		buffer.readf64(NumberB, 24), buffer.readf64(NumberB, 32),
		buffer.readf64(NumberB, 40), buffer.readf64(NumberB, 48),
		buffer.readf64(NumberB, 56), buffer.readf64(NumberB, 64), 
		buffer.readf64(NumberB, 72), buffer.readf64(NumberB, 80)

	local Buf = buffer.create(SIZE)

	buffer.writef64(Buf, 0, Overflow + A10 * B01 + A09 * B02 + A08 * B03 + A07 * B04 + A06 * B05 + A05 * B06 + A04 * B07 + A03 * B08 + A02 * B09 + A01 * B10)
	buffer.writef64(Buf, 8, A10 * B02 + A09 * B03 + A08 * B04 + A07 * B05 + A06 * B06 + A05 * B07 + A04 * B08 + A03 * B09 + A02 * B10)
	buffer.writef64(Buf, 16, A10 * B03 + A09 * B04 + A08 * B05 + A07 * B06 + A06 * B07 + A05 * B08 + A04 * B09 + A03 * B10)
	buffer.writef64(Buf, 24, A10 * B04 + A09 * B05 + A08 * B06 + A07 * B07 + A06 * B08 + A05 * B09 + A04 * B10)
	buffer.writef64(Buf, 32, A10 * B05 + A09 * B06 + A08 * B07 + A07 * B08 + A06 * B09 + A05 * B10)
	buffer.writef64(Buf, 40, A10 * B06 + A09 * B07 + A08 * B08 + A07 * B09 + A06 * B10)
	buffer.writef64(Buf, 48, A10 * B07 + A09 * B08 + A08 * B09 + A07 * B10)
	buffer.writef64(Buf, 56, A10 * B08 + A09 * B09 + A08 * B10)
	buffer.writef64(Buf, 64, A10 * B09 + A09 * B10)
	buffer.writef64(Buf, 72, A10 * B10)
	buffer.writef64(Buf, 80, 0)

	return LowResult, Carry(Buf, Buf)
end

local function DWAdd(NumberA0: buffer, NumberA1: buffer, NumberB0: buffer, NumberB1: buffer): (buffer, buffer, number)
	local LowSum = Carry(Add(NumberA0, NumberB0))
	local CarryOut = buffer.readf64(LowSum, CARRY)

	local HighSum = Add(NumberA1, NumberB1)
	buffer.writef64(HighSum, 0, buffer.readf64(HighSum, 0) + CarryOut)
	local Carried = Carry(HighSum, HighSum)

	return LowSum, Carried, buffer.readf64(Carried, CARRY)
end

local function Half(NumberA: buffer): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(NumberA, 0),
		buffer.readf64(NumberA, 8),
		buffer.readf64(NumberA, 16),
		buffer.readf64(NumberA, 24),
		buffer.readf64(NumberA, 32),
		buffer.readf64(NumberA, 40),
		buffer.readf64(NumberA, 48),
		buffer.readf64(NumberA, 56),
		buffer.readf64(NumberA, 64),
		buffer.readf64(NumberA, 72),
		buffer.readf64(NumberA, 80)

	local Buf = buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 * 0.5 + A01 * 2 ^ 23)
	buffer.writef64(Buf, 8, A02 * 2 ^ 23)
	buffer.writef64(Buf, 16, A03 * 2 ^ 23)
	buffer.writef64(Buf, 24, A04 * 2 ^ 23)
	buffer.writef64(Buf, 32, A05 * 2 ^ 23)
	buffer.writef64(Buf, 40, A06 * 2 ^ 23)
	buffer.writef64(Buf, 48, A07 * 2 ^ 23)
	buffer.writef64(Buf, 56, A08 * 2 ^ 23)
	buffer.writef64(Buf, 64, A09 * 2 ^ 23)
	buffer.writef64(Buf, 72, A10 * 2 ^ 23)
	buffer.writef64(Buf, 80, 0)

	return CarryWeak(Buf, Buf)
end

local function Third(NumberA: buffer): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(NumberA, 0),
		buffer.readf64(NumberA, 8),
		buffer.readf64(NumberA, 16),
		buffer.readf64(NumberA, 24),
		buffer.readf64(NumberA, 32),
		buffer.readf64(NumberA, 40),
		buffer.readf64(NumberA, 48),
		buffer.readf64(NumberA, 56),
		buffer.readf64(NumberA, 64),
		buffer.readf64(NumberA, 72),
		buffer.readf64(NumberA, 80)

	local Division00 = A00 * 0xaaaaaa
	local Division01 = A01 * 0xaaaaaa + Division00
	local Division02 = A02 * 0xaaaaaa + Division01
	local Division03 = A03 * 0xaaaaaa + Division02
	local Division04 = A04 * 0xaaaaaa + Division03
	local Division05 = A05 * 0xaaaaaa + Division04
	local Division06 = A06 * 0xaaaaaa + Division05
	local Division07 = A07 * 0xaaaaaa + Division06
	local Division08 = A08 * 0xaaaaaa + Division07
	local Division09 = A09 * 0xaaaaaa + Division08
	local Division10 = A10 * 0xaaaaaa + Division09

	local Buf = buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 + Division00)
	buffer.writef64(Buf, 8, A01 + Division01)
	buffer.writef64(Buf, 16, A02 + Division02)
	buffer.writef64(Buf, 24, A03 + Division03)
	buffer.writef64(Buf, 32, A04 + Division04)
	buffer.writef64(Buf, 40, A05 + Division05)
	buffer.writef64(Buf, 48, A06 + Division06)
	buffer.writef64(Buf, 56, A07 + Division07)
	buffer.writef64(Buf, 64, A08 + Division08)
	buffer.writef64(Buf, 72, A09 + Division09)
	buffer.writef64(Buf, 80, A10 + Division10)

	return CarryWeak(Buf, Buf)
end

local function Mod2(NumberA: buffer): number
	return buffer.readf64(NumberA, 0) % 2
end

local function Mod3(NumberA: buffer): number
	return (
		buffer.readf64(NumberA, 0) + 
			buffer.readf64(NumberA, 8) + 
			buffer.readf64(NumberA, 16) + 
			buffer.readf64(NumberA, 24) + 
			buffer.readf64(NumberA, 32) + 
			buffer.readf64(NumberA, 40) + 
			buffer.readf64(NumberA, 48) + 
			buffer.readf64(NumberA, 56) + 
			buffer.readf64(NumberA, 64) + 
			buffer.readf64(NumberA, 72) + 
			buffer.readf64(NumberA, 80)
	) % 3
end

local function Approx(NumberA: buffer): number
	return buffer.readf64(NumberA, 0)
		+ buffer.readf64(NumberA, 8) * 2 ^ 24
		+ buffer.readf64(NumberA, 16) * 2 ^ 48
		+ buffer.readf64(NumberA, 24) * 2 ^ 72
		+ buffer.readf64(NumberA, 32) * 2 ^ 96
		+ buffer.readf64(NumberA, 40) * 2 ^ 120
		+ buffer.readf64(NumberA, 48) * 2 ^ 144
		+ buffer.readf64(NumberA, 56) * 2 ^ 168
		+ buffer.readf64(NumberA, 64) * 2 ^ 192
		+ buffer.readf64(NumberA, 72) * 2 ^ 216
		+ buffer.readf64(NumberA, 80) * 2 ^ 240
end

local function Cmp(NumberA: buffer, NumberB: buffer): number
	return Approx(Sub(NumberA, NumberB))
end

local function Num(RegularNumber: number): buffer
	local Buf = buffer.create(SIZE)
	buffer.writef64(Buf, 0, RegularNumber)
	return Buf
end

return {
	Carry = Carry,
	CarryWeak = CarryWeak,
	Add = Add,
	Sub = Sub,
	DWAdd = DWAdd,
	LMul = LMul,
	Mul = Mul,
	Half = Half,
	Third = Third,
	Mod2 = Mod2,
	Mod3 = Mod3,
	Approx = Approx,
	Cmp = Cmp,
	Num = Num,
}