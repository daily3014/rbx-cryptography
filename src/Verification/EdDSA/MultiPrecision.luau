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

--!native
--!optimize 2


local Unpack = unpack or table.unpack

-- carry a number in base 2^24 into signed limb form (weaker version)
local function CarryWeak(LargeNumber)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = Unpack(LargeNumber)

	local Carry00 = A00 + 3 * 2 ^ 75 - 3 * 2 ^ 75 A01 = A01 + Carry00 * 2 ^ -24
	local Carry01 = A01 + 3 * 2 ^ 75 - 3 * 2 ^ 75 A02 = A02 + Carry01 * 2 ^ -24
	local Carry02 = A02 + 3 * 2 ^ 75 - 3 * 2 ^ 75 A03 = A03 + Carry02 * 2 ^ -24
	local Carry03 = A03 + 3 * 2 ^ 75 - 3 * 2 ^ 75 A04 = A04 + Carry03 * 2 ^ -24
	local Carry04 = A04 + 3 * 2 ^ 75 - 3 * 2 ^ 75 A05 = A05 + Carry04 * 2 ^ -24
	local Carry05 = A05 + 3 * 2 ^ 75 - 3 * 2 ^ 75 A06 = A06 + Carry05 * 2 ^ -24
	local Carry06 = A06 + 3 * 2 ^ 75 - 3 * 2 ^ 75 A07 = A07 + Carry06 * 2 ^ -24
	local Carry07 = A07 + 3 * 2 ^ 75 - 3 * 2 ^ 75 A08 = A08 + Carry07 * 2 ^ -24
	local Carry08 = A08 + 3 * 2 ^ 75 - 3 * 2 ^ 75 A09 = A09 + Carry08 * 2 ^ -24
	local Carry09 = A09 + 3 * 2 ^ 75 - 3 * 2 ^ 75 A10 = A10 + Carry09 * 2 ^ -24
	local Carry10 = A10 + 3 * 2 ^ 75 - 3 * 2 ^ 75

	return {
		A00 - Carry00,
		A01 - Carry01,
		A02 - Carry02,
		A03 - Carry03,
		A04 - Carry04,
		A05 - Carry05,
		A06 - Carry06,
		A07 - Carry07,
		A08 - Carry08,
		A09 - Carry09,
		A10 - Carry10,
	}, Carry10 * 2 ^ -24
end

-- carry a number in base 2^24 (proper version)
local function Carry(LargeNumber)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = Unpack(LargeNumber)

	local Low00 = A00 % 2 ^ 24 A01 = A01 + (A00 - Low00) * 2 ^ -24
	local Low01 = A01 % 2 ^ 24 A02 = A02 + (A01 - Low01) * 2 ^ -24
	local Low02 = A02 % 2 ^ 24 A03 = A03 + (A02 - Low02) * 2 ^ -24
	local Low03 = A03 % 2 ^ 24 A04 = A04 + (A03 - Low03) * 2 ^ -24
	local Low04 = A04 % 2 ^ 24 A05 = A05 + (A04 - Low04) * 2 ^ -24
	local Low05 = A05 % 2 ^ 24 A06 = A06 + (A05 - Low05) * 2 ^ -24
	local Low06 = A06 % 2 ^ 24 A07 = A07 + (A06 - Low06) * 2 ^ -24
	local Low07 = A07 % 2 ^ 24 A08 = A08 + (A07 - Low07) * 2 ^ -24
	local Low08 = A08 % 2 ^ 24 A09 = A09 + (A08 - Low08) * 2 ^ -24
	local Low09 = A09 % 2 ^ 24 A10 = A10 + (A09 - Low09) * 2 ^ -24
	local Low10 = A10 % 2 ^ 24
	local High10 = (A10 - Low10) * 2 ^ -24

	return {Low00, Low01, Low02, Low03, Low04, Low05, Low06, Low07, Low08, Low09, Low10}, High10
end

-- add two multi-precision numbers
local function Add(NumberA, NumberB)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = Unpack(NumberA)
	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 = Unpack(NumberB)

	return {
		A00 + B00,
		A01 + B01,
		A02 + B02,
		A03 + B03,
		A04 + B04,
		A05 + B05,
		A06 + B06,
		A07 + B07,
		A08 + B08,
		A09 + B09,
		A10 + B10,
	}
end

-- subtract one multi-precision number from another
local function Sub(NumberA, NumberB)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = Unpack(NumberA)
	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 = Unpack(NumberB)

	return {
		A00 - B00,
		A01 - B01,
		A02 - B02,
		A03 - B03,
		A04 - B04,
		A05 - B05,
		A06 - B06,
		A07 - B07,
		A08 - B08,
		A09 - B09,
		A10 - B10,
	}
end

-- compute lower half of product between two numbers
local function LMul(NumberA, NumberB)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = Unpack(NumberA)
	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 = Unpack(NumberB)

	return Carry {
		A00 * B00,
		A01 * B00 + A00 * B01,
		A02 * B00 + A01 * B01 + A00 * B02,
		A03 * B00 + A02 * B01 + A01 * B02 + A00 * B03,
		A04 * B00 + A03 * B01 + A02 * B02 + A01 * B03 + A00 * B04,
		A05 * B00 + A04 * B01 + A03 * B02 + A02 * B03 + A01 * B04 + A00 * B05,
		A06 * B00 + A05 * B01 + A04 * B02 + A03 * B03 + A02 * B04 + A01 * B05 + A00 * B06,
		A07 * B00 + A06 * B01 + A05 * B02 + A04 * B03 + A03 * B04 + A02 * B05 + A01 * B06 + A00 * B07,
		A08 * B00 + A07 * B01 + A06 * B02 + A05 * B03 + A04 * B04 + A03 * B05 + A02 * B06 + A01 * B07 + A00 * B08,
		A09 * B00 + A08 * B01 + A07 * B02 + A06 * B03 + A05 * B04 + A04 * B05 + A03 * B06 + A02 * B07 + A01 * B08 + A00 * B09,
		A10 * B00 + A09 * B01 + A08 * B02 + A07 * B03 + A06 * B04 + A05 * B05 + A04 * B06 + A03 * B07 + A02 * B08 + A01 * B09 + A00 * B10,
	}
end

-- compute full product between two numbers
local function Mul(NumberA, NumberB)
	local LowResult, Overflow = LMul(NumberA, NumberB)

	local _, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = Unpack(NumberA)
	local _, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 = Unpack(NumberB)

	-- the carry is always 0 here
	return LowResult, (Carry {
		Overflow + A10 * B01 + A09 * B02 + A08 * B03 + A07 * B04 + A06 * B05 + A05 * B06 + A04 * B07 + A03 * B08 + A02 * B09 + A01 * B10,
		A10 * B02 + A09 * B03 + A08 * B04 + A07 * B05 + A06 * B06 + A05 * B07 + A04 * B08 + A03 * B09 + A02 * B10,
		A10 * B03 + A09 * B04 + A08 * B05 + A07 * B06 + A06 * B07 + A05 * B08 + A04 * B09 + A03 * B10,
		A10 * B04 + A09 * B05 + A08 * B06 + A07 * B07 + A06 * B08 + A05 * B09 + A04 * B10,
		A10 * B05 + A09 * B06 + A08 * B07 + A07 * B08 + A06 * B09 + A05 * B10,
		A10 * B06 + A09 * B07 + A08 * B08 + A07 * B09 + A06 * B10,
		A10 * B07 + A09 * B08 + A08 * B09 + A07 * B10,
		A10 * B08 + A09 * B09 + A08 * B10,
		A10 * B09 + A09 * B10,
		A10 * B10,
		0
	})
end

-- compute double-width sum of two numbers
local function DWAdd(NumberA0, NumberA1, NumberB0, NumberB1)
	local LowSum, CarryOut = Carry(Add(NumberA0, NumberB0))
	local HighSum = Add(NumberA1, NumberB1)
	HighSum[1] = HighSum[1] + CarryOut
	return LowSum, Carry(HighSum)
end

-- compute half of a number (divide by 2)
local function Half(NumberA)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = Unpack(NumberA)

	return (CarryWeak {
		A00 * 0.5 + A01 * 2 ^ 23,
		A02 * 2 ^ 23,
		A03 * 2 ^ 23,
		A04 * 2 ^ 23,
		A05 * 2 ^ 23,
		A06 * 2 ^ 23,
		A07 * 2 ^ 23,
		A08 * 2 ^ 23,
		A09 * 2 ^ 23,
		A10 * 2 ^ 23,
		0,
	})
end

-- compute a third of a number (divide by 3)
local function Third(NumberA)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = Unpack(NumberA)

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

	-- compute modular division mod 2^264, carry isn't 0 but isn't part of a/3 either
	return (CarryWeak {
		A00 + Division00,
		A01 + Division01,
		A02 + Division02,
		A03 + Division03,
		A04 + Division04,
		A05 + Division05,
		A06 + Division06,
		A07 + Division07,
		A08 + Division08,
		A09 + Division09,
		A10 + Division10,
	})
end

-- compute a number modulo 2
local function Mod2(NumberA)
	return NumberA[1] % 2
end

-- compute a number modulo 3
local function Mod3(NumberA)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = Unpack(NumberA)
	return (A00 + A01 + A02 + A03 + A04 + A05 + A06 + A07 + A08 + A09 + A10) % 3
end

-- compute floating point approximation of most significant bits
local function Approx(NumberA)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = Unpack(NumberA)
	return A00
		+ A01 * 2 ^ 24
		+ A02 * 2 ^ 48
		+ A03 * 2 ^ 72
		+ A04 * 2 ^ 96
		+ A05 * 2 ^ 120
		+ A06 * 2 ^ 144
		+ A07 * 2 ^ 168
		+ A08 * 2 ^ 192
		+ A09 * 2 ^ 216
		+ A10 * 2 ^ 240
end

-- compare two numbers for ordering
local function Cmp(NumberA, NumberB)
	return Approx(Sub(NumberA, NumberB))
end

-- convert a regular number to multi-precision format
local function Num(RegularNumber)
	return {RegularNumber, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
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
