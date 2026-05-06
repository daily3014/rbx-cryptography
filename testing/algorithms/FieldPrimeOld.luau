--[=[
	Cryptography library: Field Prime (Curve25519 Base Field)

	Return type: varies by function
	Example usage:
		local FieldPrime = require("FieldPrime")

		--------Usage Case 1: Basic arithmetic--------
		local ElementA = FieldPrime.Num(42)
		local ElementB = FieldPrime.Num(17)
		local Sum = FieldPrime.Add(ElementA, ElementB)
		local Product = FieldPrime.Mul(ElementA, ElementB)

		--------Usage Case 2: Encoding/decoding--------
		local Encoded = FieldPrime.Encode(ElementA)
		local Decoded = FieldPrime.Decode(Encoded)
--]=]

--!strict
--!optimize 2
--!native

local SIZE = 104
local COMPOUND_V = (19 / 2 ^ 255)
local SQUARES = buffer.create(SIZE) do
	local Tbl = {
		0958640 * 2 ^ 0,
		0826664 * 2 ^ 22,
		1613251 * 2 ^ 43,
		1041528 * 2 ^ 64,
		0013673 * 2 ^ 85,
		0387171 * 2 ^ 107,
		1824679 * 2 ^ 128,
		0313839 * 2 ^ 149,
		0709440 * 2 ^ 170,
		0122635 * 2 ^ 192,
		0262782 * 2 ^ 213,
		0712905 * 2 ^ 234,
	}

	for Index = 1, 12 do
		buffer.writef64(SQUARES, (Index - 1) * 8, Tbl[Index])
	end
end

local FieldPrime = {}

function FieldPrime.Num(Number: number): buffer
	local Buf = buffer.create(SIZE)
	buffer.writef64(Buf, 0, Number)

	return Buf
end

function FieldPrime.Neg(ElementA: buffer): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local Buf = buffer.create(SIZE)

	buffer.writef64(Buf, 0, -A00)
	buffer.writef64(Buf, 8, -A01)
	buffer.writef64(Buf, 16, -A02)
	buffer.writef64(Buf, 24, -A03)
	buffer.writef64(Buf, 32, -A04)
	buffer.writef64(Buf, 40, -A05)
	buffer.writef64(Buf, 48, -A06)
	buffer.writef64(Buf, 56, -A07)
	buffer.writef64(Buf, 64, -A08)
	buffer.writef64(Buf, 72, -A09)
	buffer.writef64(Buf, 80, -A10)
	buffer.writef64(Buf, 88, -A11)

	return Buf
end

function FieldPrime.Add(ElementA: buffer, ElementB: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11 =
		buffer.readf64(ElementB, 0), buffer.readf64(ElementB, 8),
		buffer.readf64(ElementB, 16), buffer.readf64(ElementB, 24),
		buffer.readf64(ElementB, 32), buffer.readf64(ElementB, 40),
		buffer.readf64(ElementB, 48), buffer.readf64(ElementB, 56),
		buffer.readf64(ElementB, 64), buffer.readf64(ElementB, 72),
		buffer.readf64(ElementB, 80), buffer.readf64(ElementB, 88)

	local Buf = Storage or buffer.create(SIZE)

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
	buffer.writef64(Buf, 88, A11 + B11)

	return Buf
end

function FieldPrime.Sub(ElementA: buffer, ElementB: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11 =
		buffer.readf64(ElementB, 0), buffer.readf64(ElementB, 8),
		buffer.readf64(ElementB, 16), buffer.readf64(ElementB, 24),
		buffer.readf64(ElementB, 32), buffer.readf64(ElementB, 40),
		buffer.readf64(ElementB, 48), buffer.readf64(ElementB, 56),
		buffer.readf64(ElementB, 64), buffer.readf64(ElementB, 72),
		buffer.readf64(ElementB, 80), buffer.readf64(ElementB, 88)

	local Buf = Storage or buffer.create(SIZE)

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
	buffer.writef64(Buf, 88, A11 - B11)

	return Buf
end

function FieldPrime.Carry(ElementA: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11

	C11 = A11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	A00 += 19 / 2 ^ 255 * C11

	C00 = A00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	A01 += C00
	C01 = A01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	A02 += C01
	C02 = A02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	A03 += C02
	C03 = A03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	A04 += C03
	C04 = A04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	A05 += C04
	C05 = A05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	A06 += C05
	C06 = A06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	A07 += C06
	C07 = A07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	A08 += C07
	C08 = A08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	A09 += C08
	C09 = A09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	A10 += C09
	C10 = A10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	A11 = A11 - C11 + C10

	C11 = A11 + 3 * 2 ^ 306 - 3 * 2 ^ 306

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 - C00 + 19 / 2 ^ 255 * C11)
	buffer.writef64(Buf, 8, A01 - C01)
	buffer.writef64(Buf, 16, A02 - C02)
	buffer.writef64(Buf, 24, A03 - C03)
	buffer.writef64(Buf, 32, A04 - C04)
	buffer.writef64(Buf, 40, A05 - C05)
	buffer.writef64(Buf, 48, A06 - C06)
	buffer.writef64(Buf, 56, A07 - C07)
	buffer.writef64(Buf, 64, A08 - C08)
	buffer.writef64(Buf, 72, A09 - C09)
	buffer.writef64(Buf, 80, A10 - C10)
	buffer.writef64(Buf, 88, A11 - C11)

	return Buf
end

function FieldPrime.Canonicalize(ElementA: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11

	C00 = A00 % 2 ^ 22
	A01 += A00 - C00
	C01 = A01 % 2 ^ 43
	A02 += A01 - C01
	C02 = A02 % 2 ^ 64
	A03 += A02 - C02
	C03 = A03 % 2 ^ 85
	A04 += A03 - C03
	C04 = A04 % 2 ^ 107
	A05 += A04 - C04
	C05 = A05 % 2 ^ 128
	A06 += A05 - C05
	C06 = A06 % 2 ^ 149
	A07 += A06 - C06
	C07 = A07 % 2 ^ 170
	A08 += A07 - C07
	C08 = A08 % 2 ^ 192
	A09 += A08 - C08
	C09 = A09 % 2 ^ 213
	A10 += A09 - C09
	C10 = A10 % 2 ^ 234
	A11 += A10 - C10
	C11 = A11 % 2 ^ 255
	C00 += 19 / 2 ^ 255 * (A11 - C11)

	local Buf = Storage or buffer.create(SIZE)
	if C11 / 2 ^ 234 == 2 ^ 21 - 1
		and C10 / 2 ^ 213 == 2 ^ 21 - 1
		and C09 / 2 ^ 192 == 2 ^ 21 - 1
		and C08 / 2 ^ 170 == 2 ^ 22 - 1
		and C07 / 2 ^ 149 == 2 ^ 21 - 1
		and C06 / 2 ^ 128 == 2 ^ 21 - 1
		and C05 / 2 ^ 107 == 2 ^ 21 - 1
		and C04 / 2 ^ 85 == 2 ^ 22 - 1
		and C03 / 2 ^ 64 == 2 ^ 21 - 1
		and C02 / 2 ^ 43 == 2 ^ 21 - 1
		and C01 / 2 ^ 22 == 2 ^ 21 - 1
		and C00 >= 2 ^ 22 - 19
	then
		buffer.writef64(Buf, 0, 19 - 2 ^ 22 + C00)
		for Index = 8, 88, 8 do
			buffer.writef64(Buf, Index, 0)
		end
	else
		buffer.writef64(Buf, 0, C00)
		buffer.writef64(Buf, 8, C01)
		buffer.writef64(Buf, 16, C02)
		buffer.writef64(Buf, 24, C03)
		buffer.writef64(Buf, 32, C04)
		buffer.writef64(Buf, 40, C05)
		buffer.writef64(Buf, 48, C06)
		buffer.writef64(Buf, 56, C07)
		buffer.writef64(Buf, 64, C08)
		buffer.writef64(Buf, 72, C09)
		buffer.writef64(Buf, 80, C10)
		buffer.writef64(Buf, 88, C11)
	end

	return Buf
end

function FieldPrime.Eq(ElementA: buffer, ElementB: buffer): boolean
	local Difference = FieldPrime.Canonicalize(FieldPrime.Sub(ElementA, ElementB))
	local DifferenceAccumulator = 0
	for LimbIndex = 0, 88, 8 do
		local LimbLow = buffer.readu32(Difference, LimbIndex)
		local LimbHigh = buffer.readu32(Difference, LimbIndex + 4)
		DifferenceAccumulator = bit32.bor(DifferenceAccumulator, LimbLow, LimbHigh)
	end

	return DifferenceAccumulator == 0
end

local A00: number, A01: number, A02: number, A03: number, A04: number, A05: number, A06: number,
A07: number, A08: number, A09: number, A10: number, A11: number
local B00: number, B01: number, B02: number, B03: number, B04: number, B05: number, B06: number,
B07: number, B08: number, B09: number, B10: number, B11: number

function FieldPrime.Mul(ElementA: buffer, ElementB: buffer, Storage: buffer?): buffer
	local CompoundV = COMPOUND_V
	A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11 =
		buffer.readf64(ElementB, 0), buffer.readf64(ElementB, 8),
		buffer.readf64(ElementB, 16), buffer.readf64(ElementB, 24),
		buffer.readf64(ElementB, 32), buffer.readf64(ElementB, 40),
		buffer.readf64(ElementB, 48), buffer.readf64(ElementB, 56),
		buffer.readf64(ElementB, 64), buffer.readf64(ElementB, 72),
		buffer.readf64(ElementB, 80), buffer.readf64(ElementB, 88)

	local T00: number, T01: number, T02: number, T03: number, T04: number, T05: number, T06: number,
	T07: number, T08: number, T09: number, T10: number, T11: number =
		A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11

	local U00: number, U01: number, U02: number, U03: number, U04: number, U05: number, U06: number,
	U07: number, U08: number, U09: number, U10: number, U11: number =
		B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11

	local C00 = T11 * U01
		+ T10 * U02
		+ T09 * U03
		+ T08 * U04
		+ T07 * U05
		+ T06 * U06
		+ T05 * U07
		+ T04 * U08
		+ T03 * U09
		+ T02 * U10
		+ T01 * U11

	local C01 = T11 * U02
		+ T10 * U03
		+ T09 * U04
		+ T08 * U05
		+ T07 * U06
		+ T06 * U07
		+ T05 * U08
		+ T04 * U09
		+ T03 * U10
		+ T02 * U11

	local C02 = T11 * U03
		+ T10 * U04
		+ T09 * U05
		+ T08 * U06
		+ T07 * U07
		+ T06 * U08
		+ T05 * U09
		+ T04 * U10
		+ T03 * U11

	local C03 = T11 * U04
		+ T10 * U05
		+ T09 * U06
		+ T08 * U07
		+ T07 * U08
		+ T06 * U09
		+ T05 * U10
		+ T04 * U11

	local C04 = T11 * U05
		+ T10 * U06
		+ T09 * U07
		+ T08 * U08
		+ T07 * U09
		+ T06 * U10
		+ T05 * U11

	local C05 = T11 * U06
		+ T10 * U07
		+ T09 * U08
		+ T08 * U09
		+ T07 * U10
		+ T06 * U11

	local C06 = T11 * U07
		+ T10 * U08
		+ T09 * U09
		+ T08 * U10
		+ T07 * U11

	local C07 = T11 * U08
		+ T10 * U09
		+ T09 * U10
		+ T08 * U11

	local C08 = T11 * U09
		+ T10 * U10
		+ T09 * U11

	local C09 = T11 * U10 + T10 * U11
	local C10 = T11 * U11

	C00 *= CompoundV
	C00 += T00 * U00

	C01 *= CompoundV
	C01 += T01 * U00
		+ T00 * U01

	C02 *= CompoundV
	C02 += T02 * U00
		+ T01 * U01
		+ T00 * U02

	C03 *= CompoundV
	C03 += T03 * U00
		+ T02 * U01
		+ T01 * U02
		+ T00 * U03

	C04 *= CompoundV
	C04 += T04 * U00
		+ T03 * U01
		+ T02 * U02
		+ T01 * U03
		+ T00 * U04

	C05 *= CompoundV
	C05 += T05 * U00
		+ T04 * U01
		+ T03 * U02
		+ T02 * U03
		+ T01 * U04
		+ T00 * U05

	C06 *= CompoundV
	C06 += T06 * U00
		+ T05 * U01
		+ T04 * U02
		+ T03 * U03
		+ T02 * U04
		+ T01 * U05
		+ T00 * U06

	C07 *= CompoundV
	C07 += T07 * U00
		+ T06 * U01
		+ T05 * U02
		+ T04 * U03
		+ T03 * U04
		+ T02 * U05
		+ T01 * U06
		+ T00 * U07

	C08 *= CompoundV
	C08 += T08 * U00
		+ T07 * U01
		+ T06 * U02
		+ T05 * U03
		+ T04 * U04
		+ T03 * U05
		+ T02 * U06
		+ T01 * U07
		+ T00 * U08

	C09 *= CompoundV
	C09 += T09 * U00
		+ T08 * U01
		+ T07 * U02
		+ T06 * U03
		+ T05 * U04
		+ T04 * U05
		+ T03 * U06
		+ T02 * U07
		+ T01 * U08
		+ T00 * U09

	C10 *= CompoundV
	C10 += T10 * U00
		+ T09 * U01
		+ T08 * U02
		+ T07 * U03
		+ T06 * U04
		+ T05 * U05
		+ T04 * U06
		+ T03 * U07
		+ T02 * U08
		+ T01 * U09
		+ T00 * U10

	local C11 = T11 * U00
		+ T10 * U01
		+ T09 * U02
		+ T08 * U03
		+ T07 * U04
		+ T06 * U05
		+ T05 * U06
		+ T04 * U07
		+ T03 * U08
		+ T02 * U09
		+ T01 * U10
		+ T00 * U11

	T10 = C10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	C11 += T10
	T11 = C11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	C00 += CompoundV * T11

	T00 = C00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	C01 += T00
	T01 = C01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	C02 += T01
	T02 = C02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	C03 += T02
	T03 = C03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	C04 += T03
	T04 = C04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	C05 += T04
	T05 = C05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	C06 += T05
	T06 = C06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	C07 += T06
	T07 = C07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	C08 += T07
	T08 = C08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	C09 += T08
	T09 = C09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	C10 = C10 - T10 + T09
	T10 = C10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	C11 = C11 - T11 + T10

	T11 = C11 + 3 * 2 ^ 306 - 3 * 2 ^ 306

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, C00 - T00 + CompoundV * T11)
	buffer.writef64(Buf, 8, C01 - T01)
	buffer.writef64(Buf, 16, C02 - T02)
	buffer.writef64(Buf, 24, C03 - T03)
	buffer.writef64(Buf, 32, C04 - T04)
	buffer.writef64(Buf, 40, C05 - T05)
	buffer.writef64(Buf, 48, C06 - T06)
	buffer.writef64(Buf, 56, C07 - T07)
	buffer.writef64(Buf, 64, C08 - T08)
	buffer.writef64(Buf, 72, C09 - T09)
	buffer.writef64(Buf, 80, C10 - T10)
	buffer.writef64(Buf, 88, C11 - T11)

	return Buf
end

function FieldPrime.Square(ElementA: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local D00 = A00 * 2
	local D01 = A01 * 2
	local D02 = A02 * 2
	local D03 = A03 * 2
	local D04 = A04 * 2
	local D05 = A05 * 2
	local D06 = A06 * 2
	local D07 = A07 * 2
	local D08 = A08 * 2
	local D09 = A09 * 2
	local D10 = A10 * 2

	local ReductionFactor = 19 / 2 ^ 255

	local H00 = A11 * D01 + A10 * D02 + A09 * D03 + A08 * D04 + A07 * D05 + A06 * A06
	local H01 = A11 * D02 + A10 * D03 + A09 * D04 + A08 * D05 + A07 * D06
	local H02 = A11 * D03 + A10 * D04 + A09 * D05 + A08 * D06 + A07 * A07
	local H03 = A11 * D04 + A10 * D05 + A09 * D06 + A08 * D07
	local H04 = A11 * D05 + A10 * D06 + A09 * D07 + A08 * A08
	local H05 = A11 * D06 + A10 * D07 + A09 * D08
	local H06 = A11 * D07 + A10 * D08 + A09 * A09
	local H07 = A11 * D08 + A10 * D09
	local H08 = A11 * D09 + A10 * A10
	local H09 = A11 * D10
	local H10 = A11 * A11

	local L00 = A00 * A00
	local L01 = A01 * D00
	local L02 = A02 * D00 + A01 * A01
	local L03 = A03 * D00 + A02 * D01
	local L04 = A04 * D00 + A03 * D01 + A02 * A02
	local L05 = A05 * D00 + A04 * D01 + A03 * D02
	local L06 = A06 * D00 + A05 * D01 + A04 * D02 + A03 * A03
	local L07 = A07 * D00 + A06 * D01 + A05 * D02 + A04 * D03
	local L08 = A08 * D00 + A07 * D01 + A06 * D02 + A05 * D03 + A04 * A04
	local L09 = A09 * D00 + A08 * D01 + A07 * D02 + A06 * D03 + A05 * D04
	local L10 = A10 * D00 + A09 * D01 + A08 * D02 + A07 * D03 + A06 * D04 + A05 * A05
	local L11 = A11 * D00 + A10 * D01 + A09 * D02 + A08 * D03 + A07 * D04 + A06 * D05

	local Result = Storage or buffer.create(SIZE)
	buffer.writef64(Result, 0, H00 * ReductionFactor + L00)
	buffer.writef64(Result, 8, H01 * ReductionFactor + L01)
	buffer.writef64(Result, 16, H02 * ReductionFactor + L02)
	buffer.writef64(Result, 24, H03 * ReductionFactor + L03)
	buffer.writef64(Result, 32, H04 * ReductionFactor + L04)
	buffer.writef64(Result, 40, H05 * ReductionFactor + L05)
	buffer.writef64(Result, 48, H06 * ReductionFactor + L06)
	buffer.writef64(Result, 56, H07 * ReductionFactor + L07)
	buffer.writef64(Result, 64, H08 * ReductionFactor + L08)
	buffer.writef64(Result, 72, H09 * ReductionFactor + L09)
	buffer.writef64(Result, 80, H10 * ReductionFactor + L10)
	buffer.writef64(Result, 88, L11)

	return FieldPrime.Carry(Result, Result)
end

function FieldPrime.KMul(ElementA: buffer, SmallK: number, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11

	A00 *= SmallK
	A01 *= SmallK
	A02 *= SmallK
	A03 *= SmallK
	A04 *= SmallK
	A05 *= SmallK
	A06 *= SmallK
	A07 *= SmallK
	A08 *= SmallK
	A09 *= SmallK
	A10 *= SmallK
	A11 *= SmallK

	C11 = A11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	A00 += 19 / 2 ^ 255 * C11

	C00 = A00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	A01 += C00
	C01 = A01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	A02 += C01
	C02 = A02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	A03 += C02
	C03 = A03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	A04 += C03
	C04 = A04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	A05 += C04
	C05 = A05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	A06 += C05
	C06 = A06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	A07 += C06
	C07 = A07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	A08 += C07
	C08 = A08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	A09 += C08
	C09 = A09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	A10 += C09
	C10 = A10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	A11 = A11 - C11 + C10

	C11 = A11 + 3 * 2 ^ 306 - 3 * 2 ^ 306

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 - C00 + 19 / 2 ^ 255 * C11)
	buffer.writef64(Buf, 8, A01 - C01)
	buffer.writef64(Buf, 16, A02 - C02)
	buffer.writef64(Buf, 24, A03 - C03)
	buffer.writef64(Buf, 32, A04 - C04)
	buffer.writef64(Buf, 40, A05 - C05)
	buffer.writef64(Buf, 48, A06 - C06)
	buffer.writef64(Buf, 56, A07 - C07)
	buffer.writef64(Buf, 64, A08 - C08)
	buffer.writef64(Buf, 72, A09 - C09)
	buffer.writef64(Buf, 80, A10 - C10)
	buffer.writef64(Buf, 88, A11 - C11)

	return Buf
end

function FieldPrime.NSquare(ElementA: buffer, SquareCount: number, StoreInBuffer: boolean?): buffer
	local Square = FieldPrime.Square
	if StoreInBuffer then
		for _ = 1, SquareCount do
			Square(ElementA, ElementA)
		end

		return ElementA
	else
		for _ = 1, SquareCount do
			ElementA = Square(ElementA)
		end

		return ElementA
	end
end

function FieldPrime.Invert(ElementA: buffer, Storage: buffer?): buffer
	local Mul = FieldPrime.Mul

	local A2 = FieldPrime.Square(ElementA)
	local A9 = Mul(ElementA, FieldPrime.NSquare(A2, 2))
	local A11 = Mul(A9, A2)

	local X5 = Mul(FieldPrime.Square(A11), A9)
	local X10 = Mul(FieldPrime.NSquare(X5, 5), X5)
	local X20 = Mul(FieldPrime.NSquare(X10, 10), X10)
	local X40 = Mul(FieldPrime.NSquare(X20, 20), X20)
	local X50 = Mul(FieldPrime.NSquare(X40, 10), X10)
	local X100 = Mul(FieldPrime.NSquare(X50, 50), X50)
	local X200 = Mul(FieldPrime.NSquare(X100, 100), X100)
	local X250 = Mul(FieldPrime.NSquare(X200, 50), X50)

	return Mul(FieldPrime.NSquare(X250, 5), A11, Storage)
end

function FieldPrime.SqrtDiv(ElementU: buffer, ElementV: buffer): buffer?
	local Mul = FieldPrime.Mul
	local Square = FieldPrime.Square
	local Carry = FieldPrime.Carry

	Carry(ElementU, ElementU)

	local V2 = Square(ElementV)
	local V3 = Mul(ElementV, V2)
	local UV3 = Mul(ElementU, V3)
	local V4 = Square(V2)
	local UV7 = Mul(UV3, V4)

	local X2 = Mul(Square(UV7), UV7)
	local X4 = Mul(FieldPrime.NSquare(X2, 2), X2)
	local X8 = Mul(FieldPrime.NSquare(X4, 4), X4)
	local X16 = Mul(FieldPrime.NSquare(X8, 8), X8)
	local X18 = Mul(FieldPrime.NSquare(X16, 2), X2)
	local X32 = Mul(FieldPrime.NSquare(X16, 16), X16)
	local X50 = Mul(FieldPrime.NSquare(X32, 18), X18)
	local X100 = Mul(FieldPrime.NSquare(X50, 50), X50)
	local X200 = Mul(FieldPrime.NSquare(X100, 100), X100)
	local X250 = Mul(FieldPrime.NSquare(X200, 50), X50)
	local PowerResult = Mul(FieldPrime.NSquare(X250, 2), UV7)

	local CandidateB = Mul(UV3, PowerResult)
	local B2 = Square(CandidateB)
	local VB2 = Mul(ElementV, B2)

	if not FieldPrime.Eq(VB2, ElementU) then
		CandidateB = Mul(CandidateB, SQUARES)
		B2 = Square(CandidateB)
		VB2 = Mul(ElementV, B2)
	end

	if FieldPrime.Eq(VB2, ElementU) then
		return CandidateB
	else
		return nil
	end
end

function FieldPrime.Encode(ElementA: buffer): buffer
	ElementA = FieldPrime.Canonicalize(ElementA)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local Buf = buffer.create(32)
	local ByteIndex = 0
	local Accumulator = A00

	local Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	local Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Accumulator += A01 / 2 ^ 16

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	local Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)
	Accumulator = (Accumulator - Byte2) / 256
	ByteIndex += 1

	Accumulator += A02 / 2 ^ 40

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)
	Accumulator = (Accumulator - Byte2) / 256
	ByteIndex += 1

	Accumulator += A03 / 2 ^ 64

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Accumulator += A04 / 2 ^ 80

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)
	Accumulator = (Accumulator - Byte2) / 256
	ByteIndex += 1

	Accumulator += A05 / 2 ^ 104

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)
	Accumulator = (Accumulator - Byte2) / 256
	ByteIndex += 1

	Accumulator += A06 / 2 ^ 128

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Accumulator += A07 / 2 ^ 144

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)
	Accumulator = (Accumulator - Byte2) / 256
	ByteIndex += 1

	Accumulator += A08 / 2 ^ 168

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)
	Accumulator = (Accumulator - Byte2) / 256
	ByteIndex += 1

	Accumulator += A09 / 2 ^ 192

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Accumulator += A10 / 2 ^ 208

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)
	Accumulator = (Accumulator - Byte2) / 256
	ByteIndex += 1

	Accumulator += A11 / 2 ^ 232

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)

	return Buf
end

function FieldPrime.Decode(EncodedBytes: buffer): buffer
	local B0, B1, B2 = buffer.readu8(EncodedBytes, 0), buffer.readu8(EncodedBytes, 1), buffer.readu8(EncodedBytes, 2)
	local W00 = B0 + B1 * 256 + B2 * 65536

	B0, B1, B2 = buffer.readu8(EncodedBytes, 3), buffer.readu8(EncodedBytes, 4), buffer.readu8(EncodedBytes, 5)
	local W01 = B0 + B1 * 256 + B2 * 65536

	local W02 = buffer.readu16(EncodedBytes, 6)

	B0, B1, B2 = buffer.readu8(EncodedBytes, 8), buffer.readu8(EncodedBytes, 9), buffer.readu8(EncodedBytes, 10)
	local W03 = B0 + B1 * 256 + B2 * 65536

	B0, B1, B2 = buffer.readu8(EncodedBytes, 11), buffer.readu8(EncodedBytes, 12), buffer.readu8(EncodedBytes, 13)
	local W04 = B0 + B1 * 256 + B2 * 65536

	local W05 = buffer.readu16(EncodedBytes, 14)

	B0, B1, B2 = buffer.readu8(EncodedBytes, 16), buffer.readu8(EncodedBytes, 17), buffer.readu8(EncodedBytes, 18)
	local W06 = B0 + B1 * 256 + B2 * 65536

	B0, B1, B2 = buffer.readu8(EncodedBytes, 19), buffer.readu8(EncodedBytes, 20), buffer.readu8(EncodedBytes, 21)
	local W07 = B0 + B1 * 256 + B2 * 65536

	local W08 = buffer.readu16(EncodedBytes, 22)

	B0, B1, B2 = buffer.readu8(EncodedBytes, 24), buffer.readu8(EncodedBytes, 25), buffer.readu8(EncodedBytes, 26)
	local W09 = B0 + B1 * 256 + B2 * 65536

	B0, B1, B2 = buffer.readu8(EncodedBytes, 27), buffer.readu8(EncodedBytes, 28), buffer.readu8(EncodedBytes, 29)
	local W10 = B0 + B1 * 256 + B2 * 65536

	local W11 = buffer.readu16(EncodedBytes, 30) % 32768

	local Buf = buffer.create(SIZE)

	buffer.writef64(Buf, 0, W00)
	buffer.writef64(Buf, 8, W01 * 2 ^ 24)
	buffer.writef64(Buf, 16, W02 * 2 ^ 48)
	buffer.writef64(Buf, 24, W03 * 2 ^ 64)
	buffer.writef64(Buf, 32, W04 * 2 ^ 88)
	buffer.writef64(Buf, 40, W05 * 2 ^ 112)
	buffer.writef64(Buf, 48, W06 * 2 ^ 128)
	buffer.writef64(Buf, 56, W07 * 2 ^ 152)
	buffer.writef64(Buf, 64, W08 * 2 ^ 176)
	buffer.writef64(Buf, 72, W09 * 2 ^ 192)
	buffer.writef64(Buf, 80, W10 * 2 ^ 216)
	buffer.writef64(Buf, 88, W11 * 2 ^ 240)

	return FieldPrime.Carry(Buf, Buf)
end

function FieldPrime.Eqz(ElementA: buffer): boolean
	local Canonical = FieldPrime.Canonicalize(ElementA)
	local C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11 =
		buffer.readf64(Canonical, 0), buffer.readf64(Canonical, 8),
		buffer.readf64(Canonical, 16), buffer.readf64(Canonical, 24),
		buffer.readf64(Canonical, 32), buffer.readf64(Canonical, 40),
		buffer.readf64(Canonical, 48), buffer.readf64(Canonical, 56),
		buffer.readf64(Canonical, 64), buffer.readf64(Canonical, 72),
		buffer.readf64(Canonical, 80), buffer.readf64(Canonical, 88)

	return C00 + C01 + C02 + C03 + C04 + C05 + C06 + C07 + C08 + C09 + C10 + C11 == 0
end

return FieldPrime