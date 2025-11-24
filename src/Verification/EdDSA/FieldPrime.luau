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

	C00 = A00 + 3 * 2 ^ 73  - 3 * 2 ^ 73
	A01 += C00
	C01 = A01 + 3 * 2 ^ 94  - 3 * 2 ^ 94
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
	if  C11 / 2 ^ 234 == 2 ^ 21 - 1
		and C10 / 2 ^ 213 == 2 ^ 21 - 1
		and C09 / 2 ^ 192 == 2 ^ 21 - 1
		and C08 / 2 ^ 170 == 2 ^ 22 - 1
		and C07 / 2 ^ 149 == 2 ^ 21 - 1
		and C06 / 2 ^ 128 == 2 ^ 21 - 1
		and C05 / 2 ^ 107 == 2 ^ 21 - 1
		and C04 / 2 ^ 85  == 2 ^ 22 - 1
		and C03 / 2 ^ 64  == 2 ^ 21 - 1
		and C02 / 2 ^ 43  == 2 ^ 21 - 1
		and C01 / 2 ^ 22  == 2 ^ 21 - 1
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

local function Eq(ElementA: buffer, ElementB: buffer): boolean
	local Difference = FieldPrime.Canonicalize(FieldPrime.Sub(ElementA, ElementB))
	local DifferenceAccumulator = 0
	for LimbIndex = 0, 88, 8 do
		local LimbLow = buffer.readu32(Difference, LimbIndex)
		local LimbHigh = buffer.readu32(Difference, LimbIndex + 4)
		DifferenceAccumulator = bit32.bor(DifferenceAccumulator, LimbLow, LimbHigh)
	end
	
	return DifferenceAccumulator == 0
end

local CompoundV = (19 / 2 ^ 255)

local a00: number, a01: number, a02: number, a03: number, a04: number, a05: number, a06: number,
	a07: number, a08: number, a09: number, a10: number, a11: number
local b00: number, b01: number, b02: number, b03: number, b04: number, b05: number, b06: number,
	b07: number, b08: number, b09: number, b10: number, b11: number

function FieldPrime.Mul(ElementA: buffer, ElementB: buffer, Storage: buffer?): buffer
	local COMPOUND_V = CompoundV
	a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11 =
		buffer.readf64(ElementB, 0), buffer.readf64(ElementB, 8),
		buffer.readf64(ElementB, 16), buffer.readf64(ElementB, 24),
		buffer.readf64(ElementB, 32), buffer.readf64(ElementB, 40),
		buffer.readf64(ElementB, 48), buffer.readf64(ElementB, 56),
		buffer.readf64(ElementB, 64), buffer.readf64(ElementB, 72),
		buffer.readf64(ElementB, 80), buffer.readf64(ElementB, 88)

	local A00: number, A01: number, A02: number, A03: number, A04: number, A05: number, A06: number,
			A07: number, A08: number, A09: number, A10: number, A11: number =
		a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11

	local B00: number, B01: number, B02: number, B03: number, B04: number, B05: number, B06: number,
			B07: number, B08: number, B09: number, B10: number, B11: number =
		b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11

	local C00 = A11 * B01
		+ A10 * B02
		+ A09 * B03
		+ A08 * B04
		+ A07 * B05
		+ A06 * B06
		+ A05 * B07
		+ A04 * B08
		+ A03 * B09
		+ A02 * B10
		+ A01 * B11

	local C01 = A11 * B02
		+ A10 * B03
		+ A09 * B04
		+ A08 * B05
		+ A07 * B06
		+ A06 * B07
		+ A05 * B08
		+ A04 * B09
		+ A03 * B10
		+ A02 * B11

	local C02 = A11 * B03
		+ A10 * B04
		+ A09 * B05
		+ A08 * B06
		+ A07 * B07
		+ A06 * B08
		+ A05 * B09
		+ A04 * B10
		+ A03 * B11

	local C03 = A11 * B04
		+ A10 * B05
		+ A09 * B06
		+ A08 * B07
		+ A07 * B08
		+ A06 * B09
		+ A05 * B10
		+ A04 * B11

	local C04 = A11 * B05
		+ A10 * B06
		+ A09 * B07
		+ A08 * B08
		+ A07 * B09
		+ A06 * B10
		+ A05 * B11

	local C05 = A11 * B06
		+ A10 * B07
		+ A09 * B08
		+ A08 * B09
		+ A07 * B10
		+ A06 * B11

	local C06 = A11 * B07
		+ A10 * B08
		+ A09 * B09
		+ A08 * B10
		+ A07 * B11

	local C07 = A11 * B08
		+ A10 * B09
		+ A09 * B10
		+ A08 * B11

	local C08 = A11 * B09
		+ A10 * B10
		+ A09 * B11

	local C09 = A11 * B10 + A10 * B11
	local C10 = A11 * B11

	C00 *= COMPOUND_V
	C00 += A00 * B00

	C01 *= COMPOUND_V
	C01 += A01 * B00
		+ A00 * B01

	C02 *= COMPOUND_V
	C02 += A02 * B00
		+ A01 * B01
		+ A00 * B02

	C03 *= COMPOUND_V
	C03 += A03 * B00
		+ A02 * B01
		+ A01 * B02
		+ A00 * B03

	C04 *= COMPOUND_V
	C04 += A04 * B00
		+ A03 * B01
		+ A02 * B02
		+ A01 * B03
		+ A00 * B04

	C05 *= COMPOUND_V
	C05 += A05 * B00
		+ A04 * B01
		+ A03 * B02
		+ A02 * B03
		+ A01 * B04
		+ A00 * B05

	C06 *= COMPOUND_V
	C06 += A06 * B00
		+ A05 * B01
		+ A04 * B02
		+ A03 * B03
		+ A02 * B04
		+ A01 * B05
		+ A00 * B06

	C07 *= COMPOUND_V
	C07 += A07 * B00
		+ A06 * B01
		+ A05 * B02
		+ A04 * B03
		+ A03 * B04
		+ A02 * B05
		+ A01 * B06
		+ A00 * B07

	C08 *= COMPOUND_V
	C08 += A08 * B00
		+ A07 * B01
		+ A06 * B02
		+ A05 * B03
		+ A04 * B04
		+ A03 * B05
		+ A02 * B06
		+ A01 * B07
		+ A00 * B08

	C09 *= COMPOUND_V
	C09 += A09 * B00
		+ A08 * B01
		+ A07 * B02
		+ A06 * B03
		+ A05 * B04
		+ A04 * B05
		+ A03 * B06
		+ A02 * B07
		+ A01 * B08
		+ A00 * B09

	C10 *= COMPOUND_V
	C10 += A10 * B00
		+ A09 * B01
		+ A08 * B02
		+ A07 * B03
		+ A06 * B04
		+ A05 * B05
		+ A04 * B06
		+ A03 * B07
		+ A02 * B08
		+ A01 * B09
		+ A00 * B10

	local C11 = A11 * B00
		+ A10 * B01
		+ A09 * B02
		+ A08 * B03
		+ A07 * B04
		+ A06 * B05
		+ A05 * B06
		+ A04 * B07
		+ A03 * B08
		+ A02 * B09
		+ A01 * B10
		+ A00 * B11

	A10 = C10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	C11 += A10
	A11 = C11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	C00 += COMPOUND_V * A11

	A00 = C00 + 3 * 2 ^ 73  - 3 * 2 ^ 73
	C01 += A00
	A01 = C01 + 3 * 2 ^ 94  - 3 * 2 ^ 94
	C02 += A01
	A02 = C02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	C03 += A02
	A03 = C03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	C04 += A03
	A04 = C04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	C05 += A04
	A05 = C05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	C06 += A05
	A06 = C06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	C07 += A06
	A07 = C07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	C08 += A07
	A08 = C08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	C09 += A08
	A09 = C09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	C10 = C10 - A10 + A09
	A10 = C10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	C11 = C11 - A11 + A10

	A11 = C11 + 3 * 2 ^ 306 - 3 * 2 ^ 306

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, C00 - A00 + COMPOUND_V * A11)
	buffer.writef64(Buf, 8, C01 - A01)
	buffer.writef64(Buf, 16, C02 - A02)
	buffer.writef64(Buf, 24, C03 - A03)
	buffer.writef64(Buf, 32, C04 - A04)
	buffer.writef64(Buf, 40, C05 - A05)
	buffer.writef64(Buf, 48, C06 - A06)
	buffer.writef64(Buf, 56, C07 - A07)
	buffer.writef64(Buf, 64, C08 - A08)
	buffer.writef64(Buf, 72, C09 - A09)
	buffer.writef64(Buf, 80, C10 - A10)
	buffer.writef64(Buf, 88, C11 - A11)

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

	local Result = Storage or  buffer.create(SIZE)
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

	C00 = A00 + 3 * 2 ^ 73  - 3 * 2 ^ 73
	A01 += C00
	C01 = A01 + 3 * 2 ^ 94  - 3 * 2 ^ 94
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

local function NSquare(ElementA: buffer, SquareCount: number, StoreInBuffer: boolean?): buffer
	if StoreInBuffer then
		for _ = 1, SquareCount do
			FieldPrime.Square(ElementA, ElementA)
		end

		return ElementA
	else
		for _ = 1, SquareCount do
			ElementA = FieldPrime.Square(ElementA)
		end

		return ElementA
	end
end

function FieldPrime.Invert(ElementA: buffer, Storage: buffer?): buffer
    local Mul = FieldPrime.Mul

	local A2 = FieldPrime.Square(ElementA)
	local A9 = Mul(ElementA, NSquare(A2, 2))
	local A11 = Mul(A9, A2)

	local X5 = Mul(FieldPrime.Square(A11), A9)
	local X10 = Mul(NSquare(X5, 5), X5)
	local X20 = Mul(NSquare(X10, 10), X10)
	local X40 = Mul(NSquare(X20, 20), X20)
	local X50 = Mul(NSquare(X40, 10), X10)
	local X100 = Mul(NSquare(X50, 50), X50)
	local X200 = Mul(NSquare(X100, 100), X100)
	local X250 = Mul(NSquare(X200, 50), X50)

	return Mul(NSquare(X250, 5), A11, Storage)
end

function FieldPrime.SqrtDiv(ElementU: buffer, ElementV: buffer): buffer?
    local Mul = FieldPrime.Mul
    local Square = FieldPrime.Square

	FieldPrime.Carry(ElementU, ElementU)

	local V2 = Square(ElementV)
	local V3 = Mul(ElementV, V2)
	local V6 = Square(V3)
	local V7 = Mul(ElementV, V6)
	local UV7 = Mul(ElementU, V7)

	local X2 = Mul(Square(UV7), UV7)
	local X4 = Mul(NSquare(X2, 2), X2)
	local X8 = Mul(NSquare(X4, 4), X4)
	local X16 = Mul(NSquare(X8, 8), X8)
	local X18 = Mul(NSquare(X16, 2), X2)
	local X32 = Mul(NSquare(X16, 16), X16)
	local X50 = Mul(NSquare(X32, 18), X18)
	local X100 = Mul(NSquare(X50, 50), X50)
	local X200 = Mul(NSquare(X100, 100), X100)
	local X250 = Mul(NSquare(X200, 50), X50)
	local PowerResult = Mul(NSquare(X250, 2), UV7)

	local UV3 = Mul(ElementU, V3)
	local CandidateB = Mul(UV3, PowerResult)
	local B2 = Square(CandidateB)
	local VB2 = Mul(ElementV, B2)

	if not Eq(VB2, ElementU) then
		CandidateB = Mul(CandidateB, SQUARES)
		B2 = Square(CandidateB)
		VB2 = Mul(ElementV, B2)
	end

	if Eq(VB2, ElementU) then
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

	local function PutBytes(ByteCount)
		for _ = 1, ByteCount do
			local SingleByte = Accumulator % 256
			buffer.writeu8(Buf, ByteIndex, SingleByte)
			ByteIndex += 1
			Accumulator = (Accumulator - SingleByte) / 256
		end
	end

	PutBytes(2)
	Accumulator += A01 / 2 ^ 16
	PutBytes(3)
	Accumulator += A02 / 2 ^ 40
	PutBytes(3)
	Accumulator += A03 / 2 ^ 64
	PutBytes(2)
	Accumulator += A04 / 2 ^ 80
	PutBytes(3)
	Accumulator += A05 / 2 ^ 104
	PutBytes(3)
	Accumulator += A06 / 2 ^ 128
	PutBytes(2)
	Accumulator += A07 / 2 ^ 144
	PutBytes(3)
	Accumulator += A08 / 2 ^ 168
	PutBytes(3)
	Accumulator += A09 / 2 ^ 192
	PutBytes(2)
	Accumulator += A10 / 2 ^ 208
	PutBytes(3)
	Accumulator += A11 / 2 ^ 232
	PutBytes(3)

	return Buf
end

function FieldPrime.Decode(EncodedBytes: buffer): buffer
	local function ReadLittleEndian(Offset: number, Bytes: number): number
		local Result = 0
		for Index = 0, Bytes - 1 do
			Result += buffer.readu8(EncodedBytes, Offset + Index) * (2 ^ (8 * Index))
		end

		return Result
	end

	local W00 = ReadLittleEndian(0, 3)
	local W01 = ReadLittleEndian(3, 3)
	local W02 = ReadLittleEndian(6, 2)
	local W03 = ReadLittleEndian(8, 3)
	local W04 = ReadLittleEndian(11, 3)
	local W05 = ReadLittleEndian(14, 2)
	local W06 = ReadLittleEndian(16, 3)
	local W07 = ReadLittleEndian(19, 3)
	local W08 = ReadLittleEndian(22, 2)
	local W09 = ReadLittleEndian(24, 3)
	local W10 = ReadLittleEndian(27, 3)
	local W11 = ReadLittleEndian(30, 2)

	W11 %= 2 ^ 15

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