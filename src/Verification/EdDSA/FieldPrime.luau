--[=[
	Cryptography library: Field Prime (Curve25519 Base Field)

	Return type: varies by function
	Example usage:
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
	local A00 = buffer.readf64(ElementA, 0)
	local A01 = buffer.readf64(ElementA, 8)
	local A02 = buffer.readf64(ElementA, 16)
	local A03 = buffer.readf64(ElementA, 24)
	local A04 = buffer.readf64(ElementA, 32)
	local A05 = buffer.readf64(ElementA, 40)
	local A06 = buffer.readf64(ElementA, 48)
	local A07 = buffer.readf64(ElementA, 56)
	local A08 = buffer.readf64(ElementA, 64)
	local A09 = buffer.readf64(ElementA, 72)
	local A10 = buffer.readf64(ElementA, 80)
	local A11 = buffer.readf64(ElementA, 88)
	local Buf = Storage or buffer.create(SIZE)
	local K00 = A00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	local K01 = A01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	local K02 = A02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	local K03 = A03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	local K04 = A04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	local K05 = A05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	local K06 = A06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	local K07 = A07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	local K08 = A08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	local K09 = A09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	local K10 = A10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	local K11 = A11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	local R00 = (A00 - K00) + K11 * (19 / 2 ^ 255)
	local R01 = (A01 - K01) + K00
	local R02 = (A02 - K02) + K01
	local R03 = (A03 - K03) + K02
	local R04 = (A04 - K04) + K03
	local R05 = (A05 - K05) + K04
	local R06 = (A06 - K06) + K05
	local R07 = (A07 - K07) + K06
	local R08 = (A08 - K08) + K07
	local R09 = (A09 - K09) + K08
	local R10 = (A10 - K10) + K09
	local R11 = (A11 - K11) + K10
	local J00 = R00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	local J01 = R01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	local J02 = R02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	local J03 = R03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	local J04 = R04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	local J05 = R05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	local J06 = R06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	local J07 = R07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	local J08 = R08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	local J09 = R09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	local J10 = R10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	local J11 = R11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	buffer.writef64(Buf, 0, (R00 - J00) + J11 * (19 / 2 ^ 255))
	buffer.writef64(Buf, 8, (R01 - J01) + J00)
	buffer.writef64(Buf, 16, (R02 - J02) + J01)
	buffer.writef64(Buf, 24, (R03 - J03) + J02)
	buffer.writef64(Buf, 32, (R04 - J04) + J03)
	buffer.writef64(Buf, 40, (R05 - J05) + J04)
	buffer.writef64(Buf, 48, (R06 - J06) + J05)
	buffer.writef64(Buf, 56, (R07 - J07) + J06)
	buffer.writef64(Buf, 64, (R08 - J08) + J07)
	buffer.writef64(Buf, 72, (R09 - J09) + J08)
	buffer.writef64(Buf, 80, (R10 - J10) + J09)
	buffer.writef64(Buf, 88, (R11 - J11) + J10)
	return Buf
end

function FieldPrime.Mul(ElementA: buffer, ElementB: buffer, Storage: buffer?): buffer
	local A00 = buffer.readf64(ElementA, 0)
	local A01 = buffer.readf64(ElementA, 8)
	local A02 = buffer.readf64(ElementA, 16)
	local A03 = buffer.readf64(ElementA, 24)
	local A04 = buffer.readf64(ElementA, 32)
	local A05 = buffer.readf64(ElementA, 40)
	local A06 = buffer.readf64(ElementA, 48)
	local A07 = buffer.readf64(ElementA, 56)
	local A08 = buffer.readf64(ElementA, 64)
	local A09 = buffer.readf64(ElementA, 72)
	local A10 = buffer.readf64(ElementA, 80)
	local A11 = buffer.readf64(ElementA, 88)
	local B00 = buffer.readf64(ElementB, 0)
	local B01 = buffer.readf64(ElementB, 8)
	local B02 = buffer.readf64(ElementB, 16)
	local B03 = buffer.readf64(ElementB, 24)
	local B04 = buffer.readf64(ElementB, 32)
	local B05 = buffer.readf64(ElementB, 40)
	local B06 = buffer.readf64(ElementB, 48)
	local B07 = buffer.readf64(ElementB, 56)
	local B08 = buffer.readf64(ElementB, 64)
	local B09 = buffer.readf64(ElementB, 72)
	local B10 = buffer.readf64(ElementB, 80)
	local B11 = buffer.readf64(ElementB, 88)
	local C00 = (A01 * B11 + A02 * B10 + A03 * B09 + A04 * B08 + A05 * B07 + A06 * B06 + A07 * B05 + A08 * B04 + A09 * B03 + A10 * B02 + A11 * B01) * (19 / 2 ^ 255) + (A00 * B00)
	local C01 = (A02 * B11 + A03 * B10 + A04 * B09 + A05 * B08 + A06 * B07 + A07 * B06 + A08 * B05 + A09 * B04 + A10 * B03 + A11 * B02) * (19 / 2 ^ 255) + (A00 * B01 + A01 * B00)
	local C02 = (A03 * B11 + A04 * B10 + A05 * B09 + A06 * B08 + A07 * B07 + A08 * B06 + A09 * B05 + A10 * B04 + A11 * B03) * (19 / 2 ^ 255) + (A00 * B02 + A01 * B01 + A02 * B00)
	local C03 = (A04 * B11 + A05 * B10 + A06 * B09 + A07 * B08 + A08 * B07 + A09 * B06 + A10 * B05 + A11 * B04) * (19 / 2 ^ 255) + (A00 * B03 + A01 * B02 + A02 * B01 + A03 * B00)
	local C04 = (A05 * B11 + A06 * B10 + A07 * B09 + A08 * B08 + A09 * B07 + A10 * B06 + A11 * B05) * (19 / 2 ^ 255) + (A00 * B04 + A01 * B03 + A02 * B02 + A03 * B01 + A04 * B00)
	local C05 = (A06 * B11 + A07 * B10 + A08 * B09 + A09 * B08 + A10 * B07 + A11 * B06) * (19 / 2 ^ 255) + (A00 * B05 + A01 * B04 + A02 * B03 + A03 * B02 + A04 * B01 + A05 * B00)
	local C06 = (A07 * B11 + A08 * B10 + A09 * B09 + A10 * B08 + A11 * B07) * (19 / 2 ^ 255) + (A00 * B06 + A01 * B05 + A02 * B04 + A03 * B03 + A04 * B02 + A05 * B01 + A06 * B00)
	local C07 = (A08 * B11 + A09 * B10 + A10 * B09 + A11 * B08) * (19 / 2 ^ 255) + (A00 * B07 + A01 * B06 + A02 * B05 + A03 * B04 + A04 * B03 + A05 * B02 + A06 * B01 + A07 * B00)
	local C08 = (A09 * B11 + A10 * B10 + A11 * B09) * (19 / 2 ^ 255) + (A00 * B08 + A01 * B07 + A02 * B06 + A03 * B05 + A04 * B04 + A05 * B03 + A06 * B02 + A07 * B01 + A08 * B00)
	local C09 = (A10 * B11 + A11 * B10) * (19 / 2 ^ 255) + (A00 * B09 + A01 * B08 + A02 * B07 + A03 * B06 + A04 * B05 + A05 * B04 + A06 * B03 + A07 * B02 + A08 * B01 + A09 * B00)
	local C10 = (A11 * B11) * (19 / 2 ^ 255) + (A00 * B10 + A01 * B09 + A02 * B08 + A03 * B07 + A04 * B06 + A05 * B05 + A06 * B04 + A07 * B03 + A08 * B02 + A09 * B01 + A10 * B00)
	local C11 = A00 * B11 + A01 * B10 + A02 * B09 + A03 * B08 + A04 * B07 + A05 * B06 + A06 * B05 + A07 * B04 + A08 * B03 + A09 * B02 + A10 * B01 + A11 * B00
	local Buf = Storage or buffer.create(SIZE)
	local K00 = C00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	local K01 = C01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	local K02 = C02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	local K03 = C03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	local K04 = C04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	local K05 = C05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	local K06 = C06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	local K07 = C07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	local K08 = C08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	local K09 = C09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	local K10 = C10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	local K11 = C11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	local R00 = (C00 - K00) + K11 * (19 / 2 ^ 255)
	local R01 = (C01 - K01) + K00
	local R02 = (C02 - K02) + K01
	local R03 = (C03 - K03) + K02
	local R04 = (C04 - K04) + K03
	local R05 = (C05 - K05) + K04
	local R06 = (C06 - K06) + K05
	local R07 = (C07 - K07) + K06
	local R08 = (C08 - K08) + K07
	local R09 = (C09 - K09) + K08
	local R10 = (C10 - K10) + K09
	local R11 = (C11 - K11) + K10
	local J00 = R00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	local J01 = R01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	local J02 = R02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	local J03 = R03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	local J04 = R04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	local J05 = R05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	local J06 = R06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	local J07 = R07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	local J08 = R08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	local J09 = R09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	local J10 = R10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	local J11 = R11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	buffer.writef64(Buf, 0, (R00 - J00) + J11 * (19 / 2 ^ 255))
	buffer.writef64(Buf, 8, (R01 - J01) + J00)
	buffer.writef64(Buf, 16, (R02 - J02) + J01)
	buffer.writef64(Buf, 24, (R03 - J03) + J02)
	buffer.writef64(Buf, 32, (R04 - J04) + J03)
	buffer.writef64(Buf, 40, (R05 - J05) + J04)
	buffer.writef64(Buf, 48, (R06 - J06) + J05)
	buffer.writef64(Buf, 56, (R07 - J07) + J06)
	buffer.writef64(Buf, 64, (R08 - J08) + J07)
	buffer.writef64(Buf, 72, (R09 - J09) + J08)
	buffer.writef64(Buf, 80, (R10 - J10) + J09)
	buffer.writef64(Buf, 88, (R11 - J11) + J10)
	return Buf
end

function FieldPrime.Square(ElementA: buffer, Storage: buffer?): buffer
	local A00 = buffer.readf64(ElementA, 0)
	local A01 = buffer.readf64(ElementA, 8)
	local A02 = buffer.readf64(ElementA, 16)
	local A03 = buffer.readf64(ElementA, 24)
	local A04 = buffer.readf64(ElementA, 32)
	local A05 = buffer.readf64(ElementA, 40)
	local A06 = buffer.readf64(ElementA, 48)
	local A07 = buffer.readf64(ElementA, 56)
	local A08 = buffer.readf64(ElementA, 64)
	local A09 = buffer.readf64(ElementA, 72)
	local A10 = buffer.readf64(ElementA, 80)
	local A11 = buffer.readf64(ElementA, 88)
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
	local C00 = (A11 * D01 + A10 * D02 + A09 * D03 + A08 * D04 + A07 * D05 + A06 * A06) * (19 / 2 ^ 255) + (A00 * A00)
	local C01 = (A11 * D02 + A10 * D03 + A09 * D04 + A08 * D05 + A07 * D06) * (19 / 2 ^ 255) + (A01 * D00)
	local C02 = (A11 * D03 + A10 * D04 + A09 * D05 + A08 * D06 + A07 * A07) * (19 / 2 ^ 255) + (A02 * D00 + A01 * A01)
	local C03 = (A11 * D04 + A10 * D05 + A09 * D06 + A08 * D07) * (19 / 2 ^ 255) + (A03 * D00 + A02 * D01)
	local C04 = (A11 * D05 + A10 * D06 + A09 * D07 + A08 * A08) * (19 / 2 ^ 255) + (A04 * D00 + A03 * D01 + A02 * A02)
	local C05 = (A11 * D06 + A10 * D07 + A09 * D08) * (19 / 2 ^ 255) + (A05 * D00 + A04 * D01 + A03 * D02)
	local C06 = (A11 * D07 + A10 * D08 + A09 * A09) * (19 / 2 ^ 255) + (A06 * D00 + A05 * D01 + A04 * D02 + A03 * A03)
	local C07 = (A11 * D08 + A10 * D09) * (19 / 2 ^ 255) + (A07 * D00 + A06 * D01 + A05 * D02 + A04 * D03)
	local C08 = (A11 * D09 + A10 * A10) * (19 / 2 ^ 255) + (A08 * D00 + A07 * D01 + A06 * D02 + A05 * D03 + A04 * A04)
	local C09 = (A11 * D10) * (19 / 2 ^ 255) + (A09 * D00 + A08 * D01 + A07 * D02 + A06 * D03 + A05 * D04)
	local C10 = (A11 * A11) * (19 / 2 ^ 255) + (A10 * D00 + A09 * D01 + A08 * D02 + A07 * D03 + A06 * D04 + A05 * A05)
	local C11 = A11 * D00 + A10 * D01 + A09 * D02 + A08 * D03 + A07 * D04 + A06 * D05
	local Buf = Storage or buffer.create(SIZE)
	local K00 = C00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	local K01 = C01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	local K02 = C02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	local K03 = C03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	local K04 = C04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	local K05 = C05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	local K06 = C06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	local K07 = C07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	local K08 = C08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	local K09 = C09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	local K10 = C10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	local K11 = C11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	local R00 = (C00 - K00) + K11 * (19 / 2 ^ 255)
	local R01 = (C01 - K01) + K00
	local R02 = (C02 - K02) + K01
	local R03 = (C03 - K03) + K02
	local R04 = (C04 - K04) + K03
	local R05 = (C05 - K05) + K04
	local R06 = (C06 - K06) + K05
	local R07 = (C07 - K07) + K06
	local R08 = (C08 - K08) + K07
	local R09 = (C09 - K09) + K08
	local R10 = (C10 - K10) + K09
	local R11 = (C11 - K11) + K10
	local J00 = R00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	local J01 = R01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	local J02 = R02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	local J03 = R03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	local J04 = R04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	local J05 = R05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	local J06 = R06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	local J07 = R07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	local J08 = R08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	local J09 = R09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	local J10 = R10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	local J11 = R11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	buffer.writef64(Buf, 0, (R00 - J00) + J11 * (19 / 2 ^ 255))
	buffer.writef64(Buf, 8, (R01 - J01) + J00)
	buffer.writef64(Buf, 16, (R02 - J02) + J01)
	buffer.writef64(Buf, 24, (R03 - J03) + J02)
	buffer.writef64(Buf, 32, (R04 - J04) + J03)
	buffer.writef64(Buf, 40, (R05 - J05) + J04)
	buffer.writef64(Buf, 48, (R06 - J06) + J05)
	buffer.writef64(Buf, 56, (R07 - J07) + J06)
	buffer.writef64(Buf, 64, (R08 - J08) + J07)
	buffer.writef64(Buf, 72, (R09 - J09) + J08)
	buffer.writef64(Buf, 80, (R10 - J10) + J09)
	buffer.writef64(Buf, 88, (R11 - J11) + J10)
	return Buf
end

function FieldPrime.NSquare(ElementA: buffer, SquareCount: number, StoreInBuffer: boolean?): buffer
	if SquareCount <= 0 then
		return ElementA
	end
	local A00 = buffer.readf64(ElementA, 0)
	local A01 = buffer.readf64(ElementA, 8)
	local A02 = buffer.readf64(ElementA, 16)
	local A03 = buffer.readf64(ElementA, 24)
	local A04 = buffer.readf64(ElementA, 32)
	local A05 = buffer.readf64(ElementA, 40)
	local A06 = buffer.readf64(ElementA, 48)
	local A07 = buffer.readf64(ElementA, 56)
	local A08 = buffer.readf64(ElementA, 64)
	local A09 = buffer.readf64(ElementA, 72)
	local A10 = buffer.readf64(ElementA, 80)
	local A11 = buffer.readf64(ElementA, 88)
	for _ = 1, SquareCount do
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
	local C00 = (A11 * D01 + A10 * D02 + A09 * D03 + A08 * D04 + A07 * D05 + A06 * A06) * (19 / 2 ^ 255) + (A00 * A00)
	local C01 = (A11 * D02 + A10 * D03 + A09 * D04 + A08 * D05 + A07 * D06) * (19 / 2 ^ 255) + (A01 * D00)
	local C02 = (A11 * D03 + A10 * D04 + A09 * D05 + A08 * D06 + A07 * A07) * (19 / 2 ^ 255) + (A02 * D00 + A01 * A01)
	local C03 = (A11 * D04 + A10 * D05 + A09 * D06 + A08 * D07) * (19 / 2 ^ 255) + (A03 * D00 + A02 * D01)
	local C04 = (A11 * D05 + A10 * D06 + A09 * D07 + A08 * A08) * (19 / 2 ^ 255) + (A04 * D00 + A03 * D01 + A02 * A02)
	local C05 = (A11 * D06 + A10 * D07 + A09 * D08) * (19 / 2 ^ 255) + (A05 * D00 + A04 * D01 + A03 * D02)
	local C06 = (A11 * D07 + A10 * D08 + A09 * A09) * (19 / 2 ^ 255) + (A06 * D00 + A05 * D01 + A04 * D02 + A03 * A03)
	local C07 = (A11 * D08 + A10 * D09) * (19 / 2 ^ 255) + (A07 * D00 + A06 * D01 + A05 * D02 + A04 * D03)
	local C08 = (A11 * D09 + A10 * A10) * (19 / 2 ^ 255) + (A08 * D00 + A07 * D01 + A06 * D02 + A05 * D03 + A04 * A04)
	local C09 = (A11 * D10) * (19 / 2 ^ 255) + (A09 * D00 + A08 * D01 + A07 * D02 + A06 * D03 + A05 * D04)
	local C10 = (A11 * A11) * (19 / 2 ^ 255) + (A10 * D00 + A09 * D01 + A08 * D02 + A07 * D03 + A06 * D04 + A05 * A05)
	local C11 = A11 * D00 + A10 * D01 + A09 * D02 + A08 * D03 + A07 * D04 + A06 * D05
	local K00 = C00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	local K01 = C01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	local K02 = C02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	local K03 = C03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	local K04 = C04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	local K05 = C05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	local K06 = C06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	local K07 = C07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	local K08 = C08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	local K09 = C09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	local K10 = C10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	local K11 = C11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	local R00 = (C00 - K00) + K11 * (19 / 2 ^ 255)
	local R01 = (C01 - K01) + K00
	local R02 = (C02 - K02) + K01
	local R03 = (C03 - K03) + K02
	local R04 = (C04 - K04) + K03
	local R05 = (C05 - K05) + K04
	local R06 = (C06 - K06) + K05
	local R07 = (C07 - K07) + K06
	local R08 = (C08 - K08) + K07
	local R09 = (C09 - K09) + K08
	local R10 = (C10 - K10) + K09
	local R11 = (C11 - K11) + K10
	local J00 = R00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	local J01 = R01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	local J02 = R02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	local J03 = R03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	local J04 = R04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	local J05 = R05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	local J06 = R06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	local J07 = R07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	local J08 = R08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	local J09 = R09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	local J10 = R10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	local J11 = R11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	A00 = (R00 - J00) + J11 * (19 / 2 ^ 255)
	A01 = (R01 - J01) + J00
	A02 = (R02 - J02) + J01
	A03 = (R03 - J03) + J02
	A04 = (R04 - J04) + J03
	A05 = (R05 - J05) + J04
	A06 = (R06 - J06) + J05
	A07 = (R07 - J07) + J06
	A08 = (R08 - J08) + J07
	A09 = (R09 - J09) + J08
	A10 = (R10 - J10) + J09
	A11 = (R11 - J11) + J10
	end
	local Buf = if StoreInBuffer then ElementA else buffer.create(SIZE)
	buffer.writef64(Buf, 0, A00)
	buffer.writef64(Buf, 8, A01)
	buffer.writef64(Buf, 16, A02)
	buffer.writef64(Buf, 24, A03)
	buffer.writef64(Buf, 32, A04)
	buffer.writef64(Buf, 40, A05)
	buffer.writef64(Buf, 48, A06)
	buffer.writef64(Buf, 56, A07)
	buffer.writef64(Buf, 64, A08)
	buffer.writef64(Buf, 72, A09)
	buffer.writef64(Buf, 80, A10)
	buffer.writef64(Buf, 88, A11)
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
