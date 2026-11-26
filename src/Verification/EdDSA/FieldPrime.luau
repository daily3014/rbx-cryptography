--[=[
	Cryptography library: Field Prime (Curve25519 Base Field)

	Arithmetic in GF(2^255 - 19) using 12 weighted IEEE-754 f64 limbs
	and 2-half split carry propagation.

	Example usage:
		local ElementA = FieldPrime.Num(42)
		local ElementB = FieldPrime.Num(17)
		local Product = FieldPrime.Mul(ElementA, ElementB)
		local Encoded = FieldPrime.Encode(Product)
--]=]

--!strict
--!optimize 2

local SIZE = 104
local C19 = 19 / 2 ^ 255
local M00, M01, M02, M03 = 3 * 2 ^ 73, 3 * 2 ^ 94, 3 * 2 ^ 115, 3 * 2 ^ 136
local M04, M05, M06, M07 = 3 * 2 ^ 158, 3 * 2 ^ 179, 3 * 2 ^ 200, 3 * 2 ^ 221
local M08, M09, M10, M11 = 3 * 2 ^ 243, 3 * 2 ^ 264, 3 * 2 ^ 285, 3 * 2 ^ 306

local SQUARES: buffer = buffer.fromstring("\000\000\000\000\096\065\045\065\000\000\000\000\080\058\137\066\z
	\000\000\000\000\195\157\232\067\000\000\000\000\240\200\047\069\z
	\000\000\000\000\128\180\026\070\000\000\000\000\140\161\199\071\z
	\000\000\000\000\167\215\059\073\000\000\000\000\188\039\099\074\z
	\000\000\000\000\128\166\197\075\000\000\000\000\176\240\253\076\z
	\000\000\000\000\248\009\096\078\000\000\000\000\146\193\197\079\z
	\000\000\000\000\000\000\000\000")

local CANON_SCRATCH: buffer = buffer.create(SIZE)
local INV_T0: buffer = buffer.create(SIZE)
local INV_T1: buffer = buffer.create(SIZE)
local INV_T2: buffer = buffer.create(SIZE)
local INV_T3: buffer = buffer.create(SIZE)
local INV_T4: buffer = buffer.create(SIZE)

local FieldPrime = {}

function FieldPrime.Num(Number: number): buffer
	local Buf = buffer.create(SIZE)
	buffer.writef64(Buf, 0, Number)
	return Buf
end

@native
function FieldPrime.Neg(ElementA: buffer, Storage: buffer?): buffer
	local Buf = Storage or buffer.create(SIZE)
	buffer.writef64(Buf, 0, -buffer.readf64(ElementA, 0))
	buffer.writef64(Buf, 8, -buffer.readf64(ElementA, 8))
	buffer.writef64(Buf, 16, -buffer.readf64(ElementA, 16))
	buffer.writef64(Buf, 24, -buffer.readf64(ElementA, 24))
	buffer.writef64(Buf, 32, -buffer.readf64(ElementA, 32))
	buffer.writef64(Buf, 40, -buffer.readf64(ElementA, 40))
	buffer.writef64(Buf, 48, -buffer.readf64(ElementA, 48))
	buffer.writef64(Buf, 56, -buffer.readf64(ElementA, 56))
	buffer.writef64(Buf, 64, -buffer.readf64(ElementA, 64))
	buffer.writef64(Buf, 72, -buffer.readf64(ElementA, 72))
	buffer.writef64(Buf, 80, -buffer.readf64(ElementA, 80))
	buffer.writef64(Buf, 88, -buffer.readf64(ElementA, 88))
	return Buf
end

@native
function FieldPrime.Add(ElementA: buffer, ElementB: buffer, Storage: buffer?): buffer
	local Buf = Storage or buffer.create(SIZE)
	buffer.writef64(Buf, 0, buffer.readf64(ElementA, 0) + buffer.readf64(ElementB, 0))
	buffer.writef64(Buf, 8, buffer.readf64(ElementA, 8) + buffer.readf64(ElementB, 8))
	buffer.writef64(Buf, 16, buffer.readf64(ElementA, 16) + buffer.readf64(ElementB, 16))
	buffer.writef64(Buf, 24, buffer.readf64(ElementA, 24) + buffer.readf64(ElementB, 24))
	buffer.writef64(Buf, 32, buffer.readf64(ElementA, 32) + buffer.readf64(ElementB, 32))
	buffer.writef64(Buf, 40, buffer.readf64(ElementA, 40) + buffer.readf64(ElementB, 40))
	buffer.writef64(Buf, 48, buffer.readf64(ElementA, 48) + buffer.readf64(ElementB, 48))
	buffer.writef64(Buf, 56, buffer.readf64(ElementA, 56) + buffer.readf64(ElementB, 56))
	buffer.writef64(Buf, 64, buffer.readf64(ElementA, 64) + buffer.readf64(ElementB, 64))
	buffer.writef64(Buf, 72, buffer.readf64(ElementA, 72) + buffer.readf64(ElementB, 72))
	buffer.writef64(Buf, 80, buffer.readf64(ElementA, 80) + buffer.readf64(ElementB, 80))
	buffer.writef64(Buf, 88, buffer.readf64(ElementA, 88) + buffer.readf64(ElementB, 88))
	return Buf
end

@native
function FieldPrime.Sub(ElementA: buffer, ElementB: buffer, Storage: buffer?): buffer
	local Buf = Storage or buffer.create(SIZE)
	buffer.writef64(Buf, 0, buffer.readf64(ElementA, 0) - buffer.readf64(ElementB, 0))
	buffer.writef64(Buf, 8, buffer.readf64(ElementA, 8) - buffer.readf64(ElementB, 8))
	buffer.writef64(Buf, 16, buffer.readf64(ElementA, 16) - buffer.readf64(ElementB, 16))
	buffer.writef64(Buf, 24, buffer.readf64(ElementA, 24) - buffer.readf64(ElementB, 24))
	buffer.writef64(Buf, 32, buffer.readf64(ElementA, 32) - buffer.readf64(ElementB, 32))
	buffer.writef64(Buf, 40, buffer.readf64(ElementA, 40) - buffer.readf64(ElementB, 40))
	buffer.writef64(Buf, 48, buffer.readf64(ElementA, 48) - buffer.readf64(ElementB, 48))
	buffer.writef64(Buf, 56, buffer.readf64(ElementA, 56) - buffer.readf64(ElementB, 56))
	buffer.writef64(Buf, 64, buffer.readf64(ElementA, 64) - buffer.readf64(ElementB, 64))
	buffer.writef64(Buf, 72, buffer.readf64(ElementA, 72) - buffer.readf64(ElementB, 72))
	buffer.writef64(Buf, 80, buffer.readf64(ElementA, 80) - buffer.readf64(ElementB, 80))
	buffer.writef64(Buf, 88, buffer.readf64(ElementA, 88) - buffer.readf64(ElementB, 88))
	return Buf
end

@native
function FieldPrime.Carry(ElementA: buffer, Storage: buffer?): buffer
	local C00, C01, C02, C03, C04, C05 = buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8), buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24), buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40)
	local C06, C07, C08, C09, C10, C11 = buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56), buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72), buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)
	local K: number
	K = C00 + M00 - M00; C00 -= K; C01 += K
	K = C06 + M06 - M06; C06 -= K; C07 += K
	K = C01 + M01 - M01; C01 -= K; C02 += K
	K = C07 + M07 - M07; C07 -= K; C08 += K
	K = C02 + M02 - M02; C02 -= K; C03 += K
	K = C08 + M08 - M08; C08 -= K; C09 += K
	K = C03 + M03 - M03; C03 -= K; C04 += K
	K = C09 + M09 - M09; C09 -= K; C10 += K
	K = C04 + M04 - M04; C04 -= K; C05 += K
	K = C10 + M10 - M10; C10 -= K; C11 += K
	K = C05 + M05 - M05; C05 -= K; C06 += K
	K = C11 + M11 - M11; C11 -= K; C00 += K * C19
	K = C06 + M06 - M06; C06 -= K; C07 += K
	K = C00 + M00 - M00; C00 -= K; C01 += K
	local Buf = Storage or buffer.create(SIZE)
	buffer.writef64(Buf, 0, C00); buffer.writef64(Buf, 8, C01); buffer.writef64(Buf, 16, C02); buffer.writef64(Buf, 24, C03)
	buffer.writef64(Buf, 32, C04); buffer.writef64(Buf, 40, C05); buffer.writef64(Buf, 48, C06); buffer.writef64(Buf, 56, C07)
	buffer.writef64(Buf, 64, C08); buffer.writef64(Buf, 72, C09); buffer.writef64(Buf, 80, C10); buffer.writef64(Buf, 88, C11)
	return Buf
end

@native
function FieldPrime.Mul(ElementA: buffer, ElementB: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05 = buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8), buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24), buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40)
	local A06, A07, A08, A09, A10, A11 = buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56), buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72), buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)
	local B00, B01, B02, B03, B04, B05 = buffer.readf64(ElementB, 0), buffer.readf64(ElementB, 8), buffer.readf64(ElementB, 16), buffer.readf64(ElementB, 24), buffer.readf64(ElementB, 32), buffer.readf64(ElementB, 40)
	local B06, B07, B08, B09, B10, B11 = buffer.readf64(ElementB, 48), buffer.readf64(ElementB, 56), buffer.readf64(ElementB, 64), buffer.readf64(ElementB, 72), buffer.readf64(ElementB, 80), buffer.readf64(ElementB, 88)
	local C00 = (A01 * B11 + A02 * B10 + A03 * B09 + A04 * B08 + A05 * B07 + A06 * B06 + A07 * B05 + A08 * B04 + A09 * B03 + A10 * B02 + A11 * B01) * C19 + A00 * B00
	local C01 = (A02 * B11 + A03 * B10 + A04 * B09 + A05 * B08 + A06 * B07 + A07 * B06 + A08 * B05 + A09 * B04 + A10 * B03 + A11 * B02) * C19 + (A00 * B01 + A01 * B00)
	local C02 = (A03 * B11 + A04 * B10 + A05 * B09 + A06 * B08 + A07 * B07 + A08 * B06 + A09 * B05 + A10 * B04 + A11 * B03) * C19 + (A00 * B02 + A01 * B01 + A02 * B00)
	local C03 = (A04 * B11 + A05 * B10 + A06 * B09 + A07 * B08 + A08 * B07 + A09 * B06 + A10 * B05 + A11 * B04) * C19 + (A00 * B03 + A01 * B02 + A02 * B01 + A03 * B00)
	local C04 = (A05 * B11 + A06 * B10 + A07 * B09 + A08 * B08 + A09 * B07 + A10 * B06 + A11 * B05) * C19 + (A00 * B04 + A01 * B03 + A02 * B02 + A03 * B01 + A04 * B00)
	local C05 = (A06 * B11 + A07 * B10 + A08 * B09 + A09 * B08 + A10 * B07 + A11 * B06) * C19 + (A00 * B05 + A01 * B04 + A02 * B03 + A03 * B02 + A04 * B01 + A05 * B00)
	local C06 = (A07 * B11 + A08 * B10 + A09 * B09 + A10 * B08 + A11 * B07) * C19 + (A00 * B06 + A01 * B05 + A02 * B04 + A03 * B03 + A04 * B02 + A05 * B01 + A06 * B00)
	local C07 = (A08 * B11 + A09 * B10 + A10 * B09 + A11 * B08) * C19 + (A00 * B07 + A01 * B06 + A02 * B05 + A03 * B04 + A04 * B03 + A05 * B02 + A06 * B01 + A07 * B00)
	local C08 = (A09 * B11 + A10 * B10 + A11 * B09) * C19 + (A00 * B08 + A01 * B07 + A02 * B06 + A03 * B05 + A04 * B04 + A05 * B03 + A06 * B02 + A07 * B01 + A08 * B00)
	local C09 = (A10 * B11 + A11 * B10) * C19 + (A00 * B09 + A01 * B08 + A02 * B07 + A03 * B06 + A04 * B05 + A05 * B04 + A06 * B03 + A07 * B02 + A08 * B01 + A09 * B00)
	local C10 = (A11 * B11) * C19 + (A00 * B10 + A01 * B09 + A02 * B08 + A03 * B07 + A04 * B06 + A05 * B05 + A06 * B04 + A07 * B03 + A08 * B02 + A09 * B01 + A10 * B00)
	local C11 = A00 * B11 + A01 * B10 + A02 * B09 + A03 * B08 + A04 * B07 + A05 * B06 + A06 * B05 + A07 * B04 + A08 * B03 + A09 * B02 + A10 * B01 + A11 * B00
	local K: number
	K = C00 + M00 - M00; C00 -= K; C01 += K
	K = C06 + M06 - M06; C06 -= K; C07 += K
	K = C01 + M01 - M01; C01 -= K; C02 += K
	K = C07 + M07 - M07; C07 -= K; C08 += K
	K = C02 + M02 - M02; C02 -= K; C03 += K
	K = C08 + M08 - M08; C08 -= K; C09 += K
	K = C03 + M03 - M03; C03 -= K; C04 += K
	K = C09 + M09 - M09; C09 -= K; C10 += K
	K = C04 + M04 - M04; C04 -= K; C05 += K
	K = C10 + M10 - M10; C10 -= K; C11 += K
	K = C05 + M05 - M05; C05 -= K; C06 += K
	K = C11 + M11 - M11; C11 -= K; C00 += K * C19
	K = C06 + M06 - M06; C06 -= K; C07 += K
	K = C00 + M00 - M00; C00 -= K; C01 += K
	local Buf = Storage or buffer.create(SIZE)
	buffer.writef64(Buf, 0, C00); buffer.writef64(Buf, 8, C01); buffer.writef64(Buf, 16, C02); buffer.writef64(Buf, 24, C03)
	buffer.writef64(Buf, 32, C04); buffer.writef64(Buf, 40, C05); buffer.writef64(Buf, 48, C06); buffer.writef64(Buf, 56, C07)
	buffer.writef64(Buf, 64, C08); buffer.writef64(Buf, 72, C09); buffer.writef64(Buf, 80, C10); buffer.writef64(Buf, 88, C11)
	return Buf
end

@native
function FieldPrime.Square(ElementA: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05 = buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8), buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24), buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40)
	local A06, A07, A08, A09, A10, A11 = buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56), buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72), buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)
	local D00, D01, D02, D03, D04, D05 = A00 * 2, A01 * 2, A02 * 2, A03 * 2, A04 * 2, A05 * 2
	local D06, D07, D08, D09, D10 = A06 * 2, A07 * 2, A08 * 2, A09 * 2, A10 * 2
	local C00 = (A11 * D01 + A10 * D02 + A09 * D03 + A08 * D04 + A07 * D05 + A06 * A06) * C19 + A00 * A00
	local C01 = (A11 * D02 + A10 * D03 + A09 * D04 + A08 * D05 + A07 * D06) * C19 + A01 * D00
	local C02 = (A11 * D03 + A10 * D04 + A09 * D05 + A08 * D06 + A07 * A07) * C19 + (A02 * D00 + A01 * A01)
	local C03 = (A11 * D04 + A10 * D05 + A09 * D06 + A08 * D07) * C19 + (A03 * D00 + A02 * D01)
	local C04 = (A11 * D05 + A10 * D06 + A09 * D07 + A08 * A08) * C19 + (A04 * D00 + A03 * D01 + A02 * A02)
	local C05 = (A11 * D06 + A10 * D07 + A09 * D08) * C19 + (A05 * D00 + A04 * D01 + A03 * D02)
	local C06 = (A11 * D07 + A10 * D08 + A09 * A09) * C19 + (A06 * D00 + A05 * D01 + A04 * D02 + A03 * A03)
	local C07 = (A11 * D08 + A10 * D09) * C19 + (A07 * D00 + A06 * D01 + A05 * D02 + A04 * D03)
	local C08 = (A11 * D09 + A10 * A10) * C19 + (A08 * D00 + A07 * D01 + A06 * D02 + A05 * D03 + A04 * A04)
	local C09 = (A11 * D10) * C19 + (A09 * D00 + A08 * D01 + A07 * D02 + A06 * D03 + A05 * D04)
	local C10 = (A11 * A11) * C19 + (A10 * D00 + A09 * D01 + A08 * D02 + A07 * D03 + A06 * D04 + A05 * A05)
	local C11 = A11 * D00 + A10 * D01 + A09 * D02 + A08 * D03 + A07 * D04 + A06 * D05
	local K: number
	K = C00 + M00 - M00; C00 -= K; C01 += K
	K = C06 + M06 - M06; C06 -= K; C07 += K
	K = C01 + M01 - M01; C01 -= K; C02 += K
	K = C07 + M07 - M07; C07 -= K; C08 += K
	K = C02 + M02 - M02; C02 -= K; C03 += K
	K = C08 + M08 - M08; C08 -= K; C09 += K
	K = C03 + M03 - M03; C03 -= K; C04 += K
	K = C09 + M09 - M09; C09 -= K; C10 += K
	K = C04 + M04 - M04; C04 -= K; C05 += K
	K = C10 + M10 - M10; C10 -= K; C11 += K
	K = C05 + M05 - M05; C05 -= K; C06 += K
	K = C11 + M11 - M11; C11 -= K; C00 += K * C19
	K = C06 + M06 - M06; C06 -= K; C07 += K
	K = C00 + M00 - M00; C00 -= K; C01 += K
	local Buf = Storage or buffer.create(SIZE)
	buffer.writef64(Buf, 0, C00); buffer.writef64(Buf, 8, C01); buffer.writef64(Buf, 16, C02); buffer.writef64(Buf, 24, C03)
	buffer.writef64(Buf, 32, C04); buffer.writef64(Buf, 40, C05); buffer.writef64(Buf, 48, C06); buffer.writef64(Buf, 56, C07)
	buffer.writef64(Buf, 64, C08); buffer.writef64(Buf, 72, C09); buffer.writef64(Buf, 80, C10); buffer.writef64(Buf, 88, C11)
	return Buf
end

@native
function FieldPrime.NSquare(ElementA: buffer, SquareCount: number, Storage: buffer?): buffer
	if SquareCount <= 0 then
		if Storage and Storage ~= ElementA then
			buffer.copy(Storage, 0, ElementA, 0, SIZE)
			return Storage
		end
		return ElementA
	end
	local A00, A01, A02, A03, A04, A05 = buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8), buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24), buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40)
	local A06, A07, A08, A09, A10, A11 = buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56), buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72), buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)
	for _ = 1, SquareCount do
		local D00, D01, D02, D03, D04, D05 = A00 * 2, A01 * 2, A02 * 2, A03 * 2, A04 * 2, A05 * 2
		local D06, D07, D08, D09, D10 = A06 * 2, A07 * 2, A08 * 2, A09 * 2, A10 * 2
		local C00 = (A11 * D01 + A10 * D02 + A09 * D03 + A08 * D04 + A07 * D05 + A06 * A06) * C19 + A00 * A00
		local C01 = (A11 * D02 + A10 * D03 + A09 * D04 + A08 * D05 + A07 * D06) * C19 + A01 * D00
		local C02 = (A11 * D03 + A10 * D04 + A09 * D05 + A08 * D06 + A07 * A07) * C19 + (A02 * D00 + A01 * A01)
		local C03 = (A11 * D04 + A10 * D05 + A09 * D06 + A08 * D07) * C19 + (A03 * D00 + A02 * D01)
		local C04 = (A11 * D05 + A10 * D06 + A09 * D07 + A08 * A08) * C19 + (A04 * D00 + A03 * D01 + A02 * A02)
		local C05 = (A11 * D06 + A10 * D07 + A09 * D08) * C19 + (A05 * D00 + A04 * D01 + A03 * D02)
		local C06 = (A11 * D07 + A10 * D08 + A09 * A09) * C19 + (A06 * D00 + A05 * D01 + A04 * D02 + A03 * A03)
		local C07 = (A11 * D08 + A10 * D09) * C19 + (A07 * D00 + A06 * D01 + A05 * D02 + A04 * D03)
		local C08 = (A11 * D09 + A10 * A10) * C19 + (A08 * D00 + A07 * D01 + A06 * D02 + A05 * D03 + A04 * A04)
		local C09 = (A11 * D10) * C19 + (A09 * D00 + A08 * D01 + A07 * D02 + A06 * D03 + A05 * D04)
		local C10 = (A11 * A11) * C19 + (A10 * D00 + A09 * D01 + A08 * D02 + A07 * D03 + A06 * D04 + A05 * A05)
		local C11 = A11 * D00 + A10 * D01 + A09 * D02 + A08 * D03 + A07 * D04 + A06 * D05
		local K: number
		K = C00 + M00 - M00; C00 -= K; C01 += K
		K = C06 + M06 - M06; C06 -= K; C07 += K
		K = C01 + M01 - M01; C01 -= K; C02 += K
		K = C07 + M07 - M07; C07 -= K; C08 += K
		K = C02 + M02 - M02; C02 -= K; C03 += K
		K = C08 + M08 - M08; C08 -= K; C09 += K
		K = C03 + M03 - M03; C03 -= K; C04 += K
		K = C09 + M09 - M09; C09 -= K; C10 += K
		K = C04 + M04 - M04; C04 -= K; C05 += K
		K = C10 + M10 - M10; C10 -= K; C11 += K
		K = C05 + M05 - M05; C05 -= K; C06 += K
		K = C11 + M11 - M11; C11 -= K; C00 += K * C19
		K = C06 + M06 - M06; C06 -= K; C07 += K
		K = C00 + M00 - M00; C00 -= K; C01 += K
		A00, A01, A02, A03, A04, A05 = C00, C01, C02, C03, C04, C05
		A06, A07, A08, A09, A10, A11 = C06, C07, C08, C09, C10, C11
	end
	local Buf = Storage or buffer.create(SIZE)
	buffer.writef64(Buf, 0, A00); buffer.writef64(Buf, 8, A01); buffer.writef64(Buf, 16, A02); buffer.writef64(Buf, 24, A03)
	buffer.writef64(Buf, 32, A04); buffer.writef64(Buf, 40, A05); buffer.writef64(Buf, 48, A06); buffer.writef64(Buf, 56, A07)
	buffer.writef64(Buf, 64, A08); buffer.writef64(Buf, 72, A09); buffer.writef64(Buf, 80, A10); buffer.writef64(Buf, 88, A11)
	return Buf
end

@native
function FieldPrime.Canonicalize(ElementA: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05 = buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8), buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24), buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40)
	local A06, A07, A08, A09, A10, A11 = buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56), buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72), buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)
	local C00: number, C01: number, C02: number, C03: number, C04: number, C05: number
	local C06: number, C07: number, C08: number, C09: number, C10: number, C11: number

	for _ = 1, 2 do
		C00 = A00 % 2 ^ 22; A01 += A00 - C00
		C01 = A01 % 2 ^ 43; A02 += A01 - C01
		C02 = A02 % 2 ^ 64; A03 += A02 - C02
		C03 = A03 % 2 ^ 85; A04 += A03 - C03
		C04 = A04 % 2 ^ 107; A05 += A04 - C04
		C05 = A05 % 2 ^ 128; A06 += A05 - C05
		C06 = A06 % 2 ^ 149; A07 += A06 - C06
		C07 = A07 % 2 ^ 170; A08 += A07 - C07
		C08 = A08 % 2 ^ 192; A09 += A08 - C08
		C09 = A09 % 2 ^ 213; A10 += A09 - C09
		C10 = A10 % 2 ^ 234; A11 += A10 - C10
		C11 = A11 % 2 ^ 255; C00 += (A11 - C11) * C19
		A00, A01, A02, A03, A04, A05 = C00, C01, C02, C03, C04, C05
		A06, A07, A08, A09, A10, A11 = C06, C07, C08, C09, C10, C11
	end

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
		buffer.writef64(Buf, 0, C00); buffer.writef64(Buf, 8, C01); buffer.writef64(Buf, 16, C02); buffer.writef64(Buf, 24, C03)
		buffer.writef64(Buf, 32, C04); buffer.writef64(Buf, 40, C05); buffer.writef64(Buf, 48, C06); buffer.writef64(Buf, 56, C07)
		buffer.writef64(Buf, 64, C08); buffer.writef64(Buf, 72, C09); buffer.writef64(Buf, 80, C10); buffer.writef64(Buf, 88, C11)
	end

	return Buf
end

@native
function FieldPrime.Eqz(ElementA: buffer): boolean
	local Canonical = FieldPrime.Canonicalize(ElementA, CANON_SCRATCH)
	return buffer.readf64(Canonical, 0)
		+ buffer.readf64(Canonical, 8)
		+ buffer.readf64(Canonical, 16)
		+ buffer.readf64(Canonical, 24)
		+ buffer.readf64(Canonical, 32)
		+ buffer.readf64(Canonical, 40)
		+ buffer.readf64(Canonical, 48)
		+ buffer.readf64(Canonical, 56)
		+ buffer.readf64(Canonical, 64)
		+ buffer.readf64(Canonical, 72)
		+ buffer.readf64(Canonical, 80)
		+ buffer.readf64(Canonical, 88) == 0
end

@native
function FieldPrime.EqzAt(Point: buffer, Offset: number): boolean
	buffer.copy(CANON_SCRATCH, 0, Point, Offset, SIZE)
	return FieldPrime.Eqz(CANON_SCRATCH)
end

@native
function FieldPrime.Eq(ElementA: buffer, ElementB: buffer): boolean
	FieldPrime.Sub(ElementA, ElementB, CANON_SCRATCH)
	local Difference = FieldPrime.Canonicalize(CANON_SCRATCH, CANON_SCRATCH)
	local Acc = 0
	for LimbIndex = 0, 88, 8 do
		Acc = bit32.bor(Acc, buffer.readu32(Difference, LimbIndex), buffer.readu32(Difference, LimbIndex + 4))
	end
	return Acc == 0
end

function FieldPrime.Invert(ElementA: buffer, Storage: buffer?): buffer
	local Mul = FieldPrime.Mul
	local Square = FieldPrime.Square
	local NSquare = FieldPrime.NSquare
	local T0, T1, T2, T3, T4 = INV_T0, INV_T1, INV_T2, INV_T3, INV_T4

	Square(ElementA, T0)
	NSquare(T0, 2, T1)
	Mul(ElementA, T1, T1)
	Mul(T1, T0, T0)
	Square(T0, T2)
	Mul(T2, T1, T1)
	NSquare(T1, 5, T2)
	Mul(T2, T1, T2)
	NSquare(T2, 10, T3)
	Mul(T3, T2, T3)
	NSquare(T3, 20, T4)
	Mul(T4, T3, T3)
	NSquare(T3, 10, T3)
	Mul(T3, T2, T2)
	NSquare(T2, 50, T3)
	Mul(T3, T2, T3)
	NSquare(T3, 100, T4)
	Mul(T4, T3, T3)
	NSquare(T3, 50, T3)
	Mul(T3, T2, T3)
	NSquare(T3, 5, T3)
	return Mul(T3, T0, Storage)
end

function FieldPrime.SqrtDiv(ElementU: buffer, ElementV: buffer, Storage: buffer?): buffer?
	local Mul = FieldPrime.Mul
	local Square = FieldPrime.Square
	local NSquare = FieldPrime.NSquare
	local T0, T1, T2, T3, T4 = INV_T0, INV_T1, INV_T2, INV_T3, INV_T4

	FieldPrime.Carry(ElementU, ElementU)

	Square(ElementV, T0)
	Mul(ElementV, T0, T1)
	Mul(ElementU, T1, T1)
	Square(T0, T0)
	Mul(T1, T0, T0)

	Square(T0, T2)
	Mul(T2, T0, T2)
	NSquare(T2, 2, T3)
	Mul(T3, T2, T3)
	NSquare(T3, 4, T4)
	Mul(T4, T3, T3)
	NSquare(T3, 8, T4)
	Mul(T4, T3, T3)
	NSquare(T3, 2, T4)
	Mul(T4, T2, T2)
	NSquare(T3, 16, T4)
	Mul(T4, T3, T3)
	NSquare(T3, 18, T3)
	Mul(T3, T2, T2)
	NSquare(T2, 50, T3)
	Mul(T3, T2, T3)
	NSquare(T3, 100, T4)
	Mul(T4, T3, T3)
	NSquare(T3, 50, T3)
	Mul(T3, T2, T3)
	NSquare(T3, 2, T3)
	Mul(T3, T0, T3)

	local Candidate = Storage or buffer.create(SIZE)
	Mul(T1, T3, Candidate)
	Square(Candidate, T0)
	Mul(ElementV, T0, T0)

	if not FieldPrime.Eq(T0, ElementU) then
		Mul(Candidate, SQUARES, Candidate)
		Square(Candidate, T0)
		Mul(ElementV, T0, T0)
	end

	if FieldPrime.Eq(T0, ElementU) then
		return Candidate
	end

	return nil
end

@native
function FieldPrime.EncodeInto(ElementA: buffer, Out: buffer): ()
	local Canonical = FieldPrime.Canonicalize(ElementA, CANON_SCRATCH)
	local A00, A01, A02, A03, A04, A05 = buffer.readf64(Canonical, 0), buffer.readf64(Canonical, 8), buffer.readf64(Canonical, 16), buffer.readf64(Canonical, 24), buffer.readf64(Canonical, 32), buffer.readf64(Canonical, 40)
	local A06, A07, A08, A09, A10, A11 = buffer.readf64(Canonical, 48), buffer.readf64(Canonical, 56), buffer.readf64(Canonical, 64), buffer.readf64(Canonical, 72), buffer.readf64(Canonical, 80), buffer.readf64(Canonical, 88)

	local Acc = A00
	local B = Acc % 256; buffer.writeu8(Out, 0, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 1, B); Acc = (Acc - B) / 256

	Acc += A01 * 2 ^ -16
	B = Acc % 256; buffer.writeu8(Out, 2, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 3, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 4, B); Acc = (Acc - B) / 256

	Acc += A02 * 2 ^ -40
	B = Acc % 256; buffer.writeu8(Out, 5, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 6, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 7, B); Acc = (Acc - B) / 256

	Acc += A03 * 2 ^ -64
	B = Acc % 256; buffer.writeu8(Out, 8, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 9, B); Acc = (Acc - B) / 256

	Acc += A04 * 2 ^ -80
	B = Acc % 256; buffer.writeu8(Out, 10, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 11, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 12, B); Acc = (Acc - B) / 256

	Acc += A05 * 2 ^ -104
	B = Acc % 256; buffer.writeu8(Out, 13, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 14, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 15, B); Acc = (Acc - B) / 256

	Acc += A06 * 2 ^ -128
	B = Acc % 256; buffer.writeu8(Out, 16, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 17, B); Acc = (Acc - B) / 256

	Acc += A07 * 2 ^ -144
	B = Acc % 256; buffer.writeu8(Out, 18, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 19, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 20, B); Acc = (Acc - B) / 256

	Acc += A08 * 2 ^ -168
	B = Acc % 256; buffer.writeu8(Out, 21, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 22, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 23, B); Acc = (Acc - B) / 256

	Acc += A09 * 2 ^ -192
	B = Acc % 256; buffer.writeu8(Out, 24, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 25, B); Acc = (Acc - B) / 256

	Acc += A10 * 2 ^ -208
	B = Acc % 256; buffer.writeu8(Out, 26, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 27, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 28, B); Acc = (Acc - B) / 256

	Acc += A11 * 2 ^ -232
	B = Acc % 256; buffer.writeu8(Out, 29, B); Acc = (Acc - B) / 256
	B = Acc % 256; buffer.writeu8(Out, 30, B); Acc = (Acc - B) / 256
	buffer.writeu8(Out, 31, Acc % 256)
end

function FieldPrime.Encode(ElementA: buffer): buffer
	local Out = buffer.create(32)
	FieldPrime.EncodeInto(ElementA, Out)
	return Out
end

@native
function FieldPrime.DecodeInto(EncodedBytes: buffer, Out: buffer): ()
	local W00 = buffer.readu8(EncodedBytes, 0) + buffer.readu8(EncodedBytes, 1) * 256 + buffer.readu8(EncodedBytes, 2) * 65536
	local W01 = buffer.readu8(EncodedBytes, 3) + buffer.readu8(EncodedBytes, 4) * 256 + buffer.readu8(EncodedBytes, 5) * 65536
	local W02 = buffer.readu16(EncodedBytes, 6)
	local W03 = buffer.readu8(EncodedBytes, 8) + buffer.readu8(EncodedBytes, 9) * 256 + buffer.readu8(EncodedBytes, 10) * 65536
	local W04 = buffer.readu8(EncodedBytes, 11) + buffer.readu8(EncodedBytes, 12) * 256 + buffer.readu8(EncodedBytes, 13) * 65536
	local W05 = buffer.readu16(EncodedBytes, 14)
	local W06 = buffer.readu8(EncodedBytes, 16) + buffer.readu8(EncodedBytes, 17) * 256 + buffer.readu8(EncodedBytes, 18) * 65536
	local W07 = buffer.readu8(EncodedBytes, 19) + buffer.readu8(EncodedBytes, 20) * 256 + buffer.readu8(EncodedBytes, 21) * 65536
	local W08 = buffer.readu16(EncodedBytes, 22)
	local W09 = buffer.readu8(EncodedBytes, 24) + buffer.readu8(EncodedBytes, 25) * 256 + buffer.readu8(EncodedBytes, 26) * 65536
	local W10 = buffer.readu8(EncodedBytes, 27) + buffer.readu8(EncodedBytes, 28) * 256 + buffer.readu8(EncodedBytes, 29) * 65536
	local W11 = bit32.band(buffer.readu16(EncodedBytes, 30), 0x7FFF)

	buffer.writef64(Out, 0, W00)
	buffer.writef64(Out, 8, W01 * 2 ^ 24)
	buffer.writef64(Out, 16, W02 * 2 ^ 48)
	buffer.writef64(Out, 24, W03 * 2 ^ 64)
	buffer.writef64(Out, 32, W04 * 2 ^ 88)
	buffer.writef64(Out, 40, W05 * 2 ^ 112)
	buffer.writef64(Out, 48, W06 * 2 ^ 128)
	buffer.writef64(Out, 56, W07 * 2 ^ 152)
	buffer.writef64(Out, 64, W08 * 2 ^ 176)
	buffer.writef64(Out, 72, W09 * 2 ^ 192)
	buffer.writef64(Out, 80, W10 * 2 ^ 216)
	buffer.writef64(Out, 88, W11 * 2 ^ 240)
	FieldPrime.Carry(Out, Out)
end

function FieldPrime.Decode(EncodedBytes: buffer): buffer
	local Buf = buffer.create(SIZE)
	FieldPrime.DecodeInto(EncodedBytes, Buf)
	return Buf
end

function FieldPrime.ClearCaches(): ()
	buffer.fill(CANON_SCRATCH, 0, 0)
	buffer.fill(INV_T0, 0, 0)
	buffer.fill(INV_T1, 0, 0)
	buffer.fill(INV_T2, 0, 0)
	buffer.fill(INV_T3, 0, 0)
	buffer.fill(INV_T4, 0, 0)
end

return FieldPrime
