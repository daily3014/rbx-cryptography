--[=[
	Cryptography library: Edwards25519

	Extended twisted Edwards curve operations with split-carry 12-limb
	field arithmetic, lazy basepoint table construction, and joint
	windowed NAF scalar multiplication.

	Example usage:
		Edwards25519.MulGBytes(Scalar32, OutPoint, false)
		Edwards25519.EncodeInto(OutPoint, Encoded32)
--]=]

--!strict
--!optimize 2

local FieldPrime = require("./FieldPrime")

local POINT_SIZE = 416
local COORD_SIZE = 104
local AFFINE_NIELS_SIZE = 312
local BASE_RADIX_WIDTH = 6
local BASE_POINT_ROW = 32
local C19 = 19 / 2 ^ 255
local M00, M01, M02, M03 = 3 * 2 ^ 73, 3 * 2 ^ 94, 3 * 2 ^ 115, 3 * 2 ^ 136
local M04, M05, M06, M07 = 3 * 2 ^ 158, 3 * 2 ^ 179, 3 * 2 ^ 200, 3 * 2 ^ 221
local M08, M09, M10, M11 = 3 * 2 ^ 243, 3 * 2 ^ 264, 3 * 2 ^ 285, 3 * 2 ^ 306

local CURVE_D: buffer = buffer.fromstring("\000\000\000\000\182\120\057\065\000\000\000\000\102\175\129\194\z
	\000\000\000\000\212\122\221\067\000\000\000\000\176\138\253\068\z
	\000\000\000\000\010\106\130\070\000\000\000\000\000\002\092\071\z
	\000\000\000\000\160\093\024\201\000\000\000\000\224\093\094\074\z
	\000\000\000\000\048\206\220\203\000\000\000\000\232\252\047\077\z
	\000\000\000\000\108\197\109\078\000\000\000\000\074\254\198\207\z
	\000\000\000\000\000\000\000\000")
local CURVE_K: buffer = buffer.fromstring("\000\000\000\000\078\029\042\193\000\000\000\000\054\161\140\066\z
	\000\000\000\000\104\041\180\195\000\000\000\000\184\138\013\069\z
	\000\000\000\000\236\043\139\198\000\000\000\000\000\003\108\071\z
	\000\000\000\000\160\093\040\201\000\000\000\000\224\093\110\074\z
	\000\000\000\000\128\142\185\075\000\000\000\000\000\200\136\204\z
	\000\000\000\000\110\197\125\078\000\000\000\000\108\003\194\079\z
	\000\000\000\000\000\000\000\000")
local BASEPOINT_G: buffer = buffer.fromstring("\000\000\000\000\230\042\058\193\000\000\000\000\134\251\132\194\z
	\000\000\000\000\232\084\203\195\000\000\000\000\204\158\022\069\z
	\000\000\000\000\092\237\099\198\000\000\000\000\050\075\218\071\z
	\000\000\000\000\072\071\034\201\000\000\000\000\034\224\124\202\z
	\000\000\000\000\142\173\207\203\000\000\000\000\254\167\044\077\z
	\000\000\000\000\042\195\114\206\000\000\000\000\156\180\192\079\z
	\000\000\000\000\000\000\000\000\000\000\000\000\149\153\057\193\z
	\000\000\000\000\152\153\121\194\000\000\000\000\154\153\217\067\z
	\000\000\000\000\152\153\025\069\000\000\000\000\154\153\121\198\z
	\000\000\000\000\154\153\217\071\000\000\000\000\152\153\025\073\z
	\000\000\000\000\154\153\121\202\000\000\000\000\154\153\217\075\z
	\000\000\000\000\152\153\025\077\000\000\000\000\154\153\121\206\z
	\000\000\000\000\152\153\185\207\000\000\000\000\000\000\000\000\z
	\000\000\000\000\000\000\240\063\000\000\000\000\000\000\000\000\z
	\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\z
	\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\z
	\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\z
	\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\z
	\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\z
	\000\000\000\000\000\000\000\000\000\000\000\000\148\068\032\193\z
	\000\000\000\000\046\157\133\066\000\000\000\000\162\119\219\067\z
	\000\000\000\000\022\090\045\197\000\000\000\000\040\226\095\198\z
	\000\000\000\000\080\120\192\071\000\000\000\000\250\198\039\073\z
	\000\000\000\000\182\025\119\202\000\000\000\000\148\186\217\075\z
	\000\000\000\000\202\236\038\077\000\000\000\000\016\005\110\206\z
	\000\000\000\000\160\120\184\207\000\000\000\000\000\000\000\000")

local IDENTITY_O: buffer = buffer.create(POINT_SIZE)
buffer.writef64(IDENTITY_O, COORD_SIZE, 1)
buffer.writef64(IDENTITY_O, 2 * COORD_SIZE, 1)

local ONE: buffer = buffer.create(COORD_SIZE)
buffer.writef64(ONE, 0, 1)

local MULG_DUMMY: buffer = buffer.create(POINT_SIZE)
local NAF_WORK: buffer = buffer.create(POINT_SIZE)
local NAF_STEP: buffer = buffer.create(POINT_SIZE)
local JOINT_DIGITS_P: buffer = buffer.create(136)
local JOINT_DIGITS_Q: buffer = buffer.create(136)

local SCRATCH_A: buffer = buffer.create(COORD_SIZE)
local SCRATCH_B: buffer = buffer.create(COORD_SIZE)
local SCRATCH_C: buffer = buffer.create(COORD_SIZE)
local SCRATCH_D: buffer = buffer.create(COORD_SIZE)
local SCRATCH_E: buffer = buffer.create(COORD_SIZE)
local DECODE_WORK: buffer = buffer.create(32)

local AFFINE_BASEPOINT_TABLE: buffer? = nil

local Edwards25519 = {}

@native
local function FieldMul(
	A00: number, A01: number, A02: number, A03: number, A04: number, A05: number,
	A06: number, A07: number, A08: number, A09: number, A10: number, A11: number,
	B00: number, B01: number, B02: number, B03: number, B04: number, B05: number,
	B06: number, B07: number, B08: number, B09: number, B10: number, B11: number
): (number, number, number, number, number, number, number, number, number, number, number, number)
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
	return C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11
end

@native
local function FieldSquare(
	A00: number, A01: number, A02: number, A03: number, A04: number, A05: number,
	A06: number, A07: number, A08: number, A09: number, A10: number, A11: number
): (number, number, number, number, number, number, number, number, number, number, number, number)
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
	return C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11
end

@native
function Edwards25519.DoubleInPlace(Point: buffer, WithT: boolean): ()
	local X00, X01, X02, X03, X04, X05 = buffer.readf64(Point, 0), buffer.readf64(Point, 8), buffer.readf64(Point, 16), buffer.readf64(Point, 24), buffer.readf64(Point, 32), buffer.readf64(Point, 40)
	local X06, X07, X08, X09, X10, X11 = buffer.readf64(Point, 48), buffer.readf64(Point, 56), buffer.readf64(Point, 64), buffer.readf64(Point, 72), buffer.readf64(Point, 80), buffer.readf64(Point, 88)
	local Y00, Y01, Y02, Y03, Y04, Y05 = buffer.readf64(Point, 104), buffer.readf64(Point, 112), buffer.readf64(Point, 120), buffer.readf64(Point, 128), buffer.readf64(Point, 136), buffer.readf64(Point, 144)
	local Y06, Y07, Y08, Y09, Y10, Y11 = buffer.readf64(Point, 152), buffer.readf64(Point, 160), buffer.readf64(Point, 168), buffer.readf64(Point, 176), buffer.readf64(Point, 184), buffer.readf64(Point, 192)
	local Z00, Z01, Z02, Z03, Z04, Z05 = buffer.readf64(Point, 208), buffer.readf64(Point, 216), buffer.readf64(Point, 224), buffer.readf64(Point, 232), buffer.readf64(Point, 240), buffer.readf64(Point, 248)
	local Z06, Z07, Z08, Z09, Z10, Z11 = buffer.readf64(Point, 256), buffer.readf64(Point, 264), buffer.readf64(Point, 272), buffer.readf64(Point, 280), buffer.readf64(Point, 288), buffer.readf64(Point, 296)

	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 = FieldSquare(X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11)
	if not Point then return end
	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11 = FieldSquare(Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11)
	if not Point then return end
	Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11 = FieldSquare(Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11)
	if not Point then return end

	X00 += Y00; X01 += Y01; X02 += Y02; X03 += Y03; X04 += Y04; X05 += Y05
	X06 += Y06; X07 += Y07; X08 += Y08; X09 += Y09; X10 += Y10; X11 += Y11
	Y00 = A00 + B00; Y01 = A01 + B01; Y02 = A02 + B02; Y03 = A03 + B03; Y04 = A04 + B04; Y05 = A05 + B05
	Y06 = A06 + B06; Y07 = A07 + B07; Y08 = A08 + B08; Y09 = A09 + B09; Y10 = A10 + B10; Y11 = A11 + B11

	X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11 = FieldSquare(X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11)
	if not Point then return end

	X00 -= Y00; X01 -= Y01; X02 -= Y02; X03 -= Y03; X04 -= Y04; X05 -= Y05
	X06 -= Y06; X07 -= Y07; X08 -= Y08; X09 -= Y09; X10 -= Y10; X11 -= Y11
	B00 -= A00; B01 -= A01; B02 -= A02; B03 -= A03; B04 -= A04; B05 -= A05
	B06 -= A06; B07 -= A07; B08 -= A08; B09 -= A09; B10 -= A10; B11 -= A11
	Z00 = Z00 * 2 - B00; Z01 = Z01 * 2 - B01; Z02 = Z02 * 2 - B02; Z03 = Z03 * 2 - B03; Z04 = Z04 * 2 - B04; Z05 = Z05 * 2 - B05
	Z06 = Z06 * 2 - B06; Z07 = Z07 * 2 - B07; Z08 = Z08 * 2 - B08; Z09 = Z09 * 2 - B09; Z10 = Z10 * 2 - B10; Z11 = Z11 * 2 - B11

	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11)
		buffer.writef64(Point, 0, O00); buffer.writef64(Point, 8, O01); buffer.writef64(Point, 16, O02); buffer.writef64(Point, 24, O03)
		buffer.writef64(Point, 32, O04); buffer.writef64(Point, 40, O05); buffer.writef64(Point, 48, O06); buffer.writef64(Point, 56, O07)
		buffer.writef64(Point, 64, O08); buffer.writef64(Point, 72, O09); buffer.writef64(Point, 80, O10); buffer.writef64(Point, 88, O11)
	end
	if not Point then return end
	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11)
		buffer.writef64(Point, 104, O00); buffer.writef64(Point, 112, O01); buffer.writef64(Point, 120, O02); buffer.writef64(Point, 128, O03)
		buffer.writef64(Point, 136, O04); buffer.writef64(Point, 144, O05); buffer.writef64(Point, 152, O06); buffer.writef64(Point, 160, O07)
		buffer.writef64(Point, 168, O08); buffer.writef64(Point, 176, O09); buffer.writef64(Point, 184, O10); buffer.writef64(Point, 192, O11)
	end
	if not Point then return end
	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11, B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11)
		buffer.writef64(Point, 208, O00); buffer.writef64(Point, 216, O01); buffer.writef64(Point, 224, O02); buffer.writef64(Point, 232, O03)
		buffer.writef64(Point, 240, O04); buffer.writef64(Point, 248, O05); buffer.writef64(Point, 256, O06); buffer.writef64(Point, 264, O07)
		buffer.writef64(Point, 272, O08); buffer.writef64(Point, 280, O09); buffer.writef64(Point, 288, O10); buffer.writef64(Point, 296, O11)
	end
	if not Point then return end
	if WithT then
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11)
		buffer.writef64(Point, 312, O00); buffer.writef64(Point, 320, O01); buffer.writef64(Point, 328, O02); buffer.writef64(Point, 336, O03)
		buffer.writef64(Point, 344, O04); buffer.writef64(Point, 352, O05); buffer.writef64(Point, 360, O06); buffer.writef64(Point, 368, O07)
		buffer.writef64(Point, 376, O08); buffer.writef64(Point, 384, O09); buffer.writef64(Point, 392, O10); buffer.writef64(Point, 400, O11)
	end
end

@native
local function AddInPlace(Point: buffer, Table: buffer, PlusOffset: number, MinusOffset: number, TOffset: number, ZOffset: number, Sign: number, WithT: boolean): ()
	local X00, X01, X02, X03, X04, X05 = buffer.readf64(Point, 0), buffer.readf64(Point, 8), buffer.readf64(Point, 16), buffer.readf64(Point, 24), buffer.readf64(Point, 32), buffer.readf64(Point, 40)
	local X06, X07, X08, X09, X10, X11 = buffer.readf64(Point, 48), buffer.readf64(Point, 56), buffer.readf64(Point, 64), buffer.readf64(Point, 72), buffer.readf64(Point, 80), buffer.readf64(Point, 88)
	local Y00, Y01, Y02, Y03, Y04, Y05 = buffer.readf64(Point, 104), buffer.readf64(Point, 112), buffer.readf64(Point, 120), buffer.readf64(Point, 128), buffer.readf64(Point, 136), buffer.readf64(Point, 144)
	local Y06, Y07, Y08, Y09, Y10, Y11 = buffer.readf64(Point, 152), buffer.readf64(Point, 160), buffer.readf64(Point, 168), buffer.readf64(Point, 176), buffer.readf64(Point, 184), buffer.readf64(Point, 192)
	local Z00, Z01, Z02, Z03, Z04, Z05 = buffer.readf64(Point, 208), buffer.readf64(Point, 216), buffer.readf64(Point, 224), buffer.readf64(Point, 232), buffer.readf64(Point, 240), buffer.readf64(Point, 248)
	local Z06, Z07, Z08, Z09, Z10, Z11 = buffer.readf64(Point, 256), buffer.readf64(Point, 264), buffer.readf64(Point, 272), buffer.readf64(Point, 280), buffer.readf64(Point, 288), buffer.readf64(Point, 296)
	local T00, T01, T02, T03, T04, T05 = buffer.readf64(Point, 312), buffer.readf64(Point, 320), buffer.readf64(Point, 328), buffer.readf64(Point, 336), buffer.readf64(Point, 344), buffer.readf64(Point, 352)
	local T06, T07, T08, T09, T10, T11 = buffer.readf64(Point, 360), buffer.readf64(Point, 368), buffer.readf64(Point, 376), buffer.readf64(Point, 384), buffer.readf64(Point, 392), buffer.readf64(Point, 400)

	local A00, A01, A02, A03, A04, A05 = Y00 - X00, Y01 - X01, Y02 - X02, Y03 - X03, Y04 - X04, Y05 - X05
	local A06, A07, A08, A09, A10, A11 = Y06 - X06, Y07 - X07, Y08 - X08, Y09 - X09, Y10 - X10, Y11 - X11
	local N00, N01, N02, N03, N04, N05 = buffer.readf64(Table, MinusOffset), buffer.readf64(Table, MinusOffset + 8), buffer.readf64(Table, MinusOffset + 16), buffer.readf64(Table, MinusOffset + 24), buffer.readf64(Table, MinusOffset + 32), buffer.readf64(Table, MinusOffset + 40)
	local N06, N07, N08, N09, N10, N11 = buffer.readf64(Table, MinusOffset + 48), buffer.readf64(Table, MinusOffset + 56), buffer.readf64(Table, MinusOffset + 64), buffer.readf64(Table, MinusOffset + 72), buffer.readf64(Table, MinusOffset + 80), buffer.readf64(Table, MinusOffset + 88)
	A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 = FieldMul(A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11, N00, N01, N02, N03, N04, N05, N06, N07, N08, N09, N10, N11)
	if PlusOffset < 0 then return end

	Y00 += X00; Y01 += X01; Y02 += X02; Y03 += X03; Y04 += X04; Y05 += X05
	Y06 += X06; Y07 += X07; Y08 += X08; Y09 += X09; Y10 += X10; Y11 += X11
	N00 = buffer.readf64(Table, PlusOffset); N01 = buffer.readf64(Table, PlusOffset + 8); N02 = buffer.readf64(Table, PlusOffset + 16)
	N03 = buffer.readf64(Table, PlusOffset + 24); N04 = buffer.readf64(Table, PlusOffset + 32); N05 = buffer.readf64(Table, PlusOffset + 40)
	N06 = buffer.readf64(Table, PlusOffset + 48); N07 = buffer.readf64(Table, PlusOffset + 56); N08 = buffer.readf64(Table, PlusOffset + 64)
	N09 = buffer.readf64(Table, PlusOffset + 72); N10 = buffer.readf64(Table, PlusOffset + 80); N11 = buffer.readf64(Table, PlusOffset + 88)
	Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11 = FieldMul(Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11, N00, N01, N02, N03, N04, N05, N06, N07, N08, N09, N10, N11)
	if PlusOffset < 0 then return end

	N00 = buffer.readf64(Table, TOffset); N01 = buffer.readf64(Table, TOffset + 8); N02 = buffer.readf64(Table, TOffset + 16)
	N03 = buffer.readf64(Table, TOffset + 24); N04 = buffer.readf64(Table, TOffset + 32); N05 = buffer.readf64(Table, TOffset + 40)
	N06 = buffer.readf64(Table, TOffset + 48); N07 = buffer.readf64(Table, TOffset + 56); N08 = buffer.readf64(Table, TOffset + 64)
	N09 = buffer.readf64(Table, TOffset + 72); N10 = buffer.readf64(Table, TOffset + 80); N11 = buffer.readf64(Table, TOffset + 88)
	T00, T01, T02, T03, T04, T05, T06, T07, T08, T09, T10, T11 = FieldMul(T00, T01, T02, T03, T04, T05, T06, T07, T08, T09, T10, T11, N00, N01, N02, N03, N04, N05, N06, N07, N08, N09, N10, N11)
	if PlusOffset < 0 then return end

	if ZOffset < 0 then
		Z00 += Z00; Z01 += Z01; Z02 += Z02; Z03 += Z03; Z04 += Z04; Z05 += Z05
		Z06 += Z06; Z07 += Z07; Z08 += Z08; Z09 += Z09; Z10 += Z10; Z11 += Z11
	else
		N00 = buffer.readf64(Table, ZOffset); N01 = buffer.readf64(Table, ZOffset + 8); N02 = buffer.readf64(Table, ZOffset + 16)
		N03 = buffer.readf64(Table, ZOffset + 24); N04 = buffer.readf64(Table, ZOffset + 32); N05 = buffer.readf64(Table, ZOffset + 40)
		N06 = buffer.readf64(Table, ZOffset + 48); N07 = buffer.readf64(Table, ZOffset + 56); N08 = buffer.readf64(Table, ZOffset + 64)
		N09 = buffer.readf64(Table, ZOffset + 72); N10 = buffer.readf64(Table, ZOffset + 80); N11 = buffer.readf64(Table, ZOffset + 88)
		Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11 = FieldMul(Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11, N00, N01, N02, N03, N04, N05, N06, N07, N08, N09, N10, N11)
		if PlusOffset < 0 then return end
	end

	X00, X01, X02, X03, X04, X05 = Y00 - A00, Y01 - A01, Y02 - A02, Y03 - A03, Y04 - A04, Y05 - A05
	X06, X07, X08, X09, X10, X11 = Y06 - A06, Y07 - A07, Y08 - A08, Y09 - A09, Y10 - A10, Y11 - A11
	T00 *= Sign; T01 *= Sign; T02 *= Sign; T03 *= Sign; T04 *= Sign; T05 *= Sign
	T06 *= Sign; T07 *= Sign; T08 *= Sign; T09 *= Sign; T10 *= Sign; T11 *= Sign
	N00, N01, N02, N03, N04, N05 = Z00 - T00, Z01 - T01, Z02 - T02, Z03 - T03, Z04 - T04, Z05 - T05
	N06, N07, N08, N09, N10, N11 = Z06 - T06, Z07 - T07, Z08 - T08, Z09 - T09, Z10 - T10, Z11 - T11
	Z00 += T00; Z01 += T01; Z02 += T02; Z03 += T03; Z04 += T04; Z05 += T05
	Z06 += T06; Z07 += T07; Z08 += T08; Z09 += T09; Z10 += T10; Z11 += T11
	Y00 += A00; Y01 += A01; Y02 += A02; Y03 += A03; Y04 += A04; Y05 += A05
	Y06 += A06; Y07 += A07; Y08 += A08; Y09 += A09; Y10 += A10; Y11 += A11

	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, N00, N01, N02, N03, N04, N05, N06, N07, N08, N09, N10, N11)
		buffer.writef64(Point, 0, O00); buffer.writef64(Point, 8, O01); buffer.writef64(Point, 16, O02); buffer.writef64(Point, 24, O03)
		buffer.writef64(Point, 32, O04); buffer.writef64(Point, 40, O05); buffer.writef64(Point, 48, O06); buffer.writef64(Point, 56, O07)
		buffer.writef64(Point, 64, O08); buffer.writef64(Point, 72, O09); buffer.writef64(Point, 80, O10); buffer.writef64(Point, 88, O11)
	end
	if PlusOffset < 0 then return end
	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11, Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11)
		buffer.writef64(Point, 104, O00); buffer.writef64(Point, 112, O01); buffer.writef64(Point, 120, O02); buffer.writef64(Point, 128, O03)
		buffer.writef64(Point, 136, O04); buffer.writef64(Point, 144, O05); buffer.writef64(Point, 152, O06); buffer.writef64(Point, 160, O07)
		buffer.writef64(Point, 168, O08); buffer.writef64(Point, 176, O09); buffer.writef64(Point, 184, O10); buffer.writef64(Point, 192, O11)
	end
	if PlusOffset < 0 then return end
	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(N00, N01, N02, N03, N04, N05, N06, N07, N08, N09, N10, N11, Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11)
		buffer.writef64(Point, 208, O00); buffer.writef64(Point, 216, O01); buffer.writef64(Point, 224, O02); buffer.writef64(Point, 232, O03)
		buffer.writef64(Point, 240, O04); buffer.writef64(Point, 248, O05); buffer.writef64(Point, 256, O06); buffer.writef64(Point, 264, O07)
		buffer.writef64(Point, 272, O08); buffer.writef64(Point, 280, O09); buffer.writef64(Point, 288, O10); buffer.writef64(Point, 296, O11)
	end
	if PlusOffset < 0 then return end
	if WithT then
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11)
		buffer.writef64(Point, 312, O00); buffer.writef64(Point, 320, O01); buffer.writef64(Point, 328, O02); buffer.writef64(Point, 336, O03)
		buffer.writef64(Point, 344, O04); buffer.writef64(Point, 352, O05); buffer.writef64(Point, 360, O06); buffer.writef64(Point, 368, O07)
		buffer.writef64(Point, 376, O08); buffer.writef64(Point, 384, O09); buffer.writef64(Point, 392, O10); buffer.writef64(Point, 400, O11)
	end
end

function Edwards25519.NielsInto(Point: buffer, Out: buffer, OutOffset: number): ()
	buffer.copy(SCRATCH_A, 0, Point, 0, COORD_SIZE)
	buffer.copy(SCRATCH_B, 0, Point, COORD_SIZE, COORD_SIZE)
	buffer.copy(SCRATCH_C, 0, Point, 2 * COORD_SIZE, COORD_SIZE)
	buffer.copy(SCRATCH_D, 0, Point, 3 * COORD_SIZE, COORD_SIZE)

	FieldPrime.Add(SCRATCH_B, SCRATCH_A, SCRATCH_E)
	buffer.copy(Out, OutOffset, SCRATCH_E, 0, COORD_SIZE)
	FieldPrime.Sub(SCRATCH_B, SCRATCH_A, SCRATCH_E)
	buffer.copy(Out, OutOffset + COORD_SIZE, SCRATCH_E, 0, COORD_SIZE)
	FieldPrime.Add(SCRATCH_C, SCRATCH_C, SCRATCH_C)
	buffer.copy(Out, OutOffset + 2 * COORD_SIZE, SCRATCH_C, 0, COORD_SIZE)
	FieldPrime.Mul(SCRATCH_D, CURVE_K, SCRATCH_D)
	buffer.copy(Out, OutOffset + 3 * COORD_SIZE, SCRATCH_D, 0, COORD_SIZE)
end

function Edwards25519.SubNielsInPlace(Point: buffer, NielsPoint: buffer): ()
	AddInPlace(Point, NielsPoint, 104, 0, 312, 208, -1, false)
end

function Edwards25519.EncodeInto(Point: buffer, Out32: buffer): ()
	buffer.copy(SCRATCH_A, 0, Point, 0, COORD_SIZE)
	buffer.copy(SCRATCH_B, 0, Point, COORD_SIZE, COORD_SIZE)
	buffer.copy(SCRATCH_C, 0, Point, 2 * COORD_SIZE, COORD_SIZE)

	FieldPrime.Invert(SCRATCH_C, SCRATCH_C)
	FieldPrime.Mul(SCRATCH_A, SCRATCH_C, SCRATCH_A)
	FieldPrime.Mul(SCRATCH_B, SCRATCH_C, SCRATCH_B)

	FieldPrime.EncodeInto(SCRATCH_B, Out32)
	FieldPrime.Canonicalize(SCRATCH_A, SCRATCH_A)
	local XSignBit = buffer.readf64(SCRATCH_A, 0) % 2
	buffer.writeu8(Out32, 31, buffer.readu8(Out32, 31) + XSignBit * 128)
end

function Edwards25519.DecodeInto(EncodedBuffer: buffer, OutPoint: buffer): boolean
	buffer.copy(DECODE_WORK, 0, EncodedBuffer, 0, 32)
	local LastByte = buffer.readu8(DECODE_WORK, 31)
	local SignBit = bit32.rshift(LastByte, 7)
	buffer.writeu8(DECODE_WORK, 31, bit32.band(LastByte, 0x7F))

	if buffer.readu32(DECODE_WORK, 28) == 0x7FFFFFFF
		and buffer.readu32(DECODE_WORK, 0) >= 0xFFFFFFED
		and bit32.band(
			buffer.readu32(DECODE_WORK, 4), buffer.readu32(DECODE_WORK, 8),
			buffer.readu32(DECODE_WORK, 12), buffer.readu32(DECODE_WORK, 16),
			buffer.readu32(DECODE_WORK, 20), buffer.readu32(DECODE_WORK, 24)
		) == 0xFFFFFFFF
	then
		return false
	end

	FieldPrime.DecodeInto(DECODE_WORK, SCRATCH_B)
	FieldPrime.Square(SCRATCH_B, SCRATCH_C)
	FieldPrime.Sub(SCRATCH_C, ONE, SCRATCH_D)
	FieldPrime.Mul(SCRATCH_C, CURVE_D, SCRATCH_E)
	FieldPrime.Add(SCRATCH_E, ONE, SCRATCH_E)

	if not FieldPrime.SqrtDiv(SCRATCH_D, SCRATCH_E, SCRATCH_A) then
		return false
	end

	FieldPrime.Canonicalize(SCRATCH_A, SCRATCH_C)
	local XSignBit = buffer.readf64(SCRATCH_C, 0) % 2
	if XSignBit ~= SignBit then
		if FieldPrime.Eqz(SCRATCH_C) then
			return false
		end
		FieldPrime.Neg(SCRATCH_A, SCRATCH_A)
		FieldPrime.Carry(SCRATCH_A, SCRATCH_A)
	end

	FieldPrime.Mul(SCRATCH_A, SCRATCH_B, SCRATCH_D)
	buffer.copy(OutPoint, 0, SCRATCH_A, 0, COORD_SIZE)
	buffer.copy(OutPoint, COORD_SIZE, SCRATCH_B, 0, COORD_SIZE)
	buffer.copy(OutPoint, 2 * COORD_SIZE, ONE, 0, COORD_SIZE)
	buffer.copy(OutPoint, 3 * COORD_SIZE, SCRATCH_D, 0, COORD_SIZE)
	return true
end

local function GetBaseTable(): buffer
	local Cached = AFFINE_BASEPOINT_TABLE
	if Cached then
		return Cached
	end

	local MaxWindows = 43
	local Count = MaxWindows * BASE_POINT_ROW
	local Points = buffer.create(Count * POINT_SIZE)
	local Current = buffer.create(POINT_SIZE)
	local Working = buffer.create(POINT_SIZE)
	local Step = buffer.create(POINT_SIZE)
	buffer.copy(Current, 0, BASEPOINT_G, 0, POINT_SIZE)

	for WindowIndex = 0, MaxWindows - 1 do
		local Base = WindowIndex * BASE_POINT_ROW * POINT_SIZE
		buffer.copy(Points, Base, Current, 0, POINT_SIZE)
		buffer.copy(Working, 0, Current, 0, POINT_SIZE)
		Edwards25519.NielsInto(Current, Step, 0)

		for Multiple = 1, BASE_POINT_ROW - 1 do
			AddInPlace(Working, Step, 0, 104, 312, 208, 1, true)
			buffer.copy(Points, Base + Multiple * POINT_SIZE, Working, 0, POINT_SIZE)
		end

		for _ = 1, BASE_RADIX_WIDTH do
			Edwards25519.DoubleInPlace(Current, true)
		end
	end

	local Mul = FieldPrime.Mul
	local Prefix = buffer.create(Count * COORD_SIZE)
	buffer.copy(Prefix, 0, Points, 2 * COORD_SIZE, COORD_SIZE)
	for Index = 1, Count - 1 do
		buffer.copy(SCRATCH_A, 0, Prefix, (Index - 1) * COORD_SIZE, COORD_SIZE)
		buffer.copy(SCRATCH_B, 0, Points, Index * POINT_SIZE + 2 * COORD_SIZE, COORD_SIZE)
		Mul(SCRATCH_A, SCRATCH_B, SCRATCH_C)
		buffer.copy(Prefix, Index * COORD_SIZE, SCRATCH_C, 0, COORD_SIZE)
	end

	buffer.copy(SCRATCH_A, 0, Prefix, (Count - 1) * COORD_SIZE, COORD_SIZE)
	local Inverse = FieldPrime.Invert(SCRATCH_A)
	local TableData = buffer.create(Count * AFFINE_NIELS_SIZE)

	for Index = Count - 1, 0, -1 do
		local PointOffset = Index * POINT_SIZE
		if Index > 0 then
			buffer.copy(SCRATCH_A, 0, Prefix, (Index - 1) * COORD_SIZE, COORD_SIZE)
			Mul(Inverse, SCRATCH_A, SCRATCH_C)
			buffer.copy(SCRATCH_B, 0, Points, PointOffset + 2 * COORD_SIZE, COORD_SIZE)
			Mul(Inverse, SCRATCH_B, Inverse)
		else
			buffer.copy(SCRATCH_C, 0, Inverse, 0, COORD_SIZE)
		end

		buffer.copy(SCRATCH_A, 0, Points, PointOffset, COORD_SIZE)
		buffer.copy(SCRATCH_B, 0, Points, PointOffset + COORD_SIZE, COORD_SIZE)
		Mul(SCRATCH_A, SCRATCH_C, SCRATCH_A)
		Mul(SCRATCH_B, SCRATCH_C, SCRATCH_B)
		Mul(SCRATCH_A, SCRATCH_B, SCRATCH_D)
		Mul(SCRATCH_D, CURVE_K, SCRATCH_D)

		local Offset = Index * AFFINE_NIELS_SIZE
		FieldPrime.Add(SCRATCH_B, SCRATCH_A, SCRATCH_E)
		buffer.copy(TableData, Offset, SCRATCH_E, 0, COORD_SIZE)
		FieldPrime.Sub(SCRATCH_B, SCRATCH_A, SCRATCH_E)
		buffer.copy(TableData, Offset + COORD_SIZE, SCRATCH_E, 0, COORD_SIZE)
		buffer.copy(TableData, Offset + 2 * COORD_SIZE, SCRATCH_D, 0, COORD_SIZE)
	end

	AFFINE_BASEPOINT_TABLE = TableData
	return TableData
end

@native
function Edwards25519.MulGBytes(Scalar32: buffer, OutPoint: buffer, Public: boolean): ()
	local AffineTable = GetBaseTable()
	buffer.copy(OutPoint, 0, IDENTITY_O, 0, POINT_SIZE)
	local DummyPoint = MULG_DUMMY
	if not Public then
		buffer.copy(DummyPoint, 0, IDENTITY_O, 0, POINT_SIZE)
	end

	local Carry = 0
	for WindowIndex = 0, 42 do
		local BitPos = WindowIndex * 6
		local BytePos = bit32.rshift(BitPos, 3)
		local BitOff = bit32.band(BitPos, 7)
		local Bits: number
		if BytePos <= 30 then
			Bits = bit32.band(bit32.rshift(buffer.readu16(Scalar32, BytePos), BitOff), 63)
		elseif BytePos == 31 then
			Bits = bit32.rshift(buffer.readu8(Scalar32, 31), BitOff)
		else
			Bits = 0
		end
		local Digit = Bits + Carry
		if Digit >= 32 then
			Digit -= 64
			Carry = 1
		else
			Carry = 0
		end

		local BaseOffset = WindowIndex * BASE_POINT_ROW * AFFINE_NIELS_SIZE
		local NeedT = WindowIndex < 42 or Public
		if Digit > 0 then
			AddInPlace(OutPoint, AffineTable, BaseOffset + (Digit - 1) * AFFINE_NIELS_SIZE, BaseOffset + (Digit - 1) * AFFINE_NIELS_SIZE + 104, BaseOffset + (Digit - 1) * AFFINE_NIELS_SIZE + 208, -1, 1, NeedT)
		elseif Digit < 0 then
			local Idx = (-Digit - 1) * AFFINE_NIELS_SIZE + BaseOffset
			AddInPlace(OutPoint, AffineTable, Idx + 104, Idx, Idx + 208, -1, -1, NeedT)
		elseif not Public then
			AddInPlace(DummyPoint, AffineTable, BaseOffset, BaseOffset + 104, BaseOffset + 208, -1, 1, NeedT)
		end
	end
end

function Edwards25519.WindowedNAFTable(BasePoint: buffer, WindowWidth: number, Storage: buffer?): buffer
	local MaxOddMultiples = bit32.lshift(1, WindowWidth - 1)
	local TableData = Storage or buffer.create(MaxOddMultiples * POINT_SIZE)

	buffer.copy(NAF_WORK, 0, BasePoint, 0, POINT_SIZE)
	Edwards25519.DoubleInPlace(NAF_WORK, true)
	Edwards25519.NielsInto(NAF_WORK, NAF_STEP, 0)

	buffer.copy(NAF_WORK, 0, BasePoint, 0, POINT_SIZE)
	Edwards25519.NielsInto(NAF_WORK, TableData, 0)

	for OddMultiple = 3, MaxOddMultiples, 2 do
		AddInPlace(NAF_WORK, NAF_STEP, 0, 104, 312, 208, 1, true)
		Edwards25519.NielsInto(NAF_WORK, TableData, (OddMultiple - 1) * POINT_SIZE)
	end

	return TableData
end

@native
local function PackedNaf(Packed: buffer, Base: number, WindowWidth: number, BitCount: number, Digits: buffer): number
	buffer.fill(Digits, 0, 0)
	local Mask = bit32.lshift(1, WindowWidth) - 1
	local WindowVal = bit32.lshift(1, WindowWidth)
	local Carry = 0
	local Position = 0
	local Top = 0

	while Position < BitCount do
		local Window = bit32.rshift(buffer.readu32(Packed, Base + bit32.rshift(Position, 3)), bit32.band(Position, 7))
		if bit32.band(Window, 1) == Carry then
			Position += 1
		else
			local Word = bit32.band(Window, Mask) + Carry
			Carry = bit32.rshift(Word, WindowWidth - 1)
			buffer.writei8(Digits, Position, Word - Carry * WindowVal)
			Top = Position + 1
			Position += WindowWidth
		end
	end

	if Carry ~= 0 then
		buffer.writei8(Digits, Position, 1)
		Top = Position + 1
	end

	return Top
end

@native
function Edwards25519.MulDoubleWithTables(
	TableP: buffer,
	WidthP: number,
	BaseP: number,
	TableQ: buffer,
	WidthQ: number,
	BaseQ: number,
	Packed: buffer,
	BitCount: number,
	NegateQ: boolean,
	OutPoint: buffer
): ()
	local DigitsP = JOINT_DIGITS_P
	local DigitsQ = JOINT_DIGITS_Q
	local Top = math.max(PackedNaf(Packed, BaseP, WidthP, BitCount, DigitsP), PackedNaf(Packed, BaseQ, WidthQ, BitCount, DigitsQ))
	local SignQ = if NegateQ then -1 else 1

	buffer.copy(OutPoint, 0, IDENTITY_O, 0, POINT_SIZE)

	for Position = Top - 1, 0, -1 do
		local DigitP = buffer.readi8(DigitsP, Position)
		local DigitQ = buffer.readi8(DigitsQ, Position) * SignQ
		local IsLast = Position == 0

		Edwards25519.DoubleInPlace(OutPoint, DigitP ~= 0 or DigitQ ~= 0 or IsLast)

		if DigitP ~= 0 then
			local NeedT = DigitQ ~= 0 or IsLast
			if DigitP > 0 then
				local Off = (DigitP - 1) * POINT_SIZE
				AddInPlace(OutPoint, TableP, Off, Off + 104, Off + 312, Off + 208, 1, NeedT)
			else
				local Off = (-DigitP - 1) * POINT_SIZE
				AddInPlace(OutPoint, TableP, Off + 104, Off, Off + 312, Off + 208, -1, NeedT)
			end
		end

		if DigitQ ~= 0 then
			if DigitQ > 0 then
				local Off = (DigitQ - 1) * POINT_SIZE
				AddInPlace(OutPoint, TableQ, Off, Off + 104, Off + 312, Off + 208, 1, IsLast)
			else
				local Off = (-DigitQ - 1) * POINT_SIZE
				AddInPlace(OutPoint, TableQ, Off + 104, Off, Off + 312, Off + 208, -1, IsLast)
			end
		end
	end
end

function Edwards25519.ClearCaches(): ()
	buffer.fill(MULG_DUMMY, 0, 0)
	buffer.fill(NAF_WORK, 0, 0)
	buffer.fill(NAF_STEP, 0, 0)
	buffer.fill(JOINT_DIGITS_P, 0, 0)
	buffer.fill(JOINT_DIGITS_Q, 0, 0)
	buffer.fill(SCRATCH_A, 0, 0)
	buffer.fill(SCRATCH_B, 0, 0)
	buffer.fill(SCRATCH_C, 0, 0)
	buffer.fill(SCRATCH_D, 0, 0)
	buffer.fill(SCRATCH_E, 0, 0)
	buffer.fill(DECODE_WORK, 0, 0)
end

return Edwards25519
