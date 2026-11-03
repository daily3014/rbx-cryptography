--[=[
	Cryptography library: Edwards25519

	Return type: varies by function
	Example usage:
		--------Usage Case 1: Point addition--------
		local Point1 = Edwards.Decode(SomeEncodedBuffer)
		local Point2 = Edwards.Decode(AnotherEncodedBuffer)
		local NielsPoint2 = Edwards.Niels(Point2)
		local Sum = Edwards.Add(Point1, NielsPoint2)

		--------Usage Case 2: Scalar multiplication with buffer-based bits--------
		local SomeScalar = FieldQuadratic.Decode(ScalarBytes)
		local ScalarBits, BitCount = FieldQuadratic.Bits(SomeScalar)
		local Result = Edwards.MulG(ScalarBits, BitCount)
		local EncodedResult = Edwards.Encode(Result)
--]=]

--!strict
--!optimize 2
--!native

local FieldPrime = require("./FieldPrime")

local POINT_SIZE = 416
local COORD_SIZE = 104
local AFFINE_NIELS_SIZE = 312
local BASE_RADIX_WIDTH = 6
local BASE_POINT_ROW = 2 ^ BASE_RADIX_WIDTH / 2

local CURVE_D = FieldPrime.Mul(FieldPrime.Num(-121665), FieldPrime.Invert(FieldPrime.Num(121666)))
local CURVE_K = FieldPrime.KMul(CURVE_D, 2)

local IDENTITY_O = buffer.create(POINT_SIZE) do
	buffer.copy(IDENTITY_O, 0, FieldPrime.Num(0), 0, COORD_SIZE)
	buffer.copy(IDENTITY_O, COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)
	buffer.copy(IDENTITY_O, 2 * COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)
	buffer.copy(IDENTITY_O, 3 * COORD_SIZE, FieldPrime.Num(0), 0, COORD_SIZE)
end

local COORD_BUFFER_0 = buffer.create(COORD_SIZE)
local COORD_BUFFER_1 = buffer.create(COORD_SIZE)
local COORD_BUFFER_2 = buffer.create(COORD_SIZE)
local COORD_BUFFER_3 = buffer.create(COORD_SIZE)
local COORD_BUFFER_4 = buffer.create(COORD_SIZE)
local COORD_BUFFER_5 = buffer.create(COORD_SIZE)
local COORD_BUFFER_6 = buffer.create(COORD_SIZE)
local COORD_BUFFER_7 = buffer.create(COORD_SIZE)

local MUL_RESULT_POINT = buffer.create(POINT_SIZE)

local MULG_RESULT_POINT = buffer.create(POINT_SIZE)
local MULG_DUMMY_POINT = buffer.create(POINT_SIZE)

local NAF_TABLE_DOUBLED = buffer.create(POINT_SIZE)
local NAF_TABLE_P1X = buffer.create(COORD_SIZE)
local NAF_TABLE_P1Y = buffer.create(COORD_SIZE)
local NAF_TABLE_P1Z = buffer.create(COORD_SIZE)
local NAF_TABLE_P1T = buffer.create(COORD_SIZE)
local NAF_TABLE_N2P = buffer.create(COORD_SIZE)
local NAF_TABLE_N2M = buffer.create(COORD_SIZE)
local NAF_TABLE_N2Z = buffer.create(COORD_SIZE)
local NAF_TABLE_N2T = buffer.create(COORD_SIZE)
local NAF_TABLE_TMP = buffer.create(COORD_SIZE)
local NAF_TABLE_DBL_P = buffer.create(COORD_SIZE)
local NAF_TABLE_DBL_M = buffer.create(COORD_SIZE)
local NAF_TABLE_DBL_Z = buffer.create(COORD_SIZE)
local NAF_TABLE_DBL_T = buffer.create(COORD_SIZE)

local NAF_OUTPUT = buffer.create(512 * 8)
local RADIX_OUTPUT = buffer.create(272 * 8)

local BASEPONT_G: buffer? = nil
local AFFINE_BASEPOINT_TABLE: buffer? = nil

local function GetCoord(Point: buffer, Index: number, Storage: buffer?): buffer
	local Coord = Storage or buffer.create(COORD_SIZE)
	buffer.copy(Coord, 0, Point, Index * COORD_SIZE, COORD_SIZE)
	return Coord
end

local Edwards25519 = {}

local function FieldMul(A00: number, A01: number, A02: number, A03: number, A04: number, A05: number, A06: number, A07: number, A08: number, A09: number, A10: number, A11: number, B00: number, B01: number, B02: number, B03: number, B04: number, B05: number, B06: number, B07: number, B08: number, B09: number, B10: number, B11: number): (number, number, number, number, number, number, number, number, number, number, number, number)
	local R00, R01, R02, R03, R04, R05, R06, R07, R08, R09, R10, R11
	do
		local c00 = (A01 * B11 + A02 * B10 + A03 * B09 + A04 * B08 + A05 * B07 + A06 * B06 + A07 * B05 + A08 * B04 + A09 * B03 + A10 * B02 + A11 * B01) * (19 / 2 ^ 255) + (A00 * B00)
		local c01 = (A02 * B11 + A03 * B10 + A04 * B09 + A05 * B08 + A06 * B07 + A07 * B06 + A08 * B05 + A09 * B04 + A10 * B03 + A11 * B02) * (19 / 2 ^ 255) + (A00 * B01 + A01 * B00)
		local c02 = (A03 * B11 + A04 * B10 + A05 * B09 + A06 * B08 + A07 * B07 + A08 * B06 + A09 * B05 + A10 * B04 + A11 * B03) * (19 / 2 ^ 255) + (A00 * B02 + A01 * B01 + A02 * B00)
		local c03 = (A04 * B11 + A05 * B10 + A06 * B09 + A07 * B08 + A08 * B07 + A09 * B06 + A10 * B05 + A11 * B04) * (19 / 2 ^ 255) + (A00 * B03 + A01 * B02 + A02 * B01 + A03 * B00)
		local c04 = (A05 * B11 + A06 * B10 + A07 * B09 + A08 * B08 + A09 * B07 + A10 * B06 + A11 * B05) * (19 / 2 ^ 255) + (A00 * B04 + A01 * B03 + A02 * B02 + A03 * B01 + A04 * B00)
		local c05 = (A06 * B11 + A07 * B10 + A08 * B09 + A09 * B08 + A10 * B07 + A11 * B06) * (19 / 2 ^ 255) + (A00 * B05 + A01 * B04 + A02 * B03 + A03 * B02 + A04 * B01 + A05 * B00)
		local c06 = (A07 * B11 + A08 * B10 + A09 * B09 + A10 * B08 + A11 * B07) * (19 / 2 ^ 255) + (A00 * B06 + A01 * B05 + A02 * B04 + A03 * B03 + A04 * B02 + A05 * B01 + A06 * B00)
		local c07 = (A08 * B11 + A09 * B10 + A10 * B09 + A11 * B08) * (19 / 2 ^ 255) + (A00 * B07 + A01 * B06 + A02 * B05 + A03 * B04 + A04 * B03 + A05 * B02 + A06 * B01 + A07 * B00)
		local c08 = (A09 * B11 + A10 * B10 + A11 * B09) * (19 / 2 ^ 255) + (A00 * B08 + A01 * B07 + A02 * B06 + A03 * B05 + A04 * B04 + A05 * B03 + A06 * B02 + A07 * B01 + A08 * B00)
		local c09 = (A10 * B11 + A11 * B10) * (19 / 2 ^ 255) + (A00 * B09 + A01 * B08 + A02 * B07 + A03 * B06 + A04 * B05 + A05 * B04 + A06 * B03 + A07 * B02 + A08 * B01 + A09 * B00)
		local c10 = (A11 * B11) * (19 / 2 ^ 255) + (A00 * B10 + A01 * B09 + A02 * B08 + A03 * B07 + A04 * B06 + A05 * B05 + A06 * B04 + A07 * B03 + A08 * B02 + A09 * B01 + A10 * B00)
		local c11 = A00 * B11 + A01 * B10 + A02 * B09 + A03 * B08 + A04 * B07 + A05 * B06 + A06 * B05 + A07 * B04 + A08 * B03 + A09 * B02 + A10 * B01 + A11 * B00
		local k00 = c00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
		local k01 = c01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
		local k02 = c02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
		local k03 = c03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
		local k04 = c04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
		local k05 = c05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
		local k06 = c06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
		local k07 = c07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
		local k08 = c08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
		local k09 = c09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
		local k10 = c10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
		local k11 = c11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
		local b00 = (c00 - k00) + k11 * (19 / 2 ^ 255)
		local b01 = (c01 - k01) + k00
		local b02 = (c02 - k02) + k01
		local b03 = (c03 - k03) + k02
		local b04 = (c04 - k04) + k03
		local b05 = (c05 - k05) + k04
		local b06 = (c06 - k06) + k05
		local b07 = (c07 - k07) + k06
		local b08 = (c08 - k08) + k07
		local b09 = (c09 - k09) + k08
		local b10 = (c10 - k10) + k09
		local b11 = (c11 - k11) + k10
		local j00 = b00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
		local j01 = b01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
		local j02 = b02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
		local j03 = b03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
		local j04 = b04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
		local j05 = b05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
		local j06 = b06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
		local j07 = b07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
		local j08 = b08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
		local j09 = b09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
		local j10 = b10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
		local j11 = b11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
		R00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		R01 = (b01 - j01) + j00
		R02 = (b02 - j02) + j01
		R03 = (b03 - j03) + j02
		R04 = (b04 - j04) + j03
		R05 = (b05 - j05) + j04
		R06 = (b06 - j06) + j05
		R07 = (b07 - j07) + j06
		R08 = (b08 - j08) + j07
		R09 = (b09 - j09) + j08
		R10 = (b10 - j10) + j09
		R11 = (b11 - j11) + j10
	end
	return R00, R01, R02, R03, R04, R05, R06, R07, R08, R09, R10, R11
end

local function FieldSquare(A00: number, A01: number, A02: number, A03: number, A04: number, A05: number, A06: number, A07: number, A08: number, A09: number, A10: number, A11: number): (number, number, number, number, number, number, number, number, number, number, number, number)
	local R00, R01, R02, R03, R04, R05, R06, R07, R08, R09, R10, R11
	do
		local d00 = A00 * 2
		local d01 = A01 * 2
		local d02 = A02 * 2
		local d03 = A03 * 2
		local d04 = A04 * 2
		local d05 = A05 * 2
		local d06 = A06 * 2
		local d07 = A07 * 2
		local d08 = A08 * 2
		local d09 = A09 * 2
		local d10 = A10 * 2
		local c00 = (A11 * d01 + A10 * d02 + A09 * d03 + A08 * d04 + A07 * d05 + A06 * A06) * (19 / 2 ^ 255) + (A00 * A00)
		local c01 = (A11 * d02 + A10 * d03 + A09 * d04 + A08 * d05 + A07 * d06) * (19 / 2 ^ 255) + (A01 * d00)
		local c02 = (A11 * d03 + A10 * d04 + A09 * d05 + A08 * d06 + A07 * A07) * (19 / 2 ^ 255) + (A02 * d00 + A01 * A01)
		local c03 = (A11 * d04 + A10 * d05 + A09 * d06 + A08 * d07) * (19 / 2 ^ 255) + (A03 * d00 + A02 * d01)
		local c04 = (A11 * d05 + A10 * d06 + A09 * d07 + A08 * A08) * (19 / 2 ^ 255) + (A04 * d00 + A03 * d01 + A02 * A02)
		local c05 = (A11 * d06 + A10 * d07 + A09 * d08) * (19 / 2 ^ 255) + (A05 * d00 + A04 * d01 + A03 * d02)
		local c06 = (A11 * d07 + A10 * d08 + A09 * A09) * (19 / 2 ^ 255) + (A06 * d00 + A05 * d01 + A04 * d02 + A03 * A03)
		local c07 = (A11 * d08 + A10 * d09) * (19 / 2 ^ 255) + (A07 * d00 + A06 * d01 + A05 * d02 + A04 * d03)
		local c08 = (A11 * d09 + A10 * A10) * (19 / 2 ^ 255) + (A08 * d00 + A07 * d01 + A06 * d02 + A05 * d03 + A04 * A04)
		local c09 = (A11 * d10) * (19 / 2 ^ 255) + (A09 * d00 + A08 * d01 + A07 * d02 + A06 * d03 + A05 * d04)
		local c10 = (A11 * A11) * (19 / 2 ^ 255) + (A10 * d00 + A09 * d01 + A08 * d02 + A07 * d03 + A06 * d04 + A05 * A05)
		local c11 = A11 * d00 + A10 * d01 + A09 * d02 + A08 * d03 + A07 * d04 + A06 * d05
		local k00 = c00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
		local k01 = c01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
		local k02 = c02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
		local k03 = c03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
		local k04 = c04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
		local k05 = c05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
		local k06 = c06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
		local k07 = c07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
		local k08 = c08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
		local k09 = c09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
		local k10 = c10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
		local k11 = c11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
		local b00 = (c00 - k00) + k11 * (19 / 2 ^ 255)
		local b01 = (c01 - k01) + k00
		local b02 = (c02 - k02) + k01
		local b03 = (c03 - k03) + k02
		local b04 = (c04 - k04) + k03
		local b05 = (c05 - k05) + k04
		local b06 = (c06 - k06) + k05
		local b07 = (c07 - k07) + k06
		local b08 = (c08 - k08) + k07
		local b09 = (c09 - k09) + k08
		local b10 = (c10 - k10) + k09
		local b11 = (c11 - k11) + k10
		local j00 = b00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
		local j01 = b01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
		local j02 = b02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
		local j03 = b03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
		local j04 = b04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
		local j05 = b05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
		local j06 = b06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
		local j07 = b07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
		local j08 = b08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
		local j09 = b09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
		local j10 = b10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
		local j11 = b11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
		R00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		R01 = (b01 - j01) + j00
		R02 = (b02 - j02) + j01
		R03 = (b03 - j03) + j02
		R04 = (b04 - j04) + j03
		R05 = (b05 - j05) + j04
		R06 = (b06 - j06) + j05
		R07 = (b07 - j07) + j06
		R08 = (b08 - j08) + j07
		R09 = (b09 - j09) + j08
		R10 = (b10 - j10) + j09
		R11 = (b11 - j11) + j10
	end
	return R00, R01, R02, R03, R04, R05, R06, R07, R08, R09, R10, R11
end

function Edwards25519.DoubleInPlace(Point: buffer, WithT: boolean)
	local X00 = buffer.readf64(Point, 0 + 0)
	local X01 = buffer.readf64(Point, 0 + 8)
	local X02 = buffer.readf64(Point, 0 + 16)
	local X03 = buffer.readf64(Point, 0 + 24)
	local X04 = buffer.readf64(Point, 0 + 32)
	local X05 = buffer.readf64(Point, 0 + 40)
	local X06 = buffer.readf64(Point, 0 + 48)
	local X07 = buffer.readf64(Point, 0 + 56)
	local X08 = buffer.readf64(Point, 0 + 64)
	local X09 = buffer.readf64(Point, 0 + 72)
	local X10 = buffer.readf64(Point, 0 + 80)
	local X11 = buffer.readf64(Point, 0 + 88)
	local Y00 = buffer.readf64(Point, 104 + 0)
	local Y01 = buffer.readf64(Point, 104 + 8)
	local Y02 = buffer.readf64(Point, 104 + 16)
	local Y03 = buffer.readf64(Point, 104 + 24)
	local Y04 = buffer.readf64(Point, 104 + 32)
	local Y05 = buffer.readf64(Point, 104 + 40)
	local Y06 = buffer.readf64(Point, 104 + 48)
	local Y07 = buffer.readf64(Point, 104 + 56)
	local Y08 = buffer.readf64(Point, 104 + 64)
	local Y09 = buffer.readf64(Point, 104 + 72)
	local Y10 = buffer.readf64(Point, 104 + 80)
	local Y11 = buffer.readf64(Point, 104 + 88)
	local Z00 = buffer.readf64(Point, 208 + 0)
	local Z01 = buffer.readf64(Point, 208 + 8)
	local Z02 = buffer.readf64(Point, 208 + 16)
	local Z03 = buffer.readf64(Point, 208 + 24)
	local Z04 = buffer.readf64(Point, 208 + 32)
	local Z05 = buffer.readf64(Point, 208 + 40)
	local Z06 = buffer.readf64(Point, 208 + 48)
	local Z07 = buffer.readf64(Point, 208 + 56)
	local Z08 = buffer.readf64(Point, 208 + 64)
	local Z09 = buffer.readf64(Point, 208 + 72)
	local Z10 = buffer.readf64(Point, 208 + 80)
	local Z11 = buffer.readf64(Point, 208 + 88)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 = FieldSquare(X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11)
	if not Point then return end
	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11 = FieldSquare(Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11)
	if not Point then return end
	Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11 = FieldSquare(Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11)
	if not Point then return end
	Z00 = Z00 + Z00
	Z01 = Z01 + Z01
	Z02 = Z02 + Z02
	Z03 = Z03 + Z03
	Z04 = Z04 + Z04
	Z05 = Z05 + Z05
	Z06 = Z06 + Z06
	Z07 = Z07 + Z07
	Z08 = Z08 + Z08
	Z09 = Z09 + Z09
	Z10 = Z10 + Z10
	Z11 = Z11 + Z11
	X00 = X00 + Y00
	X01 = X01 + Y01
	X02 = X02 + Y02
	X03 = X03 + Y03
	X04 = X04 + Y04
	X05 = X05 + Y05
	X06 = X06 + Y06
	X07 = X07 + Y07
	X08 = X08 + Y08
	X09 = X09 + Y09
	X10 = X10 + Y10
	X11 = X11 + Y11
	Y00 = A00 + B00
	Y01 = A01 + B01
	Y02 = A02 + B02
	Y03 = A03 + B03
	Y04 = A04 + B04
	Y05 = A05 + B05
	Y06 = A06 + B06
	Y07 = A07 + B07
	Y08 = A08 + B08
	Y09 = A09 + B09
	Y10 = A10 + B10
	Y11 = A11 + B11
	X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11 = FieldSquare(X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11)
	if not Point then return end
	X00 = X00 - Y00
	X01 = X01 - Y01
	X02 = X02 - Y02
	X03 = X03 - Y03
	X04 = X04 - Y04
	X05 = X05 - Y05
	X06 = X06 - Y06
	X07 = X07 - Y07
	X08 = X08 - Y08
	X09 = X09 - Y09
	X10 = X10 - Y10
	X11 = X11 - Y11
	do
		local k00 = X00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
		local k01 = X01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
		local k02 = X02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
		local k03 = X03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
		local k04 = X04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
		local k05 = X05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
		local k06 = X06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
		local k07 = X07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
		local k08 = X08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
		local k09 = X09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
		local k10 = X10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
		local k11 = X11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
		local b00 = (X00 - k00) + k11 * (19 / 2 ^ 255)
		local b01 = (X01 - k01) + k00
		local b02 = (X02 - k02) + k01
		local b03 = (X03 - k03) + k02
		local b04 = (X04 - k04) + k03
		local b05 = (X05 - k05) + k04
		local b06 = (X06 - k06) + k05
		local b07 = (X07 - k07) + k06
		local b08 = (X08 - k08) + k07
		local b09 = (X09 - k09) + k08
		local b10 = (X10 - k10) + k09
		local b11 = (X11 - k11) + k10
		local j00 = b00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
		local j01 = b01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
		local j02 = b02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
		local j03 = b03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
		local j04 = b04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
		local j05 = b05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
		local j06 = b06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
		local j07 = b07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
		local j08 = b08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
		local j09 = b09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
		local j10 = b10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
		local j11 = b11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
		X00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		X01 = (b01 - j01) + j00
		X02 = (b02 - j02) + j01
		X03 = (b03 - j03) + j02
		X04 = (b04 - j04) + j03
		X05 = (b05 - j05) + j04
		X06 = (b06 - j06) + j05
		X07 = (b07 - j07) + j06
		X08 = (b08 - j08) + j07
		X09 = (b09 - j09) + j08
		X10 = (b10 - j10) + j09
		X11 = (b11 - j11) + j10
	end
	B00 = B00 - A00
	B01 = B01 - A01
	B02 = B02 - A02
	B03 = B03 - A03
	B04 = B04 - A04
	B05 = B05 - A05
	B06 = B06 - A06
	B07 = B07 - A07
	B08 = B08 - A08
	B09 = B09 - A09
	B10 = B10 - A10
	B11 = B11 - A11
	Z00 = Z00 - B00
	Z01 = Z01 - B01
	Z02 = Z02 - B02
	Z03 = Z03 - B03
	Z04 = Z04 - B04
	Z05 = Z05 - B05
	Z06 = Z06 - B06
	Z07 = Z07 - B07
	Z08 = Z08 - B08
	Z09 = Z09 - B09
	Z10 = Z10 - B10
	Z11 = Z11 - B11
	do
		local k00 = Z00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
		local k01 = Z01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
		local k02 = Z02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
		local k03 = Z03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
		local k04 = Z04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
		local k05 = Z05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
		local k06 = Z06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
		local k07 = Z07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
		local k08 = Z08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
		local k09 = Z09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
		local k10 = Z10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
		local k11 = Z11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
		local b00 = (Z00 - k00) + k11 * (19 / 2 ^ 255)
		local b01 = (Z01 - k01) + k00
		local b02 = (Z02 - k02) + k01
		local b03 = (Z03 - k03) + k02
		local b04 = (Z04 - k04) + k03
		local b05 = (Z05 - k05) + k04
		local b06 = (Z06 - k06) + k05
		local b07 = (Z07 - k07) + k06
		local b08 = (Z08 - k08) + k07
		local b09 = (Z09 - k09) + k08
		local b10 = (Z10 - k10) + k09
		local b11 = (Z11 - k11) + k10
		local j00 = b00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
		local j01 = b01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
		local j02 = b02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
		local j03 = b03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
		local j04 = b04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
		local j05 = b05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
		local j06 = b06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
		local j07 = b07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
		local j08 = b08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
		local j09 = b09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
		local j10 = b10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
		local j11 = b11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
		Z00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		Z01 = (b01 - j01) + j00
		Z02 = (b02 - j02) + j01
		Z03 = (b03 - j03) + j02
		Z04 = (b04 - j04) + j03
		Z05 = (b05 - j05) + j04
		Z06 = (b06 - j06) + j05
		Z07 = (b07 - j07) + j06
		Z08 = (b08 - j08) + j07
		Z09 = (b09 - j09) + j08
		Z10 = (b10 - j10) + j09
		Z11 = (b11 - j11) + j10
	end
	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11)
		buffer.writef64(Point, 0 + 0, O00)
		buffer.writef64(Point, 0 + 8, O01)
		buffer.writef64(Point, 0 + 16, O02)
		buffer.writef64(Point, 0 + 24, O03)
		buffer.writef64(Point, 0 + 32, O04)
		buffer.writef64(Point, 0 + 40, O05)
		buffer.writef64(Point, 0 + 48, O06)
		buffer.writef64(Point, 0 + 56, O07)
		buffer.writef64(Point, 0 + 64, O08)
		buffer.writef64(Point, 0 + 72, O09)
		buffer.writef64(Point, 0 + 80, O10)
		buffer.writef64(Point, 0 + 88, O11)
	end
	if not Point then return end
	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11, Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11)
		buffer.writef64(Point, 104 + 0, O00)
		buffer.writef64(Point, 104 + 8, O01)
		buffer.writef64(Point, 104 + 16, O02)
		buffer.writef64(Point, 104 + 24, O03)
		buffer.writef64(Point, 104 + 32, O04)
		buffer.writef64(Point, 104 + 40, O05)
		buffer.writef64(Point, 104 + 48, O06)
		buffer.writef64(Point, 104 + 56, O07)
		buffer.writef64(Point, 104 + 64, O08)
		buffer.writef64(Point, 104 + 72, O09)
		buffer.writef64(Point, 104 + 80, O10)
		buffer.writef64(Point, 104 + 88, O11)
	end
	if not Point then return end
	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11, B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11)
		buffer.writef64(Point, 208 + 0, O00)
		buffer.writef64(Point, 208 + 8, O01)
		buffer.writef64(Point, 208 + 16, O02)
		buffer.writef64(Point, 208 + 24, O03)
		buffer.writef64(Point, 208 + 32, O04)
		buffer.writef64(Point, 208 + 40, O05)
		buffer.writef64(Point, 208 + 48, O06)
		buffer.writef64(Point, 208 + 56, O07)
		buffer.writef64(Point, 208 + 64, O08)
		buffer.writef64(Point, 208 + 72, O09)
		buffer.writef64(Point, 208 + 80, O10)
		buffer.writef64(Point, 208 + 88, O11)
	end
	if not Point then return end
	if WithT then
		do
			local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11)
			buffer.writef64(Point, 312 + 0, O00)
			buffer.writef64(Point, 312 + 8, O01)
			buffer.writef64(Point, 312 + 16, O02)
			buffer.writef64(Point, 312 + 24, O03)
			buffer.writef64(Point, 312 + 32, O04)
			buffer.writef64(Point, 312 + 40, O05)
			buffer.writef64(Point, 312 + 48, O06)
			buffer.writef64(Point, 312 + 56, O07)
			buffer.writef64(Point, 312 + 64, O08)
			buffer.writef64(Point, 312 + 72, O09)
			buffer.writef64(Point, 312 + 80, O10)
			buffer.writef64(Point, 312 + 88, O11)
		end
		if not Point then return end
	end
end

function Edwards25519.AddInPlace(Point: buffer, Table: buffer, PlusOffset: number, MinusOffset: number, TOffset: number, ZOffset: number, Sign: number)
	local X00 = buffer.readf64(Point, 0 + 0)
	local X01 = buffer.readf64(Point, 0 + 8)
	local X02 = buffer.readf64(Point, 0 + 16)
	local X03 = buffer.readf64(Point, 0 + 24)
	local X04 = buffer.readf64(Point, 0 + 32)
	local X05 = buffer.readf64(Point, 0 + 40)
	local X06 = buffer.readf64(Point, 0 + 48)
	local X07 = buffer.readf64(Point, 0 + 56)
	local X08 = buffer.readf64(Point, 0 + 64)
	local X09 = buffer.readf64(Point, 0 + 72)
	local X10 = buffer.readf64(Point, 0 + 80)
	local X11 = buffer.readf64(Point, 0 + 88)
	local Y00 = buffer.readf64(Point, 104 + 0)
	local Y01 = buffer.readf64(Point, 104 + 8)
	local Y02 = buffer.readf64(Point, 104 + 16)
	local Y03 = buffer.readf64(Point, 104 + 24)
	local Y04 = buffer.readf64(Point, 104 + 32)
	local Y05 = buffer.readf64(Point, 104 + 40)
	local Y06 = buffer.readf64(Point, 104 + 48)
	local Y07 = buffer.readf64(Point, 104 + 56)
	local Y08 = buffer.readf64(Point, 104 + 64)
	local Y09 = buffer.readf64(Point, 104 + 72)
	local Y10 = buffer.readf64(Point, 104 + 80)
	local Y11 = buffer.readf64(Point, 104 + 88)
	local Z00 = buffer.readf64(Point, 208 + 0)
	local Z01 = buffer.readf64(Point, 208 + 8)
	local Z02 = buffer.readf64(Point, 208 + 16)
	local Z03 = buffer.readf64(Point, 208 + 24)
	local Z04 = buffer.readf64(Point, 208 + 32)
	local Z05 = buffer.readf64(Point, 208 + 40)
	local Z06 = buffer.readf64(Point, 208 + 48)
	local Z07 = buffer.readf64(Point, 208 + 56)
	local Z08 = buffer.readf64(Point, 208 + 64)
	local Z09 = buffer.readf64(Point, 208 + 72)
	local Z10 = buffer.readf64(Point, 208 + 80)
	local Z11 = buffer.readf64(Point, 208 + 88)
	local T00 = buffer.readf64(Point, 312 + 0)
	local T01 = buffer.readf64(Point, 312 + 8)
	local T02 = buffer.readf64(Point, 312 + 16)
	local T03 = buffer.readf64(Point, 312 + 24)
	local T04 = buffer.readf64(Point, 312 + 32)
	local T05 = buffer.readf64(Point, 312 + 40)
	local T06 = buffer.readf64(Point, 312 + 48)
	local T07 = buffer.readf64(Point, 312 + 56)
	local T08 = buffer.readf64(Point, 312 + 64)
	local T09 = buffer.readf64(Point, 312 + 72)
	local T10 = buffer.readf64(Point, 312 + 80)
	local T11 = buffer.readf64(Point, 312 + 88)
	local A00 = Y00 - X00
	local A01 = Y01 - X01
	local A02 = Y02 - X02
	local A03 = Y03 - X03
	local A04 = Y04 - X04
	local A05 = Y05 - X05
	local A06 = Y06 - X06
	local A07 = Y07 - X07
	local A08 = Y08 - X08
	local A09 = Y09 - X09
	local A10 = Y10 - X10
	local A11 = Y11 - X11
	local N00 = buffer.readf64(Table, MinusOffset + 0)
	local N01 = buffer.readf64(Table, MinusOffset + 8)
	local N02 = buffer.readf64(Table, MinusOffset + 16)
	local N03 = buffer.readf64(Table, MinusOffset + 24)
	local N04 = buffer.readf64(Table, MinusOffset + 32)
	local N05 = buffer.readf64(Table, MinusOffset + 40)
	local N06 = buffer.readf64(Table, MinusOffset + 48)
	local N07 = buffer.readf64(Table, MinusOffset + 56)
	local N08 = buffer.readf64(Table, MinusOffset + 64)
	local N09 = buffer.readf64(Table, MinusOffset + 72)
	local N10 = buffer.readf64(Table, MinusOffset + 80)
	local N11 = buffer.readf64(Table, MinusOffset + 88)
	A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 = FieldMul(A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11, N00, N01, N02, N03, N04, N05, N06, N07, N08, N09, N10, N11)
	if PlusOffset < 0 then return end
	Y00 = Y00 + X00
	Y01 = Y01 + X01
	Y02 = Y02 + X02
	Y03 = Y03 + X03
	Y04 = Y04 + X04
	Y05 = Y05 + X05
	Y06 = Y06 + X06
	Y07 = Y07 + X07
	Y08 = Y08 + X08
	Y09 = Y09 + X09
	Y10 = Y10 + X10
	Y11 = Y11 + X11
	N00 = buffer.readf64(Table, PlusOffset + 0)
	N01 = buffer.readf64(Table, PlusOffset + 8)
	N02 = buffer.readf64(Table, PlusOffset + 16)
	N03 = buffer.readf64(Table, PlusOffset + 24)
	N04 = buffer.readf64(Table, PlusOffset + 32)
	N05 = buffer.readf64(Table, PlusOffset + 40)
	N06 = buffer.readf64(Table, PlusOffset + 48)
	N07 = buffer.readf64(Table, PlusOffset + 56)
	N08 = buffer.readf64(Table, PlusOffset + 64)
	N09 = buffer.readf64(Table, PlusOffset + 72)
	N10 = buffer.readf64(Table, PlusOffset + 80)
	N11 = buffer.readf64(Table, PlusOffset + 88)
	Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11 = FieldMul(Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11, N00, N01, N02, N03, N04, N05, N06, N07, N08, N09, N10, N11)
	if PlusOffset < 0 then return end
	N00 = buffer.readf64(Table, TOffset + 0)
	N01 = buffer.readf64(Table, TOffset + 8)
	N02 = buffer.readf64(Table, TOffset + 16)
	N03 = buffer.readf64(Table, TOffset + 24)
	N04 = buffer.readf64(Table, TOffset + 32)
	N05 = buffer.readf64(Table, TOffset + 40)
	N06 = buffer.readf64(Table, TOffset + 48)
	N07 = buffer.readf64(Table, TOffset + 56)
	N08 = buffer.readf64(Table, TOffset + 64)
	N09 = buffer.readf64(Table, TOffset + 72)
	N10 = buffer.readf64(Table, TOffset + 80)
	N11 = buffer.readf64(Table, TOffset + 88)
	T00, T01, T02, T03, T04, T05, T06, T07, T08, T09, T10, T11 = FieldMul(T00, T01, T02, T03, T04, T05, T06, T07, T08, T09, T10, T11, N00, N01, N02, N03, N04, N05, N06, N07, N08, N09, N10, N11)
	if PlusOffset < 0 then return end
	if ZOffset < 0 then
		Z00 = Z00 + Z00
		Z01 = Z01 + Z01
		Z02 = Z02 + Z02
		Z03 = Z03 + Z03
		Z04 = Z04 + Z04
		Z05 = Z05 + Z05
		Z06 = Z06 + Z06
		Z07 = Z07 + Z07
		Z08 = Z08 + Z08
		Z09 = Z09 + Z09
		Z10 = Z10 + Z10
		Z11 = Z11 + Z11
	else
		N00 = buffer.readf64(Table, ZOffset + 0)
		N01 = buffer.readf64(Table, ZOffset + 8)
		N02 = buffer.readf64(Table, ZOffset + 16)
		N03 = buffer.readf64(Table, ZOffset + 24)
		N04 = buffer.readf64(Table, ZOffset + 32)
		N05 = buffer.readf64(Table, ZOffset + 40)
		N06 = buffer.readf64(Table, ZOffset + 48)
		N07 = buffer.readf64(Table, ZOffset + 56)
		N08 = buffer.readf64(Table, ZOffset + 64)
		N09 = buffer.readf64(Table, ZOffset + 72)
		N10 = buffer.readf64(Table, ZOffset + 80)
		N11 = buffer.readf64(Table, ZOffset + 88)
		Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11 = FieldMul(Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11, N00, N01, N02, N03, N04, N05, N06, N07, N08, N09, N10, N11)
		if PlusOffset < 0 then return end
	end
	X00 = Y00 - A00
	X01 = Y01 - A01
	X02 = Y02 - A02
	X03 = Y03 - A03
	X04 = Y04 - A04
	X05 = Y05 - A05
	X06 = Y06 - A06
	X07 = Y07 - A07
	X08 = Y08 - A08
	X09 = Y09 - A09
	X10 = Y10 - A10
	X11 = Y11 - A11
	T00 = T00 * Sign
	T01 = T01 * Sign
	T02 = T02 * Sign
	T03 = T03 * Sign
	T04 = T04 * Sign
	T05 = T05 * Sign
	T06 = T06 * Sign
	T07 = T07 * Sign
	T08 = T08 * Sign
	T09 = T09 * Sign
	T10 = T10 * Sign
	T11 = T11 * Sign
	N00 = Z00 - T00
	N01 = Z01 - T01
	N02 = Z02 - T02
	N03 = Z03 - T03
	N04 = Z04 - T04
	N05 = Z05 - T05
	N06 = Z06 - T06
	N07 = Z07 - T07
	N08 = Z08 - T08
	N09 = Z09 - T09
	N10 = Z10 - T10
	N11 = Z11 - T11
	Z00 = Z00 + T00
	Z01 = Z01 + T01
	Z02 = Z02 + T02
	Z03 = Z03 + T03
	Z04 = Z04 + T04
	Z05 = Z05 + T05
	Z06 = Z06 + T06
	Z07 = Z07 + T07
	Z08 = Z08 + T08
	Z09 = Z09 + T09
	Z10 = Z10 + T10
	Z11 = Z11 + T11
	Y00 = Y00 + A00
	Y01 = Y01 + A01
	Y02 = Y02 + A02
	Y03 = Y03 + A03
	Y04 = Y04 + A04
	Y05 = Y05 + A05
	Y06 = Y06 + A06
	Y07 = Y07 + A07
	Y08 = Y08 + A08
	Y09 = Y09 + A09
	Y10 = Y10 + A10
	Y11 = Y11 + A11
	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, N00, N01, N02, N03, N04, N05, N06, N07, N08, N09, N10, N11)
		buffer.writef64(Point, 0 + 0, O00)
		buffer.writef64(Point, 0 + 8, O01)
		buffer.writef64(Point, 0 + 16, O02)
		buffer.writef64(Point, 0 + 24, O03)
		buffer.writef64(Point, 0 + 32, O04)
		buffer.writef64(Point, 0 + 40, O05)
		buffer.writef64(Point, 0 + 48, O06)
		buffer.writef64(Point, 0 + 56, O07)
		buffer.writef64(Point, 0 + 64, O08)
		buffer.writef64(Point, 0 + 72, O09)
		buffer.writef64(Point, 0 + 80, O10)
		buffer.writef64(Point, 0 + 88, O11)
	end
	if PlusOffset < 0 then return end
	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11, Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11)
		buffer.writef64(Point, 104 + 0, O00)
		buffer.writef64(Point, 104 + 8, O01)
		buffer.writef64(Point, 104 + 16, O02)
		buffer.writef64(Point, 104 + 24, O03)
		buffer.writef64(Point, 104 + 32, O04)
		buffer.writef64(Point, 104 + 40, O05)
		buffer.writef64(Point, 104 + 48, O06)
		buffer.writef64(Point, 104 + 56, O07)
		buffer.writef64(Point, 104 + 64, O08)
		buffer.writef64(Point, 104 + 72, O09)
		buffer.writef64(Point, 104 + 80, O10)
		buffer.writef64(Point, 104 + 88, O11)
	end
	if PlusOffset < 0 then return end
	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(N00, N01, N02, N03, N04, N05, N06, N07, N08, N09, N10, N11, Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11)
		buffer.writef64(Point, 208 + 0, O00)
		buffer.writef64(Point, 208 + 8, O01)
		buffer.writef64(Point, 208 + 16, O02)
		buffer.writef64(Point, 208 + 24, O03)
		buffer.writef64(Point, 208 + 32, O04)
		buffer.writef64(Point, 208 + 40, O05)
		buffer.writef64(Point, 208 + 48, O06)
		buffer.writef64(Point, 208 + 56, O07)
		buffer.writef64(Point, 208 + 64, O08)
		buffer.writef64(Point, 208 + 72, O09)
		buffer.writef64(Point, 208 + 80, O10)
		buffer.writef64(Point, 208 + 88, O11)
	end
	if PlusOffset < 0 then return end
	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11)
		buffer.writef64(Point, 312 + 0, O00)
		buffer.writef64(Point, 312 + 8, O01)
		buffer.writef64(Point, 312 + 16, O02)
		buffer.writef64(Point, 312 + 24, O03)
		buffer.writef64(Point, 312 + 32, O04)
		buffer.writef64(Point, 312 + 40, O05)
		buffer.writef64(Point, 312 + 48, O06)
		buffer.writef64(Point, 312 + 56, O07)
		buffer.writef64(Point, 312 + 64, O08)
		buffer.writef64(Point, 312 + 72, O09)
		buffer.writef64(Point, 312 + 80, O10)
		buffer.writef64(Point, 312 + 88, O11)
	end
	if PlusOffset < 0 then return end
end

function Edwards25519.AddNielsInPlace(Point: buffer, Table: buffer, Offset: number)
	Edwards25519.AddInPlace(Point, Table, Offset, Offset + 104, Offset + 312, Offset + 208, 1)
end

function Edwards25519.SubNielsInPlace(Point: buffer, Table: buffer, Offset: number)
	Edwards25519.AddInPlace(Point, Table, Offset + 104, Offset, Offset + 312, Offset + 208, -1)
end

function Edwards25519.AddAffineInPlace(Point: buffer, Table: buffer, Offset: number)
	Edwards25519.AddInPlace(Point, Table, Offset, Offset + 104, Offset + 208, -1, 1)
end

function Edwards25519.SubAffineInPlace(Point: buffer, Table: buffer, Offset: number)
	Edwards25519.AddInPlace(Point, Table, Offset + 104, Offset, Offset + 208, -1, -1)
end

function Edwards25519.Double(Point1: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1Z = GetCoord(Point1, 2, COORD_BUFFER_2)

	local SquaredA = FieldPrime.Square(Point1X)
	local SquaredB = FieldPrime.Square(Point1Y)
	FieldPrime.Square(Point1Z, Point1Z)
	FieldPrime.Add(Point1Z, Point1Z, Point1Z)
	local DoubledD = Point1Z
	local SumE = FieldPrime.Add(SquaredA, SquaredB)
	FieldPrime.Add(Point1X, Point1Y, Point1X)
	local SumF = Point1X
	local SquaredG = FieldPrime.Square(SumF)
	FieldPrime.Sub(SquaredG, SumE, SquaredG)
	FieldPrime.Carry(SquaredG, SquaredG)
	local DiffH = SquaredG
	FieldPrime.Sub(SquaredB, SquaredA, SquaredB)
	local DiffI = SquaredB
	FieldPrime.Sub(DoubledD, DiffI, DoubledD)
	FieldPrime.Carry(DoubledD, DoubledD)
	local DiffJ = DoubledD

	local NewX = FieldPrime.Mul(DiffH, DiffJ)
	local NewY = FieldPrime.Mul(DiffI, SumE)
	FieldPrime.Mul(DiffJ, DiffI, DiffJ)
	local NewZ = DiffJ
	FieldPrime.Mul(DiffH, SumE, DiffH)
	local NewT = DiffH

	local Result = Storage or buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, NewX, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, NewY, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, NewZ, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, NewT, 0, COORD_SIZE)

	return Result
end

function Edwards25519.Add(Point1: buffer, NielsPoint2: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1Z = GetCoord(Point1, 2, COORD_BUFFER_2)
	local Point1T = GetCoord(Point1, 3, COORD_BUFFER_3)

	local Niels1Plus = GetCoord(NielsPoint2, 0, COORD_BUFFER_4)
	local Niels1Minus = GetCoord(NielsPoint2, 1, COORD_BUFFER_5)
	local Niels1Z = GetCoord(NielsPoint2, 2, COORD_BUFFER_6)
	local Niels1T = GetCoord(NielsPoint2, 3, COORD_BUFFER_7)

	local DiffA = FieldPrime.Sub(Point1Y, Point1X)
	FieldPrime.Mul(DiffA, Niels1Minus, DiffA)
	local ProductB = DiffA

	local SumC = FieldPrime.Add(Point1Y, Point1X)
	FieldPrime.Mul(SumC, Niels1Plus, SumC)
	local ProductD = SumC

	FieldPrime.Mul(Point1T, Niels1T, Point1T)
	local ProductE = Point1T

	FieldPrime.Mul(Point1Z, Niels1Z, Point1Z)
	local ProductF = Point1Z

	local DiffG = FieldPrime.Sub(ProductD, ProductB)
	local DiffH = FieldPrime.Sub(ProductF, ProductE)

	FieldPrime.Add(ProductF, ProductE, ProductF)
	local SumI = ProductF

	FieldPrime.Add(ProductD, ProductB, ProductD)
	local SumJ = ProductD

	local NewX = FieldPrime.Mul(DiffG, DiffH)
	local NewY = FieldPrime.Mul(SumI, SumJ)
	FieldPrime.Mul(DiffH, SumI, DiffH)
	local NewZ = DiffH
	FieldPrime.Mul(DiffG, SumJ, DiffG)
	local NewT = DiffG

	local Result = Storage or buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, NewX, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, NewY, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, NewZ, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, NewT, 0, COORD_SIZE)

	return Result
end

function Edwards25519.Sub(Point1: buffer, NielsPoint2: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1Z = GetCoord(Point1, 2, COORD_BUFFER_2)
	local Point1T = GetCoord(Point1, 3, COORD_BUFFER_3)

	local Niels1Plus = GetCoord(NielsPoint2, 0, COORD_BUFFER_4)
	local Niels1Minus = GetCoord(NielsPoint2, 1, COORD_BUFFER_5)
	local Niels1Z = GetCoord(NielsPoint2, 2, COORD_BUFFER_6)
	local Niels1T = GetCoord(NielsPoint2, 3, COORD_BUFFER_7)

	local DiffA = FieldPrime.Sub(Point1Y, Point1X)
	FieldPrime.Mul(DiffA, Niels1Plus, DiffA)
	local ProductB = DiffA
	FieldPrime.Add(Point1Y, Point1X, Point1Y)
	local SumC = Point1Y
	FieldPrime.Mul(SumC, Niels1Minus, SumC)
	local ProductD = SumC
	FieldPrime.Mul(Point1T, Niels1T, Point1T)
	local ProductE = Point1T
	FieldPrime.Mul(Point1Z, Niels1Z, Point1Z)
	local ProductF = Point1Z
	local DiffG = FieldPrime.Sub(ProductD, ProductB)
	local SumH = FieldPrime.Add(ProductF, ProductE)
	local DiffI = FieldPrime.Sub(ProductF, ProductE)
	FieldPrime.Add(ProductD, ProductB, ProductD)
	local SumJ = ProductD

	local NewX = FieldPrime.Mul(DiffG, SumH)
	local NewY = FieldPrime.Mul(DiffI, SumJ)
	FieldPrime.Mul(SumH, DiffI, SumH)
	local NewZ = SumH
	FieldPrime.Mul(DiffG, SumJ, DiffG)
	local NewT = DiffG

	local Result = Storage or buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, NewX, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, NewY, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, NewZ, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, NewT, 0, COORD_SIZE)

	return Result
end

function Edwards25519.Niels(Point1: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1Z = GetCoord(Point1, 2, COORD_BUFFER_2)
	local Point1T = GetCoord(Point1, 3, COORD_BUFFER_3)

	local PlusN3 = FieldPrime.Add(Point1Y, Point1X)
	local MinusN3 = FieldPrime.Sub(Point1Y, Point1X)
	FieldPrime.Add(Point1Z, Point1Z, Point1Z)
	local DoubledN3Z = Point1Z
	FieldPrime.Mul(Point1T, CURVE_K, Point1T)
	local ScaledN3T = Point1T

	local Result = Storage or buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, PlusN3, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, MinusN3, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, DoubledN3Z, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, ScaledN3T, 0, COORD_SIZE)

	return Result
end

function Edwards25519.AffineNiels(Point1: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1T = GetCoord(Point1, 3, COORD_BUFFER_3)

	local YPlusX = FieldPrime.Add(Point1Y, Point1X)
	local YMinusX = FieldPrime.Sub(Point1Y, Point1X)
	FieldPrime.Mul(Point1T, CURVE_K, Point1T)
	local T2d = Point1T

	local Result = Storage or buffer.create(AFFINE_NIELS_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, YPlusX, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, YMinusX, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, T2d, 0, COORD_SIZE)

	return Result
end

function Edwards25519.AddAffine(Point1: buffer, AffineNiels2: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1Z = GetCoord(Point1, 2, COORD_BUFFER_2)
	local Point1T = GetCoord(Point1, 3, COORD_BUFFER_3)

	local Niels2YPlusX = GetCoord(AffineNiels2, 0, COORD_BUFFER_4)
	local Niels2YMinusX = GetCoord(AffineNiels2, 1, COORD_BUFFER_5)
	local Niels2T2d = GetCoord(AffineNiels2, 2, COORD_BUFFER_6)

	local DiffA = FieldPrime.Sub(Point1Y, Point1X)
	FieldPrime.Mul(DiffA, Niels2YMinusX, DiffA)
	local ProductB = DiffA

	local SumC = FieldPrime.Add(Point1Y, Point1X)
	FieldPrime.Mul(SumC, Niels2YPlusX, SumC)
	local ProductD = SumC

	FieldPrime.Mul(Point1T, Niels2T2d, Point1T)
	local ProductE = Point1T

	FieldPrime.Add(Point1Z, Point1Z, Point1Z)
	local ProductF = Point1Z

	local DiffG = FieldPrime.Sub(ProductD, ProductB)
	local DiffH = FieldPrime.Sub(ProductF, ProductE)

	FieldPrime.Add(ProductF, ProductE, ProductF)
	local SumI = ProductF

	FieldPrime.Add(ProductD, ProductB, ProductD)
	local SumJ = ProductD

	local NewX = FieldPrime.Mul(DiffG, DiffH)
	local NewY = FieldPrime.Mul(SumI, SumJ)
	FieldPrime.Mul(DiffH, SumI, DiffH)
	local NewZ = DiffH
	FieldPrime.Mul(DiffG, SumJ, DiffG)
	local NewT = DiffG

	local Result = Storage or buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, NewX, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, NewY, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, NewZ, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, NewT, 0, COORD_SIZE)

	return Result
end

function Edwards25519.SubAffine(Point1: buffer, AffineNiels2: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1Z = GetCoord(Point1, 2, COORD_BUFFER_2)
	local Point1T = GetCoord(Point1, 3, COORD_BUFFER_3)

	local Niels2YPlusX = GetCoord(AffineNiels2, 0, COORD_BUFFER_4)
	local Niels2YMinusX = GetCoord(AffineNiels2, 1, COORD_BUFFER_5)
	local Niels2T2d = GetCoord(AffineNiels2, 2, COORD_BUFFER_6)

	local DiffA = FieldPrime.Sub(Point1Y, Point1X)
	FieldPrime.Mul(DiffA, Niels2YPlusX, DiffA)
	local ProductB = DiffA

	FieldPrime.Add(Point1Y, Point1X, Point1Y)
	local SumC = Point1Y
	FieldPrime.Mul(SumC, Niels2YMinusX, SumC)
	local ProductD = SumC

	FieldPrime.Mul(Point1T, Niels2T2d, Point1T)
	local ProductE = Point1T

	FieldPrime.Add(Point1Z, Point1Z, Point1Z)
	local ProductF = Point1Z

	local DiffG = FieldPrime.Sub(ProductD, ProductB)
	local SumH = FieldPrime.Add(ProductF, ProductE)
	local DiffI = FieldPrime.Sub(ProductF, ProductE)
	FieldPrime.Add(ProductD, ProductB, ProductD)
	local SumJ = ProductD

	local NewX = FieldPrime.Mul(DiffG, SumH)
	local NewY = FieldPrime.Mul(DiffI, SumJ)
	FieldPrime.Mul(SumH, DiffI, SumH)
	local NewZ = SumH
	FieldPrime.Mul(DiffG, SumJ, DiffG)
	local NewT = DiffG

	local Result = Storage or buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, NewX, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, NewY, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, NewZ, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, NewT, 0, COORD_SIZE)

	return Result
end

function Edwards25519.Scale(Point1: buffer): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1Z = GetCoord(Point1, 2, COORD_BUFFER_2)

	FieldPrime.Invert(Point1Z, Point1Z)
	local ZInverse = Point1Z
	FieldPrime.Mul(Point1X, ZInverse, Point1X)
	local NewX = Point1X
	FieldPrime.Mul(Point1Y, ZInverse, Point1Y)
	local NewY = Point1Y
	local NewZ = FieldPrime.Num(1)
	local NewT = FieldPrime.Mul(NewX, NewY)

	local Result = buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, NewX, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, NewY, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, NewZ, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, NewT, 0, COORD_SIZE)

	return Result
end

function Edwards25519.Encode(Point1: buffer): buffer
	local ScaledPoint = Edwards25519.Scale(Point1)
	local Point1X = GetCoord(ScaledPoint, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(ScaledPoint, 1, COORD_BUFFER_1)

	local EncodedY = FieldPrime.Encode(Point1Y)
	local CanonicalX = FieldPrime.Canonicalize(Point1X)
	local XSignBit = buffer.readf64(CanonicalX, 0) % 2

	local ResultBuffer = buffer.create(32)
	buffer.copy(ResultBuffer, 0, EncodedY, 0, 32)

	local LastByte = buffer.readu8(ResultBuffer, 31)
	buffer.writeu8(ResultBuffer, 31, LastByte + XSignBit * 128)

	return ResultBuffer
end

function Edwards25519.Decode(EncodedBuffer: buffer): buffer?
	local WorkingBuffer = buffer.create(32)
	buffer.copy(WorkingBuffer, 0, EncodedBuffer, 0, 32)

	local LastByte = buffer.readu8(WorkingBuffer, 31)
	local SignBit = bit32.extract(LastByte, 7)
	buffer.writeu8(WorkingBuffer, 31, bit32.band(LastByte, 0x7F))

	local YCoord = FieldPrime.Decode(WorkingBuffer)
	local YSquared = FieldPrime.Square(YCoord)
	local Numerator = FieldPrime.Sub(YSquared, FieldPrime.Num(1))
	local Denominator = FieldPrime.Mul(YSquared, CURVE_D)
	local DenomPlusOne = FieldPrime.Add(Denominator, FieldPrime.Num(1))

	local XCoord = FieldPrime.SqrtDiv(Numerator, DenomPlusOne)
	if not XCoord then
		return nil
	end

	local CanonicalX = FieldPrime.Canonicalize(XCoord)
	local XSignBit = buffer.readf64(CanonicalX, 0) % 2

	if XSignBit ~= SignBit then
		XCoord = FieldPrime.Carry(FieldPrime.Neg(XCoord))
	end

	local ZCoord = FieldPrime.Num(1)
	local TCoord = FieldPrime.Mul(XCoord, YCoord)

	local Result = buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, XCoord, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, YCoord, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, ZCoord, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, TCoord, 0, COORD_SIZE)

	return Result
end

local BASEPOINT_BYTES = buffer.create(32) do
	local BasePointHex = {
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
	}

	for Index = 1, 32 do
		buffer.writeu8(BASEPOINT_BYTES, Index - 1, BasePointHex[Index])
	end

	BASEPONT_G = Edwards25519.Decode(BASEPOINT_BYTES)
end

function Edwards25519.AffineRadixWTable(BasePoint: buffer, RadixWidth: number): buffer
	if RadixWidth <= 0 or RadixWidth > 8 then
		error("Invalid Radix width", 2)
	end

	if buffer.len(BasePoint) ~= POINT_SIZE then
		error("Invalid Basepoint", 2)
	end

	local PointSize = POINT_SIZE
	local CoordSize = COORD_SIZE
	local NielsSize = AFFINE_NIELS_SIZE
	local MaxWindows = math.ceil(256 / RadixWidth)
	local MaxRowSize = 2 ^ RadixWidth / 2
	local Count = MaxWindows * MaxRowSize

	local Points = buffer.create(Count * PointSize)
	local Current = buffer.create(PointSize)
	buffer.copy(Current, 0, BasePoint, 0, PointSize)
	local Working = buffer.create(PointSize)
	local Step = buffer.create(PointSize)

	for WindowIndex = 0, MaxWindows - 1 do
		local Base = WindowIndex * MaxRowSize * PointSize
		buffer.copy(Points, Base, Current, 0, PointSize)
		buffer.copy(Working, 0, Current, 0, PointSize)
		Edwards25519.Niels(Current, Step)

		for Multiple = 1, MaxRowSize - 1 do
			Edwards25519.AddNielsInPlace(Working, Step, 0)
			buffer.copy(Points, Base + Multiple * PointSize, Working, 0, PointSize)
		end

		for _ = 1, RadixWidth do
			Edwards25519.DoubleInPlace(Current, true)
		end
	end

	local Mul = FieldPrime.Mul
	local Prefix = buffer.create(Count * CoordSize)
	local ZCoord = buffer.create(CoordSize)
	buffer.copy(Prefix, 0, Points, 2 * CoordSize, CoordSize)
	local Previous = buffer.create(CoordSize)
	for Index = 1, Count - 1 do
		buffer.copy(Previous, 0, Prefix, (Index - 1) * CoordSize, CoordSize)
		buffer.copy(ZCoord, 0, Points, Index * PointSize + 2 * CoordSize, CoordSize)
		local Product = Mul(Previous, ZCoord)
		buffer.copy(Prefix, Index * CoordSize, Product, 0, CoordSize)
	end

	local Last = buffer.create(CoordSize)
	buffer.copy(Last, 0, Prefix, (Count - 1) * CoordSize, CoordSize)
	local Inverse = FieldPrime.Invert(Last)

	local TableData = buffer.create(Count * NielsSize)
	local XCoord = buffer.create(CoordSize)
	local YCoord = buffer.create(CoordSize)
	local ZInverse = buffer.create(CoordSize)

	for Index = Count - 1, 0, -1 do
		local PointOffset = Index * PointSize
		if Index > 0 then
			buffer.copy(Previous, 0, Prefix, (Index - 1) * CoordSize, CoordSize)
			Mul(Inverse, Previous, ZInverse)
			buffer.copy(ZCoord, 0, Points, PointOffset + 2 * CoordSize, CoordSize)
			Inverse = Mul(Inverse, ZCoord)
		else
			buffer.copy(ZInverse, 0, Inverse, 0, CoordSize)
		end

		buffer.copy(XCoord, 0, Points, PointOffset, CoordSize)
		buffer.copy(YCoord, 0, Points, PointOffset + CoordSize, CoordSize)
		Mul(XCoord, ZInverse, XCoord)
		Mul(YCoord, ZInverse, YCoord)
		local TCoord = Mul(Mul(XCoord, YCoord), CURVE_K)

		local Offset = Index * NielsSize
		buffer.copy(TableData, Offset, FieldPrime.Add(YCoord, XCoord), 0, CoordSize)
		buffer.copy(TableData, Offset + CoordSize, FieldPrime.Sub(YCoord, XCoord), 0, CoordSize)
		buffer.copy(TableData, Offset + 2 * CoordSize, TCoord, 0, CoordSize)
	end

	return TableData
end

do
	if BASEPONT_G then
		AFFINE_BASEPOINT_TABLE = Edwards25519.AffineRadixWTable(BASEPONT_G, BASE_RADIX_WIDTH)
	end
end

function Edwards25519.GetAffineBasePointTableEntry(WindowIndex: number, Multiple: number, Storage: buffer?): buffer
	if not AFFINE_BASEPOINT_TABLE then
		return buffer.create(0)
	end

	local BaseOffset = ((WindowIndex - 1) * BASE_POINT_ROW * AFFINE_NIELS_SIZE)
	local Offset = BaseOffset + ((Multiple - 1) * AFFINE_NIELS_SIZE)

	local AffineNielsPoint = Storage or buffer.create(AFFINE_NIELS_SIZE)
	buffer.copy(AffineNielsPoint, 0, AFFINE_BASEPOINT_TABLE, Offset, AFFINE_NIELS_SIZE)

	return AffineNielsPoint
end

function Edwards25519.SignedRadixW(ScalarBits: buffer, ScalarBitCount: number, RadixWidth: number): (buffer, number)
	if ScalarBitCount <= 0 or ScalarBitCount > 256 then
		error("Invalid scalar bit count", 2)
	end

	if RadixWidth <= 0 or RadixWidth > 8 then
		error("Invalid Radix width", 2)
	end

	local RadixValue = 2 ^ RadixWidth
	local HalfRadix = RadixValue / 2
	local MaxOutputLength = 272
	local OutputDigits = RADIX_OUTPUT
	local OutputLength, Accumulator = 0, 0
	local Multiplier = 1

	for BitIndex = 1, ScalarBitCount do
		if BitIndex > ScalarBitCount then
			break
		end

		local BitValue = buffer.readf64(ScalarBits, (BitIndex - 1) * 8)
		Accumulator += BitValue * Multiplier
		Multiplier *= 2

		while BitIndex == ScalarBitCount and Accumulator > 0 or Multiplier > RadixValue do
			if OutputLength >= MaxOutputLength then
				error("Output overflow in SignedRadixW")
			end

			local Remainder = bit32.band(Accumulator, RadixValue - 1)
			if Remainder >= HalfRadix then
				Remainder -= RadixValue
			end
			Accumulator = (Accumulator - Remainder) / RadixValue
			Multiplier /= RadixValue
			buffer.writef64(OutputDigits, OutputLength * 8, Remainder)
			OutputLength += 1
		end
	end

	return OutputDigits, OutputLength
end

function Edwards25519.WindowedNAF(ScalarBits: buffer, ScalarBitCount: number, WindowWidth: number): (buffer, number)
	local WindowValue = 2 ^ WindowWidth
	local HalfWindow = WindowValue / 2
	local OutputNAF = NAF_OUTPUT
	local OutputLength = 0
	local Accumulator = 0
	local Multiplier = 1

	for BitIndex = 1, ScalarBitCount do
		local BitValue = buffer.readf64(ScalarBits, (BitIndex - 1) * 8)
		Accumulator += BitValue * Multiplier
		Multiplier *= 2

		while BitIndex == ScalarBitCount and Accumulator > 0 or Multiplier > WindowValue do
			if bit32.band(Accumulator, 1) == 0 then
				Accumulator /= 2
				Multiplier /= 2
				buffer.writef64(OutputNAF, OutputLength * 8, 0)
				OutputLength += 1
			else
				local Remainder = bit32.band(Accumulator, WindowValue - 1)
				if Remainder >= HalfWindow then
					Remainder -= WindowValue
				end
				Accumulator -= Remainder
				buffer.writef64(OutputNAF, OutputLength * 8, Remainder)
				OutputLength += 1
			end
		end
	end

	while OutputLength > 0 and buffer.readf64(OutputNAF, (OutputLength - 1) * 8) == 0 do
		OutputLength -= 1
	end

	return OutputNAF, OutputLength
end

function Edwards25519.WindowedNAFTable(BasePoint: buffer, WindowWidth: number): buffer
	local PointSize = POINT_SIZE
	local CoordSize = COORD_SIZE
	local CurveK = CURVE_K
	local MaxOddMultiples = 2 ^ WindowWidth

	Edwards25519.Double(BasePoint, NAF_TABLE_DOUBLED)

	local TableData = buffer.create(MaxOddMultiples * PointSize)

	local FAdd = FieldPrime.Add
	local FSub = FieldPrime.Sub
	local FMul = FieldPrime.Mul

	local P1X = NAF_TABLE_P1X
	local P1Y = NAF_TABLE_P1Y
	local P1Z = NAF_TABLE_P1Z
	local P1T = NAF_TABLE_P1T
	local N2P = NAF_TABLE_N2P
	local N2M = NAF_TABLE_N2M
	local N2Z = NAF_TABLE_N2Z
	local N2T = NAF_TABLE_N2T
	local TMP = NAF_TABLE_TMP
	local DBLP = NAF_TABLE_DBL_P
	local DBLM = NAF_TABLE_DBL_M
	local DBLZ = NAF_TABLE_DBL_Z
	local DBLT = NAF_TABLE_DBL_T
	local Doubled = NAF_TABLE_DOUBLED

	buffer.copy(P1X, 0, Doubled, 0, CoordSize)
	buffer.copy(P1Y, 0, Doubled, CoordSize, CoordSize)
	buffer.copy(P1Z, 0, Doubled, 2 * CoordSize, CoordSize)
	buffer.copy(P1T, 0, Doubled, 3 * CoordSize, CoordSize)

	FAdd(P1Y, P1X, DBLP)
	FSub(P1Y, P1X, DBLM)
	FAdd(P1Z, P1Z, DBLZ)
	FMul(P1T, CurveK, DBLT)

	buffer.copy(P1X, 0, BasePoint, 0, CoordSize)
	buffer.copy(P1Y, 0, BasePoint, CoordSize, CoordSize)
	buffer.copy(P1Z, 0, BasePoint, 2 * CoordSize, CoordSize)
	buffer.copy(P1T, 0, BasePoint, 3 * CoordSize, CoordSize)

	FAdd(P1Y, P1X, N2P)
	FSub(P1Y, P1X, N2M)
	FAdd(P1Z, P1Z, N2Z)
	FMul(P1T, CurveK, N2T)

	buffer.copy(TableData, 0, N2P, 0, CoordSize)
	buffer.copy(TableData, CoordSize, N2M, 0, CoordSize)
	buffer.copy(TableData, 2 * CoordSize, N2Z, 0, CoordSize)
	buffer.copy(TableData, 3 * CoordSize, N2T, 0, CoordSize)

	buffer.copy(P1X, 0, BasePoint, 0, CoordSize)
	buffer.copy(P1Y, 0, BasePoint, CoordSize, CoordSize)
	buffer.copy(P1Z, 0, BasePoint, 2 * CoordSize, CoordSize)
	buffer.copy(P1T, 0, BasePoint, 3 * CoordSize, CoordSize)

	for OddMultiple = 3, MaxOddMultiples, 2 do
		local CurrentOffset = ((OddMultiple - 1) * PointSize)

		FSub(P1Y, P1X, TMP)
		FMul(TMP, DBLM, TMP)
		FAdd(P1Y, P1X, N2P)
		FMul(N2P, DBLP, N2P)
		FMul(P1T, DBLT, P1T)
		FMul(P1Z, DBLZ, P1Z)

		FSub(N2P, TMP, N2M)
		FSub(P1Z, P1T, N2Z)
		FAdd(P1Z, P1T, P1Z)
		FAdd(N2P, TMP, N2P)

		FMul(N2M, N2Z, P1X)
		FMul(P1Z, N2P, P1Y)
		FMul(N2Z, P1Z, P1Z)
		FMul(N2M, N2P, P1T)

		FAdd(P1Y, P1X, N2P)
		FSub(P1Y, P1X, N2M)
		FAdd(P1Z, P1Z, N2Z)
		FMul(P1T, CurveK, N2T)

		buffer.copy(TableData, CurrentOffset, N2P, 0, CoordSize)
		buffer.copy(TableData, CurrentOffset + CoordSize, N2M, 0, CoordSize)
		buffer.copy(TableData, CurrentOffset + 2 * CoordSize, N2Z, 0, CoordSize)
		buffer.copy(TableData, CurrentOffset + 3 * CoordSize, N2T, 0, CoordSize)
	end

	return TableData
end

function Edwards25519.MulG(ScalarBits: buffer, ScalarBitCount: number): buffer
	local PointSize = POINT_SIZE
	local AffineNielsSize = AFFINE_NIELS_SIZE
	local BasePointRow = BASE_POINT_ROW
	local AffineTable = AFFINE_BASEPOINT_TABLE :: buffer

	local SignedWindows, WindowCount = Edwards25519.SignedRadixW(ScalarBits, ScalarBitCount, BASE_RADIX_WIDTH)

	local ResultPoint = MULG_RESULT_POINT
	buffer.copy(ResultPoint, 0, IDENTITY_O, 0, PointSize)

	local DummyPoint = MULG_DUMMY_POINT
	buffer.copy(DummyPoint, 0, IDENTITY_O, 0, PointSize)

	local AddAffine = Edwards25519.AddAffineInPlace
	local SubAffine = Edwards25519.SubAffineInPlace

	for WindowIndex = 1, WindowCount do
		local WindowValue = buffer.readf64(SignedWindows, (WindowIndex - 1) * 8)
		local BaseOffset = (WindowIndex - 1) * BasePointRow * AffineNielsSize

		if WindowValue > 0 then
			AddAffine(ResultPoint, AffineTable, BaseOffset + (WindowValue - 1) * AffineNielsSize)
		elseif WindowValue < 0 then
			SubAffine(ResultPoint, AffineTable, BaseOffset + (-WindowValue - 1) * AffineNielsSize)
		else
			AddAffine(DummyPoint, AffineTable, BaseOffset)
		end
	end

	local Output = buffer.create(PointSize)
	buffer.copy(Output, 0, ResultPoint, 0, PointSize)
	return Output
end

function Edwards25519.Mul(BasePoint: buffer, ScalarBits: buffer, ScalarBitCount: number): buffer
	local PointSize = POINT_SIZE

	local NAFForm, NAFLength = Edwards25519.WindowedNAF(ScalarBits, ScalarBitCount, 5)
	local MultipleTable = Edwards25519.WindowedNAFTable(BasePoint, 5)

	local ResultPoint = MUL_RESULT_POINT
	buffer.copy(ResultPoint, 0, IDENTITY_O, 0, PointSize)

	local DoubleInPlace = Edwards25519.DoubleInPlace
	local AddNiels = Edwards25519.AddNielsInPlace
	local SubNiels = Edwards25519.SubNielsInPlace

	for NAFIndex = NAFLength, 1, -1 do
		local NAFDigit = buffer.readf64(NAFForm, (NAFIndex - 1) * 8)

		if NAFDigit == 0 then
			DoubleInPlace(ResultPoint, NAFIndex == 1 or buffer.readf64(NAFForm, (NAFIndex - 2) * 8) ~= 0)
		elseif NAFDigit > 0 then
			AddNiels(ResultPoint, MultipleTable, (NAFDigit - 1) * PointSize)
		else
			SubNiels(ResultPoint, MultipleTable, (-NAFDigit - 1) * PointSize)
		end
	end

	local Output = buffer.create(PointSize)
	buffer.copy(Output, 0, ResultPoint, 0, PointSize)
	return Output
end

return Edwards25519
