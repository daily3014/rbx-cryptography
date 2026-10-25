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
local MUL_NIELS_POINT = buffer.create(POINT_SIZE)
local MUL_DOUBLE_X = buffer.create(COORD_SIZE)
local MUL_DOUBLE_Y = buffer.create(COORD_SIZE)
local MUL_DOUBLE_Z = buffer.create(COORD_SIZE)
local MUL_DOUBLE_A = buffer.create(COORD_SIZE)
local MUL_DOUBLE_B = buffer.create(COORD_SIZE)
local MUL_DOUBLE_E = buffer.create(COORD_SIZE)
local MUL_DOUBLE_G = buffer.create(COORD_SIZE)
local MUL_P1X = buffer.create(COORD_SIZE)
local MUL_P1Y = buffer.create(COORD_SIZE)
local MUL_P1Z = buffer.create(COORD_SIZE)
local MUL_P1T = buffer.create(COORD_SIZE)
local MUL_N2P = buffer.create(COORD_SIZE)
local MUL_N2M = buffer.create(COORD_SIZE)
local MUL_N2Z = buffer.create(COORD_SIZE)
local MUL_N2T = buffer.create(COORD_SIZE)
local MUL_TMP = buffer.create(COORD_SIZE)

local MULG_RESULT_POINT = buffer.create(POINT_SIZE)
local MULG_AFFINE_NIELS = buffer.create(AFFINE_NIELS_SIZE)
local MULG_DUMMY_POINT = buffer.create(POINT_SIZE)
local MULG_P1X = buffer.create(COORD_SIZE)
local MULG_P1Y = buffer.create(COORD_SIZE)
local MULG_P1Z = buffer.create(COORD_SIZE)
local MULG_P1T = buffer.create(COORD_SIZE)
local MULG_N2P = buffer.create(COORD_SIZE)
local MULG_N2M = buffer.create(COORD_SIZE)
local MULG_N2T = buffer.create(COORD_SIZE)
local MULG_TMP = buffer.create(COORD_SIZE)

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
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11
	do
		local d00 = X00 * 2
		local d01 = X01 * 2
		local d02 = X02 * 2
		local d03 = X03 * 2
		local d04 = X04 * 2
		local d05 = X05 * 2
		local d06 = X06 * 2
		local d07 = X07 * 2
		local d08 = X08 * 2
		local d09 = X09 * 2
		local d10 = X10 * 2
		local c00 = (X11 * d01 + X10 * d02 + X09 * d03 + X08 * d04 + X07 * d05 + X06 * X06) * (19 / 2 ^ 255) + (X00 * X00)
		local c01 = (X11 * d02 + X10 * d03 + X09 * d04 + X08 * d05 + X07 * d06) * (19 / 2 ^ 255) + (X01 * d00)
		local c02 = (X11 * d03 + X10 * d04 + X09 * d05 + X08 * d06 + X07 * X07) * (19 / 2 ^ 255) + (X02 * d00 + X01 * X01)
		local c03 = (X11 * d04 + X10 * d05 + X09 * d06 + X08 * d07) * (19 / 2 ^ 255) + (X03 * d00 + X02 * d01)
		local c04 = (X11 * d05 + X10 * d06 + X09 * d07 + X08 * X08) * (19 / 2 ^ 255) + (X04 * d00 + X03 * d01 + X02 * X02)
		local c05 = (X11 * d06 + X10 * d07 + X09 * d08) * (19 / 2 ^ 255) + (X05 * d00 + X04 * d01 + X03 * d02)
		local c06 = (X11 * d07 + X10 * d08 + X09 * X09) * (19 / 2 ^ 255) + (X06 * d00 + X05 * d01 + X04 * d02 + X03 * X03)
		local c07 = (X11 * d08 + X10 * d09) * (19 / 2 ^ 255) + (X07 * d00 + X06 * d01 + X05 * d02 + X04 * d03)
		local c08 = (X11 * d09 + X10 * X10) * (19 / 2 ^ 255) + (X08 * d00 + X07 * d01 + X06 * d02 + X05 * d03 + X04 * X04)
		local c09 = (X11 * d10) * (19 / 2 ^ 255) + (X09 * d00 + X08 * d01 + X07 * d02 + X06 * d03 + X05 * d04)
		local c10 = (X11 * X11) * (19 / 2 ^ 255) + (X10 * d00 + X09 * d01 + X08 * d02 + X07 * d03 + X06 * d04 + X05 * X05)
		local c11 = X11 * d00 + X10 * d01 + X09 * d02 + X08 * d03 + X07 * d04 + X06 * d05
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
		A00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		A01 = (b01 - j01) + j00
		A02 = (b02 - j02) + j01
		A03 = (b03 - j03) + j02
		A04 = (b04 - j04) + j03
		A05 = (b05 - j05) + j04
		A06 = (b06 - j06) + j05
		A07 = (b07 - j07) + j06
		A08 = (b08 - j08) + j07
		A09 = (b09 - j09) + j08
		A10 = (b10 - j10) + j09
		A11 = (b11 - j11) + j10
	end
	if not Point then return end
	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11
	do
		local d00 = Y00 * 2
		local d01 = Y01 * 2
		local d02 = Y02 * 2
		local d03 = Y03 * 2
		local d04 = Y04 * 2
		local d05 = Y05 * 2
		local d06 = Y06 * 2
		local d07 = Y07 * 2
		local d08 = Y08 * 2
		local d09 = Y09 * 2
		local d10 = Y10 * 2
		local c00 = (Y11 * d01 + Y10 * d02 + Y09 * d03 + Y08 * d04 + Y07 * d05 + Y06 * Y06) * (19 / 2 ^ 255) + (Y00 * Y00)
		local c01 = (Y11 * d02 + Y10 * d03 + Y09 * d04 + Y08 * d05 + Y07 * d06) * (19 / 2 ^ 255) + (Y01 * d00)
		local c02 = (Y11 * d03 + Y10 * d04 + Y09 * d05 + Y08 * d06 + Y07 * Y07) * (19 / 2 ^ 255) + (Y02 * d00 + Y01 * Y01)
		local c03 = (Y11 * d04 + Y10 * d05 + Y09 * d06 + Y08 * d07) * (19 / 2 ^ 255) + (Y03 * d00 + Y02 * d01)
		local c04 = (Y11 * d05 + Y10 * d06 + Y09 * d07 + Y08 * Y08) * (19 / 2 ^ 255) + (Y04 * d00 + Y03 * d01 + Y02 * Y02)
		local c05 = (Y11 * d06 + Y10 * d07 + Y09 * d08) * (19 / 2 ^ 255) + (Y05 * d00 + Y04 * d01 + Y03 * d02)
		local c06 = (Y11 * d07 + Y10 * d08 + Y09 * Y09) * (19 / 2 ^ 255) + (Y06 * d00 + Y05 * d01 + Y04 * d02 + Y03 * Y03)
		local c07 = (Y11 * d08 + Y10 * d09) * (19 / 2 ^ 255) + (Y07 * d00 + Y06 * d01 + Y05 * d02 + Y04 * d03)
		local c08 = (Y11 * d09 + Y10 * Y10) * (19 / 2 ^ 255) + (Y08 * d00 + Y07 * d01 + Y06 * d02 + Y05 * d03 + Y04 * Y04)
		local c09 = (Y11 * d10) * (19 / 2 ^ 255) + (Y09 * d00 + Y08 * d01 + Y07 * d02 + Y06 * d03 + Y05 * d04)
		local c10 = (Y11 * Y11) * (19 / 2 ^ 255) + (Y10 * d00 + Y09 * d01 + Y08 * d02 + Y07 * d03 + Y06 * d04 + Y05 * Y05)
		local c11 = Y11 * d00 + Y10 * d01 + Y09 * d02 + Y08 * d03 + Y07 * d04 + Y06 * d05
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
		B00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		B01 = (b01 - j01) + j00
		B02 = (b02 - j02) + j01
		B03 = (b03 - j03) + j02
		B04 = (b04 - j04) + j03
		B05 = (b05 - j05) + j04
		B06 = (b06 - j06) + j05
		B07 = (b07 - j07) + j06
		B08 = (b08 - j08) + j07
		B09 = (b09 - j09) + j08
		B10 = (b10 - j10) + j09
		B11 = (b11 - j11) + j10
	end
	if not Point then return end
	do
		local d00 = Z00 * 2
		local d01 = Z01 * 2
		local d02 = Z02 * 2
		local d03 = Z03 * 2
		local d04 = Z04 * 2
		local d05 = Z05 * 2
		local d06 = Z06 * 2
		local d07 = Z07 * 2
		local d08 = Z08 * 2
		local d09 = Z09 * 2
		local d10 = Z10 * 2
		local c00 = (Z11 * d01 + Z10 * d02 + Z09 * d03 + Z08 * d04 + Z07 * d05 + Z06 * Z06) * (19 / 2 ^ 255) + (Z00 * Z00)
		local c01 = (Z11 * d02 + Z10 * d03 + Z09 * d04 + Z08 * d05 + Z07 * d06) * (19 / 2 ^ 255) + (Z01 * d00)
		local c02 = (Z11 * d03 + Z10 * d04 + Z09 * d05 + Z08 * d06 + Z07 * Z07) * (19 / 2 ^ 255) + (Z02 * d00 + Z01 * Z01)
		local c03 = (Z11 * d04 + Z10 * d05 + Z09 * d06 + Z08 * d07) * (19 / 2 ^ 255) + (Z03 * d00 + Z02 * d01)
		local c04 = (Z11 * d05 + Z10 * d06 + Z09 * d07 + Z08 * Z08) * (19 / 2 ^ 255) + (Z04 * d00 + Z03 * d01 + Z02 * Z02)
		local c05 = (Z11 * d06 + Z10 * d07 + Z09 * d08) * (19 / 2 ^ 255) + (Z05 * d00 + Z04 * d01 + Z03 * d02)
		local c06 = (Z11 * d07 + Z10 * d08 + Z09 * Z09) * (19 / 2 ^ 255) + (Z06 * d00 + Z05 * d01 + Z04 * d02 + Z03 * Z03)
		local c07 = (Z11 * d08 + Z10 * d09) * (19 / 2 ^ 255) + (Z07 * d00 + Z06 * d01 + Z05 * d02 + Z04 * d03)
		local c08 = (Z11 * d09 + Z10 * Z10) * (19 / 2 ^ 255) + (Z08 * d00 + Z07 * d01 + Z06 * d02 + Z05 * d03 + Z04 * Z04)
		local c09 = (Z11 * d10) * (19 / 2 ^ 255) + (Z09 * d00 + Z08 * d01 + Z07 * d02 + Z06 * d03 + Z05 * d04)
		local c10 = (Z11 * Z11) * (19 / 2 ^ 255) + (Z10 * d00 + Z09 * d01 + Z08 * d02 + Z07 * d03 + Z06 * d04 + Z05 * Z05)
		local c11 = Z11 * d00 + Z10 * d01 + Z09 * d02 + Z08 * d03 + Z07 * d04 + Z06 * d05
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
	do
		local d00 = X00 * 2
		local d01 = X01 * 2
		local d02 = X02 * 2
		local d03 = X03 * 2
		local d04 = X04 * 2
		local d05 = X05 * 2
		local d06 = X06 * 2
		local d07 = X07 * 2
		local d08 = X08 * 2
		local d09 = X09 * 2
		local d10 = X10 * 2
		local c00 = (X11 * d01 + X10 * d02 + X09 * d03 + X08 * d04 + X07 * d05 + X06 * X06) * (19 / 2 ^ 255) + (X00 * X00)
		local c01 = (X11 * d02 + X10 * d03 + X09 * d04 + X08 * d05 + X07 * d06) * (19 / 2 ^ 255) + (X01 * d00)
		local c02 = (X11 * d03 + X10 * d04 + X09 * d05 + X08 * d06 + X07 * X07) * (19 / 2 ^ 255) + (X02 * d00 + X01 * X01)
		local c03 = (X11 * d04 + X10 * d05 + X09 * d06 + X08 * d07) * (19 / 2 ^ 255) + (X03 * d00 + X02 * d01)
		local c04 = (X11 * d05 + X10 * d06 + X09 * d07 + X08 * X08) * (19 / 2 ^ 255) + (X04 * d00 + X03 * d01 + X02 * X02)
		local c05 = (X11 * d06 + X10 * d07 + X09 * d08) * (19 / 2 ^ 255) + (X05 * d00 + X04 * d01 + X03 * d02)
		local c06 = (X11 * d07 + X10 * d08 + X09 * X09) * (19 / 2 ^ 255) + (X06 * d00 + X05 * d01 + X04 * d02 + X03 * X03)
		local c07 = (X11 * d08 + X10 * d09) * (19 / 2 ^ 255) + (X07 * d00 + X06 * d01 + X05 * d02 + X04 * d03)
		local c08 = (X11 * d09 + X10 * X10) * (19 / 2 ^ 255) + (X08 * d00 + X07 * d01 + X06 * d02 + X05 * d03 + X04 * X04)
		local c09 = (X11 * d10) * (19 / 2 ^ 255) + (X09 * d00 + X08 * d01 + X07 * d02 + X06 * d03 + X05 * d04)
		local c10 = (X11 * X11) * (19 / 2 ^ 255) + (X10 * d00 + X09 * d01 + X08 * d02 + X07 * d03 + X06 * d04 + X05 * X05)
		local c11 = X11 * d00 + X10 * d01 + X09 * d02 + X08 * d03 + X07 * d04 + X06 * d05
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
		local c00 = (X01 * Z11 + X02 * Z10 + X03 * Z09 + X04 * Z08 + X05 * Z07 + X06 * Z06 + X07 * Z05 + X08 * Z04 + X09 * Z03 + X10 * Z02 + X11 * Z01) * (19 / 2 ^ 255) + (X00 * Z00)
		local c01 = (X02 * Z11 + X03 * Z10 + X04 * Z09 + X05 * Z08 + X06 * Z07 + X07 * Z06 + X08 * Z05 + X09 * Z04 + X10 * Z03 + X11 * Z02) * (19 / 2 ^ 255) + (X00 * Z01 + X01 * Z00)
		local c02 = (X03 * Z11 + X04 * Z10 + X05 * Z09 + X06 * Z08 + X07 * Z07 + X08 * Z06 + X09 * Z05 + X10 * Z04 + X11 * Z03) * (19 / 2 ^ 255) + (X00 * Z02 + X01 * Z01 + X02 * Z00)
		local c03 = (X04 * Z11 + X05 * Z10 + X06 * Z09 + X07 * Z08 + X08 * Z07 + X09 * Z06 + X10 * Z05 + X11 * Z04) * (19 / 2 ^ 255) + (X00 * Z03 + X01 * Z02 + X02 * Z01 + X03 * Z00)
		local c04 = (X05 * Z11 + X06 * Z10 + X07 * Z09 + X08 * Z08 + X09 * Z07 + X10 * Z06 + X11 * Z05) * (19 / 2 ^ 255) + (X00 * Z04 + X01 * Z03 + X02 * Z02 + X03 * Z01 + X04 * Z00)
		local c05 = (X06 * Z11 + X07 * Z10 + X08 * Z09 + X09 * Z08 + X10 * Z07 + X11 * Z06) * (19 / 2 ^ 255) + (X00 * Z05 + X01 * Z04 + X02 * Z03 + X03 * Z02 + X04 * Z01 + X05 * Z00)
		local c06 = (X07 * Z11 + X08 * Z10 + X09 * Z09 + X10 * Z08 + X11 * Z07) * (19 / 2 ^ 255) + (X00 * Z06 + X01 * Z05 + X02 * Z04 + X03 * Z03 + X04 * Z02 + X05 * Z01 + X06 * Z00)
		local c07 = (X08 * Z11 + X09 * Z10 + X10 * Z09 + X11 * Z08) * (19 / 2 ^ 255) + (X00 * Z07 + X01 * Z06 + X02 * Z05 + X03 * Z04 + X04 * Z03 + X05 * Z02 + X06 * Z01 + X07 * Z00)
		local c08 = (X09 * Z11 + X10 * Z10 + X11 * Z09) * (19 / 2 ^ 255) + (X00 * Z08 + X01 * Z07 + X02 * Z06 + X03 * Z05 + X04 * Z04 + X05 * Z03 + X06 * Z02 + X07 * Z01 + X08 * Z00)
		local c09 = (X10 * Z11 + X11 * Z10) * (19 / 2 ^ 255) + (X00 * Z09 + X01 * Z08 + X02 * Z07 + X03 * Z06 + X04 * Z05 + X05 * Z04 + X06 * Z03 + X07 * Z02 + X08 * Z01 + X09 * Z00)
		local c10 = (X11 * Z11) * (19 / 2 ^ 255) + (X00 * Z10 + X01 * Z09 + X02 * Z08 + X03 * Z07 + X04 * Z06 + X05 * Z05 + X06 * Z04 + X07 * Z03 + X08 * Z02 + X09 * Z01 + X10 * Z00)
		local c11 = X00 * Z11 + X01 * Z10 + X02 * Z09 + X03 * Z08 + X04 * Z07 + X05 * Z06 + X06 * Z05 + X07 * Z04 + X08 * Z03 + X09 * Z02 + X10 * Z01 + X11 * Z00
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
		buffer.writef64(Point, 0 + 0, (b00 - j00) + j11 * (19 / 2 ^ 255))
		buffer.writef64(Point, 0 + 8, (b01 - j01) + j00)
		buffer.writef64(Point, 0 + 16, (b02 - j02) + j01)
		buffer.writef64(Point, 0 + 24, (b03 - j03) + j02)
		buffer.writef64(Point, 0 + 32, (b04 - j04) + j03)
		buffer.writef64(Point, 0 + 40, (b05 - j05) + j04)
		buffer.writef64(Point, 0 + 48, (b06 - j06) + j05)
		buffer.writef64(Point, 0 + 56, (b07 - j07) + j06)
		buffer.writef64(Point, 0 + 64, (b08 - j08) + j07)
		buffer.writef64(Point, 0 + 72, (b09 - j09) + j08)
		buffer.writef64(Point, 0 + 80, (b10 - j10) + j09)
		buffer.writef64(Point, 0 + 88, (b11 - j11) + j10)
	end
	if not Point then return end
	do
		local c00 = (B01 * Y11 + B02 * Y10 + B03 * Y09 + B04 * Y08 + B05 * Y07 + B06 * Y06 + B07 * Y05 + B08 * Y04 + B09 * Y03 + B10 * Y02 + B11 * Y01) * (19 / 2 ^ 255) + (B00 * Y00)
		local c01 = (B02 * Y11 + B03 * Y10 + B04 * Y09 + B05 * Y08 + B06 * Y07 + B07 * Y06 + B08 * Y05 + B09 * Y04 + B10 * Y03 + B11 * Y02) * (19 / 2 ^ 255) + (B00 * Y01 + B01 * Y00)
		local c02 = (B03 * Y11 + B04 * Y10 + B05 * Y09 + B06 * Y08 + B07 * Y07 + B08 * Y06 + B09 * Y05 + B10 * Y04 + B11 * Y03) * (19 / 2 ^ 255) + (B00 * Y02 + B01 * Y01 + B02 * Y00)
		local c03 = (B04 * Y11 + B05 * Y10 + B06 * Y09 + B07 * Y08 + B08 * Y07 + B09 * Y06 + B10 * Y05 + B11 * Y04) * (19 / 2 ^ 255) + (B00 * Y03 + B01 * Y02 + B02 * Y01 + B03 * Y00)
		local c04 = (B05 * Y11 + B06 * Y10 + B07 * Y09 + B08 * Y08 + B09 * Y07 + B10 * Y06 + B11 * Y05) * (19 / 2 ^ 255) + (B00 * Y04 + B01 * Y03 + B02 * Y02 + B03 * Y01 + B04 * Y00)
		local c05 = (B06 * Y11 + B07 * Y10 + B08 * Y09 + B09 * Y08 + B10 * Y07 + B11 * Y06) * (19 / 2 ^ 255) + (B00 * Y05 + B01 * Y04 + B02 * Y03 + B03 * Y02 + B04 * Y01 + B05 * Y00)
		local c06 = (B07 * Y11 + B08 * Y10 + B09 * Y09 + B10 * Y08 + B11 * Y07) * (19 / 2 ^ 255) + (B00 * Y06 + B01 * Y05 + B02 * Y04 + B03 * Y03 + B04 * Y02 + B05 * Y01 + B06 * Y00)
		local c07 = (B08 * Y11 + B09 * Y10 + B10 * Y09 + B11 * Y08) * (19 / 2 ^ 255) + (B00 * Y07 + B01 * Y06 + B02 * Y05 + B03 * Y04 + B04 * Y03 + B05 * Y02 + B06 * Y01 + B07 * Y00)
		local c08 = (B09 * Y11 + B10 * Y10 + B11 * Y09) * (19 / 2 ^ 255) + (B00 * Y08 + B01 * Y07 + B02 * Y06 + B03 * Y05 + B04 * Y04 + B05 * Y03 + B06 * Y02 + B07 * Y01 + B08 * Y00)
		local c09 = (B10 * Y11 + B11 * Y10) * (19 / 2 ^ 255) + (B00 * Y09 + B01 * Y08 + B02 * Y07 + B03 * Y06 + B04 * Y05 + B05 * Y04 + B06 * Y03 + B07 * Y02 + B08 * Y01 + B09 * Y00)
		local c10 = (B11 * Y11) * (19 / 2 ^ 255) + (B00 * Y10 + B01 * Y09 + B02 * Y08 + B03 * Y07 + B04 * Y06 + B05 * Y05 + B06 * Y04 + B07 * Y03 + B08 * Y02 + B09 * Y01 + B10 * Y00)
		local c11 = B00 * Y11 + B01 * Y10 + B02 * Y09 + B03 * Y08 + B04 * Y07 + B05 * Y06 + B06 * Y05 + B07 * Y04 + B08 * Y03 + B09 * Y02 + B10 * Y01 + B11 * Y00
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
		buffer.writef64(Point, 104 + 0, (b00 - j00) + j11 * (19 / 2 ^ 255))
		buffer.writef64(Point, 104 + 8, (b01 - j01) + j00)
		buffer.writef64(Point, 104 + 16, (b02 - j02) + j01)
		buffer.writef64(Point, 104 + 24, (b03 - j03) + j02)
		buffer.writef64(Point, 104 + 32, (b04 - j04) + j03)
		buffer.writef64(Point, 104 + 40, (b05 - j05) + j04)
		buffer.writef64(Point, 104 + 48, (b06 - j06) + j05)
		buffer.writef64(Point, 104 + 56, (b07 - j07) + j06)
		buffer.writef64(Point, 104 + 64, (b08 - j08) + j07)
		buffer.writef64(Point, 104 + 72, (b09 - j09) + j08)
		buffer.writef64(Point, 104 + 80, (b10 - j10) + j09)
		buffer.writef64(Point, 104 + 88, (b11 - j11) + j10)
	end
	if not Point then return end
	do
		local c00 = (Z01 * B11 + Z02 * B10 + Z03 * B09 + Z04 * B08 + Z05 * B07 + Z06 * B06 + Z07 * B05 + Z08 * B04 + Z09 * B03 + Z10 * B02 + Z11 * B01) * (19 / 2 ^ 255) + (Z00 * B00)
		local c01 = (Z02 * B11 + Z03 * B10 + Z04 * B09 + Z05 * B08 + Z06 * B07 + Z07 * B06 + Z08 * B05 + Z09 * B04 + Z10 * B03 + Z11 * B02) * (19 / 2 ^ 255) + (Z00 * B01 + Z01 * B00)
		local c02 = (Z03 * B11 + Z04 * B10 + Z05 * B09 + Z06 * B08 + Z07 * B07 + Z08 * B06 + Z09 * B05 + Z10 * B04 + Z11 * B03) * (19 / 2 ^ 255) + (Z00 * B02 + Z01 * B01 + Z02 * B00)
		local c03 = (Z04 * B11 + Z05 * B10 + Z06 * B09 + Z07 * B08 + Z08 * B07 + Z09 * B06 + Z10 * B05 + Z11 * B04) * (19 / 2 ^ 255) + (Z00 * B03 + Z01 * B02 + Z02 * B01 + Z03 * B00)
		local c04 = (Z05 * B11 + Z06 * B10 + Z07 * B09 + Z08 * B08 + Z09 * B07 + Z10 * B06 + Z11 * B05) * (19 / 2 ^ 255) + (Z00 * B04 + Z01 * B03 + Z02 * B02 + Z03 * B01 + Z04 * B00)
		local c05 = (Z06 * B11 + Z07 * B10 + Z08 * B09 + Z09 * B08 + Z10 * B07 + Z11 * B06) * (19 / 2 ^ 255) + (Z00 * B05 + Z01 * B04 + Z02 * B03 + Z03 * B02 + Z04 * B01 + Z05 * B00)
		local c06 = (Z07 * B11 + Z08 * B10 + Z09 * B09 + Z10 * B08 + Z11 * B07) * (19 / 2 ^ 255) + (Z00 * B06 + Z01 * B05 + Z02 * B04 + Z03 * B03 + Z04 * B02 + Z05 * B01 + Z06 * B00)
		local c07 = (Z08 * B11 + Z09 * B10 + Z10 * B09 + Z11 * B08) * (19 / 2 ^ 255) + (Z00 * B07 + Z01 * B06 + Z02 * B05 + Z03 * B04 + Z04 * B03 + Z05 * B02 + Z06 * B01 + Z07 * B00)
		local c08 = (Z09 * B11 + Z10 * B10 + Z11 * B09) * (19 / 2 ^ 255) + (Z00 * B08 + Z01 * B07 + Z02 * B06 + Z03 * B05 + Z04 * B04 + Z05 * B03 + Z06 * B02 + Z07 * B01 + Z08 * B00)
		local c09 = (Z10 * B11 + Z11 * B10) * (19 / 2 ^ 255) + (Z00 * B09 + Z01 * B08 + Z02 * B07 + Z03 * B06 + Z04 * B05 + Z05 * B04 + Z06 * B03 + Z07 * B02 + Z08 * B01 + Z09 * B00)
		local c10 = (Z11 * B11) * (19 / 2 ^ 255) + (Z00 * B10 + Z01 * B09 + Z02 * B08 + Z03 * B07 + Z04 * B06 + Z05 * B05 + Z06 * B04 + Z07 * B03 + Z08 * B02 + Z09 * B01 + Z10 * B00)
		local c11 = Z00 * B11 + Z01 * B10 + Z02 * B09 + Z03 * B08 + Z04 * B07 + Z05 * B06 + Z06 * B05 + Z07 * B04 + Z08 * B03 + Z09 * B02 + Z10 * B01 + Z11 * B00
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
		buffer.writef64(Point, 208 + 0, (b00 - j00) + j11 * (19 / 2 ^ 255))
		buffer.writef64(Point, 208 + 8, (b01 - j01) + j00)
		buffer.writef64(Point, 208 + 16, (b02 - j02) + j01)
		buffer.writef64(Point, 208 + 24, (b03 - j03) + j02)
		buffer.writef64(Point, 208 + 32, (b04 - j04) + j03)
		buffer.writef64(Point, 208 + 40, (b05 - j05) + j04)
		buffer.writef64(Point, 208 + 48, (b06 - j06) + j05)
		buffer.writef64(Point, 208 + 56, (b07 - j07) + j06)
		buffer.writef64(Point, 208 + 64, (b08 - j08) + j07)
		buffer.writef64(Point, 208 + 72, (b09 - j09) + j08)
		buffer.writef64(Point, 208 + 80, (b10 - j10) + j09)
		buffer.writef64(Point, 208 + 88, (b11 - j11) + j10)
	end
	if not Point then return end
	if WithT then
		do
			local c00 = (X01 * Y11 + X02 * Y10 + X03 * Y09 + X04 * Y08 + X05 * Y07 + X06 * Y06 + X07 * Y05 + X08 * Y04 + X09 * Y03 + X10 * Y02 + X11 * Y01) * (19 / 2 ^ 255) + (X00 * Y00)
			local c01 = (X02 * Y11 + X03 * Y10 + X04 * Y09 + X05 * Y08 + X06 * Y07 + X07 * Y06 + X08 * Y05 + X09 * Y04 + X10 * Y03 + X11 * Y02) * (19 / 2 ^ 255) + (X00 * Y01 + X01 * Y00)
			local c02 = (X03 * Y11 + X04 * Y10 + X05 * Y09 + X06 * Y08 + X07 * Y07 + X08 * Y06 + X09 * Y05 + X10 * Y04 + X11 * Y03) * (19 / 2 ^ 255) + (X00 * Y02 + X01 * Y01 + X02 * Y00)
			local c03 = (X04 * Y11 + X05 * Y10 + X06 * Y09 + X07 * Y08 + X08 * Y07 + X09 * Y06 + X10 * Y05 + X11 * Y04) * (19 / 2 ^ 255) + (X00 * Y03 + X01 * Y02 + X02 * Y01 + X03 * Y00)
			local c04 = (X05 * Y11 + X06 * Y10 + X07 * Y09 + X08 * Y08 + X09 * Y07 + X10 * Y06 + X11 * Y05) * (19 / 2 ^ 255) + (X00 * Y04 + X01 * Y03 + X02 * Y02 + X03 * Y01 + X04 * Y00)
			local c05 = (X06 * Y11 + X07 * Y10 + X08 * Y09 + X09 * Y08 + X10 * Y07 + X11 * Y06) * (19 / 2 ^ 255) + (X00 * Y05 + X01 * Y04 + X02 * Y03 + X03 * Y02 + X04 * Y01 + X05 * Y00)
			local c06 = (X07 * Y11 + X08 * Y10 + X09 * Y09 + X10 * Y08 + X11 * Y07) * (19 / 2 ^ 255) + (X00 * Y06 + X01 * Y05 + X02 * Y04 + X03 * Y03 + X04 * Y02 + X05 * Y01 + X06 * Y00)
			local c07 = (X08 * Y11 + X09 * Y10 + X10 * Y09 + X11 * Y08) * (19 / 2 ^ 255) + (X00 * Y07 + X01 * Y06 + X02 * Y05 + X03 * Y04 + X04 * Y03 + X05 * Y02 + X06 * Y01 + X07 * Y00)
			local c08 = (X09 * Y11 + X10 * Y10 + X11 * Y09) * (19 / 2 ^ 255) + (X00 * Y08 + X01 * Y07 + X02 * Y06 + X03 * Y05 + X04 * Y04 + X05 * Y03 + X06 * Y02 + X07 * Y01 + X08 * Y00)
			local c09 = (X10 * Y11 + X11 * Y10) * (19 / 2 ^ 255) + (X00 * Y09 + X01 * Y08 + X02 * Y07 + X03 * Y06 + X04 * Y05 + X05 * Y04 + X06 * Y03 + X07 * Y02 + X08 * Y01 + X09 * Y00)
			local c10 = (X11 * Y11) * (19 / 2 ^ 255) + (X00 * Y10 + X01 * Y09 + X02 * Y08 + X03 * Y07 + X04 * Y06 + X05 * Y05 + X06 * Y04 + X07 * Y03 + X08 * Y02 + X09 * Y01 + X10 * Y00)
			local c11 = X00 * Y11 + X01 * Y10 + X02 * Y09 + X03 * Y08 + X04 * Y07 + X05 * Y06 + X06 * Y05 + X07 * Y04 + X08 * Y03 + X09 * Y02 + X10 * Y01 + X11 * Y00
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
			buffer.writef64(Point, 312 + 0, (b00 - j00) + j11 * (19 / 2 ^ 255))
			buffer.writef64(Point, 312 + 8, (b01 - j01) + j00)
			buffer.writef64(Point, 312 + 16, (b02 - j02) + j01)
			buffer.writef64(Point, 312 + 24, (b03 - j03) + j02)
			buffer.writef64(Point, 312 + 32, (b04 - j04) + j03)
			buffer.writef64(Point, 312 + 40, (b05 - j05) + j04)
			buffer.writef64(Point, 312 + 48, (b06 - j06) + j05)
			buffer.writef64(Point, 312 + 56, (b07 - j07) + j06)
			buffer.writef64(Point, 312 + 64, (b08 - j08) + j07)
			buffer.writef64(Point, 312 + 72, (b09 - j09) + j08)
			buffer.writef64(Point, 312 + 80, (b10 - j10) + j09)
			buffer.writef64(Point, 312 + 88, (b11 - j11) + j10)
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
	do
		local c00 = (A01 * N11 + A02 * N10 + A03 * N09 + A04 * N08 + A05 * N07 + A06 * N06 + A07 * N05 + A08 * N04 + A09 * N03 + A10 * N02 + A11 * N01) * (19 / 2 ^ 255) + (A00 * N00)
		local c01 = (A02 * N11 + A03 * N10 + A04 * N09 + A05 * N08 + A06 * N07 + A07 * N06 + A08 * N05 + A09 * N04 + A10 * N03 + A11 * N02) * (19 / 2 ^ 255) + (A00 * N01 + A01 * N00)
		local c02 = (A03 * N11 + A04 * N10 + A05 * N09 + A06 * N08 + A07 * N07 + A08 * N06 + A09 * N05 + A10 * N04 + A11 * N03) * (19 / 2 ^ 255) + (A00 * N02 + A01 * N01 + A02 * N00)
		local c03 = (A04 * N11 + A05 * N10 + A06 * N09 + A07 * N08 + A08 * N07 + A09 * N06 + A10 * N05 + A11 * N04) * (19 / 2 ^ 255) + (A00 * N03 + A01 * N02 + A02 * N01 + A03 * N00)
		local c04 = (A05 * N11 + A06 * N10 + A07 * N09 + A08 * N08 + A09 * N07 + A10 * N06 + A11 * N05) * (19 / 2 ^ 255) + (A00 * N04 + A01 * N03 + A02 * N02 + A03 * N01 + A04 * N00)
		local c05 = (A06 * N11 + A07 * N10 + A08 * N09 + A09 * N08 + A10 * N07 + A11 * N06) * (19 / 2 ^ 255) + (A00 * N05 + A01 * N04 + A02 * N03 + A03 * N02 + A04 * N01 + A05 * N00)
		local c06 = (A07 * N11 + A08 * N10 + A09 * N09 + A10 * N08 + A11 * N07) * (19 / 2 ^ 255) + (A00 * N06 + A01 * N05 + A02 * N04 + A03 * N03 + A04 * N02 + A05 * N01 + A06 * N00)
		local c07 = (A08 * N11 + A09 * N10 + A10 * N09 + A11 * N08) * (19 / 2 ^ 255) + (A00 * N07 + A01 * N06 + A02 * N05 + A03 * N04 + A04 * N03 + A05 * N02 + A06 * N01 + A07 * N00)
		local c08 = (A09 * N11 + A10 * N10 + A11 * N09) * (19 / 2 ^ 255) + (A00 * N08 + A01 * N07 + A02 * N06 + A03 * N05 + A04 * N04 + A05 * N03 + A06 * N02 + A07 * N01 + A08 * N00)
		local c09 = (A10 * N11 + A11 * N10) * (19 / 2 ^ 255) + (A00 * N09 + A01 * N08 + A02 * N07 + A03 * N06 + A04 * N05 + A05 * N04 + A06 * N03 + A07 * N02 + A08 * N01 + A09 * N00)
		local c10 = (A11 * N11) * (19 / 2 ^ 255) + (A00 * N10 + A01 * N09 + A02 * N08 + A03 * N07 + A04 * N06 + A05 * N05 + A06 * N04 + A07 * N03 + A08 * N02 + A09 * N01 + A10 * N00)
		local c11 = A00 * N11 + A01 * N10 + A02 * N09 + A03 * N08 + A04 * N07 + A05 * N06 + A06 * N05 + A07 * N04 + A08 * N03 + A09 * N02 + A10 * N01 + A11 * N00
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
		A00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		A01 = (b01 - j01) + j00
		A02 = (b02 - j02) + j01
		A03 = (b03 - j03) + j02
		A04 = (b04 - j04) + j03
		A05 = (b05 - j05) + j04
		A06 = (b06 - j06) + j05
		A07 = (b07 - j07) + j06
		A08 = (b08 - j08) + j07
		A09 = (b09 - j09) + j08
		A10 = (b10 - j10) + j09
		A11 = (b11 - j11) + j10
	end
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
	do
		local c00 = (Y01 * N11 + Y02 * N10 + Y03 * N09 + Y04 * N08 + Y05 * N07 + Y06 * N06 + Y07 * N05 + Y08 * N04 + Y09 * N03 + Y10 * N02 + Y11 * N01) * (19 / 2 ^ 255) + (Y00 * N00)
		local c01 = (Y02 * N11 + Y03 * N10 + Y04 * N09 + Y05 * N08 + Y06 * N07 + Y07 * N06 + Y08 * N05 + Y09 * N04 + Y10 * N03 + Y11 * N02) * (19 / 2 ^ 255) + (Y00 * N01 + Y01 * N00)
		local c02 = (Y03 * N11 + Y04 * N10 + Y05 * N09 + Y06 * N08 + Y07 * N07 + Y08 * N06 + Y09 * N05 + Y10 * N04 + Y11 * N03) * (19 / 2 ^ 255) + (Y00 * N02 + Y01 * N01 + Y02 * N00)
		local c03 = (Y04 * N11 + Y05 * N10 + Y06 * N09 + Y07 * N08 + Y08 * N07 + Y09 * N06 + Y10 * N05 + Y11 * N04) * (19 / 2 ^ 255) + (Y00 * N03 + Y01 * N02 + Y02 * N01 + Y03 * N00)
		local c04 = (Y05 * N11 + Y06 * N10 + Y07 * N09 + Y08 * N08 + Y09 * N07 + Y10 * N06 + Y11 * N05) * (19 / 2 ^ 255) + (Y00 * N04 + Y01 * N03 + Y02 * N02 + Y03 * N01 + Y04 * N00)
		local c05 = (Y06 * N11 + Y07 * N10 + Y08 * N09 + Y09 * N08 + Y10 * N07 + Y11 * N06) * (19 / 2 ^ 255) + (Y00 * N05 + Y01 * N04 + Y02 * N03 + Y03 * N02 + Y04 * N01 + Y05 * N00)
		local c06 = (Y07 * N11 + Y08 * N10 + Y09 * N09 + Y10 * N08 + Y11 * N07) * (19 / 2 ^ 255) + (Y00 * N06 + Y01 * N05 + Y02 * N04 + Y03 * N03 + Y04 * N02 + Y05 * N01 + Y06 * N00)
		local c07 = (Y08 * N11 + Y09 * N10 + Y10 * N09 + Y11 * N08) * (19 / 2 ^ 255) + (Y00 * N07 + Y01 * N06 + Y02 * N05 + Y03 * N04 + Y04 * N03 + Y05 * N02 + Y06 * N01 + Y07 * N00)
		local c08 = (Y09 * N11 + Y10 * N10 + Y11 * N09) * (19 / 2 ^ 255) + (Y00 * N08 + Y01 * N07 + Y02 * N06 + Y03 * N05 + Y04 * N04 + Y05 * N03 + Y06 * N02 + Y07 * N01 + Y08 * N00)
		local c09 = (Y10 * N11 + Y11 * N10) * (19 / 2 ^ 255) + (Y00 * N09 + Y01 * N08 + Y02 * N07 + Y03 * N06 + Y04 * N05 + Y05 * N04 + Y06 * N03 + Y07 * N02 + Y08 * N01 + Y09 * N00)
		local c10 = (Y11 * N11) * (19 / 2 ^ 255) + (Y00 * N10 + Y01 * N09 + Y02 * N08 + Y03 * N07 + Y04 * N06 + Y05 * N05 + Y06 * N04 + Y07 * N03 + Y08 * N02 + Y09 * N01 + Y10 * N00)
		local c11 = Y00 * N11 + Y01 * N10 + Y02 * N09 + Y03 * N08 + Y04 * N07 + Y05 * N06 + Y06 * N05 + Y07 * N04 + Y08 * N03 + Y09 * N02 + Y10 * N01 + Y11 * N00
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
		Y00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		Y01 = (b01 - j01) + j00
		Y02 = (b02 - j02) + j01
		Y03 = (b03 - j03) + j02
		Y04 = (b04 - j04) + j03
		Y05 = (b05 - j05) + j04
		Y06 = (b06 - j06) + j05
		Y07 = (b07 - j07) + j06
		Y08 = (b08 - j08) + j07
		Y09 = (b09 - j09) + j08
		Y10 = (b10 - j10) + j09
		Y11 = (b11 - j11) + j10
	end
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
	do
		local c00 = (T01 * N11 + T02 * N10 + T03 * N09 + T04 * N08 + T05 * N07 + T06 * N06 + T07 * N05 + T08 * N04 + T09 * N03 + T10 * N02 + T11 * N01) * (19 / 2 ^ 255) + (T00 * N00)
		local c01 = (T02 * N11 + T03 * N10 + T04 * N09 + T05 * N08 + T06 * N07 + T07 * N06 + T08 * N05 + T09 * N04 + T10 * N03 + T11 * N02) * (19 / 2 ^ 255) + (T00 * N01 + T01 * N00)
		local c02 = (T03 * N11 + T04 * N10 + T05 * N09 + T06 * N08 + T07 * N07 + T08 * N06 + T09 * N05 + T10 * N04 + T11 * N03) * (19 / 2 ^ 255) + (T00 * N02 + T01 * N01 + T02 * N00)
		local c03 = (T04 * N11 + T05 * N10 + T06 * N09 + T07 * N08 + T08 * N07 + T09 * N06 + T10 * N05 + T11 * N04) * (19 / 2 ^ 255) + (T00 * N03 + T01 * N02 + T02 * N01 + T03 * N00)
		local c04 = (T05 * N11 + T06 * N10 + T07 * N09 + T08 * N08 + T09 * N07 + T10 * N06 + T11 * N05) * (19 / 2 ^ 255) + (T00 * N04 + T01 * N03 + T02 * N02 + T03 * N01 + T04 * N00)
		local c05 = (T06 * N11 + T07 * N10 + T08 * N09 + T09 * N08 + T10 * N07 + T11 * N06) * (19 / 2 ^ 255) + (T00 * N05 + T01 * N04 + T02 * N03 + T03 * N02 + T04 * N01 + T05 * N00)
		local c06 = (T07 * N11 + T08 * N10 + T09 * N09 + T10 * N08 + T11 * N07) * (19 / 2 ^ 255) + (T00 * N06 + T01 * N05 + T02 * N04 + T03 * N03 + T04 * N02 + T05 * N01 + T06 * N00)
		local c07 = (T08 * N11 + T09 * N10 + T10 * N09 + T11 * N08) * (19 / 2 ^ 255) + (T00 * N07 + T01 * N06 + T02 * N05 + T03 * N04 + T04 * N03 + T05 * N02 + T06 * N01 + T07 * N00)
		local c08 = (T09 * N11 + T10 * N10 + T11 * N09) * (19 / 2 ^ 255) + (T00 * N08 + T01 * N07 + T02 * N06 + T03 * N05 + T04 * N04 + T05 * N03 + T06 * N02 + T07 * N01 + T08 * N00)
		local c09 = (T10 * N11 + T11 * N10) * (19 / 2 ^ 255) + (T00 * N09 + T01 * N08 + T02 * N07 + T03 * N06 + T04 * N05 + T05 * N04 + T06 * N03 + T07 * N02 + T08 * N01 + T09 * N00)
		local c10 = (T11 * N11) * (19 / 2 ^ 255) + (T00 * N10 + T01 * N09 + T02 * N08 + T03 * N07 + T04 * N06 + T05 * N05 + T06 * N04 + T07 * N03 + T08 * N02 + T09 * N01 + T10 * N00)
		local c11 = T00 * N11 + T01 * N10 + T02 * N09 + T03 * N08 + T04 * N07 + T05 * N06 + T06 * N05 + T07 * N04 + T08 * N03 + T09 * N02 + T10 * N01 + T11 * N00
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
		T00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		T01 = (b01 - j01) + j00
		T02 = (b02 - j02) + j01
		T03 = (b03 - j03) + j02
		T04 = (b04 - j04) + j03
		T05 = (b05 - j05) + j04
		T06 = (b06 - j06) + j05
		T07 = (b07 - j07) + j06
		T08 = (b08 - j08) + j07
		T09 = (b09 - j09) + j08
		T10 = (b10 - j10) + j09
		T11 = (b11 - j11) + j10
	end
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
		do
			local c00 = (Z01 * N11 + Z02 * N10 + Z03 * N09 + Z04 * N08 + Z05 * N07 + Z06 * N06 + Z07 * N05 + Z08 * N04 + Z09 * N03 + Z10 * N02 + Z11 * N01) * (19 / 2 ^ 255) + (Z00 * N00)
			local c01 = (Z02 * N11 + Z03 * N10 + Z04 * N09 + Z05 * N08 + Z06 * N07 + Z07 * N06 + Z08 * N05 + Z09 * N04 + Z10 * N03 + Z11 * N02) * (19 / 2 ^ 255) + (Z00 * N01 + Z01 * N00)
			local c02 = (Z03 * N11 + Z04 * N10 + Z05 * N09 + Z06 * N08 + Z07 * N07 + Z08 * N06 + Z09 * N05 + Z10 * N04 + Z11 * N03) * (19 / 2 ^ 255) + (Z00 * N02 + Z01 * N01 + Z02 * N00)
			local c03 = (Z04 * N11 + Z05 * N10 + Z06 * N09 + Z07 * N08 + Z08 * N07 + Z09 * N06 + Z10 * N05 + Z11 * N04) * (19 / 2 ^ 255) + (Z00 * N03 + Z01 * N02 + Z02 * N01 + Z03 * N00)
			local c04 = (Z05 * N11 + Z06 * N10 + Z07 * N09 + Z08 * N08 + Z09 * N07 + Z10 * N06 + Z11 * N05) * (19 / 2 ^ 255) + (Z00 * N04 + Z01 * N03 + Z02 * N02 + Z03 * N01 + Z04 * N00)
			local c05 = (Z06 * N11 + Z07 * N10 + Z08 * N09 + Z09 * N08 + Z10 * N07 + Z11 * N06) * (19 / 2 ^ 255) + (Z00 * N05 + Z01 * N04 + Z02 * N03 + Z03 * N02 + Z04 * N01 + Z05 * N00)
			local c06 = (Z07 * N11 + Z08 * N10 + Z09 * N09 + Z10 * N08 + Z11 * N07) * (19 / 2 ^ 255) + (Z00 * N06 + Z01 * N05 + Z02 * N04 + Z03 * N03 + Z04 * N02 + Z05 * N01 + Z06 * N00)
			local c07 = (Z08 * N11 + Z09 * N10 + Z10 * N09 + Z11 * N08) * (19 / 2 ^ 255) + (Z00 * N07 + Z01 * N06 + Z02 * N05 + Z03 * N04 + Z04 * N03 + Z05 * N02 + Z06 * N01 + Z07 * N00)
			local c08 = (Z09 * N11 + Z10 * N10 + Z11 * N09) * (19 / 2 ^ 255) + (Z00 * N08 + Z01 * N07 + Z02 * N06 + Z03 * N05 + Z04 * N04 + Z05 * N03 + Z06 * N02 + Z07 * N01 + Z08 * N00)
			local c09 = (Z10 * N11 + Z11 * N10) * (19 / 2 ^ 255) + (Z00 * N09 + Z01 * N08 + Z02 * N07 + Z03 * N06 + Z04 * N05 + Z05 * N04 + Z06 * N03 + Z07 * N02 + Z08 * N01 + Z09 * N00)
			local c10 = (Z11 * N11) * (19 / 2 ^ 255) + (Z00 * N10 + Z01 * N09 + Z02 * N08 + Z03 * N07 + Z04 * N06 + Z05 * N05 + Z06 * N04 + Z07 * N03 + Z08 * N02 + Z09 * N01 + Z10 * N00)
			local c11 = Z00 * N11 + Z01 * N10 + Z02 * N09 + Z03 * N08 + Z04 * N07 + Z05 * N06 + Z06 * N05 + Z07 * N04 + Z08 * N03 + Z09 * N02 + Z10 * N01 + Z11 * N00
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
		local c00 = (X01 * N11 + X02 * N10 + X03 * N09 + X04 * N08 + X05 * N07 + X06 * N06 + X07 * N05 + X08 * N04 + X09 * N03 + X10 * N02 + X11 * N01) * (19 / 2 ^ 255) + (X00 * N00)
		local c01 = (X02 * N11 + X03 * N10 + X04 * N09 + X05 * N08 + X06 * N07 + X07 * N06 + X08 * N05 + X09 * N04 + X10 * N03 + X11 * N02) * (19 / 2 ^ 255) + (X00 * N01 + X01 * N00)
		local c02 = (X03 * N11 + X04 * N10 + X05 * N09 + X06 * N08 + X07 * N07 + X08 * N06 + X09 * N05 + X10 * N04 + X11 * N03) * (19 / 2 ^ 255) + (X00 * N02 + X01 * N01 + X02 * N00)
		local c03 = (X04 * N11 + X05 * N10 + X06 * N09 + X07 * N08 + X08 * N07 + X09 * N06 + X10 * N05 + X11 * N04) * (19 / 2 ^ 255) + (X00 * N03 + X01 * N02 + X02 * N01 + X03 * N00)
		local c04 = (X05 * N11 + X06 * N10 + X07 * N09 + X08 * N08 + X09 * N07 + X10 * N06 + X11 * N05) * (19 / 2 ^ 255) + (X00 * N04 + X01 * N03 + X02 * N02 + X03 * N01 + X04 * N00)
		local c05 = (X06 * N11 + X07 * N10 + X08 * N09 + X09 * N08 + X10 * N07 + X11 * N06) * (19 / 2 ^ 255) + (X00 * N05 + X01 * N04 + X02 * N03 + X03 * N02 + X04 * N01 + X05 * N00)
		local c06 = (X07 * N11 + X08 * N10 + X09 * N09 + X10 * N08 + X11 * N07) * (19 / 2 ^ 255) + (X00 * N06 + X01 * N05 + X02 * N04 + X03 * N03 + X04 * N02 + X05 * N01 + X06 * N00)
		local c07 = (X08 * N11 + X09 * N10 + X10 * N09 + X11 * N08) * (19 / 2 ^ 255) + (X00 * N07 + X01 * N06 + X02 * N05 + X03 * N04 + X04 * N03 + X05 * N02 + X06 * N01 + X07 * N00)
		local c08 = (X09 * N11 + X10 * N10 + X11 * N09) * (19 / 2 ^ 255) + (X00 * N08 + X01 * N07 + X02 * N06 + X03 * N05 + X04 * N04 + X05 * N03 + X06 * N02 + X07 * N01 + X08 * N00)
		local c09 = (X10 * N11 + X11 * N10) * (19 / 2 ^ 255) + (X00 * N09 + X01 * N08 + X02 * N07 + X03 * N06 + X04 * N05 + X05 * N04 + X06 * N03 + X07 * N02 + X08 * N01 + X09 * N00)
		local c10 = (X11 * N11) * (19 / 2 ^ 255) + (X00 * N10 + X01 * N09 + X02 * N08 + X03 * N07 + X04 * N06 + X05 * N05 + X06 * N04 + X07 * N03 + X08 * N02 + X09 * N01 + X10 * N00)
		local c11 = X00 * N11 + X01 * N10 + X02 * N09 + X03 * N08 + X04 * N07 + X05 * N06 + X06 * N05 + X07 * N04 + X08 * N03 + X09 * N02 + X10 * N01 + X11 * N00
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
		buffer.writef64(Point, 0 + 0, (b00 - j00) + j11 * (19 / 2 ^ 255))
		buffer.writef64(Point, 0 + 8, (b01 - j01) + j00)
		buffer.writef64(Point, 0 + 16, (b02 - j02) + j01)
		buffer.writef64(Point, 0 + 24, (b03 - j03) + j02)
		buffer.writef64(Point, 0 + 32, (b04 - j04) + j03)
		buffer.writef64(Point, 0 + 40, (b05 - j05) + j04)
		buffer.writef64(Point, 0 + 48, (b06 - j06) + j05)
		buffer.writef64(Point, 0 + 56, (b07 - j07) + j06)
		buffer.writef64(Point, 0 + 64, (b08 - j08) + j07)
		buffer.writef64(Point, 0 + 72, (b09 - j09) + j08)
		buffer.writef64(Point, 0 + 80, (b10 - j10) + j09)
		buffer.writef64(Point, 0 + 88, (b11 - j11) + j10)
	end
	if PlusOffset < 0 then return end
	do
		local c00 = (Z01 * Y11 + Z02 * Y10 + Z03 * Y09 + Z04 * Y08 + Z05 * Y07 + Z06 * Y06 + Z07 * Y05 + Z08 * Y04 + Z09 * Y03 + Z10 * Y02 + Z11 * Y01) * (19 / 2 ^ 255) + (Z00 * Y00)
		local c01 = (Z02 * Y11 + Z03 * Y10 + Z04 * Y09 + Z05 * Y08 + Z06 * Y07 + Z07 * Y06 + Z08 * Y05 + Z09 * Y04 + Z10 * Y03 + Z11 * Y02) * (19 / 2 ^ 255) + (Z00 * Y01 + Z01 * Y00)
		local c02 = (Z03 * Y11 + Z04 * Y10 + Z05 * Y09 + Z06 * Y08 + Z07 * Y07 + Z08 * Y06 + Z09 * Y05 + Z10 * Y04 + Z11 * Y03) * (19 / 2 ^ 255) + (Z00 * Y02 + Z01 * Y01 + Z02 * Y00)
		local c03 = (Z04 * Y11 + Z05 * Y10 + Z06 * Y09 + Z07 * Y08 + Z08 * Y07 + Z09 * Y06 + Z10 * Y05 + Z11 * Y04) * (19 / 2 ^ 255) + (Z00 * Y03 + Z01 * Y02 + Z02 * Y01 + Z03 * Y00)
		local c04 = (Z05 * Y11 + Z06 * Y10 + Z07 * Y09 + Z08 * Y08 + Z09 * Y07 + Z10 * Y06 + Z11 * Y05) * (19 / 2 ^ 255) + (Z00 * Y04 + Z01 * Y03 + Z02 * Y02 + Z03 * Y01 + Z04 * Y00)
		local c05 = (Z06 * Y11 + Z07 * Y10 + Z08 * Y09 + Z09 * Y08 + Z10 * Y07 + Z11 * Y06) * (19 / 2 ^ 255) + (Z00 * Y05 + Z01 * Y04 + Z02 * Y03 + Z03 * Y02 + Z04 * Y01 + Z05 * Y00)
		local c06 = (Z07 * Y11 + Z08 * Y10 + Z09 * Y09 + Z10 * Y08 + Z11 * Y07) * (19 / 2 ^ 255) + (Z00 * Y06 + Z01 * Y05 + Z02 * Y04 + Z03 * Y03 + Z04 * Y02 + Z05 * Y01 + Z06 * Y00)
		local c07 = (Z08 * Y11 + Z09 * Y10 + Z10 * Y09 + Z11 * Y08) * (19 / 2 ^ 255) + (Z00 * Y07 + Z01 * Y06 + Z02 * Y05 + Z03 * Y04 + Z04 * Y03 + Z05 * Y02 + Z06 * Y01 + Z07 * Y00)
		local c08 = (Z09 * Y11 + Z10 * Y10 + Z11 * Y09) * (19 / 2 ^ 255) + (Z00 * Y08 + Z01 * Y07 + Z02 * Y06 + Z03 * Y05 + Z04 * Y04 + Z05 * Y03 + Z06 * Y02 + Z07 * Y01 + Z08 * Y00)
		local c09 = (Z10 * Y11 + Z11 * Y10) * (19 / 2 ^ 255) + (Z00 * Y09 + Z01 * Y08 + Z02 * Y07 + Z03 * Y06 + Z04 * Y05 + Z05 * Y04 + Z06 * Y03 + Z07 * Y02 + Z08 * Y01 + Z09 * Y00)
		local c10 = (Z11 * Y11) * (19 / 2 ^ 255) + (Z00 * Y10 + Z01 * Y09 + Z02 * Y08 + Z03 * Y07 + Z04 * Y06 + Z05 * Y05 + Z06 * Y04 + Z07 * Y03 + Z08 * Y02 + Z09 * Y01 + Z10 * Y00)
		local c11 = Z00 * Y11 + Z01 * Y10 + Z02 * Y09 + Z03 * Y08 + Z04 * Y07 + Z05 * Y06 + Z06 * Y05 + Z07 * Y04 + Z08 * Y03 + Z09 * Y02 + Z10 * Y01 + Z11 * Y00
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
		buffer.writef64(Point, 104 + 0, (b00 - j00) + j11 * (19 / 2 ^ 255))
		buffer.writef64(Point, 104 + 8, (b01 - j01) + j00)
		buffer.writef64(Point, 104 + 16, (b02 - j02) + j01)
		buffer.writef64(Point, 104 + 24, (b03 - j03) + j02)
		buffer.writef64(Point, 104 + 32, (b04 - j04) + j03)
		buffer.writef64(Point, 104 + 40, (b05 - j05) + j04)
		buffer.writef64(Point, 104 + 48, (b06 - j06) + j05)
		buffer.writef64(Point, 104 + 56, (b07 - j07) + j06)
		buffer.writef64(Point, 104 + 64, (b08 - j08) + j07)
		buffer.writef64(Point, 104 + 72, (b09 - j09) + j08)
		buffer.writef64(Point, 104 + 80, (b10 - j10) + j09)
		buffer.writef64(Point, 104 + 88, (b11 - j11) + j10)
	end
	if PlusOffset < 0 then return end
	do
		local c00 = (N01 * Z11 + N02 * Z10 + N03 * Z09 + N04 * Z08 + N05 * Z07 + N06 * Z06 + N07 * Z05 + N08 * Z04 + N09 * Z03 + N10 * Z02 + N11 * Z01) * (19 / 2 ^ 255) + (N00 * Z00)
		local c01 = (N02 * Z11 + N03 * Z10 + N04 * Z09 + N05 * Z08 + N06 * Z07 + N07 * Z06 + N08 * Z05 + N09 * Z04 + N10 * Z03 + N11 * Z02) * (19 / 2 ^ 255) + (N00 * Z01 + N01 * Z00)
		local c02 = (N03 * Z11 + N04 * Z10 + N05 * Z09 + N06 * Z08 + N07 * Z07 + N08 * Z06 + N09 * Z05 + N10 * Z04 + N11 * Z03) * (19 / 2 ^ 255) + (N00 * Z02 + N01 * Z01 + N02 * Z00)
		local c03 = (N04 * Z11 + N05 * Z10 + N06 * Z09 + N07 * Z08 + N08 * Z07 + N09 * Z06 + N10 * Z05 + N11 * Z04) * (19 / 2 ^ 255) + (N00 * Z03 + N01 * Z02 + N02 * Z01 + N03 * Z00)
		local c04 = (N05 * Z11 + N06 * Z10 + N07 * Z09 + N08 * Z08 + N09 * Z07 + N10 * Z06 + N11 * Z05) * (19 / 2 ^ 255) + (N00 * Z04 + N01 * Z03 + N02 * Z02 + N03 * Z01 + N04 * Z00)
		local c05 = (N06 * Z11 + N07 * Z10 + N08 * Z09 + N09 * Z08 + N10 * Z07 + N11 * Z06) * (19 / 2 ^ 255) + (N00 * Z05 + N01 * Z04 + N02 * Z03 + N03 * Z02 + N04 * Z01 + N05 * Z00)
		local c06 = (N07 * Z11 + N08 * Z10 + N09 * Z09 + N10 * Z08 + N11 * Z07) * (19 / 2 ^ 255) + (N00 * Z06 + N01 * Z05 + N02 * Z04 + N03 * Z03 + N04 * Z02 + N05 * Z01 + N06 * Z00)
		local c07 = (N08 * Z11 + N09 * Z10 + N10 * Z09 + N11 * Z08) * (19 / 2 ^ 255) + (N00 * Z07 + N01 * Z06 + N02 * Z05 + N03 * Z04 + N04 * Z03 + N05 * Z02 + N06 * Z01 + N07 * Z00)
		local c08 = (N09 * Z11 + N10 * Z10 + N11 * Z09) * (19 / 2 ^ 255) + (N00 * Z08 + N01 * Z07 + N02 * Z06 + N03 * Z05 + N04 * Z04 + N05 * Z03 + N06 * Z02 + N07 * Z01 + N08 * Z00)
		local c09 = (N10 * Z11 + N11 * Z10) * (19 / 2 ^ 255) + (N00 * Z09 + N01 * Z08 + N02 * Z07 + N03 * Z06 + N04 * Z05 + N05 * Z04 + N06 * Z03 + N07 * Z02 + N08 * Z01 + N09 * Z00)
		local c10 = (N11 * Z11) * (19 / 2 ^ 255) + (N00 * Z10 + N01 * Z09 + N02 * Z08 + N03 * Z07 + N04 * Z06 + N05 * Z05 + N06 * Z04 + N07 * Z03 + N08 * Z02 + N09 * Z01 + N10 * Z00)
		local c11 = N00 * Z11 + N01 * Z10 + N02 * Z09 + N03 * Z08 + N04 * Z07 + N05 * Z06 + N06 * Z05 + N07 * Z04 + N08 * Z03 + N09 * Z02 + N10 * Z01 + N11 * Z00
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
		buffer.writef64(Point, 208 + 0, (b00 - j00) + j11 * (19 / 2 ^ 255))
		buffer.writef64(Point, 208 + 8, (b01 - j01) + j00)
		buffer.writef64(Point, 208 + 16, (b02 - j02) + j01)
		buffer.writef64(Point, 208 + 24, (b03 - j03) + j02)
		buffer.writef64(Point, 208 + 32, (b04 - j04) + j03)
		buffer.writef64(Point, 208 + 40, (b05 - j05) + j04)
		buffer.writef64(Point, 208 + 48, (b06 - j06) + j05)
		buffer.writef64(Point, 208 + 56, (b07 - j07) + j06)
		buffer.writef64(Point, 208 + 64, (b08 - j08) + j07)
		buffer.writef64(Point, 208 + 72, (b09 - j09) + j08)
		buffer.writef64(Point, 208 + 80, (b10 - j10) + j09)
		buffer.writef64(Point, 208 + 88, (b11 - j11) + j10)
	end
	if PlusOffset < 0 then return end
	do
		local c00 = (X01 * Y11 + X02 * Y10 + X03 * Y09 + X04 * Y08 + X05 * Y07 + X06 * Y06 + X07 * Y05 + X08 * Y04 + X09 * Y03 + X10 * Y02 + X11 * Y01) * (19 / 2 ^ 255) + (X00 * Y00)
		local c01 = (X02 * Y11 + X03 * Y10 + X04 * Y09 + X05 * Y08 + X06 * Y07 + X07 * Y06 + X08 * Y05 + X09 * Y04 + X10 * Y03 + X11 * Y02) * (19 / 2 ^ 255) + (X00 * Y01 + X01 * Y00)
		local c02 = (X03 * Y11 + X04 * Y10 + X05 * Y09 + X06 * Y08 + X07 * Y07 + X08 * Y06 + X09 * Y05 + X10 * Y04 + X11 * Y03) * (19 / 2 ^ 255) + (X00 * Y02 + X01 * Y01 + X02 * Y00)
		local c03 = (X04 * Y11 + X05 * Y10 + X06 * Y09 + X07 * Y08 + X08 * Y07 + X09 * Y06 + X10 * Y05 + X11 * Y04) * (19 / 2 ^ 255) + (X00 * Y03 + X01 * Y02 + X02 * Y01 + X03 * Y00)
		local c04 = (X05 * Y11 + X06 * Y10 + X07 * Y09 + X08 * Y08 + X09 * Y07 + X10 * Y06 + X11 * Y05) * (19 / 2 ^ 255) + (X00 * Y04 + X01 * Y03 + X02 * Y02 + X03 * Y01 + X04 * Y00)
		local c05 = (X06 * Y11 + X07 * Y10 + X08 * Y09 + X09 * Y08 + X10 * Y07 + X11 * Y06) * (19 / 2 ^ 255) + (X00 * Y05 + X01 * Y04 + X02 * Y03 + X03 * Y02 + X04 * Y01 + X05 * Y00)
		local c06 = (X07 * Y11 + X08 * Y10 + X09 * Y09 + X10 * Y08 + X11 * Y07) * (19 / 2 ^ 255) + (X00 * Y06 + X01 * Y05 + X02 * Y04 + X03 * Y03 + X04 * Y02 + X05 * Y01 + X06 * Y00)
		local c07 = (X08 * Y11 + X09 * Y10 + X10 * Y09 + X11 * Y08) * (19 / 2 ^ 255) + (X00 * Y07 + X01 * Y06 + X02 * Y05 + X03 * Y04 + X04 * Y03 + X05 * Y02 + X06 * Y01 + X07 * Y00)
		local c08 = (X09 * Y11 + X10 * Y10 + X11 * Y09) * (19 / 2 ^ 255) + (X00 * Y08 + X01 * Y07 + X02 * Y06 + X03 * Y05 + X04 * Y04 + X05 * Y03 + X06 * Y02 + X07 * Y01 + X08 * Y00)
		local c09 = (X10 * Y11 + X11 * Y10) * (19 / 2 ^ 255) + (X00 * Y09 + X01 * Y08 + X02 * Y07 + X03 * Y06 + X04 * Y05 + X05 * Y04 + X06 * Y03 + X07 * Y02 + X08 * Y01 + X09 * Y00)
		local c10 = (X11 * Y11) * (19 / 2 ^ 255) + (X00 * Y10 + X01 * Y09 + X02 * Y08 + X03 * Y07 + X04 * Y06 + X05 * Y05 + X06 * Y04 + X07 * Y03 + X08 * Y02 + X09 * Y01 + X10 * Y00)
		local c11 = X00 * Y11 + X01 * Y10 + X02 * Y09 + X03 * Y08 + X04 * Y07 + X05 * Y06 + X06 * Y05 + X07 * Y04 + X08 * Y03 + X09 * Y02 + X10 * Y01 + X11 * Y00
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
		buffer.writef64(Point, 312 + 0, (b00 - j00) + j11 * (19 / 2 ^ 255))
		buffer.writef64(Point, 312 + 8, (b01 - j01) + j00)
		buffer.writef64(Point, 312 + 16, (b02 - j02) + j01)
		buffer.writef64(Point, 312 + 24, (b03 - j03) + j02)
		buffer.writef64(Point, 312 + 32, (b04 - j04) + j03)
		buffer.writef64(Point, 312 + 40, (b05 - j05) + j04)
		buffer.writef64(Point, 312 + 48, (b06 - j06) + j05)
		buffer.writef64(Point, 312 + 56, (b07 - j07) + j06)
		buffer.writef64(Point, 312 + 64, (b08 - j08) + j07)
		buffer.writef64(Point, 312 + 72, (b09 - j09) + j08)
		buffer.writef64(Point, 312 + 80, (b10 - j10) + j09)
		buffer.writef64(Point, 312 + 88, (b11 - j11) + j10)
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
