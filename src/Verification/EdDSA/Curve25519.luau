--[=[
	Cryptography library: Curve25519 Montgomery

	Example usage:
		-- Point multiplication
		local BasePoint = Curve25519.G
		local Result = Curve25519.Ladder(BasePoint, ScalarBits, BitCount)

		-- Decode a public key
		local DecodedPoint = Curve25519.Decode(EncodedBytes)
--]=]

--!strict
--!optimize 2
--!native

local FieldPrime = require("./FieldPrime")
local Curve25519 = {}

local COORD_SIZE = 104
local MONTGOMERY_POINT_SIZE = 2 * COORD_SIZE

local LADDER_STATE = buffer.create(4 * COORD_SIZE)
local DIFF_X = buffer.create(COORD_SIZE)
local DIFF_Z = buffer.create(COORD_SIZE)
local ONE = FieldPrime.Num(1)

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

local function LadderStep(State: buffer, DiffX: buffer, DiffZ: buffer, Swap: number, UnitZ: boolean)
	local P00 = buffer.readf64(State, 0)
	local Q00 = buffer.readf64(State, 208)
	local WP00 = Swap * (Q00 - P00)
	P00 += WP00
	Q00 -= WP00
	local P01 = buffer.readf64(State, 8)
	local Q01 = buffer.readf64(State, 216)
	local WP01 = Swap * (Q01 - P01)
	P01 += WP01
	Q01 -= WP01
	local P02 = buffer.readf64(State, 16)
	local Q02 = buffer.readf64(State, 224)
	local WP02 = Swap * (Q02 - P02)
	P02 += WP02
	Q02 -= WP02
	local P03 = buffer.readf64(State, 24)
	local Q03 = buffer.readf64(State, 232)
	local WP03 = Swap * (Q03 - P03)
	P03 += WP03
	Q03 -= WP03
	local P04 = buffer.readf64(State, 32)
	local Q04 = buffer.readf64(State, 240)
	local WP04 = Swap * (Q04 - P04)
	P04 += WP04
	Q04 -= WP04
	local P05 = buffer.readf64(State, 40)
	local Q05 = buffer.readf64(State, 248)
	local WP05 = Swap * (Q05 - P05)
	P05 += WP05
	Q05 -= WP05
	local P06 = buffer.readf64(State, 48)
	local Q06 = buffer.readf64(State, 256)
	local WP06 = Swap * (Q06 - P06)
	P06 += WP06
	Q06 -= WP06
	local P07 = buffer.readf64(State, 56)
	local Q07 = buffer.readf64(State, 264)
	local WP07 = Swap * (Q07 - P07)
	P07 += WP07
	Q07 -= WP07
	local P08 = buffer.readf64(State, 64)
	local Q08 = buffer.readf64(State, 272)
	local WP08 = Swap * (Q08 - P08)
	P08 += WP08
	Q08 -= WP08
	local P09 = buffer.readf64(State, 72)
	local Q09 = buffer.readf64(State, 280)
	local WP09 = Swap * (Q09 - P09)
	P09 += WP09
	Q09 -= WP09
	local P10 = buffer.readf64(State, 80)
	local Q10 = buffer.readf64(State, 288)
	local WP10 = Swap * (Q10 - P10)
	P10 += WP10
	Q10 -= WP10
	local P11 = buffer.readf64(State, 88)
	local Q11 = buffer.readf64(State, 296)
	local WP11 = Swap * (Q11 - P11)
	P11 += WP11
	Q11 -= WP11
	local R00 = buffer.readf64(State, 104)
	local U00 = buffer.readf64(State, 312)
	local WR00 = Swap * (U00 - R00)
	R00 += WR00
	U00 -= WR00
	local R01 = buffer.readf64(State, 112)
	local U01 = buffer.readf64(State, 320)
	local WR01 = Swap * (U01 - R01)
	R01 += WR01
	U01 -= WR01
	local R02 = buffer.readf64(State, 120)
	local U02 = buffer.readf64(State, 328)
	local WR02 = Swap * (U02 - R02)
	R02 += WR02
	U02 -= WR02
	local R03 = buffer.readf64(State, 128)
	local U03 = buffer.readf64(State, 336)
	local WR03 = Swap * (U03 - R03)
	R03 += WR03
	U03 -= WR03
	local R04 = buffer.readf64(State, 136)
	local U04 = buffer.readf64(State, 344)
	local WR04 = Swap * (U04 - R04)
	R04 += WR04
	U04 -= WR04
	local R05 = buffer.readf64(State, 144)
	local U05 = buffer.readf64(State, 352)
	local WR05 = Swap * (U05 - R05)
	R05 += WR05
	U05 -= WR05
	local R06 = buffer.readf64(State, 152)
	local U06 = buffer.readf64(State, 360)
	local WR06 = Swap * (U06 - R06)
	R06 += WR06
	U06 -= WR06
	local R07 = buffer.readf64(State, 160)
	local U07 = buffer.readf64(State, 368)
	local WR07 = Swap * (U07 - R07)
	R07 += WR07
	U07 -= WR07
	local R08 = buffer.readf64(State, 168)
	local U08 = buffer.readf64(State, 376)
	local WR08 = Swap * (U08 - R08)
	R08 += WR08
	U08 -= WR08
	local R09 = buffer.readf64(State, 176)
	local U09 = buffer.readf64(State, 384)
	local WR09 = Swap * (U09 - R09)
	R09 += WR09
	U09 -= WR09
	local R10 = buffer.readf64(State, 184)
	local U10 = buffer.readf64(State, 392)
	local WR10 = Swap * (U10 - R10)
	R10 += WR10
	U10 -= WR10
	local R11 = buffer.readf64(State, 192)
	local U11 = buffer.readf64(State, 400)
	local WR11 = Swap * (U11 - R11)
	R11 += WR11
	U11 -= WR11
	local A00 = P00 + R00
	local A01 = P01 + R01
	local A02 = P02 + R02
	local A03 = P03 + R03
	local A04 = P04 + R04
	local A05 = P05 + R05
	local A06 = P06 + R06
	local A07 = P07 + R07
	local A08 = P08 + R08
	local A09 = P09 + R09
	local A10 = P10 + R10
	local A11 = P11 + R11
	local B00 = P00 - R00
	local B01 = P01 - R01
	local B02 = P02 - R02
	local B03 = P03 - R03
	local B04 = P04 - R04
	local B05 = P05 - R05
	local B06 = P06 - R06
	local B07 = P07 - R07
	local B08 = P08 - R08
	local B09 = P09 - R09
	local B10 = P10 - R10
	local B11 = P11 - R11
	local AA00, AA01, AA02, AA03, AA04, AA05, AA06, AA07, AA08, AA09, AA10, AA11 = FieldSquare(A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11)
	if Swap < 0 then return end
	local BB00, BB01, BB02, BB03, BB04, BB05, BB06, BB07, BB08, BB09, BB10, BB11 = FieldSquare(B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11)
	if Swap < 0 then return end
	local C00 = Q00 + U00
	local C01 = Q01 + U01
	local C02 = Q02 + U02
	local C03 = Q03 + U03
	local C04 = Q04 + U04
	local C05 = Q05 + U05
	local C06 = Q06 + U06
	local C07 = Q07 + U07
	local C08 = Q08 + U08
	local C09 = Q09 + U09
	local C10 = Q10 + U10
	local C11 = Q11 + U11
	local D00 = Q00 - U00
	local D01 = Q01 - U01
	local D02 = Q02 - U02
	local D03 = Q03 - U03
	local D04 = Q04 - U04
	local D05 = Q05 - U05
	local D06 = Q06 - U06
	local D07 = Q07 - U07
	local D08 = Q08 - U08
	local D09 = Q09 - U09
	local D10 = Q10 - U10
	local D11 = Q11 - U11
	D00, D01, D02, D03, D04, D05, D06, D07, D08, D09, D10, D11 = FieldMul(D00, D01, D02, D03, D04, D05, D06, D07, D08, D09, D10, D11, A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11)
	if Swap < 0 then return end
	C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11 = FieldMul(C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11, B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11)
	if Swap < 0 then return end
	local E00 = AA00 - BB00
	local E01 = AA01 - BB01
	local E02 = AA02 - BB02
	local E03 = AA03 - BB03
	local E04 = AA04 - BB04
	local E05 = AA05 - BB05
	local E06 = AA06 - BB06
	local E07 = AA07 - BB07
	local E08 = AA08 - BB08
	local E09 = AA09 - BB09
	local E10 = AA10 - BB10
	local E11 = AA11 - BB11
	local S00 = D00 + C00
	local S01 = D01 + C01
	local S02 = D02 + C02
	local S03 = D03 + C03
	local S04 = D04 + C04
	local S05 = D05 + C05
	local S06 = D06 + C06
	local S07 = D07 + C07
	local S08 = D08 + C08
	local S09 = D09 + C09
	local S10 = D10 + C10
	local S11 = D11 + C11
	if UnitZ then
		do
			local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldSquare(S00, S01, S02, S03, S04, S05, S06, S07, S08, S09, S10, S11)
			buffer.writef64(State, 208 + 0, O00)
			buffer.writef64(State, 208 + 8, O01)
			buffer.writef64(State, 208 + 16, O02)
			buffer.writef64(State, 208 + 24, O03)
			buffer.writef64(State, 208 + 32, O04)
			buffer.writef64(State, 208 + 40, O05)
			buffer.writef64(State, 208 + 48, O06)
			buffer.writef64(State, 208 + 56, O07)
			buffer.writef64(State, 208 + 64, O08)
			buffer.writef64(State, 208 + 72, O09)
			buffer.writef64(State, 208 + 80, O10)
			buffer.writef64(State, 208 + 88, O11)
		end
		if Swap < 0 then return end
	else
		S00, S01, S02, S03, S04, S05, S06, S07, S08, S09, S10, S11 = FieldSquare(S00, S01, S02, S03, S04, S05, S06, S07, S08, S09, S10, S11)
		if Swap < 0 then return end
		local Y00 = buffer.readf64(DiffZ, 0 + 0)
		local Y01 = buffer.readf64(DiffZ, 0 + 8)
		local Y02 = buffer.readf64(DiffZ, 0 + 16)
		local Y03 = buffer.readf64(DiffZ, 0 + 24)
		local Y04 = buffer.readf64(DiffZ, 0 + 32)
		local Y05 = buffer.readf64(DiffZ, 0 + 40)
		local Y06 = buffer.readf64(DiffZ, 0 + 48)
		local Y07 = buffer.readf64(DiffZ, 0 + 56)
		local Y08 = buffer.readf64(DiffZ, 0 + 64)
		local Y09 = buffer.readf64(DiffZ, 0 + 72)
		local Y10 = buffer.readf64(DiffZ, 0 + 80)
		local Y11 = buffer.readf64(DiffZ, 0 + 88)
		do
			local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11, S00, S01, S02, S03, S04, S05, S06, S07, S08, S09, S10, S11)
			buffer.writef64(State, 208 + 0, O00)
			buffer.writef64(State, 208 + 8, O01)
			buffer.writef64(State, 208 + 16, O02)
			buffer.writef64(State, 208 + 24, O03)
			buffer.writef64(State, 208 + 32, O04)
			buffer.writef64(State, 208 + 40, O05)
			buffer.writef64(State, 208 + 48, O06)
			buffer.writef64(State, 208 + 56, O07)
			buffer.writef64(State, 208 + 64, O08)
			buffer.writef64(State, 208 + 72, O09)
			buffer.writef64(State, 208 + 80, O10)
			buffer.writef64(State, 208 + 88, O11)
		end
		if Swap < 0 then return end
	end
	local M00 = D00 - C00
	local M01 = D01 - C01
	local M02 = D02 - C02
	local M03 = D03 - C03
	local M04 = D04 - C04
	local M05 = D05 - C05
	local M06 = D06 - C06
	local M07 = D07 - C07
	local M08 = D08 - C08
	local M09 = D09 - C09
	local M10 = D10 - C10
	local M11 = D11 - C11
	M00, M01, M02, M03, M04, M05, M06, M07, M08, M09, M10, M11 = FieldSquare(M00, M01, M02, M03, M04, M05, M06, M07, M08, M09, M10, M11)
	if Swap < 0 then return end
	local X00 = buffer.readf64(DiffX, 0 + 0)
	local X01 = buffer.readf64(DiffX, 0 + 8)
	local X02 = buffer.readf64(DiffX, 0 + 16)
	local X03 = buffer.readf64(DiffX, 0 + 24)
	local X04 = buffer.readf64(DiffX, 0 + 32)
	local X05 = buffer.readf64(DiffX, 0 + 40)
	local X06 = buffer.readf64(DiffX, 0 + 48)
	local X07 = buffer.readf64(DiffX, 0 + 56)
	local X08 = buffer.readf64(DiffX, 0 + 64)
	local X09 = buffer.readf64(DiffX, 0 + 72)
	local X10 = buffer.readf64(DiffX, 0 + 80)
	local X11 = buffer.readf64(DiffX, 0 + 88)
	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, M00, M01, M02, M03, M04, M05, M06, M07, M08, M09, M10, M11)
		buffer.writef64(State, 312 + 0, O00)
		buffer.writef64(State, 312 + 8, O01)
		buffer.writef64(State, 312 + 16, O02)
		buffer.writef64(State, 312 + 24, O03)
		buffer.writef64(State, 312 + 32, O04)
		buffer.writef64(State, 312 + 40, O05)
		buffer.writef64(State, 312 + 48, O06)
		buffer.writef64(State, 312 + 56, O07)
		buffer.writef64(State, 312 + 64, O08)
		buffer.writef64(State, 312 + 72, O09)
		buffer.writef64(State, 312 + 80, O10)
		buffer.writef64(State, 312 + 88, O11)
	end
	if Swap < 0 then return end
	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(AA00, AA01, AA02, AA03, AA04, AA05, AA06, AA07, AA08, AA09, AA10, AA11, BB00, BB01, BB02, BB03, BB04, BB05, BB06, BB07, BB08, BB09, BB10, BB11)
		buffer.writef64(State, 0 + 0, O00)
		buffer.writef64(State, 0 + 8, O01)
		buffer.writef64(State, 0 + 16, O02)
		buffer.writef64(State, 0 + 24, O03)
		buffer.writef64(State, 0 + 32, O04)
		buffer.writef64(State, 0 + 40, O05)
		buffer.writef64(State, 0 + 48, O06)
		buffer.writef64(State, 0 + 56, O07)
		buffer.writef64(State, 0 + 64, O08)
		buffer.writef64(State, 0 + 72, O09)
		buffer.writef64(State, 0 + 80, O10)
		buffer.writef64(State, 0 + 88, O11)
	end
	if Swap < 0 then return end
	local K00 = E00 * 121666
	local K01 = E01 * 121666
	local K02 = E02 * 121666
	local K03 = E03 * 121666
	local K04 = E04 * 121666
	local K05 = E05 * 121666
	local K06 = E06 * 121666
	local K07 = E07 * 121666
	local K08 = E08 * 121666
	local K09 = E09 * 121666
	local K10 = E10 * 121666
	local K11 = E11 * 121666
	do
		local k00 = K00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
		local k01 = K01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
		local k02 = K02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
		local k03 = K03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
		local k04 = K04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
		local k05 = K05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
		local k06 = K06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
		local k07 = K07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
		local k08 = K08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
		local k09 = K09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
		local k10 = K10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
		local k11 = K11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
		local b00 = (K00 - k00) + k11 * (19 / 2 ^ 255)
		local b01 = (K01 - k01) + k00
		local b02 = (K02 - k02) + k01
		local b03 = (K03 - k03) + k02
		local b04 = (K04 - k04) + k03
		local b05 = (K05 - k05) + k04
		local b06 = (K06 - k06) + k05
		local b07 = (K07 - k07) + k06
		local b08 = (K08 - k08) + k07
		local b09 = (K09 - k09) + k08
		local b10 = (K10 - k10) + k09
		local b11 = (K11 - k11) + k10
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
		K00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		K01 = (b01 - j01) + j00
		K02 = (b02 - j02) + j01
		K03 = (b03 - j03) + j02
		K04 = (b04 - j04) + j03
		K05 = (b05 - j05) + j04
		K06 = (b06 - j06) + j05
		K07 = (b07 - j07) + j06
		K08 = (b08 - j08) + j07
		K09 = (b09 - j09) + j08
		K10 = (b10 - j10) + j09
		K11 = (b11 - j11) + j10
	end
	K00 = BB00 + K00
	K01 = BB01 + K01
	K02 = BB02 + K02
	K03 = BB03 + K03
	K04 = BB04 + K04
	K05 = BB05 + K05
	K06 = BB06 + K06
	K07 = BB07 + K07
	K08 = BB08 + K08
	K09 = BB09 + K09
	K10 = BB10 + K10
	K11 = BB11 + K11
	do
		local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(E00, E01, E02, E03, E04, E05, E06, E07, E08, E09, E10, E11, K00, K01, K02, K03, K04, K05, K06, K07, K08, K09, K10, K11)
		buffer.writef64(State, 104 + 0, O00)
		buffer.writef64(State, 104 + 8, O01)
		buffer.writef64(State, 104 + 16, O02)
		buffer.writef64(State, 104 + 24, O03)
		buffer.writef64(State, 104 + 32, O04)
		buffer.writef64(State, 104 + 40, O05)
		buffer.writef64(State, 104 + 48, O06)
		buffer.writef64(State, 104 + 56, O07)
		buffer.writef64(State, 104 + 64, O08)
		buffer.writef64(State, 104 + 72, O09)
		buffer.writef64(State, 104 + 80, O10)
		buffer.writef64(State, 104 + 88, O11)
	end
	if Swap < 0 then return end
end

function Curve25519.Ladder(DifferencePoint: buffer, ScalarBits: buffer, ScalarBitCount: number): buffer
	local State = LADDER_STATE
	local DiffX, DiffZ = DIFF_X, DIFF_Z
	buffer.copy(DiffX, 0, DifferencePoint, 0, COORD_SIZE)
	buffer.copy(DiffZ, 0, DifferencePoint, COORD_SIZE, COORD_SIZE)

	buffer.copy(State, 0, ONE, 0, COORD_SIZE)
	buffer.fill(State, COORD_SIZE, 0, COORD_SIZE)
	buffer.copy(State, 2 * COORD_SIZE, DiffX, 0, COORD_SIZE)
	buffer.copy(State, 3 * COORD_SIZE, DiffZ, 0, COORD_SIZE)

	local UnitZ = buffer.readf64(DiffZ, 0) == 1
	for Offset = 8, 88, 8 do
		if buffer.readf64(DiffZ, Offset) ~= 0 then
			UnitZ = false
		end
	end

	local PrevBit = 0
	local Step = LadderStep

	for BitIndex = ScalarBitCount, 1, -1 do
		local BitValue = buffer.readu8(ScalarBits, BitIndex - 1)
		Step(State, DiffX, DiffZ, bit32.bxor(PrevBit, BitValue), UnitZ)
		PrevBit = BitValue
	end

	local Result = buffer.create(MONTGOMERY_POINT_SIZE)
	for Offset = 0, 88, 8 do
		local X1, X2 = buffer.readf64(State, Offset), buffer.readf64(State, 2 * COORD_SIZE + Offset)
		local Z1, Z2 = buffer.readf64(State, COORD_SIZE + Offset), buffer.readf64(State, 3 * COORD_SIZE + Offset)
		buffer.writef64(Result, Offset, X1 + PrevBit * (X2 - X1))
		buffer.writef64(Result, COORD_SIZE + Offset, Z1 + PrevBit * (Z2 - Z1))
	end

	return Result
end

function Curve25519.Decode(EncodedBuffer: buffer): buffer
	local Point = buffer.create(MONTGOMERY_POINT_SIZE)
	buffer.copy(Point, 0 * COORD_SIZE, FieldPrime.Decode(EncodedBuffer), 0, COORD_SIZE)
	buffer.copy(Point, 1 * COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)

	return Point
end

local Point = buffer.create(MONTGOMERY_POINT_SIZE)
buffer.copy(Point, 0 * COORD_SIZE, FieldPrime.Num(9), 0, COORD_SIZE)
buffer.copy(Point, 1 * COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)
Curve25519.G = Point

return Curve25519
