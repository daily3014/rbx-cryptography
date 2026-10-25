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

local function LadderStep(State: buffer, DiffX: buffer, DiffZ: buffer, Swap: number, UnitZ: boolean)
	local P00 = buffer.readf64(State, 0)
	local Q00 = buffer.readf64(State, 208)
	local W00 = Swap * (Q00 - P00)
	P00 += W00
	Q00 -= W00
	local P01 = buffer.readf64(State, 8)
	local Q01 = buffer.readf64(State, 216)
	local W01 = Swap * (Q01 - P01)
	P01 += W01
	Q01 -= W01
	local P02 = buffer.readf64(State, 16)
	local Q02 = buffer.readf64(State, 224)
	local W02 = Swap * (Q02 - P02)
	P02 += W02
	Q02 -= W02
	local P03 = buffer.readf64(State, 24)
	local Q03 = buffer.readf64(State, 232)
	local W03 = Swap * (Q03 - P03)
	P03 += W03
	Q03 -= W03
	local P04 = buffer.readf64(State, 32)
	local Q04 = buffer.readf64(State, 240)
	local W04 = Swap * (Q04 - P04)
	P04 += W04
	Q04 -= W04
	local P05 = buffer.readf64(State, 40)
	local Q05 = buffer.readf64(State, 248)
	local W05 = Swap * (Q05 - P05)
	P05 += W05
	Q05 -= W05
	local P06 = buffer.readf64(State, 48)
	local Q06 = buffer.readf64(State, 256)
	local W06 = Swap * (Q06 - P06)
	P06 += W06
	Q06 -= W06
	local P07 = buffer.readf64(State, 56)
	local Q07 = buffer.readf64(State, 264)
	local W07 = Swap * (Q07 - P07)
	P07 += W07
	Q07 -= W07
	local P08 = buffer.readf64(State, 64)
	local Q08 = buffer.readf64(State, 272)
	local W08 = Swap * (Q08 - P08)
	P08 += W08
	Q08 -= W08
	local P09 = buffer.readf64(State, 72)
	local Q09 = buffer.readf64(State, 280)
	local W09 = Swap * (Q09 - P09)
	P09 += W09
	Q09 -= W09
	local P10 = buffer.readf64(State, 80)
	local Q10 = buffer.readf64(State, 288)
	local W10 = Swap * (Q10 - P10)
	P10 += W10
	Q10 -= W10
	local P11 = buffer.readf64(State, 88)
	local Q11 = buffer.readf64(State, 296)
	local W11 = Swap * (Q11 - P11)
	P11 += W11
	Q11 -= W11
	local R00 = buffer.readf64(State, 104)
	local U00 = buffer.readf64(State, 312)
	local W00 = Swap * (U00 - R00)
	R00 += W00
	U00 -= W00
	local R01 = buffer.readf64(State, 112)
	local U01 = buffer.readf64(State, 320)
	local W01 = Swap * (U01 - R01)
	R01 += W01
	U01 -= W01
	local R02 = buffer.readf64(State, 120)
	local U02 = buffer.readf64(State, 328)
	local W02 = Swap * (U02 - R02)
	R02 += W02
	U02 -= W02
	local R03 = buffer.readf64(State, 128)
	local U03 = buffer.readf64(State, 336)
	local W03 = Swap * (U03 - R03)
	R03 += W03
	U03 -= W03
	local R04 = buffer.readf64(State, 136)
	local U04 = buffer.readf64(State, 344)
	local W04 = Swap * (U04 - R04)
	R04 += W04
	U04 -= W04
	local R05 = buffer.readf64(State, 144)
	local U05 = buffer.readf64(State, 352)
	local W05 = Swap * (U05 - R05)
	R05 += W05
	U05 -= W05
	local R06 = buffer.readf64(State, 152)
	local U06 = buffer.readf64(State, 360)
	local W06 = Swap * (U06 - R06)
	R06 += W06
	U06 -= W06
	local R07 = buffer.readf64(State, 160)
	local U07 = buffer.readf64(State, 368)
	local W07 = Swap * (U07 - R07)
	R07 += W07
	U07 -= W07
	local R08 = buffer.readf64(State, 168)
	local U08 = buffer.readf64(State, 376)
	local W08 = Swap * (U08 - R08)
	R08 += W08
	U08 -= W08
	local R09 = buffer.readf64(State, 176)
	local U09 = buffer.readf64(State, 384)
	local W09 = Swap * (U09 - R09)
	R09 += W09
	U09 -= W09
	local R10 = buffer.readf64(State, 184)
	local U10 = buffer.readf64(State, 392)
	local W10 = Swap * (U10 - R10)
	R10 += W10
	U10 -= W10
	local R11 = buffer.readf64(State, 192)
	local U11 = buffer.readf64(State, 400)
	local W11 = Swap * (U11 - R11)
	R11 += W11
	U11 -= W11
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
	local AA00, AA01, AA02, AA03, AA04, AA05, AA06, AA07, AA08, AA09, AA10, AA11
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
		AA00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		AA01 = (b01 - j01) + j00
		AA02 = (b02 - j02) + j01
		AA03 = (b03 - j03) + j02
		AA04 = (b04 - j04) + j03
		AA05 = (b05 - j05) + j04
		AA06 = (b06 - j06) + j05
		AA07 = (b07 - j07) + j06
		AA08 = (b08 - j08) + j07
		AA09 = (b09 - j09) + j08
		AA10 = (b10 - j10) + j09
		AA11 = (b11 - j11) + j10
	end
	if Swap < 0 then return end
	local BB00, BB01, BB02, BB03, BB04, BB05, BB06, BB07, BB08, BB09, BB10, BB11
	do
		local d00 = B00 * 2
		local d01 = B01 * 2
		local d02 = B02 * 2
		local d03 = B03 * 2
		local d04 = B04 * 2
		local d05 = B05 * 2
		local d06 = B06 * 2
		local d07 = B07 * 2
		local d08 = B08 * 2
		local d09 = B09 * 2
		local d10 = B10 * 2
		local c00 = (B11 * d01 + B10 * d02 + B09 * d03 + B08 * d04 + B07 * d05 + B06 * B06) * (19 / 2 ^ 255) + (B00 * B00)
		local c01 = (B11 * d02 + B10 * d03 + B09 * d04 + B08 * d05 + B07 * d06) * (19 / 2 ^ 255) + (B01 * d00)
		local c02 = (B11 * d03 + B10 * d04 + B09 * d05 + B08 * d06 + B07 * B07) * (19 / 2 ^ 255) + (B02 * d00 + B01 * B01)
		local c03 = (B11 * d04 + B10 * d05 + B09 * d06 + B08 * d07) * (19 / 2 ^ 255) + (B03 * d00 + B02 * d01)
		local c04 = (B11 * d05 + B10 * d06 + B09 * d07 + B08 * B08) * (19 / 2 ^ 255) + (B04 * d00 + B03 * d01 + B02 * B02)
		local c05 = (B11 * d06 + B10 * d07 + B09 * d08) * (19 / 2 ^ 255) + (B05 * d00 + B04 * d01 + B03 * d02)
		local c06 = (B11 * d07 + B10 * d08 + B09 * B09) * (19 / 2 ^ 255) + (B06 * d00 + B05 * d01 + B04 * d02 + B03 * B03)
		local c07 = (B11 * d08 + B10 * d09) * (19 / 2 ^ 255) + (B07 * d00 + B06 * d01 + B05 * d02 + B04 * d03)
		local c08 = (B11 * d09 + B10 * B10) * (19 / 2 ^ 255) + (B08 * d00 + B07 * d01 + B06 * d02 + B05 * d03 + B04 * B04)
		local c09 = (B11 * d10) * (19 / 2 ^ 255) + (B09 * d00 + B08 * d01 + B07 * d02 + B06 * d03 + B05 * d04)
		local c10 = (B11 * B11) * (19 / 2 ^ 255) + (B10 * d00 + B09 * d01 + B08 * d02 + B07 * d03 + B06 * d04 + B05 * B05)
		local c11 = B11 * d00 + B10 * d01 + B09 * d02 + B08 * d03 + B07 * d04 + B06 * d05
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
		BB00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		BB01 = (b01 - j01) + j00
		BB02 = (b02 - j02) + j01
		BB03 = (b03 - j03) + j02
		BB04 = (b04 - j04) + j03
		BB05 = (b05 - j05) + j04
		BB06 = (b06 - j06) + j05
		BB07 = (b07 - j07) + j06
		BB08 = (b08 - j08) + j07
		BB09 = (b09 - j09) + j08
		BB10 = (b10 - j10) + j09
		BB11 = (b11 - j11) + j10
	end
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
	do
		local c00 = (D01 * A11 + D02 * A10 + D03 * A09 + D04 * A08 + D05 * A07 + D06 * A06 + D07 * A05 + D08 * A04 + D09 * A03 + D10 * A02 + D11 * A01) * (19 / 2 ^ 255) + (D00 * A00)
		local c01 = (D02 * A11 + D03 * A10 + D04 * A09 + D05 * A08 + D06 * A07 + D07 * A06 + D08 * A05 + D09 * A04 + D10 * A03 + D11 * A02) * (19 / 2 ^ 255) + (D00 * A01 + D01 * A00)
		local c02 = (D03 * A11 + D04 * A10 + D05 * A09 + D06 * A08 + D07 * A07 + D08 * A06 + D09 * A05 + D10 * A04 + D11 * A03) * (19 / 2 ^ 255) + (D00 * A02 + D01 * A01 + D02 * A00)
		local c03 = (D04 * A11 + D05 * A10 + D06 * A09 + D07 * A08 + D08 * A07 + D09 * A06 + D10 * A05 + D11 * A04) * (19 / 2 ^ 255) + (D00 * A03 + D01 * A02 + D02 * A01 + D03 * A00)
		local c04 = (D05 * A11 + D06 * A10 + D07 * A09 + D08 * A08 + D09 * A07 + D10 * A06 + D11 * A05) * (19 / 2 ^ 255) + (D00 * A04 + D01 * A03 + D02 * A02 + D03 * A01 + D04 * A00)
		local c05 = (D06 * A11 + D07 * A10 + D08 * A09 + D09 * A08 + D10 * A07 + D11 * A06) * (19 / 2 ^ 255) + (D00 * A05 + D01 * A04 + D02 * A03 + D03 * A02 + D04 * A01 + D05 * A00)
		local c06 = (D07 * A11 + D08 * A10 + D09 * A09 + D10 * A08 + D11 * A07) * (19 / 2 ^ 255) + (D00 * A06 + D01 * A05 + D02 * A04 + D03 * A03 + D04 * A02 + D05 * A01 + D06 * A00)
		local c07 = (D08 * A11 + D09 * A10 + D10 * A09 + D11 * A08) * (19 / 2 ^ 255) + (D00 * A07 + D01 * A06 + D02 * A05 + D03 * A04 + D04 * A03 + D05 * A02 + D06 * A01 + D07 * A00)
		local c08 = (D09 * A11 + D10 * A10 + D11 * A09) * (19 / 2 ^ 255) + (D00 * A08 + D01 * A07 + D02 * A06 + D03 * A05 + D04 * A04 + D05 * A03 + D06 * A02 + D07 * A01 + D08 * A00)
		local c09 = (D10 * A11 + D11 * A10) * (19 / 2 ^ 255) + (D00 * A09 + D01 * A08 + D02 * A07 + D03 * A06 + D04 * A05 + D05 * A04 + D06 * A03 + D07 * A02 + D08 * A01 + D09 * A00)
		local c10 = (D11 * A11) * (19 / 2 ^ 255) + (D00 * A10 + D01 * A09 + D02 * A08 + D03 * A07 + D04 * A06 + D05 * A05 + D06 * A04 + D07 * A03 + D08 * A02 + D09 * A01 + D10 * A00)
		local c11 = D00 * A11 + D01 * A10 + D02 * A09 + D03 * A08 + D04 * A07 + D05 * A06 + D06 * A05 + D07 * A04 + D08 * A03 + D09 * A02 + D10 * A01 + D11 * A00
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
		D00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		D01 = (b01 - j01) + j00
		D02 = (b02 - j02) + j01
		D03 = (b03 - j03) + j02
		D04 = (b04 - j04) + j03
		D05 = (b05 - j05) + j04
		D06 = (b06 - j06) + j05
		D07 = (b07 - j07) + j06
		D08 = (b08 - j08) + j07
		D09 = (b09 - j09) + j08
		D10 = (b10 - j10) + j09
		D11 = (b11 - j11) + j10
	end
	if Swap < 0 then return end
	do
		local c00 = (C01 * B11 + C02 * B10 + C03 * B09 + C04 * B08 + C05 * B07 + C06 * B06 + C07 * B05 + C08 * B04 + C09 * B03 + C10 * B02 + C11 * B01) * (19 / 2 ^ 255) + (C00 * B00)
		local c01 = (C02 * B11 + C03 * B10 + C04 * B09 + C05 * B08 + C06 * B07 + C07 * B06 + C08 * B05 + C09 * B04 + C10 * B03 + C11 * B02) * (19 / 2 ^ 255) + (C00 * B01 + C01 * B00)
		local c02 = (C03 * B11 + C04 * B10 + C05 * B09 + C06 * B08 + C07 * B07 + C08 * B06 + C09 * B05 + C10 * B04 + C11 * B03) * (19 / 2 ^ 255) + (C00 * B02 + C01 * B01 + C02 * B00)
		local c03 = (C04 * B11 + C05 * B10 + C06 * B09 + C07 * B08 + C08 * B07 + C09 * B06 + C10 * B05 + C11 * B04) * (19 / 2 ^ 255) + (C00 * B03 + C01 * B02 + C02 * B01 + C03 * B00)
		local c04 = (C05 * B11 + C06 * B10 + C07 * B09 + C08 * B08 + C09 * B07 + C10 * B06 + C11 * B05) * (19 / 2 ^ 255) + (C00 * B04 + C01 * B03 + C02 * B02 + C03 * B01 + C04 * B00)
		local c05 = (C06 * B11 + C07 * B10 + C08 * B09 + C09 * B08 + C10 * B07 + C11 * B06) * (19 / 2 ^ 255) + (C00 * B05 + C01 * B04 + C02 * B03 + C03 * B02 + C04 * B01 + C05 * B00)
		local c06 = (C07 * B11 + C08 * B10 + C09 * B09 + C10 * B08 + C11 * B07) * (19 / 2 ^ 255) + (C00 * B06 + C01 * B05 + C02 * B04 + C03 * B03 + C04 * B02 + C05 * B01 + C06 * B00)
		local c07 = (C08 * B11 + C09 * B10 + C10 * B09 + C11 * B08) * (19 / 2 ^ 255) + (C00 * B07 + C01 * B06 + C02 * B05 + C03 * B04 + C04 * B03 + C05 * B02 + C06 * B01 + C07 * B00)
		local c08 = (C09 * B11 + C10 * B10 + C11 * B09) * (19 / 2 ^ 255) + (C00 * B08 + C01 * B07 + C02 * B06 + C03 * B05 + C04 * B04 + C05 * B03 + C06 * B02 + C07 * B01 + C08 * B00)
		local c09 = (C10 * B11 + C11 * B10) * (19 / 2 ^ 255) + (C00 * B09 + C01 * B08 + C02 * B07 + C03 * B06 + C04 * B05 + C05 * B04 + C06 * B03 + C07 * B02 + C08 * B01 + C09 * B00)
		local c10 = (C11 * B11) * (19 / 2 ^ 255) + (C00 * B10 + C01 * B09 + C02 * B08 + C03 * B07 + C04 * B06 + C05 * B05 + C06 * B04 + C07 * B03 + C08 * B02 + C09 * B01 + C10 * B00)
		local c11 = C00 * B11 + C01 * B10 + C02 * B09 + C03 * B08 + C04 * B07 + C05 * B06 + C06 * B05 + C07 * B04 + C08 * B03 + C09 * B02 + C10 * B01 + C11 * B00
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
		C00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		C01 = (b01 - j01) + j00
		C02 = (b02 - j02) + j01
		C03 = (b03 - j03) + j02
		C04 = (b04 - j04) + j03
		C05 = (b05 - j05) + j04
		C06 = (b06 - j06) + j05
		C07 = (b07 - j07) + j06
		C08 = (b08 - j08) + j07
		C09 = (b09 - j09) + j08
		C10 = (b10 - j10) + j09
		C11 = (b11 - j11) + j10
	end
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
			local d00 = S00 * 2
			local d01 = S01 * 2
			local d02 = S02 * 2
			local d03 = S03 * 2
			local d04 = S04 * 2
			local d05 = S05 * 2
			local d06 = S06 * 2
			local d07 = S07 * 2
			local d08 = S08 * 2
			local d09 = S09 * 2
			local d10 = S10 * 2
			local c00 = (S11 * d01 + S10 * d02 + S09 * d03 + S08 * d04 + S07 * d05 + S06 * S06) * (19 / 2 ^ 255) + (S00 * S00)
			local c01 = (S11 * d02 + S10 * d03 + S09 * d04 + S08 * d05 + S07 * d06) * (19 / 2 ^ 255) + (S01 * d00)
			local c02 = (S11 * d03 + S10 * d04 + S09 * d05 + S08 * d06 + S07 * S07) * (19 / 2 ^ 255) + (S02 * d00 + S01 * S01)
			local c03 = (S11 * d04 + S10 * d05 + S09 * d06 + S08 * d07) * (19 / 2 ^ 255) + (S03 * d00 + S02 * d01)
			local c04 = (S11 * d05 + S10 * d06 + S09 * d07 + S08 * S08) * (19 / 2 ^ 255) + (S04 * d00 + S03 * d01 + S02 * S02)
			local c05 = (S11 * d06 + S10 * d07 + S09 * d08) * (19 / 2 ^ 255) + (S05 * d00 + S04 * d01 + S03 * d02)
			local c06 = (S11 * d07 + S10 * d08 + S09 * S09) * (19 / 2 ^ 255) + (S06 * d00 + S05 * d01 + S04 * d02 + S03 * S03)
			local c07 = (S11 * d08 + S10 * d09) * (19 / 2 ^ 255) + (S07 * d00 + S06 * d01 + S05 * d02 + S04 * d03)
			local c08 = (S11 * d09 + S10 * S10) * (19 / 2 ^ 255) + (S08 * d00 + S07 * d01 + S06 * d02 + S05 * d03 + S04 * S04)
			local c09 = (S11 * d10) * (19 / 2 ^ 255) + (S09 * d00 + S08 * d01 + S07 * d02 + S06 * d03 + S05 * d04)
			local c10 = (S11 * S11) * (19 / 2 ^ 255) + (S10 * d00 + S09 * d01 + S08 * d02 + S07 * d03 + S06 * d04 + S05 * S05)
			local c11 = S11 * d00 + S10 * d01 + S09 * d02 + S08 * d03 + S07 * d04 + S06 * d05
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
			buffer.writef64(State, 208 + 0, (b00 - j00) + j11 * (19 / 2 ^ 255))
			buffer.writef64(State, 208 + 8, (b01 - j01) + j00)
			buffer.writef64(State, 208 + 16, (b02 - j02) + j01)
			buffer.writef64(State, 208 + 24, (b03 - j03) + j02)
			buffer.writef64(State, 208 + 32, (b04 - j04) + j03)
			buffer.writef64(State, 208 + 40, (b05 - j05) + j04)
			buffer.writef64(State, 208 + 48, (b06 - j06) + j05)
			buffer.writef64(State, 208 + 56, (b07 - j07) + j06)
			buffer.writef64(State, 208 + 64, (b08 - j08) + j07)
			buffer.writef64(State, 208 + 72, (b09 - j09) + j08)
			buffer.writef64(State, 208 + 80, (b10 - j10) + j09)
			buffer.writef64(State, 208 + 88, (b11 - j11) + j10)
		end
		if Swap < 0 then return end
	else
		do
			local d00 = S00 * 2
			local d01 = S01 * 2
			local d02 = S02 * 2
			local d03 = S03 * 2
			local d04 = S04 * 2
			local d05 = S05 * 2
			local d06 = S06 * 2
			local d07 = S07 * 2
			local d08 = S08 * 2
			local d09 = S09 * 2
			local d10 = S10 * 2
			local c00 = (S11 * d01 + S10 * d02 + S09 * d03 + S08 * d04 + S07 * d05 + S06 * S06) * (19 / 2 ^ 255) + (S00 * S00)
			local c01 = (S11 * d02 + S10 * d03 + S09 * d04 + S08 * d05 + S07 * d06) * (19 / 2 ^ 255) + (S01 * d00)
			local c02 = (S11 * d03 + S10 * d04 + S09 * d05 + S08 * d06 + S07 * S07) * (19 / 2 ^ 255) + (S02 * d00 + S01 * S01)
			local c03 = (S11 * d04 + S10 * d05 + S09 * d06 + S08 * d07) * (19 / 2 ^ 255) + (S03 * d00 + S02 * d01)
			local c04 = (S11 * d05 + S10 * d06 + S09 * d07 + S08 * S08) * (19 / 2 ^ 255) + (S04 * d00 + S03 * d01 + S02 * S02)
			local c05 = (S11 * d06 + S10 * d07 + S09 * d08) * (19 / 2 ^ 255) + (S05 * d00 + S04 * d01 + S03 * d02)
			local c06 = (S11 * d07 + S10 * d08 + S09 * S09) * (19 / 2 ^ 255) + (S06 * d00 + S05 * d01 + S04 * d02 + S03 * S03)
			local c07 = (S11 * d08 + S10 * d09) * (19 / 2 ^ 255) + (S07 * d00 + S06 * d01 + S05 * d02 + S04 * d03)
			local c08 = (S11 * d09 + S10 * S10) * (19 / 2 ^ 255) + (S08 * d00 + S07 * d01 + S06 * d02 + S05 * d03 + S04 * S04)
			local c09 = (S11 * d10) * (19 / 2 ^ 255) + (S09 * d00 + S08 * d01 + S07 * d02 + S06 * d03 + S05 * d04)
			local c10 = (S11 * S11) * (19 / 2 ^ 255) + (S10 * d00 + S09 * d01 + S08 * d02 + S07 * d03 + S06 * d04 + S05 * S05)
			local c11 = S11 * d00 + S10 * d01 + S09 * d02 + S08 * d03 + S07 * d04 + S06 * d05
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
			S00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
			S01 = (b01 - j01) + j00
			S02 = (b02 - j02) + j01
			S03 = (b03 - j03) + j02
			S04 = (b04 - j04) + j03
			S05 = (b05 - j05) + j04
			S06 = (b06 - j06) + j05
			S07 = (b07 - j07) + j06
			S08 = (b08 - j08) + j07
			S09 = (b09 - j09) + j08
			S10 = (b10 - j10) + j09
			S11 = (b11 - j11) + j10
		end
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
			local c00 = (Y01 * S11 + Y02 * S10 + Y03 * S09 + Y04 * S08 + Y05 * S07 + Y06 * S06 + Y07 * S05 + Y08 * S04 + Y09 * S03 + Y10 * S02 + Y11 * S01) * (19 / 2 ^ 255) + (Y00 * S00)
			local c01 = (Y02 * S11 + Y03 * S10 + Y04 * S09 + Y05 * S08 + Y06 * S07 + Y07 * S06 + Y08 * S05 + Y09 * S04 + Y10 * S03 + Y11 * S02) * (19 / 2 ^ 255) + (Y00 * S01 + Y01 * S00)
			local c02 = (Y03 * S11 + Y04 * S10 + Y05 * S09 + Y06 * S08 + Y07 * S07 + Y08 * S06 + Y09 * S05 + Y10 * S04 + Y11 * S03) * (19 / 2 ^ 255) + (Y00 * S02 + Y01 * S01 + Y02 * S00)
			local c03 = (Y04 * S11 + Y05 * S10 + Y06 * S09 + Y07 * S08 + Y08 * S07 + Y09 * S06 + Y10 * S05 + Y11 * S04) * (19 / 2 ^ 255) + (Y00 * S03 + Y01 * S02 + Y02 * S01 + Y03 * S00)
			local c04 = (Y05 * S11 + Y06 * S10 + Y07 * S09 + Y08 * S08 + Y09 * S07 + Y10 * S06 + Y11 * S05) * (19 / 2 ^ 255) + (Y00 * S04 + Y01 * S03 + Y02 * S02 + Y03 * S01 + Y04 * S00)
			local c05 = (Y06 * S11 + Y07 * S10 + Y08 * S09 + Y09 * S08 + Y10 * S07 + Y11 * S06) * (19 / 2 ^ 255) + (Y00 * S05 + Y01 * S04 + Y02 * S03 + Y03 * S02 + Y04 * S01 + Y05 * S00)
			local c06 = (Y07 * S11 + Y08 * S10 + Y09 * S09 + Y10 * S08 + Y11 * S07) * (19 / 2 ^ 255) + (Y00 * S06 + Y01 * S05 + Y02 * S04 + Y03 * S03 + Y04 * S02 + Y05 * S01 + Y06 * S00)
			local c07 = (Y08 * S11 + Y09 * S10 + Y10 * S09 + Y11 * S08) * (19 / 2 ^ 255) + (Y00 * S07 + Y01 * S06 + Y02 * S05 + Y03 * S04 + Y04 * S03 + Y05 * S02 + Y06 * S01 + Y07 * S00)
			local c08 = (Y09 * S11 + Y10 * S10 + Y11 * S09) * (19 / 2 ^ 255) + (Y00 * S08 + Y01 * S07 + Y02 * S06 + Y03 * S05 + Y04 * S04 + Y05 * S03 + Y06 * S02 + Y07 * S01 + Y08 * S00)
			local c09 = (Y10 * S11 + Y11 * S10) * (19 / 2 ^ 255) + (Y00 * S09 + Y01 * S08 + Y02 * S07 + Y03 * S06 + Y04 * S05 + Y05 * S04 + Y06 * S03 + Y07 * S02 + Y08 * S01 + Y09 * S00)
			local c10 = (Y11 * S11) * (19 / 2 ^ 255) + (Y00 * S10 + Y01 * S09 + Y02 * S08 + Y03 * S07 + Y04 * S06 + Y05 * S05 + Y06 * S04 + Y07 * S03 + Y08 * S02 + Y09 * S01 + Y10 * S00)
			local c11 = Y00 * S11 + Y01 * S10 + Y02 * S09 + Y03 * S08 + Y04 * S07 + Y05 * S06 + Y06 * S05 + Y07 * S04 + Y08 * S03 + Y09 * S02 + Y10 * S01 + Y11 * S00
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
			buffer.writef64(State, 208 + 0, (b00 - j00) + j11 * (19 / 2 ^ 255))
			buffer.writef64(State, 208 + 8, (b01 - j01) + j00)
			buffer.writef64(State, 208 + 16, (b02 - j02) + j01)
			buffer.writef64(State, 208 + 24, (b03 - j03) + j02)
			buffer.writef64(State, 208 + 32, (b04 - j04) + j03)
			buffer.writef64(State, 208 + 40, (b05 - j05) + j04)
			buffer.writef64(State, 208 + 48, (b06 - j06) + j05)
			buffer.writef64(State, 208 + 56, (b07 - j07) + j06)
			buffer.writef64(State, 208 + 64, (b08 - j08) + j07)
			buffer.writef64(State, 208 + 72, (b09 - j09) + j08)
			buffer.writef64(State, 208 + 80, (b10 - j10) + j09)
			buffer.writef64(State, 208 + 88, (b11 - j11) + j10)
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
	do
		local d00 = M00 * 2
		local d01 = M01 * 2
		local d02 = M02 * 2
		local d03 = M03 * 2
		local d04 = M04 * 2
		local d05 = M05 * 2
		local d06 = M06 * 2
		local d07 = M07 * 2
		local d08 = M08 * 2
		local d09 = M09 * 2
		local d10 = M10 * 2
		local c00 = (M11 * d01 + M10 * d02 + M09 * d03 + M08 * d04 + M07 * d05 + M06 * M06) * (19 / 2 ^ 255) + (M00 * M00)
		local c01 = (M11 * d02 + M10 * d03 + M09 * d04 + M08 * d05 + M07 * d06) * (19 / 2 ^ 255) + (M01 * d00)
		local c02 = (M11 * d03 + M10 * d04 + M09 * d05 + M08 * d06 + M07 * M07) * (19 / 2 ^ 255) + (M02 * d00 + M01 * M01)
		local c03 = (M11 * d04 + M10 * d05 + M09 * d06 + M08 * d07) * (19 / 2 ^ 255) + (M03 * d00 + M02 * d01)
		local c04 = (M11 * d05 + M10 * d06 + M09 * d07 + M08 * M08) * (19 / 2 ^ 255) + (M04 * d00 + M03 * d01 + M02 * M02)
		local c05 = (M11 * d06 + M10 * d07 + M09 * d08) * (19 / 2 ^ 255) + (M05 * d00 + M04 * d01 + M03 * d02)
		local c06 = (M11 * d07 + M10 * d08 + M09 * M09) * (19 / 2 ^ 255) + (M06 * d00 + M05 * d01 + M04 * d02 + M03 * M03)
		local c07 = (M11 * d08 + M10 * d09) * (19 / 2 ^ 255) + (M07 * d00 + M06 * d01 + M05 * d02 + M04 * d03)
		local c08 = (M11 * d09 + M10 * M10) * (19 / 2 ^ 255) + (M08 * d00 + M07 * d01 + M06 * d02 + M05 * d03 + M04 * M04)
		local c09 = (M11 * d10) * (19 / 2 ^ 255) + (M09 * d00 + M08 * d01 + M07 * d02 + M06 * d03 + M05 * d04)
		local c10 = (M11 * M11) * (19 / 2 ^ 255) + (M10 * d00 + M09 * d01 + M08 * d02 + M07 * d03 + M06 * d04 + M05 * M05)
		local c11 = M11 * d00 + M10 * d01 + M09 * d02 + M08 * d03 + M07 * d04 + M06 * d05
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
		M00 = (b00 - j00) + j11 * (19 / 2 ^ 255)
		M01 = (b01 - j01) + j00
		M02 = (b02 - j02) + j01
		M03 = (b03 - j03) + j02
		M04 = (b04 - j04) + j03
		M05 = (b05 - j05) + j04
		M06 = (b06 - j06) + j05
		M07 = (b07 - j07) + j06
		M08 = (b08 - j08) + j07
		M09 = (b09 - j09) + j08
		M10 = (b10 - j10) + j09
		M11 = (b11 - j11) + j10
	end
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
		local c00 = (X01 * M11 + X02 * M10 + X03 * M09 + X04 * M08 + X05 * M07 + X06 * M06 + X07 * M05 + X08 * M04 + X09 * M03 + X10 * M02 + X11 * M01) * (19 / 2 ^ 255) + (X00 * M00)
		local c01 = (X02 * M11 + X03 * M10 + X04 * M09 + X05 * M08 + X06 * M07 + X07 * M06 + X08 * M05 + X09 * M04 + X10 * M03 + X11 * M02) * (19 / 2 ^ 255) + (X00 * M01 + X01 * M00)
		local c02 = (X03 * M11 + X04 * M10 + X05 * M09 + X06 * M08 + X07 * M07 + X08 * M06 + X09 * M05 + X10 * M04 + X11 * M03) * (19 / 2 ^ 255) + (X00 * M02 + X01 * M01 + X02 * M00)
		local c03 = (X04 * M11 + X05 * M10 + X06 * M09 + X07 * M08 + X08 * M07 + X09 * M06 + X10 * M05 + X11 * M04) * (19 / 2 ^ 255) + (X00 * M03 + X01 * M02 + X02 * M01 + X03 * M00)
		local c04 = (X05 * M11 + X06 * M10 + X07 * M09 + X08 * M08 + X09 * M07 + X10 * M06 + X11 * M05) * (19 / 2 ^ 255) + (X00 * M04 + X01 * M03 + X02 * M02 + X03 * M01 + X04 * M00)
		local c05 = (X06 * M11 + X07 * M10 + X08 * M09 + X09 * M08 + X10 * M07 + X11 * M06) * (19 / 2 ^ 255) + (X00 * M05 + X01 * M04 + X02 * M03 + X03 * M02 + X04 * M01 + X05 * M00)
		local c06 = (X07 * M11 + X08 * M10 + X09 * M09 + X10 * M08 + X11 * M07) * (19 / 2 ^ 255) + (X00 * M06 + X01 * M05 + X02 * M04 + X03 * M03 + X04 * M02 + X05 * M01 + X06 * M00)
		local c07 = (X08 * M11 + X09 * M10 + X10 * M09 + X11 * M08) * (19 / 2 ^ 255) + (X00 * M07 + X01 * M06 + X02 * M05 + X03 * M04 + X04 * M03 + X05 * M02 + X06 * M01 + X07 * M00)
		local c08 = (X09 * M11 + X10 * M10 + X11 * M09) * (19 / 2 ^ 255) + (X00 * M08 + X01 * M07 + X02 * M06 + X03 * M05 + X04 * M04 + X05 * M03 + X06 * M02 + X07 * M01 + X08 * M00)
		local c09 = (X10 * M11 + X11 * M10) * (19 / 2 ^ 255) + (X00 * M09 + X01 * M08 + X02 * M07 + X03 * M06 + X04 * M05 + X05 * M04 + X06 * M03 + X07 * M02 + X08 * M01 + X09 * M00)
		local c10 = (X11 * M11) * (19 / 2 ^ 255) + (X00 * M10 + X01 * M09 + X02 * M08 + X03 * M07 + X04 * M06 + X05 * M05 + X06 * M04 + X07 * M03 + X08 * M02 + X09 * M01 + X10 * M00)
		local c11 = X00 * M11 + X01 * M10 + X02 * M09 + X03 * M08 + X04 * M07 + X05 * M06 + X06 * M05 + X07 * M04 + X08 * M03 + X09 * M02 + X10 * M01 + X11 * M00
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
		buffer.writef64(State, 312 + 0, (b00 - j00) + j11 * (19 / 2 ^ 255))
		buffer.writef64(State, 312 + 8, (b01 - j01) + j00)
		buffer.writef64(State, 312 + 16, (b02 - j02) + j01)
		buffer.writef64(State, 312 + 24, (b03 - j03) + j02)
		buffer.writef64(State, 312 + 32, (b04 - j04) + j03)
		buffer.writef64(State, 312 + 40, (b05 - j05) + j04)
		buffer.writef64(State, 312 + 48, (b06 - j06) + j05)
		buffer.writef64(State, 312 + 56, (b07 - j07) + j06)
		buffer.writef64(State, 312 + 64, (b08 - j08) + j07)
		buffer.writef64(State, 312 + 72, (b09 - j09) + j08)
		buffer.writef64(State, 312 + 80, (b10 - j10) + j09)
		buffer.writef64(State, 312 + 88, (b11 - j11) + j10)
	end
	if Swap < 0 then return end
	do
		local c00 = (AA01 * BB11 + AA02 * BB10 + AA03 * BB09 + AA04 * BB08 + AA05 * BB07 + AA06 * BB06 + AA07 * BB05 + AA08 * BB04 + AA09 * BB03 + AA10 * BB02 + AA11 * BB01) * (19 / 2 ^ 255) + (AA00 * BB00)
		local c01 = (AA02 * BB11 + AA03 * BB10 + AA04 * BB09 + AA05 * BB08 + AA06 * BB07 + AA07 * BB06 + AA08 * BB05 + AA09 * BB04 + AA10 * BB03 + AA11 * BB02) * (19 / 2 ^ 255) + (AA00 * BB01 + AA01 * BB00)
		local c02 = (AA03 * BB11 + AA04 * BB10 + AA05 * BB09 + AA06 * BB08 + AA07 * BB07 + AA08 * BB06 + AA09 * BB05 + AA10 * BB04 + AA11 * BB03) * (19 / 2 ^ 255) + (AA00 * BB02 + AA01 * BB01 + AA02 * BB00)
		local c03 = (AA04 * BB11 + AA05 * BB10 + AA06 * BB09 + AA07 * BB08 + AA08 * BB07 + AA09 * BB06 + AA10 * BB05 + AA11 * BB04) * (19 / 2 ^ 255) + (AA00 * BB03 + AA01 * BB02 + AA02 * BB01 + AA03 * BB00)
		local c04 = (AA05 * BB11 + AA06 * BB10 + AA07 * BB09 + AA08 * BB08 + AA09 * BB07 + AA10 * BB06 + AA11 * BB05) * (19 / 2 ^ 255) + (AA00 * BB04 + AA01 * BB03 + AA02 * BB02 + AA03 * BB01 + AA04 * BB00)
		local c05 = (AA06 * BB11 + AA07 * BB10 + AA08 * BB09 + AA09 * BB08 + AA10 * BB07 + AA11 * BB06) * (19 / 2 ^ 255) + (AA00 * BB05 + AA01 * BB04 + AA02 * BB03 + AA03 * BB02 + AA04 * BB01 + AA05 * BB00)
		local c06 = (AA07 * BB11 + AA08 * BB10 + AA09 * BB09 + AA10 * BB08 + AA11 * BB07) * (19 / 2 ^ 255) + (AA00 * BB06 + AA01 * BB05 + AA02 * BB04 + AA03 * BB03 + AA04 * BB02 + AA05 * BB01 + AA06 * BB00)
		local c07 = (AA08 * BB11 + AA09 * BB10 + AA10 * BB09 + AA11 * BB08) * (19 / 2 ^ 255) + (AA00 * BB07 + AA01 * BB06 + AA02 * BB05 + AA03 * BB04 + AA04 * BB03 + AA05 * BB02 + AA06 * BB01 + AA07 * BB00)
		local c08 = (AA09 * BB11 + AA10 * BB10 + AA11 * BB09) * (19 / 2 ^ 255) + (AA00 * BB08 + AA01 * BB07 + AA02 * BB06 + AA03 * BB05 + AA04 * BB04 + AA05 * BB03 + AA06 * BB02 + AA07 * BB01 + AA08 * BB00)
		local c09 = (AA10 * BB11 + AA11 * BB10) * (19 / 2 ^ 255) + (AA00 * BB09 + AA01 * BB08 + AA02 * BB07 + AA03 * BB06 + AA04 * BB05 + AA05 * BB04 + AA06 * BB03 + AA07 * BB02 + AA08 * BB01 + AA09 * BB00)
		local c10 = (AA11 * BB11) * (19 / 2 ^ 255) + (AA00 * BB10 + AA01 * BB09 + AA02 * BB08 + AA03 * BB07 + AA04 * BB06 + AA05 * BB05 + AA06 * BB04 + AA07 * BB03 + AA08 * BB02 + AA09 * BB01 + AA10 * BB00)
		local c11 = AA00 * BB11 + AA01 * BB10 + AA02 * BB09 + AA03 * BB08 + AA04 * BB07 + AA05 * BB06 + AA06 * BB05 + AA07 * BB04 + AA08 * BB03 + AA09 * BB02 + AA10 * BB01 + AA11 * BB00
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
		buffer.writef64(State, 0 + 0, (b00 - j00) + j11 * (19 / 2 ^ 255))
		buffer.writef64(State, 0 + 8, (b01 - j01) + j00)
		buffer.writef64(State, 0 + 16, (b02 - j02) + j01)
		buffer.writef64(State, 0 + 24, (b03 - j03) + j02)
		buffer.writef64(State, 0 + 32, (b04 - j04) + j03)
		buffer.writef64(State, 0 + 40, (b05 - j05) + j04)
		buffer.writef64(State, 0 + 48, (b06 - j06) + j05)
		buffer.writef64(State, 0 + 56, (b07 - j07) + j06)
		buffer.writef64(State, 0 + 64, (b08 - j08) + j07)
		buffer.writef64(State, 0 + 72, (b09 - j09) + j08)
		buffer.writef64(State, 0 + 80, (b10 - j10) + j09)
		buffer.writef64(State, 0 + 88, (b11 - j11) + j10)
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
		local c00 = (E01 * K11 + E02 * K10 + E03 * K09 + E04 * K08 + E05 * K07 + E06 * K06 + E07 * K05 + E08 * K04 + E09 * K03 + E10 * K02 + E11 * K01) * (19 / 2 ^ 255) + (E00 * K00)
		local c01 = (E02 * K11 + E03 * K10 + E04 * K09 + E05 * K08 + E06 * K07 + E07 * K06 + E08 * K05 + E09 * K04 + E10 * K03 + E11 * K02) * (19 / 2 ^ 255) + (E00 * K01 + E01 * K00)
		local c02 = (E03 * K11 + E04 * K10 + E05 * K09 + E06 * K08 + E07 * K07 + E08 * K06 + E09 * K05 + E10 * K04 + E11 * K03) * (19 / 2 ^ 255) + (E00 * K02 + E01 * K01 + E02 * K00)
		local c03 = (E04 * K11 + E05 * K10 + E06 * K09 + E07 * K08 + E08 * K07 + E09 * K06 + E10 * K05 + E11 * K04) * (19 / 2 ^ 255) + (E00 * K03 + E01 * K02 + E02 * K01 + E03 * K00)
		local c04 = (E05 * K11 + E06 * K10 + E07 * K09 + E08 * K08 + E09 * K07 + E10 * K06 + E11 * K05) * (19 / 2 ^ 255) + (E00 * K04 + E01 * K03 + E02 * K02 + E03 * K01 + E04 * K00)
		local c05 = (E06 * K11 + E07 * K10 + E08 * K09 + E09 * K08 + E10 * K07 + E11 * K06) * (19 / 2 ^ 255) + (E00 * K05 + E01 * K04 + E02 * K03 + E03 * K02 + E04 * K01 + E05 * K00)
		local c06 = (E07 * K11 + E08 * K10 + E09 * K09 + E10 * K08 + E11 * K07) * (19 / 2 ^ 255) + (E00 * K06 + E01 * K05 + E02 * K04 + E03 * K03 + E04 * K02 + E05 * K01 + E06 * K00)
		local c07 = (E08 * K11 + E09 * K10 + E10 * K09 + E11 * K08) * (19 / 2 ^ 255) + (E00 * K07 + E01 * K06 + E02 * K05 + E03 * K04 + E04 * K03 + E05 * K02 + E06 * K01 + E07 * K00)
		local c08 = (E09 * K11 + E10 * K10 + E11 * K09) * (19 / 2 ^ 255) + (E00 * K08 + E01 * K07 + E02 * K06 + E03 * K05 + E04 * K04 + E05 * K03 + E06 * K02 + E07 * K01 + E08 * K00)
		local c09 = (E10 * K11 + E11 * K10) * (19 / 2 ^ 255) + (E00 * K09 + E01 * K08 + E02 * K07 + E03 * K06 + E04 * K05 + E05 * K04 + E06 * K03 + E07 * K02 + E08 * K01 + E09 * K00)
		local c10 = (E11 * K11) * (19 / 2 ^ 255) + (E00 * K10 + E01 * K09 + E02 * K08 + E03 * K07 + E04 * K06 + E05 * K05 + E06 * K04 + E07 * K03 + E08 * K02 + E09 * K01 + E10 * K00)
		local c11 = E00 * K11 + E01 * K10 + E02 * K09 + E03 * K08 + E04 * K07 + E05 * K06 + E06 * K05 + E07 * K04 + E08 * K03 + E09 * K02 + E10 * K01 + E11 * K00
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
		buffer.writef64(State, 104 + 0, (b00 - j00) + j11 * (19 / 2 ^ 255))
		buffer.writef64(State, 104 + 8, (b01 - j01) + j00)
		buffer.writef64(State, 104 + 16, (b02 - j02) + j01)
		buffer.writef64(State, 104 + 24, (b03 - j03) + j02)
		buffer.writef64(State, 104 + 32, (b04 - j04) + j03)
		buffer.writef64(State, 104 + 40, (b05 - j05) + j04)
		buffer.writef64(State, 104 + 48, (b06 - j06) + j05)
		buffer.writef64(State, 104 + 56, (b07 - j07) + j06)
		buffer.writef64(State, 104 + 64, (b08 - j08) + j07)
		buffer.writef64(State, 104 + 72, (b09 - j09) + j08)
		buffer.writef64(State, 104 + 80, (b10 - j10) + j09)
		buffer.writef64(State, 104 + 88, (b11 - j11) + j10)
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
