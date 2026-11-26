--[=[
	Cryptography library: Curve25519 Montgomery Ladder

	Performs X25519 scalar multiplication on the Montgomery curve
	using split-carry 12-limb field arithmetic.

	Example usage:
		Curve25519.LadderUnitZ(DiffX, SecretKey, OutX, OutZ)
--]=]

--!strict
--!optimize 2

local COORD_SIZE = 104
local C19 = 19 / 2 ^ 255
local M00, M01, M02, M03 = 3 * 2 ^ 73, 3 * 2 ^ 94, 3 * 2 ^ 115, 3 * 2 ^ 136
local M04, M05, M06, M07 = 3 * 2 ^ 158, 3 * 2 ^ 179, 3 * 2 ^ 200, 3 * 2 ^ 221
local M08, M09, M10, M11 = 3 * 2 ^ 243, 3 * 2 ^ 264, 3 * 2 ^ 285, 3 * 2 ^ 306

local LADDER_STATE: buffer = buffer.create(4 * COORD_SIZE)

local Curve25519 = {}

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
function Curve25519.LadderUnitZ(DiffX: buffer, SecretKey: buffer, OutX: buffer, OutZ: buffer): ()
	local State = LADDER_STATE
	buffer.fill(State, 0, 0, 4 * COORD_SIZE)
	buffer.writef64(State, 0, 1)
	buffer.copy(State, 208, DiffX, 0, COORD_SIZE)
	buffer.writef64(State, 312, 1)

	local X00, X01, X02, X03, X04, X05 = buffer.readf64(DiffX, 0), buffer.readf64(DiffX, 8), buffer.readf64(DiffX, 16), buffer.readf64(DiffX, 24), buffer.readf64(DiffX, 32), buffer.readf64(DiffX, 40)
	local X06, X07, X08, X09, X10, X11 = buffer.readf64(DiffX, 48), buffer.readf64(DiffX, 56), buffer.readf64(DiffX, 64), buffer.readf64(DiffX, 72), buffer.readf64(DiffX, 80), buffer.readf64(DiffX, 88)

	local PrevBit = 0
	for BitIndex = 254, 0, -1 do
		local ByteIdx = bit32.rshift(BitIndex, 3)
		local Byte = buffer.readu8(SecretKey, ByteIdx)
		if ByteIdx == 0 then
			Byte = bit32.band(Byte, 0xF8)
		elseif ByteIdx == 31 then
			Byte = bit32.bor(bit32.band(Byte, 0x7F), 0x40)
		end
		local BitValue = bit32.band(bit32.rshift(Byte, bit32.band(BitIndex, 7)), 1)
		local Swap = bit32.bxor(PrevBit, BitValue)
		PrevBit = BitValue

		local P00, Q00 = buffer.readf64(State, 0), buffer.readf64(State, 208); local W = Swap * (Q00 - P00); P00 += W; Q00 -= W
		local P01, Q01 = buffer.readf64(State, 8), buffer.readf64(State, 216); W = Swap * (Q01 - P01); P01 += W; Q01 -= W
		local P02, Q02 = buffer.readf64(State, 16), buffer.readf64(State, 224); W = Swap * (Q02 - P02); P02 += W; Q02 -= W
		local P03, Q03 = buffer.readf64(State, 24), buffer.readf64(State, 232); W = Swap * (Q03 - P03); P03 += W; Q03 -= W
		local P04, Q04 = buffer.readf64(State, 32), buffer.readf64(State, 240); W = Swap * (Q04 - P04); P04 += W; Q04 -= W
		local P05, Q05 = buffer.readf64(State, 40), buffer.readf64(State, 248); W = Swap * (Q05 - P05); P05 += W; Q05 -= W
		local P06, Q06 = buffer.readf64(State, 48), buffer.readf64(State, 256); W = Swap * (Q06 - P06); P06 += W; Q06 -= W
		local P07, Q07 = buffer.readf64(State, 56), buffer.readf64(State, 264); W = Swap * (Q07 - P07); P07 += W; Q07 -= W
		local P08, Q08 = buffer.readf64(State, 64), buffer.readf64(State, 272); W = Swap * (Q08 - P08); P08 += W; Q08 -= W
		local P09, Q09 = buffer.readf64(State, 72), buffer.readf64(State, 280); W = Swap * (Q09 - P09); P09 += W; Q09 -= W
		local P10, Q10 = buffer.readf64(State, 80), buffer.readf64(State, 288); W = Swap * (Q10 - P10); P10 += W; Q10 -= W
		local P11, Q11 = buffer.readf64(State, 88), buffer.readf64(State, 296); W = Swap * (Q11 - P11); P11 += W; Q11 -= W

		local R00, U00 = buffer.readf64(State, 104), buffer.readf64(State, 312); W = Swap * (U00 - R00); R00 += W; U00 -= W
		local R01, U01 = buffer.readf64(State, 112), buffer.readf64(State, 320); W = Swap * (U01 - R01); R01 += W; U01 -= W
		local R02, U02 = buffer.readf64(State, 120), buffer.readf64(State, 328); W = Swap * (U02 - R02); R02 += W; U02 -= W
		local R03, U03 = buffer.readf64(State, 128), buffer.readf64(State, 336); W = Swap * (U03 - R03); R03 += W; U03 -= W
		local R04, U04 = buffer.readf64(State, 136), buffer.readf64(State, 344); W = Swap * (U04 - R04); R04 += W; U04 -= W
		local R05, U05 = buffer.readf64(State, 144), buffer.readf64(State, 352); W = Swap * (U05 - R05); R05 += W; U05 -= W
		local R06, U06 = buffer.readf64(State, 152), buffer.readf64(State, 360); W = Swap * (U06 - R06); R06 += W; U06 -= W
		local R07, U07 = buffer.readf64(State, 160), buffer.readf64(State, 368); W = Swap * (U07 - R07); R07 += W; U07 -= W
		local R08, U08 = buffer.readf64(State, 168), buffer.readf64(State, 376); W = Swap * (U08 - R08); R08 += W; U08 -= W
		local R09, U09 = buffer.readf64(State, 176), buffer.readf64(State, 384); W = Swap * (U09 - R09); R09 += W; U09 -= W
		local R10, U10 = buffer.readf64(State, 184), buffer.readf64(State, 392); W = Swap * (U10 - R10); R10 += W; U10 -= W
		local R11, U11 = buffer.readf64(State, 192), buffer.readf64(State, 400); W = Swap * (U11 - R11); R11 += W; U11 -= W

		local A00, B00 = P00 + R00, P00 - R00
		local A01, B01 = P01 + R01, P01 - R01
		local A02, B02 = P02 + R02, P02 - R02
		local A03, B03 = P03 + R03, P03 - R03
		local A04, B04 = P04 + R04, P04 - R04
		local A05, B05 = P05 + R05, P05 - R05
		local A06, B06 = P06 + R06, P06 - R06
		local A07, B07 = P07 + R07, P07 - R07
		local A08, B08 = P08 + R08, P08 - R08
		local A09, B09 = P09 + R09, P09 - R09
		local A10, B10 = P10 + R10, P10 - R10
		local A11, B11 = P11 + R11, P11 - R11

		local AA00, AA01, AA02, AA03, AA04, AA05, AA06, AA07, AA08, AA09, AA10, AA11 = FieldSquare(A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11)
		if Swap < 0 then return end
		local BB00, BB01, BB02, BB03, BB04, BB05, BB06, BB07, BB08, BB09, BB10, BB11 = FieldSquare(B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11)
		if Swap < 0 then return end

		local C00, D00 = Q00 + U00, Q00 - U00
		local C01, D01 = Q01 + U01, Q01 - U01
		local C02, D02 = Q02 + U02, Q02 - U02
		local C03, D03 = Q03 + U03, Q03 - U03
		local C04, D04 = Q04 + U04, Q04 - U04
		local C05, D05 = Q05 + U05, Q05 - U05
		local C06, D06 = Q06 + U06, Q06 - U06
		local C07, D07 = Q07 + U07, Q07 - U07
		local C08, D08 = Q08 + U08, Q08 - U08
		local C09, D09 = Q09 + U09, Q09 - U09
		local C10, D10 = Q10 + U10, Q10 - U10
		local C11, D11 = Q11 + U11, Q11 - U11

		D00, D01, D02, D03, D04, D05, D06, D07, D08, D09, D10, D11 = FieldMul(D00, D01, D02, D03, D04, D05, D06, D07, D08, D09, D10, D11, A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11)
		if Swap < 0 then return end
		C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11 = FieldMul(C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11, B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11)
		if Swap < 0 then return end

		do
			local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldSquare(
				D00 + C00, D01 + C01, D02 + C02, D03 + C03, D04 + C04, D05 + C05,
				D06 + C06, D07 + C07, D08 + C08, D09 + C09, D10 + C10, D11 + C11
			)
			buffer.writef64(State, 208, O00); buffer.writef64(State, 216, O01); buffer.writef64(State, 224, O02); buffer.writef64(State, 232, O03)
			buffer.writef64(State, 240, O04); buffer.writef64(State, 248, O05); buffer.writef64(State, 256, O06); buffer.writef64(State, 264, O07)
			buffer.writef64(State, 272, O08); buffer.writef64(State, 280, O09); buffer.writef64(State, 288, O10); buffer.writef64(State, 296, O11)
		end
		if Swap < 0 then return end

		local S00, S01, S02, S03, S04, S05, S06, S07, S08, S09, S10, S11 = FieldSquare(
			D00 - C00, D01 - C01, D02 - C02, D03 - C03, D04 - C04, D05 - C05,
			D06 - C06, D07 - C07, D08 - C08, D09 - C09, D10 - C10, D11 - C11
		)
		if Swap < 0 then return end
		do
			local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, S00, S01, S02, S03, S04, S05, S06, S07, S08, S09, S10, S11)
			buffer.writef64(State, 312, O00); buffer.writef64(State, 320, O01); buffer.writef64(State, 328, O02); buffer.writef64(State, 336, O03)
			buffer.writef64(State, 344, O04); buffer.writef64(State, 352, O05); buffer.writef64(State, 360, O06); buffer.writef64(State, 368, O07)
			buffer.writef64(State, 376, O08); buffer.writef64(State, 384, O09); buffer.writef64(State, 392, O10); buffer.writef64(State, 400, O11)
		end
		if Swap < 0 then return end

		do
			local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(AA00, AA01, AA02, AA03, AA04, AA05, AA06, AA07, AA08, AA09, AA10, AA11, BB00, BB01, BB02, BB03, BB04, BB05, BB06, BB07, BB08, BB09, BB10, BB11)
			buffer.writef64(State, 0, O00); buffer.writef64(State, 8, O01); buffer.writef64(State, 16, O02); buffer.writef64(State, 24, O03)
			buffer.writef64(State, 32, O04); buffer.writef64(State, 40, O05); buffer.writef64(State, 48, O06); buffer.writef64(State, 56, O07)
			buffer.writef64(State, 64, O08); buffer.writef64(State, 72, O09); buffer.writef64(State, 80, O10); buffer.writef64(State, 88, O11)
		end
		if Swap < 0 then return end

		local E00, E01, E02, E03, E04, E05 = AA00 - BB00, AA01 - BB01, AA02 - BB02, AA03 - BB03, AA04 - BB04, AA05 - BB05
		local E06, E07, E08, E09, E10, E11 = AA06 - BB06, AA07 - BB07, AA08 - BB08, AA09 - BB09, AA10 - BB10, AA11 - BB11
		local K00, K01, K02, K03, K04, K05 = E00 * 121666, E01 * 121666, E02 * 121666, E03 * 121666, E04 * 121666, E05 * 121666
		local K06, K07, K08, K09, K10, K11 = E06 * 121666, E07 * 121666, E08 * 121666, E09 * 121666, E10 * 121666, E11 * 121666
		local K: number
		K = K00 + M00 - M00; K00 -= K; K01 += K
		K = K06 + M06 - M06; K06 -= K; K07 += K
		K = K01 + M01 - M01; K01 -= K; K02 += K
		K = K07 + M07 - M07; K07 -= K; K08 += K
		K = K02 + M02 - M02; K02 -= K; K03 += K
		K = K08 + M08 - M08; K08 -= K; K09 += K
		K = K03 + M03 - M03; K03 -= K; K04 += K
		K = K09 + M09 - M09; K09 -= K; K10 += K
		K = K04 + M04 - M04; K04 -= K; K05 += K
		K = K10 + M10 - M10; K10 -= K; K11 += K
		K = K05 + M05 - M05; K05 -= K; K06 += K
		K = K11 + M11 - M11; K11 -= K; K00 += K * C19
		K = K06 + M06 - M06; K06 -= K; K07 += K
		K = K00 + M00 - M00; K00 -= K; K01 += K
		do
			local O00, O01, O02, O03, O04, O05, O06, O07, O08, O09, O10, O11 = FieldMul(
				E00, E01, E02, E03, E04, E05, E06, E07, E08, E09, E10, E11,
				BB00 + K00, BB01 + K01, BB02 + K02, BB03 + K03, BB04 + K04, BB05 + K05,
				BB06 + K06, BB07 + K07, BB08 + K08, BB09 + K09, BB10 + K10, BB11 + K11
			)
			buffer.writef64(State, 104, O00); buffer.writef64(State, 112, O01); buffer.writef64(State, 120, O02); buffer.writef64(State, 128, O03)
			buffer.writef64(State, 136, O04); buffer.writef64(State, 144, O05); buffer.writef64(State, 152, O06); buffer.writef64(State, 160, O07)
			buffer.writef64(State, 168, O08); buffer.writef64(State, 176, O09); buffer.writef64(State, 184, O10); buffer.writef64(State, 192, O11)
		end
		if Swap < 0 then return end
	end

	for Offset = 0, 88, 8 do
		local X1, X2 = buffer.readf64(State, Offset), buffer.readf64(State, 208 + Offset)
		local Z1, Z2 = buffer.readf64(State, 104 + Offset), buffer.readf64(State, 312 + Offset)
		buffer.writef64(OutX, Offset, X1 + PrevBit * (X2 - X1))
		buffer.writef64(OutZ, Offset, Z1 + PrevBit * (Z2 - Z1))
	end
end

function Curve25519.ClearCaches(): ()
	buffer.fill(LADDER_STATE, 0, 0)
end

return Curve25519
