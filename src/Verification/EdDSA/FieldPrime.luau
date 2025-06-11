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

--!native
--!optimize 2
local Unpack = unpack or table.unpack
local UnpackFieldPrime, FormatFieldPrime = string.unpack, "<I3I3I2I3I3I2I3I3I2I3I3I2"

-- the modular square root of -1 (useful for point decompression)
local SquareRootMinusOne = {
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

-- turn a regular number into a field element
local function Num(Number)
	return { Number, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
end

-- negate a field element (get -a)
local function Neg(ElementA)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 = Unpack(ElementA)
	return {
		-A00,
		-A01,
		-A02,
		-A03,
		-A04,
		-A05,
		-A06,
		-A07,
		-A08,
		-A09,
		-A10,
		-A11,
	}
end

-- add two field elements together
local function Add(ElementA, ElementB)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 = Unpack(ElementA)
	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11 = Unpack(ElementB)
	return {
		A00 + B00,
		A01 + B01,
		A02 + B02,
		A03 + B03,
		A04 + B04,
		A05 + B05,
		A06 + B06,
		A07 + B07,
		A08 + B08,
		A09 + B09,
		A10 + B10,
		A11 + B11,
	}
end

-- subtract one field element from another
local function Sub(ElementA, ElementB)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 = Unpack(ElementA)
	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11 = Unpack(ElementB)
	return {
		A00 - B00,
		A01 - B01,
		A02 - B02,
		A03 - B03,
		A04 - B04,
		A05 - B05,
		A06 - B06,
		A07 - B07,
		A08 - B08,
		A09 - B09,
		A10 - B10,
		A11 - B11,
	}
end

-- carry propagation and small modular reduction to keep things tidy
local function Carry(ElementA)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 = Unpack(ElementA)
	local C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11

	C11 = A11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	A00 = A00 + 19 / 2 ^ 255 * C11

	C00 = A00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	A01 = A01 + C00
	C01 = A01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	A02 = A02 + C01
	C02 = A02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	A03 = A03 + C02
	C03 = A03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	A04 = A04 + C03
	C04 = A04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	A05 = A05 + C04
	C05 = A05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	A06 = A06 + C05
	C06 = A06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	A07 = A07 + C06
	C07 = A07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	A08 = A08 + C07
	C08 = A08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	A09 = A09 + C08
	C09 = A09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	A10 = A10 + C09
	C10 = A10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	A11 = A11 - C11 + C10

	C11 = A11 + 3 * 2 ^ 306 - 3 * 2 ^ 306

	return {
		A00 - C00 + 19 / 2 ^ 255 * C11,
		A01 - C01,
		A02 - C02,
		A03 - C03,
		A04 - C04,
		A05 - C05,
		A06 - C06,
		A07 - C07,
		A08 - C08,
		A09 - C09,
		A10 - C10,
		A11 - C11,
	}
end

-- get the canonical representation of a field element
-- some elements can be represented in two ways, this picks the smaller one
local function Canonicalize(ElementA)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 = Unpack(ElementA)
	local C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11

	-- do a full euclidean reduction
	-- TODO: range check this properly
	C00 = A00 % 2 ^ 22
	A01 = A00 - C00 + A01
	C01 = A01 % 2 ^ 43
	A02 = A01 - C01 + A02
	C02 = A02 % 2 ^ 64
	A03 = A02 - C02 + A03
	C03 = A03 % 2 ^ 85
	A04 = A03 - C03 + A04
	C04 = A04 % 2 ^ 107
	A05 = A04 - C04 + A05
	C05 = A05 % 2 ^ 128
	A06 = A05 - C05 + A06
	C06 = A06 % 2 ^ 149
	A07 = A06 - C06 + A07
	C07 = A07 % 2 ^ 170
	A08 = A07 - C07 + A08
	C08 = A08 % 2 ^ 192
	A09 = A08 - C08 + A09
	C09 = A09 % 2 ^ 213
	A10 = A09 - C09 + A10
	C10 = A10 % 2 ^ 234
	A11 = A10 - C10 + A11
	C11 = A11 % 2 ^ 255
	C00 = C00 + 19 / 2 ^ 255 * (A11 - C11)

	-- check if we're at the special case where we need to subtract p
	if
		C11 / 2 ^ 234 == 2 ^ 21 - 1
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
		return { 19 - 2 ^ 22 + C00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
	else
		return { C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11 }
	end
end

-- check if two field elements are equal
local function Eq(ElementA, ElementB)
	local Difference = Canonicalize(Sub(ElementA, ElementB))
	for LimbIndex = 1, 12 do
		if Difference[LimbIndex] ~= 0 then
			return false
		end
	end
	return true
end

-- multiply two field elements together (the big one)
local function Mul(ElementA, ElementB)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 = Unpack(ElementA)
	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11 = Unpack(ElementB)
	local C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11

	-- multiply the high half and put it in c00..c11
	C00 = A11 * B01
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
	C01 = A11 * B02
		+ A10 * B03
		+ A09 * B04
		+ A08 * B05
		+ A07 * B06
		+ A06 * B07
		+ A05 * B08
		+ A04 * B09
		+ A03 * B10
		+ A02 * B11
	C02 = A11 * B03 + A10 * B04 + A09 * B05 + A08 * B06 + A07 * B07 + A06 * B08 + A05 * B09 + A04 * B10 + A03 * B11
	C03 = A11 * B04 + A10 * B05 + A09 * B06 + A08 * B07 + A07 * B08 + A06 * B09 + A05 * B10 + A04 * B11
	C04 = A11 * B05 + A10 * B06 + A09 * B07 + A08 * B08 + A07 * B09 + A06 * B10 + A05 * B11
	C05 = A11 * B06 + A10 * B07 + A09 * B08 + A08 * B09 + A07 * B10 + A06 * B11
	C06 = A11 * B07 + A10 * B08 + A09 * B09 + A08 * B10 + A07 * B11
	C07 = A11 * B08 + A10 * B09 + A09 * B10 + A08 * B11
	C08 = A11 * B09 + A10 * B10 + A09 * B11
	C09 = A11 * B10 + A10 * B11
	C10 = A11 * B11

	-- multiply the low half with reduction and add to c00..c11
	C00 = C00 * (19 / 2 ^ 255) + A00 * B00
	C01 = C01 * (19 / 2 ^ 255) + A01 * B00 + A00 * B01
	C02 = C02 * (19 / 2 ^ 255) + A02 * B00 + A01 * B01 + A00 * B02
	C03 = C03 * (19 / 2 ^ 255) + A03 * B00 + A02 * B01 + A01 * B02 + A00 * B03
	C04 = C04 * (19 / 2 ^ 255) + A04 * B00 + A03 * B01 + A02 * B02 + A01 * B03 + A00 * B04
	C05 = C05 * (19 / 2 ^ 255) + A05 * B00 + A04 * B01 + A03 * B02 + A02 * B03 + A01 * B04 + A00 * B05
	C06 = C06 * (19 / 2 ^ 255) + A06 * B00 + A05 * B01 + A04 * B02 + A03 * B03 + A02 * B04 + A01 * B05 + A00 * B06
	C07 = C07 * (19 / 2 ^ 255)
		+ A07 * B00
		+ A06 * B01
		+ A05 * B02
		+ A04 * B03
		+ A03 * B04
		+ A02 * B05
		+ A01 * B06
		+ A00 * B07
	C08 = C08 * (19 / 2 ^ 255)
		+ A08 * B00
		+ A07 * B01
		+ A06 * B02
		+ A05 * B03
		+ A04 * B04
		+ A03 * B05
		+ A02 * B06
		+ A01 * B07
		+ A00 * B08
	C09 = C09 * (19 / 2 ^ 255)
		+ A09 * B00
		+ A08 * B01
		+ A07 * B02
		+ A06 * B03
		+ A05 * B04
		+ A04 * B05
		+ A03 * B06
		+ A02 * B07
		+ A01 * B08
		+ A00 * B09
	C10 = C10 * (19 / 2 ^ 255)
		+ A10 * B00
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
	C11 = A11 * B00
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

	-- carry and reduce the result
	A10 = C10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	C11 = C11 + A10
	A11 = C11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	C00 = C00 + 19 / 2 ^ 255 * A11

	A00 = C00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	C01 = C01 + A00
	A01 = C01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	C02 = C02 + A01
	A02 = C02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	C03 = C03 + A02
	A03 = C03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	C04 = C04 + A03
	A04 = C04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	C05 = C05 + A04
	A05 = C05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	C06 = C06 + A05
	A06 = C06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	C07 = C07 + A06
	A07 = C07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	C08 = C08 + A07
	A08 = C08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	C09 = C09 + A08
	A09 = C09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	C10 = C10 - A10 + A09
	A10 = C10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	C11 = C11 - A11 + A10

	A11 = C11 + 3 * 2 ^ 306 - 3 * 2 ^ 306

	return {
		C00 - A00 + 19 / 2 ^ 255 * A11,
		C01 - A01,
		C02 - A02,
		C03 - A03,
		C04 - A04,
		C05 - A05,
		C06 - A06,
		C07 - A07,
		C08 - A08,
		C09 - A09,
		C10 - A10,
		C11 - A11,
	}
end

-- square a field element (optimized version of mul(a, a))
local function Square(ElementA)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 = Unpack(ElementA)
	local D00, D01, D02, D03, D04, D05, D06, D07, D08, D09, D10
	local C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11

	-- compute 2a for the cross terms
	D00 = A00 + A00
	D01 = A01 + A01
	D02 = A02 + A02
	D03 = A03 + A03
	D04 = A04 + A04
	D05 = A05 + A05
	D06 = A06 + A06
	D07 = A07 + A07
	D08 = A08 + A08
	D09 = A09 + A09
	D10 = A10 + A10

	-- multiply the high half
	C00 = A11 * D01 + A10 * D02 + A09 * D03 + A08 * D04 + A07 * D05 + A06 * A06
	C01 = A11 * D02 + A10 * D03 + A09 * D04 + A08 * D05 + A07 * D06
	C02 = A11 * D03 + A10 * D04 + A09 * D05 + A08 * D06 + A07 * A07
	C03 = A11 * D04 + A10 * D05 + A09 * D06 + A08 * D07
	C04 = A11 * D05 + A10 * D06 + A09 * D07 + A08 * A08
	C05 = A11 * D06 + A10 * D07 + A09 * D08
	C06 = A11 * D07 + A10 * D08 + A09 * A09
	C07 = A11 * D08 + A10 * D09
	C08 = A11 * D09 + A10 * A10
	C09 = A11 * D10
	C10 = A11 * A11

	-- multiply the low half with reduction
	C00 = C00 * (19 / 2 ^ 255) + A00 * A00
	C01 = C01 * (19 / 2 ^ 255) + A01 * D00
	C02 = C02 * (19 / 2 ^ 255) + A02 * D00 + A01 * A01
	C03 = C03 * (19 / 2 ^ 255) + A03 * D00 + A02 * D01
	C04 = C04 * (19 / 2 ^ 255) + A04 * D00 + A03 * D01 + A02 * A02
	C05 = C05 * (19 / 2 ^ 255) + A05 * D00 + A04 * D01 + A03 * D02
	C06 = C06 * (19 / 2 ^ 255) + A06 * D00 + A05 * D01 + A04 * D02 + A03 * A03
	C07 = C07 * (19 / 2 ^ 255) + A07 * D00 + A06 * D01 + A05 * D02 + A04 * D03
	C08 = C08 * (19 / 2 ^ 255) + A08 * D00 + A07 * D01 + A06 * D02 + A05 * D03 + A04 * A04
	C09 = C09 * (19 / 2 ^ 255) + A09 * D00 + A08 * D01 + A07 * D02 + A06 * D03 + A05 * D04
	C10 = C10 * (19 / 2 ^ 255) + A10 * D00 + A09 * D01 + A08 * D02 + A07 * D03 + A06 * D04 + A05 * A05
	C11 = A11 * D00 + A10 * D01 + A09 * D02 + A08 * D03 + A07 * D04 + A06 * D05

	-- carry and reduce
	A10 = C10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	C11 = C11 + A10
	A11 = C11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	C00 = C00 + 19 / 2 ^ 255 * A11

	A00 = C00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	C01 = C01 + A00
	A01 = C01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	C02 = C02 + A01
	A02 = C02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	C03 = C03 + A02
	A03 = C03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	C04 = C04 + A03
	A04 = C04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	C05 = C05 + A04
	A05 = C05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	C06 = C06 + A05
	A06 = C06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	C07 = C07 + A06
	A07 = C07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	C08 = C08 + A07
	A08 = C08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	C09 = C09 + A08
	A09 = C09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	C10 = C10 - A10 + A09
	A10 = C10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	C11 = C11 - A11 + A10

	A11 = C11 + 3 * 2 ^ 306 - 3 * 2 ^ 306

	return {
		C00 - A00 + 19 / 2 ^ 255 * A11,
		C01 - A01,
		C02 - A02,
		C03 - A03,
		C04 - A04,
		C05 - A05,
		C06 - A06,
		C07 - A07,
		C08 - A08,
		C09 - A09,
		C10 - A10,
		C11 - A11,
	}
end

-- multiply a field element by a small integer
local function KMul(ElementA, SmallK)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 = Unpack(ElementA)
	local C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11

	-- TODO: range check this properly
	A00 = A00 * SmallK
	A01 = A01 * SmallK
	A02 = A02 * SmallK
	A03 = A03 * SmallK
	A04 = A04 * SmallK
	A05 = A05 * SmallK
	A06 = A06 * SmallK
	A07 = A07 * SmallK
	A08 = A08 * SmallK
	A09 = A09 * SmallK
	A10 = A10 * SmallK
	A11 = A11 * SmallK

	C11 = A11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	A00 = A00 + 19 / 2 ^ 255 * C11

	C00 = A00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	A01 = A01 + C00
	C01 = A01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	A02 = A02 + C01
	C02 = A02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	A03 = A03 + C02
	C03 = A03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	A04 = A04 + C03
	C04 = A04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	A05 = A05 + C04
	C05 = A05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	A06 = A06 + C05
	C06 = A06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	A07 = A07 + C06
	C07 = A07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	A08 = A08 + C07
	C08 = A08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	A09 = A09 + C08
	C09 = A09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	A10 = A10 + C09
	C10 = A10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	A11 = A11 - C11 + C10

	C11 = A11 + 3 * 2 ^ 306 - 3 * 2 ^ 306

	return {
		A00 - C00 + 19 / 2 ^ 255 * C11,
		A01 - C01,
		A02 - C02,
		A03 - C03,
		A04 - C04,
		A05 - C05,
		A06 - C06,
		A07 - C07,
		A08 - C08,
		A09 - C09,
		A10 - C10,
		A11 - C11,
	}
end

-- square an element multiple times (for exponentiation chains)
local function NSquare(ElementA, SquareCount)
	for _ = 1, SquareCount do
		ElementA = Square(ElementA)
	end
	return ElementA
end

-- compute the modular inverse using fermat's little theorem
local function Invert(ElementA)
	local A2 = Square(ElementA)
	local A9 = Mul(ElementA, NSquare(A2, 2))
	local A11 = Mul(A9, A2)

	local X5 = Mul(Square(A11), A9)
	local X10 = Mul(NSquare(X5, 5), X5)
	local X20 = Mul(NSquare(X10, 10), X10)
	local X40 = Mul(NSquare(X20, 20), X20)
	local X50 = Mul(NSquare(X40, 10), X10)
	local X100 = Mul(NSquare(X50, 50), X50)
	local X200 = Mul(NSquare(X100, 100), X100)
	local X250 = Mul(NSquare(X200, 50), X50)

	return Mul(NSquare(X250, 5), A11)
end

-- find an element x such that vx^2 = u (used for point decompression)
-- when v = 0, the returned element can be anything
local function SqrtDiv(ElementU, ElementV)
	ElementU = Carry(ElementU)

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
		-- found sqrt(-u/v), multiply by i to get the right answer
		CandidateB = Mul(CandidateB, SquareRootMinusOne)
		B2 = Square(CandidateB)
		VB2 = Mul(ElementV, B2)
	end

	if Eq(VB2, ElementU) then
		return CandidateB
	else
		return nil
	end
end

-- turn a field element into 32 bytes (little-endian)
local function Encode(ElementA)
	ElementA = Canonicalize(ElementA)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 = Unpack(ElementA)

	local ByteArray = {}
	local Accumulator = A00

	local function PutBytes(ByteCount)
		for _ = 1, ByteCount do
			local SingleByte = Accumulator % 256
			ByteArray[#ByteArray + 1] = SingleByte
			Accumulator = (Accumulator - SingleByte) / 256
		end
	end

	PutBytes(2)
	Accumulator = Accumulator + A01 / 2 ^ 16
	PutBytes(3)
	Accumulator = Accumulator + A02 / 2 ^ 40
	PutBytes(3)
	Accumulator = Accumulator + A03 / 2 ^ 64
	PutBytes(2)
	Accumulator = Accumulator + A04 / 2 ^ 80
	PutBytes(3)
	Accumulator = Accumulator + A05 / 2 ^ 104
	PutBytes(3)
	Accumulator = Accumulator + A06 / 2 ^ 128
	PutBytes(2)
	Accumulator = Accumulator + A07 / 2 ^ 144
	PutBytes(3)
	Accumulator = Accumulator + A08 / 2 ^ 168
	PutBytes(3)
	Accumulator = Accumulator + A09 / 2 ^ 192
	PutBytes(2)
	Accumulator = Accumulator + A10 / 2 ^ 208
	PutBytes(3)
	Accumulator = Accumulator + A11 / 2 ^ 232
	PutBytes(3)

	return string.char(Unpack(ByteArray))
end

-- turn 32 bytes back into a field element (little-endian)
local function Decode(EncodedBytes)
	local W00, W01, W02, W03, W04, W05, W06, W07, W08, W09, W10, W11 =
		UnpackFieldPrime(FormatFieldPrime, EncodedBytes, 1)

	W11 = W11 % 2 ^ 15

	return Carry({
		W00,
		W01 * 2 ^ 24,
		W02 * 2 ^ 48,
		W03 * 2 ^ 64,
		W04 * 2 ^ 88,
		W05 * 2 ^ 112,
		W06 * 2 ^ 128,
		W07 * 2 ^ 152,
		W08 * 2 ^ 176,
		W09 * 2 ^ 192,
		W10 * 2 ^ 216,
		W11 * 2 ^ 240,
	})
end

-- check if a field element equals zero
local function Eqz(ElementA)
	local Canonical = Canonicalize(ElementA)
	local C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11 = Unpack(Canonical)
	return C00 + C01 + C02 + C03 + C04 + C05 + C06 + C07 + C08 + C09 + C10 + C11 == 0
end

return {
	Num = Num,
	Neg = Neg,
	Add = Add,
	Sub = Sub,
	KMul = KMul,
	Mul = Mul,
	Canonicalize = Canonicalize,
	Square = Square,
	Carry = Carry,
	Invert = Invert,
	SqrtDiv = SqrtDiv,
	Encode = Encode,
	Decode = Decode,
	Eqz = Eqz,
}
