--[=[
	Cryptography library: Field Quadratic (Curve25519 Scalar Field)

	Arithmetic modulo the Ed25519 group order L using 11 radix-2^24 limbs
	and Montgomery multiplication.

	Example usage:
		local ScalarA = FieldQuadratic.Decode(SomeBytes)
		local ScalarB = FieldQuadratic.Decode(OtherBytes)
		local Product = FieldQuadratic.Mul(ScalarA, ScalarB)
		local EncodedResult = FieldQuadratic.Encode(Product)
--]=]

--!strict
--!optimize 2

local SIZE = 96
local INV24 = 2 ^ -24
local RADIX = 16777216

local FIELD_ORDER_BYTES: buffer = buffer.fromstring("\237\211\245\092\026\099\018\088\214\156\247\162\222\249\222\020\z
	\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\016")
local FIELD_ORDER: buffer = buffer.fromstring("\000\000\000\160\125\186\110\065\000\000\000\000\151\198\088\065\z
	\000\000\000\064\002\203\106\065\000\000\000\128\243\094\100\065\z
	\000\000\000\192\059\223\107\065\000\000\000\000\000\000\052\064\z
	\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\z
	\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\z
	\000\000\000\000\000\000\176\064\000\000\000\000\000\000\000\000")
local MONTGOMERY_T0: buffer = buffer.fromstring("\000\000\000\192\134\031\085\065\000\000\000\000\018\163\061\065\z
	\000\000\000\160\086\250\111\065\000\000\000\128\080\183\111\065\z
	\000\000\000\064\222\064\100\065\000\000\000\064\172\250\090\065\z
	\000\000\000\128\209\127\076\065\000\000\000\000\084\231\052\065\z
	\000\000\000\192\006\035\109\065\000\000\000\224\077\222\104\065\z
	\000\000\000\192\182\147\105\065\000\000\000\000\000\000\000\000")
local MONTGOMERY_T1: buffer = buffer.fromstring("\000\000\000\128\191\086\102\065\000\000\000\000\148\171\058\065\z
	\000\000\000\064\204\195\095\065\000\000\000\000\159\026\077\065\z
	\000\000\000\000\134\097\060\065\000\000\000\160\140\107\105\065\z
	\000\000\000\160\204\183\110\065\000\000\000\192\133\244\092\065\z
	\000\000\000\000\118\231\078\065\000\000\000\128\038\012\095\065\z
	\000\000\000\000\000\176\113\064\000\000\000\000\000\000\000\000")
local MONTGOMERY_T2: buffer = buffer.fromstring("\000\000\000\160\050\002\097\065\000\000\000\128\183\078\098\065\z
	\000\000\000\000\044\090\058\065\000\000\000\000\145\128\102\065\z
	\000\000\000\192\239\052\082\065\000\000\000\000\213\118\106\065\z
	\000\000\000\000\069\217\086\065\000\000\000\000\059\001\091\065\z
	\000\000\000\128\187\012\096\065\000\000\000\224\216\057\099\065\z
	\000\000\000\000\000\212\156\064\000\000\000\000\000\000\000\000")

local MP_PROD_LOW: buffer = buffer.create(SIZE)
local MP_PROD_HIGH: buffer = buffer.create(SIZE)
local MP_RED_LOW: buffer = buffer.create(SIZE)
local MP_RED_HIGH: buffer = buffer.create(SIZE)
local MP_TMP: buffer = buffer.create(SIZE)
local DECODE_LOW: buffer = buffer.create(SIZE)
local DECODE_HIGH: buffer = buffer.create(SIZE)
local DECODE_WIDE_A: buffer = buffer.create(SIZE)
local DECODE_WIDE_B: buffer = buffer.create(SIZE)
local CLAMPED_BUFFER: buffer = buffer.create(32)

@native
local function CarryMP(Src: buffer, Out: buffer): ()
	local A00, A01, A02, A03, A04, A05 = buffer.readf64(Src, 0), buffer.readf64(Src, 8), buffer.readf64(Src, 16), buffer.readf64(Src, 24), buffer.readf64(Src, 32), buffer.readf64(Src, 40)
	local A06, A07, A08, A09, A10 = buffer.readf64(Src, 48), buffer.readf64(Src, 56), buffer.readf64(Src, 64), buffer.readf64(Src, 72), buffer.readf64(Src, 80)

	local C: number
	C = math.floor(A00 * INV24); buffer.writef64(Out, 0, A00 - C * RADIX); A01 += C
	C = math.floor(A01 * INV24); buffer.writef64(Out, 8, A01 - C * RADIX); A02 += C
	C = math.floor(A02 * INV24); buffer.writef64(Out, 16, A02 - C * RADIX); A03 += C
	C = math.floor(A03 * INV24); buffer.writef64(Out, 24, A03 - C * RADIX); A04 += C
	C = math.floor(A04 * INV24); buffer.writef64(Out, 32, A04 - C * RADIX); A05 += C
	C = math.floor(A05 * INV24); buffer.writef64(Out, 40, A05 - C * RADIX); A06 += C
	C = math.floor(A06 * INV24); buffer.writef64(Out, 48, A06 - C * RADIX); A07 += C
	C = math.floor(A07 * INV24); buffer.writef64(Out, 56, A07 - C * RADIX); A08 += C
	C = math.floor(A08 * INV24); buffer.writef64(Out, 64, A08 - C * RADIX); A09 += C
	C = math.floor(A09 * INV24); buffer.writef64(Out, 72, A09 - C * RADIX); A10 += C
	C = math.floor(A10 * INV24); buffer.writef64(Out, 80, A10 - C * RADIX); buffer.writef64(Out, 88, C)
end

@native
local function LMulMP(A: buffer, B: buffer, Out: buffer): ()
	local A00, A01, A02, A03, A04, A05 = buffer.readf64(A, 0), buffer.readf64(A, 8), buffer.readf64(A, 16), buffer.readf64(A, 24), buffer.readf64(A, 32), buffer.readf64(A, 40)
	local A06, A07, A08, A09, A10 = buffer.readf64(A, 48), buffer.readf64(A, 56), buffer.readf64(A, 64), buffer.readf64(A, 72), buffer.readf64(A, 80)
	local B00, B01, B02, B03, B04, B05 = buffer.readf64(B, 0), buffer.readf64(B, 8), buffer.readf64(B, 16), buffer.readf64(B, 24), buffer.readf64(B, 32), buffer.readf64(B, 40)
	local B06, B07, B08, B09, B10 = buffer.readf64(B, 48), buffer.readf64(B, 56), buffer.readf64(B, 64), buffer.readf64(B, 72), buffer.readf64(B, 80)

	local L00 = A00 * B00
	local C = math.floor(L00 * INV24); buffer.writef64(Out, 0, L00 - C * RADIX)
	local L01 = A01 * B00 + A00 * B01 + C
	C = math.floor(L01 * INV24); buffer.writef64(Out, 8, L01 - C * RADIX)
	local L02 = A02 * B00 + A01 * B01 + A00 * B02 + C
	C = math.floor(L02 * INV24); buffer.writef64(Out, 16, L02 - C * RADIX)
	local L03 = A03 * B00 + A02 * B01 + A01 * B02 + A00 * B03 + C
	C = math.floor(L03 * INV24); buffer.writef64(Out, 24, L03 - C * RADIX)
	local L04 = A04 * B00 + A03 * B01 + A02 * B02 + A01 * B03 + A00 * B04 + C
	C = math.floor(L04 * INV24); buffer.writef64(Out, 32, L04 - C * RADIX)
	local L05 = A05 * B00 + A04 * B01 + A03 * B02 + A02 * B03 + A01 * B04 + A00 * B05 + C
	C = math.floor(L05 * INV24); buffer.writef64(Out, 40, L05 - C * RADIX)
	local L06 = A06 * B00 + A05 * B01 + A04 * B02 + A03 * B03 + A02 * B04 + A01 * B05 + A00 * B06 + C
	C = math.floor(L06 * INV24); buffer.writef64(Out, 48, L06 - C * RADIX)
	local L07 = A07 * B00 + A06 * B01 + A05 * B02 + A04 * B03 + A03 * B04 + A02 * B05 + A01 * B06 + A00 * B07 + C
	C = math.floor(L07 * INV24); buffer.writef64(Out, 56, L07 - C * RADIX)
	local L08 = A08 * B00 + A07 * B01 + A06 * B02 + A05 * B03 + A04 * B04 + A03 * B05 + A02 * B06 + A01 * B07 + A00 * B08 + C
	C = math.floor(L08 * INV24); buffer.writef64(Out, 64, L08 - C * RADIX)
	local L09 = A09 * B00 + A08 * B01 + A07 * B02 + A06 * B03 + A05 * B04 + A04 * B05 + A03 * B06 + A02 * B07 + A01 * B08 + A00 * B09 + C
	C = math.floor(L09 * INV24); buffer.writef64(Out, 72, L09 - C * RADIX)
	local L10 = A10 * B00 + A09 * B01 + A08 * B02 + A07 * B03 + A06 * B04 + A05 * B05 + A04 * B06 + A03 * B07 + A02 * B08 + A01 * B09 + A00 * B10 + C
	C = math.floor(L10 * INV24); buffer.writef64(Out, 80, L10 - C * RADIX); buffer.writef64(Out, 88, C)
end

@native
local function MulMP(A: buffer, B: buffer, LowOut: buffer, HighOut: buffer): ()
	LMulMP(A, B, LowOut)
	local Overflow = buffer.readf64(LowOut, 88)
	local A01, A02, A03, A04, A05 = buffer.readf64(A, 8), buffer.readf64(A, 16), buffer.readf64(A, 24), buffer.readf64(A, 32), buffer.readf64(A, 40)
	local A06, A07, A08, A09, A10 = buffer.readf64(A, 48), buffer.readf64(A, 56), buffer.readf64(A, 64), buffer.readf64(A, 72), buffer.readf64(A, 80)
	local B01, B02, B03, B04, B05 = buffer.readf64(B, 8), buffer.readf64(B, 16), buffer.readf64(B, 24), buffer.readf64(B, 32), buffer.readf64(B, 40)
	local B06, B07, B08, B09, B10 = buffer.readf64(B, 48), buffer.readf64(B, 56), buffer.readf64(B, 64), buffer.readf64(B, 72), buffer.readf64(B, 80)

	local H00 = Overflow + A10 * B01 + A09 * B02 + A08 * B03 + A07 * B04 + A06 * B05 + A05 * B06 + A04 * B07 + A03 * B08 + A02 * B09 + A01 * B10
	local C = math.floor(H00 * INV24); buffer.writef64(HighOut, 0, H00 - C * RADIX)
	local H01 = A10 * B02 + A09 * B03 + A08 * B04 + A07 * B05 + A06 * B06 + A05 * B07 + A04 * B08 + A03 * B09 + A02 * B10 + C
	C = math.floor(H01 * INV24); buffer.writef64(HighOut, 8, H01 - C * RADIX)
	local H02 = A10 * B03 + A09 * B04 + A08 * B05 + A07 * B06 + A06 * B07 + A05 * B08 + A04 * B09 + A03 * B10 + C
	C = math.floor(H02 * INV24); buffer.writef64(HighOut, 16, H02 - C * RADIX)
	local H03 = A10 * B04 + A09 * B05 + A08 * B06 + A07 * B07 + A06 * B08 + A05 * B09 + A04 * B10 + C
	C = math.floor(H03 * INV24); buffer.writef64(HighOut, 24, H03 - C * RADIX)
	local H04 = A10 * B05 + A09 * B06 + A08 * B07 + A07 * B08 + A06 * B09 + A05 * B10 + C
	C = math.floor(H04 * INV24); buffer.writef64(HighOut, 32, H04 - C * RADIX)
	local H05 = A10 * B06 + A09 * B07 + A08 * B08 + A07 * B09 + A06 * B10 + C
	C = math.floor(H05 * INV24); buffer.writef64(HighOut, 40, H05 - C * RADIX)
	local H06 = A10 * B07 + A09 * B08 + A08 * B09 + A07 * B10 + C
	C = math.floor(H06 * INV24); buffer.writef64(HighOut, 48, H06 - C * RADIX)
	local H07 = A10 * B08 + A09 * B09 + A08 * B10 + C
	C = math.floor(H07 * INV24); buffer.writef64(HighOut, 56, H07 - C * RADIX)
	local H08 = A10 * B09 + A09 * B10 + C
	C = math.floor(H08 * INV24); buffer.writef64(HighOut, 64, H08 - C * RADIX)
	local H09 = A10 * B10 + C
	C = math.floor(H09 * INV24); buffer.writef64(HighOut, 72, H09 - C * RADIX)
	buffer.writef64(HighOut, 80, C)
	buffer.writef64(HighOut, 88, 0)
end

@native
local function ReduceInto(LargeNumber: buffer, Out: buffer): ()
	local C = 0
	for Offset = 0, 80, 8 do
		local D = buffer.readf64(LargeNumber, Offset) - buffer.readf64(FIELD_ORDER, Offset) + C
		C = math.floor(D * INV24)
		buffer.writef64(MP_TMP, Offset, D - C * RADIX)
	end
	if C < 0 then
		CarryMP(LargeNumber, Out)
	else
		buffer.copy(Out, 0, MP_TMP, 0, 88)
		buffer.writef64(Out, 88, C)
	end
end

@native
local function MontReduceInto(Low: buffer, High: buffer?, Out: buffer): ()
	LMulMP(Low, MONTGOMERY_T0, MP_TMP)
	MulMP(MP_TMP, FIELD_ORDER, MP_RED_LOW, MP_RED_HIGH)
	local C = 0
	for Offset = 0, 80, 8 do
		local S = buffer.readf64(Low, Offset) + buffer.readf64(MP_RED_LOW, Offset) + C
		C = math.floor(S * INV24)
	end
	if High then
		for Offset = 0, 80, 8 do
			local S = buffer.readf64(High, Offset) + buffer.readf64(MP_RED_HIGH, Offset) + C
			C = math.floor(S * INV24)
			buffer.writef64(MP_RED_HIGH, Offset, S - C * RADIX)
		end
	else
		for Offset = 0, 80, 8 do
			local S = buffer.readf64(MP_RED_HIGH, Offset) + C
			C = math.floor(S * INV24)
			buffer.writef64(MP_RED_HIGH, Offset, S - C * RADIX)
		end
	end
	ReduceInto(MP_RED_HIGH, Out)
end

local FieldQuadratic = {}

@native
function FieldQuadratic.IsValidScalar(ScalarBytes: buffer): boolean
	local FieldOrder = FIELD_ORDER_BYTES
	local Borrow = 0
	for Index = 0, 31 do
		local Diff = buffer.readu8(ScalarBytes, Index) - buffer.readu8(FieldOrder, Index) - Borrow
		Borrow = 1 - bit32.rshift(Diff + 256, 8)
	end
	return Borrow == 1
end

@native
function FieldQuadratic.Add(ScalarA: buffer, ScalarB: buffer, Out: buffer?): buffer
	local Dest = Out or buffer.create(SIZE)
	for Offset = 0, 80, 8 do
		buffer.writef64(MP_PROD_LOW, Offset, buffer.readf64(ScalarA, Offset) + buffer.readf64(ScalarB, Offset))
	end
	ReduceInto(MP_PROD_LOW, Dest)
	return Dest
end

function FieldQuadratic.Mul(ScalarA: buffer, ScalarB: buffer, Out: buffer?): buffer
	local Dest = Out or buffer.create(SIZE)
	MulMP(ScalarA, ScalarB, MP_PROD_LOW, MP_PROD_HIGH)
	MontReduceInto(MP_PROD_LOW, MP_PROD_HIGH, Dest)
	return Dest
end

function FieldQuadratic.Montgomery(RegularScalar: buffer, Out: buffer?): buffer
	return FieldQuadratic.Mul(RegularScalar, MONTGOMERY_T1, Out)
end

function FieldQuadratic.Regular(MontgomeryScalar: buffer, Out: buffer?): buffer
	local Dest = Out or buffer.create(SIZE)
	MontReduceInto(MontgomeryScalar, nil, Dest)
	return Dest
end

@native
function FieldQuadratic.EncodeInto(MontgomeryScalar: buffer, Out32: buffer): ()
	MontReduceInto(MontgomeryScalar, nil, DECODE_LOW)
	local ByteIndex = 0
	for LimbIndex = 0, 9 do
		local Value = buffer.readf64(DECODE_LOW, LimbIndex * 8)
		buffer.writeu8(Out32, ByteIndex, bit32.band(Value, 0xFF))
		buffer.writeu8(Out32, ByteIndex + 1, bit32.band(bit32.rshift(Value, 8), 0xFF))
		buffer.writeu8(Out32, ByteIndex + 2, bit32.band(bit32.rshift(Value, 16), 0xFF))
		ByteIndex += 3
	end
	local LastValue = buffer.readf64(DECODE_LOW, 80)
	buffer.writeu8(Out32, 30, bit32.band(LastValue, 0xFF))
	buffer.writeu8(Out32, 31, bit32.band(bit32.rshift(LastValue, 8), 0xFF))
end

function FieldQuadratic.Encode(MontgomeryScalar: buffer): buffer
	local EncodedBuffer = buffer.create(32)
	FieldQuadratic.EncodeInto(MontgomeryScalar, EncodedBuffer)
	return EncodedBuffer
end

@native
function FieldQuadratic.Decode(EncodedBuffer: buffer, Out: buffer?): buffer
	local DecodedBuffer = DECODE_LOW
	local ByteIndex = 0
	for LimbIndex = 0, 9 do
		local Value = buffer.readu8(EncodedBuffer, ByteIndex)
			+ buffer.readu8(EncodedBuffer, ByteIndex + 1) * 256
			+ buffer.readu8(EncodedBuffer, ByteIndex + 2) * 65536
		buffer.writef64(DecodedBuffer, LimbIndex * 8, Value)
		ByteIndex += 3
	end
	buffer.writef64(DecodedBuffer, 80, buffer.readu8(EncodedBuffer, 30) + buffer.readu8(EncodedBuffer, 31) * 256)
	return FieldQuadratic.Mul(DecodedBuffer, MONTGOMERY_T1, Out)
end

@native
function FieldQuadratic.DecodeWide(WideBuffer: buffer, Out: buffer?): buffer
	local LowPart = DECODE_LOW
	local HighPart = DECODE_HIGH
	for LimbIndex = 0, 10 do
		local ByteIndex = LimbIndex * 3
		buffer.writef64(
			LowPart,
			LimbIndex * 8,
			buffer.readu8(WideBuffer, ByteIndex)
				+ buffer.readu8(WideBuffer, ByteIndex + 1) * 256
				+ buffer.readu8(WideBuffer, ByteIndex + 2) * 65536
		)
	end
	for LimbIndex = 0, 9 do
		local ByteIndex = 33 + LimbIndex * 3
		buffer.writef64(
			HighPart,
			LimbIndex * 8,
			buffer.readu8(WideBuffer, ByteIndex)
				+ buffer.readu8(WideBuffer, ByteIndex + 1) * 256
				+ buffer.readu8(WideBuffer, ByteIndex + 2) * 65536
		)
	end
	buffer.writef64(HighPart, 80, buffer.readu8(WideBuffer, 63))

	FieldQuadratic.Mul(LowPart, MONTGOMERY_T1, DECODE_WIDE_A)
	FieldQuadratic.Mul(HighPart, MONTGOMERY_T2, DECODE_WIDE_B)
	return FieldQuadratic.Add(DECODE_WIDE_A, DECODE_WIDE_B, Out)
end

function FieldQuadratic.DecodeClamped(ClampedBuffer: buffer, Out: buffer?): buffer
	buffer.copy(CLAMPED_BUFFER, 0, ClampedBuffer, 0, 32)
	buffer.writeu8(CLAMPED_BUFFER, 0, bit32.band(buffer.readu8(CLAMPED_BUFFER, 0), 0xF8))
	buffer.writeu8(CLAMPED_BUFFER, 31, bit32.bor(bit32.band(buffer.readu8(CLAMPED_BUFFER, 31), 0x7F), 0x40))
	return FieldQuadratic.Decode(CLAMPED_BUFFER, Out)
end

function FieldQuadratic.ClearCaches(): ()
	buffer.fill(MP_PROD_LOW, 0, 0)
	buffer.fill(MP_PROD_HIGH, 0, 0)
	buffer.fill(MP_RED_LOW, 0, 0)
	buffer.fill(MP_RED_HIGH, 0, 0)
	buffer.fill(MP_TMP, 0, 0)
	buffer.fill(DECODE_LOW, 0, 0)
	buffer.fill(DECODE_HIGH, 0, 0)
	buffer.fill(DECODE_WIDE_A, 0, 0)
	buffer.fill(DECODE_WIDE_B, 0, 0)
	buffer.fill(CLAMPED_BUFFER, 0, 0)
end

return FieldQuadratic
