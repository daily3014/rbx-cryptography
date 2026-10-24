--[=[
	Cryptography library: Field Quadratic (Curve25519 Scalar Field)

	Return type: varies by function
	Example usage:
		--------Usage Case 1: Basic scalar arithmetic--------
		local ScalarA = FieldQuadratic.Decode(SomeBytes)
		local ScalarB = FieldQuadratic.Decode(OtherBytes)
		local Sum = FieldQuadratic.Add(ScalarA, ScalarB)
		local Product = FieldQuadratic.Mul(ScalarA, ScalarB)

		--------Usage Case 2: Convert to bits for scalar multiplication--------
		local ScalarBits = FieldQuadratic.Bits(ScalarA)
		local EncodedResult = FieldQuadratic.Encode(Product)
--]=]

--!strict
--!optimize 2
--!native

local MultiPrecision = require("./MultiPrecision")

local CONSTANT_ZERO = MultiPrecision.Num(0)

local OUTPUT_BUFFER = buffer.create(8192)
local DECODE_WIDE_LOW = buffer.create(96)
local DECODE_WIDE_HIGH = buffer.create(96)
local DECODE_BUFFER = buffer.create(96)
local CLAMPED_BUFFER = buffer.create(32)

local FIELD_ORDER_BYTES = buffer.create(32) do
	local Bytes = {
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
	}
	for Index = 1, 32 do
		buffer.writeu8(FIELD_ORDER_BYTES, Index - 1, Bytes[Index])
	end
end

local FIELD_ORDER = buffer.create(96) do
	local ByteIndex = 0

	for LimbIndex = 0, 9 do
		local Value = buffer.readu8(FIELD_ORDER_BYTES, ByteIndex)
			+ buffer.readu8(FIELD_ORDER_BYTES, ByteIndex + 1) * 256
			+ buffer.readu8(FIELD_ORDER_BYTES, ByteIndex + 2) * 65536

		buffer.writef64(FIELD_ORDER, LimbIndex * 8, Value)
		ByteIndex += 3
	end

	local LastValue = buffer.readu8(FIELD_ORDER_BYTES, 30)
		+ buffer.readu8(FIELD_ORDER_BYTES, 31) * 256
	buffer.writef64(FIELD_ORDER, 10 * 8, LastValue)
end

local MONTGOMERY_T0 = buffer.create(96) do
	local Values = {
		05537307, 01942290, 16765621, 16628356, 10618610,
		07072433, 03735459, 01369940, 15276086, 13038191,
		13409718
	}
	for Index = 1, 11 do
		buffer.writef64(MONTGOMERY_T0, (Index - 1) * 8, Values[Index])
	end
end

local MONTGOMERY_T1 = buffer.create(96) do
	local Values = {
		11711996, 01747860, 08326961, 03814718, 01859974,
		13327461, 16105061, 07590423, 04050668, 08138906,
		00000283
	}
	for Index = 1, 11 do
		buffer.writef64(MONTGOMERY_T1, (Index - 1) * 8, Values[Index])
	end
end

local function Reduce(LargeNumber: buffer): buffer
	local Difference = MultiPrecision.Sub(LargeNumber, FIELD_ORDER)

	if MultiPrecision.Approx(Difference) < 0 then
		return MultiPrecision.Carry(LargeNumber)
	end

	return MultiPrecision.Carry(Difference)
end

local function Demontgomery(MontgomeryScalar: buffer): buffer
	local ReductionLow, ReductionHigh = MultiPrecision.Mul(MultiPrecision.LMul(MontgomeryScalar, MONTGOMERY_T0), FIELD_ORDER)
	local _, ResultHigh = MultiPrecision.DWAdd(MontgomeryScalar, CONSTANT_ZERO, ReductionLow, ReductionHigh)

	return Reduce(ResultHigh)
end

local function RebaseLE(InputBuffer: buffer, InputLength: number, FromBase: number, ToBase: number): (buffer, number)
	local OutputLength = 0
	local Accumulator = 0
	local Multiplier = 1

	for Index = 0, InputLength - 1 do
		Accumulator += buffer.readf64(InputBuffer, Index * 8) * Multiplier
		Multiplier *= FromBase
		while Multiplier >= ToBase do
			local Remainder = Accumulator % ToBase
			Accumulator = (Accumulator - Remainder) / ToBase
			Multiplier /= ToBase
			buffer.writef64(OUTPUT_BUFFER, OutputLength * 8, Remainder)
			OutputLength += 1
		end
	end

	if Multiplier > 0 then
		buffer.writef64(OUTPUT_BUFFER, OutputLength * 8, Accumulator)
		OutputLength += 1
	end

	return OUTPUT_BUFFER, OutputLength
end

local FieldQuadratic = {}

function FieldQuadratic.IsValidScalar(ScalarBytes: buffer): boolean
	local FieldOrder = FIELD_ORDER_BYTES
	local Borrow = 0

	for Index = 0, 31 do
		local ScalarByte = buffer.readu8(ScalarBytes, Index)
		local OrderByte = buffer.readu8(FieldOrder, Index)
		local Diff = ScalarByte - OrderByte - Borrow
		Borrow = 1 - bit32.rshift(Diff + 256, 8)
	end

	return Borrow == 1
end

function FieldQuadratic.Montgomery(RegularScalar: buffer): buffer
	return FieldQuadratic.Mul(RegularScalar, MONTGOMERY_T1)
end

function FieldQuadratic.Add(ScalarA: buffer, ScalarB: buffer): buffer
	return Reduce(MultiPrecision.Add(ScalarA, ScalarB))
end

function FieldQuadratic.Neg(ScalarA: buffer): buffer
	return Reduce(MultiPrecision.Sub(FIELD_ORDER, ScalarA))
end

function FieldQuadratic.Mul(ScalarA: buffer, ScalarB: buffer): buffer
	local ProductLow, ProductHigh = MultiPrecision.Mul(ScalarA, ScalarB)
	local ReductionLow, ReductionHigh = MultiPrecision.Mul(MultiPrecision.LMul(ProductLow, MONTGOMERY_T0), FIELD_ORDER)
	local _, ResultHigh = MultiPrecision.DWAdd(ProductLow, ProductHigh, ReductionLow, ReductionHigh)

	return Reduce(ResultHigh)
end

function FieldQuadratic.Encode(MontgomeryScalar: buffer): buffer
	local DemontResult = Demontgomery(MontgomeryScalar)
	local EncodedBuffer = buffer.create(32)
	local ByteIndex = 0
	for LimbIndex = 0, 9 do
		local Value = buffer.readf64(DemontResult, LimbIndex * 8)
		buffer.writeu8(EncodedBuffer, ByteIndex, Value % 256)
		Value = Value // 256
		buffer.writeu8(EncodedBuffer, ByteIndex + 1, Value % 256)
		Value = Value // 256
		buffer.writeu8(EncodedBuffer, ByteIndex + 2, Value % 256)
		ByteIndex += 3
	end

	local LastValue = buffer.readf64(DemontResult, 10 * 8)
	buffer.writeu8(EncodedBuffer, 30, LastValue % 256)
	LastValue = LastValue // 256
	buffer.writeu8(EncodedBuffer, 31, LastValue % 256)

	return EncodedBuffer
end

function FieldQuadratic.Decode(EncodedBuffer: buffer): buffer
	local DecodedBuffer = DECODE_BUFFER
	local ByteIndex = 0

	for LimbIndex = 0, 9 do
		local Value = buffer.readu8(EncodedBuffer, ByteIndex)
			+ buffer.readu8(EncodedBuffer, ByteIndex + 1) * 256
			+ buffer.readu8(EncodedBuffer, ByteIndex + 2) * 65536

		buffer.writef64(DecodedBuffer, LimbIndex * 8, Value)
		ByteIndex += 3
	end

	local LastValue = buffer.readu8(EncodedBuffer, 30)
		+ buffer.readu8(EncodedBuffer, 31) * 256
	buffer.writef64(DecodedBuffer, 10 * 8, LastValue)

	return FieldQuadratic.Montgomery(DecodedBuffer)
end

function FieldQuadratic.DecodeWide(WideBuffer: buffer): buffer
	local LowPart = DECODE_WIDE_LOW
	local HighPart = DECODE_WIDE_HIGH

	for LimbIndex = 0, 10 do
		local ByteIndex = LimbIndex * 3
		local Value = buffer.readu8(WideBuffer, ByteIndex)
			+ buffer.readu8(WideBuffer, ByteIndex + 1) * 256
			+ buffer.readu8(WideBuffer, ByteIndex + 2) * 65536
		buffer.writef64(LowPart, LimbIndex * 8, Value)
	end

	for LimbIndex = 0, 9 do
		local ByteIndex = 33 + LimbIndex * 3
		local Value = buffer.readu8(WideBuffer, ByteIndex)
			+ buffer.readu8(WideBuffer, ByteIndex + 1) * 256
			+ buffer.readu8(WideBuffer, ByteIndex + 2) * 65536
		buffer.writef64(HighPart, LimbIndex * 8, Value)
	end
	buffer.writef64(HighPart, 10 * 8, buffer.readu8(WideBuffer, 63))

	local MontLow = FieldQuadratic.Montgomery(LowPart)
	local MontHigh = FieldQuadratic.Montgomery(HighPart)
	local MontMontHigh = FieldQuadratic.Montgomery(MontHigh)

	return FieldQuadratic.Add(MontLow, MontMontHigh)
end

function FieldQuadratic.DecodeClamped(ClampedBuffer: buffer): buffer
	local ClampedCopy = CLAMPED_BUFFER
	buffer.copy(ClampedCopy, 0, ClampedBuffer, 0, 32)

	local FirstByte = buffer.readu8(ClampedCopy, 0)
	buffer.writeu8(ClampedCopy, 0, bit32.band(FirstByte, 0xF8))

	local LastByte = buffer.readu8(ClampedCopy, 31)
	buffer.writeu8(ClampedCopy, 31, bit32.bor(bit32.band(LastByte, 0x7F), 0x40))

	return FieldQuadratic.Decode(ClampedCopy)
end

function FieldQuadratic.Bits(MontgomeryScalar: buffer): (buffer, number)
	local DemontResult = Demontgomery(MontgomeryScalar)
	local BitOutput, BitCount = RebaseLE(DemontResult, 11, 2 ^ 24, 2)

	if BitCount > 253 then
		BitCount = 253
	end

	return BitOutput, BitCount
end

return FieldQuadratic
