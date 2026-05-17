--[=[
	Cryptography library: Field Quadratic (Curve25519 Scalar Field)

	Return type: varies by function
	Example usage:
		local FieldQuadratic = require("FieldQuadratic")

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

local RULE_BUFFER = buffer.create(1024)
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

local function WriteIntLimbs(Buf: buffer, Values: {number})
	for Index = 1, 11 do
		buffer.writeinteger(Buf, (Index - 1) * 8, integer.create(Values[Index]) :: integer)
	end
end

local FIELD_ORDER = buffer.create(96) do
	local Limbs = table.create(11, 0)
	local ByteIndex = 0
	for LimbIndex = 1, 10 do
		Limbs[LimbIndex] = buffer.readu8(FIELD_ORDER_BYTES, ByteIndex)
			+ buffer.readu8(FIELD_ORDER_BYTES, ByteIndex + 1) * 256
			+ buffer.readu8(FIELD_ORDER_BYTES, ByteIndex + 2) * 65536
		ByteIndex += 3
	end
	Limbs[11] = buffer.readu8(FIELD_ORDER_BYTES, 30)
		+ buffer.readu8(FIELD_ORDER_BYTES, 31) * 256
	WriteIntLimbs(FIELD_ORDER, Limbs)
end

local MONTGOMERY_T0 = buffer.create(96) do
	WriteIntLimbs(MONTGOMERY_T0, {
		05537307, 01942290, 16765621, 16628356, 10618610,
		07072433, 03735459, 01369940, 15276086, 13038191,
		13409718
	})
end

local MONTGOMERY_T1 = buffer.create(96) do
	WriteIntLimbs(MONTGOMERY_T1, {
		11711996, 01747860, 08326961, 03814718, 01859974,
		13327461, 16105061, 07590423, 04050668, 08138906,
		00000283
	})
end

local DIVIDE_8 = buffer.create(96) do
	WriteIntLimbs(DIVIDE_8, {
		5110253, 3039345, 2503500, 11779568, 15416472,
		16766550, 16777215, 16777215, 16777215, 16777215,
		4095
	})
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

local function RebaseLE24ToBits(InputBuffer: buffer, InputLength: number): (buffer, number)
	local OutputBuffer = buffer.create(InputLength * 24 + 8)
	local OutputLength = 0
	local Accumulator = 0i
	local Multiplier = 1i
	local TwoPow24 = 0x1000000i

	for Index = 0, InputLength - 1 do
		Accumulator = integer.add(Accumulator, integer.mul(buffer.readinteger(InputBuffer, Index * 8), Multiplier))
		Multiplier = integer.mul(Multiplier, TwoPow24)
		while integer.ge(Multiplier, 2i) do
			local Remainder = integer.band(Accumulator, 1i)
			Accumulator = integer.arshift(Accumulator, 1i)
			Multiplier = integer.arshift(Multiplier, 1i)
			buffer.writeu8(OutputBuffer, OutputLength, integer.tonumber(Remainder))
			OutputLength += 1
		end
	end

	if integer.gt(Multiplier, 0i) then
		buffer.writeu8(OutputBuffer, OutputLength, integer.tonumber(Accumulator))
		OutputLength += 1
	end

	return OutputBuffer, OutputLength
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

function FieldQuadratic.Sub(ScalarA: buffer, ScalarB: buffer): buffer
	return FieldQuadratic.Add(ScalarA, FieldQuadratic.Neg(ScalarB))
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
	for LimbIndex = 0, 9 do
		local Value = buffer.readinteger(DemontResult, LimbIndex * 8)
		buffer.writeu32(EncodedBuffer, LimbIndex * 3, integer.tonumber(integer.band(Value, 0xFFFFFFi)))
	end

	local LastValue = buffer.readinteger(DemontResult, 80)
	buffer.writeu16(EncodedBuffer, 30, integer.tonumber(integer.band(LastValue, 0xFFFFi)))

	return EncodedBuffer
end

function FieldQuadratic.Decode(EncodedBuffer: buffer): buffer
	local DecodedBuffer = DECODE_BUFFER

	for LimbIndex = 0, 9 do
		local Value = bit32.band(buffer.readu32(EncodedBuffer, LimbIndex * 3), 0xFFFFFF)
		buffer.writeinteger(DecodedBuffer, LimbIndex * 8, integer.create(Value) :: integer)
	end

	local LastValue = buffer.readu16(EncodedBuffer, 30)
	buffer.writeinteger(DecodedBuffer, 80, integer.create(LastValue) :: integer)

	return FieldQuadratic.Montgomery(DecodedBuffer)
end

function FieldQuadratic.DecodeWide(WideBuffer: buffer): buffer
	local LowPart = DECODE_WIDE_LOW
	local HighPart = DECODE_WIDE_HIGH

	for LimbIndex = 0, 10 do
		local Value = bit32.band(buffer.readu32(WideBuffer, LimbIndex * 3), 0xFFFFFF)
		buffer.writeinteger(LowPart, LimbIndex * 8, integer.create(Value) :: integer)
	end

	for LimbIndex = 0, 9 do
		local Value = bit32.band(buffer.readu32(WideBuffer, 33 + LimbIndex * 3), 0xFFFFFF)
		buffer.writeinteger(HighPart, LimbIndex * 8, integer.create(Value) :: integer)
	end
	buffer.writeinteger(HighPart, 80, integer.create(buffer.readu8(WideBuffer, 63)) :: integer)

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
	local BitOutput, BitCount = RebaseLE24ToBits(DemontResult, 11)

	if BitCount > 253 then
		BitCount = 253
	end

	return BitOutput, BitCount
end

return FieldQuadratic
