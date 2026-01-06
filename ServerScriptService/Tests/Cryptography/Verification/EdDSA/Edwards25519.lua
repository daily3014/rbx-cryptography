-- @ScriptType: ModuleScript
--[=[
	Cryptography library: Edwards25519

	Return type: varies by function
	Example usage:
		local Edwards = require("Edwards25519")
		local FieldQuadratic = require("FieldQuadratic")

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

local BASEPONT_G = nil
local BASEPOINT_TABLE: buffer

local POINT_SIZE = 416
local COORD_SIZE = 104

local BASE_RADIX_WIDTH = 5
local BASE_POINT_ROW = 2 ^ BASE_RADIX_WIDTH / 2

local CURVE_D = FieldPrime.Mul(FieldPrime.Num(-121665), FieldPrime.Invert(FieldPrime.Num(121666)))
local CURVE_K = FieldPrime.KMul(CURVE_D, 2)

local IDENTITY_O = buffer.create(POINT_SIZE) do
	buffer.copy(IDENTITY_O, 0, FieldPrime.Num(0), 0, COORD_SIZE)
	buffer.copy(IDENTITY_O, COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)
	buffer.copy(IDENTITY_O, 2 * COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)
	buffer.copy(IDENTITY_O, 3 * COORD_SIZE, FieldPrime.Num(0), 0, COORD_SIZE)
end

local function GetCoord(Point: buffer, Index: number): buffer
	local Coord = buffer.create(COORD_SIZE)
	buffer.copy(Coord, 0, Point, Index * COORD_SIZE, COORD_SIZE)

	return Coord
end

local Edwards25519 = {}

function Edwards25519.Double(Point1: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0)
	local Point1Y = GetCoord(Point1, 1)
	local Point1Z = GetCoord(Point1, 2)

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
	local Point1X = GetCoord(Point1, 0)
	local Point1Y = GetCoord(Point1, 1)
	local Point1Z = GetCoord(Point1, 2)
	local Point1T = GetCoord(Point1, 3)

	local Niels1Plus = GetCoord(NielsPoint2, 0)
	local Niels1Minus = GetCoord(NielsPoint2, 1)
	local Niels1Z = GetCoord(NielsPoint2, 2)
	local Niels1T = GetCoord(NielsPoint2, 3)

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
	local Point1X = GetCoord(Point1, 0)
	local Point1Y = GetCoord(Point1, 1)
	local Point1Z = GetCoord(Point1, 2)
	local Point1T = GetCoord(Point1, 3)

	local Niels1Plus = GetCoord(NielsPoint2, 0)
	local Niels1Minus = GetCoord(NielsPoint2, 1)
	local Niels1Z = GetCoord(NielsPoint2, 2)
	local Niels1T = GetCoord(NielsPoint2, 3)

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
	local Point1X = GetCoord(Point1, 0)
	local Point1Y = GetCoord(Point1, 1)
	local Point1Z = GetCoord(Point1, 2)
	local Point1T = GetCoord(Point1, 3)

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

function Edwards25519.Scale(Point1: buffer): buffer
	local Point1X = GetCoord(Point1, 0)
	local Point1Y = GetCoord(Point1, 1)
	local Point1Z = GetCoord(Point1, 2)

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
	local Point1X = GetCoord(ScaledPoint, 0)
	local Point1Y = GetCoord(ScaledPoint, 1)

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

local function SignedRadixW(ScalarBits: buffer, ScalarBitCount: number, RadixWidth: number): (buffer, number)
	if ScalarBitCount <= 0 or ScalarBitCount > 256 then
		error("Invalid scalar bit  count", 2)
	end

	if RadixWidth <= 0 or RadixWidth > 8 then
		error("Invalid Radix width", 2)
	end

	local RadixValue = 2 ^ RadixWidth
	local HalfRadix = RadixValue / 2
	local MaxOutputLength = ScalarBitCount + math.ceil(math.log(ScalarBitCount, 2)) + 1
	local OutputDigits = buffer.create(MaxOutputLength * 8)
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

			local Remainder = Accumulator % RadixValue
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

local function RadixWTable(BasePoint: buffer, RadixWidth: number): buffer
	if RadixWidth <= 0 or RadixWidth > 8 then
		error("Invalid Radix width", 2)
	end

	if buffer.len(BasePoint) ~= POINT_SIZE then
		error("Invalid Basepoint", 2)
	end

	local PointSize = POINT_SIZE
	local MaxWindows = math.ceil(256 / RadixWidth)
	local MaxRowSize = 2 ^ RadixWidth / 2

	local TableData = buffer.create(MaxWindows * MaxRowSize * PointSize)

	local CurrentBasePoint = buffer.create(PointSize)
	buffer.copy(CurrentBasePoint, 0, BasePoint, 0, PointSize)

	for WindowIndex = 1, MaxWindows do
		local BaseOffset = ((WindowIndex - 1) * MaxRowSize * PointSize)
		local WorkingPoint = buffer.create(PointSize)
		buffer.copy(WorkingPoint, 0, CurrentBasePoint, 0, PointSize)

		local NielsBuffer = buffer.create(PointSize)
		local FirstNiels = Edwards25519.Niels(WorkingPoint)
		buffer.copy(TableData, BaseOffset, FirstNiels, 0, PointSize)

		for Multiple = 2, MaxRowSize do
			Edwards25519.Add(WorkingPoint, FirstNiels, WorkingPoint)
			Edwards25519.Niels(WorkingPoint, NielsBuffer)

			local Offset = BaseOffset + ((Multiple - 1) * PointSize)
			buffer.copy(TableData, Offset, NielsBuffer, 0, PointSize)
		end

		for _ = 1, RadixWidth do
			CurrentBasePoint = Edwards25519.Double(CurrentBasePoint)
		end
	end

	return TableData
end

do
	if BASEPONT_G then
		BASEPOINT_TABLE = RadixWTable(BASEPONT_G, BASE_RADIX_WIDTH)
	end
end

local function GetBasePointTableEntry(WindowIndex: number, Multiple: number, Storage: buffer?): buffer
	local BaseOffset = ((WindowIndex - 1) * BASE_POINT_ROW * POINT_SIZE)
	local Offset = BaseOffset + ((Multiple - 1) * POINT_SIZE)

	local NielsPoint = Storage or buffer.create(POINT_SIZE)
	buffer.copy(NielsPoint, 0, BASEPOINT_TABLE, Offset, POINT_SIZE)

	return NielsPoint
end

local function WindowedNAF(ScalarBits: buffer, ScalarBitCount: number, WindowWidth: number): (buffer, number)
	local WindowValue = 2 ^ WindowWidth
	local HalfWindow = WindowValue / 2
	local OutputNAF = buffer.create(512 * 8)
	local OutputLength = 0
	local Accumulator = 0
	local Multiplier = 1

	for BitIndex = 1, ScalarBitCount do
		local BitValue = buffer.readf64(ScalarBits, (BitIndex - 1) * 8)
		Accumulator += BitValue * Multiplier
		Multiplier *= 2

		while BitIndex == ScalarBitCount and Accumulator > 0 or Multiplier > WindowValue do
			if Accumulator % 2 == 0 then
				Accumulator /= 2
				Multiplier /= 2
				buffer.writef64(OutputNAF, OutputLength * 8, 0)
				OutputLength += 1
			else
				local Remainder = Accumulator % WindowValue
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

local function WindowedNAFTable(BasePoint: buffer, WindowWidth: number): buffer
	local PointSize = POINT_SIZE

	local MaxOddMultiples = 2 ^ WindowWidth
	local DoubledPoint = Edwards25519.Double(BasePoint)

	local TableData = buffer.create(MaxOddMultiples * PointSize)

	Edwards25519.Niels(BasePoint, BasePoint)
	local FirstNiels = BasePoint
	buffer.copy(TableData, 0, FirstNiels, 0, PointSize)

	for OddMultiple = 3, MaxOddMultiples, 2 do
		local PrevOffset = ((OddMultiple - 3) * PointSize)
		local CurrentOffset = ((OddMultiple - 1) * PointSize)

		buffer.copy(BasePoint, 0, TableData, PrevOffset, PointSize)

		Edwards25519.Niels(Edwards25519.Add(DoubledPoint, BasePoint, BasePoint), BasePoint)
		local CurrentNiels = BasePoint
		buffer.copy(TableData, CurrentOffset, CurrentNiels, 0, PointSize)
	end

	return TableData
end

function Edwards25519.MulG(ScalarBits: buffer, ScalarBitCount: number): buffer
	local PointSize = POINT_SIZE

	local SignedWindows, WindowCount = SignedRadixW(ScalarBits, ScalarBitCount, BASE_RADIX_WIDTH)
	local ResultPoint = buffer.create(PointSize)
	buffer.copy(ResultPoint, 0, IDENTITY_O, 0, PointSize)

	local NielsPoint = buffer.create(PointSize)
	for WindowIndex = 1, WindowCount do
		local WindowValue = buffer.readf64(SignedWindows, (WindowIndex - 1) * 8)
		if WindowValue > 0 then
			GetBasePointTableEntry(WindowIndex, WindowValue, NielsPoint)
			ResultPoint = Edwards25519.Add(ResultPoint, NielsPoint)
		elseif WindowValue < 0 then
			GetBasePointTableEntry(WindowIndex, -WindowValue, NielsPoint)
			ResultPoint = Edwards25519.Sub(ResultPoint, NielsPoint)
		end
	end

	return ResultPoint
end

function Edwards25519.Mul(BasePoint: buffer, ScalarBits: buffer, ScalarBitCount: number): buffer
	local NAFForm, NAFLength = WindowedNAF(ScalarBits, ScalarBitCount, 5)
	local MultipleTable = WindowedNAFTable(BasePoint, 5)
	local ResultPoint = buffer.create(POINT_SIZE)
	buffer.copy(ResultPoint, 0, IDENTITY_O, 0, POINT_SIZE)

	local NielsPoint = buffer.create(POINT_SIZE)
	for NAFIndex = NAFLength, 1, -1 do
		local NAFDigit = buffer.readf64(NAFForm, (NAFIndex - 1) * 8)

		if NAFDigit == 0 then
			Edwards25519.Double(ResultPoint, ResultPoint)
		elseif NAFDigit > 0 then
			buffer.copy(NielsPoint, 0, MultipleTable, ((NAFDigit - 1) * POINT_SIZE), POINT_SIZE)
			Edwards25519.Add(ResultPoint, NielsPoint, ResultPoint)
		else
			buffer.copy(NielsPoint, 0, MultipleTable, (((-NAFDigit) - 1) * POINT_SIZE), POINT_SIZE)
			Edwards25519.Sub(ResultPoint, NielsPoint, ResultPoint)
		end
	end

	return ResultPoint
end

return Edwards25519