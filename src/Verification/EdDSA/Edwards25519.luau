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
--!native
--!optimize 2

local FieldPrime = require("./FieldPrime")

local POINT_SIZE = 416
local COORD_SIZE = 104

local Edwards25519 = {}

local BasePointRadixWidth = 5
local BasePointTableMaxRowSize = 2 ^ BasePointRadixWidth / 2

local CurveD = FieldPrime.Mul(FieldPrime.Num(-121665), FieldPrime.Invert(FieldPrime.Num(121666)))
local CurveK = FieldPrime.KMul(CurveD, 2)

local IdentityO = buffer.create(POINT_SIZE)
do
	buffer.copy(IdentityO, 0, FieldPrime.Num(0), 0, COORD_SIZE)
	buffer.copy(IdentityO, COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)
	buffer.copy(IdentityO, 2 * COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)
	buffer.copy(IdentityO, 3 * COORD_SIZE, FieldPrime.Num(0), 0, COORD_SIZE)
end

local BasePointG = nil
local BasePointTable = nil

local function GetCoord(Point: buffer, Index: number): buffer
	local Coord = buffer.create(COORD_SIZE)
	buffer.copy(Coord, 0, Point, Index * COORD_SIZE, COORD_SIZE)
	return Coord
end

local function SetCoord(Point: buffer, Index: number, Value: buffer)
	buffer.copy(Point, Index * COORD_SIZE, Value, 0, COORD_SIZE)
end

function Edwards25519.Double(Point1: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0)
	local Point1Y = GetCoord(Point1, 1)
	local Point1Z = GetCoord(Point1, 2)

	local SquaredA = FieldPrime.Square(Point1X)
	local SquaredB = FieldPrime.Square(Point1Y)
	FieldPrime.Square(Point1Z, Point1Z) -- Reused Point1Z
	FieldPrime.Add(Point1Z, Point1Z, Point1Z) -- Reused Point1Z
	local DoubledD = Point1Z
	local SumE = FieldPrime.Add(SquaredA, SquaredB)
	FieldPrime.Add(Point1X, Point1Y, Point1X) -- Reused Point1X
	local SumF = Point1X
	local SquaredG = FieldPrime.Square(SumF)
	FieldPrime.Sub(SquaredG, SumE, SquaredG) -- Reused SquaredG
	FieldPrime.Carry(SquaredG, SquaredG) -- Reused SquaredG
	local DiffH = SquaredG
	FieldPrime.Sub(SquaredB, SquaredA, SquaredB) -- Reused SquaredB
	local DiffI = SquaredB
	FieldPrime.Sub(DoubledD, DiffI, DoubledD) -- Reused DoubledD
	FieldPrime.Carry(DoubledD, DoubledD) -- Reused DoubledD
	local DiffJ = DoubledD

	local NewX = FieldPrime.Mul(DiffH, DiffJ)
	local NewY = FieldPrime.Mul(DiffI, SumE)
	FieldPrime.Mul(DiffJ, DiffI, DiffJ) -- Reused DiffJ
	local NewZ = DiffJ
	FieldPrime.Mul(DiffH, SumE, DiffH) -- Reused DiffH
	local NewT = DiffH

	local Result = Storage or buffer.create(POINT_SIZE)
	SetCoord(Result, 0, NewX)
	SetCoord(Result, 1, NewY)
	SetCoord(Result, 2, NewZ)
	SetCoord(Result, 3, NewT)
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
	FieldPrime.Mul(DiffA, Niels1Minus, DiffA) -- Reused DiffA
	local ProductB = DiffA

	local SumC = FieldPrime.Add(Point1Y, Point1X)
	FieldPrime.Mul(SumC, Niels1Plus, SumC) -- Reused SumC
	local ProductD = SumC

	FieldPrime.Mul(Point1T, Niels1T, Point1T) -- Reused Point1T
	local ProductE = Point1T

	FieldPrime.Mul(Point1Z, Niels1Z, Point1Z) -- Reused Point1Z
	local ProductF = Point1Z

	local DiffG = FieldPrime.Sub(ProductD, ProductB)
	local DiffH = FieldPrime.Sub(ProductF, ProductE)

	FieldPrime.Add(ProductF, ProductE, ProductF) -- Reused ProductF
	local SumI = ProductF

	FieldPrime.Add(ProductD, ProductB, ProductD) -- Reused ProductD
	local SumJ = ProductD

	local NewX = FieldPrime.Mul(DiffG, DiffH)
	local NewY = FieldPrime.Mul(SumI, SumJ)
	FieldPrime.Mul(DiffH, SumI, DiffH) -- Reused DiffH
	local NewZ = DiffH
	FieldPrime.Mul(DiffG, SumJ, DiffG) -- Reused  DiffG
	local NewT = DiffG

	local Result = Storage or buffer.create(POINT_SIZE)
	SetCoord(Result, 0, NewX)
	SetCoord(Result, 1, NewY)
	SetCoord(Result, 2, NewZ)
	SetCoord(Result, 3, NewT)
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
	FieldPrime.Mul(DiffA, Niels1Plus, DiffA) -- Reused DiffA
	local ProductB = DiffA
	FieldPrime.Add(Point1Y, Point1X, Point1Y) -- Reused Point1Y
	local SumC = Point1Y
	FieldPrime.Mul(SumC, Niels1Minus, SumC) -- Reused SumC (=> Point1Y)
	local ProductD = SumC
	FieldPrime.Mul(Point1T, Niels1T, Point1T) -- Reused Point1T
	local ProductE = Point1T
	FieldPrime.Mul(Point1Z, Niels1Z, Point1Z) -- Reused Point1Z
	local ProductF = Point1Z
	local DiffG = FieldPrime.Sub(ProductD, ProductB)
	local SumH = FieldPrime.Add(ProductF, ProductE)
	local DiffI = FieldPrime.Sub(ProductF, ProductE)
	FieldPrime.Add(ProductD, ProductB, ProductD) -- Reused ProductD
	local SumJ = ProductD

	local NewX = FieldPrime.Mul(DiffG, SumH)
	local NewY = FieldPrime.Mul(DiffI, SumJ)
	FieldPrime.Mul(SumH, DiffI, SumH) -- Reused SumH
	local NewZ = SumH
	FieldPrime.Mul(DiffG, SumJ, DiffG) -- Reused DiffG
	local NewT = DiffG

	local Result = Storage or buffer.create(POINT_SIZE)
	SetCoord(Result, 0, NewX)
	SetCoord(Result, 1, NewY)
	SetCoord(Result, 2, NewZ)
	SetCoord(Result, 3, NewT)
	return Result
end

function Edwards25519.Niels(Point1: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0)
	local Point1Y = GetCoord(Point1, 1)
	local Point1Z = GetCoord(Point1, 2)
	local Point1T = GetCoord(Point1, 3)

	local PlusN3 = FieldPrime.Add(Point1Y, Point1X)
	local MinusN3 = FieldPrime.Sub(Point1Y, Point1X)
	FieldPrime.Add(Point1Z, Point1Z, Point1Z) -- Reused Point1Z
	local DoubledN3Z = Point1Z
	FieldPrime.Mul(Point1T, CurveK, Point1T) -- Reused Point1T
	local ScaledN3T = Point1T

	local Result = Storage or buffer.create(POINT_SIZE)
	SetCoord(Result, 0, PlusN3)
	SetCoord(Result, 1, MinusN3)
	SetCoord(Result, 2, DoubledN3Z)
	SetCoord(Result, 3, ScaledN3T)
	return Result
end

function Edwards25519.Scale(Point1: buffer): buffer
	local Point1X = GetCoord(Point1, 0)
	local Point1Y = GetCoord(Point1, 1)
	local Point1Z = GetCoord(Point1, 2)

	FieldPrime.Invert(Point1Z, Point1Z) -- Reused Point1Z
	local ZInverse = Point1Z
	FieldPrime.Mul(Point1X, ZInverse, Point1X) -- Reused Point1X
	local NewX = Point1X
	FieldPrime.Mul(Point1Y, ZInverse, Point1Y) -- Reused Point1Y
	local NewY = Point1Y
	local NewZ = FieldPrime.Num(1)
	local NewT = FieldPrime.Mul(NewX, NewY)

	local Result = buffer.create(POINT_SIZE)
	SetCoord(Result, 0, NewX)
	SetCoord(Result, 1, NewY)
	SetCoord(Result, 2, NewZ)
	SetCoord(Result, 3, NewT)
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
	local Denominator = FieldPrime.Mul(YSquared, CurveD)
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
	SetCoord(Result, 0, XCoord)
	SetCoord(Result, 1, YCoord)
	SetCoord(Result, 2, ZCoord)
	SetCoord(Result, 3, TCoord)
	return Result
end

do
	local BasePointBytes = buffer.create(32)
	local BasePointHex = {
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
	}

	for Index = 1, 32 do
		buffer.writeu8(BasePointBytes, Index - 1, BasePointHex[Index])
	end

	BasePointG = Edwards25519.Decode(BasePointBytes)
end

local function SignedRadixW(ScalarBits: buffer, ScalarBitCount: number, RadixWidth: number): (buffer, number)
	local RadixValue = 2 ^ RadixWidth
	local HalfRadix = RadixValue / 2
	local OutputDigits = buffer.create(64 * 8)
	local OutputLength = 0
	local Accumulator = 0
	local Multiplier = 1

	for BitIndex = 1, ScalarBitCount do
		local BitValue = buffer.readf64(ScalarBits, (BitIndex - 1) * 8)
		Accumulator = Accumulator + BitValue * Multiplier
		Multiplier = Multiplier * 2

		while BitIndex == ScalarBitCount and Accumulator > 0 or Multiplier > RadixValue do
			local Remainder = Accumulator % RadixValue
			if Remainder >= HalfRadix then
				Remainder = Remainder - RadixValue
			end
			Accumulator = (Accumulator - Remainder) / RadixValue
			Multiplier = Multiplier / RadixValue
			buffer.writef64(OutputDigits, OutputLength * 8, Remainder)
			OutputLength = OutputLength + 1
		end
	end

	return OutputDigits, OutputLength
end

local function RadixWTable(BasePoint: buffer, RadixWidth: number): buffer
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
	if BasePointG then
		BasePointTable = RadixWTable(BasePointG, BasePointRadixWidth)
	end
end

local function GetBasePointTableEntry(WindowIndex: number, Multiple: number, Storage: buffer?): buffer
	local BaseOffset = ((WindowIndex - 1) * BasePointTableMaxRowSize * POINT_SIZE)
	local Offset = BaseOffset + ((Multiple - 1) * POINT_SIZE)

	local NielsPoint = Storage or buffer.create(POINT_SIZE)
	buffer.copy(NielsPoint, 0, BasePointTable, Offset, POINT_SIZE)
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
		Accumulator = Accumulator + BitValue * Multiplier
		Multiplier = Multiplier * 2

		while BitIndex == ScalarBitCount and Accumulator > 0 or Multiplier > WindowValue do
			if Accumulator % 2 == 0 then
				Accumulator = Accumulator / 2
				Multiplier = Multiplier / 2
				buffer.writef64(OutputNAF, OutputLength * 8, 0)
				OutputLength = OutputLength + 1
			else
				local Remainder = Accumulator % WindowValue
				if Remainder >= HalfWindow then
					Remainder = Remainder - WindowValue
				end
				Accumulator = Accumulator - Remainder
				buffer.writef64(OutputNAF, OutputLength * 8, Remainder)
				OutputLength = OutputLength + 1
			end
		end
	end

	while OutputLength > 0 and buffer.readf64(OutputNAF, (OutputLength - 1) * 8) == 0 do
		OutputLength = OutputLength - 1
	end

	return OutputNAF, OutputLength
end

local function WindowedNAFTable(BasePoint: buffer, WindowWidth: number): buffer
	local PointSize = POINT_SIZE

	local MaxOddMultiples = 2 ^ WindowWidth
	local DoubledPoint = Edwards25519.Double(BasePoint)

	local TableData = buffer.create(MaxOddMultiples * PointSize)

	Edwards25519.Niels(BasePoint, BasePoint) -- Reused BasePoint
	local FirstNiels = BasePoint
	buffer.copy(TableData, 0, FirstNiels, 0, PointSize)

	for OddMultiple = 3, MaxOddMultiples, 2 do
		local PrevOffset = ((OddMultiple - 3) * PointSize)
		local CurrentOffset = ((OddMultiple - 1) * PointSize)

		buffer.copy(BasePoint, 0, TableData, PrevOffset, PointSize)

		Edwards25519.Niels(Edwards25519.Add(DoubledPoint, BasePoint, BasePoint), BasePoint) -- Reused BasePoint
		local CurrentNiels = BasePoint
		buffer.copy(TableData, CurrentOffset, CurrentNiels, 0, PointSize)
	end

	return TableData
end

function Edwards25519.MulG(ScalarBits: buffer, ScalarBitCount: number): buffer
	local PointSize = POINT_SIZE

	local SignedWindows, WindowCount = SignedRadixW(ScalarBits, ScalarBitCount, BasePointRadixWidth)
	local ResultPoint = buffer.create(PointSize)
	buffer.copy(ResultPoint, 0, IdentityO, 0, PointSize)

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
	buffer.copy(ResultPoint, 0, IdentityO, 0, POINT_SIZE)

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
