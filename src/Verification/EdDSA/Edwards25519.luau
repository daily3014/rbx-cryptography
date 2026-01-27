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

	local MaxWindows = math.ceil(256 / RadixWidth)
	local MaxRowSize = 2 ^ RadixWidth / 2

	local TableData = buffer.create(MaxWindows * MaxRowSize * AFFINE_NIELS_SIZE)

	local CurrentBasePoint = buffer.create(POINT_SIZE)
	buffer.copy(CurrentBasePoint, 0, BasePoint, 0, POINT_SIZE)

	local AffineNiels = Edwards25519.AffineNiels
	local Add = Edwards25519.Add
	local Double = Edwards25519.Double
	local Scale = Edwards25519.Scale
	local Niels = Edwards25519.Niels
	local NielsSize = AFFINE_NIELS_SIZE

	for WindowIndex = 1, MaxWindows do
		local BaseOffset = ((WindowIndex - 1) * MaxRowSize * NielsSize)
		local WorkingPoint = buffer.create(POINT_SIZE)
		buffer.copy(WorkingPoint, 0, CurrentBasePoint, 0, POINT_SIZE)

		local ScaledPoint = Scale(WorkingPoint)
		local FirstAffineNiels = AffineNiels(ScaledPoint)
		buffer.copy(TableData, BaseOffset, FirstAffineNiels, 0, NielsSize)

		local FirstNiels = Niels(ScaledPoint)

		for Multiple = 2, MaxRowSize do
			Add(WorkingPoint, FirstNiels, WorkingPoint)
			local Scaled = Scale(WorkingPoint)
			local AffineNielsBuffer = AffineNiels(Scaled)

			local Offset = BaseOffset + ((Multiple - 1) * NielsSize)
			buffer.copy(TableData, Offset, AffineNielsBuffer, 0, NielsSize)
		end

		for _ = 1, RadixWidth do
			CurrentBasePoint = Double(CurrentBasePoint)
		end
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
	local CoordSize = COORD_SIZE
	local AffineNielsSize = AFFINE_NIELS_SIZE
	local IdentityO = IDENTITY_O
	local BaseRadixWidth = BASE_RADIX_WIDTH
	local BasePointRow = BASE_POINT_ROW
	local AffineTable = AFFINE_BASEPOINT_TABLE :: buffer

	local SignedWindows, WindowCount = Edwards25519.SignedRadixW(ScalarBits, ScalarBitCount, BaseRadixWidth)

	local ResultPoint = MULG_RESULT_POINT
	buffer.copy(ResultPoint, 0, IdentityO, 0, PointSize)

	local AffineNielsPoint = MULG_AFFINE_NIELS
	local DummyPoint = MULG_DUMMY_POINT
	buffer.copy(DummyPoint, 0, IdentityO, 0, PointSize)

	local FAdd = FieldPrime.Add
	local FSub = FieldPrime.Sub
	local FMul = FieldPrime.Mul

	local P1X = MULG_P1X
	local P1Y = MULG_P1Y
	local P1Z = MULG_P1Z
	local P1T = MULG_P1T
	local N2P = MULG_N2P
	local N2M = MULG_N2M
	local N2T = MULG_N2T
	local TMP = MULG_TMP

	for WindowIndex = 1, WindowCount do
		local WindowValue = buffer.readf64(SignedWindows, (WindowIndex - 1) * 8)

		if WindowValue > 0 then
			local BaseOffset = ((WindowIndex - 1) * BasePointRow * AffineNielsSize)
			local Offset = BaseOffset + ((WindowValue - 1) * AffineNielsSize)
			buffer.copy(AffineNielsPoint, 0, AffineTable, Offset, AffineNielsSize)

			buffer.copy(P1X, 0, ResultPoint, 0, CoordSize)
			buffer.copy(P1Y, 0, ResultPoint, CoordSize, CoordSize)
			buffer.copy(P1Z, 0, ResultPoint, 2 * CoordSize, CoordSize)
			buffer.copy(P1T, 0, ResultPoint, 3 * CoordSize, CoordSize)
			buffer.copy(N2P, 0, AffineNielsPoint, 0, CoordSize)
			buffer.copy(N2M, 0, AffineNielsPoint, CoordSize, CoordSize)
			buffer.copy(N2T, 0, AffineNielsPoint, 2 * CoordSize, CoordSize)

			FSub(P1Y, P1X, TMP)
			FMul(TMP, N2M, TMP)
			FAdd(P1Y, P1X, P1X)
			FMul(P1X, N2P, P1X)
			FMul(P1T, N2T, P1T)
			FAdd(P1Z, P1Z, P1Z)

			FSub(P1X, TMP, P1Y)
			FSub(P1Z, P1T, N2P)
			FAdd(P1Z, P1T, P1Z)
			FAdd(P1X, TMP, P1X)

			FMul(P1Y, N2P, TMP)
			FMul(P1Z, P1X, P1T)
			FMul(N2P, P1Z, P1Z)
			FMul(P1Y, P1X, P1X)

			buffer.copy(ResultPoint, 0, TMP, 0, CoordSize)
			buffer.copy(ResultPoint, CoordSize, P1T, 0, CoordSize)
			buffer.copy(ResultPoint, 2 * CoordSize, P1Z, 0, CoordSize)
			buffer.copy(ResultPoint, 3 * CoordSize, P1X, 0, CoordSize)

		elseif WindowValue < 0 then
			local BaseOffset = ((WindowIndex - 1) * BasePointRow * AffineNielsSize)
			local Offset = BaseOffset + (((-WindowValue) - 1) * AffineNielsSize)
			buffer.copy(AffineNielsPoint, 0, AffineTable, Offset, AffineNielsSize)

			buffer.copy(P1X, 0, ResultPoint, 0, CoordSize)
			buffer.copy(P1Y, 0, ResultPoint, CoordSize, CoordSize)
			buffer.copy(P1Z, 0, ResultPoint, 2 * CoordSize, CoordSize)
			buffer.copy(P1T, 0, ResultPoint, 3 * CoordSize, CoordSize)
			buffer.copy(N2P, 0, AffineNielsPoint, 0, CoordSize)
			buffer.copy(N2M, 0, AffineNielsPoint, CoordSize, CoordSize)
			buffer.copy(N2T, 0, AffineNielsPoint, 2 * CoordSize, CoordSize)

			FSub(P1Y, P1X, TMP)
			FMul(TMP, N2P, TMP)
			FAdd(P1Y, P1X, P1X)
			FMul(P1X, N2M, P1X)
			FMul(P1T, N2T, P1T)
			FAdd(P1Z, P1Z, P1Z)

			FSub(P1X, TMP, P1Y)
			FAdd(P1Z, P1T, N2P)
			FSub(P1Z, P1T, P1Z)
			FAdd(P1X, TMP, P1X)

			FMul(P1Y, N2P, TMP)
			FMul(P1Z, P1X, P1T)
			FMul(N2P, P1Z, P1Z)
			FMul(P1Y, P1X, P1X)

			buffer.copy(ResultPoint, 0, TMP, 0, CoordSize)
			buffer.copy(ResultPoint, CoordSize, P1T, 0, CoordSize)
			buffer.copy(ResultPoint, 2 * CoordSize, P1Z, 0, CoordSize)
			buffer.copy(ResultPoint, 3 * CoordSize, P1X, 0, CoordSize)

		else
			local BaseOffset = ((WindowIndex - 1) * BasePointRow * AffineNielsSize)
			buffer.copy(AffineNielsPoint, 0, AffineTable, BaseOffset, AffineNielsSize)

			buffer.copy(P1X, 0, DummyPoint, 0, CoordSize)
			buffer.copy(P1Y, 0, DummyPoint, CoordSize, CoordSize)
			buffer.copy(P1Z, 0, DummyPoint, 2 * CoordSize, CoordSize)
			buffer.copy(P1T, 0, DummyPoint, 3 * CoordSize, CoordSize)
			buffer.copy(N2P, 0, AffineNielsPoint, 0, CoordSize)
			buffer.copy(N2M, 0, AffineNielsPoint, CoordSize, CoordSize)
			buffer.copy(N2T, 0, AffineNielsPoint, 2 * CoordSize, CoordSize)

			FSub(P1Y, P1X, TMP)
			FMul(TMP, N2M, TMP)
			FAdd(P1Y, P1X, P1X)
			FMul(P1X, N2P, P1X)
			FMul(P1T, N2T, P1T)
			FAdd(P1Z, P1Z, P1Z)

			FSub(P1X, TMP, P1Y)
			FSub(P1Z, P1T, N2P)
			FAdd(P1Z, P1T, P1Z)
			FAdd(P1X, TMP, P1X)

			FMul(P1Y, N2P, TMP)
			FMul(P1Z, P1X, P1T)
			FMul(N2P, P1Z, P1Z)
			FMul(P1Y, P1X, P1X)

			buffer.copy(DummyPoint, 0, TMP, 0, CoordSize)
			buffer.copy(DummyPoint, CoordSize, P1T, 0, CoordSize)
			buffer.copy(DummyPoint, 2 * CoordSize, P1Z, 0, CoordSize)
			buffer.copy(DummyPoint, 3 * CoordSize, P1X, 0, CoordSize)
		end
	end

	local Output = buffer.create(PointSize)
	buffer.copy(Output, 0, ResultPoint, 0, PointSize)
	return Output
end

function Edwards25519.Mul(BasePoint: buffer, ScalarBits: buffer, ScalarBitCount: number): buffer
	local PointSize = POINT_SIZE
	local CoordSize = COORD_SIZE
	local IdentityO = IDENTITY_O

	local NAFForm, NAFLength = Edwards25519.WindowedNAF(ScalarBits, ScalarBitCount, 5)
	local MultipleTable = Edwards25519.WindowedNAFTable(BasePoint, 5)

	local ResultPoint = MUL_RESULT_POINT
	buffer.copy(ResultPoint, 0, IdentityO, 0, PointSize)

	local NielsPoint = MUL_NIELS_POINT

	local Square = FieldPrime.Square
	local FAdd = FieldPrime.Add
	local FSub = FieldPrime.Sub
	local FMul = FieldPrime.Mul
	local Carry = FieldPrime.Carry

	local DoubleX = MUL_DOUBLE_X
	local DoubleY = MUL_DOUBLE_Y
	local DoubleZ = MUL_DOUBLE_Z
	local DoubleA = MUL_DOUBLE_A
	local DoubleB = MUL_DOUBLE_B
	local DoubleE = MUL_DOUBLE_E
	local DoubleG = MUL_DOUBLE_G

	local P1X = MUL_P1X
	local P1Y = MUL_P1Y
	local P1Z = MUL_P1Z
	local P1T = MUL_P1T
	local N2P = MUL_N2P
	local N2M = MUL_N2M
	local N2Z = MUL_N2Z
	local N2T = MUL_N2T
	local TMP = MUL_TMP

	for NAFIndex = NAFLength, 1, -1 do
		local NAFDigit = buffer.readf64(NAFForm, (NAFIndex - 1) * 8)

		if NAFDigit == 0 then
			buffer.copy(DoubleX, 0, ResultPoint, 0, CoordSize)
			buffer.copy(DoubleY, 0, ResultPoint, CoordSize, CoordSize)
			buffer.copy(DoubleZ, 0, ResultPoint, 2 * CoordSize, CoordSize)

			Square(DoubleX, DoubleA)
			Square(DoubleY, DoubleB)
			Square(DoubleZ, DoubleZ)
			FAdd(DoubleZ, DoubleZ, DoubleZ)
			FAdd(DoubleA, DoubleB, DoubleE)
			FAdd(DoubleX, DoubleY, DoubleX)
			Square(DoubleX, DoubleG)
			FSub(DoubleG, DoubleE, DoubleG)
			Carry(DoubleG, DoubleG)
			FSub(DoubleB, DoubleA, DoubleB)
			FSub(DoubleZ, DoubleB, DoubleZ)
			Carry(DoubleZ, DoubleZ)

			FMul(DoubleG, DoubleZ, DoubleX)
			FMul(DoubleB, DoubleE, DoubleY)
			FMul(DoubleZ, DoubleB, DoubleZ)
			FMul(DoubleG, DoubleE, DoubleE)

			buffer.copy(ResultPoint, 0, DoubleX, 0, CoordSize)
			buffer.copy(ResultPoint, CoordSize, DoubleY, 0, CoordSize)
			buffer.copy(ResultPoint, 2 * CoordSize, DoubleZ, 0, CoordSize)
			buffer.copy(ResultPoint, 3 * CoordSize, DoubleE, 0, CoordSize)

		elseif NAFDigit > 0 then
			buffer.copy(NielsPoint, 0, MultipleTable, ((NAFDigit - 1) * PointSize), PointSize)

			buffer.copy(P1X, 0, ResultPoint, 0, CoordSize)
			buffer.copy(P1Y, 0, ResultPoint, CoordSize, CoordSize)
			buffer.copy(P1Z, 0, ResultPoint, 2 * CoordSize, CoordSize)
			buffer.copy(P1T, 0, ResultPoint, 3 * CoordSize, CoordSize)
			buffer.copy(N2P, 0, NielsPoint, 0, CoordSize)
			buffer.copy(N2M, 0, NielsPoint, CoordSize, CoordSize)
			buffer.copy(N2Z, 0, NielsPoint, 2 * CoordSize, CoordSize)
			buffer.copy(N2T, 0, NielsPoint, 3 * CoordSize, CoordSize)

			FSub(P1Y, P1X, TMP)
			FMul(TMP, N2M, TMP)
			FAdd(P1Y, P1X, P1X)
			FMul(P1X, N2P, P1X)
			FMul(P1T, N2T, P1T)
			FMul(P1Z, N2Z, P1Z)

			FSub(P1X, TMP, P1Y)
			FSub(P1Z, P1T, N2P)
			FAdd(P1Z, P1T, P1Z)
			FAdd(P1X, TMP, P1X)

			FMul(P1Y, N2P, TMP)
			FMul(P1Z, P1X, P1T)
			FMul(N2P, P1Z, P1Z)
			FMul(P1Y, P1X, P1X)

			buffer.copy(ResultPoint, 0, TMP, 0, CoordSize)
			buffer.copy(ResultPoint, CoordSize, P1T, 0, CoordSize)
			buffer.copy(ResultPoint, 2 * CoordSize, P1Z, 0, CoordSize)
			buffer.copy(ResultPoint, 3 * CoordSize, P1X, 0, CoordSize)

		else
			buffer.copy(NielsPoint, 0, MultipleTable, (((-NAFDigit) - 1) * PointSize), PointSize)

			buffer.copy(P1X, 0, ResultPoint, 0, CoordSize)
			buffer.copy(P1Y, 0, ResultPoint, CoordSize, CoordSize)
			buffer.copy(P1Z, 0, ResultPoint, 2 * CoordSize, CoordSize)
			buffer.copy(P1T, 0, ResultPoint, 3 * CoordSize, CoordSize)
			buffer.copy(N2P, 0, NielsPoint, 0, CoordSize)
			buffer.copy(N2M, 0, NielsPoint, CoordSize, CoordSize)
			buffer.copy(N2Z, 0, NielsPoint, 2 * CoordSize, CoordSize)
			buffer.copy(N2T, 0, NielsPoint, 3 * CoordSize, CoordSize)

			FSub(P1Y, P1X, TMP)
			FMul(TMP, N2P, TMP)
			FAdd(P1Y, P1X, P1X)
			FMul(P1X, N2M, P1X)
			FMul(P1T, N2T, P1T)
			FMul(P1Z, N2Z, P1Z)

			FSub(P1X, TMP, P1Y)
			FAdd(P1Z, P1T, N2P)
			FSub(P1Z, P1T, P1Z)
			FAdd(P1X, TMP, P1X)

			FMul(P1Y, N2P, TMP)
			FMul(P1Z, P1X, P1T)
			FMul(N2P, P1Z, P1Z)
			FMul(P1Y, P1X, P1X)

			buffer.copy(ResultPoint, 0, TMP, 0, CoordSize)
			buffer.copy(ResultPoint, CoordSize, P1T, 0, CoordSize)
			buffer.copy(ResultPoint, 2 * CoordSize, P1Z, 0, CoordSize)
			buffer.copy(ResultPoint, 3 * CoordSize, P1X, 0, CoordSize)
		end
	end

	local Output = buffer.create(PointSize)
	buffer.copy(Output, 0, ResultPoint, 0, PointSize)
	return Output
end

return Edwards25519