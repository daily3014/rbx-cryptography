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

local COORD_SIZE = 80
local POINT_SIZE = 4 * COORD_SIZE
local AFFINE_NIELS_SIZE = 3 * COORD_SIZE
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

local NAF_OUTPUT = buffer.create(512)
local RADIX_OUTPUT = buffer.create(272)

local BASEPOINT_G: buffer
local AFFINE_BASEPOINT_TABLE: buffer 
local BASEPOINT_NAF_TABLE: buffer
local STRAUSS_NAF_WIDTH = 5

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
	local XSignBit = integer.tonumber(integer.band(buffer.readinteger(CanonicalX, 0), 1i))

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
	local XSignBit = integer.tonumber(integer.band(buffer.readinteger(CanonicalX, 0), 1i))

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

	local Result = Edwards25519.Decode(BASEPOINT_BYTES)
	if not Result then
		error("Failed to decode basepoint")
	end
	BASEPOINT_G = Result
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

	local Add = Edwards25519.Add
	local Double = Edwards25519.Double
	local Niels = Edwards25519.Niels
	local NielsSize = AFFINE_NIELS_SIZE
	local FMul = FieldPrime.Mul
	local FAdd = FieldPrime.Add
	local FSub = FieldPrime.Sub
	local FInvert = FieldPrime.Invert

	local WorkingPoints = table.create(MaxRowSize) :: {buffer}
	local Zs = table.create(MaxRowSize) :: {buffer}
	local Partials = table.create(MaxRowSize) :: {buffer}
	local ZInvs = table.create(MaxRowSize) :: {buffer}

	for WindowIndex = 1, MaxWindows do
		local BaseOffset = ((WindowIndex - 1) * MaxRowSize * NielsSize)

		WorkingPoints[1] = buffer.create(POINT_SIZE)
		buffer.copy(WorkingPoints[1], 0, CurrentBasePoint, 0, POINT_SIZE)

		local FirstNiels = Niels(CurrentBasePoint)

		for Multiple = 2, MaxRowSize do
			local NewPoint = buffer.create(POINT_SIZE)
			Add(WorkingPoints[Multiple - 1], FirstNiels, NewPoint)
			WorkingPoints[Multiple] = NewPoint
		end

		for I = 1, MaxRowSize do
			local Z = buffer.create(COORD_SIZE)
			buffer.copy(Z, 0, WorkingPoints[I], 2 * COORD_SIZE, COORD_SIZE)
			Zs[I] = Z
		end

		Partials[1] = buffer.create(COORD_SIZE)
		buffer.copy(Partials[1], 0, Zs[1], 0, COORD_SIZE)
		for I = 2, MaxRowSize do
			Partials[I] = FMul(Partials[I - 1], Zs[I])
		end

		local FinalInv = FInvert(Partials[MaxRowSize])

		ZInvs[MaxRowSize] = FMul(FinalInv, Partials[MaxRowSize - 1])
		local CurrentInv = FMul(FinalInv, Zs[MaxRowSize])
		for I = MaxRowSize - 1, 2, -1 do
			ZInvs[I] = FMul(CurrentInv, Partials[I - 1])
			CurrentInv = FMul(CurrentInv, Zs[I])
		end
		ZInvs[1] = CurrentInv

		for I = 1, MaxRowSize do
			local WP = WorkingPoints[I]
			local ZI = ZInvs[I]

			local X = buffer.create(COORD_SIZE)
			local Y = buffer.create(COORD_SIZE)
			buffer.copy(X, 0, WP, 0, COORD_SIZE)
			buffer.copy(Y, 0, WP, COORD_SIZE, COORD_SIZE)

			local AffX = FMul(X, ZI)
			local AffY = FMul(Y, ZI)
			local AffT = FMul(AffX, AffY)

			local YPlusX = FAdd(AffY, AffX)
			local YMinusX = FSub(AffY, AffX)
			local T2d = FMul(AffT, CURVE_K)

			local Offset = BaseOffset + ((I - 1) * NielsSize)
			buffer.copy(TableData, Offset, YPlusX, 0, COORD_SIZE)
			buffer.copy(TableData, Offset + COORD_SIZE, YMinusX, 0, COORD_SIZE)
			buffer.copy(TableData, Offset + 2 * COORD_SIZE, T2d, 0, COORD_SIZE)
		end

		for _ = 1, RadixWidth do
			CurrentBasePoint = Double(CurrentBasePoint)
		end
	end

	return TableData
end

do
	if BASEPOINT_G then
		AFFINE_BASEPOINT_TABLE = Edwards25519.AffineRadixWTable(BASEPOINT_G, BASE_RADIX_WIDTH)
	end
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

		local BitValue = buffer.readu8(ScalarBits, BitIndex - 1)
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
			buffer.writei8(OutputDigits, OutputLength, Remainder)
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
		local BitValue = buffer.readu8(ScalarBits, BitIndex - 1)
		Accumulator += BitValue * Multiplier
		Multiplier *= 2

		while BitIndex == ScalarBitCount and Accumulator > 0 or Multiplier > WindowValue do
			if Accumulator % 2 == 0 then
				Accumulator /= 2
				Multiplier /= 2
				buffer.writei8(OutputNAF, OutputLength, 0)
				OutputLength += 1
			else
				local Remainder = Accumulator % WindowValue
				if Remainder >= HalfWindow then
					Remainder -= WindowValue
				end
				Accumulator -= Remainder
				buffer.writei8(OutputNAF, OutputLength, Remainder)
				OutputLength += 1
			end
		end
	end

	while OutputLength > 0 and buffer.readi8(OutputNAF, OutputLength - 1) == 0 do
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

do
	if BASEPOINT_G then
		BASEPOINT_NAF_TABLE = Edwards25519.WindowedNAFTable(BASEPOINT_G, STRAUSS_NAF_WIDTH)
	end
end

function Edwards25519.MulG(ScalarBits: buffer, ScalarBitCount: number): buffer
	local PointSize = POINT_SIZE
	local CoordSize = COORD_SIZE
	local AffineNielsSize = AFFINE_NIELS_SIZE
	local IdentityO = IDENTITY_O
	local BaseRadixWidth = BASE_RADIX_WIDTH
	local BasePointRow = BASE_POINT_ROW
	local AffineTable = AFFINE_BASEPOINT_TABLE 

	local SignedWindows, WindowCount = Edwards25519.SignedRadixW(ScalarBits, ScalarBitCount, BaseRadixWidth)

	local FAdd = FieldPrime.Add
	local FSub = FieldPrime.Sub
	local FMul = FieldPrime.Mul

	local RX = MULG_P1X
	local RY = MULG_P1Y
	local RZ = MULG_P1Z
	local RT = MULG_P1T
	local TMP = MULG_TMP
	buffer.copy(RX, 0, IdentityO, 0, CoordSize)
	buffer.copy(RY, 0, IdentityO, CoordSize, CoordSize)
	buffer.copy(RZ, 0, IdentityO, 2 * CoordSize, CoordSize)
	buffer.copy(RT, 0, IdentityO, 3 * CoordSize, CoordSize)

	local DX = buffer.create(CoordSize)
	local DY = buffer.create(CoordSize)
	local DZ = buffer.create(CoordSize)
	local DT = buffer.create(CoordSize)
	local DTMP = buffer.create(CoordSize)
	buffer.copy(DX, 0, IdentityO, 0, CoordSize)
	buffer.copy(DY, 0, IdentityO, CoordSize, CoordSize)
	buffer.copy(DZ, 0, IdentityO, 2 * CoordSize, CoordSize)
	buffer.copy(DT, 0, IdentityO, 3 * CoordSize, CoordSize)

	local N2P = MULG_N2P
	local N2M = MULG_N2M
	local N2T = MULG_N2T

	for WindowIndex = 1, WindowCount do
		local WindowValue = buffer.readi8(SignedWindows, WindowIndex - 1)
		local BaseOffset = ((WindowIndex - 1) * BasePointRow * AffineNielsSize)

		if WindowValue ~= 0 then
			local TableEntry = if WindowValue > 0 then (WindowValue - 1) else ((-WindowValue) - 1)
			local Offset = BaseOffset + (TableEntry * AffineNielsSize)
			buffer.copy(N2P, 0, AffineTable, Offset, CoordSize)
			buffer.copy(N2M, 0, AffineTable, Offset + CoordSize, CoordSize)
			buffer.copy(N2T, 0, AffineTable, Offset + 2 * CoordSize, CoordSize)

			if WindowValue > 0 then
				FSub(RY, RX, TMP)
				FMul(TMP, N2M, TMP)
				FAdd(RY, RX, RX)
				FMul(RX, N2P, RX)
				FMul(RT, N2T, RT)
				FAdd(RZ, RZ, RZ)

				FSub(RX, TMP, RY)
				FSub(RZ, RT, N2P)
				FAdd(RZ, RT, RZ)
				FAdd(RX, TMP, RX)

				FMul(RY, N2P, TMP)
				FMul(RZ, RX, RT)
				FMul(N2P, RZ, RZ)
				FMul(RY, RX, RX)
			else
				FSub(RY, RX, TMP)
				FMul(TMP, N2P, TMP)
				FAdd(RY, RX, RX)
				FMul(RX, N2M, RX)
				FMul(RT, N2T, RT)
				FAdd(RZ, RZ, RZ)

				FSub(RX, TMP, RY)
				FAdd(RZ, RT, N2P)
				FSub(RZ, RT, RZ)
				FAdd(RX, TMP, RX)

				FMul(RY, N2P, TMP)
				FMul(RZ, RX, RT)
				FMul(N2P, RZ, RZ)
				FMul(RY, RX, RX)
			end

			RX, RY, RT, TMP = TMP, RT, RX, RY
		else
			buffer.copy(N2P, 0, AffineTable, BaseOffset, CoordSize)
			buffer.copy(N2M, 0, AffineTable, BaseOffset + CoordSize, CoordSize)
			buffer.copy(N2T, 0, AffineTable, BaseOffset + 2 * CoordSize, CoordSize)

			FSub(DY, DX, DTMP)
			FMul(DTMP, N2M, DTMP)
			FAdd(DY, DX, DX)
			FMul(DX, N2P, DX)
			FMul(DT, N2T, DT)
			FAdd(DZ, DZ, DZ)

			FSub(DX, DTMP, DY)
			FSub(DZ, DT, N2P)
			FAdd(DZ, DT, DZ)
			FAdd(DX, DTMP, DX)

			FMul(DY, N2P, DTMP)
			FMul(DZ, DX, DT)
			FMul(N2P, DZ, DZ)
			FMul(DY, DX, DX)

			DX, DY, DT, DTMP = DTMP, DT, DX, DY
		end
	end

	local Output = buffer.create(PointSize)
	buffer.copy(Output, 0, RX, 0, CoordSize)
	buffer.copy(Output, CoordSize, RY, 0, CoordSize)
	buffer.copy(Output, 2 * CoordSize, RZ, 0, CoordSize)
	buffer.copy(Output, 3 * CoordSize, RT, 0, CoordSize)
	return Output
end

function Edwards25519.Mul(BasePoint: buffer, ScalarBits: buffer, ScalarBitCount: number): buffer
	local PointSize = POINT_SIZE
	local CoordSize = COORD_SIZE

	local NAFForm, NAFLength = Edwards25519.WindowedNAF(ScalarBits, ScalarBitCount, 5)
	local MultipleTable = Edwards25519.WindowedNAFTable(BasePoint, 5)

	local Square = FieldPrime.Square
	local FAdd = FieldPrime.Add
	local FSub = FieldPrime.Sub
	local FMul = FieldPrime.Mul
	local Carry = FieldPrime.Carry

	local RX = MUL_P1X
	local RY = MUL_P1Y
	local RZ = MUL_P1Z
	local RT = MUL_P1T
	local TMP = MUL_TMP
	buffer.copy(RX, 0, IDENTITY_O, 0, CoordSize)
	buffer.copy(RY, 0, IDENTITY_O, CoordSize, CoordSize)
	buffer.copy(RZ, 0, IDENTITY_O, 2 * CoordSize, CoordSize)
	buffer.copy(RT, 0, IDENTITY_O, 3 * CoordSize, CoordSize)

	local DA = MUL_DOUBLE_A
	local DB = MUL_DOUBLE_B
	local DE = MUL_DOUBLE_E
	local DG = MUL_DOUBLE_G
	local N2P = MUL_N2P
	local N2M = MUL_N2M
	local N2Z = MUL_N2Z
	local N2T = MUL_N2T

	for NAFIndex = NAFLength, 1, -1 do
		local NAFDigit = buffer.readi8(NAFForm, NAFIndex - 1)

		if NAFDigit == 0 then
			Square(RX, DA)
			Square(RY, DB)
			Square(RZ, RZ)
			FAdd(RZ, RZ, RZ)
			FAdd(DA, DB, DE)
			FAdd(RX, RY, RX)
			Square(RX, DG)
			FSub(DG, DE, DG)
			Carry(DG, DG)
			FSub(DB, DA, DB)
			FSub(RZ, DB, RZ)
			Carry(RZ, RZ)

			FMul(DG, RZ, RX)
			FMul(DB, DE, RY)
			FMul(RZ, DB, RZ)
			FMul(DG, DE, RT)
		else
			local TableIndex = if NAFDigit > 0 then (NAFDigit - 1) else ((-NAFDigit) - 1)
			local Offset = TableIndex * PointSize
			buffer.copy(N2P, 0, MultipleTable, Offset, CoordSize)
			buffer.copy(N2M, 0, MultipleTable, Offset + CoordSize, CoordSize)
			buffer.copy(N2Z, 0, MultipleTable, Offset + 2 * CoordSize, CoordSize)
			buffer.copy(N2T, 0, MultipleTable, Offset + 3 * CoordSize, CoordSize)

			if NAFDigit > 0 then
				FSub(RY, RX, TMP)
				FMul(TMP, N2M, TMP)
				FAdd(RY, RX, RX)
				FMul(RX, N2P, RX)
				FMul(RT, N2T, RT)
				FMul(RZ, N2Z, RZ)

				FSub(RX, TMP, RY)
				FSub(RZ, RT, N2P)
				FAdd(RZ, RT, RZ)
				FAdd(RX, TMP, RX)

				FMul(RY, N2P, TMP)
				FMul(RZ, RX, RT)
				FMul(N2P, RZ, RZ)
				FMul(RY, RX, RX)
			else
				FSub(RY, RX, TMP)
				FMul(TMP, N2P, TMP)
				FAdd(RY, RX, RX)
				FMul(RX, N2M, RX)
				FMul(RT, N2T, RT)
				FMul(RZ, N2Z, RZ)

				FSub(RX, TMP, RY)
				FAdd(RZ, RT, N2P)
				FSub(RZ, RT, RZ)
				FAdd(RX, TMP, RX)

				FMul(RY, N2P, TMP)
				FMul(RZ, RX, RT)
				FMul(N2P, RZ, RZ)
				FMul(RY, RX, RX)
			end

			RX, RY, RT, TMP = TMP, RT, RX, RY
		end
	end

	local Output = buffer.create(PointSize)
	buffer.copy(Output, 0, RX, 0, CoordSize)
	buffer.copy(Output, CoordSize, RY, 0, CoordSize)
	buffer.copy(Output, 2 * CoordSize, RZ, 0, CoordSize)
	buffer.copy(Output, 3 * CoordSize, RT, 0, CoordSize)
	return Output
end

local function StandardWNAF(ScalarBits: buffer, BitCount: number, W: number): (buffer, number)
	local PadSize = BitCount + W + 8
	local Bits = buffer.create(PadSize)
	for I = 0, BitCount - 1 do
		buffer.writeu8(Bits, I, buffer.readu8(ScalarBits, I))
	end

	local Out = buffer.create(PadSize)
	local Pow2W = 2 ^ W
	local HalfPow2W = 2 ^ (W - 1)

	local OutLen = 0
	local Pos = 0
	while Pos < PadSize - W do
		if buffer.readu8(Bits, Pos) == 0 then
			buffer.writei8(Out, OutLen, 0)
		else
			local V = 0
			for K = 0, W - 1 do
				V += buffer.readu8(Bits, Pos + K) * (2 ^ K)
			end
			local Val
			if V >= HalfPow2W then
				Val = V - Pow2W
				for K = 0, W - 1 do buffer.writeu8(Bits, Pos + K, 0) end
				local J = Pos + W
				while J < PadSize do
					if buffer.readu8(Bits, J) == 0 then
						buffer.writeu8(Bits, J, 1)
						break
					else
						buffer.writeu8(Bits, J, 0)
						J += 1
					end
				end
			else
				Val = V
				for K = 0, W - 1 do buffer.writeu8(Bits, Pos + K, 0) end
			end
			buffer.writei8(Out, OutLen, Val)
		end
		OutLen += 1
		Pos += 1
	end

	while OutLen > 0 and buffer.readi8(Out, OutLen - 1) == 0 do
		OutLen -= 1
	end

	return Out, OutLen
end

function Edwards25519.MulDoubleStraussG(VarPoint: buffer, K1Bits: buffer, K1Count: number, K2Bits: buffer, K2Count: number): buffer
	local PointSize = POINT_SIZE
	local CoordSize = COORD_SIZE
	local W = STRAUSS_NAF_WIDTH

	local NAF1, L1 = StandardWNAF(K1Bits, K1Count, W)
	local NAF2, L2 = StandardWNAF(K2Bits, K2Count, W)
	local VarTable = Edwards25519.WindowedNAFTable(VarPoint, W)
	local GTable = BASEPOINT_NAF_TABLE 

	local Square = FieldPrime.Square
	local FAdd = FieldPrime.Add
	local FSub = FieldPrime.Sub
	local FMul = FieldPrime.Mul
	local Carry = FieldPrime.Carry

	local RX = buffer.create(CoordSize)
	local RY = buffer.create(CoordSize)
	local RZ = buffer.create(CoordSize)
	local RT = buffer.create(CoordSize)
	buffer.copy(RX, 0, IDENTITY_O, 0, CoordSize)
	buffer.copy(RY, 0, IDENTITY_O, CoordSize, CoordSize)
	buffer.copy(RZ, 0, IDENTITY_O, 2 * CoordSize, CoordSize)
	buffer.copy(RT, 0, IDENTITY_O, 3 * CoordSize, CoordSize)

	local DA = buffer.create(CoordSize)
	local DB = buffer.create(CoordSize)
	local DE = buffer.create(CoordSize)
	local DG = buffer.create(CoordSize)
	local N2P = buffer.create(CoordSize)
	local N2M = buffer.create(CoordSize)
	local N2Z = buffer.create(CoordSize)
	local N2T = buffer.create(CoordSize)
	local TMP = buffer.create(CoordSize)

	local MaxLen = if L1 > L2 then L1 else L2
	local Started = false

	for I = MaxLen, 1, -1 do
		local D1 = if I <= L1 then buffer.readi8(NAF1, I - 1) else 0
		local D2 = if I <= L2 then buffer.readi8(NAF2, I - 1) else 0

		if Started then
			Square(RX, DA)
			Square(RY, DB)
			Square(RZ, RZ)
			FAdd(RZ, RZ, RZ)
			FAdd(DA, DB, DE)
			FAdd(RX, RY, RX)
			Square(RX, DG)
			FSub(DG, DE, DG)
			Carry(DG, DG)
			FSub(DB, DA, DB)
			FSub(RZ, DB, RZ)
			Carry(RZ, RZ)

			FMul(DG, RZ, RX)
			FMul(DB, DE, RY)
			FMul(RZ, DB, RZ)
			FMul(DG, DE, RT)
		end

		if D1 ~= 0 then
			Started = true
			local TableIndex = if D1 > 0 then (D1 - 1) else ((-D1) - 1)
			local Offset = TableIndex * PointSize
			buffer.copy(N2P, 0, VarTable, Offset, CoordSize)
			buffer.copy(N2M, 0, VarTable, Offset + CoordSize, CoordSize)
			buffer.copy(N2Z, 0, VarTable, Offset + 2 * CoordSize, CoordSize)
			buffer.copy(N2T, 0, VarTable, Offset + 3 * CoordSize, CoordSize)

			if D1 > 0 then
				FSub(RY, RX, TMP); FMul(TMP, N2M, TMP)
				FAdd(RY, RX, RX); FMul(RX, N2P, RX)
				FMul(RT, N2T, RT); FMul(RZ, N2Z, RZ)
				FSub(RX, TMP, RY); FSub(RZ, RT, N2P)
				FAdd(RZ, RT, RZ); FAdd(RX, TMP, RX)
				FMul(RY, N2P, TMP); FMul(RZ, RX, RT)
				FMul(N2P, RZ, RZ); FMul(RY, RX, RX)
			else
				FSub(RY, RX, TMP); FMul(TMP, N2P, TMP)
				FAdd(RY, RX, RX); FMul(RX, N2M, RX)
				FMul(RT, N2T, RT); FMul(RZ, N2Z, RZ)
				FSub(RX, TMP, RY); FAdd(RZ, RT, N2P)
				FSub(RZ, RT, RZ); FAdd(RX, TMP, RX)
				FMul(RY, N2P, TMP); FMul(RZ, RX, RT)
				FMul(N2P, RZ, RZ); FMul(RY, RX, RX)
			end
			RX, RY, RT, TMP = TMP, RT, RX, RY
		end

		if D2 ~= 0 then
			Started = true
			local TableIndex = if D2 > 0 then (D2 - 1) else ((-D2) - 1)
			local Offset = TableIndex * PointSize
			buffer.copy(N2P, 0, GTable, Offset, CoordSize)
			buffer.copy(N2M, 0, GTable, Offset + CoordSize, CoordSize)
			buffer.copy(N2Z, 0, GTable, Offset + 2 * CoordSize, CoordSize)
			buffer.copy(N2T, 0, GTable, Offset + 3 * CoordSize, CoordSize)

			if D2 > 0 then
				FSub(RY, RX, TMP); FMul(TMP, N2M, TMP)
				FAdd(RY, RX, RX); FMul(RX, N2P, RX)
				FMul(RT, N2T, RT); FMul(RZ, N2Z, RZ)
				FSub(RX, TMP, RY); FSub(RZ, RT, N2P)
				FAdd(RZ, RT, RZ); FAdd(RX, TMP, RX)
				FMul(RY, N2P, TMP); FMul(RZ, RX, RT)
				FMul(N2P, RZ, RZ); FMul(RY, RX, RX)
			else
				FSub(RY, RX, TMP); FMul(TMP, N2P, TMP)
				FAdd(RY, RX, RX); FMul(RX, N2M, RX)
				FMul(RT, N2T, RT); FMul(RZ, N2Z, RZ)
				FSub(RX, TMP, RY); FAdd(RZ, RT, N2P)
				FSub(RZ, RT, RZ); FAdd(RX, TMP, RX)
				FMul(RY, N2P, TMP); FMul(RZ, RX, RT)
				FMul(N2P, RZ, RZ); FMul(RY, RX, RX)
			end
			RX, RY, RT, TMP = TMP, RT, RX, RY
		end
	end

	local Output = buffer.create(PointSize)
	buffer.copy(Output, 0, RX, 0, CoordSize)
	buffer.copy(Output, CoordSize, RY, 0, CoordSize)
	buffer.copy(Output, 2 * CoordSize, RZ, 0, CoordSize)
	buffer.copy(Output, 3 * CoordSize, RT, 0, CoordSize)
	return Output
end

return Edwards25519