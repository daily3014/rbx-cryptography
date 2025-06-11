--[=[
   Cryptography library: Edwards25519
   
   Return type: varies by function
   Example usage:
   	local Edwards = require("Edwards25519")
   	
   	--------Usage Case 1: Point addition--------
   	local Point1 = Edwards.Decode(SomeEncodedPoint)
   	local Point2 = Edwards.Decode(AnotherEncodedPoint)
   	local Sum = Edwards.Add(Point1, Edwards.Niels(Point2))
   	
   	--------Usage Case 2: Scalar multiplication--------
   	local ScalarBits = {1, 0, 1, 1, 0} -- example bits
   	local Result = Edwards.MulG(ScalarBits)
   	local EncodedResult = Edwards.Encode(Result)
--]=]

--!native
--!optimize 2

local FieldPrime = require(script.Parent.FieldPrime)

local Unpack = unpack or table.unpack

-- EdwardsPoint represents a point on edwards25519 in extended coordinates
local CurveD = FieldPrime.Mul(FieldPrime.Num(-121665), FieldPrime.Invert(FieldPrime.Num(121666)))
local CurveK = FieldPrime.KMul(CurveD, 2)

--NielsPoint represents a point in niels coordinates for fast addition
local IdentityO = { FieldPrime.Num(0), FieldPrime.Num(1), FieldPrime.Num(1), FieldPrime.Num(0) }
local BasePointG = nil

-- double a point efficiently using dedicated doubling formula
local function Double(Point1)
	-- note: some fp.sub calls here technically break contracts but work in practice
	-- because fp.carry handles the larger intermediate values properly
	local Point1X, Point1Y, Point1Z = Unpack(Point1)
	local SquaredA = FieldPrime.Square(Point1X)
	local SquaredB = FieldPrime.Square(Point1Y)
	local SquaredC = FieldPrime.Square(Point1Z)
	local DoubledD = FieldPrime.Add(SquaredC, SquaredC)
	local SumE = FieldPrime.Add(SquaredA, SquaredB)
	local SumF = FieldPrime.Add(Point1X, Point1Y)
	local SquaredG = FieldPrime.Square(SumF)
	local DiffH = FieldPrime.Carry(FieldPrime.Sub(SquaredG, SumE))
	local DiffI = FieldPrime.Sub(SquaredB, SquaredA)
	local DiffJ = FieldPrime.Carry(FieldPrime.Sub(DoubledD, DiffI))
	local NewX = FieldPrime.Mul(DiffH, DiffJ)
	local NewY = FieldPrime.Mul(DiffI, SumE)
	local NewZ = FieldPrime.Mul(DiffJ, DiffI)
	local NewT = FieldPrime.Mul(DiffH, SumE)
	return { NewX, NewY, NewZ, NewT }
end

-- add two points where second is in niels form
local function Add(Point1, NielsPoint2)
	local Point1X, Point1Y, Point1Z, Point1T = Unpack(Point1)
	local Niels1Plus, Niels1Minus, Niels1Z, Niels1T = Unpack(NielsPoint2)
	local DiffA = FieldPrime.Sub(Point1Y, Point1X)
	local ProductB = FieldPrime.Mul(DiffA, Niels1Minus)
	local SumC = FieldPrime.Add(Point1Y, Point1X)
	local ProductD = FieldPrime.Mul(SumC, Niels1Plus)
	local ProductE = FieldPrime.Mul(Point1T, Niels1T)
	local ProductF = FieldPrime.Mul(Point1Z, Niels1Z)
	local DiffG = FieldPrime.Sub(ProductD, ProductB)
	local DiffH = FieldPrime.Sub(ProductF, ProductE)
	local SumI = FieldPrime.Add(ProductF, ProductE)
	local SumJ = FieldPrime.Add(ProductD, ProductB)
	local NewX = FieldPrime.Mul(DiffG, DiffH)
	local NewY = FieldPrime.Mul(SumI, SumJ)
	local NewZ = FieldPrime.Mul(DiffH, SumI)
	local NewT = FieldPrime.Mul(DiffG, SumJ)
	return { NewX, NewY, NewZ, NewT }
end

-- subtract second point from first where second is in niels form
local function Sub(Point1, NielsPoint2)
	local Point1X, Point1Y, Point1Z, Point1T = Unpack(Point1)
	local Niels1Plus, Niels1Minus, Niels1Z, Niels1T = Unpack(NielsPoint2)
	local DiffA = FieldPrime.Sub(Point1Y, Point1X)
	local ProductB = FieldPrime.Mul(DiffA, Niels1Plus)
	local SumC = FieldPrime.Add(Point1Y, Point1X)
	local ProductD = FieldPrime.Mul(SumC, Niels1Minus)
	local ProductE = FieldPrime.Mul(Point1T, Niels1T)
	local ProductF = FieldPrime.Mul(Point1Z, Niels1Z)
	local DiffG = FieldPrime.Sub(ProductD, ProductB)
	local SumH = FieldPrime.Add(ProductF, ProductE)
	local DiffI = FieldPrime.Sub(ProductF, ProductE)
	local SumJ = FieldPrime.Add(ProductD, ProductB)
	local NewX = FieldPrime.Mul(DiffG, SumH)
	local NewY = FieldPrime.Mul(DiffI, SumJ)
	local NewZ = FieldPrime.Mul(SumH, DiffI)
	local NewT = FieldPrime.Mul(DiffG, SumJ)
	return { NewX, NewY, NewZ, NewT }
end

-- convert a point to niels coordinates for faster addition/subtraction
local function Niels(Point1)
	local Point1X, Point1Y, Point1Z, Point1T = Unpack(Point1)
	local PlusN3 = FieldPrime.Add(Point1Y, Point1X)
	local MinusN3 = FieldPrime.Sub(Point1Y, Point1X)
	local DoubledN3Z = FieldPrime.Add(Point1Z, Point1Z)
	local ScaledN3T = FieldPrime.Mul(Point1T, CurveK)
	return { PlusN3, MinusN3, DoubledN3Z, ScaledN3T }
end

-- normalize a point so Z coordinate becomes 1
local function Scale(Point1)
	local Point1X, Point1Y, Point1Z = Unpack(Point1)
	local ZInverse = FieldPrime.Invert(Point1Z)
	local NewX = FieldPrime.Mul(Point1X, ZInverse)
	local NewY = FieldPrime.Mul(Point1Y, ZInverse)
	local NewZ = FieldPrime.Num(1)
	local NewT = FieldPrime.Mul(NewX, NewY)
	return { NewX, NewY, NewZ, NewT }
end

-- turn a normalized point into its 32-byte encoding
local function Encode(Point1)
	Point1 = Scale(Point1)
	local Point1X, Point1Y = Unpack(Point1)
	local EncodedY = FieldPrime.Encode(Point1Y)
	local XSignBit = FieldPrime.Canonicalize(Point1X)[1] % 2
	return EncodedY:sub(1, -2) .. string.char(EncodedY:byte(-1) + XSignBit * 128)
end

-- turn 32 bytes back into a point (might fail if not on curve)
local function Decode(EncodedString)
	local YCoord = FieldPrime.Decode(EncodedString)
	local YSquared = FieldPrime.Square(YCoord)
	local Numerator = FieldPrime.Sub(YSquared, FieldPrime.Num(1))
	local Denominator = FieldPrime.Mul(YSquared, CurveD)
	local DenomPlusOne = FieldPrime.Add(Denominator, FieldPrime.Num(1))
	local XCoord = FieldPrime.SqrtDiv(Numerator, DenomPlusOne)
	if not XCoord then
		return nil
	end
	local XSignBit = FieldPrime.Canonicalize(XCoord)[1] % 2
	if XSignBit ~= bit32.extract(EncodedString:byte(-1), 7) then
		XCoord = FieldPrime.Carry(FieldPrime.Neg(XCoord))
	end
	local ZCoord = FieldPrime.Num(1)
	local TCoord = FieldPrime.Mul(XCoord, YCoord)
	return { XCoord, YCoord, ZCoord, TCoord }
end

BasePointG = Decode("Xfffffffffffffffffffffffffffffff")

-- convert little-endian bits to signed radix form for faster scalar mult
local function SignedRadixW(ScalarBits, RadixWidth)
	-- this could be cleaner but it works
	local RadixValue = 2 ^ RadixWidth
	local HalfRadix = RadixValue / 2
	local OutputDigits = {}
	local Accumulator = 0
	local Multiplier = 1
	for BitIndex = 1, #ScalarBits do
		Accumulator = Accumulator + ScalarBits[BitIndex] * Multiplier
		Multiplier = Multiplier * 2
		while BitIndex == #ScalarBits and Accumulator > 0 or Multiplier > RadixValue do
			local Remainder = Accumulator % RadixValue
			if Remainder >= HalfRadix then
				Remainder = Remainder - RadixValue
			end
			Accumulator = (Accumulator - Remainder) / RadixValue
			Multiplier = Multiplier / RadixValue
			OutputDigits[#OutputDigits + 1] = Remainder
		end
	end
	return OutputDigits
end

-- build a multiplication table for radix-w scalar multiplication
local function RadixWTable(BasePoint, RadixWidth)
	local OutputTable = {}
	for WindowIndex = 1, math.ceil(256 / RadixWidth) do
		local CurrentRow = { Niels(BasePoint) }
		for Multiple = 2, 2 ^ RadixWidth / 2 do
			BasePoint = Add(BasePoint, CurrentRow[1])
			CurrentRow[Multiple] = Niels(BasePoint)
		end
		OutputTable[WindowIndex] = CurrentRow
		BasePoint = Double(BasePoint)
	end
	return OutputTable
end

-- radix width for the precomputed base point table
local BasePointRadixWidth = 5

-- precomputed multiplication table for the base point
local BasePointTable = RadixWTable(BasePointG, BasePointRadixWidth)

-- convert bits to windowed non-adjacent form for efficient scalar mult
-- returns 0 for doubling or odd integer for addition with multiple
local function WindowedNAF(ScalarBits, WindowWidth)
	-- again this could be prettier but it works
	local WindowValue = 2 ^ WindowWidth
	local HalfWindow = WindowValue / 2
	local OutputNAF = {}
	local Accumulator = 0
	local Multiplier = 1
	for BitIndex = 1, #ScalarBits do
		Accumulator = Accumulator + ScalarBits[BitIndex] * Multiplier
		Multiplier = Multiplier * 2
		while BitIndex == #ScalarBits and Accumulator > 0 or Multiplier > WindowValue do
			if Accumulator % 2 == 0 then
				Accumulator = Accumulator / 2
				Multiplier = Multiplier / 2
				OutputNAF[#OutputNAF + 1] = 0
			else
				local Remainder = Accumulator % WindowValue
				if Remainder >= HalfWindow then
					Remainder = Remainder - WindowValue
				end
				Accumulator = Accumulator - Remainder
				OutputNAF[#OutputNAF + 1] = Remainder
			end
		end
	end
	while OutputNAF[#OutputNAF] == 0 do
		OutputNAF[#OutputNAF] = nil
	end
	return OutputNAF
end

-- build a table for windowed NAF scalar multiplication
local function WindowedNAFTable(BasePoint, WindowWidth)
	local DoubledPoint = Double(BasePoint)
	local OutputTable = { Niels(BasePoint) }
	for OddMultiple = 3, 2 ^ WindowWidth, 2 do
		OutputTable[OddMultiple] = Niels(Add(DoubledPoint, OutputTable[OddMultiple - 2]))
	end
	return OutputTable
end

-- multiply the base point by a scalar using precomputed table
local function MulG(ScalarBits)
	local SignedWindows = SignedRadixW(ScalarBits, BasePointRadixWidth)
	local ResultPoint = IdentityO
	for WindowIndex = 1, #SignedWindows do
		local WindowValue = SignedWindows[WindowIndex]
		if WindowValue > 0 then
			ResultPoint = Add(ResultPoint, BasePointTable[WindowIndex][WindowValue])
		elseif WindowValue < 0 then
			ResultPoint = Sub(ResultPoint, BasePointTable[WindowIndex][-WindowValue])
		end
	end
	return ResultPoint
end

-- multiply any point by a scalar using windowed NAF
local function Mul(BasePoint, ScalarBits)
	local NAFForm = WindowedNAF(ScalarBits, 5)
	local MultipleTable = WindowedNAFTable(BasePoint, 5)
	local ResultPoint = IdentityO
	for NAFIndex = #NAFForm, 1, -1 do
		local NAFDigit = NAFForm[NAFIndex]
		if NAFDigit == 0 then
			ResultPoint = Double(ResultPoint)
		elseif NAFDigit > 0 then
			ResultPoint = Add(ResultPoint, MultipleTable[NAFDigit])
		else
			ResultPoint = Sub(ResultPoint, MultipleTable[-NAFDigit])
		end
	end
	return ResultPoint
end

return {
	Double = Double,
	Add = Add,
	Sub = Sub,
	Niels = Niels,
	Scale = Scale,
	Encode = Encode,
	Decode = Decode,
	MulG = MulG,
	Mul = Mul,
}
