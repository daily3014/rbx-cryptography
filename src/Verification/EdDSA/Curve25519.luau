--[=[
	Cryptography library: Curve25519 Montgomery

	Return type: varies by function
	Example usage:
		local Curve25519 = require("Curve25519")
		local FieldQuadratic = require("FieldQuadratic")

		--------Usage Case 1: Point multiplication--------
		local BasePoint = Curve25519.G
		local SomeScalar = FieldQuadratic.Decode(ScalarBytes)
		local ScalarBits, BitCount = FieldQuadratic.Bits(SomeScalar)
		local Result = Curve25519.Ladder8(BasePoint, ScalarBits, BitCount)

		--------Usage Case 2: Encode/decode points--------
		local EncodedPoint = Curve25519.Encode(Curve25519.Scale(Result))
		local DecodedPoint = Curve25519.Decode(EncodedPoint)
--]=]

--!strict
--!optimize 2
--!native

local FieldPrime = require("./FieldPrime")
local CSPRNG = require("./CSPRNG")

local MONTGOMERY_POINT_SIZE = 208
local COORD_SIZE = 104

local function GetMontgomeryCoord(Point: buffer, Index: number): buffer
	local Coord = buffer.create(COORD_SIZE)
	buffer.copy(Coord, 0, Point, Index * COORD_SIZE, COORD_SIZE)
	
	return Coord
end

local function Double(PointToDouble: buffer): buffer
	local CoordX = GetMontgomeryCoord(PointToDouble, 0)
	local CoordZ = GetMontgomeryCoord(PointToDouble, 1)

	local SumXZ = FieldPrime.Add(CoordX, CoordZ)
	local SumSquared = FieldPrime.Square(SumXZ)
	local DiffXZ = FieldPrime.Sub(CoordX, CoordZ)
	local DiffSquared = FieldPrime.Square(DiffXZ)
	local Difference = FieldPrime.Sub(SumSquared, DiffSquared)
	local NewX = FieldPrime.Mul(SumSquared, DiffSquared)
	local NewZ = FieldPrime.Mul(Difference, FieldPrime.Add(DiffSquared, FieldPrime.KMul(Difference, 121666)))

	local Point = buffer.create(MONTGOMERY_POINT_SIZE)
	buffer.copy(Point, 0 * COORD_SIZE, NewX, 0, COORD_SIZE)
	buffer.copy(Point, 1 * COORD_SIZE, NewZ, 0, COORD_SIZE)

	return Point
end

local Curve25519 = {}

function Curve25519.DifferentialAdd(DifferencePoint: buffer, Point1: buffer, Point2: buffer): buffer
	local DiffX = GetMontgomeryCoord(DifferencePoint, 0)
	local DiffZ = GetMontgomeryCoord(DifferencePoint, 1)
	local X1 = GetMontgomeryCoord(Point1, 0)
	local Z1 = GetMontgomeryCoord(Point1, 1)
	local X2 = GetMontgomeryCoord(Point2, 0)
	local Z2 = GetMontgomeryCoord(Point2, 1)

	local SumA = FieldPrime.Add(X1, Z1)
	local DiffB = FieldPrime.Sub(X1, Z1)
	local SumC = FieldPrime.Add(X2, Z2)
	local DiffD = FieldPrime.Sub(X2, Z2)
	local CrossDA = FieldPrime.Mul(DiffD, SumA)
	local CrossCB = FieldPrime.Mul(SumC, DiffB)
	
	local NewX = FieldPrime.Mul(DiffZ, FieldPrime.Square(FieldPrime.Add(CrossDA, CrossCB)))
	local NewZ = FieldPrime.Mul(DiffX, FieldPrime.Square(FieldPrime.Sub(CrossDA, CrossCB)))

	local Point = buffer.create(MONTGOMERY_POINT_SIZE)
	buffer.copy(Point, 0 * COORD_SIZE, NewX, 0, COORD_SIZE)
	buffer.copy(Point, 1 * COORD_SIZE, NewZ, 0, COORD_SIZE)

	return Point
end

local function LadderStep(DifferencePoint: buffer, Point1: buffer, Point2: buffer): (buffer, buffer)
	local DiffX = GetMontgomeryCoord(DifferencePoint, 0)
	local DiffZ = GetMontgomeryCoord(DifferencePoint, 1)
	local X1 = GetMontgomeryCoord(Point1, 0)
	local Z1 = GetMontgomeryCoord(Point1, 1)
	local X2 = GetMontgomeryCoord(Point2, 0)
	local Z2 = GetMontgomeryCoord(Point2, 1)
	
	local SumA = FieldPrime.Add(X1, Z1)
	local SumSquaredAA = FieldPrime.Square(SumA)
	local DiffB = FieldPrime.Sub(X1, Z1)
	local DiffSquaredBB = FieldPrime.Square(DiffB)
	
	local DifferenceE = FieldPrime.Sub(SumSquaredAA, DiffSquaredBB)
	local DiffD = FieldPrime.Sub(X2, Z2)
	local CrossDA = FieldPrime.Mul(DiffD, SumA)
	local SumC = FieldPrime.Add(X2, Z2)
	local CrossCB = FieldPrime.Mul(SumC, DiffB)
	
	local NewX4 = FieldPrime.Mul(DiffZ, FieldPrime.Square(FieldPrime.Add(CrossDA, CrossCB)))
	local NewZ4 = FieldPrime.Mul(DiffX, FieldPrime.Square(FieldPrime.Sub(CrossDA, CrossCB)))
	local NewX3 = FieldPrime.Mul(SumSquaredAA, DiffSquaredBB)
	local NewZ3 = FieldPrime.Mul(DifferenceE, FieldPrime.Add(DiffSquaredBB, FieldPrime.KMul(DifferenceE, 121666)))

	local Point = buffer.create(MONTGOMERY_POINT_SIZE)
	buffer.copy(Point, 0 * COORD_SIZE, NewX3, 0, COORD_SIZE)
	buffer.copy(Point, 1 * COORD_SIZE, NewZ3, 0, COORD_SIZE)
	
	local SecondPoint = buffer.create(MONTGOMERY_POINT_SIZE)
	buffer.copy(SecondPoint, 0 * COORD_SIZE, NewX4, 0, COORD_SIZE)
	buffer.copy(SecondPoint, 1 * COORD_SIZE, NewZ4, 0, COORD_SIZE)

	return Point, SecondPoint
end

local function Ladder(DifferencePoint: buffer, ScalarBits: buffer, ScalarBitCount: number): buffer
	local CurrentP = buffer.create(MONTGOMERY_POINT_SIZE)
	buffer.copy(CurrentP, 0 * COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)
	buffer.copy(CurrentP, 1 * COORD_SIZE, FieldPrime.Num(0), 0, COORD_SIZE)

	local CurrentQ = buffer.create(MONTGOMERY_POINT_SIZE)
	buffer.copy(CurrentQ, 0, DifferencePoint, 0, MONTGOMERY_POINT_SIZE)

	local LadderStep = LadderStep

	for BitIndex = ScalarBitCount, 1, -1 do
		local BitValue = buffer.readf64(ScalarBits, (BitIndex - 1) * 8)
		if BitValue == 0 then
			CurrentP, CurrentQ = LadderStep(DifferencePoint, CurrentP, CurrentQ)
		else
			CurrentQ, CurrentP = LadderStep(DifferencePoint, CurrentQ, CurrentP)
		end
	end

	return CurrentP
end

function Curve25519.Decode(EncodedBuffer: buffer): buffer
	local Point = buffer.create(MONTGOMERY_POINT_SIZE)
	buffer.copy(Point, 0 * COORD_SIZE, FieldPrime.Decode(EncodedBuffer), 0, COORD_SIZE)
	buffer.copy(Point, 1 * COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)
	
	return Point
end

function Curve25519.Prac(BasePoint: buffer, PracRuleset: {any}): (buffer?, buffer?, buffer?)
	local DifferentialAdd = Curve25519.DifferentialAdd
	local RandomBuffer = CSPRNG.Ed25519Random()
	local RandomFactor = FieldPrime.Decode(RandomBuffer)

	local BaseX = GetMontgomeryCoord(BasePoint, 0)
	local BaseZ = GetMontgomeryCoord(BasePoint, 1)
	local RandomizedA = buffer.create(MONTGOMERY_POINT_SIZE)
	buffer.copy(RandomizedA, 0 * COORD_SIZE, FieldPrime.Mul(BaseX, RandomFactor), 0, COORD_SIZE)
	buffer.copy(RandomizedA, 1 * COORD_SIZE, FieldPrime.Mul(BaseZ, RandomFactor), 0, COORD_SIZE)
	
	RandomizedA = Double(Double(Double(RandomizedA)))

	local AZ = GetMontgomeryCoord(RandomizedA, 1)
	if FieldPrime.Eqz(AZ) then
		return nil, nil, nil
	end

	RandomizedA = Ladder(RandomizedA, PracRuleset[1], PracRuleset[2])

	local Rules: buffer = PracRuleset[3]
	local RuleCount: number = PracRuleset[4]
	if RuleCount == 0 then
		return RandomizedA, nil, nil
	end

	local CurrentB, CurrentC
	local FirstRule = buffer.readf64(Rules, (RuleCount - 1) * 8)
	if FirstRule == 2 then
		local DoubledA = Double(RandomizedA)
		RandomizedA, CurrentB, CurrentC = DifferentialAdd(RandomizedA, DoubledA, RandomizedA), RandomizedA, DoubledA
	elseif FirstRule == 3 or FirstRule == 5 then
		RandomizedA, CurrentB, CurrentC = Double(RandomizedA), RandomizedA, RandomizedA
	elseif FirstRule == 6 then
		local DoubledA = Double(RandomizedA)
		local TripledA = DifferentialAdd(RandomizedA, DoubledA, RandomizedA)
		RandomizedA, CurrentB, CurrentC = Double(TripledA), RandomizedA, DifferentialAdd(RandomizedA, TripledA, DoubledA)
	elseif FirstRule == 7 then
		local DoubledA = Double(RandomizedA)
		local TripledA = DifferentialAdd(RandomizedA, DoubledA, RandomizedA)
		local QuadrupleA = Double(DoubledA)
		RandomizedA, CurrentB, CurrentC = DifferentialAdd(TripledA, QuadrupleA, RandomizedA), RandomizedA, QuadrupleA
	elseif FirstRule == 8 then
		local DoubledA = Double(RandomizedA)
		local TripledA = DifferentialAdd(RandomizedA, DoubledA, RandomizedA)
		RandomizedA, CurrentB, CurrentC = Double(DoubledA), RandomizedA, TripledA
	else
		RandomizedA, CurrentB, CurrentC = RandomizedA, Double(RandomizedA), RandomizedA
	end

	if not CurrentC then
		return nil, nil, nil
	end

	for RuleIndex = RuleCount - 1, 1, -1 do
		local CurrentRule = buffer.readf64(Rules, (RuleIndex - 1) * 8)
		if CurrentRule == 0 then
			RandomizedA, CurrentB = CurrentB, RandomizedA
		elseif CurrentRule == 1 then
			local SumAB = DifferentialAdd(CurrentC, RandomizedA, CurrentB)
			RandomizedA, CurrentB = DifferentialAdd(CurrentB, SumAB, RandomizedA), DifferentialAdd(RandomizedA, SumAB, CurrentB)
		elseif CurrentRule == 2 then
			RandomizedA, CurrentC = DifferentialAdd(CurrentB, DifferentialAdd(CurrentC, RandomizedA, CurrentB), RandomizedA), Double(RandomizedA)
		elseif CurrentRule == 3 then
			RandomizedA, CurrentC = DifferentialAdd(CurrentC, RandomizedA, CurrentB), RandomizedA
		elseif CurrentRule == 5 then
			RandomizedA, CurrentC = Double(RandomizedA), DifferentialAdd(CurrentB, RandomizedA, CurrentC)
		elseif CurrentRule == 6 then
			local SumAB = DifferentialAdd(CurrentC, RandomizedA, CurrentB)
			local DoubledSumAABB = Double(SumAB)
			RandomizedA, CurrentC = DifferentialAdd(SumAB, DoubledSumAABB, SumAB), DifferentialAdd(DifferentialAdd(RandomizedA, SumAB, CurrentB), DoubledSumAABB, RandomizedA)
		elseif CurrentRule == 7 then
			local SumAB = DifferentialAdd(CurrentC, RandomizedA, CurrentB)
			local DoubleAAB = DifferentialAdd(CurrentB, SumAB, RandomizedA)
			RandomizedA, CurrentC = DifferentialAdd(RandomizedA, DoubleAAB, SumAB), DifferentialAdd(SumAB, DoubleAAB, RandomizedA)
		elseif CurrentRule == 8 then
			local DoubledA = Double(RandomizedA)
			RandomizedA, CurrentC = DifferentialAdd(CurrentC, DoubledA, DifferentialAdd(CurrentC, RandomizedA, CurrentB)), DifferentialAdd(RandomizedA, DoubledA, RandomizedA)
		else
			CurrentB, CurrentC = Double(CurrentB), DifferentialAdd(RandomizedA, CurrentC, CurrentB)
		end
	end

	return RandomizedA, CurrentB, CurrentC
end

local Point = buffer.create(MONTGOMERY_POINT_SIZE)
buffer.copy(Point, 0 * COORD_SIZE, FieldPrime.Num(9), 0, COORD_SIZE)
buffer.copy(Point, 1 * COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)
Curve25519.G = Point

return Curve25519