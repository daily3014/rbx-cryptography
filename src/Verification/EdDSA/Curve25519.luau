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
--!native
--!optimize 2

local FieldPrime = require("./FieldPrime")
local Edwards25519 = require("./Edwards25519")
local RandomBytes = require("./Random")

local MONTGOMERY_POINT_SIZE = 208
local COORD_SIZE = 104

local function GetMontgomeryCoord(Point: buffer, Index: number): buffer
	local Coord = buffer.create(COORD_SIZE)
	buffer.copy(Coord, 0, Point, Index * COORD_SIZE, COORD_SIZE)
	return Coord
end

local function SetMontgomeryCoord(Point: buffer, Index: number, Value: buffer)
	buffer.copy(Point, Index * COORD_SIZE, Value, 0, COORD_SIZE)
end

local function CreateMontgomeryPoint(X: buffer, Z: buffer): buffer
	local Point = buffer.create(MONTGOMERY_POINT_SIZE)
	SetMontgomeryCoord(Point, 0, X)
	SetMontgomeryCoord(Point, 1, Z)
	return Point
end

local function Double(PointToDouble: buffer): buffer
	local CoordX = GetMontgomeryCoord(PointToDouble, 0)
	local CoordZ = GetMontgomeryCoord(PointToDouble, 1)

	local SumXZ = FieldPrime.Add(CoordX, CoordZ)
	FieldPrime.Square(SumXZ, SumXZ) -- Reused SumXZ
	local SumSquared = SumXZ
	FieldPrime.Sub(CoordX, CoordZ, CoordX) -- Reused CoordX
	FieldPrime.Square(CoordX, CoordX) -- Reused CoordX
	local DiffSquared = CoordX
	local Difference = FieldPrime.Sub(SumSquared, DiffSquared)
	FieldPrime.Mul(SumSquared, DiffSquared, SumSquared) -- Reused SumSquared
	local NewX = SumSquared
	FieldPrime.Add(DiffSquared, FieldPrime.KMul(Difference, 121666), DiffSquared) -- Reused DiffSquared
	FieldPrime.Mul(Difference, DiffSquared, Difference) -- Reused Difference
	local NewZ = Difference

	return CreateMontgomeryPoint(NewX, NewZ)
end

local function DifferentialAdd(DifferencePoint: buffer, Point1: buffer, Point2: buffer): buffer
	local DiffX = GetMontgomeryCoord(DifferencePoint, 0)
	local DiffZ = GetMontgomeryCoord(DifferencePoint, 1)
	local X1 = GetMontgomeryCoord(Point1, 0)
	local Z1 = GetMontgomeryCoord(Point1, 1)
	local X2 = GetMontgomeryCoord(Point2, 0)
	local Z2 = GetMontgomeryCoord(Point2, 1)

	local SumA = FieldPrime.Add(X1, Z1)
	FieldPrime.Sub(X1, Z1, X1) -- Reused X1
	local DiffB = X1
	local SumC = FieldPrime.Add(X2, Z2)
	FieldPrime.Sub(X2, Z2, X2) -- Reused X2
	local DiffD = X2
	FieldPrime.Mul(DiffD, SumA, DiffD) -- Reused DiffD
	local CrossDA = DiffD
	FieldPrime.Mul(SumC, DiffB, SumC) -- Reused SumC
	local CrossCB = SumC
	
	local CrossDACB = FieldPrime.Add(CrossDA, CrossCB)
	FieldPrime.Square(CrossDACB, CrossDACB) -- Reused CrossDACB
	FieldPrime.Mul(DiffZ, CrossDACB) -- Reused CrossDACB
	local NewX = CrossDACB
	FieldPrime.Sub(CrossDA, CrossCB, CrossDA) -- Reused CrossDA
	FieldPrime.Square(CrossDA, CrossDA) -- Reused CrossDA
	FieldPrime.Mul(DiffX, CrossDA, CrossDA) -- Reused CrossDA
	local NewZ = CrossDA

	return CreateMontgomeryPoint(NewX, NewZ)
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
	FieldPrime.Sub(X1, Z1, X1) -- Reused X1
	local DiffB = X1
	local DiffSquaredBB = FieldPrime.Square(DiffB)
	local DifferenceE = FieldPrime.Sub(SumSquaredAA, DiffSquaredBB)
	
	local DiffD = FieldPrime.Sub(X2, Z2)
	FieldPrime.Mul(DiffD, SumA, DiffD) -- Reused DiffD
	local CrossDA = DiffD
	
	FieldPrime.Add(X2, Z2, X2) -- Reused X2
	local SumC = X2
	FieldPrime.Mul(SumC, DiffB, SumC) -- Reused SumC
	local CrossCB = SumC
	
	local NewX4 = FieldPrime.Mul(DiffZ, FieldPrime.Square(FieldPrime.Add(CrossDA, CrossCB)))
	local NewZ4 = FieldPrime.Mul(DiffX, FieldPrime.Square(FieldPrime.Sub(CrossDA, CrossCB)))
	
	FieldPrime.Mul(SumSquaredAA, DiffSquaredBB, SumSquaredAA) -- Reused SumSquaredAA
	local NewX3 = SumSquaredAA
	
	local A = FieldPrime.Add(DiffSquaredBB, FieldPrime.KMul(DifferenceE, 121666), DiffSquaredBB) -- Reused DiffSquaredBB
	FieldPrime.Mul(DifferenceE, A) -- Reused DifferenceE
	local NewZ3 = DifferenceE

	return CreateMontgomeryPoint(NewX3, NewZ3), CreateMontgomeryPoint(NewX4, NewZ4)
end

local function Ladder(DifferencePoint: buffer, ScalarBits: buffer, ScalarBitCount: number): buffer
	local CurrentP = CreateMontgomeryPoint(FieldPrime.Num(1), FieldPrime.Num(0))
	local CurrentQ = buffer.create(MONTGOMERY_POINT_SIZE)
	buffer.copy(CurrentQ, 0, DifferencePoint, 0, MONTGOMERY_POINT_SIZE)

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

local function Ladder8(BasePoint: buffer, ScalarBits: buffer, ScalarBitCount: number): buffer
	local RandomBuffer = RandomBytes.Random(32)
	local RandomFactor = FieldPrime.Decode(RandomBuffer)

	local BaseX = GetMontgomeryCoord(BasePoint, 0)
	local BaseZ = GetMontgomeryCoord(BasePoint, 1)
	local RandomizedPoint = CreateMontgomeryPoint(
		FieldPrime.Mul(BaseX, RandomFactor), 
		FieldPrime.Mul(BaseZ, RandomFactor)
	)

	return Double(Double(Double(Ladder(RandomizedPoint, ScalarBits, ScalarBitCount))))
end

local function Scale(InputPoint: buffer): buffer
	local InputX = GetMontgomeryCoord(InputPoint, 0)
	local InputZ = GetMontgomeryCoord(InputPoint, 1)

	return CreateMontgomeryPoint(
		FieldPrime.Mul(InputX, FieldPrime.Invert(InputZ)), 
		FieldPrime.Num(1)
	)
end

local function Encode(NormalizedPoint: buffer): buffer
	local X = GetMontgomeryCoord(NormalizedPoint, 0)
	return FieldPrime.Encode(X)
end

local function Decode(EncodedBuffer: buffer): buffer
	return CreateMontgomeryPoint(FieldPrime.Decode(EncodedBuffer), FieldPrime.Num(1))
end

local function DecodeEd(EdwardsBuffer: buffer): buffer
	local YCoord = FieldPrime.Decode(EdwardsBuffer)
	local Numerator = FieldPrime.Carry(FieldPrime.Add(FieldPrime.Num(1), YCoord))
	local Denominator = FieldPrime.Carry(FieldPrime.Sub(FieldPrime.Num(1), YCoord))
	if FieldPrime.Eqz(Denominator) then
		return CreateMontgomeryPoint(FieldPrime.Num(0), FieldPrime.Num(1))
	else
		return CreateMontgomeryPoint(Numerator, Denominator)
	end
end

local function MulG(ScalarBits: buffer, ScalarBitCount: number): buffer
	local EdwardsPoint = Edwards25519.MulG(ScalarBits, ScalarBitCount)

	-- Extract Y and Z coordinates from Edwards point (indices 1 and 2)
	local PointY = buffer.create(COORD_SIZE)
	local PointZ = buffer.create(COORD_SIZE)
	buffer.copy(PointY, 0, EdwardsPoint, COORD_SIZE, COORD_SIZE)
	buffer.copy(PointZ, 0, EdwardsPoint, 2 * COORD_SIZE, COORD_SIZE)

	local NewX = FieldPrime.Carry(FieldPrime.Add(PointY, PointZ))
	local NewZ = FieldPrime.Carry(FieldPrime.Sub(PointZ, PointY))

	return CreateMontgomeryPoint(NewX, NewZ)
end

local function Prac(BasePoint: buffer, PracRuleset: {any}): (buffer?, buffer?, buffer?)
	local RandomBuffer = RandomBytes.Random(32)
	local RandomFactor = FieldPrime.Decode(RandomBuffer)

	local BaseX = GetMontgomeryCoord(BasePoint, 0)
	local BaseZ = GetMontgomeryCoord(BasePoint, 1)
	local RandomizedA = CreateMontgomeryPoint(
		FieldPrime.Mul(BaseX, RandomFactor), 
		FieldPrime.Mul(BaseZ, RandomFactor)
	)

	RandomizedA = Double(Double(Double(RandomizedA)))

	local AZ = GetMontgomeryCoord(RandomizedA, 1)
	if FieldPrime.Eqz(AZ) then
		return nil, nil, nil
	end

	RandomizedA = Ladder(RandomizedA, PracRuleset[1], PracRuleset[2])

	local Rules = PracRuleset[3]
	local RuleCount = PracRuleset[4]
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

local G = CreateMontgomeryPoint(FieldPrime.Num(9), FieldPrime.Num(1))

return {
	G = G,
	DifferentialAdd = DifferentialAdd,
	Scale = Scale,
	Encode = Encode,
	Decode = Decode,
	DecodeEd = DecodeEd,
	Ladder8 = Ladder8,
	MulG = MulG,
	Prac = Prac,
}