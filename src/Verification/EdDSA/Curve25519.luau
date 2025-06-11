--[=[
   Cryptography library: Curve25519 Montgomery
   
   Return type: varies by function
   Example usage:
   	local Curve25519 = require("Curve25519")
   	
   	--------Usage Case 1: Point multiplication--------
   	local BasePoint = Curve25519.G
   	local ScalarBits = {1, 0, 1, 1, 0} -- example bits
   	local Result = Curve25519.Ladder8(BasePoint, ScalarBits)
   	
   	--------Usage Case 2: Encode/decode points--------
   	local EncodedPoint = Curve25519.Encode(Curve25519.Scale(Result))
   	local DecodedPoint = Curve25519.Decode(EncodedPoint)
--]=]

--!native
--!optimize 2

local FieldPrime = require(script.Parent.FieldPrime)
local Edwards25519 = require(script.Parent.Edwards25519)
local RandomBytes = require(script.Parent.Random)

-- double a point because why not
local function Double(PointToDouble)
	local CoordX, CoordZ = PointToDouble[1], PointToDouble[2]
	local SumXZ = FieldPrime.Add(CoordX, CoordZ)
	local SumSquared = FieldPrime.Square(SumXZ)
	local DiffXZ = FieldPrime.Sub(CoordX, CoordZ)
	local DiffSquared = FieldPrime.Square(DiffXZ)
	local Difference = FieldPrime.Sub(SumSquared, DiffSquared)
	local NewX = FieldPrime.Mul(SumSquared, DiffSquared)
	local NewZ = FieldPrime.Mul(Difference, FieldPrime.Add(DiffSquared, FieldPrime.KMul(Difference, 121666)))
	return { NewX, NewZ }
end

-- differential addition when you need to add two points but have their difference
local function DifferentialAdd(DifferencePoint, Point1, Point2)
	local DiffX, DiffZ = DifferencePoint[1], DifferencePoint[2]
	local X1, Z1 = Point1[1], Point1[2]
	local X2, Z2 = Point2[1], Point2[2]
	local SumA = FieldPrime.Add(X1, Z1)
	local DiffB = FieldPrime.Sub(X1, Z1)
	local SumC = FieldPrime.Add(X2, Z2)
	local DiffD = FieldPrime.Sub(X2, Z2)
	local CrossDA = FieldPrime.Mul(DiffD, SumA)
	local CrossCB = FieldPrime.Mul(SumC, DiffB)
	local NewX = FieldPrime.Mul(DiffZ, FieldPrime.Square(FieldPrime.Add(CrossDA, CrossCB)))
	local NewZ = FieldPrime.Mul(DiffX, FieldPrime.Square(FieldPrime.Sub(CrossDA, CrossCB)))
	return { NewX, NewZ }
end

-- one step of the montgomery ladder algorithm
local function LadderStep(DifferencePoint, Point1, Point2)
	local DiffX, DiffZ = DifferencePoint[1], DifferencePoint[2]
	local X1, Z1 = Point1[1], Point1[2]
	local X2, Z2 = Point2[1], Point2[2]
	local SumA = FieldPrime.Add(X1, Z1)
	local SumSquaredAA = FieldPrime.Square(SumA)
	local DiffB = FieldPrime.Sub(X1, Z1)
	local DiffSquaredBB = FieldPrime.Square(DiffB)
	local DifferenceE = FieldPrime.Sub(SumSquaredAA, DiffSquaredBB)
	local SumC = FieldPrime.Add(X2, Z2)
	local DiffD = FieldPrime.Sub(X2, Z2)
	local CrossDA = FieldPrime.Mul(DiffD, SumA)
	local CrossCB = FieldPrime.Mul(SumC, DiffB)
	local NewX4 = FieldPrime.Mul(DiffZ, FieldPrime.Square(FieldPrime.Add(CrossDA, CrossCB)))
	local NewZ4 = FieldPrime.Mul(DiffX, FieldPrime.Square(FieldPrime.Sub(CrossDA, CrossCB)))
	local NewX3 = FieldPrime.Mul(SumSquaredAA, DiffSquaredBB)
	local NewZ3 = FieldPrime.Mul(DifferenceE, FieldPrime.Add(DiffSquaredBB, FieldPrime.KMul(DifferenceE, 121666)))
	return { NewX3, NewZ3 }, { NewX4, NewZ4 }
end

-- montgomery ladder for scalar multiplication
local function Ladder(DifferencePoint, ScalarBits)
	local CurrentP = { FieldPrime.Num(1), FieldPrime.Num(0) }
	local CurrentQ = DifferencePoint

	for BitIndex = #ScalarBits, 1, -1 do
		if ScalarBits[BitIndex] == 0 then
			CurrentP, CurrentQ = LadderStep(DifferencePoint, CurrentP, CurrentQ)
		else
			CurrentQ, CurrentP = LadderStep(DifferencePoint, CurrentQ, CurrentP)
		end
	end

	return CurrentP
end

-- scalar multiplication with automatic 8x cofactor clearing
local function Ladder8(BasePoint, ScalarBits)
	-- throw some randomness in to prevent timing attacks
	local RandomFactor = FieldPrime.Decode(RandomBytes.Random(32))
	local RandomizedPoint = { FieldPrime.Mul(BasePoint[1], RandomFactor), FieldPrime.Mul(BasePoint[2], RandomFactor) }

	-- multiply then clear cofactor by tripling the doubling
	return Double(Double(Double(Ladder(RandomizedPoint, ScalarBits))))
end

-- normalize a point so Z coordinate becomes 1
local function Scale(InputPoint)
	return { FieldPrime.Mul(InputPoint[1], FieldPrime.Invert(InputPoint[2])), FieldPrime.Num(1) }
end

-- turn a normalized point into bytes
local function Encode(NormalizedPoint)
	return FieldPrime.Encode(NormalizedPoint[1])
end

-- turn bytes back into a point
local function Decode(EncodedString)
	return { FieldPrime.Decode(EncodedString), FieldPrime.Num(1) }
end

-- convert edwards25519 point to curve25519 point (ignores sign bit)
-- special case: identity point (0,1) maps to 2-torsion point (0,0)
local function DecodeEd(EdwardsString)
	local YCoord = FieldPrime.Decode(EdwardsString)
	local Numerator = FieldPrime.Carry(FieldPrime.Add(FieldPrime.Num(1), YCoord))
	local Denominator = FieldPrime.Carry(FieldPrime.Sub(FieldPrime.Num(1), YCoord))
	if FieldPrime.Eqz(Denominator) then
		return { FieldPrime.Num(0), FieldPrime.Num(1) }
	else
		return { Numerator, Denominator }
	end
end

-- multiply by the base point using edwards then convert
local function MulG(ScalarBits)
	-- do the multiplication on edwards side
	local EdwardsPoint = Edwards25519.MulG(ScalarBits)

	-- map to montgomery using birational equivalence
	local PointY, PointZ = EdwardsPoint[2], EdwardsPoint[3]
	local NewX = FieldPrime.Carry(FieldPrime.Add(PointY, PointZ))
	local NewZ = FieldPrime.Carry(FieldPrime.Sub(PointZ, PointY))

	return { NewX, NewZ }
end

-- compute two different scalar mults efficiently using prac algorithm
-- returns nil if any result would be the identity
local function Prac(BasePoint, PracRuleset)
	-- randomize to prevent side channel attacks
	local RandomFactor = FieldPrime.Decode(RandomBytes.Random(32))
	local RandomizedA = { FieldPrime.Mul(BasePoint[1], RandomFactor), FieldPrime.Mul(BasePoint[2], RandomFactor) }

	-- start with [8]P to clear small subgroups
	RandomizedA = Double(Double(Double(RandomizedA)))

	-- bail if we hit a small order point
	if FieldPrime.Eqz(RandomizedA[2]) then
		return
	end

	-- apply the gcd ladder first
	RandomizedA = Ladder(RandomizedA, PracRuleset[1])

	-- check if the scalars are equal (empty ruleset)
	local Rules = PracRuleset[2]
	if #Rules == 0 then
		return
	end

	-- handle the first rule specially since A-B=O breaks differential addition
	local CurrentB, CurrentC
	local FirstRule = Rules[#Rules]
	if FirstRule == 2 then
		-- (A, B, C) becomes (3A, A, 2A)
		local DoubledA = Double(RandomizedA)
		RandomizedA, CurrentB, CurrentC = DifferentialAdd(RandomizedA, DoubledA, RandomizedA), RandomizedA, DoubledA
	elseif FirstRule == 3 or FirstRule == 5 then
		-- (A, B, C) becomes (2A, A, A)
		RandomizedA, CurrentB, CurrentC = Double(RandomizedA), RandomizedA, RandomizedA
	elseif FirstRule == 6 then
		-- (A, B, C) becomes (6A, A, 5A)
		local DoubledA = Double(RandomizedA)
		local TripledA = DifferentialAdd(RandomizedA, DoubledA, RandomizedA)
		RandomizedA, CurrentB, CurrentC =
			Double(TripledA), RandomizedA, DifferentialAdd(RandomizedA, TripledA, DoubledA)
	elseif FirstRule == 7 then
		-- (A, B, C) becomes (5A, A, 4A)
		local DoubledA = Double(RandomizedA)
		local TripledA = DifferentialAdd(RandomizedA, DoubledA, RandomizedA)
		local QuadrupleA = Double(DoubledA)
		RandomizedA, CurrentB, CurrentC = DifferentialAdd(TripledA, QuadrupleA, RandomizedA), RandomizedA, QuadrupleA
	elseif FirstRule == 8 then
		-- (A, B, C) becomes (4A, A, 3A)
		local DoubledA = Double(RandomizedA)
		local TripledA = DifferentialAdd(RandomizedA, DoubledA, RandomizedA)
		RandomizedA, CurrentB, CurrentC = Double(DoubledA), RandomizedA, TripledA
	else
		-- (A, B, C) becomes (A, 2A, A)
		RandomizedA, CurrentB, CurrentC = RandomizedA, Double(RandomizedA), RandomizedA
	end

	-- process the remaining rules in reverse order
	for RuleIndex = #Rules - 1, 1, -1 do
		local CurrentRule = Rules[RuleIndex]
		if CurrentRule == 0 then
			-- (A, B, C) becomes (B, A, B - A)
			RandomizedA, CurrentB = CurrentB, RandomizedA
		elseif CurrentRule == 1 then
			-- (A, B, C) becomes (2A + B, A + 2B, A - B)
			local SumAB = DifferentialAdd(CurrentC, RandomizedA, CurrentB)
			RandomizedA, CurrentB =
				DifferentialAdd(CurrentB, SumAB, RandomizedA), DifferentialAdd(RandomizedA, SumAB, CurrentB)
		elseif CurrentRule == 2 then
			-- (A, B, C) becomes (2A + B, B, 2A)
			RandomizedA, CurrentC =
				DifferentialAdd(CurrentB, DifferentialAdd(CurrentC, RandomizedA, CurrentB), RandomizedA),
				Double(RandomizedA)
		elseif CurrentRule == 3 then
			-- (A, B, C) becomes (A + B, B, A)
			RandomizedA, CurrentC = DifferentialAdd(CurrentC, RandomizedA, CurrentB), RandomizedA
		elseif CurrentRule == 5 then
			-- (A, B, C) becomes (2A, B, 2A - B)
			RandomizedA, CurrentC = Double(RandomizedA), DifferentialAdd(CurrentB, RandomizedA, CurrentC)
		elseif CurrentRule == 6 then
			-- (A, B, C) becomes (3A + 3B, B, 3A + 2B)
			local SumAB = DifferentialAdd(CurrentC, RandomizedA, CurrentB)
			local DoubledSumAABB = Double(SumAB)
			RandomizedA, CurrentC =
				DifferentialAdd(SumAB, DoubledSumAABB, SumAB),
				DifferentialAdd(DifferentialAdd(RandomizedA, SumAB, CurrentB), DoubledSumAABB, RandomizedA)
		elseif CurrentRule == 7 then
			-- (A, B, C) becomes (3A + 2B, B, 3A + B)
			local SumAB = DifferentialAdd(CurrentC, RandomizedA, CurrentB)
			local DoubleAAB = DifferentialAdd(CurrentB, SumAB, RandomizedA)
			RandomizedA, CurrentC =
				DifferentialAdd(RandomizedA, DoubleAAB, SumAB), DifferentialAdd(SumAB, DoubleAAB, RandomizedA)
		elseif CurrentRule == 8 then
			-- (A, B, C) becomes (3A + B, B, 3A)
			local DoubledA = Double(RandomizedA)
			RandomizedA, CurrentC =
				DifferentialAdd(CurrentC, DoubledA, DifferentialAdd(CurrentC, RandomizedA, CurrentB)),
				DifferentialAdd(RandomizedA, DoubledA, RandomizedA)
		else
			-- (A, B, C) becomes (A, 2B, A - 2B)
			CurrentB, CurrentC = Double(CurrentB), DifferentialAdd(RandomizedA, CurrentC, CurrentB)
		end
	end

	return RandomizedA, CurrentB, CurrentC
end

return {
	G = { FieldPrime.Num(9), FieldPrime.Num(1) },
	DifferentialAdd = DifferentialAdd,
	Scale = Scale,
	Encode = Encode,
	Decode = Decode,
	DecodeEd = DecodeEd,
	Ladder8 = Ladder8,
	MulG = MulG,
	Prac = Prac,
}
