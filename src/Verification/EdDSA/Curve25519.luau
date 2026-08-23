--[=[
	Cryptography library: Curve25519 Montgomery

	Example usage:
		-- Point multiplication
		local BasePoint = Curve25519.G
		local Result = Curve25519.Ladder(BasePoint, ScalarBits, BitCount)

		-- Decode a public key
		local DecodedPoint = Curve25519.Decode(EncodedBytes)
--]=]

--!strict
--!optimize 2
--!native

local FieldPrime = require("./FieldPrime")
local Curve25519 = {}

local COORD_SIZE = 80
local MONTGOMERY_POINT_SIZE = 2 * COORD_SIZE

local function GetMontgomeryCoord(Point: buffer, Index: number): buffer
	local Coord = buffer.create(COORD_SIZE)
	buffer.copy(Coord, 0, Point, Index * COORD_SIZE, COORD_SIZE)

	return Coord
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

local function SwapPoint(ConditionBit: number, PointA: buffer, PointB: buffer)
	local LowMask = integer.create(bit32.arshift(bit32.bor(ConditionBit, -ConditionBit), 31)) :: integer
	local Mask = integer.bor(LowMask, integer.lshift(LowMask, 32i))

	for Offset = 0, MONTGOMERY_POINT_SIZE - 8, 8 do
		local A = buffer.readinteger(PointA, Offset)
		local B = buffer.readinteger(PointB, Offset)
		local Delta = integer.band(Mask, integer.bxor(A, B))
		buffer.writeinteger(PointA, Offset, integer.bxor(A, Delta))
		buffer.writeinteger(PointB, Offset, integer.bxor(B, Delta))
	end
end

function Curve25519.Ladder(DifferencePoint: buffer, ScalarBits: buffer, ScalarBitCount: number): buffer
	local CurrentP = buffer.create(MONTGOMERY_POINT_SIZE)
	buffer.copy(CurrentP, 0 * COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)
	buffer.copy(CurrentP, 1 * COORD_SIZE, FieldPrime.Num(0), 0, COORD_SIZE)

	local CurrentQ = buffer.create(MONTGOMERY_POINT_SIZE)
	buffer.copy(CurrentQ, 0, DifferencePoint, 0, MONTGOMERY_POINT_SIZE)

	local PrevBit = 0
	local LadderStep = LadderStep

	for BitIndex = ScalarBitCount, 1, -1 do
		local BitValue = buffer.readu8(ScalarBits, BitIndex - 1)
		local Swap = bit32.bxor(PrevBit, BitValue)
		SwapPoint(Swap, CurrentP, CurrentQ)
		PrevBit = BitValue

		CurrentP, CurrentQ = LadderStep(DifferencePoint, CurrentP, CurrentQ)
	end

	SwapPoint(PrevBit, CurrentP, CurrentQ)
	return CurrentP
end

function Curve25519.Decode(EncodedBuffer: buffer): buffer
	local Point = buffer.create(MONTGOMERY_POINT_SIZE)
	buffer.copy(Point, 0 * COORD_SIZE, FieldPrime.Decode(EncodedBuffer), 0, COORD_SIZE)
	buffer.copy(Point, 1 * COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)

	return Point
end

local Point = buffer.create(MONTGOMERY_POINT_SIZE)
buffer.copy(Point, 0 * COORD_SIZE, FieldPrime.Num(9), 0, COORD_SIZE)
buffer.copy(Point, 1 * COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)
Curve25519.G = Point

return Curve25519