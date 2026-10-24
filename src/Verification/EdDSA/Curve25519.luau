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
local CtSwapBuffers = require("../../Utilities/Functions").CtSwapBuffers
local Curve25519 = {}

local COORD_SIZE = 104
local MONTGOMERY_POINT_SIZE = 2 * COORD_SIZE

local DiffX, DiffZ = buffer.create(COORD_SIZE), buffer.create(COORD_SIZE)
local X1, Z1 = buffer.create(COORD_SIZE), buffer.create(COORD_SIZE)
local X2, Z2 = buffer.create(COORD_SIZE), buffer.create(COORD_SIZE)
local SumA, SumSquaredAA = buffer.create(COORD_SIZE), buffer.create(COORD_SIZE)
local DiffB, DiffSquaredBB = buffer.create(COORD_SIZE), buffer.create(COORD_SIZE)
local DifferenceE, DiffD = buffer.create(COORD_SIZE), buffer.create(COORD_SIZE)
local CrossDA, SumC, CrossCB = buffer.create(COORD_SIZE), buffer.create(COORD_SIZE), buffer.create(COORD_SIZE)
local Temp = buffer.create(COORD_SIZE)
local ONE = FieldPrime.Num(1)

local Add, Sub, Mul, Square, KMul = FieldPrime.Add, FieldPrime.Sub, FieldPrime.Mul, FieldPrime.Square, FieldPrime.KMul

local function LadderStep()
	Add(X1, Z1, SumA)
	Square(SumA, SumSquaredAA)
	Sub(X1, Z1, DiffB)
	Square(DiffB, DiffSquaredBB)
	Sub(SumSquaredAA, DiffSquaredBB, DifferenceE)
	Sub(X2, Z2, DiffD)
	Mul(DiffD, SumA, CrossDA)
	Add(X2, Z2, SumC)
	Mul(SumC, DiffB, CrossCB)

	Square(Add(CrossDA, CrossCB, Temp), Temp)
	Mul(DiffZ, Temp, X2)
	Square(Sub(CrossDA, CrossCB, Temp), Temp)
	Mul(DiffX, Temp, Z2)

	Mul(SumSquaredAA, DiffSquaredBB, X1)
	Add(DiffSquaredBB, KMul(DifferenceE, 121666, Temp), Temp)
	Mul(DifferenceE, Temp, Z1)
end

local function SwapPoints(ConditionBit: number)
	CtSwapBuffers(ConditionBit, X1, X2)
	CtSwapBuffers(ConditionBit, Z1, Z2)
end

function Curve25519.Ladder(DifferencePoint: buffer, ScalarBits: buffer, ScalarBitCount: number): buffer
	buffer.copy(DiffX, 0, DifferencePoint, 0, COORD_SIZE)
	buffer.copy(DiffZ, 0, DifferencePoint, COORD_SIZE, COORD_SIZE)

	buffer.copy(X1, 0, ONE, 0, COORD_SIZE)
	buffer.fill(Z1, 0, 0, COORD_SIZE)
	buffer.copy(X2, 0, DiffX, 0, COORD_SIZE)
	buffer.copy(Z2, 0, DiffZ, 0, COORD_SIZE)

	local PrevBit = 0
	local LadderStep, SwapPoints = LadderStep, SwapPoints

	for BitIndex = ScalarBitCount, 1, -1 do
		local BitValue = buffer.readu8(ScalarBits, BitIndex - 1)
		SwapPoints(bit32.bxor(PrevBit, BitValue))
		PrevBit = BitValue

		LadderStep()
	end

	SwapPoints(PrevBit)

	local Result = buffer.create(MONTGOMERY_POINT_SIZE)
	buffer.copy(Result, 0, X1, 0, COORD_SIZE)
	buffer.copy(Result, COORD_SIZE, Z1, 0, COORD_SIZE)

	return Result
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
