--[=[
	Cryptography library: Masked X25519 (Double Key Exchange)

	Return type: varies by function
	Example usage:
		local MaskedX25519 = require("MaskedX25519")

		--------Usage Case 1: Create masked key--------
		local SecretKey = RandomBytes.Generate(32)
		local MaskedKey = MaskedX25519.Mask(SecretKey)
		local PublicKey = MaskedX25519.PublicKey(MaskedKey)

		--------Usage Case 2: Double key exchange--------
		local StaticSecret, EphemeralSecret = MaskedX25519.Exchange(MaskedKey, TheirPublicKey)

		--------Usage Case 3: Refresh masking--------
		local RemaskedKey = MaskedX25519.Remask(MaskedKey)
--]=]

--!native
--!optimize 2

local FieldQuadratic = require("./FieldQuadratic")
local FieldPrime = require("./FieldPrime")
local Curve25519 = require("./Curve25519")
local SHA512 = require("./SHA512")
local RandomBytes = require("./Random")

local COORD_SIZE = 104

local function GetMontgomeryCoord(Point: buffer, Index: number): buffer
	local Coord = buffer.create(COORD_SIZE)
	buffer.copy(Coord, 0, Point, Index * COORD_SIZE, COORD_SIZE)
	return Coord
end

local function Mask(SecretKey: buffer): buffer
	local RandomMask = RandomBytes.Random(32)
	local ScalarX = FieldQuadratic.DecodeClamped(SecretKey)
	local ScalarR = FieldQuadratic.DecodeClamped(RandomMask)
	local MaskedScalar = FieldQuadratic.Sub(ScalarX, ScalarR)
	local EncodedMaskedScalar = FieldQuadratic.Encode(MaskedScalar)

	local MaskedKey = buffer.create(64)
	buffer.copy(MaskedKey, 0, EncodedMaskedScalar, 0, 32)
	buffer.copy(MaskedKey, 32, RandomMask, 0, 32)

	return MaskedKey
end

local function MaskSignature(SignatureSecretKey: buffer): buffer
	local HashResult = SHA512(SignatureSecretKey)
	local FirstHalf = buffer.create(32)
	buffer.copy(FirstHalf, 0, HashResult, 0, 32)
	return Mask(FirstHalf)
end

local function Remask(MaskedKey: buffer): buffer
	local NewRandomMask = RandomBytes.Random(32)

	local MaskedScalarBytes = buffer.create(32)
	buffer.copy(MaskedScalarBytes, 0, MaskedKey, 0, 32)
	local MaskedScalar = FieldQuadratic.Decode(MaskedScalarBytes)

	local OldMaskBytes = buffer.create(32)
	buffer.copy(OldMaskBytes, 0, MaskedKey, 32, 32)
	local OldMask = FieldQuadratic.DecodeClamped(OldMaskBytes)

	local NewMask = FieldQuadratic.DecodeClamped(NewRandomMask)
	local RemaskedScalar = FieldQuadratic.Add(MaskedScalar, FieldQuadratic.Sub(OldMask, NewMask))
	local EncodedRemaskedScalar = FieldQuadratic.Encode(RemaskedScalar)

	local RemaskedKey = buffer.create(64)
	buffer.copy(RemaskedKey, 0, EncodedRemaskedScalar, 0, 32)
	buffer.copy(RemaskedKey, 32, NewRandomMask, 0, 32)

	return RemaskedKey
end

local function EphemeralSecretKey(MaskedKey: buffer): buffer
	local EphemeralKey = buffer.create(32)
	buffer.copy(EphemeralKey, 0, MaskedKey, 32, 32)
	return EphemeralKey
end

local function ExchangeOnPoint(MaskedSecretKey: buffer, CurvePoint: buffer): (buffer, buffer)
	local MaskedScalarBytes = buffer.create(32)
	buffer.copy(MaskedScalarBytes, 0, MaskedSecretKey, 0, 32)
	local MaskedScalar = FieldQuadratic.Decode(MaskedScalarBytes)

	local MaskBytes = buffer.create(32)
	buffer.copy(MaskBytes, 0, MaskedSecretKey, 32, 32)
	local MaskScalar = FieldQuadratic.DecodeClamped(MaskBytes)

	local MaskPoint, MaskedPoint, DifferencePoint = Curve25519.Prac(CurvePoint, {FieldQuadratic.MakeRuleset(FieldQuadratic.Eighth(MaskScalar), FieldQuadratic.Eighth(MaskedScalar))})
	if not MaskPoint then
		local ZeroOutput = FieldPrime.Encode(FieldPrime.Num(0))
		return ZeroOutput, ZeroOutput
	end

	local FullScalarPoint = Curve25519.DifferentialAdd(DifferencePoint, MaskPoint, MaskedPoint)

	local PointX = GetMontgomeryCoord(CurvePoint, 0)
	local PointZ = GetMontgomeryCoord(CurvePoint, 1)
	local FullPointX = GetMontgomeryCoord(FullScalarPoint, 0)
	local FullPointZ = GetMontgomeryCoord(FullScalarPoint, 1)
	local MaskPointX = GetMontgomeryCoord(MaskPoint, 0)
	local MaskPointZ = GetMontgomeryCoord(MaskPoint, 1)

	PointX, PointZ = FieldPrime.Mul(PointX, PointZ), FieldPrime.Square(PointZ)
	FullPointX, FullPointZ = FieldPrime.Mul(FullPointX, FullPointZ), FieldPrime.Square(FullPointZ)
	MaskPointX, MaskPointZ = FieldPrime.Mul(MaskPointX, MaskPointZ), FieldPrime.Square(MaskPointZ)

	local PointXSquared = FieldPrime.Square(PointX)
	local PointZSquared = FieldPrime.Square(PointZ)
	local PointXZ = FieldPrime.Mul(PointX, PointZ)
	local CurveConstantTerm = FieldPrime.KMul(PointXZ, 486662)
	local RightHandSide = FieldPrime.Mul(PointX, FieldPrime.Add(PointXSquared, FieldPrime.Carry(FieldPrime.Add(CurveConstantTerm, PointZSquared))))

	local SquareRoot = FieldPrime.SqrtDiv(FieldPrime.Num(1), FieldPrime.Mul(FieldPrime.Mul(FullPointZ, MaskPointZ), RightHandSide))
	if not SquareRoot then
		local ZeroOutput = FieldPrime.Encode(FieldPrime.Num(0))
		return ZeroOutput, ZeroOutput
	end

	local CombinedInverse = FieldPrime.Mul(FieldPrime.Square(SquareRoot), RightHandSide)
	local FullPointZInverse = FieldPrime.Mul(CombinedInverse, MaskPointZ)
	local MaskPointZInverse = FieldPrime.Mul(CombinedInverse, FullPointZ)

	return FieldPrime.Encode(FieldPrime.Mul(FullPointX, FullPointZInverse)), FieldPrime.Encode(FieldPrime.Mul(MaskPointX, MaskPointZInverse))
end

local function PublicKey(MaskedKey: buffer): buffer
	return (ExchangeOnPoint(MaskedKey, Curve25519.G))
end

local function Exchange(MaskedSecretKey: buffer, TheirPublicKey: buffer): (buffer, buffer)
	return ExchangeOnPoint(MaskedSecretKey, Curve25519.Decode(TheirPublicKey))
end

return {
	Mask = Mask,
	MaskSignature = MaskSignature,
	Remask = Remask,
	PublicKey = PublicKey,
	EphemeralSecretKey = EphemeralSecretKey,
	Exchange = Exchange,
}