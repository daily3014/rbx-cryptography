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

local FieldQuadratic = require(script.Parent.FieldQuadratic)
local FieldPrime = require(script.Parent.FieldPrime)
local Curve25519 = require(script.Parent.Curve25519)
local SHA512 = require(script.Parent.SHA512)
local RandomBytes = require(script.Parent.Random)

-- mask an exchange secret key to protect against side channel attacks
local function Mask(SecretKey)
	local RandomMask = RandomBytes.Random(32)
	local ScalarX = FieldQuadratic.DecodeClamped(SecretKey)
	local ScalarR = FieldQuadratic.DecodeClamped(RandomMask)
	local MaskedScalar = FieldQuadratic.Sub(ScalarX, ScalarR)
	return FieldQuadratic.Encode(MaskedScalar) .. RandomMask
end

-- mask a signature secret key (for ed25519 compatibility)
local function MaskSignature(SignatureSecretKey)
	return Mask(SHA512.Digest(SignatureSecretKey):sub(1, 32))
end

-- refresh the masking on a masked key with new randomness
local function Remask(MaskedKey)
	local NewRandomMask = RandomBytes.Random(32)
	local MaskedScalar = FieldQuadratic.Decode(MaskedKey:sub(1, 32))
	local OldMask = FieldQuadratic.DecodeClamped(MaskedKey:sub(33))
	local NewMask = FieldQuadratic.DecodeClamped(NewRandomMask)
	local RemaskedScalar = FieldQuadratic.Add(MaskedScalar, FieldQuadratic.Sub(OldMask, NewMask))
	return FieldQuadratic.Encode(RemaskedScalar) .. NewRandomMask
end

-- get the ephemeral exchange secret key from a masked key
-- this is the second secret key in the "double key exchange"
-- the ephemeral key changes every time remask is called
local function EphemeralSecretKey(MaskedKey)
	return MaskedKey:sub(33)
end

-- perform key exchange on a specific point (internal helper)
local function ExchangeOnPoint(MaskedSecretKey, CurvePoint)
	local MaskedScalar = FieldQuadratic.Decode(MaskedSecretKey:sub(1, 32))
	local MaskScalar = FieldQuadratic.DecodeClamped(MaskedSecretKey:sub(33))
	local MaskPoint, MaskedPoint, DifferencePoint = Curve25519.Prac(
		CurvePoint,
		FieldQuadratic.MakeRuleset(FieldQuadratic.Eighth(MaskScalar), FieldQuadratic.Eighth(MaskedScalar))
	)

	-- bail early if point has small order or if mask equals masked scalar
	if not MaskPoint then
		local ZeroOutput = FieldPrime.Encode(FieldPrime.Num(0))
		return ZeroOutput, ZeroOutput
	end

	local FullScalarPoint = Curve25519.DifferentialAdd(DifferencePoint, MaskPoint, MaskedPoint)

	-- extract coordinates for scaling operations
	local PointX, PointZ = CurvePoint[1], CurvePoint[2]
	local FullPointX, FullPointZ = FullScalarPoint[1], FullScalarPoint[2]
	local MaskPointX, MaskPointZ = MaskPoint[1], MaskPoint[2]

	-- ensure all z coordinates are squares to make sqrt computation work
	PointX, PointZ = FieldPrime.Mul(PointX, PointZ), FieldPrime.Square(PointZ)
	FullPointX, FullPointZ = FieldPrime.Mul(FullPointX, FullPointZ), FieldPrime.Square(FullPointZ)
	MaskPointX, MaskPointZ = FieldPrime.Mul(MaskPointX, MaskPointZ), FieldPrime.Square(MaskPointZ)

	-- check if point is on the correct curve (not the twist)
	-- we split secret x into (x - r mod q, r) but this only works if point order is q
	-- need to check curve equation: y²z = x(x² + axz + z²) where z is square
	local PointXSquared = FieldPrime.Square(PointX)
	local PointZSquared = FieldPrime.Square(PointZ)
	local PointXZ = FieldPrime.Mul(PointX, PointZ)
	local CurveConstantTerm = FieldPrime.KMul(PointXZ, 486662)
	local RightHandSide = FieldPrime.Mul(
		PointX,
		FieldPrime.Add(PointXSquared, FieldPrime.Carry(FieldPrime.Add(CurveConstantTerm, PointZSquared)))
	)

	-- find square root of 1 / (rhs * fullPointZ * maskPointZ)
	-- none of these should be zero unless point has small order (already checked)
	-- since we squared both z coordinates, root exists iff rhs is square (curve check)
	local SquareRoot =
		FieldPrime.SqrtDiv(FieldPrime.Num(1), FieldPrime.Mul(FieldPrime.Mul(FullPointZ, MaskPointZ), RightHandSide))
	if not SquareRoot then
		local ZeroOutput = FieldPrime.Encode(FieldPrime.Num(0))
		return ZeroOutput, ZeroOutput
	end

	-- get inverses of both z coordinates
	local CombinedInverse = FieldPrime.Mul(FieldPrime.Square(SquareRoot), RightHandSide)
	local FullPointZInverse = FieldPrime.Mul(CombinedInverse, MaskPointZ)
	local MaskPointZInverse = FieldPrime.Mul(CombinedInverse, FullPointZ)

	-- finish scaling and encode the outputs
	return FieldPrime.Encode(FieldPrime.Mul(FullPointX, FullPointZInverse)),
		FieldPrime.Encode(FieldPrime.Mul(MaskPointX, MaskPointZInverse))
end

-- get the x25519 public key from a masked key
local function PublicKey(MaskedKey)
	return (ExchangeOnPoint(MaskedKey, Curve25519.G))
end

-- perform double key exchange (returns two shared secrets)
-- returns 0 if input public key has small order or isn't on base curve
-- this is different from standard x25519 which works even on the twist
-- may incorrectly return 0 with negligible chance if mask matches masked key
local function Exchange(MaskedSecretKey, TheirPublicKey)
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
