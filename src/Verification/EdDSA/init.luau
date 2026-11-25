--[=[
	Cryptography library: EdDSA (Ed25519)

	Example usage:
		local SecretKey = CSPRNG.RandomBytes(32)
		local PublicKey = EdDSA.PublicKey(SecretKey)

		local Message = buffer.fromstring("Hello World")
		local Signature = EdDSA.Sign(Message, SecretKey, PublicKey)

		local IsValid = EdDSA.Verify(Message, PublicKey, Signature)
--]=]

--!strict
--!optimize 2
--!native

local FieldQuadratic = require("@self/FieldQuadratic")
local FieldPrime = require("@self/FieldPrime")
local SHA512Module = require("../Hashing/SHA2/SHA512")
local SHA512 = SHA512Module.SHA512_Internal
local Edwards25519 = require("@self/Edwards25519")
local ScalarSplit = require("@self/ScalarSplit")
local X25519 = require("@self/X25519")
local Concatenate = require("../Utilities/Functions").Concatenate

local ED25519_SECRET_KEY_SIZE = 32
local ED25519_PUBLIC_KEY_SIZE = 32
local ED25519_SIGNATURE_SIZE = 64

local SIGN_KEYS = buffer.create(65)
local SIGN_SCALAR = buffer.create(96)
local SIGN_PREFIX = buffer.create(32)

type VerifyKey = {
	PublicKey: buffer,
	Table: buffer,
}

local VERIFY_KEY: VerifyKey? = nil

local SPLIT_HALVES = buffer.create(144)
local SCALE_REGULAR = buffer.create(96)

local SMALL_ORDER = buffer.create(160) do
	local Words = {
		0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x8F95E826, 0xB027B2C2, 0x89F4C345, 0xF098EFF2, 0x05ACDFD5, 0x3933C6D3, 0x880238B1, 0x05FC536D,
		0x706A17C7, 0x4FD84D3D, 0x760B3CBA, 0x0F67100D, 0xFA53202A, 0xC6CC392C, 0x77FDC74E, 0x7A03AC92,
		0xFFFFFFEC, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF,
	}

	for Index = 1, 40 do
		buffer.writeu32(SMALL_ORDER, (Index - 1) * 4, Words[Index])
	end
end

local function Differs(BytesA: buffer, OffsetA: number, BytesB: buffer, OffsetB: number): number
	return bit32.bor(
		bit32.bxor(buffer.readu32(BytesA, OffsetA), buffer.readu32(BytesB, OffsetB)),
		bit32.bxor(buffer.readu32(BytesA, OffsetA + 4), buffer.readu32(BytesB, OffsetB + 4)),
		bit32.bxor(buffer.readu32(BytesA, OffsetA + 8), buffer.readu32(BytesB, OffsetB + 8)),
		bit32.bxor(buffer.readu32(BytesA, OffsetA + 12), buffer.readu32(BytesB, OffsetB + 12)),
		bit32.bxor(buffer.readu32(BytesA, OffsetA + 16), buffer.readu32(BytesB, OffsetB + 16)),
		bit32.bxor(buffer.readu32(BytesA, OffsetA + 20), buffer.readu32(BytesB, OffsetB + 20)),
		bit32.bxor(buffer.readu32(BytesA, OffsetA + 24), buffer.readu32(BytesB, OffsetB + 24)),
		bit32.bxor(buffer.readu32(BytesA, OffsetA + 28), buffer.readu32(BytesB, OffsetB + 28))
	)
end

local function IsSmallOrder(Encoded: buffer): boolean
	local Table = SMALL_ORDER
	local Word0, Word1, Word2, Word3 = buffer.readu32(Encoded, 0), buffer.readu32(Encoded, 4), buffer.readu32(Encoded, 8), buffer.readu32(Encoded, 12)
	local Word4, Word5, Word6, Word7 = buffer.readu32(Encoded, 16), buffer.readu32(Encoded, 20), buffer.readu32(Encoded, 24), bit32.band(buffer.readu32(Encoded, 28), 0x7FFFFFFF)

	for Offset = 0, 128, 32 do
		local Difference = bit32.bor(
			bit32.bxor(Word7, buffer.readu32(Table, Offset + 28)),
			bit32.bxor(Word0, buffer.readu32(Table, Offset)),
			bit32.bxor(Word1, buffer.readu32(Table, Offset + 4)),
			bit32.bxor(Word2, buffer.readu32(Table, Offset + 8)),
			bit32.bxor(Word3, buffer.readu32(Table, Offset + 12)),
			bit32.bxor(Word4, buffer.readu32(Table, Offset + 16)),
			bit32.bxor(Word5, buffer.readu32(Table, Offset + 20)),
			bit32.bxor(Word6, buffer.readu32(Table, Offset + 24))
		)

		if Difference == 0 then
			return true
		end
	end

	return false
end

local EDDSA = {
	X25519 = X25519
}

function EDDSA.PublicKey(SecretKey: buffer): buffer
	if SecretKey == nil then
		error("SecretKey cannot be nil", 2)
	end

	if typeof(SecretKey) ~= "buffer" then
		error(`SecretKey must be a buffer, got {typeof(SecretKey)}`, 2)
	end

	local SecretKeyLength = buffer.len(SecretKey)
	if SecretKeyLength ~= ED25519_SECRET_KEY_SIZE then
		error(`SecretKey must be exactly {ED25519_SECRET_KEY_SIZE} bytes long, got {SecretKeyLength} bytes`, 2)
	end

	local Hash = SHA512(SecretKey)
	local FirstHalf = buffer.create(32)
	buffer.copy(FirstHalf, 0, Hash, 0, 32)

	local ScalarX = FieldQuadratic.DecodeClamped(FirstHalf)
	local ScalarBits, BitCount = FieldQuadratic.Bits(ScalarX)

	return Edwards25519.Encode(Edwards25519.MulG(ScalarBits, BitCount))
end

function EDDSA.Sign(Message: buffer, SecretKey: buffer, PublicKey: buffer): buffer
	if SecretKey == nil then
		error("SecretKey cannot be nil", 2)
	end

	if typeof(SecretKey) ~= "buffer" then
		error(`SecretKey must be a buffer, got {typeof(SecretKey)}`, 2)
	end

	local SecretKeyLength = buffer.len(SecretKey)
	if SecretKeyLength ~= ED25519_SECRET_KEY_SIZE then
		error(`SecretKey must be exactly {ED25519_SECRET_KEY_SIZE} bytes long, got {SecretKeyLength} bytes`, 2)
	end

	if PublicKey == nil then
		error("PublicKey cannot be nil", 2)
	end

	if typeof(PublicKey) ~= "buffer" then
		error(`PublicKey must be a buffer, got {typeof(PublicKey)}`, 2)
	end

	local PublicKeyLength = buffer.len(PublicKey)
	if PublicKeyLength ~= ED25519_PUBLIC_KEY_SIZE then
		error(`PublicKey must be exactly {ED25519_PUBLIC_KEY_SIZE} bytes long, got {PublicKeyLength} bytes`, 2)
	end

	if Message == nil then
		error("Message cannot be nil", 2)
	end

	if typeof(Message) ~= "buffer" then
		error(`Message must be a buffer, got {typeof(Message)}`, 2)
	end

	local Keys = SIGN_KEYS
	local ScalarX = SIGN_SCALAR
	local Prefix = SIGN_PREFIX
	if Differs(SecretKey, 0, Keys, 0) ~= 0 or buffer.readu8(Keys, 64) == 0 then
		local Hash = SHA512(SecretKey)
		local FirstHalf = buffer.create(32)
		buffer.copy(FirstHalf, 0, Hash, 0, 32)
		buffer.copy(ScalarX, 0, FieldQuadratic.DecodeClamped(FirstHalf), 0, 96)
		buffer.copy(Prefix, 0, Hash, 32, 32)

		local ScalarBits, BitCount = FieldQuadratic.Bits(ScalarX)
		buffer.copy(Keys, 32, Edwards25519.Encode(Edwards25519.MulG(ScalarBits, BitCount)), 0, 32)
		buffer.copy(Keys, 0, SecretKey, 0, 32)
		buffer.writeu8(Keys, 64, 1)
	end

	if Differs(PublicKey, 0, Keys, 32) ~= 0 then
		error("PublicKey is not the public key of SecretKey", 2)
	end

	local NonceSource = Concatenate(Prefix, Message)
	local NonceHash = SHA512(NonceSource)
	local NonceK = FieldQuadratic.DecodeWide(NonceHash)

	local NonceBits, NonceBitCount = FieldQuadratic.Bits(NonceK)
	local CommitmentR = Edwards25519.MulG(NonceBits, NonceBitCount)
	local CommitmentString = Edwards25519.Encode(CommitmentR)

	local ChallengeInput = Concatenate(CommitmentString, PublicKey, Message)
	local ChallengeHash = SHA512(ChallengeInput)
	local ChallengeE = FieldQuadratic.DecodeWide(ChallengeHash)

	local ResponseS = FieldQuadratic.Add(NonceK, FieldQuadratic.Mul(ScalarX, ChallengeE))
	local ResponseString = FieldQuadratic.Encode(ResponseS)

	return Concatenate(CommitmentString, ResponseString)
end

function EDDSA.Verify(Message: buffer, PublicKey: buffer, Signature: buffer): boolean
	if typeof(Message) ~= "buffer" or typeof(PublicKey) ~= "buffer" or typeof(Signature) ~= "buffer" then
		return false
	end

	if buffer.len(PublicKey) ~= ED25519_PUBLIC_KEY_SIZE or buffer.len(Signature) ~= ED25519_SIGNATURE_SIZE then
		return false
	end

	local LastByte = buffer.readu8(Signature, 63)
	if bit32.btest(LastByte, 0xE0) then
		return false
	end

	local CommitmentBytes = buffer.create(32)
	buffer.copy(CommitmentBytes, 0, Signature, 0, 32)
	local ResponseBytes = buffer.create(32)
	buffer.copy(ResponseBytes, 0, Signature, 32, 32)

	if not FieldQuadratic.IsValidScalar(ResponseBytes) then
		return false
	end

	local Known = VERIFY_KEY
	if not (Known and Differs(PublicKey, 0, Known.PublicKey, 0) == 0) then
		if IsSmallOrder(PublicKey) then
			return false
		end

		local Decoded = Edwards25519.Decode(PublicKey)
		if not Decoded then
			return false
		end

		local Copy = buffer.create(32)
		buffer.copy(Copy, 0, PublicKey, 0, 32)
		Known = {
			PublicKey = Copy,
			Table = Edwards25519.MulTable(Decoded),
		}
		VERIFY_KEY = Known
	end

	local CommitmentPoint = Edwards25519.Decode(CommitmentBytes)
	if not CommitmentPoint then
		return false
	end

	local ChallengeInput = Concatenate(CommitmentBytes, PublicKey, Message)
	local ChallengeHash = SHA512(ChallengeInput)
	local ChallengeScalar = FieldQuadratic.DecodeWide(ChallengeHash)

	local Halves = SPLIT_HALVES
	local Negative = ScalarSplit.Split(FieldQuadratic.Regular(ChallengeScalar), Halves)

	local ScaleRegular = SCALE_REGULAR
	buffer.copy(ScaleRegular, 0, Halves, 48, 48)
	local ResponseScalar = FieldQuadratic.Decode(ResponseBytes)
	local Scaled = FieldQuadratic.Mul(FieldQuadratic.Montgomery(ScaleRegular), ResponseScalar)
	local ScaledBits, ScaledBitCount = FieldQuadratic.Bits(Scaled)
	local SB = Edwards25519.MulG(ScaledBits, ScaledBitCount)

	local CommitmentTable = Edwards25519.WindowedNAFTable(CommitmentPoint, 4)
	local Joint = Edwards25519.MulDoubleWithTables(CommitmentTable, 4, 120, (Known :: VerifyKey).Table, 5, 96, Halves, 128, Negative)

	local SBNiels = Edwards25519.Niels(SB)
	local Difference = Edwards25519.Sub(Joint, SBNiels)

	Difference = Edwards25519.Double(Difference)
	Difference = Edwards25519.Double(Difference)
	Difference = Edwards25519.Double(Difference)

	local DifferenceX = buffer.create(104)
	local DifferenceT = buffer.create(104)
	buffer.copy(DifferenceX, 0, Difference, 0 * 104, 104)
	buffer.copy(DifferenceT, 0, Difference, 3 * 104, 104)

	local XIsZero = FieldPrime.Eqz(DifferenceX)
	local TIsZero = FieldPrime.Eqz(DifferenceT)

	return XIsZero and TIsZero
end

function EDDSA.ClearCaches()
	buffer.fill(SIGN_KEYS, 0, 0)
	buffer.fill(SIGN_SCALAR, 0, 0)
	buffer.fill(SIGN_PREFIX, 0, 0)
	buffer.fill(SPLIT_HALVES, 0, 0)
	buffer.fill(SCALE_REGULAR, 0, 0)
	VERIFY_KEY = nil

	X25519.ClearCaches()
	SHA512Module.ClearCaches()
end

return EDDSA