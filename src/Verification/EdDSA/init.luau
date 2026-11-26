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

local FieldQuadratic = require("@self/FieldQuadratic")
local FieldPrime = require("@self/FieldPrime")
local SHA512Module = require("../Hashing/SHA2/SHA512")
local SHA512 = SHA512Module.SHA512_Internal
local Edwards25519 = require("@self/Edwards25519")
local ScalarSplit = require("@self/ScalarSplit")
local Lazy = require("../Lazy")

local ED25519_SECRET_KEY_SIZE = 32
local ED25519_PUBLIC_KEY_SIZE = 32
local ED25519_SIGNATURE_SIZE = 64
local POINT_SIZE = 416

local SIGN_KEYS: buffer = buffer.create(65)
local SIGN_SCALAR: buffer = buffer.create(96)
local SIGN_PREFIX: buffer = buffer.create(32)

type VerifyKey = {
	PublicKey: buffer,
	Table: buffer,
}

type EdDSA = {
	X25519: typeof(require("@self/X25519")),
	PublicKey: (SecretKey: buffer) -> buffer,
	Sign: (Message: buffer, SecretKey: buffer, PublicKey: buffer) -> buffer,
	Verify: (Message: buffer, PublicKey: buffer, Signature: buffer) -> boolean,
	ClearCaches: () -> (),
}

local VERIFY_KEY: VerifyKey? = nil
local EDDSA: EdDSA

local SPLIT_HALVES: buffer = buffer.create(144)
local SCALE_REGULAR: buffer = buffer.create(96)
local SCALAR_BYTES: buffer = buffer.create(32)
local SCALAR_A: buffer = buffer.create(96)
local SCALAR_B: buffer = buffer.create(96)
local POINT_A: buffer = buffer.create(POINT_SIZE)
local POINT_B: buffer = buffer.create(POINT_SIZE)
local POINT_NIELS: buffer = buffer.create(POINT_SIZE)
local VERIFY_R_TABLE: buffer = buffer.create(8 * POINT_SIZE)

local SMALL_ORDER: buffer = buffer.create(160)
do
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

local function Hash2(A: buffer, AOff: number, ALen: number, B: buffer, BLen: number): buffer
	local Buf = buffer.create(ALen + BLen)
	buffer.copy(Buf, 0, A, AOff, ALen)
	if BLen > 0 then
		buffer.copy(Buf, ALen, B, 0, BLen)
	end
	return SHA512(Buf)
end

local function Hash3(A: buffer, AOff: number, B: buffer, C: buffer, CLen: number): buffer
	local Total = 64 + CLen
	local Buf = buffer.create(Total)
	buffer.copy(Buf, 0, A, AOff, 32)
	buffer.copy(Buf, 32, B, 0, 32)
	if CLen > 0 then
		buffer.copy(Buf, 64, C, 0, CLen)
	end
	return SHA512(Buf)
end

@native
local function Differs(BytesA: buffer, OffsetA: number, BytesB: buffer, OffsetB: number): number
	return bit32.bor(
		bit32.bor(
			bit32.bxor(buffer.readu32(BytesA, OffsetA), buffer.readu32(BytesB, OffsetB)),
			bit32.bxor(buffer.readu32(BytesA, OffsetA + 4), buffer.readu32(BytesB, OffsetB + 4)),
			bit32.bxor(buffer.readu32(BytesA, OffsetA + 8), buffer.readu32(BytesB, OffsetB + 8)),
			bit32.bxor(buffer.readu32(BytesA, OffsetA + 12), buffer.readu32(BytesB, OffsetB + 12))
		),
		bit32.bor(
			bit32.bxor(buffer.readu32(BytesA, OffsetA + 16), buffer.readu32(BytesB, OffsetB + 16)),
			bit32.bxor(buffer.readu32(BytesA, OffsetA + 20), buffer.readu32(BytesB, OffsetB + 20)),
			bit32.bxor(buffer.readu32(BytesA, OffsetA + 24), buffer.readu32(BytesB, OffsetB + 24)),
			bit32.bxor(buffer.readu32(BytesA, OffsetA + 28), buffer.readu32(BytesB, OffsetB + 28))
		)
	)
end

@native
local function IsSmallOrder(Encoded: buffer): boolean
	local Table = SMALL_ORDER
	local Word0, Word1, Word2, Word3 = buffer.readu32(Encoded, 0), buffer.readu32(Encoded, 4), buffer.readu32(Encoded, 8), buffer.readu32(Encoded, 12)
	local Word4, Word5, Word6, Word7 = buffer.readu32(Encoded, 16), buffer.readu32(Encoded, 20), buffer.readu32(Encoded, 24), bit32.band(buffer.readu32(Encoded, 28), 0x7FFFFFFF)

	for Offset = 0, 128, 32 do
		local Difference = bit32.bor(
			bit32.bor(
				bit32.bxor(Word7, buffer.readu32(Table, Offset + 28)),
				bit32.bxor(Word0, buffer.readu32(Table, Offset)),
				bit32.bxor(Word1, buffer.readu32(Table, Offset + 4)),
				bit32.bxor(Word2, buffer.readu32(Table, Offset + 8))
			),
			bit32.bor(
				bit32.bxor(Word3, buffer.readu32(Table, Offset + 12)),
				bit32.bxor(Word4, buffer.readu32(Table, Offset + 16)),
				bit32.bxor(Word5, buffer.readu32(Table, Offset + 20)),
				bit32.bxor(Word6, buffer.readu32(Table, Offset + 24))
			)
		)
		if Difference == 0 then
			return true
		end
	end

	return false
end

local function PublicKey(SecretKey: buffer): buffer
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
	buffer.copy(SCALAR_BYTES, 0, Hash, 0, 32)
	buffer.writeu8(SCALAR_BYTES, 0, bit32.band(buffer.readu8(SCALAR_BYTES, 0), 0xF8))
	buffer.writeu8(SCALAR_BYTES, 31, bit32.bor(bit32.band(buffer.readu8(SCALAR_BYTES, 31), 0x7F), 0x40))

	Edwards25519.MulGBytes(SCALAR_BYTES, POINT_A, false)
	local Out = buffer.create(32)
	Edwards25519.EncodeInto(POINT_A, Out)
	return Out
end

local function Sign(Message: buffer, SecretKey: buffer, PublicKey: buffer): buffer
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
		buffer.copy(SCALAR_BYTES, 0, Hash, 0, 32)
		buffer.writeu8(SCALAR_BYTES, 0, bit32.band(buffer.readu8(SCALAR_BYTES, 0), 0xF8))
		buffer.writeu8(SCALAR_BYTES, 31, bit32.bor(bit32.band(buffer.readu8(SCALAR_BYTES, 31), 0x7F), 0x40))
		FieldQuadratic.Decode(SCALAR_BYTES, ScalarX)
		buffer.copy(Prefix, 0, Hash, 32, 32)

		Edwards25519.MulGBytes(SCALAR_BYTES, POINT_A, false)
		Edwards25519.EncodeInto(POINT_A, SCALAR_BYTES)
		buffer.copy(Keys, 32, SCALAR_BYTES, 0, 32)
		buffer.copy(Keys, 0, SecretKey, 0, 32)
		buffer.writeu8(Keys, 64, 1)
	end

	if Differs(PublicKey, 0, Keys, 32) ~= 0 then
		error("PublicKey is not the public key of SecretKey", 2)
	end

	local MsgLen = buffer.len(Message)
	local NonceHash = Hash2(Prefix, 0, 32, Message, MsgLen)
	FieldQuadratic.DecodeWide(NonceHash, SCALAR_A)
	FieldQuadratic.EncodeInto(SCALAR_A, SCALAR_BYTES)

	local Signature = buffer.create(ED25519_SIGNATURE_SIZE)
	Edwards25519.MulGBytes(SCALAR_BYTES, POINT_A, false)
	Edwards25519.EncodeInto(POINT_A, SCALAR_BYTES)
	buffer.copy(Signature, 0, SCALAR_BYTES, 0, 32)

	local ChallengeHash = Hash3(SCALAR_BYTES, 0, PublicKey, Message, MsgLen)
	FieldQuadratic.DecodeWide(ChallengeHash, SCALAR_B)
	FieldQuadratic.Mul(ScalarX, SCALAR_B, SCALAR_B)
	FieldQuadratic.Add(SCALAR_A, SCALAR_B, SCALAR_A)
	FieldQuadratic.EncodeInto(SCALAR_A, SCALAR_BYTES)
	buffer.copy(Signature, 32, SCALAR_BYTES, 0, 32)

	return Signature
end

local function Verify(Message: buffer, PublicKey: buffer, Signature: buffer): boolean
	if typeof(Message) ~= "buffer" or typeof(PublicKey) ~= "buffer" or typeof(Signature) ~= "buffer" then
		return false
	end

	if buffer.len(PublicKey) ~= ED25519_PUBLIC_KEY_SIZE or buffer.len(Signature) ~= ED25519_SIGNATURE_SIZE then
		return false
	end

	if bit32.btest(buffer.readu8(Signature, 63), 0xE0) then
		return false
	end

	buffer.copy(SCALAR_BYTES, 0, Signature, 32, 32)
	if not FieldQuadratic.IsValidScalar(SCALAR_BYTES) then
		return false
	end

	local Known = VERIFY_KEY
	if not (Known and Differs(PublicKey, 0, Known.PublicKey, 0) == 0) then
		if IsSmallOrder(PublicKey) then
			return false
		end

		if not Edwards25519.DecodeInto(PublicKey, POINT_A) then
			return false
		end

		local Copy: buffer
		local Table: buffer
		if Known then
			Copy = Known.PublicKey
			Table = Known.Table
		else
			Copy = buffer.create(32)
			Table = buffer.create(16 * POINT_SIZE)
			Known = {
				PublicKey = Copy,
				Table = Table,
			}
			VERIFY_KEY = Known
		end
		buffer.copy(Copy, 0, PublicKey, 0, 32)
		Edwards25519.WindowedNAFTable(POINT_A, 5, Table)
	end

	if not Edwards25519.DecodeInto(Signature, POINT_A) then
		return false
	end

	local ChallengeHash = Hash3(Signature, 0, PublicKey, Message, buffer.len(Message))
	FieldQuadratic.DecodeWide(ChallengeHash, SCALAR_A)
	FieldQuadratic.Regular(SCALAR_A, SCALAR_B)

	local Halves = SPLIT_HALVES
	local Negative = ScalarSplit.Split(SCALAR_B, Halves)

	buffer.fill(SCALE_REGULAR, 48, 0, 48)
	buffer.copy(SCALE_REGULAR, 0, Halves, 48, 48)
	FieldQuadratic.Decode(SCALAR_BYTES, SCALAR_A)
	FieldQuadratic.Montgomery(SCALE_REGULAR, SCALAR_B)
	FieldQuadratic.Mul(SCALAR_B, SCALAR_A, SCALAR_A)
	FieldQuadratic.EncodeInto(SCALAR_A, SCALAR_BYTES)
	Edwards25519.MulGBytes(SCALAR_BYTES, POINT_B, true)

	Edwards25519.WindowedNAFTable(POINT_A, 4, VERIFY_R_TABLE)
	Edwards25519.MulDoubleWithTables(VERIFY_R_TABLE, 4, 120, (Known :: VerifyKey).Table, 5, 96, Halves, 128, Negative, POINT_A)

	Edwards25519.NielsInto(POINT_B, POINT_NIELS, 0)
	Edwards25519.SubNielsInPlace(POINT_A, POINT_NIELS)

	Edwards25519.DoubleInPlace(POINT_A, false)
	Edwards25519.DoubleInPlace(POINT_A, false)
	Edwards25519.DoubleInPlace(POINT_A, true)

	return FieldPrime.EqzAt(POINT_A, 0) and FieldPrime.EqzAt(POINT_A, 312)
end

local function ClearCaches(): ()
	buffer.fill(SIGN_KEYS, 0, 0)
	buffer.fill(SIGN_SCALAR, 0, 0)
	buffer.fill(SIGN_PREFIX, 0, 0)
	buffer.fill(SPLIT_HALVES, 0, 0)
	buffer.fill(SCALE_REGULAR, 0, 0)
	buffer.fill(SCALAR_BYTES, 0, 0)
	buffer.fill(SCALAR_A, 0, 0)
	buffer.fill(SCALAR_B, 0, 0)
	buffer.fill(POINT_A, 0, 0)
	buffer.fill(POINT_B, 0, 0)
	buffer.fill(POINT_NIELS, 0, 0)
	buffer.fill(VERIFY_R_TABLE, 0, 0)
	VERIFY_KEY = nil

	local LoadedX25519 = rawget(EDDSA :: any, "X25519")
	if LoadedX25519 then
		LoadedX25519.ClearCaches()
	else
		Edwards25519.ClearCaches()
		FieldPrime.ClearCaches()
	end
	FieldQuadratic.ClearCaches()
	ScalarSplit.ClearCaches()
	SHA512Module.ClearCaches()
end

EDDSA = Lazy.Attach({
	PublicKey = PublicKey,
	Sign = Sign,
	Verify = Verify,
	ClearCaches = ClearCaches,
}, {
	X25519 = function()
		return require("@self/X25519")
	end,
})

return EDDSA
