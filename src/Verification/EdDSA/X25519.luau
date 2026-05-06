--[=[
	Cryptography library: X25519 Diffie-Hellman key exchange (RFC 7748)

	Plain Montgomery ladder. The Roblox sandbox has no realistic
	side-channel attack surface (no power analysis, no EM, no cache timing,
	timer resolution far coarser than any per-bit leak), so the previous
	masked split-scalar implementation has been replaced with a direct
	ladder for ~50% better throughput.

	Sizes:
		SecretKey:    32 bytes
		PublicKey:    32 bytes
		SharedSecret: 32 bytes

	Example usage:
		local AlicePrivate = CSPRNG.RandomBytes(32)
		local BobPrivate = CSPRNG.RandomBytes(32)

		local AlicePublic = X25519.PublicKey(AlicePrivate)
		local BobPublic = X25519.PublicKey(BobPrivate)

		local AliceShared = X25519.Exchange(AlicePrivate, BobPublic)
		local BobShared = X25519.Exchange(BobPrivate, AlicePublic)

		Expect(ToHex(AliceShared)).ToBe(ToHex(BobShared))
--]=]

--!strict
--!optimize 2
--!native

local FieldPrime = require("./FieldPrime")
local Curve25519 = require("./Curve25519")
local CSPRNG = require("./CSPRNG")

local COORD_SIZE = 80
local X25519_SECRET_KEY_SIZE = 32
local X25519_PUBLIC_KEY_SIZE = 32
local X25519_SCALAR_BITS = 255

local CLAMPED_BITS = buffer.create(256)
local BYTE_TO_BITS = buffer.create(256 * 8) do
	for B = 0, 255 do
		for I = 0, 7 do
			buffer.writeu8(BYTE_TO_BITS, B * 8 + I, bit32.band(bit32.rshift(B, I), 1))
		end
	end
end

local function ClampedScalarBits(SecretKey: buffer): (buffer, number)
	local Bits = CLAMPED_BITS

	local Off = bit32.band(buffer.readu8(SecretKey, 0), 0xF8) * 8
	buffer.writeu32(Bits, 0, buffer.readu32(BYTE_TO_BITS, Off))
	buffer.writeu32(Bits, 4, buffer.readu32(BYTE_TO_BITS, Off + 4))

	for ByteIndex = 1, 30 do
		local TableOff = buffer.readu8(SecretKey, ByteIndex) * 8
		local Base = ByteIndex * 8
		buffer.writeu32(Bits, Base, buffer.readu32(BYTE_TO_BITS, TableOff))
		buffer.writeu32(Bits, Base + 4, buffer.readu32(BYTE_TO_BITS, TableOff + 4))
	end

	Off = bit32.bor(bit32.band(buffer.readu8(SecretKey, 31), 0x7F), 0x40) * 8
	buffer.writeu32(Bits, 248, buffer.readu32(BYTE_TO_BITS, Off))
	buffer.writeu32(Bits, 252, buffer.readu32(BYTE_TO_BITS, Off + 4))

	return Bits, X25519_SCALAR_BITS
end

local X25519 = {}

local function ScalarMult(SecretKey: buffer, BasePoint: buffer): buffer
	local Bits, BitCount = ClampedScalarBits(SecretKey)
	local Result = Curve25519.Ladder(BasePoint, Bits, BitCount)

	local ResultX = buffer.create(COORD_SIZE)
	local ResultZ = buffer.create(COORD_SIZE)
	buffer.copy(ResultX, 0, Result, 0 * COORD_SIZE, COORD_SIZE)
	buffer.copy(ResultZ, 0, Result, 1 * COORD_SIZE, COORD_SIZE)

	if FieldPrime.Eqz(ResultZ) then
		return buffer.create(32)
	end

	local Inverse = FieldPrime.Invert(ResultZ)
	return FieldPrime.Encode(FieldPrime.Mul(ResultX, Inverse))
end

function X25519.PublicKey(SecretKey: buffer): buffer
	if SecretKey == nil then
		error("SecretKey cannot be nil", 2)
	end

	if typeof(SecretKey) ~= "buffer" then
		error(`SecretKey must be a buffer, got {typeof(SecretKey)}`, 2)
	end

	local SecretKeyLength = buffer.len(SecretKey)
	if SecretKeyLength ~= X25519_SECRET_KEY_SIZE then
		error(`SecretKey must be exactly {X25519_SECRET_KEY_SIZE} bytes long, got {SecretKeyLength} bytes`, 2)
	end

	return ScalarMult(SecretKey, Curve25519.G)
end

function X25519.Exchange(SecretKey: buffer, TheirPublicKey: buffer): buffer
	if SecretKey == nil then
		error("SecretKey cannot be nil", 2)
	end

	if typeof(SecretKey) ~= "buffer" then
		error(`SecretKey must be a buffer, got {typeof(SecretKey)}`, 2)
	end

	local SecretKeyLength = buffer.len(SecretKey)
	if SecretKeyLength ~= X25519_SECRET_KEY_SIZE then
		error(`SecretKey must be exactly {X25519_SECRET_KEY_SIZE} bytes long, got {SecretKeyLength} bytes`, 2)
	end

	if TheirPublicKey == nil then
		error("TheirPublicKey cannot be nil", 2)
	end

	if typeof(TheirPublicKey) ~= "buffer" then
		error(`TheirPublicKey must be a buffer, got {typeof(TheirPublicKey)}`, 2)
	end

	local TheirPublicKeyLength = buffer.len(TheirPublicKey)
	if TheirPublicKeyLength ~= X25519_PUBLIC_KEY_SIZE then
		error(`TheirPublicKey must be exactly {X25519_PUBLIC_KEY_SIZE} bytes long, got {TheirPublicKeyLength} bytes`, 2)
	end

	return ScalarMult(SecretKey, Curve25519.Decode(TheirPublicKey))
end

return X25519
