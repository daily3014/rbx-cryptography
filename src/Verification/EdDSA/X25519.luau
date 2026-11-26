--[=[
	Cryptography library: X25519 Diffie-Hellman key exchange (RFC 7748)

	Sizes:
		SecretKey:    32 bytes
		PublicKey:    32 bytes
		SharedSecret: 32 bytes

	Example usage:
		local AlicePublic = X25519.PublicKey(AlicePrivate)
		local AliceShared = X25519.Exchange(AlicePrivate, BobPublic)
--]=]

--!strict
--!optimize 2

local FieldPrime = require("./FieldPrime")
local Curve25519 = require("./Curve25519")
local Edwards25519 = require("./Edwards25519")
local CtIsAllZero = require("../../Utilities/Functions").CtIsAllZero

local COORD_SIZE = 104
local POINT_SIZE = 416
local X25519_SECRET_KEY_SIZE = 32
local X25519_PUBLIC_KEY_SIZE = 32

local CLAMPED_KEY: buffer = buffer.create(32)
local WORK_POINT: buffer = buffer.create(POINT_SIZE)
local WORK_X: buffer = buffer.create(COORD_SIZE)
local WORK_Z: buffer = buffer.create(COORD_SIZE)
local WORK_NUM: buffer = buffer.create(COORD_SIZE)
local WORK_DEN: buffer = buffer.create(COORD_SIZE)

local X25519 = {}

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

	buffer.copy(CLAMPED_KEY, 0, SecretKey, 0, 32)
	buffer.writeu8(CLAMPED_KEY, 0, bit32.band(buffer.readu8(CLAMPED_KEY, 0), 0xF8))
	buffer.writeu8(CLAMPED_KEY, 31, bit32.bor(bit32.band(buffer.readu8(CLAMPED_KEY, 31), 0x7F), 0x40))

	Edwards25519.MulGBytes(CLAMPED_KEY, WORK_POINT, false)
	buffer.copy(WORK_X, 0, WORK_POINT, COORD_SIZE, COORD_SIZE)
	buffer.copy(WORK_Z, 0, WORK_POINT, 2 * COORD_SIZE, COORD_SIZE)

	FieldPrime.Add(WORK_Z, WORK_X, WORK_NUM)
	FieldPrime.Sub(WORK_Z, WORK_X, WORK_DEN)
	FieldPrime.Invert(WORK_DEN, WORK_DEN)
	FieldPrime.Mul(WORK_NUM, WORK_DEN, WORK_NUM)

	local Out = buffer.create(32)
	FieldPrime.EncodeInto(WORK_NUM, Out)
	return Out
end

function X25519.Exchange(SecretKey: buffer, TheirPublicKey: buffer): buffer?
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

	if typeof(TheirPublicKey) ~= "buffer" or buffer.len(TheirPublicKey) ~= X25519_PUBLIC_KEY_SIZE then
		return nil
	end

	FieldPrime.DecodeInto(TheirPublicKey, WORK_NUM)
	Curve25519.LadderUnitZ(WORK_NUM, SecretKey, WORK_X, WORK_Z)

	if FieldPrime.Eqz(WORK_Z) then
		return nil
	end

	FieldPrime.Invert(WORK_Z, WORK_Z)
	FieldPrime.Mul(WORK_X, WORK_Z, WORK_X)

	local SharedSecret = buffer.create(32)
	FieldPrime.EncodeInto(WORK_X, SharedSecret)
	if CtIsAllZero(SharedSecret) then
		return nil
	end

	return SharedSecret
end

function X25519.ClearCaches(): ()
	buffer.fill(CLAMPED_KEY, 0, 0)
	buffer.fill(WORK_POINT, 0, 0)
	buffer.fill(WORK_X, 0, 0)
	buffer.fill(WORK_Z, 0, 0)
	buffer.fill(WORK_NUM, 0, 0)
	buffer.fill(WORK_DEN, 0, 0)
	Curve25519.ClearCaches()
	Edwards25519.ClearCaches()
	FieldPrime.ClearCaches()
end

return X25519
