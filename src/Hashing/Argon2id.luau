--[=[
	Cryptography library: Argon2id (RFC 9106)

	Password hashing function:
		m = 19456 KiB (19 MiB), t = 2, p = 1, output 32 bytes.

	Suggested parameter tiers:
		Interactive (~20 ms):  m =  8 MiB, t = 2, p = 1
		Default     (~50 ms):  m = 19 MiB, t = 2, p = 1   (OWASP minimum)
		Sensitive  (~270 ms):  m = 64 MiB, t = 3, p = 1   (OWASP recommended)

	Usage:
		local Hex, Tag = Argon2id(Password, Salt)
		local Hex, Tag = Argon2id(Password, Salt, {
			TimeCost = 2,
			MemoryCost = 19456,
			Parallelism = 1,
			OutputLength = 32,
			Secret = SecretBuf,           -- optional
			AssociatedData = AdBuf,       -- optional
			Formatted = true,             -- optional # returns formatted string instead of hex representation
		})
--]=]

--!strict
--!optimize 2
--!native

type Argon2idOptions = {
	TimeCost: number?,
	MemoryCost: number?,
	Parallelism: number?,
	OutputLength: number?,
	Secret: buffer?,
	AssociatedData: buffer?,
	Formatted: boolean?,
}

local Blake2b = require("./Blake2b")
local Base64 = require("../Utilities/Base64")
local Conversions = require("../Utilities/Conversions")

local BLOCK_BYTES = 1024
local SYNC_POINTS = 4
local ARGON2ID_TYPE = 2
local ARGON2_VERSION = 0x13

local ScratchR = buffer.create(BLOCK_BYTES)
local ScratchZ = buffer.create(BLOCK_BYTES)
local ZeroBlock = buffer.create(BLOCK_BYTES)
local AddressInput = buffer.create(BLOCK_BYTES)
local AddressTmp = buffer.create(BLOCK_BYTES)
local AddressBlock = buffer.create(BLOCK_BYTES)

local function ToBase64(Input: buffer | string): string
	Input = if typeof(Input) == "string"
		then buffer.fromstring(Input)
		else Input

	local RawBase64 = buffer.tostring(Base64.Encode(Input))
	local Stripped = string.gsub(RawBase64, "=", "")

	return Stripped
end

local function VariableHash(OutBuf: buffer, OutOffset: number, OutLen: number, Input: buffer): ()
	local InputLen = buffer.len(Input)
	local Tmp = buffer.create(4 + InputLen)
	buffer.writeu32(Tmp, 0, OutLen)
	buffer.copy(Tmp, 4, Input, 0, InputLen)

	if OutLen <= 64 then
		local _, Hash = Blake2b(Tmp, OutLen)
		buffer.copy(OutBuf, OutOffset, Hash, 0, OutLen)
		return
	end

	local _, V = Blake2b(Tmp, 64)
	buffer.copy(OutBuf, OutOffset, V, 0, 32)
	local Pos = 32

	while OutLen - Pos > 64 do
		local _, NewV = Blake2b(V, 64)
		V = NewV
		buffer.copy(OutBuf, OutOffset + Pos, V, 0, 32)
		Pos += 32
	end

	local _, Final = Blake2b(V, OutLen - Pos)
	buffer.copy(OutBuf, OutOffset + Pos, Final, 0, OutLen - Pos)
end

local function Compress(OutMem: buffer, OutOff: number, XMem: buffer, XOff: number, YMem: buffer, YOff: number): ()
	local LR = ScratchR
	local LZ = ScratchZ

	for I = 0, 1016, 8 do
		local Combined = integer.bxor(buffer.readinteger(XMem, XOff + I), buffer.readinteger(YMem, YOff + I))
		buffer.writeinteger(LR, I, Combined)
		buffer.writeinteger(LZ, I, Combined)
	end

	for Row = 0, 7 do
		local Off = Row * 128
		local v0 = buffer.readinteger(LZ, Off + 0)
		local v1 = buffer.readinteger(LZ, Off + 8)
		local v2 = buffer.readinteger(LZ, Off + 16)
		local v3 = buffer.readinteger(LZ, Off + 24)
		local v4 = buffer.readinteger(LZ, Off + 32)
		local v5 = buffer.readinteger(LZ, Off + 40)
		local v6 = buffer.readinteger(LZ, Off + 48)
		local v7 = buffer.readinteger(LZ, Off + 56)
		local v8 = buffer.readinteger(LZ, Off + 64)
		local v9 = buffer.readinteger(LZ, Off + 72)
		local v10 = buffer.readinteger(LZ, Off + 80)
		local v11 = buffer.readinteger(LZ, Off + 88)
		local v12 = buffer.readinteger(LZ, Off + 96)
		local v13 = buffer.readinteger(LZ, Off + 104)
		local v14 = buffer.readinteger(LZ, Off + 112)
		local v15 = buffer.readinteger(LZ, Off + 120)
		local La, Lb, Pr
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v4), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v0), 32i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v12), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v8), 24i)
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v4), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v0), 16i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v12), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v8), 63i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v5), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v1), 32i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v13), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v9), 24i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v5), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v1), 16i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v13), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v9), 63i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v6), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v2), 32i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v14), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v10), 24i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v6), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v2), 16i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v14), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v10), 63i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v7), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v3), 32i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v15), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v11), 24i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v7), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v3), 16i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v15), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v11), 63i)
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v5), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v0), 32i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v15), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v10), 24i)
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v5), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v0), 16i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v15), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v10), 63i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v6), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v1), 32i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v12), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v11), 24i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v6), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v1), 16i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v12), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v11), 63i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v7), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v2), 32i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v13), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v8), 24i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v7), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v2), 16i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v13), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v8), 63i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v4), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v3), 32i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v14), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v9), 24i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v4), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v3), 16i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v14), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v9), 63i)
		buffer.writeinteger(LZ, Off + 0, v0)
		buffer.writeinteger(LZ, Off + 8, v1)
		buffer.writeinteger(LZ, Off + 16, v2)
		buffer.writeinteger(LZ, Off + 24, v3)
		buffer.writeinteger(LZ, Off + 32, v4)
		buffer.writeinteger(LZ, Off + 40, v5)
		buffer.writeinteger(LZ, Off + 48, v6)
		buffer.writeinteger(LZ, Off + 56, v7)
		buffer.writeinteger(LZ, Off + 64, v8)
		buffer.writeinteger(LZ, Off + 72, v9)
		buffer.writeinteger(LZ, Off + 80, v10)
		buffer.writeinteger(LZ, Off + 88, v11)
		buffer.writeinteger(LZ, Off + 96, v12)
		buffer.writeinteger(LZ, Off + 104, v13)
		buffer.writeinteger(LZ, Off + 112, v14)
		buffer.writeinteger(LZ, Off + 120, v15)
	end

	for Col = 0, 7 do
		local Off = Col * 16
		local v0 = buffer.readinteger(LZ, Off + 0)
		local v1 = buffer.readinteger(LZ, Off + 8)
		local v2 = buffer.readinteger(LZ, Off + 128)
		local v3 = buffer.readinteger(LZ, Off + 136)
		local v4 = buffer.readinteger(LZ, Off + 256)
		local v5 = buffer.readinteger(LZ, Off + 264)
		local v6 = buffer.readinteger(LZ, Off + 384)
		local v7 = buffer.readinteger(LZ, Off + 392)
		local v8 = buffer.readinteger(LZ, Off + 512)
		local v9 = buffer.readinteger(LZ, Off + 520)
		local v10 = buffer.readinteger(LZ, Off + 640)
		local v11 = buffer.readinteger(LZ, Off + 648)
		local v12 = buffer.readinteger(LZ, Off + 768)
		local v13 = buffer.readinteger(LZ, Off + 776)
		local v14 = buffer.readinteger(LZ, Off + 896)
		local v15 = buffer.readinteger(LZ, Off + 904)
		local La, Lb, Pr
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v4), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v0), 32i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v12), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v8), 24i)
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v4), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v0), 16i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v12), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v8), 63i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v5), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v1), 32i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v13), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v9), 24i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v5), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v1), 16i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v13), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v9), 63i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v6), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v2), 32i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v14), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v10), 24i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v6), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v2), 16i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v14), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v10), 63i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v7), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v3), 32i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v15), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v11), 24i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v7), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v3), 16i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v15), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v11), 63i)
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v5), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v0), 32i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v15), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v10), 24i)
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v5), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v0), 16i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v15), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v10), 63i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v6), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v1), 32i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v12), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v11), 24i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v6), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v1), 16i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v12), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v11), 63i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v7), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v2), 32i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v13), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v8), 24i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v7), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v2), 16i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v13), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v8), 63i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v4), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v3), 32i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v14), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v9), 24i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v4), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v3), 16i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v14), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v9), 63i)
		buffer.writeinteger(LZ, Off + 0, v0)
		buffer.writeinteger(LZ, Off + 8, v1)
		buffer.writeinteger(LZ, Off + 128, v2)
		buffer.writeinteger(LZ, Off + 136, v3)
		buffer.writeinteger(LZ, Off + 256, v4)
		buffer.writeinteger(LZ, Off + 264, v5)
		buffer.writeinteger(LZ, Off + 384, v6)
		buffer.writeinteger(LZ, Off + 392, v7)
		buffer.writeinteger(LZ, Off + 512, v8)
		buffer.writeinteger(LZ, Off + 520, v9)
		buffer.writeinteger(LZ, Off + 640, v10)
		buffer.writeinteger(LZ, Off + 648, v11)
		buffer.writeinteger(LZ, Off + 768, v12)
		buffer.writeinteger(LZ, Off + 776, v13)
		buffer.writeinteger(LZ, Off + 896, v14)
		buffer.writeinteger(LZ, Off + 904, v15)
	end

	for I = 0, 1016, 8 do
		buffer.writeinteger(OutMem, OutOff + I, integer.bxor(buffer.readinteger(LZ, I), buffer.readinteger(LR, I)))
	end
end

local function CompressXor(OutMem: buffer, OutOff: number, XMem: buffer, XOff: number, YMem: buffer, YOff: number): ()
	local LR = ScratchR
	local LZ = ScratchZ

	for I = 0, 1016, 8 do
		local Combined = integer.bxor(buffer.readinteger(XMem, XOff + I), buffer.readinteger(YMem, YOff + I))
		buffer.writeinteger(LR, I, Combined)
		buffer.writeinteger(LZ, I, Combined)
	end

	for Row = 0, 7 do
		local Off = Row * 128
		local v0 = buffer.readinteger(LZ, Off + 0)
		local v1 = buffer.readinteger(LZ, Off + 8)
		local v2 = buffer.readinteger(LZ, Off + 16)
		local v3 = buffer.readinteger(LZ, Off + 24)
		local v4 = buffer.readinteger(LZ, Off + 32)
		local v5 = buffer.readinteger(LZ, Off + 40)
		local v6 = buffer.readinteger(LZ, Off + 48)
		local v7 = buffer.readinteger(LZ, Off + 56)
		local v8 = buffer.readinteger(LZ, Off + 64)
		local v9 = buffer.readinteger(LZ, Off + 72)
		local v10 = buffer.readinteger(LZ, Off + 80)
		local v11 = buffer.readinteger(LZ, Off + 88)
		local v12 = buffer.readinteger(LZ, Off + 96)
		local v13 = buffer.readinteger(LZ, Off + 104)
		local v14 = buffer.readinteger(LZ, Off + 112)
		local v15 = buffer.readinteger(LZ, Off + 120)
		local La, Lb, Pr
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v4), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v0), 32i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v12), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v8), 24i)
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v4), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v0), 16i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v12), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v8), 63i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v5), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v1), 32i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v13), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v9), 24i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v5), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v1), 16i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v13), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v9), 63i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v6), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v2), 32i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v14), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v10), 24i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v6), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v2), 16i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v14), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v10), 63i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v7), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v3), 32i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v15), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v11), 24i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v7), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v3), 16i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v15), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v11), 63i)
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v5), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v0), 32i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v15), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v10), 24i)
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v5), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v0), 16i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v15), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v10), 63i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v6), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v1), 32i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v12), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v11), 24i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v6), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v1), 16i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v12), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v11), 63i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v7), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v2), 32i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v13), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v8), 24i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v7), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v2), 16i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v13), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v8), 63i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v4), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v3), 32i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v14), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v9), 24i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v4), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v3), 16i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v14), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v9), 63i)
		buffer.writeinteger(LZ, Off + 0, v0)
		buffer.writeinteger(LZ, Off + 8, v1)
		buffer.writeinteger(LZ, Off + 16, v2)
		buffer.writeinteger(LZ, Off + 24, v3)
		buffer.writeinteger(LZ, Off + 32, v4)
		buffer.writeinteger(LZ, Off + 40, v5)
		buffer.writeinteger(LZ, Off + 48, v6)
		buffer.writeinteger(LZ, Off + 56, v7)
		buffer.writeinteger(LZ, Off + 64, v8)
		buffer.writeinteger(LZ, Off + 72, v9)
		buffer.writeinteger(LZ, Off + 80, v10)
		buffer.writeinteger(LZ, Off + 88, v11)
		buffer.writeinteger(LZ, Off + 96, v12)
		buffer.writeinteger(LZ, Off + 104, v13)
		buffer.writeinteger(LZ, Off + 112, v14)
		buffer.writeinteger(LZ, Off + 120, v15)
	end

	for Col = 0, 7 do
		local Off = Col * 16
		local v0 = buffer.readinteger(LZ, Off + 0)
		local v1 = buffer.readinteger(LZ, Off + 8)
		local v2 = buffer.readinteger(LZ, Off + 128)
		local v3 = buffer.readinteger(LZ, Off + 136)
		local v4 = buffer.readinteger(LZ, Off + 256)
		local v5 = buffer.readinteger(LZ, Off + 264)
		local v6 = buffer.readinteger(LZ, Off + 384)
		local v7 = buffer.readinteger(LZ, Off + 392)
		local v8 = buffer.readinteger(LZ, Off + 512)
		local v9 = buffer.readinteger(LZ, Off + 520)
		local v10 = buffer.readinteger(LZ, Off + 640)
		local v11 = buffer.readinteger(LZ, Off + 648)
		local v12 = buffer.readinteger(LZ, Off + 768)
		local v13 = buffer.readinteger(LZ, Off + 776)
		local v14 = buffer.readinteger(LZ, Off + 896)
		local v15 = buffer.readinteger(LZ, Off + 904)
		local La, Lb, Pr
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v4), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v0), 32i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v12), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v8), 24i)
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v4), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v0), 16i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v12), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v8), 63i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v5), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v1), 32i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v13), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v9), 24i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v5), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v1), 16i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v13), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v9), 63i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v6), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v2), 32i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v14), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v10), 24i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v6), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v2), 16i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v14), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v10), 63i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v7), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v3), 32i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v15), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v11), 24i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v7), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v3), 16i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v15), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v11), 63i)
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v5), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v0), 32i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v15), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v10), 24i)
		La = integer.band(v0, 0xFFFFFFFFi); Lb = integer.band(v5, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v0 = integer.add(integer.add(v0, v5), integer.add(Pr, Pr))
		v15 = integer.rrotate(integer.bxor(v15, v0), 16i)
		La = integer.band(v10, 0xFFFFFFFFi); Lb = integer.band(v15, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v10 = integer.add(integer.add(v10, v15), integer.add(Pr, Pr))
		v5 = integer.rrotate(integer.bxor(v5, v10), 63i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v6), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v1), 32i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v12), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v11), 24i)
		La = integer.band(v1, 0xFFFFFFFFi); Lb = integer.band(v6, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v1 = integer.add(integer.add(v1, v6), integer.add(Pr, Pr))
		v12 = integer.rrotate(integer.bxor(v12, v1), 16i)
		La = integer.band(v11, 0xFFFFFFFFi); Lb = integer.band(v12, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v11 = integer.add(integer.add(v11, v12), integer.add(Pr, Pr))
		v6 = integer.rrotate(integer.bxor(v6, v11), 63i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v7), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v2), 32i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v13), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v8), 24i)
		La = integer.band(v2, 0xFFFFFFFFi); Lb = integer.band(v7, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v2 = integer.add(integer.add(v2, v7), integer.add(Pr, Pr))
		v13 = integer.rrotate(integer.bxor(v13, v2), 16i)
		La = integer.band(v8, 0xFFFFFFFFi); Lb = integer.band(v13, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v8 = integer.add(integer.add(v8, v13), integer.add(Pr, Pr))
		v7 = integer.rrotate(integer.bxor(v7, v8), 63i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v4), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v3), 32i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v14), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v9), 24i)
		La = integer.band(v3, 0xFFFFFFFFi); Lb = integer.band(v4, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v3 = integer.add(integer.add(v3, v4), integer.add(Pr, Pr))
		v14 = integer.rrotate(integer.bxor(v14, v3), 16i)
		La = integer.band(v9, 0xFFFFFFFFi); Lb = integer.band(v14, 0xFFFFFFFFi); Pr = integer.mul(La, Lb)
		v9 = integer.add(integer.add(v9, v14), integer.add(Pr, Pr))
		v4 = integer.rrotate(integer.bxor(v4, v9), 63i)
		buffer.writeinteger(LZ, Off + 0, v0)
		buffer.writeinteger(LZ, Off + 8, v1)
		buffer.writeinteger(LZ, Off + 128, v2)
		buffer.writeinteger(LZ, Off + 136, v3)
		buffer.writeinteger(LZ, Off + 256, v4)
		buffer.writeinteger(LZ, Off + 264, v5)
		buffer.writeinteger(LZ, Off + 384, v6)
		buffer.writeinteger(LZ, Off + 392, v7)
		buffer.writeinteger(LZ, Off + 512, v8)
		buffer.writeinteger(LZ, Off + 520, v9)
		buffer.writeinteger(LZ, Off + 640, v10)
		buffer.writeinteger(LZ, Off + 648, v11)
		buffer.writeinteger(LZ, Off + 768, v12)
		buffer.writeinteger(LZ, Off + 776, v13)
		buffer.writeinteger(LZ, Off + 896, v14)
		buffer.writeinteger(LZ, Off + 904, v15)
	end

	for I = 0, 1016, 8 do
		buffer.writeinteger(OutMem, OutOff + I, integer.bxor(
			buffer.readinteger(OutMem, OutOff + I),
			integer.bxor(buffer.readinteger(LZ, I), buffer.readinteger(LR, I))
		))
	end
end

local function GenerateAddressBlock(Pass: number, Lane: number, Slice: number, TotalBlocks: number, TotalPasses: number, Counter: number): ()
	buffer.fill(AddressInput, 0, 0, BLOCK_BYTES)
	buffer.writeinteger(AddressInput, 0, integer.create(Pass))
	buffer.writeinteger(AddressInput, 8, integer.create(Lane))
	buffer.writeinteger(AddressInput, 16, integer.create(Slice))
	buffer.writeinteger(AddressInput, 24, integer.create(TotalBlocks))
	buffer.writeinteger(AddressInput, 32, integer.create(TotalPasses))
	buffer.writeinteger(AddressInput, 40, integer.create(ARGON2ID_TYPE))
	buffer.writeinteger(AddressInput, 48, integer.create(Counter))
	Compress(AddressTmp, 0, ZeroBlock, 0, AddressInput, 0)
	Compress(AddressBlock, 0, ZeroBlock, 0, AddressTmp, 0)
end

local function ComputeRef(
	J1U32: number, J2U32: number,
	Pass: number, CurrLane: number, Slice: number,
	LaneLength: number, SegmentLength: number,
	IndexInSegment: number, Parallelism: number
): (number, number)
	local RefLane: number
	if Pass == 0 and Slice == 0 then
		RefLane = CurrLane
	else
		RefLane = J2U32 % Parallelism
	end

	local SameLane = RefLane == CurrLane
	local RefAreaSize: number
	if Pass == 0 then
		if Slice == 0 then
			RefAreaSize = IndexInSegment - 1
		elseif SameLane then
			RefAreaSize = Slice * SegmentLength + IndexInSegment - 1
		else
			RefAreaSize = Slice * SegmentLength - (IndexInSegment == 0 and 1 or 0)
		end
	else
		if SameLane then
			RefAreaSize = LaneLength - SegmentLength + IndexInSegment - 1
		else
			RefAreaSize = LaneLength - SegmentLength - (IndexInSegment == 0 and 1 or 0)
		end
	end

	local J1Int = integer.create(J1U32)
	local X = integer.tonumber(integer.rshift(integer.mul(J1Int, J1Int), 32i))
	local Y: number
	if RefAreaSize < 0x200000 then
		Y = math.floor(RefAreaSize * X / 0x100000000)
	else
		Y = integer.tonumber(integer.rshift(integer.mul(integer.create(RefAreaSize), integer.create(X)), 32i))
	end
	local RelPos = RefAreaSize - 1 - Y

	local StartPos = 0
	if Pass ~= 0 then
		StartPos = (Slice + 1 == SYNC_POINTS) and 0 or (Slice + 1) * SegmentLength
	end

	return RefLane, (StartPos + RelPos) % LaneLength
end

local function FillSegment(Memory: buffer, Pass: number, Lane: number, Slice: number, LaneLength: number, SegmentLength: number, Parallelism: number, TotalBlocks: number, TotalPasses: number): ()
	local UseDataIndep = Pass == 0 and Slice < 2
	local LAddressBlock = AddressBlock

	local SegmentStart = Slice * SegmentLength
	local LaneStart = Lane * LaneLength * 1024

	local StartIdx = 0
	local AddressCounter = 0
	if Pass == 0 and Slice == 0 then
		StartIdx = 2
		if UseDataIndep then
			AddressCounter = 1
			GenerateAddressBlock(Pass, Lane, Slice, TotalBlocks, TotalPasses, AddressCounter)
		end
	end

	if UseDataIndep then
		for IndexInSegment = StartIdx, SegmentLength - 1 do
			if IndexInSegment % 128 == 0 and IndexInSegment ~= StartIdx then
				AddressCounter += 1
				GenerateAddressBlock(Pass, Lane, Slice, TotalBlocks, TotalPasses, AddressCounter)
			elseif IndexInSegment == 0 then
				AddressCounter = 1
				GenerateAddressBlock(Pass, Lane, Slice, TotalBlocks, TotalPasses, AddressCounter)
			end

			local CurrIndex = SegmentStart + IndexInSegment
			local CurrOff = LaneStart + CurrIndex * 1024
			local PrevIndex = (CurrIndex == 0) and (LaneLength - 1) or (CurrIndex - 1)
			local PrevOff = LaneStart + PrevIndex * 1024

			local AddrU64 = buffer.readinteger(LAddressBlock, (IndexInSegment % 128) * 8)
			local J1 = integer.tonumber(integer.band(AddrU64, 0xFFFFFFFFi))
			local J2 = integer.tonumber(integer.rshift(AddrU64, 32i))

			local RefLane, RefIndex = ComputeRef(J1, J2, Pass, Lane, Slice, LaneLength, SegmentLength, IndexInSegment, Parallelism)
			local RefOff = (RefLane * LaneLength + RefIndex) * 1024

			Compress(Memory, CurrOff, Memory, PrevOff, Memory, RefOff)
		end
	elseif Pass > 0 then
		for IndexInSegment = StartIdx, SegmentLength - 1 do
			local CurrIndex = SegmentStart + IndexInSegment
			local CurrOff = LaneStart + CurrIndex * 1024
			local PrevIndex = (CurrIndex == 0) and (LaneLength - 1) or (CurrIndex - 1)
			local PrevOff = LaneStart + PrevIndex * 1024

			local U64 = buffer.readinteger(Memory, PrevOff)
			local J1 = integer.tonumber(integer.band(U64, 0xFFFFFFFFi))
			local J2 = integer.tonumber(integer.rshift(U64, 32i))

			local RefLane, RefIndex = ComputeRef(J1, J2, Pass, Lane, Slice, LaneLength, SegmentLength, IndexInSegment, Parallelism)
			local RefOff = (RefLane * LaneLength + RefIndex) * 1024

			CompressXor(Memory, CurrOff, Memory, PrevOff, Memory, RefOff)
		end
	else
		for IndexInSegment = StartIdx, SegmentLength - 1 do
			local CurrIndex = SegmentStart + IndexInSegment
			local CurrOff = LaneStart + CurrIndex * 1024
			local PrevIndex = (CurrIndex == 0) and (LaneLength - 1) or (CurrIndex - 1)
			local PrevOff = LaneStart + PrevIndex * 1024

			local U64 = buffer.readinteger(Memory, PrevOff)
			local J1 = integer.tonumber(integer.band(U64, 0xFFFFFFFFi))
			local J2 = integer.tonumber(integer.rshift(U64, 32i))

			local RefLane, RefIndex = ComputeRef(J1, J2, Pass, Lane, Slice, LaneLength, SegmentLength, IndexInSegment, Parallelism)
			local RefOff = (RefLane * LaneLength + RefIndex) * 1024

			Compress(Memory, CurrOff, Memory, PrevOff, Memory, RefOff)
		end
	end
end

local function Argon2id(Password: buffer, Salt: buffer, Options: Argon2idOptions?): (string, buffer)
	if typeof(Password) ~= "buffer" then error("Password must be a buffer", 2) end
	if typeof(Salt) ~= "buffer" then error("Salt must be a buffer", 2) end

	local Opts: Argon2idOptions = Options or {}
	local TimeCost = math.floor(Opts.TimeCost or 2)
	local MemoryCost = math.floor(Opts.MemoryCost or 19456)
	local Parallelism = math.floor(Opts.Parallelism or 1)
	local OutputLength = math.floor(Opts.OutputLength or 32)
	local Secret = Opts.Secret
	local AssociatedData = Opts.AssociatedData

	if TimeCost < 1 then error("TimeCost must be >= 1", 2) end
	if Parallelism < 1 or Parallelism > 16777215 then error("Parallelism must be in [1, 2^24 - 1]", 2) end
	if MemoryCost < 8 * Parallelism then error(`MemoryCost must be >= 8 * Parallelism (got {MemoryCost} < {8 * Parallelism})`, 2) end
	if OutputLength < 4 then error("OutputLength must be >= 4", 2) end
	if buffer.len(Salt) < 8 then error("Salt must be >= 8 bytes", 2) end

	local TotalBlocks = math.floor(MemoryCost / (4 * Parallelism)) * 4 * Parallelism
	local LaneLength = TotalBlocks // Parallelism
	local SegmentLength = LaneLength // SYNC_POINTS

	local PassLen = buffer.len(Password)
	local SaltLen = buffer.len(Salt)
	local SecretLen = Secret and buffer.len(Secret) or 0
	local AssocLen = AssociatedData and buffer.len(AssociatedData) or 0

	local H0Input = buffer.create(4 * 10 + PassLen + SaltLen + SecretLen + AssocLen)
	buffer.writeu32(H0Input, 0, Parallelism)
	buffer.writeu32(H0Input, 4, OutputLength)
	buffer.writeu32(H0Input, 8, MemoryCost)
	buffer.writeu32(H0Input, 12, TimeCost)
	buffer.writeu32(H0Input, 16, ARGON2_VERSION)
	buffer.writeu32(H0Input, 20, ARGON2ID_TYPE)
	buffer.writeu32(H0Input, 24, PassLen)
	buffer.copy(H0Input, 28, Password, 0, PassLen)
	local Off = 28 + PassLen
	buffer.writeu32(H0Input, Off, SaltLen)
	buffer.copy(H0Input, Off + 4, Salt, 0, SaltLen)
	Off += 4 + SaltLen
	buffer.writeu32(H0Input, Off, SecretLen)
	if Secret and SecretLen > 0 then buffer.copy(H0Input, Off + 4, Secret, 0, SecretLen) end
	Off += 4 + SecretLen
	buffer.writeu32(H0Input, Off, AssocLen)
	if AssociatedData and AssocLen > 0 then buffer.copy(H0Input, Off + 4, AssociatedData, 0, AssocLen) end

	local _, H0 = Blake2b(H0Input, 64)

	local Memory = buffer.create(TotalBlocks * BLOCK_BYTES)

	local InitInput = buffer.create(64 + 4 + 4)
	buffer.copy(InitInput, 0, H0, 0, 64)

	for I = 0, Parallelism - 1 do
		for J = 0, 1 do
			buffer.writeu32(InitInput, 64, J)
			buffer.writeu32(InitInput, 68, I)
			local Position = (I * LaneLength + J) * BLOCK_BYTES
			VariableHash(Memory, Position, BLOCK_BYTES, InitInput)
		end
	end

	for Pass = 0, TimeCost - 1 do
		for Slice = 0, SYNC_POINTS - 1 do
			for Lane = 0, Parallelism - 1 do
				FillSegment(Memory, Pass, Lane, Slice, LaneLength, SegmentLength, Parallelism, TotalBlocks, TimeCost)
			end
		end
	end

	local FinalBlock = buffer.create(BLOCK_BYTES)
	buffer.copy(FinalBlock, 0, Memory, (LaneLength - 1) * BLOCK_BYTES, BLOCK_BYTES)
	for I = 1, Parallelism - 1 do
		local LastBlockOff = (I * LaneLength + LaneLength - 1) * BLOCK_BYTES
		for J = 0, 1016, 8 do
			buffer.writeinteger(FinalBlock, J, integer.bxor(buffer.readinteger(FinalBlock, J), buffer.readinteger(Memory, LastBlockOff + J)))
		end
	end

	local Tag = buffer.create(OutputLength)
	VariableHash(Tag, 0, OutputLength, FinalBlock)

	if Opts.Formatted then
		return `$argon2id$v=19$m={MemoryCost},t={TimeCost},p={Parallelism}${ToBase64(Salt)}${ToBase64(Tag)}`, Tag
	end

	return Conversions.ToHex(Tag), Tag
end

return Argon2id
