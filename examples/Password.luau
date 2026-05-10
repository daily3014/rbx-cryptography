--[=[
	Password Storage System using Argon2id (RFC 9106)

	Argon2id is a memory hard password hashing function.
	 It is specifically designed to make brute force attacks expensive even when an
	attacker has access to GPUs or ASICs, by forcing each hash to consume a
	large amount of memory.

	Use this when:
	- Users choose their own passwords (humans pick predictable passwords).
	- You store hashes server side and want to limit damage if the database leaks.

	Defaults are:
	- m = 19 MiB, t = 2, p = 1, output 32 bytes —> OWASP minimum recommendation.
	- ~50 ms per hash in Luau native codegen.

	If you need stronger security, use {MemoryCost = 65536, TimeCost = 3} (OWASP recommended).

	Usage:
		local Storage = Storage:CreatePasswordRecord("MyP@ssw0rd!")
		-- save Storage.Hash, Storage.Salt to your DataStore

		local Ok = VerifyPassword("MyP@ssw0rd!", Storage.Hash, Storage.Salt)
--]=]

--!strict
--!optimize 2
--!native

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Cryptography = require(ReplicatedStorage:WaitForChild("Cryptography"))
local Argon2id = Cryptography.Hashing.Argon2id
local CSPRNG = Cryptography.Utilities.CSPRNG

type StoredPassword = {
	Hash: buffer,
	Salt: buffer,
	CreatedAt: number,
}

local SALT_SIZE = 16
local HASH_SIZE = 32

local function GenerateRandomSalt(): buffer
	return CSPRNG.RandomBytes(SALT_SIZE)
end

local function ConstantTimeEquals(Buffer1: buffer, Buffer2: buffer): boolean
	local Length = buffer.len(Buffer1)
	if Length ~= buffer.len(Buffer2) then
		return false
	end

	local Result = 0
	for I = 0, Length - 1 do
		Result = bit32.bor(Result, bit32.bxor(buffer.readu8(Buffer1, I), buffer.readu8(Buffer2, I)))
	end

	return Result == 0
end

local function CreatePasswordHash(Password: string): (buffer, buffer)
	local Salt = GenerateRandomSalt()
	local PasswordBuffer = buffer.fromstring(Password)
	local _, Hash = Argon2id(PasswordBuffer, Salt)
	return Hash, Salt
end

local function VerifyPassword(Password: string, StoredHash: buffer, Salt: buffer): boolean
	local PasswordBuffer = buffer.fromstring(Password)
	local _, ComputedHash = Argon2id(PasswordBuffer, Salt)
	return ConstantTimeEquals(ComputedHash, StoredHash)
end

local function CreateStoredPassword(Password: string): StoredPassword
	local Hash, Salt = CreatePasswordHash(Password)
	return {
		Hash = Hash,
		Salt = Salt,
		CreatedAt = os.time(),
	}
end

return {
	CreatePasswordHash = CreatePasswordHash,
	VerifyPassword = VerifyPassword,
	CreateStoredPassword = CreateStoredPassword,
	HASH_SIZE = HASH_SIZE,
	SALT_SIZE = SALT_SIZE,
}
