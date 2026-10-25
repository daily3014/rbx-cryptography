--[=[
	Password Storage System using BLAKE3

	This system uses BLAKE3 for password hashing instead of Argon2id.

	Idea:
		Argon2id intentionally slows down each hash to make brute force attacks expensive.
		This is needed when users choose their own passwords, as human chosen passwords
		are predictable and exist in a searchable space even with strict requirements.

		However, my idea takes a different approach: passwords are generated using a
		cryptographically secure random number generator (CSPRNG), creating truly random
		24+ character passwords from a 94 character charset. This creates a search space of
		94^24 ≈ 10^47 possibilities, computationally infeasible to brute force no matter hashing speed.

		With CSPRNG generated passwords:
		- No dictionary attacks possible (no human patterns)
		- No need for expensive key derivation functions
		- BLAKE3's speed becomes an advantage
		- Users store passwords in their password manager (1Password, Bitwarden, etc.)

	Password Requirements:
		- Minimum 24 characters (CSPRNG generated)
		- Maximum 128 characters

	Usage:
		local GeneratedPassword = GenerateSecurePassword(24) -- App generates this locally
		-- User stores GeneratedPassword in their password manager
		local Hash, Salt = CreatePasswordHash(GeneratedPassword)
		local IsValid = VerifyPassword(GeneratedPassword, Hash, Salt)
--]=]

--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Cryptography = require(ReplicatedStorage:WaitForChild("Cryptography"))
local BLAKE3 = Cryptography.Hashing.Blake3
local CSPRNG = Cryptography.Utilities.CSPRNG
local CtCompare = Cryptography.Utilities.CtCompare

type StoredPassword = {
	Hash: buffer,
	Salt: buffer,
	CreatedAt: number,
}

local MIN_LENGTH = 24
local MAX_LENGTH = 128
local SALT_SIZE = 32 -- BLAKE3 keys are exactly 32 bytes
local HASH_SIZE = 32

-- Every printable ASCII character except space (94 characters)
local CHARSET = buffer.create(94)
for Index = 0, 93 do
	buffer.writeu8(CHARSET, Index, 33 + Index)
end

local RandomPassword = CSPRNG.MakeRandomString(CHARSET)

local function CheckLength(Password: string)
	if #Password < MIN_LENGTH or #Password > MAX_LENGTH then
		error(`Password must be {MIN_LENGTH} to {MAX_LENGTH} characters, got {#Password}`, 3)
	end
end

local function GenerateSecurePassword(Length: number?): string
	local Password = RandomPassword(Length or MIN_LENGTH) :: string
	CheckLength(Password)
	return Password
end

-- The salt is used as the BLAKE3 key, so the same password never hashes to the same value twice
local function HashWithSalt(Password: string, Salt: buffer): buffer
	local _, Hash = BLAKE3.DigestKeyed(buffer.fromstring(Password), Salt, HASH_SIZE)
	return Hash
end

local function CreatePasswordHash(Password: string): (buffer, buffer)
	CheckLength(Password)

	local Salt = CSPRNG.RandomBytes(SALT_SIZE)
	return HashWithSalt(Password, Salt), Salt
end

local function VerifyPassword(Password: string, StoredHash: buffer, Salt: buffer): boolean
	if #Password < MIN_LENGTH or #Password > MAX_LENGTH then
		return false
	end

	-- Constant time comparison, so response time doesn't leak how much of the hash matched
	return CtCompare(HashWithSalt(Password, Salt), StoredHash)
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
	GenerateSecurePassword = GenerateSecurePassword,
	CreatePasswordHash = CreatePasswordHash,
	VerifyPassword = VerifyPassword,
	CreateStoredPassword = CreateStoredPassword,
	HASH_SIZE = HASH_SIZE,
	SALT_SIZE = SALT_SIZE,
}
