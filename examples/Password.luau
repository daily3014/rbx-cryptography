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
		
		With CSPRNG-generated passwords:
		- No dictionary attacks possible (no human patterns)
		- No need for expensive key derivation functions
		- BLAKE3's speed becomes an advantage
		- Users store passwords in their password manager (1Password, Bitwarden, etc.)
	
	Password Requirements:
		- Minimum 24 characters (CSPRNG-generated)
		- Maximum 128 characters
		
	Usage:
		local GeneratedPassword = GenerateSecurePassword(24) -- App generates this locally
		-- User stores GeneratedPassword in their password manager
		local Hash, Salt = CreatePasswordHash(GeneratedPassword)
		local IsValid = VerifyPassword(GeneratedPassword, Hash, Salt)
--]=]

--!strict
--!optimize 2
--!native

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Cryptography = require(ReplicatedStorage:WaitForChild("Cryptography"))
local BLAKE3 = Cryptography.Hashing.Blake3
local CSPRNG = Cryptography.Utilities.CSPRNG
local Conversions = Cryptography.Utilities.Conversions

type PasswordValidationResult = {
	Valid: boolean,
	Errors: {string}
}

type StoredPassword = {
	Hash: buffer,
	Salt: buffer,
	CreatedAt: number
}

local MIN_LENGTH = 24
local MAX_LENGTH = 128
local SALT_SIZE = 32
local HASH_SIZE = 32
local MIN_UNPREDICTABILITY = 6.0

local SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

local function GenerateRandomSalt(): buffer
	return CSPRNG.RandomBytes(SALT_SIZE)
end

local function ConstantTimeEquals(Buffer1: buffer, Buffer2: buffer, Length: number): boolean
	local Result = 0
	for I = 0, Length - 1 do
		local Byte1 = buffer.readu8(Buffer1, I)
		local Byte2 = buffer.readu8(Buffer2, I)
		Result = bit32.bor(Result, bit32.bxor(Byte1, Byte2))
	end

	return Result == 0
end

local function CreatePasswordHash(Password: string): (buffer, buffer)
	local Salt = GenerateRandomSalt()
	local PasswordBuffer = buffer.fromstring(Password)

	local Combined = buffer.create(SALT_SIZE + #Password)
	buffer.copy(Combined, 0, Salt, 0, SALT_SIZE)
	buffer.copy(Combined, SALT_SIZE, PasswordBuffer, 0, #Password)

	local _, Hash = BLAKE3.Digest(Combined)

	return Hash, Salt
end

local function VerifyPassword(Password: string, StoredHash: buffer, Salt: buffer): boolean
	local PasswordBuffer = buffer.fromstring(Password)

	local Combined = buffer.create(SALT_SIZE + #Password)
	buffer.copy(Combined, 0, Salt, 0, SALT_SIZE)
	buffer.copy(Combined, SALT_SIZE, PasswordBuffer, 0, #Password)

	local _, ComputedHash = BLAKE3.Digest(Combined)

	return ConstantTimeEquals(ComputedHash, StoredHash, HASH_SIZE)
end

local function CreateStoredPassword(Password: string): StoredPassword
	local Hash, Salt = CreatePasswordHash(Password)

	return {
		Hash = Hash,
		Salt = Salt,
		CreatedAt = os.time()
	}
end

return {
	CreatePasswordHash = CreatePasswordHash,
	VerifyPassword = VerifyPassword,
	CreateStoredPassword = CreateStoredPassword,
}