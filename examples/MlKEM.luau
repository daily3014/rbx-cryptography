--!strict
local ReplicatedStorage = game:GetService("ReplicatedStorage")
-- Get the library
local Cryptography = require(ReplicatedStorage:WaitForChild("Cryptography"))
local MlKem = Cryptography.Verification.MlKEM
local CSPRNG = Cryptography.Utilities.CSPRNG

--[[
	ML-KEM stands for:
		Module-Lattice-based
		Key Encapsulation Mechanism
	
	ML-KEM is a post-quantum key encapsulation method from NIST FIPS 203. 
	It allows two parties to establish a shared 32 byte secret 
	that can be used for symmetric encryption.
	
	ML-KEM needs two 32 byte seeds for key generation and does
	encapsulation with a 32 byte message to create a ciphertext and shared secret. 
	The recipient uses their secret key to decapsulate and recover the same shared secret.
--]]

-- Generate keypair using required seeds
local SeedD = CSPRNG.RandomBytes(32)
local SeedZ = CSPRNG.RandomBytes(32)
local PublicKey, SecretKey = MlKem.MLKEM_768.KeyGen(SeedD, SeedZ)

--[[
	ValidateDecapsulationKey checks the integrity of a decapsulation key.
	
	The decapsulation key contains an embedded copy of the public key and
	a hash of that public key. This function recomputes the hash and verifies
	it matches the stored hash, detecting any corruption or tampering.
	
	Per FIPS 203 Section 7.3, this check doesn't need to run on every 
	decapsulation. You can call it once when:
		- Loading a key from storage
		- Receiving a key from another source
		- After key generation (optional, as freshly generated keys are valid)
	
	Returns true if the key is valid, false if corrupted/tampered.
--]]
local IsKeyValid = MlKem.MLKEM_768.ValidateDecapsulationKey(SecretKey)
if not IsKeyValid then
	error("Decapsulation key failed integrity check")
end

-- Encapsulate with 32-byte message
local Message = CSPRNG.RandomBytes(32)
local Ciphertext, SharedSecret = MlKem.MLKEM_768.Encapsulate(PublicKey, Message)

if not Ciphertext or not SharedSecret then
	error("Encapsulation failed")
end

-- Decapsulate to recover shared secret
local RecoveredSecret = MlKem.MLKEM_768.Decapsulate(SecretKey, Ciphertext)

-- Verify secrets match
print("Success:", MlKem.SecretsEqual(SharedSecret, RecoveredSecret))

-- Different security levels
local Pub512, Sec512 = MlKem.MLKEM_512.KeyGen(CSPRNG.RandomBytes(32), CSPRNG.RandomBytes(32))
local Pub1024, Sec1024 = MlKem.MLKEM_1024.KeyGen(CSPRNG.RandomBytes(32), CSPRNG.RandomBytes(32))

-- Key sizes
print("ML-KEM-512 sizes:", buffer.len(Pub512), buffer.len(Sec512))
print("ML-KEM-768 sizes:", buffer.len(PublicKey), buffer.len(SecretKey))
print("ML-KEM-1024 sizes:", buffer.len(Pub1024), buffer.len(Sec1024))
-- Quite big