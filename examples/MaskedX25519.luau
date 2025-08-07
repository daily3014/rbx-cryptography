--[=[
	Cryptography library: MaskedX25519 (Double Key Exchange)
	Deniable Encryption: Client to Server Key Exchange with Plausible Deniability

	This library provides plausible deniability by generating two valid shared secrets.
	Under coercion, you can claim either secret was the "real" one used for communication.
--]=]
--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Cryptography = require(ReplicatedStorage:WaitForChild("Cryptography"))

local MaskedX25519 = Cryptography.Verification.EdDSA.MaskedX25519
local AEAD = Cryptography.Encryption.AEAD
local Blake3 = Cryptography.Hashing.Blake3
local Random = Cryptography.Verification.EdDSA.CSPRNG.RandomBytes

-- Alice generates keys
local AlicePrivate = Random(32)
local AliceMasked = MaskedX25519.Mask(AlicePrivate)
local AlicePublic = MaskedX25519.PublicKey(AliceMasked)

-- Bob generates keys
local BobPrivate = Random(32)
local BobMasked = MaskedX25519.Mask(BobPrivate)
local BobPublic = MaskedX25519.PublicKey(BobMasked)

-- Exchange public keys (send these)
-- Both parties get two outputs from the exchange
local AliceShared, AliceMaskSecret = MaskedX25519.Exchange(AliceMasked, BobPublic)
local BobShared, BobMaskSecret = MaskedX25519.Exchange(BobMasked, AlicePublic)

-- Primary shared secrets match
assert(buffer.tostring(AliceShared) == buffer.tostring(BobShared))
-- Mask secrets are different but both are valid
assert(buffer.tostring(AliceMaskSecret) ~= buffer.tostring(BobMaskSecret))

local function DeriveSharedKey(Secret1: buffer, Secret2: buffer, Context: string): buffer
	local combined = buffer.create(64 + #Context)
	buffer.copy(combined, 0, Secret1, 0, 32)
	buffer.copy(combined, 32, Secret2, 0, 32)
	buffer.copy(combined, 64, buffer.fromstring(Context), 0, #Context)

	return select(2, Blake3.Digest(combined, 32))
end

-- Primary channel (uses main shared secret from both parties)
local AlicePrimaryKey = DeriveSharedKey(AliceShared, BobShared, "primary")
local BobPrimaryKey = DeriveSharedKey(AliceShared, BobShared, "primary")

-- Both should have same primary key
assert(buffer.tostring(AlicePrimaryKey) == buffer.tostring(BobPrimaryKey))

-- Cover channel, combines mask secrets from both parties
-- Alice and Bob need to exchange their mask secrets first
--(send AliceMaskSecret to Bob, Bob sends BobMaskSecret to Alice)
-- Derivation makes sure both get same key even with different secrets
local AliceCoverKey = DeriveSharedKey(AliceMaskSecret, BobMaskSecret, "cover")
local BobCoverKey = DeriveSharedKey(AliceMaskSecret, BobMaskSecret, "cover")

-- Now both have the same cover key
assert(buffer.tostring(AliceCoverKey) == buffer.tostring(BobCoverKey))

-- Encrypt messages on both channels with AEAD
local SensitiveMessage = buffer.fromstring("Critical information")
local CoverMessage = buffer.fromstring("Normal conversation")

-- AEAD encryption includes authentication tag
local Nonce1 = Random(12)
local Nonce2 = Random(12)
local AAD = buffer.fromstring("metadata")  -- Additional authenticated data

local SensitiveCiphertext, SensitiveTag = AEAD.Encrypt(SensitiveMessage, AlicePrimaryKey, Nonce1, AAD)
local CoverCiphertext, CoverTag = AEAD.Encrypt(CoverMessage, AliceCoverKey, Nonce2, AAD)

-- Send ciphertext + tag + nonce
-- Sniffer sees two active encrypted channels

-- Decryption with authentication (returns nil if authentication fails)
local DecryptedSensitive = AEAD.Decrypt(SensitiveCiphertext, BobPrimaryKey, Nonce1, SensitiveTag, AAD)
local DecryptedCover = AEAD.Decrypt(CoverCiphertext, BobCoverKey, Nonce2, CoverTag, AAD)
if not DecryptedSensitive then
	error("Primary channel authentication failed")
end

if not DecryptedCover then
	error("Cover channel authentication failed")
end

assert(buffer.tostring(DecryptedSensitive) == buffer.tostring(SensitiveMessage))
assert(buffer.tostring(DecryptedCover) == buffer.tostring(CoverMessage))

-- Deniability scenario:
--Under coercion, reveal only the mask secrets and cover key
--Claim the primary channel is old/test data
--Both channels are cryptographically valid

-- Remasking: Rotate the cover channel while keeping primary unchanged
local AliceRemasked = MaskedX25519.Remask(AliceMasked)
local NewShared, NewMaskSecret = MaskedX25519.Exchange(AliceRemasked, BobPublic)

assert(buffer.tostring(AliceShared) == buffer.tostring(NewShared)) -- Primary unchanged
assert(buffer.tostring(AliceMaskSecret) ~= buffer.tostring(NewMaskSecret)) -- Mask changed

-- Exchange new mask secrets to start new cover channel
-- This allows rotating cover traffic without changing the primary channel

-- For stronger deniability, use with:
--OTR style MAC revelation
--Ephemeral session keys
--Traffic padding
print("MaskedX25519 completed")
