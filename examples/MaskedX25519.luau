--[=[
	Cryptography library: MaskedX25519 (Double Key Exchange)
	Deniable Encryption - Client to Server Key Exchange with Plausible Deniability

	This library provides plausible deniability by generating two valid shared secrets.
	Under coercion, you can claim either secret was the "real" one used for communication.
--]=]
--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
-- Get the library
local Cryptography = require(ReplicatedStorage:WaitForChild("Cryptography"))

-- Create variables for easy access
local Blake2b = Cryptography.Hashing.Blake2b
local FromHex = Cryptography.Utilities.Conversions.FromHex
local EdDSA = Cryptography.Verification.EdDSA
local MaskedX25519 = EdDSA.MaskedX25519

-- Client
local ClientPrivate = EdDSA.CSPRNG.RandomBytes(32)
local ClientMasked = MaskedX25519.Mask(ClientPrivate)
local ClientMaskedPublic = MaskedX25519.PublicKey(ClientMasked)

-- Server  
local ServerPrivate = EdDSA.CSPRNG.RandomBytes(32)
local ServerMasked = MaskedX25519.Mask(ServerPrivate)
local ServerMaskedPublic = MaskedX25519.PublicKey(ServerMasked)

-- *Client and server exchange keys through RemoteEvents, Attributes, StringValues, etc.*

-- Client derives TWO secrets from their masked private key and server's public key
-- The mask secret provides plausible deniability - both secrets are cryptographically valid
local ClientPrimary, ClientMask = MaskedX25519.Exchange(ClientMasked, ServerMaskedPublic)

-- Server derives the SAME two secrets from their masked private key and client's public key
local ServerPrimary, ServerMask = MaskedX25519.Exchange(ServerMasked, ClientMaskedPublic)

local function GetSymmetricKey(ClientSecret: buffer, ServerSecret: buffer, ClientPub: buffer, ServerPub: buffer)
	local CombinedInput = buffer.create(128)

	buffer.copy(CombinedInput, 0, ClientSecret, 0, 32)
	buffer.copy(CombinedInput, 32, ServerSecret, 0, 32)
	buffer.copy(CombinedInput, 64, ClientPub, 0, 32)
	buffer.copy(CombinedInput, 96, ServerPub, 0, 32)

	local KeyMaterial = Blake2b(CombinedInput, 32)
	return FromHex(KeyMaterial)
end

-- Both sides can derive symmetric keys from EITHER secret pair
local PrimaryKey = GetSymmetricKey(ClientPrimary, ServerPrimary, ClientMaskedPublic, ServerMaskedPublic)
local MaskKey = GetSymmetricKey(ClientMask, ServerMask, ClientMaskedPublic, ServerMaskedPublic)

-- Usage Case 1: Deniable Communication (send both real and cover messages)
local RealMessage = buffer.fromstring("Attack at dawn")
local CoverMessage = buffer.fromstring("Remember homework")

local RealEncrypted = Cryptography.Encryption.AEAD.ChaCha20(RealMessage, PrimaryKey, buffer.fromstring("Nonce12Bytes"))
local CoverEncrypted = Cryptography.Encryption.AEAD.ChaCha20(CoverMessage, MaskKey, buffer.fromstring("Nonce12Byte2"))

-- Send both messages, observer cannot tell which is real
-- Under interrogation: "I was using the mask key for homework discussion!"

-- Usage Case 2: Single Message Deniability
local SensitiveData = buffer.fromstring("Secret information")
local Encrypted = Cryptography.Encryption.AEAD.ChaCha20(SensitiveData, PrimaryKey, buffer.fromstring("Nonce12Bytes"))

-- Under coercion: "I was actually using the mask secret, not the primary secret!"
-- Attacker cannot prove which key was really used

----- Remask example (changes the mask component for new deniability scenarios)
-- Remasking changes the mask component but keeps the same public key
ClientMasked = MaskedX25519.Remask(ClientMasked)
ServerMasked = MaskedX25519.Remask(ServerMasked)

local _, ClientNewMask = MaskedX25519.Exchange(ClientMasked, ServerMaskedPublic)
local _, ServerNewMask = MaskedX25519.Exchange(ServerMasked, ClientMaskedPublic)

-- We now have a NEW mask secret while keeping the same public keys
-- The primary secret remains the same for ongoing communication
local NewMaskKey = GetSymmetricKey(ClientNewMask, ServerNewMask, ClientMaskedPublic, ServerMaskedPublic)

-- To sign messages, you use the original private key (not the masked one)
local ClientSigningPublic = EdDSA.PublicKey(ClientPrivate)
local ClientSignature = EdDSA.Sign(ClientPrivate, ClientSigningPublic, SensitiveData)

-- Server verifies the signature with client's public key
assert(EdDSA.Verify(ClientSigningPublic, SensitiveData, ClientSignature))

print("Deniable encryption setup complete")
