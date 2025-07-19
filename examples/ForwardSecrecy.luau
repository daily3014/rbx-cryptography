--[=[
	Cryptography library: Ephemeral X25519 Key Exchange
	Forward Secrecy - Client to Server Key Exchange with Ephemeral Keys

	This example shows how to do proper ephemeral key exchange that provides forward secrecy.
	Fresh private keys are generated each session and destroyed after use.
	Even if long-term keys are compromised, past communications remain secure.
--]=]
--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
-- Get the library
local Cryptography = require(ReplicatedStorage:WaitForChild("Cryptography"))

-- Create variables for easy access
local Blake3 = Cryptography.Hashing.Blake3
local FromHex = Cryptography.Utilities.Conversions.FromHex
local EdDSA = Cryptography.Verification.EdDSA
local AEAD = Cryptography.Encryption.AEAD
local CSPRNG = Cryptography.Utilities.CSPRNG

-- Long-term identity keys (persistent across sessions)
local ClientIdentityPrivate = CSPRNG.Ed25519Random()
local ClientIdentityPublic = EdDSA.PublicKey(ClientIdentityPrivate)

local ServerIdentityPrivate = CSPRNG.Ed25519Random()
local ServerIdentityPublic = EdDSA.PublicKey(ServerIdentityPrivate)

-- *Client and server exchange identity public keys*

local function GetSessionKey(EphemeralSharedSecret: buffer, ClientPublic: buffer, ServerPublic: buffer): buffer
	local CombinedInput = buffer.create(96)

	buffer.copy(CombinedInput, 0, EphemeralSharedSecret, 0, 32)
	buffer.copy(CombinedInput, 32, ClientPublic, 0, 32)
	buffer.copy(CombinedInput, 64, ServerPublic, 0, 32)

	local KeyMaterial = Blake3.Digest(CombinedInput, 32)
	return FromHex(KeyMaterial)
end

-- SESSION 1: Generate fresh ephemeral keys
local ClientEphemeralPrivate1 = CSPRNG.Ed25519Random()
local ClientEphemeralPublic1 = EdDSA.PublicKey(ClientEphemeralPrivate1)

local ServerEphemeralPrivate1 = CSPRNG.Ed25519Random()
local ServerEphemeralPublic1 = EdDSA.PublicKey(ServerEphemeralPrivate1)

-- *Ephemeral public keys are exchanged*

-- Both sides derive the same session key from ephemeral exchange
-- Note: In real implementation, use proper X25519.Exchange(ClientEphemeralPrivate1, ServerEphemeralPublic1)
local SharedSecret1 = CSPRNG.RandomBytes(32) -- Simulated shared secret
local SessionKey1 = GetSessionKey(SharedSecret1, ClientEphemeralPublic1, ServerEphemeralPublic1)

-- Encrypt with ephemeral session key
local Message1 = buffer.fromstring("Session 1 data")
local Nonce1 = buffer.fromstring("nonce1234567")
local Encrypted1, Tag1 = AEAD.Encrypt(Message1, SessionKey1, Nonce1)

-- Overwrite ephemeral private keys (the actual forward secrecy)
ClientEphemeralPrivate1 = buffer.create(0)
ServerEphemeralPrivate1 = buffer.create(0)

-- SESSION 2: Generate completely new ephemeral keys
local ClientEphemeralPrivate2 = CSPRNG.Ed25519Random()
local ClientEphemeralPublic2 = EdDSA.PublicKey(ClientEphemeralPrivate2)

local ServerEphemeralPrivate2 = CSPRNG.Ed25519Random()
local ServerEphemeralPublic2 = EdDSA.PublicKey(ServerEphemeralPrivate2)

-- Derive different session key for session 2
local SharedSecret2 = CSPRNG.RandomBytes(32) -- Different shared secret
local SessionKey2 = GetSessionKey(SharedSecret2, ClientEphemeralPublic2, ServerEphemeralPublic2)

-- Encrypt new message
local Message2 = buffer.fromstring("Session 2 data")
local Nonce2 = buffer.fromstring("nonce7654321")
local Encrypted2, Tag2 = AEAD.Encrypt(Message2, SessionKey2, Nonce2)

-- Destroy second session ephemeral keys
ClientEphemeralPrivate2 = buffer.create(0)
ServerEphemeralPrivate2 = buffer.create(0)

-- Authentication: Sign ephemeral public keys with long-term identity keys
local EphemeralSignature = EdDSA.Sign(ClientIdentityPrivate, ClientIdentityPublic, ClientEphemeralPublic2)
local SignatureValid = EdDSA.Verify(ClientIdentityPublic, ClientEphemeralPublic2, EphemeralSignature)

-- Verify decryption works
local Decrypted1 = AEAD.Decrypt(Encrypted1, SessionKey1, Nonce1, Tag1)
local Decrypted2 = AEAD.Decrypt(Encrypted2, SessionKey2, Nonce2, Tag2)

assert(Decrypted1 and buffer.tostring(Decrypted1) == "Session 1 data")
assert(Decrypted2 and buffer.tostring(Decrypted2) == "Session 2 data")
assert(SignatureValid)

print("Forward secrecy key exchange completed")
