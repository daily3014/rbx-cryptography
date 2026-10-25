--[=[
	Cryptography library: Ephemeral X25519 Key Exchange
	Forward Secrecy - Client to Server Key Exchange with Ephemeral Keys

	This example shows how to do proper ephemeral key exchange that provides forward secrecy.
	Fresh X25519 keys are generated each session and destroyed after use.
	Even if long-term keys are compromised, past communications remain secure.

	Long-term Ed25519 identity keys sign the ephemeral public keys so each side
	knows who it is talking to (without this, a man in the middle could swap keys).
--]=]
--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
-- Get the library
local Cryptography = require(ReplicatedStorage:WaitForChild("Cryptography"))

-- Create variables for easy access
local Blake3 = Cryptography.Hashing.Blake3
local EdDSA = Cryptography.Verification.EdDSA
local X25519 = EdDSA.X25519
local AEAD = Cryptography.Encryption.AEAD
local CSPRNG = Cryptography.Utilities.CSPRNG
local Concatenate = Cryptography.Utilities.Concatenate

-- Long-term identity keys (persistent across sessions)
local ClientIdentityPrivate = CSPRNG.RandomBytes(32)
local ClientIdentityPublic = EdDSA.PublicKey(ClientIdentityPrivate)

local ServerIdentityPrivate = CSPRNG.RandomBytes(32)
local ServerIdentityPublic = EdDSA.PublicKey(ServerIdentityPrivate)

-- *Client and server exchange identity public keys*

-- Session keys are derived under a fixed context string so they never collide with other uses of the same secret
local DeriveSessionKey = Blake3.DeriveKey(buffer.fromstring("MyGame 2025-01-01 session key"))

local function GetSessionKey(SharedSecret: buffer, ClientPublic: buffer, ServerPublic: buffer): buffer
	local _, SessionKey = DeriveSessionKey(Concatenate(SharedSecret, ClientPublic, ServerPublic), 32)
	return SessionKey
end

local function RunSession(Message: string): (buffer, buffer, buffer, buffer)
	-- Generate fresh ephemeral keys
	local ClientEphemeralPrivate = CSPRNG.RandomBytes(32)
	local ClientEphemeralPublic = X25519.PublicKey(ClientEphemeralPrivate)

	local ServerEphemeralPrivate = CSPRNG.RandomBytes(32)
	local ServerEphemeralPublic = X25519.PublicKey(ServerEphemeralPrivate)

	-- Authentication: each side signs its ephemeral public key with its long-term identity key
	local ClientSignature = EdDSA.Sign(ClientEphemeralPublic, ClientIdentityPrivate, ClientIdentityPublic)
	local ServerSignature = EdDSA.Sign(ServerEphemeralPublic, ServerIdentityPrivate, ServerIdentityPublic)

	-- *Ephemeral public keys and signatures are exchanged*

	-- Each side checks the other's signature before trusting the ephemeral key
	assert(EdDSA.Verify(ClientEphemeralPublic, ClientIdentityPublic, ClientSignature), "Client ephemeral key not signed by client")
	assert(EdDSA.Verify(ServerEphemeralPublic, ServerIdentityPublic, ServerSignature), "Server ephemeral key not signed by server")

	-- Both sides compute the same shared secret without ever sending it
	local ClientShared = X25519.Exchange(ClientEphemeralPrivate, ServerEphemeralPublic)
	local ServerShared = X25519.Exchange(ServerEphemeralPrivate, ClientEphemeralPublic)

	local ClientSessionKey = GetSessionKey(ClientShared, ClientEphemeralPublic, ServerEphemeralPublic)
	local ServerSessionKey = GetSessionKey(ServerShared, ClientEphemeralPublic, ServerEphemeralPublic)

	-- Overwrite ephemeral private keys (the actual forward secrecy)
	buffer.fill(ClientEphemeralPrivate, 0, 0)
	buffer.fill(ServerEphemeralPrivate, 0, 0)

	-- Client encrypts with its session key
	local Nonce = CSPRNG.RandomBytes(12)
	local Encrypted, Tag = AEAD.Encrypt(buffer.fromstring(Message), ClientSessionKey, Nonce)

	return Encrypted, Tag, Nonce, ServerSessionKey
end

-- SESSION 1
local Encrypted1, Tag1, Nonce1, ServerKey1 = RunSession("Session 1 data")

-- SESSION 2: completely new ephemeral keys, so a completely different session key
local Encrypted2, Tag2, Nonce2, ServerKey2 = RunSession("Session 2 data")

-- Server decrypts with the session key it derived on its own
local Decrypted1 = AEAD.Decrypt(Encrypted1, ServerKey1, Nonce1, Tag1)
local Decrypted2 = AEAD.Decrypt(Encrypted2, ServerKey2, Nonce2, Tag2)

assert(Decrypted1 and buffer.tostring(Decrypted1) == "Session 1 data")
assert(Decrypted2 and buffer.tostring(Decrypted2) == "Session 2 data")

-- A session key can't decrypt another session's data
assert(AEAD.Decrypt(Encrypted1, ServerKey2, Nonce1, Tag1) == nil)

print("Forward secrecy key exchange completed")
