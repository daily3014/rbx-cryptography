--[[ Cryptography library: MaskedX25519 Example - Client to Server Key Exchange and Symmetric Key Encryption with Ephemeral Keys ]]--
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

-- Client derives a secret from their masked private key and server's public key
-- The ephemeral key generated during this exchange should only be used once for security
local ClientStatic, ClientEphemeral = MaskedX25519.Exchange(ClientMasked, ServerMaskedPublic)

-- Server derives a secret from their masked private key and client's public key
local ServerStatic, ServerEphemeral = MaskedX25519.Exchange(ServerMasked, ClientMaskedPublic)

local function GetSymmetricKey(ClientEph: buffer, ServerEph: buffer, ClientPub: buffer, ServerPub: buffer)
	local CombinedInput = buffer.create(128)
	
	buffer.copy(CombinedInput, 0, ClientEph, 0, 32)
	buffer.copy(CombinedInput, 32, ServerEph, 0, 32)
	buffer.copy(CombinedInput, 64, ClientPub, 0, 32)
	buffer.copy(CombinedInput, 96, ServerPub, 0, 32)
	
	local KeyMaterial = Blake2b(CombinedInput, 32)
	return FromHex(KeyMaterial)
end

-- Both sides derive the same symmetric key from their ephemeral keys
local SymmetricKey = GetSymmetricKey(ClientEphemeral, ServerEphemeral, ClientMaskedPublic, ServerMaskedPublic)

-- You can now encrypt messages with a symmetric key algorithm of your choice (AEAD, ChaCha20, AES)
Cryptography.Encryption.AEAD.ChaCha20(buffer.fromstring("Hello World"), SymmetricKey, buffer.fromstring("Nonce12Bytes"))

----- Ephemeral key example

-- Remasking will *not* change the public key
ClientMasked = MaskedX25519.Remask(ClientMasked)
ServerMasked = MaskedX25519.Remask(ServerMasked)

local _, ClientEphemeral = MaskedX25519.Exchange(ClientMasked, ServerMaskedPublic)
local _, ServerEphemeral = MaskedX25519.Exchange(ServerMasked, ClientMaskedPublic)

-- We have now "rerolled" the symmetric key while keeping the public keys the same
-- and without ever sharing our private keys
-- The static keys generated earlier can still be used for long-term communication
SymmetricKey = GetSymmetricKey(ClientEphemeral, ServerEphemeral, ClientMaskedPublic, ServerMaskedPublic)

local Message = buffer.fromstring("Hello World")

-- To sign messages, you use the original private key
local ClientSigningPublic = EdDSA.PublicKey(ClientPrivate)
local ClientSignature = EdDSA.Sign(ClientPrivate, ClientSigningPublic, Message)

-- Server verifies the signature with client's public key
assert(EdDSA.Verify(ClientSigningPublic, Message, ClientSignature))

print("Finished")