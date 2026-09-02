--[=[
	Cryptography library: ChaCha20-Poly1305 AEAD
	
	Sizes:
		Key: 32 bytes
		Nonce: 12 bytes (24 with XChaCha20)
		Tag: 16 bytes
		Rounds: even positive integer (default: 20)
	
	Return type: buffer, buffer (ciphertext, tag)
	Example usage:
		local Plaintext = buffer.fromstring("Hello World")
		local Key = buffer.fromstring(string.rep("k", 32))
		local Nonce = buffer.fromstring(string.rep("n", 12))
		local AAD = buffer.fromstring("additional data")
		
		local Ciphertext, Tag = AEAD.Encrypt(Plaintext, Key, Nonce, AAD, Rounds, UseXChaCha20)
		local DecryptedText = AEAD.Decrypt(Ciphertext, Key, Nonce, Tag, AAD, Rounds, UseXChaCha20)
--]=]

--!strict
--!optimize 2
--!native

local ChaCha = require("@self/ChaCha")
local Poly1305 = require("@self/Poly1305")
local CtCompare = require("../Utilities/Functions").CtCompare

local CHACHA20_KEY_SIZE = 32
local CHACHA20_NONCE_SIZE = 12
local XCHACHA20_NONCE_SIZE = 24
local POLY1305_TAG_SIZE = 16

local AEAD = {
	ChaCha20 = ChaCha.ChaCha20,
	XChaCha20 = ChaCha.XChaCha20,
	Poly1305 = Poly1305.Tag,
	Internal = {
		HChaCha20 = ChaCha.HChaCha20,
	},
}

function AEAD.Encrypt(Message: buffer, Key: buffer, Nonce: buffer, AdditionalAuthData: buffer?, Rounds: number?, UseXChaCha20: boolean?): (buffer, buffer)
	if Message == nil then
		error("Message cannot be nil", 2)
	end

	if typeof(Message) ~= "buffer" then
		error(`Message must be a buffer, got {typeof(Message)}`, 2)
	end

	if Key == nil then
		error("Key cannot be nil", 2)
	end

	if typeof(Key) ~= "buffer" then
		error(`Key must be a buffer, got {typeof(Key)}`, 2)
	end

	local KeyLength = buffer.len(Key)
	if KeyLength ~= CHACHA20_KEY_SIZE then
		error(`Key must be exactly {CHACHA20_KEY_SIZE} bytes long, got {KeyLength} bytes`, 2)
	end

	if Nonce == nil then
		error("Nonce cannot be nil", 2)
	end

	if typeof(Nonce) ~= "buffer" then
		error(`Nonce must be a buffer, got {typeof(Nonce)}`, 2)
	end

	local NonceLength = buffer.len(Nonce)
	local RequiredNonceLength = if UseXChaCha20 then XCHACHA20_NONCE_SIZE else CHACHA20_NONCE_SIZE
	if NonceLength ~= RequiredNonceLength then
		error(`Nonce must be exactly {RequiredNonceLength} bytes long, got {NonceLength} bytes`, 2)
	end

	if AdditionalAuthData then
		if typeof(AdditionalAuthData) ~= "buffer" then
			error(`AdditionalAuthData must be a buffer, got {typeof(AdditionalAuthData)}`, 2)
		end
	end

	if Rounds then
		if typeof(Rounds) ~= "number" then
			error(`Rounds must be a number, got {typeof(Rounds)}`, 2)
		end

		if Rounds <= 0 then
			error(`Rounds must be positive, got {Rounds}`, 2)
		end

		if Rounds % 2 ~= 0 then
			error(`Rounds must be even, got {Rounds}`, 2)
		end
	end

	local BlockRounds = Rounds or 20
	local AAD = AdditionalAuthData or buffer.create(0)

	local State, AuthenticationKey = ChaCha.AeadKeySetup(Key, Nonce, BlockRounds, UseXChaCha20)
	local Ciphertext = ChaCha.AeadCrypt(State, Message, BlockRounds)
	local Tag = Poly1305.AeadTag(AuthenticationKey, AAD, Ciphertext)

	return Ciphertext, Tag
end

function AEAD.Decrypt(Ciphertext: buffer, Key: buffer, Nonce: buffer, Tag: buffer, AdditionalAuthData: buffer?, Rounds: number?, UseXChaCha20: boolean?): buffer?
	if Ciphertext == nil then
		error("Ciphertext cannot be nil", 2)
	end

	if typeof(Ciphertext) ~= "buffer" then
		error(`Ciphertext must be a buffer, got {typeof(Ciphertext)}`, 2)
	end

	if Key == nil then
		error("Key cannot be nil", 2)
	end

	if typeof(Key) ~= "buffer" then
		error(`Key must be a buffer, got {typeof(Key)}`, 2)
	end

	local KeyLength = buffer.len(Key)
	if KeyLength ~= CHACHA20_KEY_SIZE then
		error(`Key must be exactly {CHACHA20_KEY_SIZE} bytes long, got {KeyLength} bytes`, 2)
	end

	if Nonce == nil then
		error("Nonce cannot be nil", 2)
	end

	if typeof(Nonce) ~= "buffer" then
		error(`Nonce must be a buffer, got {typeof(Nonce)}`, 2)
	end

	local NonceLength = buffer.len(Nonce)
	local RequiredNonceLength = if UseXChaCha20 then XCHACHA20_NONCE_SIZE else CHACHA20_NONCE_SIZE
	if NonceLength ~= RequiredNonceLength then
		error(`Nonce must be exactly {RequiredNonceLength} bytes long, got {NonceLength} bytes`, 2)
	end

	if Tag == nil then
		error("Tag cannot be nil", 2)
	end

	if typeof(Tag) ~= "buffer" then
		error(`Tag must be a buffer, got {typeof(Tag)}`, 2)
	end

	local TagLength = buffer.len(Tag)
	if TagLength ~= POLY1305_TAG_SIZE then
		error(`Tag must be exactly {POLY1305_TAG_SIZE} bytes long, got {TagLength} bytes`, 2)
	end

	if AdditionalAuthData then
		if typeof(AdditionalAuthData) ~= "buffer" then
			error(`AdditionalAuthData must be a buffer, got {typeof(AdditionalAuthData)}`, 2)
		end
	end

	if Rounds then
		if typeof(Rounds) ~= "number" then
			error(`Rounds must be a number, got {typeof(Rounds)}`, 2)
		end

		if Rounds <= 0 then
			error(`Rounds must be positive, got {Rounds}`, 2)
		end

		if Rounds % 2 ~= 0 then
			error(`Rounds must be even, got {Rounds}`, 2)
		end
	end

	local BlockRounds = Rounds or 20
	local AAD = AdditionalAuthData or buffer.create(0)

	local State, AuthenticationKey = ChaCha.AeadKeySetup(Key, Nonce, BlockRounds, UseXChaCha20)
	local ExpectedTag = Poly1305.AeadTag(AuthenticationKey, AAD, Ciphertext)

	if not CtCompare(Tag, ExpectedTag) then
		return nil
	end

	return ChaCha.AeadCrypt(State, Ciphertext, BlockRounds)
end

return AEAD