--[=[
	Cryptography library: ChaCha20-Poly1305 AEAD
	
	Sizes:
		Key: 32 bytes
		Nonce: 12 bytes
		Tag: 16 bytes
	
	Return type: buffer, buffer (ciphertext, tag)
	Example usage:
		local Plaintext = buffer.fromstring("Hello World")
		local Key = buffer.fromstring(string.rep("k", 32))
		local Nonce = buffer.fromstring(string.rep("n", 12))
		local AAD = buffer.fromstring("additional data")
		
		--------Usage Case 1--------
		local Ciphertext, Tag = AEAD.Encrypt(Plaintext, Key, Nonce, AAD)
		
		--------Usage Case 2--------
		local DecryptedText = AEAD.Decrypt(Ciphertext, Key, Nonce, Tag, AAD)
--]=]

--!strict
--!optimize 2
--!native

local ChaCha20 = require("@self/ChaCha20")
local Poly1305 = require("@self/Poly1305")

local QWORD = 8

local CHACHA20_KEY_SIZE = 32
local CHACHA20_NONCE_SIZE = 12
local POLY1305_TAG_SIZE = 16

local AEAD = {
	ChaCha20 = ChaCha20,
	Poly1305 = Poly1305
}

local function ConstantTimeCompare(Buffer1: buffer, Buffer2: buffer): boolean
	local Length1 = buffer.len(Buffer1)
	local Length2 = buffer.len(Buffer2)
	if Length1 ~= Length2 then
		return false
	end

	local Difference = 0
	for Index = 0, Length1 - 1 do
		Difference = bit32.bor(Difference, bit32.bxor(
			buffer.readu8(Buffer1, Index),
			buffer.readu8(Buffer2, Index)
			))
	end

	return Difference == 0
end

local function ConstructAuthData(AAD: buffer, Ciphertext: buffer): buffer
	local AADLength = buffer.len(AAD)
	local CiphertextLength = buffer.len(Ciphertext)
	
	local AADPadding = (-AADLength) % 16
	local CiphertextPadding = (-CiphertextLength) % 16
	
	local TotalSize = AADLength + AADPadding + CiphertextLength + CiphertextPadding + 16
	local AuthData = buffer.create(TotalSize)
	local Offset = 0

	buffer.copy(AuthData, Offset, AAD, 0, AADLength)
	Offset += AADLength + AADPadding
	buffer.copy(AuthData, Offset, Ciphertext, 0, CiphertextLength)
	Offset += CiphertextLength + CiphertextPadding
	buffer.writeu32(AuthData, Offset, AADLength)
	buffer.writeu32(AuthData, Offset + QWORD, CiphertextLength)

	return AuthData
end

local function GenerateAuthKey(Key: buffer, Nonce: buffer, Rounds: number?): buffer
	local BlockRounds = Rounds or 20
	local ZeroBlock = buffer.create(32)

	return ChaCha20(ZeroBlock, Key, Nonce, 0, BlockRounds)
end

function AEAD.Encrypt(Message: buffer, Key: buffer, Nonce: buffer, AdditionalAuthData: buffer?, Rounds: number?): (buffer, buffer)
	if Message == nil then
		error("Message cannot be nil", 2)
	end

	if typeof(Message) ~= "buffer" then
		error(`Message must be a buffer, got {typeof(Message)}`, 2)
	end

	local MessageLength = buffer.len(Message)
	if MessageLength == 0 then
		error("Message cannot be empty", 2)
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
	if NonceLength ~= CHACHA20_NONCE_SIZE then
		error(`Nonce must be exactly {CHACHA20_NONCE_SIZE} bytes long, got {NonceLength} bytes`, 2)
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

	local AuthenticationKey = GenerateAuthKey(Key, Nonce, BlockRounds)
	local Ciphertext = ChaCha20(Message, Key, Nonce, 1, BlockRounds)
	local AuthData = ConstructAuthData(AAD, Ciphertext)
	local Tag = Poly1305(AuthData, AuthenticationKey)

	return Ciphertext, Tag
end

function AEAD.Decrypt(Ciphertext: buffer, Key: buffer, Nonce: buffer, Tag: buffer, AdditionalAuthData: buffer?, Rounds: number?): buffer?
	if Ciphertext == nil then
		error("Ciphertext cannot be nil", 2)
	end

	if typeof(Ciphertext) ~= "buffer" then
		error(`Ciphertext must be a buffer, got {typeof(Ciphertext)}`, 2)
	end

	local CiphertextLength = buffer.len(Ciphertext)
	if CiphertextLength == 0 then
		error("Ciphertext cannot be empty", 2)
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
	if NonceLength ~= CHACHA20_NONCE_SIZE then
		error(`Nonce must be exactly {CHACHA20_NONCE_SIZE} bytes long, got {NonceLength} bytes`, 2)
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

	local AuthenticationKey = GenerateAuthKey(Key, Nonce, BlockRounds)
	local AuthData = ConstructAuthData(AAD, Ciphertext)
	local ExpectedTag = Poly1305(AuthData, AuthenticationKey)

	if not ConstantTimeCompare(Tag, ExpectedTag) then
		return nil
	end

	return ChaCha20(Ciphertext, Key, Nonce, 1, BlockRounds)
end

return AEAD