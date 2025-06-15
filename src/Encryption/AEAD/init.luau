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
		
		--------Encryption--------
		local Ciphertext, Tag = AEAD.Encrypt(Plaintext, Key, Nonce, AAD)
		
		--------Decryption--------
		local DecryptedText = AEAD.Decrypt(Ciphertext, Key, Nonce, Tag, AAD)
--]=]

--!strict
--!native
--!optimize 2


local ChaCha20 = require("@self/ChaCha20")
local Poly1305 = require("@self/Poly1305")

local AEAD = {
	ChaCha20 = ChaCha20,
	Poly1305 = Poly1305
}

local QWORD = 8

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

	buffer.writef64(AuthData, Offset, AADLength)
	buffer.writef64(AuthData, Offset + QWORD, CiphertextLength)

	return AuthData
end

local function GenerateAuthKey(Key: buffer, Nonce: buffer, Rounds: number?): buffer
	local BlockRounds = Rounds or 20
	local ZeroBlock = buffer.create(32)

	return ChaCha20(ZeroBlock, Key, Nonce, 0, BlockRounds)
end

function AEAD.Encrypt(Message: buffer, Key: buffer, Nonce: buffer, AdditionalAuthData: buffer?, Rounds: number?): (buffer, buffer)
	local BlockRounds = Rounds or 20
	local AAD = AdditionalAuthData or buffer.create(0)

	local AuthenticationKey = GenerateAuthKey(Key, Nonce, BlockRounds)
	local Ciphertext = ChaCha20(Message, Key, Nonce, 1, BlockRounds)

	local AuthData = ConstructAuthData(AAD, Ciphertext)

	local Tag = Poly1305(AuthData, AuthenticationKey)

	return Ciphertext, Tag
end

function AEAD.Decrypt(Ciphertext: buffer, Key: buffer, Nonce: buffer, Tag: buffer, AdditionalAuthData: buffer?, Rounds: number?): buffer?
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