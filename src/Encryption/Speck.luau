--[=[
	Cryptography library: Speck

	⚠️ WARNING: Speck is not very secure!
	For security, use AES or CHACHA20. ⚠️

	Sizes:
		Key: 8 bytes

	Return type: buffer
	Example Usage:
		local Message = buffer.fromstring("Hello World")
		local Key = buffer.fromstring("Key") 

		local Encrypted = Encrypt(Message, Key)
		local Decrypted = Decrypt(Encrypted, Key)
--]=]

--!strict
--!optimize 2
--!native

local Speck = {}

local function EncryptBlocks(CipherBuffer: buffer, PlaintextBuffer: buffer, KeyBuffer: buffer, Length: number): ()
	for Offset = 0, Length - 1, 8 do
		local Y = buffer.readu32(PlaintextBuffer, Offset)
		local X = buffer.readu32(PlaintextBuffer, Offset + 4)

		local B = buffer.readu32(KeyBuffer, 0)
		local A = buffer.readu32(KeyBuffer, 4)

		X = bit32.bxor(bit32.rrotate(X, 8) + Y, B)
		Y = bit32.bxor(bit32.lrotate(Y, 3), X)

		for RoundIndex = 0, 27, 4 do
			A = bit32.bxor(bit32.rrotate(A, 8) + B, RoundIndex)
			B = bit32.bxor(bit32.lrotate(B, 3), A)
			X = bit32.bxor(bit32.rrotate(X, 8) + Y, B)
			Y = bit32.bxor(bit32.lrotate(Y, 3), X)

			A = bit32.bxor(bit32.rrotate(A, 8) + B, RoundIndex + 1)
			B = bit32.bxor(bit32.lrotate(B, 3), A)
			X = bit32.bxor(bit32.rrotate(X, 8) + Y, B)
			Y = bit32.bxor(bit32.lrotate(Y, 3), X)

			A = bit32.bxor(bit32.rrotate(A, 8) + B, RoundIndex + 2)
			B = bit32.bxor(bit32.lrotate(B, 3), A)
			X = bit32.bxor(bit32.rrotate(X, 8) + Y, B)
			Y = bit32.bxor(bit32.lrotate(Y, 3), X)

			A = bit32.bxor(bit32.rrotate(A, 8) + B, RoundIndex + 3)
			B = bit32.bxor(bit32.lrotate(B, 3), A)
			X = bit32.bxor(bit32.rrotate(X, 8) + Y, B)
			Y = bit32.bxor(bit32.lrotate(Y, 3), X)
		end

		A = bit32.bxor(bit32.rrotate(A, 8) + B, 28)
		B = bit32.bxor(bit32.lrotate(B, 3), A)
		X = bit32.bxor(bit32.rrotate(X, 8) + Y, B)
		Y = bit32.bxor(bit32.lrotate(Y, 3), X)

		A = bit32.bxor(bit32.rrotate(A, 8) + B, 29)
		B = bit32.bxor(bit32.lrotate(B, 3), A)
		X = bit32.bxor(bit32.rrotate(X, 8) + Y, B)
		Y = bit32.bxor(bit32.lrotate(Y, 3), X)

		A = bit32.bxor(bit32.rrotate(A, 8) + B, 30)
		B = bit32.bxor(bit32.lrotate(B, 3), A)
		X = bit32.bxor(bit32.rrotate(X, 8) + Y, B)
		Y = bit32.bxor(bit32.lrotate(Y, 3), X)

		buffer.writeu32(CipherBuffer, Offset, Y)
		buffer.writeu32(CipherBuffer, Offset + 4, X)
	end
end

local function DecryptBlocks(PlaintextBuffer: buffer, CipherBuffer: buffer, RoundKeys: buffer, Length: number): ()
	for Offset = 0, Length - 1, 8 do
		local Y = buffer.readu32(CipherBuffer, Offset)
		local X = buffer.readu32(CipherBuffer, Offset + 4)

		for RoundIndex = 27, 0, -4 do
			Y = bit32.rrotate(bit32.bxor(Y, X), 3)
			X = bit32.lrotate(bit32.bxor(X, buffer.readu32(RoundKeys, (RoundIndex + 4) * 4)) - Y, 8)

			Y = bit32.rrotate(bit32.bxor(Y, X), 3)
			X = bit32.lrotate(bit32.bxor(X, buffer.readu32(RoundKeys, (RoundIndex + 3) * 4)) - Y, 8)

			Y = bit32.rrotate(bit32.bxor(Y, X), 3)
			X = bit32.lrotate(bit32.bxor(X, buffer.readu32(RoundKeys, (RoundIndex + 2) * 4)) - Y, 8)

			Y = bit32.rrotate(bit32.bxor(Y, X), 3)
			X = bit32.lrotate(bit32.bxor(X, buffer.readu32(RoundKeys, (RoundIndex + 1) * 4)) - Y, 8)
		end

		Y = bit32.rrotate(bit32.bxor(Y, X), 3)
		X = bit32.lrotate(bit32.bxor(X, buffer.readu32(RoundKeys, 12)) - Y, 8)

		Y = bit32.rrotate(bit32.bxor(Y, X), 3)
		X = bit32.lrotate(bit32.bxor(X, buffer.readu32(RoundKeys, 8)) - Y, 8)

		Y = bit32.rrotate(bit32.bxor(Y, X), 3)
		X = bit32.lrotate(bit32.bxor(X, buffer.readu32(RoundKeys, 4)) - Y, 8)

		Y = bit32.rrotate(bit32.bxor(Y, X), 3)
		X = bit32.lrotate(bit32.bxor(X, buffer.readu32(RoundKeys, 0)) - Y, 8)

		buffer.writeu32(PlaintextBuffer, Offset, Y)
		buffer.writeu32(PlaintextBuffer, Offset + 4, X)
	end
end

local function PadBuffer(InputBuffer: buffer): buffer
	local Length = buffer.len(InputBuffer)
	local Amount = 8 - (Length % 8)
	local PaddedBuffer = buffer.create(Length + Amount)

	buffer.copy(PaddedBuffer, 0, InputBuffer, 0, Length)

	if Amount == 8 then
		buffer.writeu32(PaddedBuffer, Length, 0x08080808)
		buffer.writeu32(PaddedBuffer, Length + 4, 0x08080808)
	elseif Amount == 4 then
		buffer.writeu32(PaddedBuffer, Length, Amount * 0x01010101)
	else
		for Index = Length, Length + Amount - 1 do
			buffer.writeu8(PaddedBuffer, Index, Amount)
		end
	end

	return PaddedBuffer
end

local function UnpadBuffer(InputBuffer: buffer): buffer
	local Length = buffer.len(InputBuffer)
	if Length == 0 then
		return InputBuffer
	end

	local Amount = buffer.readu8(InputBuffer, Length - 1)
	local UnpaddedBuffer = buffer.create(Length - Amount)
	buffer.copy(UnpaddedBuffer, 0, InputBuffer, 0, Length - Amount)

	return UnpaddedBuffer
end

local function PadKey(KeyBuffer: buffer): buffer
	local KeyLength = buffer.len(KeyBuffer)
	local PreparedKey = buffer.create(8)

	if KeyLength >= 8 then
		buffer.writeu32(PreparedKey, 0, buffer.readu32(KeyBuffer, 0))
		buffer.writeu32(PreparedKey, 4, buffer.readu32(KeyBuffer, 4))
	else
		buffer.copy(PreparedKey, 0, KeyBuffer, 0, KeyLength)
		for Index = KeyLength, 7 do
			buffer.writeu8(PreparedKey, Index, 0)
		end
	end

	return PreparedKey
end

local function ExpandKey(KeyBuffer: buffer): buffer
	local B = buffer.readu32(KeyBuffer, 0)
	local A = buffer.readu32(KeyBuffer, 4)

	local RoundKeys = buffer.create(128)
	buffer.writeu32(RoundKeys, 0, B)

	for RoundIndex = 0, 29, 2 do
		A = bit32.bxor(bit32.rrotate(A, 8) + B, RoundIndex)
		B = bit32.bxor(bit32.lrotate(B, 3), A)
		buffer.writeu32(RoundKeys, (RoundIndex + 1) * 4, B)

		A = bit32.bxor(bit32.rrotate(A, 8) + B, RoundIndex + 1)
		B = bit32.bxor(bit32.lrotate(B, 3), A)
		buffer.writeu32(RoundKeys, (RoundIndex + 2) * 4, B)
	end

	A = bit32.bxor(bit32.rrotate(A, 8) + B, 30)
	B = bit32.bxor(bit32.lrotate(B, 3), A)
	buffer.writeu32(RoundKeys, 124, B)

	return RoundKeys
end

function Speck.Encrypt(PlaintextBuffer: buffer, KeyBuffer: buffer): buffer
	local PaddedPlainText = PadBuffer(PlaintextBuffer)
	local PreparedKey = PadKey(KeyBuffer)

	local Length = buffer.len(PaddedPlainText)
	local CipherBuffer = buffer.create(Length)

	EncryptBlocks(CipherBuffer, PaddedPlainText, PreparedKey, Length)
	return CipherBuffer
end

function Speck.Decrypt(CipherBuffer: buffer, KeyBuffer: buffer): buffer
	local PreparedKey = PadKey(KeyBuffer)
	local Length = buffer.len(CipherBuffer)
	local PlainTextBuffer = buffer.create(Length)

	local RoundKeys = ExpandKey(PreparedKey)
	DecryptBlocks(PlainTextBuffer, CipherBuffer, RoundKeys, Length)
	return UnpadBuffer(PlainTextBuffer)
end

return Speck
