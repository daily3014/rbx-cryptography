--[=[
	Cryptography library: Simon Cipher 64-bit

	⚠️ WARNING: Speck is not very secure!
	For security, use AES or CHACHA20. ⚠️

	Return type: buffer
	Example Usage:
		local Message = buffer.fromstring("Hello World")
		local Key = buffer.fromstring("MySecretKey12345") -- 16 bytes for 128-bit key
		
		local Encrypted = Encrypt(Message, Key)
		local Decrypted = Decrypt(Encrypted, Key)
--]=]

--!strict
--!native
--!optimize 2

local ROUNDS: number = 44
local KEY_WORDS: number = 4
local BLOCK_SIZE: number = 8

local Z_SEQUENCE: {number} = {
	1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0,
	1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0,
	0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1,
	1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1
}

local Simon = {}

local function GenerateKeySchedule(KeyBuffer: buffer): buffer
	local XOR, ReadWord, WriteWord = bit32.bxor, buffer.readu32, buffer.writeu32

	local Key = buffer.create(176)
	local Sequence = Z_SEQUENCE

	for Index = 0, (KEY_WORDS - 1) * 4, 4 do
		WriteWord(Key, Index, ReadWord(KeyBuffer, Index))
	end

	for Index = KEY_WORDS, ROUNDS - 1 do
		local Temp = XOR(bit32.rrotate(ReadWord(Key, (Index - 1) * 4), 3), ReadWord(Key, (Index - 3) * 4))

		local C = Sequence[((Index - KEY_WORDS) % #Sequence) + 1]
		WriteWord(Key, Index * 4, XOR(XOR(ReadWord(Key, (Index - KEY_WORDS) * 4), XOR(Temp, bit32.rrotate(Temp, 1))), XOR(3, C)))
	end

	return Key
end

local function EncryptBlocks(CipherBuffer: buffer, PlaintextBuffer: buffer, RoundKeys: buffer, Length: number): ()
	local LeftRotate, XOR, AND, ReadWord, WriteWord = bit32.lrotate, bit32.bxor, bit32.band, buffer.readu32, buffer.writeu32

	for Offset = 0, Length - 1, BLOCK_SIZE do
		local X = ReadWord(PlaintextBuffer, Offset)
		local Y = ReadWord(PlaintextBuffer, Offset + 4)

		for Round = 0, (ROUNDS - 1) * 4, 16 do
			X, Y = XOR(Y, XOR(XOR(AND(LeftRotate(X, 1), LeftRotate(X, 8)), LeftRotate(X, 2)), ReadWord(RoundKeys, Round))), X
			X, Y = XOR(Y, XOR(XOR(AND(LeftRotate(X, 1), LeftRotate(X, 8)), LeftRotate(X, 2)), ReadWord(RoundKeys, Round + 4))), X
			X, Y = XOR(Y, XOR(XOR(AND(LeftRotate(X, 1), LeftRotate(X, 8)), LeftRotate(X, 2)), ReadWord(RoundKeys, Round + 8))), X
			X, Y = XOR(Y, XOR(XOR(AND(LeftRotate(X, 1), LeftRotate(X, 8)), LeftRotate(X, 2)), ReadWord(RoundKeys, Round + 12))), X
		end

		WriteWord(CipherBuffer, Offset, X)
		WriteWord(CipherBuffer, Offset + 4, Y)
	end
end

local function DecryptBlocks(PlaintextBuffer: buffer, CipherBuffer: buffer, RoundKeys: buffer, Length: number): ()
	local LeftRotate, XOR, AND, ReadWord, WriteWord = bit32.lrotate, bit32.bxor, bit32.band, buffer.readu32, buffer.writeu32

	for Offset = 0, Length - 1, BLOCK_SIZE do
		local X = ReadWord(CipherBuffer, Offset)
		local Y = ReadWord(CipherBuffer, Offset + 4)

		for Round = (ROUNDS - 1) * 4, 0, -16 do
			Y, X = XOR(X, XOR(XOR(AND(LeftRotate(Y, 1), LeftRotate(Y, 8)), LeftRotate(Y, 2)), ReadWord(RoundKeys, Round))), Y
			Y, X = XOR(X, XOR(XOR(AND(LeftRotate(Y, 1), LeftRotate(Y, 8)), LeftRotate(Y, 2)), ReadWord(RoundKeys, Round - 4))), Y
			Y, X = XOR(X, XOR(XOR(AND(LeftRotate(Y, 1), LeftRotate(Y, 8)), LeftRotate(Y, 2)), ReadWord(RoundKeys, Round - 8))), Y
			Y, X = XOR(X, XOR(XOR(AND(LeftRotate(Y, 1), LeftRotate(Y, 8)), LeftRotate(Y, 2)), ReadWord(RoundKeys, Round - 12))), Y
		end

		WriteWord(PlaintextBuffer, Offset, X)
		WriteWord(PlaintextBuffer, Offset + 4, Y)
	end
end

local function PadBuffer(InputBuffer: buffer): buffer
	local Length = buffer.len(InputBuffer)
	local Amount = BLOCK_SIZE - (Length % BLOCK_SIZE)

	local PaddedBuffer = buffer.create(Length + Amount)
	buffer.copy(PaddedBuffer, 0, InputBuffer, 0, Length)

	for Index = Length, Length + Amount - 1 do
		buffer.writeu8(PaddedBuffer, Index, Amount)
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

local function PrepareKey(KeyBuffer: buffer): buffer
	local KeyLength = buffer.len(KeyBuffer)
	local PreparedKey = buffer.create(16)

	if KeyLength >= 16 then
		buffer.copy(PreparedKey, 0, KeyBuffer, 0, 16)
	else
		buffer.copy(PreparedKey, 0, KeyBuffer, 0, KeyLength)
		for Index = KeyLength, 15 do
			buffer.writeu8(PreparedKey, Index, 0)
		end
	end

	return PreparedKey
end

function Simon.Encrypt(PlaintextBuffer: buffer, KeyBuffer: buffer): buffer
	local PaddedPlaintext = PadBuffer(PlaintextBuffer)
	local PreparedKey = PrepareKey(KeyBuffer)
	local RoundKeys = GenerateKeySchedule(PreparedKey)

	local Length = buffer.len(PaddedPlaintext)
	local CipherBuffer = buffer.create(Length)

	EncryptBlocks(CipherBuffer, PaddedPlaintext, RoundKeys, Length)
	return CipherBuffer
end

function Simon.Decrypt(CipherBuffer: buffer, KeyBuffer: buffer): buffer
	local PreparedKey = PrepareKey(KeyBuffer)
	local RoundKeys = GenerateKeySchedule(PreparedKey)

	local Length = buffer.len(CipherBuffer)
	local PlaintextBuffer = buffer.create(Length)

	DecryptBlocks(PlaintextBuffer, CipherBuffer, RoundKeys, Length)
	return UnpadBuffer(PlaintextBuffer)
end

return Simon