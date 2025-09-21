--[=[
	Cryptography library: Simon Cipher 64-bit

	⚠️ WARNING: Simon is not very secure!
	For security, use AES or CHACHA20. ⚠️

	Sizes:
		Key: 16 bytes

	Return type: buffer
	Example Usage:
		local Message = buffer.fromstring("Hello World")
		local Key = buffer.fromstring("MySecretKey12345")
		
		local Encrypted = Encrypt(Message, Key)
		local Decrypted = Decrypt(Encrypted, Key)
--]=]

--!strict
--!optimize 2
--!native

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
	local Key = buffer.create(176)

	buffer.writeu32(Key, 0, buffer.readu32(KeyBuffer, 0))
	buffer.writeu32(Key, 4, buffer.readu32(KeyBuffer, 4))
	buffer.writeu32(Key, 8, buffer.readu32(KeyBuffer, 8))
	buffer.writeu32(Key, 12, buffer.readu32(KeyBuffer, 12))

	for Index = KEY_WORDS, ROUNDS - 1 do
		local PrevKey = buffer.readu32(Key, (Index - 1) * 4)
		local Temp = bit32.bxor(bit32.rrotate(PrevKey, 3), buffer.readu32(Key, (Index - 3) * 4))
		local TempRotated = bit32.rrotate(Temp, 1)

		local C = Z_SEQUENCE[((Index - KEY_WORDS) % 62) + 1]
		buffer.writeu32(Key, Index * 4, bit32.bxor(bit32.bxor(buffer.readu32(Key, (Index - KEY_WORDS) * 4), bit32.bxor(Temp, TempRotated)), bit32.bxor(3, C)))
	end

	return Key
end

local function EncryptBlocks(CipherBuffer: buffer, PlaintextBuffer: buffer, RoundKeys: buffer, Length: number): ()
	for Offset = 0, Length - 1, BLOCK_SIZE do
		local X = buffer.readu32(PlaintextBuffer, Offset)
		local Y = buffer.readu32(PlaintextBuffer, Offset + 4)

		for Round = 0, (ROUNDS - 1) * 4, 16 do
			X, Y = bit32.bxor(Y, bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(X, 1), bit32.lrotate(X, 8)), bit32.lrotate(X, 2)), buffer.readu32(RoundKeys, Round))), X
			X, Y = bit32.bxor(Y, bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(X, 1), bit32.lrotate(X, 8)), bit32.lrotate(X, 2)), buffer.readu32(RoundKeys, Round + 4))), X
			X, Y = bit32.bxor(Y, bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(X, 1), bit32.lrotate(X, 8)), bit32.lrotate(X, 2)), buffer.readu32(RoundKeys, Round + 8))), X
			X, Y = bit32.bxor(Y, bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(X, 1), bit32.lrotate(X, 8)), bit32.lrotate(X, 2)), buffer.readu32(RoundKeys, Round + 12))), X
		end

		buffer.writeu32(CipherBuffer, Offset, X)
		buffer.writeu32(CipherBuffer, Offset + 4, Y)
	end
end

local function DecryptBlocks(PlaintextBuffer: buffer, CipherBuffer: buffer, RoundKeys: buffer, Length: number): ()
	for Offset = 0, Length - 1, BLOCK_SIZE do
		local X = buffer.readu32(CipherBuffer, Offset)
		local Y = buffer.readu32(CipherBuffer, Offset + 4)

		for Round = (ROUNDS - 1) * 4, 0, -16 do
			Y, X = bit32.bxor(X, bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(Y, 1), bit32.lrotate(Y, 8)), bit32.lrotate(Y, 2)), buffer.readu32(RoundKeys, Round))), Y
			Y, X = bit32.bxor(X, bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(Y, 1), bit32.lrotate(Y, 8)), bit32.lrotate(Y, 2)), buffer.readu32(RoundKeys, Round - 4))), Y
			Y, X = bit32.bxor(X, bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(Y, 1), bit32.lrotate(Y, 8)), bit32.lrotate(Y, 2)), buffer.readu32(RoundKeys, Round - 8))), Y
			Y, X = bit32.bxor(X, bit32.bxor(bit32.bxor(bit32.band(bit32.lrotate(Y, 1), bit32.lrotate(Y, 8)), bit32.lrotate(Y, 2)), buffer.readu32(RoundKeys, Round - 12))), Y
		end

		buffer.writeu32(PlaintextBuffer, Offset, X)
		buffer.writeu32(PlaintextBuffer, Offset + 4, Y)
	end
end

local function PadBuffer(InputBuffer: buffer): buffer
	local Length = buffer.len(InputBuffer)
	local Amount = BLOCK_SIZE - (Length % BLOCK_SIZE)
	local PaddedBuffer = buffer.create(Length + Amount)

	buffer.copy(PaddedBuffer, 0, InputBuffer, 0, Length)

	if Amount == 1 then
		buffer.writeu8(PaddedBuffer, Length, Amount)
	elseif Amount == 2 then
		buffer.writeu16(PaddedBuffer, Length, Amount * 0x0101)
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

local function PrepareKey(KeyBuffer: buffer): buffer
	local KeyLength = buffer.len(KeyBuffer)
	local PreparedKey = buffer.create(16)

	if KeyLength >= 16 then
		buffer.writeu32(PreparedKey, 0, buffer.readu32(KeyBuffer, 0))
		buffer.writeu32(PreparedKey, 4, buffer.readu32(KeyBuffer, 4))
		buffer.writeu32(PreparedKey, 8, buffer.readu32(KeyBuffer, 8))
		buffer.writeu32(PreparedKey, 12, buffer.readu32(KeyBuffer, 12))
	else
		buffer.copy(PreparedKey, 0, KeyBuffer, 0, KeyLength)

		for ZeroStart = KeyLength, 15, 4 do
			if ZeroStart + 3 < 16 then
				buffer.writeu32(PreparedKey, ZeroStart, 0)
			else
				for ByteIndex = ZeroStart, 15 do
					buffer.writeu8(PreparedKey, ByteIndex, 0)
				end
				break
			end
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
