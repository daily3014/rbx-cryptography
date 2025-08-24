--[=[
	Cryptography library: HMAC
	
	Return type: string or function
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Key = buffer.fromstring("Key")
		local BlockSize = 64 -- SHA256 block length (= string.len(SHA256(...)))
		
		local Result = HMAC(Message, Key, SHA2.SHA256, BlockSize)
--]=]

--!strict
--!optimize 2
--!native

export type HashFunction = (...any) -> (string, buffer)

local function FromByteAndSize(Byte: number, Size: number)
	local Buffer = buffer.create(Size)
	buffer.fill(Buffer, 0, Byte)
	return Buffer
end

local function ToBigEndian(Buffer: buffer)
	for Index = 0, buffer.len(Buffer) - 1, 4 do
		buffer.writeu32(Buffer, Index, bit32.byteswap(buffer.readu32(Buffer, Index)))
	end
end

local function ConcatenateBuffers(LeftBuffer: buffer, RightBuffer: buffer)
	local LeftBufLen = buffer.len(LeftBuffer)
	local Buffer = buffer.create(LeftBufLen + buffer.len(RightBuffer))

	buffer.copy(Buffer, 0, LeftBuffer)
	buffer.copy(Buffer, LeftBufLen, RightBuffer)

	return Buffer
end

local function XORBuffer(LeftBuffer: buffer, RightBuffer: buffer)
	local Size = math.min(buffer.len(LeftBuffer), buffer.len(RightBuffer))
	local NewBuffer = buffer.create(Size)

	for Index = 0, Size - 1 do
		local LeftValue = buffer.readu8(LeftBuffer, Index)
		local RightValue = buffer.readu8(RightBuffer, Index)
		buffer.writeu8(NewBuffer, Index, bit32.bxor(LeftValue, RightValue))
	end

	return NewBuffer
end

local function ComputeBlockSizedKey(Key: buffer, HashFunction: HashFunction, BlockSizeBytes: number): buffer
	local KeyLength = buffer.len(Key)

	if KeyLength > BlockSizeBytes then
		local _, Digest = HashFunction(Key)
		ToBigEndian(Digest)

		local PaddedKey = buffer.create(BlockSizeBytes)
		buffer.copy(PaddedKey, 0, Digest)

		return PaddedKey
	elseif KeyLength < BlockSizeBytes then
		local PaddedKey = buffer.create(BlockSizeBytes)
		buffer.copy(PaddedKey, 0, Key)

		return PaddedKey
	end

	return Key
end

local function HMAC(Message: buffer, Key: buffer, HashFunction: HashFunction, BlockSizeBytes: number): (string, buffer)
	local BlockSizedKey = ComputeBlockSizedKey(Key, HashFunction, BlockSizeBytes)

	local OuterPaddedKey = XORBuffer(BlockSizedKey, FromByteAndSize(0x5C, BlockSizeBytes))
	local InnerPaddedKey = XORBuffer(BlockSizedKey, FromByteAndSize(0x36, BlockSizeBytes))

	local _, HashedMessageWithInnerKey = HashFunction(ConcatenateBuffers(InnerPaddedKey, Message))
	ToBigEndian(HashedMessageWithInnerKey)

	local FinalMessage = ConcatenateBuffers(OuterPaddedKey, HashedMessageWithInnerKey)
	return HashFunction(FinalMessage)
end

return HMAC