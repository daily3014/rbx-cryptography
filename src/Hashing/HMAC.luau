--[=[
	Cryptography library: HMAC
	
	Return type: string or function
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Key = buffer.fromstring( "Key" )
		local BlockSize = 64 -- SHA256 block length
		
		--------Usage Case 1--------
		local Result = HMAC(Message, Key, SHA2.SHA256, BlockSize)
	
		--------Usage Case 2----------
		local Preset = PresetHMAC(SHA2.SHA256, BlockSize)
		local Result = Preset(Message, Key)
--]=]

--!native
--!strict
--!optimize 2

export type HashFunction = (Message: buffer, Salt: buffer?) -> string

export type HMAC = (Message: buffer, Key: buffer, HashFunction: HashFunction, BlockSizeBytes: number) -> string
export type PresetHMAC = (Message: buffer, Key: buffer) -> string

local Functions = {}

local function HexToBinary(HexBuffer: buffer)
	local HexBufferLength = buffer.len(HexBuffer)
	
	local Size = bit32.rshift(HexBufferLength, 1)
	local BinaryBuffer = buffer.create(Size)

	for Index = 0, HexBufferLength - 1, 2 do
		local HighByte = buffer.readu8(HexBuffer, Index)
		local LowByte = buffer.readu8(HexBuffer, Index + 1)

		local HexString = string.char(HighByte) .. string.char(LowByte)
		buffer.writeu8(BinaryBuffer, Index // 2, tonumber(HexString, 16) or 0)
	end

	return BinaryBuffer
end

local function FromByteAndSize(Byte: number, Size: number)
	local Buffer = buffer.create(Size)
	buffer.fill(Buffer, 0, Byte)
	return Buffer
end

local function XORBuffer(LeftBuffer, RightBuffer)
	local Size = math.min(buffer.len(LeftBuffer), buffer.len(RightBuffer))
	local NewBuffer = buffer.create(Size)
	
	for Index = 0, Size - 1 do
		local LeftValue = buffer.readu8(LeftBuffer, Index)
		local RightValue = buffer.readu8(RightBuffer, Index)
		buffer.writeu8(NewBuffer, Index, bit32.bxor(LeftValue, RightValue))
	end
	
	return NewBuffer
end

local function ConcatenateBuffers(LeftBuffer, RightBuffer)
	local LeftBufLen = buffer.len(LeftBuffer)
	local Buffer = buffer.create(LeftBufLen + buffer.len(RightBuffer))
	
	buffer.copy(Buffer, 0, LeftBuffer)
	buffer.copy(Buffer, LeftBufLen, RightBuffer)
	
	return Buffer
end

local function ComputeBlockSizedKey(Key: buffer, HashFunction: HashFunction, BlockSizeBytes: number): buffer
	local KeyLength = buffer.len(Key)

	if KeyLength > BlockSizeBytes then
		local HashString = HashFunction(Key)
		local HexBuffer = buffer.fromstring(HashString)
		local HashedKey = HexToBinary(HexBuffer)

		local PaddedKey = buffer.create(BlockSizeBytes)
		buffer.copy(PaddedKey, 0, HashedKey)

		return PaddedKey
	elseif KeyLength < BlockSizeBytes then
		local PaddedKey = buffer.create(BlockSizeBytes)
		buffer.copy(PaddedKey, 0, Key)

		return PaddedKey
	end

	return Key
end

function Functions.HMAC(Message: buffer, Key: buffer, HashFunction: HashFunction, BlockSizeBytes: number): string
	local BlockSizedKey = ComputeBlockSizedKey(Key, HashFunction, BlockSizeBytes)

	local OuterPaddedKey = XORBuffer(BlockSizedKey, FromByteAndSize(0x5C, BlockSizeBytes))
	local InnerPaddedKey = XORBuffer(BlockSizedKey, FromByteAndSize(0x36, BlockSizeBytes))
	
	local HashedMessageWithInnerKey = HexToBinary(buffer.fromstring(HashFunction(ConcatenateBuffers(InnerPaddedKey, Message))))
	local FinalMessage = ConcatenateBuffers(OuterPaddedKey, HashedMessageWithInnerKey)
	return HashFunction(FinalMessage)
end

function Functions.PresetHMAC(HashFunction: HashFunction, BlockSizeBytes: number): PresetHMAC
	return function(Message: buffer, Key: buffer): string
		return Functions.HMAC(Message, Key, HashFunction, BlockSizeBytes)
	end
end
	
return Functions