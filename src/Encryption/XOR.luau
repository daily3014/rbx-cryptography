--[=[
	Cryptography library: XOR Symmetric Cipher

	⚠️ WARNING: XOR is not cryptographically secure!
	Do not use the same key twice!
	For security, use AES or CHACHA20. ⚠️

	Return type: buffer 
	Example Usage:
		local Message = buffer.fromstring("Hello World")
		local Key = buffer.fromstring("MySecretKey12345") -- Fastest when its a multiple of 4 or is longer than the message
		
		local Encrypted = XOR(Message, Key)
		local Decrypted = XOR(Encrypted, Key) 
--]=]

--!strict
--!optimize 2
--!native

local function XOR(StringBuffer: buffer, KeyBuffer: buffer): buffer
	local StringLength = buffer.len(StringBuffer)
	local KeyLength = buffer.len(KeyBuffer)

	local OutputBuffer = buffer.create(StringLength)
	buffer.copy(OutputBuffer, 0, StringBuffer, 0, StringLength)

	if KeyLength == 1 then
		local KeyByte = buffer.readu8(KeyBuffer, 0)
		local KeyWord = bit32.bor(
			KeyByte,
			bit32.lshift(KeyByte, 8),
			bit32.lshift(KeyByte, 16),
			bit32.lshift(KeyByte, 24)
		)
		
		local Offset = 0
		while Offset + 3 < StringLength do
			buffer.writeu32(OutputBuffer, Offset, bit32.bxor(buffer.readu32(OutputBuffer, Offset), KeyWord))
			Offset += 4
		end
		
		while Offset < StringLength do
			buffer.writeu8(OutputBuffer, Offset, bit32.bxor(buffer.readu8(OutputBuffer, Offset), KeyByte))
			Offset += 1
		end
		
		return OutputBuffer
	end

	if KeyLength == 4 then
		local KeyWord = buffer.readu32(KeyBuffer, 0)
		local Offset = 0
		while Offset + 3 < StringLength do
			buffer.writeu32(OutputBuffer, Offset, bit32.bxor(buffer.readu32(OutputBuffer, Offset), KeyWord))
			Offset += 4
		end
		
		for Index = 0, StringLength - Offset - 1 do
			local ByteOffset = Offset + Index
			buffer.writeu8(OutputBuffer, ByteOffset, bit32.bxor(
				buffer.readu8(OutputBuffer, ByteOffset),
				buffer.readu8(KeyBuffer, Index)
				))
		end
		
		return OutputBuffer
	end

	local ExtendedKeyLength = math.min(StringLength, KeyLength * 256)
	local ExtendedKeyBuffer = buffer.create(ExtendedKeyLength)

	local Pos = 0 
	while Pos < ExtendedKeyLength do
		local CopyLen = math.min(KeyLength, ExtendedKeyLength - Pos)
		buffer.copy(ExtendedKeyBuffer, Pos, KeyBuffer, 0, CopyLen)
		Pos += CopyLen
	end

	local StringOffset = 0
	while StringOffset < StringLength do
		local ChunkSize = math.min(ExtendedKeyLength, StringLength - StringOffset)
		local KeyOffset = 0

		while KeyOffset + 3 < ChunkSize and StringOffset + KeyOffset + 3 < StringLength do
			local Offset = StringOffset + KeyOffset
			buffer.writeu32(OutputBuffer, Offset, bit32.bxor(
				buffer.readu32(OutputBuffer, Offset),
				buffer.readu32(ExtendedKeyBuffer, KeyOffset)
				))
			KeyOffset += 4
		end

		while KeyOffset < ChunkSize and StringOffset + KeyOffset < StringLength do
			local Offset = StringOffset + KeyOffset
			buffer.writeu8(OutputBuffer, Offset, bit32.bxor(
				buffer.readu8(OutputBuffer, Offset),
				buffer.readu8(ExtendedKeyBuffer, KeyOffset)
				))
			KeyOffset += 1
		end

		StringOffset += ChunkSize
	end

	return OutputBuffer
end

return XOR