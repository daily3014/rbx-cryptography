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

	if KeyLength == 0 then
		error("Key cannot be empty", 2)
	end

	local OutputBuffer = buffer.create(StringLength)

	local Key = KeyBuffer
	local Period = KeyLength
	if KeyLength % 4 ~= 0 or (KeyLength < 128 and StringLength >= 1024) then
		local Unit = KeyLength
		while Unit % 4 ~= 0 do
			Unit += KeyLength
		end
		Period = Unit * math.max(1, math.ceil(math.min(256, StringLength) / Unit))
		Key = buffer.create(Period)
		buffer.copy(Key, 0, KeyBuffer, 0, KeyLength)
		local Filled = KeyLength
		while Filled < Period do
			local Amount = math.min(Filled, Period - Filled)
			buffer.copy(Key, Filled, Key, 0, Amount)
			Filled += Amount
		end
	end

	local Offset = 0
	while Offset < StringLength do
		local Chunk = math.min(Period, StringLength - Offset)
		local Words = Chunk - Chunk % 4
		local Blocks = Chunk - Chunk % 16

		for Index = 0, Blocks - 16, 16 do
			local Position = Offset + Index
			buffer.writeu32(OutputBuffer, Position, bit32.bxor(buffer.readu32(StringBuffer, Position), buffer.readu32(Key, Index)))
			buffer.writeu32(OutputBuffer, Position + 4, bit32.bxor(buffer.readu32(StringBuffer, Position + 4), buffer.readu32(Key, Index + 4)))
			buffer.writeu32(OutputBuffer, Position + 8, bit32.bxor(buffer.readu32(StringBuffer, Position + 8), buffer.readu32(Key, Index + 8)))
			buffer.writeu32(OutputBuffer, Position + 12, bit32.bxor(buffer.readu32(StringBuffer, Position + 12), buffer.readu32(Key, Index + 12)))
		end

		for Index = Blocks, Words - 4, 4 do
			buffer.writeu32(OutputBuffer, Offset + Index, bit32.bxor(buffer.readu32(StringBuffer, Offset + Index), buffer.readu32(Key, Index)))
		end

		for Index = Words, Chunk - 1 do
			buffer.writeu8(OutputBuffer, Offset + Index, bit32.bxor(buffer.readu8(StringBuffer, Offset + Index), buffer.readu8(Key, Index)))
		end

		Offset += Chunk
	end

	return OutputBuffer
end

return XOR
