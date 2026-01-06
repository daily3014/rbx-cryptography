--[=[
	Cryptography library: SHA1
	
	⚠️ WARNING: SHA1 is cryptographically broken!
	Only use for legacy compatibility, checksums, or non-security purposes.
	For security, use SHA256 or higher. ⚠️

	Sizes:
		Digest: 20 bytes
	
	Return type: string
	Example usage:
		local Message = buffer.fromstring("Hello World")
		
		--------Usage Case 1--------
		local Result = SHA1(Message)
		
		--------Usage Case 2--------
		local OptionalSalt = buffer.fromstring("Salty")
		local Result = SHA1(Message, OptionalSalt)
--]=]

--!strict
--!optimize 2
--!native
local OFFSETS = buffer.create(320)

local function PreProcess(Contents: buffer): (buffer, number)
	local ContentLength = buffer.len(Contents)
	local Padding = (64 - ((ContentLength + 9) % 64)) % 64

	local NewContentLength = ContentLength + 1 + Padding + 8
	local NewContent = buffer.create(NewContentLength)
	buffer.copy(NewContent, 0, Contents)
	buffer.writeu8(NewContent, ContentLength, 128)

	local Length8 = ContentLength * 8
	for Index = 7, 0, -1 do
		local Remainder = Length8 % 256
		buffer.writeu8(NewContent, Index + ContentLength + 1 + Padding, Remainder)
		Length8 = (Length8 - Remainder) / 256
	end

	return NewContent, NewContentLength
end

local function DigestBlocks(Blocks: buffer, Length: number): (number, number, number, number, number)
	local A, B, C, D, E = 0x67452301, 0xefcdaB89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
	local Offsets = OFFSETS

	for Offset = 0, Length - 1, 64 do
		for BlockIndex = 0, 60, 4 do
			buffer.writeu32(Offsets, BlockIndex, bit32.byteswap(buffer.readu32(Blocks, Offset + BlockIndex)))
		end

		for Index = 64, 316, 4 do
			buffer.writeu32(Offsets, Index, bit32.lrotate(bit32.bxor(
				buffer.readu32(Offsets, Index - 12),
				buffer.readu32(Offsets, Index - 32),
				buffer.readu32(Offsets, Index - 56),
				buffer.readu32(Offsets, Index - 64)
			), 1))
		end

		local H1, H2, H3, H4, H5 = A, B, C, D, E
		
		local Temp
		for Round = 0, 19 do
			Temp = bit32.lrotate(H1, 5) +
				bit32.band(H2, H3) + bit32.band(-1 - H2, H4) +
				H5 + 0x5a827999 +
				buffer.readu32(Offsets, Round * 4)
			
			H5, H4, H3, H2, H1 = H4, H3, bit32.lrotate(H2, 30), H1, Temp
		end
		
		for Round = 20, 39 do
			Temp = bit32.lrotate(H1, 5) +
				bit32.bxor(H2, H3, H4) +
				H5 + 0x6ed9eba1 +
				buffer.readu32(Offsets, Round * 4)
			
			H5, H4, H3, H2, H1 = H4, H3, bit32.lrotate(H2, 30), H1, Temp
		end
		
		for Round = 40, 59 do
			Temp = bit32.lrotate(H1, 5) +
				bit32.band(H4, H3) + bit32.band(H2, bit32.bxor(H4, H3)) +
				H5 + 0x8f1bbcdc +
				buffer.readu32(Offsets, Round * 4)
			
			H5, H4, H3, H2, H1 = H4, H3, bit32.lrotate(H2, 30), H1, Temp
		end
		
		for Round = 60, 79 do
			Temp = bit32.lrotate(H1, 5) +
				bit32.bxor(H2, H3, H4) +
				H5 + 0xca62c1d6 +
				buffer.readu32(Offsets, Round * 4)
			
			H5, H4, H3, H2, H1 = H4, H3, bit32.lrotate(H2, 30), H1, Temp
		end

		A = bit32.bor(A + H1, 0)
		B = bit32.bor(B + H2, 0)
		C = bit32.bor(C + H3, 0)
		D = bit32.bor(D + H4, 0)
		E = bit32.bor(E + H5, 0)
	end

	return A, B, C, D, E
end

local function SHA1(Message: buffer, Salt: buffer?): string
	if Salt and buffer.len(Salt) > 0 then
		local MessageWithSalt = buffer.create(buffer.len(Message) + buffer.len(Salt))

		buffer.copy(MessageWithSalt, 0, Message)
		buffer.copy(MessageWithSalt, buffer.len(Message), Salt)

		Message = MessageWithSalt
	end

	local ProcessedMessage, Length = PreProcess(Message)
	return string.format("%08x%08x%08x%08x%08x", DigestBlocks(ProcessedMessage, Length))
end

return SHA1