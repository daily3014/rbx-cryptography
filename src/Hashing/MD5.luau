--[=[
	Cryptography library: MD5
	
	⚠️ WARNING: MD5 is cryptographically broken!
	Only use for legacy compatibility, checksums, or non-security purposes.
	For security, use SHA256 or higher. ⚠️
	
	Return type: string
	Usage:
		local Message = buffer.fromstring("Hello World")
		local Result = MD5(Message)
--]=]

--!native
--!optimize 2
--!strict

local CONSTANTS = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
}

local SHIFTS = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
}

local function PreProcess(Contents: buffer): (buffer, number)
	local ContentLength = buffer.len(Contents)
	local BitLength = ContentLength * 8

	local Padding = (56 - ((ContentLength + 1) % 64)) % 64

	local NewContentLength = ContentLength + 1 + Padding + 8
	local NewContent = buffer.create(NewContentLength)

	buffer.copy(NewContent, 0, Contents)

	buffer.writeu8(NewContent, ContentLength, 0x80)

	local LengthOffset = ContentLength + 1 + Padding
	for Index = 0, 7 do
		local Byte = BitLength % 256
		buffer.writeu8(NewContent, LengthOffset + Index, Byte)
		--BitLength = BitLength // 256
		BitLength = bit32.rshift(BitLength, 8)	
	end

	return NewContent, NewContentLength
end

local OFFSETS = table.create(64)
local function DigestBlocks(Blocks: buffer, Length: number): (number, number, number, number)
	local A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

	local Offsets = OFFSETS
	local Constants = CONSTANTS
	local Shifts = SHIFTS

	for Offset = 0, Length - 1, 64 do
		for WordIndex = 0, 15 do
			local BlockOffset = Offset + WordIndex * 4
			local Word = buffer.readu32(Blocks, BlockOffset)
			Offsets[WordIndex + 1] = Word
		end

		local OldA, OldB, OldC, OldD = A, B, C, D
		local Temp, Func = 0, 0
		for Round = 0, 15 do
			local Chunk = Offsets[Round + 1]
			Func = bit32.bxor(OldD, bit32.band(OldB, bit32.bxor(OldC, OldD)))
			Temp = OldD
			OldD = OldC
			OldC = OldB

			OldB = OldB + bit32.lrotate(OldA + Func + Constants[Round + 1] + Chunk, Shifts[Round + 1])
			OldA = Temp
		end

		for Round = 16, 31 do
			local Chunk = Offsets[(5 * Round + 1) % 16 + 1]
			Func = bit32.bxor(OldC, bit32.band(OldD, bit32.bxor(OldB, OldC)))
			Temp = OldD
			OldD = OldC
			OldC = OldB
			OldB = OldB + bit32.lrotate(OldA + Func + Constants[Round + 1] + Chunk, Shifts[Round + 1])
			OldA = Temp
		end

		for Round = 32, 47 do
			local Chunk = Offsets[(3 * Round + 5) % 16 + 1]
			Func = bit32.bxor(OldB, OldC, OldD)
			Temp = OldD
			OldD = OldC
			OldC = OldB
			OldB = OldB + bit32.lrotate(OldA + Func + Constants[Round + 1] + Chunk, Shifts[Round + 1])
			OldA = Temp
		end

		for Round = 48, 63 do
			local Chunk = Offsets[(7 * Round) % 16 + 1]
			Func = bit32.bxor(OldC, bit32.bor(OldB, bit32.bnot(OldD)))
			Temp = OldD
			OldD = OldC
			OldC = OldB
			OldB = OldB + bit32.lrotate(OldA + Func + Constants[Round + 1] + Chunk, Shifts[Round + 1])
			OldA = Temp
		end

		A = bit32.bor(OldA + A)
		B = bit32.bor(OldB + B)
		C = bit32.bor(OldC + C)
		D = bit32.bor(OldD + D)
	end

	return A, B, C, D	
end

local function MD5(Message: buffer, Salt: buffer?): string
	if Salt and buffer.len(Salt) > 0 then
		local MessageWithSalt = buffer.create(buffer.len(Message) + buffer.len(Salt))
		buffer.copy(MessageWithSalt, 0, Message)
		buffer.copy(MessageWithSalt, buffer.len(Message), Salt)
		Message = MessageWithSalt
	end

	local ProcessedMessage, Length = PreProcess(Message)
	local A, B, C, D = DigestBlocks(ProcessedMessage, Length)

	return string.format("%08x%08x%08x%08x",
		bit32.byteswap(A),
		bit32.byteswap(B),
		bit32.byteswap(C),
		bit32.byteswap(D)
	)
end

return MD5