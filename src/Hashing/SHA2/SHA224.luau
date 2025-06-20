--[=[
	Cryptography library: SHA224
	
	Return type: string
	Example usage:
		local Message = buffer.fromstring("Hello World")
		
		--------Usage Case 1--------
		local Result = SHA224(Message)
		
		--------Usage Case 2--------
		local OptionalSalt = buffer.fromstring("Salty")
		local Result = SHA224(Message, OptionalSalt)
--]=]

--!native
--!optimize 2
--!strict

local CONSTANTS = buffer.create(256) do -- CONSTANTS = k
	local RoundConstants = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	}

	for Index, Constant in ipairs(RoundConstants) do
		local BufferOffset = (Index - 1) * 4
		buffer.writeu32(CONSTANTS, BufferOffset, Constant)
	end
end

local function PreProcess(Content: buffer): (buffer, number)
	local ContentLength = buffer.len(Content)
	local Padding = (64 - ((ContentLength + 9) % 64)) % 64

	local NewContentLength = ContentLength + 1 + Padding + 8
	local NewContent = buffer.create(NewContentLength)
	buffer.copy(NewContent, 0, Content)
	buffer.writeu8(NewContent, ContentLength, 128)
	local Length8 = ContentLength * 8
	for Index = 7, 0, -1 do
		local Remainder = Length8 % 256
		buffer.writeu8(NewContent, Index + ContentLength + 1 + Padding, Remainder)
		Length8 = (Length8 - Remainder) / 256
	end

	return NewContent, NewContentLength
end

local OFFSETS = buffer.create(256)
local function DigestBlocks(Blocks: buffer, Length: number): (number, number, number, number, number, number, number, number)
	local A, B, C, D = 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939
	local E, F, G, H = 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4

	local Offsets = OFFSETS
	local Constants = CONSTANTS

	for Offset = 0, Length - 1, 64 do
		for BlockIndex = 0, 60, 4 do
			local BlockBufferIndex = Offset + BlockIndex
			local Word = bit32.byteswap(buffer.readu32(Blocks, BlockBufferIndex))

			buffer.writeu32(Offsets, BlockIndex, Word)
		end

		for Index = 64, 252, 4 do
			local Sub15 = buffer.readu32(Offsets, Index - 60)
			local Sub2 = buffer.readu32(Offsets, Index - 8)

			local Sub16 = buffer.readu32(Offsets, Index - 64)
			local Sub7 = buffer.readu32(Offsets, Index - 28)


			local S0 = bit32.bxor(bit32.rrotate(Sub15, 7), bit32.rrotate(Sub15, 18), bit32.rshift(Sub15, 3))
			local S1 = bit32.bxor(bit32.rrotate(Sub2, 17), bit32.rrotate(Sub2, 19), bit32.rshift(Sub2, 10))

			buffer.writeu32(Offsets, Index, (Sub16 + S0 + Sub7 + S1))
		end

		local OldA, OldB, OldC, OldD, OldE, OldF, OldG, OldH = A, B, C, D, E, F, G, H

		for BufferIndex = 0, 252, 4 do
			local S1 = bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25))
			local Ch = bit32.bxor(bit32.band(E, F), bit32.band(bit32.bnot(E), G))
			local Temp1 = H + S1 + Ch + buffer.readu32(Constants, BufferIndex) + buffer.readu32(Offsets, BufferIndex)
			local S0 = bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22))
			local Maj = bit32.bxor(bit32.band(A, B), bit32.band(A, C), bit32.band(B, C))
			local Temp2 = S0 + Maj

			H = G
			G = F
			F = E
			E = D + Temp1
			D = C
			C = B
			B = A
			A = Temp1 + Temp2
		end

		A = (A + OldA) % 2^32
		B = (B + OldB) % 2^32
		C = (C + OldC) % 2^32
		D = (D + OldD) % 2^32
		E = (E + OldE) % 2^32
		F = (F + OldF) % 2^32
		G = (G + OldG) % 2^32
		H = (H + OldH) % 2^32
	end

	return A, B, C, D, E, F, G, H
end

local FormatString = string.rep("%08x", 7)
local function SHA224(Message: buffer, Salt: buffer?): (string, buffer)
	if Salt and buffer.len(Salt) > 0 then
		local MessageWithSalt = buffer.create(buffer.len(Message) + buffer.len(Salt))

		buffer.copy(MessageWithSalt, 0, Message)
		buffer.copy(MessageWithSalt, buffer.len(Message), Salt)

		Message = MessageWithSalt
	end

	local ProcessedMessage, Length = PreProcess(Message)
	local A, B, C, D, E, F, G, _ = DigestBlocks(ProcessedMessage, Length)

	local Digest = buffer.create(28)

	buffer.writeu32(Digest, 0, A)
	buffer.writeu32(Digest, 4, B)
	buffer.writeu32(Digest, 8, C)
	buffer.writeu32(Digest, 12, D)
	buffer.writeu32(Digest, 16, E)
	buffer.writeu32(Digest, 20, F)
	buffer.writeu32(Digest, 24, G)

	return string.format(FormatString, A, B, C, D, E, F, G), Digest
end

return SHA224