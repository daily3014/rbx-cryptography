--[=[
	Cryptography library: SHA512 

	Sizes:
		Digest: 64 bytes
	
	Return type: string
	Example usage:
		local Message = buffer.fromstring("Hello World")
		
		--------Usage Case 1--------
		local Result = SHA512(Message)
		
		--------Usage Case 2--------
		local OptionalSalt = buffer.fromstring("Salty")
		local Result = SHA512(Message, OptionalSalt)
--]=]

--!strict
--!optimize 2
--!native

local FRONT_VALUES = buffer.create(32)
local BACK_VALUES = buffer.create(32)
local WORKING_DIGEST = buffer.create(64)

local FRONTK: {number}, BACKK: {number} do
	FRONTK = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 
		0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 
		0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 
		0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 
		0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 
		0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 
		0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 
		0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 
		0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 
		0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 0xca273ece, 
		0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5, 
		0x113f9804, 0x1b710b35, 0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 
		0x431d67c4, 0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c,
	}

	BACKK = {
		0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc, 0xf348b538,
		0xb605d019, 0xaf194f9b, 0xda6d8118, 0xa3030242, 0x45706fbe,
		0x4ee4b28c, 0xd5ffb4e2, 0xf27b896f, 0x3b1696b1, 0x25c71235,
		0xcf692694, 0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65,
		0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5, 0xee66dfab,
		0x2db43210, 0x98fb213f, 0xbeef0ee4, 0x3da88fc2, 0x930aa725,
		0xe003826f, 0x0a0e6e70, 0x46d22ffc, 0x5c26c926, 0x5ac42aed,
		0x9d95b3df, 0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
		0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30, 0xd6ef5218,
		0x5565a910, 0x5771202a, 0x32bbd1b8, 0xb8d2d0c8, 0x5141ab53,
		0xdf8eeb99, 0xe19b48a8, 0xc5c95a63, 0xe3418acb, 0x7763e373,
		0xd6b2b8a3, 0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec,
		0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b, 0xea26619c,
		0x21c0c207, 0xcde0eb1e, 0xee6ed178, 0x72176fba, 0xa2c898a6,
		0xbef90dae, 0x131c471b, 0x23047d84, 0x40c72493, 0x15c9bebc,
		0x9c100d4c, 0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817,
	}
end

do
	local INITIAL_FRONT = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	local INITIAL_BACK = {0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1, 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179}

	for Index = 1, 8 do
		local Offset = (Index - 1) * 4
		buffer.writeu32(FRONT_VALUES, Offset, INITIAL_FRONT[Index])
		buffer.writeu32(BACK_VALUES, Offset, INITIAL_BACK[Index])
	end
end

local BLOCK_FRONT = table.create(80)
local BLOCK_BACK = table.create(80)

local FORMAT_STRING = string.rep("%08x", 16)

local function PreProcess(Contents: buffer): (buffer, number)
	local ContentLength = buffer.len(Contents)
	local Padding = (128 - ((ContentLength + 17) % 128)) % 128
	local NewContentLength = ContentLength + 1 + Padding + 16

	local NewContent = buffer.create(NewContentLength)
	buffer.copy(NewContent, 0, Contents)
	buffer.writeu8(NewContent, ContentLength, 0x80)

	buffer.fill(NewContent, ContentLength + 1, 0, Padding + 8)

	local Length8 = ContentLength * 8
	local LengthOffset = ContentLength + 1 + Padding + 8

	for Index = 7, 0, -1 do
		buffer.writeu8(NewContent, LengthOffset + Index, Length8 % 256)
		Length8 = Length8 // 256
	end

	return NewContent, NewContentLength
end

local function DigestBlock(Blocks: buffer, Length: number, Digest: buffer)
	local BlockFront, BlockBack = BLOCK_FRONT, BLOCK_BACK
	local FrontK, BackK = FRONTK, BACKK

	local BAND, BOR, XOR = bit32.band, bit32.bor, bit32.bxor
	local ShiftLeft, RightShift = bit32.lshift, bit32.rshift
	local Swap = bit32.byteswap

	local H1F, H2F, H3F, H4F = buffer.readu32(FRONT_VALUES, 0), buffer.readu32(FRONT_VALUES, 4), buffer.readu32(FRONT_VALUES, 8), buffer.readu32(FRONT_VALUES, 12)
	local H5F, H6F, H7F, H8F = buffer.readu32(FRONT_VALUES, 16), buffer.readu32(FRONT_VALUES, 20), buffer.readu32(FRONT_VALUES, 24), buffer.readu32(FRONT_VALUES, 28)
	local H1B, H2B, H3B, H4B = buffer.readu32(BACK_VALUES, 0), buffer.readu32(BACK_VALUES, 4), buffer.readu32(BACK_VALUES, 8), buffer.readu32(BACK_VALUES, 12)
	local H5B, H6B, H7B, H8B = buffer.readu32(BACK_VALUES, 16), buffer.readu32(BACK_VALUES, 20), buffer.readu32(BACK_VALUES, 24), buffer.readu32(BACK_VALUES, 28)

	for Offset = 0, Length - 1, 128 do
		for T = 1, 16 do
			local ByteOffset = Offset + (T - 1) * 8
			BlockFront[T] = Swap(buffer.readu32(Blocks, ByteOffset))
			BlockBack[T] = Swap(buffer.readu32(Blocks, ByteOffset + 4))
		end

		for T = 17, 80 do
			local FT15, BT15 = BlockFront[T - 15], BlockBack[T - 15]

			local S0Front = XOR(RightShift(FT15, 1), ShiftLeft(BT15, 31), RightShift(FT15, 8), ShiftLeft(BT15, 24), RightShift(FT15, 7))
			local S0Back = XOR(RightShift(BT15, 1), ShiftLeft(FT15, 31), RightShift(BT15, 8), ShiftLeft(FT15, 24), RightShift(BT15, 7), ShiftLeft(FT15, 25))

			local FT2, BT2 = BlockFront[T - 2], BlockBack[T - 2]

			local S1Front = XOR(RightShift(FT2, 19), ShiftLeft(BT2, 13), ShiftLeft(FT2, 3), RightShift(BT2, 29), RightShift(FT2, 6))
			local S1Back = XOR(RightShift(BT2, 19), ShiftLeft(FT2, 13), ShiftLeft(BT2, 3), RightShift(FT2, 29), RightShift(BT2, 6), ShiftLeft(FT2, 26))

			local TempBack = BlockBack[T - 16] + S0Back + BlockBack[T - 7] + S1Back
			BlockBack[T] = BOR(TempBack, 0)
			BlockFront[T] = BlockFront[T - 16] + S0Front + BlockFront[T - 7] + S1Front + TempBack // 0x100000000
		end

		local AF, AB = H1F, H1B
		local BF, BB = H2F, H2B
		local CF, CB = H3F, H3B
		local DF, DB = H4F, H4B
		local EF, EB = H5F, H5B
		local FF, FB = H6F, H6B
		local GF, GB = H7F, H7B
		local HF, HB = H8F, H8B

		for T = 1, 80 do
			local S1Front = XOR(RightShift(EF, 14), ShiftLeft(EB, 18), RightShift(EF, 18), ShiftLeft(EB, 14), ShiftLeft(EF, 23), RightShift(EB, 9))
			local S1Back = XOR(RightShift(EB, 14), ShiftLeft(EF, 18), RightShift(EB, 18), ShiftLeft(EF, 14), ShiftLeft(EB, 23), RightShift(EF, 9))

			local S0Front = XOR(RightShift(AF, 28), ShiftLeft(AB, 4), ShiftLeft(AF, 30), RightShift(AB, 2), ShiftLeft(AF, 25), RightShift(AB, 7))
			local S0Back = XOR(RightShift(AB, 28), ShiftLeft(AF, 4), ShiftLeft(AB, 30), RightShift(AF, 2), ShiftLeft(AB, 25), RightShift(AF, 7))

			local ChFront = BOR(BAND(EF, FF), BAND(XOR(EF, 0xFFFFFFFF), GF))
			local ChBack = BOR(BAND(EB, FB), BAND(XOR(EB, 0xFFFFFFFF), GB))

			local MajFront = BAND(CF, BF) + BAND(AF, XOR(CF, BF))
			local MajBack = BAND(CB, BB) + BAND(AB, XOR(CB, BB))

			local Temp1Back = HB + S1Back + ChBack + BackK[T] + BlockBack[T]
			local Temp1Front = HF + S1Front + ChFront + FrontK[T] + BlockFront[T] + Temp1Back // 0x100000000
			Temp1Back = BOR(Temp1Back, 0)

			local Temp2Back = S0Back + MajBack
			local Temp2Front = S0Front + MajFront

			HF, HB = GF, GB
			GF, GB = FF, FB
			FF, FB = EF, EB

			EB = DB + Temp1Back
			EF = DF + Temp1Front + EB // 0x100000000
			EB = BOR(EB, 0)

			DF, DB = CF, CB
			CF, CB = BF, BB
			BF, BB = AF, AB

			AB = Temp1Back + Temp2Back
			AF = Temp1Front + Temp2Front + AB // 0x100000000
			AB = BOR(AB, 0)
		end

		H1B = H1B + AB
		H1F = BOR(H1F + AF + H1B // 0x100000000, 0)
		H1B = BOR(H1B, 0)

		H2B = H2B + BB
		H2F = BOR(H2F + BF + H2B // 0x100000000, 0)
		H2B = BOR(H2B, 0)

		H3B = H3B + CB
		H3F = BOR(H3F + CF + H3B // 0x100000000, 0)
		H3B = BOR(H3B, 0)

		H4B = H4B + DB
		H4F = BOR(H4F + DF + H4B // 0x100000000, 0)
		H4B = BOR(H4B, 0)

		H5B = H5B + EB
		H5F = BOR(H5F + EF + H5B // 0x100000000, 0)
		H5B = BOR(H5B, 0)

		H6B = H6B + FB
		H6F = BOR(H6F + FF + H6B // 0x100000000, 0)
		H6B = BOR(H6B, 0)

		H7B = H7B + GB
		H7F = BOR(H7F + GF + H7B // 0x100000000, 0)
		H7B = BOR(H7B, 0)

		H8B = H8B + HB
		H8F = BOR(H8F + HF + H8B // 0x100000000, 0)
		H8B = BOR(H8B, 0)
	end

	buffer.writeu32(Digest, 0, H1F)
	buffer.writeu32(Digest, 4, H1B)
	buffer.writeu32(Digest, 8, H2F)
	buffer.writeu32(Digest, 12, H2B)
	buffer.writeu32(Digest, 16, H3F)
	buffer.writeu32(Digest, 20, H3B)
	buffer.writeu32(Digest, 24, H4F)
	buffer.writeu32(Digest, 28, H4B)
	buffer.writeu32(Digest, 32, H5F)
	buffer.writeu32(Digest, 36, H5B)
	buffer.writeu32(Digest, 40, H6F)
	buffer.writeu32(Digest, 44, H6B)
	buffer.writeu32(Digest, 48, H7F)
	buffer.writeu32(Digest, 52, H7B)
	buffer.writeu32(Digest, 56, H8F)
	buffer.writeu32(Digest, 60, H8B)
end

local function SHA512(Message: buffer, Salt: buffer?): (string, buffer)
	if Salt and buffer.len(Salt) > 0 then
		local MessageWithSalt = buffer.create(buffer.len(Message) + buffer.len(Salt))
		buffer.copy(MessageWithSalt, 0, Message)
		buffer.copy(MessageWithSalt, buffer.len(Message), Salt)
		Message = MessageWithSalt
	end

	local ProcessedMessage, Length = PreProcess(Message)

	DigestBlock(ProcessedMessage, Length, WORKING_DIGEST)

	local H1F, H1B = buffer.readu32(WORKING_DIGEST, 0), buffer.readu32(WORKING_DIGEST, 4)
	local H2F, H2B = buffer.readu32(WORKING_DIGEST, 8), buffer.readu32(WORKING_DIGEST, 12)
	local H3F, H3B = buffer.readu32(WORKING_DIGEST, 16), buffer.readu32(WORKING_DIGEST, 20)
	local H4F, H4B = buffer.readu32(WORKING_DIGEST, 24), buffer.readu32(WORKING_DIGEST, 28)
	local H5F, H5B = buffer.readu32(WORKING_DIGEST, 32), buffer.readu32(WORKING_DIGEST, 36)
	local H6F, H6B = buffer.readu32(WORKING_DIGEST, 40), buffer.readu32(WORKING_DIGEST, 44)
	local H7F, H7B = buffer.readu32(WORKING_DIGEST, 48), buffer.readu32(WORKING_DIGEST, 52)
	local H8F, H8B = buffer.readu32(WORKING_DIGEST, 56), buffer.readu32(WORKING_DIGEST, 60)

	local ReturnDigest = buffer.create(64)
	buffer.copy(ReturnDigest, 0, WORKING_DIGEST)

	return string.format(FORMAT_STRING, H1F, H1B, H2F, H2B, H3F, H3B, H4F, H4B, H5F, H5B, H6F, H6B, H7F, H7B, H8F, H8B), ReturnDigest
end

return SHA512
