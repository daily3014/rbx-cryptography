--[=[
	Cryptography library: SHA384
	
	Return type: string
	Example usage:
		local Message = buffer.fromstring("Hello World")
		
		--------Usage Case 1--------
		local Result = SHA384(Message)
		
		--------Usage Case 2--------
		local OptionalSalt = buffer.fromstring("Salty")
		local Result = SHA384(Message, OptionalSalt)
--]=]

--!native
--!optimize 2
--!strict

local FRONT_VALUES = buffer.create(32)
local BACK_VALUES = buffer.create(32)

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
	local INITIAL_FRONT = {0xcbbb9d5d, 0x629a292a, 0x9159015a, 0x152fecd8, 0x67332667, 0x8eb44a87, 0xdb0c2e0d, 0x47b5481d}
	local INITIAL_BACK = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4}

	for Index, Value in INITIAL_FRONT do
		buffer.writeu32(FRONT_VALUES, (Index - 1) * 4, Value)
	end

	for Index, Value in INITIAL_BACK do
		buffer.writeu32(BACK_VALUES, (Index - 1) * 4, Value)
	end
end

local function PreProcess(Contents: buffer): (buffer, number)
	local ContentLength = buffer.len(Contents)
	local Padding = (128 - ((ContentLength + 17) % 128)) % 128

	local NewContentLength = ContentLength + 1 + Padding + 16
	local NewContent = buffer.create(NewContentLength)
	buffer.copy(NewContent, 0, Contents)
	buffer.writeu8(NewContent, ContentLength, 0x80)

	local Length8 = ContentLength * 8

	for Index = 0, 7 do
		buffer.writeu8(NewContent, ContentLength + 1 + Padding + Index, 0)
	end

	for Index = 7, 0, -1 do
		local Remainder = Length8 % 256
		buffer.writeu8(NewContent, ContentLength + 1 + Padding + 8 + Index, Remainder)
		Length8 = (Length8 - Remainder) / 256
	end

	return NewContent, NewContentLength
end

local BlockFrontTable = table.create(80)
local BlockBackTable = table.create(80)

local function DigestBlock(Blocks: buffer, Length: number, Digest: buffer)
	local BackK, FrontK = BACKK, FRONTK
	local BlockFront = BlockFrontTable
	local BlockBack = BlockBackTable

	local DefaultFront, DefaultBack = FRONT_VALUES, BACK_VALUES
	local H1F, H2F, H3F, H4F = buffer.readu32(DefaultFront, 0), buffer.readu32(DefaultFront, 4), buffer.readu32(DefaultFront, 8), buffer.readu32(DefaultFront, 12)
	local H5F, H6F, H7F, H8F = buffer.readu32(DefaultFront, 16), buffer.readu32(DefaultFront, 20), buffer.readu32(DefaultFront, 24), buffer.readu32(DefaultFront, 28)
	local H1B, H2B, H3B, H4B = buffer.readu32(DefaultBack, 0), buffer.readu32(DefaultBack, 4), buffer.readu32(DefaultBack, 8), buffer.readu32(DefaultBack, 12)
	local H5B, H6B, H7B, H8B = buffer.readu32(DefaultBack, 16), buffer.readu32(DefaultBack, 20), buffer.readu32(DefaultBack, 24), buffer.readu32(DefaultBack, 28)

	for Offset = 0, Length - 1, 128 do
		for T = 1, 16 do
			BlockFront[T] = bit32.byteswap(buffer.readu32(Blocks, Offset + (T - 1) * 8))
			BlockBack[T] = bit32.byteswap(buffer.readu32(Blocks, Offset + (T - 1) * 8 + 4))
		end

		for T = 17, 80 do
			local FT15, BT15 = BlockFront[T - 15], BlockBack[T - 15]
			local S0Front, S0Back = bit32.bxor(
				bit32.rshift(FT15, 1), bit32.lshift(BT15, 31), 
				bit32.rshift(FT15, 8), bit32.lshift(BT15, 24),
				bit32.rshift(FT15, 7)
			), bit32.bxor(
				bit32.rshift(BT15, 1), bit32.lshift(FT15, 31), 
				bit32.rshift(BT15, 8), bit32.lshift(FT15, 24),
				bit32.rshift(BT15, 7), bit32.lshift(FT15, 25)
			)

			local FT2, BT2 = BlockFront[T - 2], BlockBack[T - 2]
			local S1Front, S1Back = bit32.bxor(
				bit32.rshift(FT2, 19), bit32.lshift(BT2, 13),
				bit32.lshift(FT2, 3), bit32.rshift(BT2, 29),
				bit32.rshift(FT2, 6)
			), bit32.bxor(
				bit32.rshift(BT2, 19), bit32.lshift(FT2, 13),
				bit32.lshift(BT2, 3), bit32.rshift(FT2, 29),
				bit32.rshift(BT2, 6), bit32.lshift(FT2, 26)
			)

			local TempBack = BlockBack[T - 16] + S0Back + BlockBack[T - 7] + S1Back

			BlockBack[T] = bit32.bor(TempBack, 0)
			BlockFront[T] = BlockFront[T - 16] + S0Front + BlockFront[T - 7] + S1Front + TempBack // 2^32
		end

		local AF, AB, BF, BB, CF, CB, DF, DB = H1F, H1B, H2F, H2B, H3F, H3B, H4F, H4B
		local EF, EB, FF, FB, GF, GB, HF, HB = H5F, H5B, H6F, H6B, H7F, H7B, H8F, H8B

		for T = 1, 80 do
			local S1Front, S1Back = bit32.bxor(
				bit32.rshift(EF, 14), bit32.lshift(EB, 18),
				bit32.rshift(EF, 18), bit32.lshift(EB, 14),
				bit32.lshift(EF, 23), bit32.rshift(EB, 9)
			), bit32.bxor(
				bit32.rshift(EB, 14), bit32.lshift(EF, 18),
				bit32.rshift(EB, 18), bit32.lshift(EF, 14),
				bit32.lshift(EB, 23), bit32.rshift(EF, 9)
			)
			local S0Front, S0Back = bit32.bxor(
				bit32.rshift(AF, 28), bit32.lshift(AB, 4),
				bit32.lshift(AF, 30), bit32.rshift(AB, 2),
				bit32.lshift(AF, 25), bit32.rshift(AB, 7)
			), bit32.bxor(
				bit32.rshift(AB, 28), bit32.lshift(AF, 4),
				bit32.lshift(AB, 30), bit32.rshift(AF, 2),
				bit32.lshift(AB, 25), bit32.rshift(AF, 7)
			)

			local Temp1Back = HB + S1Back + bit32.bor(bit32.band(EB, FB), bit32.band(-1 - EB, GB), 0) + BackK[T] + BlockBack[T]
			local Temp1Front = HF + S1Front + bit32.bor(bit32.band(EF, FF), bit32.band(-1 - EF, GF), 0) + FrontK[T] + BlockFront[T] + Temp1Back // 2^32
			Temp1Back = bit32.bor(Temp1Back, 0)

			local Temp2Back = S0Back + bit32.band(CB, BB) + bit32.band(AB, bit32.bxor(CB, BB))
			local Temp2Front = S0Front + bit32.band(CF, BF) + bit32.band(AF, bit32.bxor(CF, BF))

			HF, HB = GF, GB
			GF, GB = FF, FB
			FF, FB = EF, EB

			EB = DB + Temp1Back
			EF = DF + Temp1Front + EB // 2^32
			EB = bit32.bor(EB, 0)

			DF, DB = CF, CB
			CF, CB = BF, BB
			BF, BB = AF, AB

			AB = Temp1Back + Temp2Back
			AF = Temp1Front + Temp2Front + AB // 2^32
			AB = bit32.bor(AB, 0)
		end

		H1B = H1B + AB
		H1F = bit32.bor(H1F + AF + H1B // 2^32, 0)
		H1B = bit32.bor(H1B, 0)

		H2B = H2B + BB
		H2F = bit32.bor(H2F + BF + H2B // 2^32, 0)
		H2B = bit32.bor(H2B, 0)

		H3B = H3B + CB
		H3F = bit32.bor(H3F + CF + H3B // 2^32, 0)
		H3B = bit32.bor(H3B, 0)

		H4B = H4B + DB
		H4F = bit32.bor(H4F + DF + H4B // 2^32, 0)
		H4B = bit32.bor(H4B, 0)

		H5B = H5B + EB
		H5F = bit32.bor(H5F + EF + H5B // 2^32, 0)
		H5B = bit32.bor(H5B, 0)

		H6B = H6B + FB
		H6F = bit32.bor(H6F + FF + H6B // 2^32, 0)
		H6B = bit32.bor(H6B, 0)

		H7B = H7B + GB
		H7F = bit32.bor(H7F + GF + H7B // 2^32, 0)
		H7B = bit32.bor(H7B, 0)

		H8B = H8B + HB
		H8F = bit32.bor(H8F + HF + H8B // 2^32, 0)
		H8B = bit32.bor(H8B, 0)
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

local FormatString = string.rep("%08x", 12)

local function SHA384(Message: buffer, Salt: buffer?): (string, buffer)
	if Salt and buffer.len(Salt) > 0 then
		local MessageWithSalt = buffer.create(buffer.len(Message) + buffer.len(Salt))
		buffer.copy(MessageWithSalt, 0, Message)
		buffer.copy(MessageWithSalt, buffer.len(Message), Salt)
		Message = MessageWithSalt
	end

	local ProcessedMessage, Length = PreProcess(Message)

	local Digest = buffer.create(64)
	DigestBlock(ProcessedMessage, Length, Digest)

	local H1F, H2F, H3F, H4F = buffer.readu32(Digest, 0), buffer.readu32(Digest, 8), buffer.readu32(Digest, 16), buffer.readu32(Digest, 24)
	local H5F, H6F, _, _ = buffer.readu32(Digest, 32), buffer.readu32(Digest, 40), buffer.readu32(Digest, 48), buffer.readu32(Digest, 56)
	local H1B, H2B, H3B, H4B = buffer.readu32(Digest, 4), buffer.readu32(Digest, 12), buffer.readu32(Digest, 20), buffer.readu32(Digest, 28)
	local H5B, H6B, _, _ = buffer.readu32(Digest, 36), buffer.readu32(Digest, 44), buffer.readu32(Digest, 52), buffer.readu32(Digest, 60)

	return string.format(FormatString, H1F, H1B, H2F, H2B, H3F, H3B, H4F, H4B, H5F, H5B, H6F, H6B), Digest
end

return SHA384