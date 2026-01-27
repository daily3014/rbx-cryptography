--[=[
	Cryptography library: SHA512

	Sizes:
		Digest: 64 bytes

	Return type: (string, buffer)
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Hash, HashBuffer = SHA512(Message)
--]=]

--!strict
--!optimize 2
--!native

local K_HI = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	0xca273ece, 0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5, 0x113f9804, 0x1b710b35,
	0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 0x431d67c4, 0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c,
}

local K_LO = {
	0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc, 0xf348b538, 0xb605d019, 0xaf194f9b, 0xda6d8118,
	0xa3030242, 0x45706fbe, 0x4ee4b28c, 0xd5ffb4e2, 0xf27b896f, 0x3b1696b1, 0x25c71235, 0xcf692694,
	0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65, 0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5,
	0xee66dfab, 0x2db43210, 0x98fb213f, 0xbeef0ee4, 0x3da88fc2, 0x930aa725, 0xe003826f, 0x0a0e6e70,
	0x46d22ffc, 0x5c26c926, 0x5ac42aed, 0x9d95b3df, 0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
	0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30, 0xd6ef5218, 0x5565a910, 0x5771202a, 0x32bbd1b8,
	0xb8d2d0c8, 0x5141ab53, 0xdf8eeb99, 0xe19b48a8, 0xc5c95a63, 0xe3418acb, 0x7763e373, 0xd6b2b8a3,
	0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec, 0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b,
	0xea26619c, 0x21c0c207, 0xcde0eb1e, 0xee6ed178, 0x72176fba, 0xa2c898a6, 0xbef90dae, 0x131c471b,
	0x23047d84, 0x40c72493, 0x15c9bebc, 0x9c100d4c, 0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817,
}

local W_HI = table.create(80) :: {number}
local W_LO = table.create(80) :: {number}
local DIGEST = buffer.create(64)

local function PreProcess(Contents: buffer): (buffer, number)
	local ContentLength = buffer.len(Contents)
	local Padding = (128 - ((ContentLength + 17) % 128)) % 128
	local NewLength = ContentLength + 1 + Padding + 16

	local Result = buffer.create(NewLength)
	buffer.copy(Result, 0, Contents)
	buffer.writeu8(Result, ContentLength, 0x80)
	buffer.fill(Result, ContentLength + 1, 0, Padding + 8)

	local BitLength = ContentLength * 8
	local LengthOffset = ContentLength + 1 + Padding + 8

	for Index = 7, 0, -1 do
		buffer.writeu8(Result, LengthOffset + Index, BitLength % 256)
		BitLength = BitLength // 256
	end

	return Result, NewLength
end

local function DigestBlocks(Blocks: buffer, Length: number)
	local Hi, Lo = W_HI, W_LO
	local KHi, KLo = K_HI, K_LO

	local H1Hi, H2Hi, H3Hi, H4Hi = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
	local H5Hi, H6Hi, H7Hi, H8Hi = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	local H1Lo, H2Lo, H3Lo, H4Lo = 0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1
	local H5Lo, H6Lo, H7Lo, H8Lo = 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179

	for Offset = 0, Length - 1, 128 do
		for T = 1, 16 do
			local ByteOffset = Offset + (T - 1) * 8
			Hi[T] = bit32.byteswap(buffer.readu32(Blocks, ByteOffset))
			Lo[T] = bit32.byteswap(buffer.readu32(Blocks, ByteOffset + 4))
		end

		for T = 17, 80 do
			local P15Hi, P15Lo = Hi[T - 15], Lo[T - 15]
			local P2Hi, P2Lo = Hi[T - 2], Lo[T - 2]

			local S0Lo = bit32.bxor(bit32.rshift(P15Lo, 1) + bit32.lshift(P15Hi, 31), bit32.rshift(P15Lo, 8) + bit32.lshift(P15Hi, 24), bit32.rshift(P15Lo, 7) + bit32.lshift(P15Hi, 25))
			local S1Lo = bit32.bxor(bit32.rshift(P2Lo, 19) + bit32.lshift(P2Hi, 13), bit32.lshift(P2Lo, 3) + bit32.rshift(P2Hi, 29), bit32.rshift(P2Lo, 6) + bit32.lshift(P2Hi, 26))

			local TmpLo = Lo[T - 16] + S0Lo + Lo[T - 7] + S1Lo
			Lo[T] = bit32.bor(TmpLo, 0)
			Hi[T] = bit32.bxor(bit32.rshift(P15Hi, 1) + bit32.lshift(P15Lo, 31), bit32.rshift(P15Hi, 8) + bit32.lshift(P15Lo, 24), bit32.rshift(P15Hi, 7)) +
				bit32.bxor(bit32.rshift(P2Hi, 19) + bit32.lshift(P2Lo, 13), bit32.lshift(P2Hi, 3) + bit32.rshift(P2Lo, 29), bit32.rshift(P2Hi, 6)) +
				Hi[T - 16] + Hi[T - 7] + TmpLo // 0x100000000
		end

		local AHi, ALo = H1Hi, H1Lo
		local BHi, BLo = H2Hi, H2Lo
		local CHi, CLo = H3Hi, H3Lo
		local DHi, DLo = H4Hi, H4Lo
		local EHi, ELo = H5Hi, H5Lo
		local FHi, FLo = H6Hi, H6Lo
		local GHi, GLo = H7Hi, H7Lo
		local HHi, HLo = H8Hi, H8Lo

		for T = 1, 79, 2 do
			local Sigma1Lo = bit32.bxor(bit32.rshift(ELo, 14) + bit32.lshift(EHi, 18), bit32.rshift(ELo, 18) + bit32.lshift(EHi, 14), bit32.lshift(ELo, 23) + bit32.rshift(EHi, 9))
			local Sigma1Hi = bit32.bxor(bit32.rshift(EHi, 14) + bit32.lshift(ELo, 18), bit32.rshift(EHi, 18) + bit32.lshift(ELo, 14), bit32.lshift(EHi, 23) + bit32.rshift(ELo, 9))
			local Sigma0Lo = bit32.bxor(bit32.rshift(ALo, 28) + bit32.lshift(AHi, 4), bit32.lshift(ALo, 30) + bit32.rshift(AHi, 2), bit32.lshift(ALo, 25) + bit32.rshift(AHi, 7))
			local Sigma0Hi = bit32.bxor(bit32.rshift(AHi, 28) + bit32.lshift(ALo, 4), bit32.lshift(AHi, 30) + bit32.rshift(ALo, 2), bit32.lshift(AHi, 25) + bit32.rshift(ALo, 7))
			local ChLo = bit32.band(ELo, FLo) + bit32.band(-1 - ELo, GLo)
			local ChHi = bit32.band(EHi, FHi) + bit32.band(-1 - EHi, GHi)
			local MajLo = bit32.band(CLo, BLo) + bit32.band(ALo, bit32.bxor(CLo, BLo))
			local MajHi = bit32.band(CHi, BHi) + bit32.band(AHi, bit32.bxor(CHi, BHi))

			local T1Lo = HLo + Sigma1Lo + ChLo + KLo[T] + Lo[T]
			local T1Hi = HHi + Sigma1Hi + ChHi + KHi[T] + Hi[T] + T1Lo // 0x100000000
			T1Lo = bit32.bor(T1Lo, 0)

			HHi, HLo = GHi, GLo
			GHi, GLo = FHi, FLo
			FHi, FLo = EHi, ELo

			local ELoNew = DLo + T1Lo
			EHi = DHi + T1Hi + ELoNew // 0x100000000
			ELo = bit32.bor(ELoNew, 0)

			DHi, DLo = CHi, CLo
			CHi, CLo = BHi, BLo
			BHi, BLo = AHi, ALo

			local ALoNew = T1Lo + Sigma0Lo + MajLo
			AHi = T1Hi + Sigma0Hi + MajHi + ALoNew // 0x100000000
			ALo = bit32.bor(ALoNew, 0)

			local T2 = T + 1
			Sigma1Lo = bit32.bxor(bit32.rshift(ELo, 14) + bit32.lshift(EHi, 18), bit32.rshift(ELo, 18) + bit32.lshift(EHi, 14), bit32.lshift(ELo, 23) + bit32.rshift(EHi, 9))
			Sigma1Hi = bit32.bxor(bit32.rshift(EHi, 14) + bit32.lshift(ELo, 18), bit32.rshift(EHi, 18) + bit32.lshift(ELo, 14), bit32.lshift(EHi, 23) + bit32.rshift(ELo, 9))
			Sigma0Lo = bit32.bxor(bit32.rshift(ALo, 28) + bit32.lshift(AHi, 4), bit32.lshift(ALo, 30) + bit32.rshift(AHi, 2), bit32.lshift(ALo, 25) + bit32.rshift(AHi, 7))
			Sigma0Hi = bit32.bxor(bit32.rshift(AHi, 28) + bit32.lshift(ALo, 4), bit32.lshift(AHi, 30) + bit32.rshift(ALo, 2), bit32.lshift(AHi, 25) + bit32.rshift(ALo, 7))
			ChLo = bit32.band(ELo, FLo) + bit32.band(-1 - ELo, GLo)
			ChHi = bit32.band(EHi, FHi) + bit32.band(-1 - EHi, GHi)
			MajLo = bit32.band(CLo, BLo) + bit32.band(ALo, bit32.bxor(CLo, BLo))
			MajHi = bit32.band(CHi, BHi) + bit32.band(AHi, bit32.bxor(CHi, BHi))

			T1Lo = HLo + Sigma1Lo + ChLo + KLo[T2] + Lo[T2]
			T1Hi = HHi + Sigma1Hi + ChHi + KHi[T2] + Hi[T2] + T1Lo // 0x100000000
			T1Lo = bit32.bor(T1Lo, 0)

			HHi, HLo = GHi, GLo
			GHi, GLo = FHi, FLo
			FHi, FLo = EHi, ELo

			ELoNew = DLo + T1Lo
			EHi = DHi + T1Hi + ELoNew // 0x100000000
			ELo = bit32.bor(ELoNew, 0)

			DHi, DLo = CHi, CLo
			CHi, CLo = BHi, BLo
			BHi, BLo = AHi, ALo

			ALoNew = T1Lo + Sigma0Lo + MajLo
			AHi = T1Hi + Sigma0Hi + MajHi + ALoNew // 0x100000000
			ALo = bit32.bor(ALoNew, 0)
		end

		H1Lo = H1Lo + ALo
		H1Hi = bit32.bor(H1Hi + AHi + H1Lo // 0x100000000, 0)
		H1Lo = bit32.bor(H1Lo, 0)

		H2Lo = H2Lo + BLo
		H2Hi = bit32.bor(H2Hi + BHi + H2Lo // 0x100000000, 0)
		H2Lo = bit32.bor(H2Lo, 0)

		H3Lo = H3Lo + CLo
		H3Hi = bit32.bor(H3Hi + CHi + H3Lo // 0x100000000, 0)
		H3Lo = bit32.bor(H3Lo, 0)

		H4Lo = H4Lo + DLo
		H4Hi = bit32.bor(H4Hi + DHi + H4Lo // 0x100000000, 0)
		H4Lo = bit32.bor(H4Lo, 0)

		H5Lo = H5Lo + ELo
		H5Hi = bit32.bor(H5Hi + EHi + H5Lo // 0x100000000, 0)
		H5Lo = bit32.bor(H5Lo, 0)

		H6Lo = H6Lo + FLo
		H6Hi = bit32.bor(H6Hi + FHi + H6Lo // 0x100000000, 0)
		H6Lo = bit32.bor(H6Lo, 0)

		H7Lo = H7Lo + GLo
		H7Hi = bit32.bor(H7Hi + GHi + H7Lo // 0x100000000, 0)
		H7Lo = bit32.bor(H7Lo, 0)

		H8Lo = H8Lo + HLo
		H8Hi = bit32.bor(H8Hi + HHi + H8Lo // 0x100000000, 0)
		H8Lo = bit32.bor(H8Lo, 0)
	end

	buffer.writeu32(DIGEST, 0, H1Hi)
	buffer.writeu32(DIGEST, 4, H1Lo)
	buffer.writeu32(DIGEST, 8, H2Hi)
	buffer.writeu32(DIGEST, 12, H2Lo)
	buffer.writeu32(DIGEST, 16, H3Hi)
	buffer.writeu32(DIGEST, 20, H3Lo)
	buffer.writeu32(DIGEST, 24, H4Hi)
	buffer.writeu32(DIGEST, 28, H4Lo)
	buffer.writeu32(DIGEST, 32, H5Hi)
	buffer.writeu32(DIGEST, 36, H5Lo)
	buffer.writeu32(DIGEST, 40, H6Hi)
	buffer.writeu32(DIGEST, 44, H6Lo)
	buffer.writeu32(DIGEST, 48, H7Hi)
	buffer.writeu32(DIGEST, 52, H7Lo)
	buffer.writeu32(DIGEST, 56, H8Hi)
	buffer.writeu32(DIGEST, 60, H8Lo)
end

local function SHA512(Message: buffer): (string, buffer)
	local Processed, Length = PreProcess(Message)
	DigestBlocks(Processed, Length)

	local H1Hi, H1Lo = buffer.readu32(DIGEST, 0), buffer.readu32(DIGEST, 4)
	local H2Hi, H2Lo = buffer.readu32(DIGEST, 8), buffer.readu32(DIGEST, 12)
	local H3Hi, H3Lo = buffer.readu32(DIGEST, 16), buffer.readu32(DIGEST, 20)
	local H4Hi, H4Lo = buffer.readu32(DIGEST, 24), buffer.readu32(DIGEST, 28)
	local H5Hi, H5Lo = buffer.readu32(DIGEST, 32), buffer.readu32(DIGEST, 36)
	local H6Hi, H6Lo = buffer.readu32(DIGEST, 40), buffer.readu32(DIGEST, 44)
	local H7Hi, H7Lo = buffer.readu32(DIGEST, 48), buffer.readu32(DIGEST, 52)
	local H8Hi, H8Lo = buffer.readu32(DIGEST, 56), buffer.readu32(DIGEST, 60)

	return string.format(
		"%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		H1Hi, H1Lo, H2Hi, H2Lo, H3Hi, H3Lo, H4Hi, H4Lo,
		H5Hi, H5Lo, H6Hi, H6Lo, H7Hi, H7Lo, H8Hi, H8Lo
	), DIGEST
end

return SHA512