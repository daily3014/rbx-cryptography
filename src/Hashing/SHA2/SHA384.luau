--[=[
	Cryptography library: SHA384

	Sizes:
		Digest: 48 bytes

	Return type: (string, buffer)
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Hash, HashBuffer = SHA384(Message)
--]=]

--!strict
--!optimize 2
--!native

local K_VALUES = {
	0x428a2f98d728ae22i, 0x7137449123ef65cdi, 0xb5c0fbcfec4d3b2fi, 0xe9b5dba58189dbbci,
	0x3956c25bf348b538i, 0x59f111f1b605d019i, 0x923f82a4af194f9bi, 0xab1c5ed5da6d8118i,
	0xd807aa98a3030242i, 0x12835b0145706fbei, 0x243185be4ee4b28ci, 0x550c7dc3d5ffb4e2i,
	0x72be5d74f27b896fi, 0x80deb1fe3b1696b1i, 0x9bdc06a725c71235i, 0xc19bf174cf692694i,
	0xe49b69c19ef14ad2i, 0xefbe4786384f25e3i, 0x0fc19dc68b8cd5b5i, 0x240ca1cc77ac9c65i,
	0x2de92c6f592b0275i, 0x4a7484aa6ea6e483i, 0x5cb0a9dcbd41fbd4i, 0x76f988da831153b5i,
	0x983e5152ee66dfabi, 0xa831c66d2db43210i, 0xb00327c898fb213fi, 0xbf597fc7beef0ee4i,
	0xc6e00bf33da88fc2i, 0xd5a79147930aa725i, 0x06ca6351e003826fi, 0x142929670a0e6e70i,
	0x27b70a8546d22ffci, 0x2e1b21385c26c926i, 0x4d2c6dfc5ac42aedi, 0x53380d139d95b3dfi,
	0x650a73548baf63dei, 0x766a0abb3c77b2a8i, 0x81c2c92e47edaee6i, 0x92722c851482353bi,
	0xa2bfe8a14cf10364i, 0xa81a664bbc423001i, 0xc24b8b70d0f89791i, 0xc76c51a30654be30i,
	0xd192e819d6ef5218i, 0xd69906245565a910i, 0xf40e35855771202ai, 0x106aa07032bbd1b8i,
	0x19a4c116b8d2d0c8i, 0x1e376c085141ab53i, 0x2748774cdf8eeb99i, 0x34b0bcb5e19b48a8i,
	0x391c0cb3c5c95a63i, 0x4ed8aa4ae3418acbi, 0x5b9cca4f7763e373i, 0x682e6ff3d6b2b8a3i,
	0x748f82ee5defb2fci, 0x78a5636f43172f60i, 0x84c87814a1f0ab72i, 0x8cc702081a6439eci,
	0x90befffa23631e28i, 0xa4506cebde82bde9i, 0xbef9a3f7b2c67915i, 0xc67178f2e372532bi,
	0xca273eceea26619ci, 0xd186b8c721c0c207i, 0xeada7dd6cde0eb1ei, 0xf57d4f7fee6ed178i,
	0x06f067aa72176fbai, 0x0a637dc5a2c898a6i, 0x113f9804bef90daei, 0x1b710b35131c471bi,
	0x28db77f523047d84i, 0x32caab7b40c72493i, 0x3c9ebe0a15c9bebci, 0x431d67c49c100d4ci,
	0x4cc5d4becb3e42b6i, 0x597f299cfc657e2ai, 0x5fcb6fab3ad6faeci, 0x6c44198c4a475817i,
}

local K = buffer.create(80 * 8)
for I = 1, 80 do
	buffer.writeinteger(K, (I - 1) * 8, K_VALUES[I])
end

local W = buffer.create(80 * 8)

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

local function DigestBlocks(Blocks: buffer, Length: number): (integer, integer, integer, integer, integer, integer)
	local H1, H2, H3, H4 = 0xcbbb9d5dc1059ed8i, 0x629a292a367cd507i, 0x9159015a3070dd17i, 0x152fecd8f70e5939i
	local H5, H6, H7, H8 = 0x67332667ffc00b31i, 0x8eb44a8768581511i, 0xdb0c2e0d64f98fa7i, 0x47b5481dbefa4fa4i

	for Offset = 0, Length - 1, 128 do
		for T = 0, 15 do
			buffer.writeinteger(W, T * 8, integer.bswap(buffer.readinteger(Blocks, Offset + T * 8)))
		end

		for T = 16, 79 do
			local P15 = buffer.readinteger(W, (T - 15) * 8)
			local P2 = buffer.readinteger(W, (T - 2) * 8)

			local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
			local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))

			buffer.writeinteger(W, T * 8, integer.add(integer.add(buffer.readinteger(W, (T - 16) * 8), S0), integer.add(buffer.readinteger(W, (T - 7) * 8), S1)))
		end

		local A, B, C, D = H1, H2, H3, H4
		local E, F, G, H = H5, H6, H7, H8

		for T = 0, 79 do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))

			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))

			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(K, T * 8), buffer.readinteger(W, T * 8)))
			local T2 = integer.add(Sigma0, Maj)

			H = G
			G = F
			F = E
			E = integer.add(D, T1)
			D = C
			C = B
			B = A
			A = integer.add(T1, T2)
		end

		H1 = integer.add(H1, A)
		H2 = integer.add(H2, B)
		H3 = integer.add(H3, C)
		H4 = integer.add(H4, D)
		H5 = integer.add(H5, E)
		H6 = integer.add(H6, F)
		H7 = integer.add(H7, G)
		H8 = integer.add(H8, H)
	end

	return H1, H2, H3, H4, H5, H6
end

local function SHA384(Message: buffer): (string, buffer)
	local Processed, Length = PreProcess(Message)
	local H1, H2, H3, H4, H5, H6 = DigestBlocks(Processed, Length)

	local Result = buffer.create(48)
	buffer.writeu32(Result, 0,  integer.tonumber(integer.rshift(H1, 32i)))
	buffer.writeu32(Result, 4,  integer.tonumber(integer.band(H1, 0xFFFFFFFFi)))
	buffer.writeu32(Result, 8,  integer.tonumber(integer.rshift(H2, 32i)))
	buffer.writeu32(Result, 12, integer.tonumber(integer.band(H2, 0xFFFFFFFFi)))
	buffer.writeu32(Result, 16, integer.tonumber(integer.rshift(H3, 32i)))
	buffer.writeu32(Result, 20, integer.tonumber(integer.band(H3, 0xFFFFFFFFi)))
	buffer.writeu32(Result, 24, integer.tonumber(integer.rshift(H4, 32i)))
	buffer.writeu32(Result, 28, integer.tonumber(integer.band(H4, 0xFFFFFFFFi)))
	buffer.writeu32(Result, 32, integer.tonumber(integer.rshift(H5, 32i)))
	buffer.writeu32(Result, 36, integer.tonumber(integer.band(H5, 0xFFFFFFFFi)))
	buffer.writeu32(Result, 40, integer.tonumber(integer.rshift(H6, 32i)))
	buffer.writeu32(Result, 44, integer.tonumber(integer.band(H6, 0xFFFFFFFFi)))

	-- TYPE ERROR: string.format definition doesn't support integers yet
	return string.format(
		"%016x%016x%016x%016x%016x%016x",
		H1 :: any, H2 :: any, H3 :: any, H4 :: any, H5 :: any, H6 :: any
	), Result
end

return SHA384
