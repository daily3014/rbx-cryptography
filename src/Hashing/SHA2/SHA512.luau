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

local Conversions = require("../../Utilities/Conversions")
local ToHex = Conversions.ToHex

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

local function ProcessSchedule(LW: buffer)
	do
		local P15 = buffer.readinteger(LW, 8)
		local P2 = buffer.readinteger(LW, 112)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 128, integer.add(integer.add(buffer.readinteger(LW, 0), S0), integer.add(buffer.readinteger(LW, 72), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 16)
		local P2 = buffer.readinteger(LW, 120)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 136, integer.add(integer.add(buffer.readinteger(LW, 8), S0), integer.add(buffer.readinteger(LW, 80), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 24)
		local P2 = buffer.readinteger(LW, 128)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 144, integer.add(integer.add(buffer.readinteger(LW, 16), S0), integer.add(buffer.readinteger(LW, 88), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 32)
		local P2 = buffer.readinteger(LW, 136)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 152, integer.add(integer.add(buffer.readinteger(LW, 24), S0), integer.add(buffer.readinteger(LW, 96), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 40)
		local P2 = buffer.readinteger(LW, 144)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 160, integer.add(integer.add(buffer.readinteger(LW, 32), S0), integer.add(buffer.readinteger(LW, 104), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 48)
		local P2 = buffer.readinteger(LW, 152)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 168, integer.add(integer.add(buffer.readinteger(LW, 40), S0), integer.add(buffer.readinteger(LW, 112), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 56)
		local P2 = buffer.readinteger(LW, 160)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 176, integer.add(integer.add(buffer.readinteger(LW, 48), S0), integer.add(buffer.readinteger(LW, 120), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 64)
		local P2 = buffer.readinteger(LW, 168)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 184, integer.add(integer.add(buffer.readinteger(LW, 56), S0), integer.add(buffer.readinteger(LW, 128), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 72)
		local P2 = buffer.readinteger(LW, 176)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 192, integer.add(integer.add(buffer.readinteger(LW, 64), S0), integer.add(buffer.readinteger(LW, 136), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 80)
		local P2 = buffer.readinteger(LW, 184)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 200, integer.add(integer.add(buffer.readinteger(LW, 72), S0), integer.add(buffer.readinteger(LW, 144), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 88)
		local P2 = buffer.readinteger(LW, 192)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 208, integer.add(integer.add(buffer.readinteger(LW, 80), S0), integer.add(buffer.readinteger(LW, 152), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 96)
		local P2 = buffer.readinteger(LW, 200)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 216, integer.add(integer.add(buffer.readinteger(LW, 88), S0), integer.add(buffer.readinteger(LW, 160), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 104)
		local P2 = buffer.readinteger(LW, 208)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 224, integer.add(integer.add(buffer.readinteger(LW, 96), S0), integer.add(buffer.readinteger(LW, 168), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 112)
		local P2 = buffer.readinteger(LW, 216)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 232, integer.add(integer.add(buffer.readinteger(LW, 104), S0), integer.add(buffer.readinteger(LW, 176), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 120)
		local P2 = buffer.readinteger(LW, 224)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 240, integer.add(integer.add(buffer.readinteger(LW, 112), S0), integer.add(buffer.readinteger(LW, 184), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 128)
		local P2 = buffer.readinteger(LW, 232)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 248, integer.add(integer.add(buffer.readinteger(LW, 120), S0), integer.add(buffer.readinteger(LW, 192), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 136)
		local P2 = buffer.readinteger(LW, 240)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 256, integer.add(integer.add(buffer.readinteger(LW, 128), S0), integer.add(buffer.readinteger(LW, 200), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 144)
		local P2 = buffer.readinteger(LW, 248)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 264, integer.add(integer.add(buffer.readinteger(LW, 136), S0), integer.add(buffer.readinteger(LW, 208), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 152)
		local P2 = buffer.readinteger(LW, 256)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 272, integer.add(integer.add(buffer.readinteger(LW, 144), S0), integer.add(buffer.readinteger(LW, 216), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 160)
		local P2 = buffer.readinteger(LW, 264)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 280, integer.add(integer.add(buffer.readinteger(LW, 152), S0), integer.add(buffer.readinteger(LW, 224), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 168)
		local P2 = buffer.readinteger(LW, 272)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 288, integer.add(integer.add(buffer.readinteger(LW, 160), S0), integer.add(buffer.readinteger(LW, 232), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 176)
		local P2 = buffer.readinteger(LW, 280)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 296, integer.add(integer.add(buffer.readinteger(LW, 168), S0), integer.add(buffer.readinteger(LW, 240), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 184)
		local P2 = buffer.readinteger(LW, 288)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 304, integer.add(integer.add(buffer.readinteger(LW, 176), S0), integer.add(buffer.readinteger(LW, 248), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 192)
		local P2 = buffer.readinteger(LW, 296)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 312, integer.add(integer.add(buffer.readinteger(LW, 184), S0), integer.add(buffer.readinteger(LW, 256), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 200)
		local P2 = buffer.readinteger(LW, 304)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 320, integer.add(integer.add(buffer.readinteger(LW, 192), S0), integer.add(buffer.readinteger(LW, 264), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 208)
		local P2 = buffer.readinteger(LW, 312)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 328, integer.add(integer.add(buffer.readinteger(LW, 200), S0), integer.add(buffer.readinteger(LW, 272), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 216)
		local P2 = buffer.readinteger(LW, 320)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 336, integer.add(integer.add(buffer.readinteger(LW, 208), S0), integer.add(buffer.readinteger(LW, 280), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 224)
		local P2 = buffer.readinteger(LW, 328)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 344, integer.add(integer.add(buffer.readinteger(LW, 216), S0), integer.add(buffer.readinteger(LW, 288), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 232)
		local P2 = buffer.readinteger(LW, 336)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 352, integer.add(integer.add(buffer.readinteger(LW, 224), S0), integer.add(buffer.readinteger(LW, 296), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 240)
		local P2 = buffer.readinteger(LW, 344)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 360, integer.add(integer.add(buffer.readinteger(LW, 232), S0), integer.add(buffer.readinteger(LW, 304), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 248)
		local P2 = buffer.readinteger(LW, 352)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 368, integer.add(integer.add(buffer.readinteger(LW, 240), S0), integer.add(buffer.readinteger(LW, 312), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 256)
		local P2 = buffer.readinteger(LW, 360)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 376, integer.add(integer.add(buffer.readinteger(LW, 248), S0), integer.add(buffer.readinteger(LW, 320), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 264)
		local P2 = buffer.readinteger(LW, 368)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 384, integer.add(integer.add(buffer.readinteger(LW, 256), S0), integer.add(buffer.readinteger(LW, 328), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 272)
		local P2 = buffer.readinteger(LW, 376)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 392, integer.add(integer.add(buffer.readinteger(LW, 264), S0), integer.add(buffer.readinteger(LW, 336), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 280)
		local P2 = buffer.readinteger(LW, 384)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 400, integer.add(integer.add(buffer.readinteger(LW, 272), S0), integer.add(buffer.readinteger(LW, 344), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 288)
		local P2 = buffer.readinteger(LW, 392)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 408, integer.add(integer.add(buffer.readinteger(LW, 280), S0), integer.add(buffer.readinteger(LW, 352), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 296)
		local P2 = buffer.readinteger(LW, 400)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 416, integer.add(integer.add(buffer.readinteger(LW, 288), S0), integer.add(buffer.readinteger(LW, 360), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 304)
		local P2 = buffer.readinteger(LW, 408)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 424, integer.add(integer.add(buffer.readinteger(LW, 296), S0), integer.add(buffer.readinteger(LW, 368), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 312)
		local P2 = buffer.readinteger(LW, 416)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 432, integer.add(integer.add(buffer.readinteger(LW, 304), S0), integer.add(buffer.readinteger(LW, 376), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 320)
		local P2 = buffer.readinteger(LW, 424)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 440, integer.add(integer.add(buffer.readinteger(LW, 312), S0), integer.add(buffer.readinteger(LW, 384), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 328)
		local P2 = buffer.readinteger(LW, 432)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 448, integer.add(integer.add(buffer.readinteger(LW, 320), S0), integer.add(buffer.readinteger(LW, 392), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 336)
		local P2 = buffer.readinteger(LW, 440)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 456, integer.add(integer.add(buffer.readinteger(LW, 328), S0), integer.add(buffer.readinteger(LW, 400), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 344)
		local P2 = buffer.readinteger(LW, 448)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 464, integer.add(integer.add(buffer.readinteger(LW, 336), S0), integer.add(buffer.readinteger(LW, 408), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 352)
		local P2 = buffer.readinteger(LW, 456)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 472, integer.add(integer.add(buffer.readinteger(LW, 344), S0), integer.add(buffer.readinteger(LW, 416), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 360)
		local P2 = buffer.readinteger(LW, 464)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 480, integer.add(integer.add(buffer.readinteger(LW, 352), S0), integer.add(buffer.readinteger(LW, 424), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 368)
		local P2 = buffer.readinteger(LW, 472)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 488, integer.add(integer.add(buffer.readinteger(LW, 360), S0), integer.add(buffer.readinteger(LW, 432), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 376)
		local P2 = buffer.readinteger(LW, 480)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 496, integer.add(integer.add(buffer.readinteger(LW, 368), S0), integer.add(buffer.readinteger(LW, 440), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 384)
		local P2 = buffer.readinteger(LW, 488)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 504, integer.add(integer.add(buffer.readinteger(LW, 376), S0), integer.add(buffer.readinteger(LW, 448), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 392)
		local P2 = buffer.readinteger(LW, 496)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 512, integer.add(integer.add(buffer.readinteger(LW, 384), S0), integer.add(buffer.readinteger(LW, 456), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 400)
		local P2 = buffer.readinteger(LW, 504)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 520, integer.add(integer.add(buffer.readinteger(LW, 392), S0), integer.add(buffer.readinteger(LW, 464), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 408)
		local P2 = buffer.readinteger(LW, 512)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 528, integer.add(integer.add(buffer.readinteger(LW, 400), S0), integer.add(buffer.readinteger(LW, 472), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 416)
		local P2 = buffer.readinteger(LW, 520)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 536, integer.add(integer.add(buffer.readinteger(LW, 408), S0), integer.add(buffer.readinteger(LW, 480), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 424)
		local P2 = buffer.readinteger(LW, 528)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 544, integer.add(integer.add(buffer.readinteger(LW, 416), S0), integer.add(buffer.readinteger(LW, 488), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 432)
		local P2 = buffer.readinteger(LW, 536)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 552, integer.add(integer.add(buffer.readinteger(LW, 424), S0), integer.add(buffer.readinteger(LW, 496), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 440)
		local P2 = buffer.readinteger(LW, 544)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 560, integer.add(integer.add(buffer.readinteger(LW, 432), S0), integer.add(buffer.readinteger(LW, 504), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 448)
		local P2 = buffer.readinteger(LW, 552)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 568, integer.add(integer.add(buffer.readinteger(LW, 440), S0), integer.add(buffer.readinteger(LW, 512), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 456)
		local P2 = buffer.readinteger(LW, 560)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 576, integer.add(integer.add(buffer.readinteger(LW, 448), S0), integer.add(buffer.readinteger(LW, 520), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 464)
		local P2 = buffer.readinteger(LW, 568)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 584, integer.add(integer.add(buffer.readinteger(LW, 456), S0), integer.add(buffer.readinteger(LW, 528), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 472)
		local P2 = buffer.readinteger(LW, 576)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 592, integer.add(integer.add(buffer.readinteger(LW, 464), S0), integer.add(buffer.readinteger(LW, 536), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 480)
		local P2 = buffer.readinteger(LW, 584)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 600, integer.add(integer.add(buffer.readinteger(LW, 472), S0), integer.add(buffer.readinteger(LW, 544), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 488)
		local P2 = buffer.readinteger(LW, 592)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 608, integer.add(integer.add(buffer.readinteger(LW, 480), S0), integer.add(buffer.readinteger(LW, 552), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 496)
		local P2 = buffer.readinteger(LW, 600)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 616, integer.add(integer.add(buffer.readinteger(LW, 488), S0), integer.add(buffer.readinteger(LW, 560), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 504)
		local P2 = buffer.readinteger(LW, 608)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 624, integer.add(integer.add(buffer.readinteger(LW, 496), S0), integer.add(buffer.readinteger(LW, 568), S1)))
	end
	do
		local P15 = buffer.readinteger(LW, 512)
		local P2 = buffer.readinteger(LW, 616)
		local S0 = integer.bxor(integer.rrotate(P15, 1i), integer.rrotate(P15, 8i), integer.rshift(P15, 7i))
		local S1 = integer.bxor(integer.rrotate(P2, 19i), integer.rrotate(P2, 61i), integer.rshift(P2, 6i))
		buffer.writeinteger(LW, 632, integer.add(integer.add(buffer.readinteger(LW, 504), S0), integer.add(buffer.readinteger(LW, 576), S1)))
	end
end

local function DigestBlocks(Blocks: buffer, Length: number): (integer, integer, integer, integer, integer, integer, integer, integer)
	local H1, H2, H3, H4 = 0x6a09e667f3bcc908i, 0xbb67ae8584caa73bi, 0x3c6ef372fe94f82bi, 0xa54ff53a5f1d36f1i
	local H5, H6, H7, H8 = 0x510e527fade682d1i, 0x9b05688c2b3e6c1fi, 0x1f83d9abfb41bd6bi, 0x5be0cd19137e2179i

	local LW, LK = W, K

	for Offset = 0, Length - 1, 128 do
		for T = 0, 15 do
			buffer.writeinteger(LW, T * 8, integer.bswap(buffer.readinteger(Blocks, Offset + T * 8)))
		end

		ProcessSchedule(LW)

		local A, B, C, D = H1, H2, H3, H4
		local E, F, G, H = H5, H6, H7, H8

		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 0), buffer.readinteger(LW, 0)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 8), buffer.readinteger(LW, 8)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 16), buffer.readinteger(LW, 16)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 24), buffer.readinteger(LW, 24)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 32), buffer.readinteger(LW, 32)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 40), buffer.readinteger(LW, 40)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 48), buffer.readinteger(LW, 48)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 56), buffer.readinteger(LW, 56)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 64), buffer.readinteger(LW, 64)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 72), buffer.readinteger(LW, 72)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 80), buffer.readinteger(LW, 80)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 88), buffer.readinteger(LW, 88)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 96), buffer.readinteger(LW, 96)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 104), buffer.readinteger(LW, 104)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 112), buffer.readinteger(LW, 112)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 120), buffer.readinteger(LW, 120)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 128), buffer.readinteger(LW, 128)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 136), buffer.readinteger(LW, 136)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 144), buffer.readinteger(LW, 144)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 152), buffer.readinteger(LW, 152)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 160), buffer.readinteger(LW, 160)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 168), buffer.readinteger(LW, 168)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 176), buffer.readinteger(LW, 176)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 184), buffer.readinteger(LW, 184)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 192), buffer.readinteger(LW, 192)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 200), buffer.readinteger(LW, 200)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 208), buffer.readinteger(LW, 208)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 216), buffer.readinteger(LW, 216)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 224), buffer.readinteger(LW, 224)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 232), buffer.readinteger(LW, 232)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 240), buffer.readinteger(LW, 240)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 248), buffer.readinteger(LW, 248)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 256), buffer.readinteger(LW, 256)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 264), buffer.readinteger(LW, 264)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 272), buffer.readinteger(LW, 272)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 280), buffer.readinteger(LW, 280)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 288), buffer.readinteger(LW, 288)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 296), buffer.readinteger(LW, 296)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 304), buffer.readinteger(LW, 304)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 312), buffer.readinteger(LW, 312)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 320), buffer.readinteger(LW, 320)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 328), buffer.readinteger(LW, 328)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 336), buffer.readinteger(LW, 336)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 344), buffer.readinteger(LW, 344)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 352), buffer.readinteger(LW, 352)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 360), buffer.readinteger(LW, 360)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 368), buffer.readinteger(LW, 368)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 376), buffer.readinteger(LW, 376)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 384), buffer.readinteger(LW, 384)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 392), buffer.readinteger(LW, 392)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 400), buffer.readinteger(LW, 400)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 408), buffer.readinteger(LW, 408)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 416), buffer.readinteger(LW, 416)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 424), buffer.readinteger(LW, 424)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 432), buffer.readinteger(LW, 432)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 440), buffer.readinteger(LW, 440)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 448), buffer.readinteger(LW, 448)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 456), buffer.readinteger(LW, 456)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 464), buffer.readinteger(LW, 464)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 472), buffer.readinteger(LW, 472)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 480), buffer.readinteger(LW, 480)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 488), buffer.readinteger(LW, 488)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 496), buffer.readinteger(LW, 496)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 504), buffer.readinteger(LW, 504)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 512), buffer.readinteger(LW, 512)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 520), buffer.readinteger(LW, 520)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 528), buffer.readinteger(LW, 528)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 536), buffer.readinteger(LW, 536)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 544), buffer.readinteger(LW, 544)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 552), buffer.readinteger(LW, 552)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 560), buffer.readinteger(LW, 560)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 568), buffer.readinteger(LW, 568)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 576), buffer.readinteger(LW, 576)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 584), buffer.readinteger(LW, 584)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 592), buffer.readinteger(LW, 592)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 600), buffer.readinteger(LW, 600)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 608), buffer.readinteger(LW, 608)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 616), buffer.readinteger(LW, 616)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 624), buffer.readinteger(LW, 624)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
		end
		do
			local Sigma0 = integer.bxor(integer.rrotate(A, 28i), integer.rrotate(A, 34i), integer.rrotate(A, 39i))
			local Sigma1 = integer.bxor(integer.rrotate(E, 14i), integer.rrotate(E, 18i), integer.rrotate(E, 41i))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			local T1 = integer.add(integer.add(integer.add(H, Sigma1), Ch), integer.add(buffer.readinteger(LK, 632), buffer.readinteger(LW, 632)))
			local T2 = integer.add(Sigma0, Maj)
			H = G; G = F; F = E; E = integer.add(D, T1); D = C; C = B; B = A; A = integer.add(T1, T2)
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

	return H1, H2, H3, H4, H5, H6, H7, H8
end


local function SHA512_Internal(Message: buffer): buffer
	local Processed, Length = PreProcess(Message)
	local H1, H2, H3, H4, H5, H6, H7, H8 = DigestBlocks(Processed, Length)

	local Result = buffer.create(64)
	buffer.writeinteger(Result, 0,  integer.bswap(H1))
	buffer.writeinteger(Result, 8,  integer.bswap(H2))
	buffer.writeinteger(Result, 16, integer.bswap(H3))
	buffer.writeinteger(Result, 24, integer.bswap(H4))
	buffer.writeinteger(Result, 32, integer.bswap(H5))
	buffer.writeinteger(Result, 40, integer.bswap(H6))
	buffer.writeinteger(Result, 48, integer.bswap(H7))
	buffer.writeinteger(Result, 56, integer.bswap(H8))

	return Result
end

local function SHA512(Message: buffer): (string, buffer)
	local Result = SHA512_Internal(Message)

	return ToHex(Result), Result
end

return {
	SHA512 = SHA512,
	SHA512_Internal = SHA512_Internal,
}
