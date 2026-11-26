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

local CARRY = 2 ^ -32

local BUF: buffer = buffer.create(1344)
buffer.writestring(BUF, 704, "\x98\x2F\x8A\x42\x22\xAE\x28\xD7\x91\x44\x37\x71\xCD\x65\xEF\x23\z
	\xCF\xFB\xC0\xB5\x2F\x3B\x4D\xEC\xA5\xDB\xB5\xE9\xBC\xDB\x89\x81\z
	\x5B\xC2\x56\x39\x38\xB5\x48\xF3\xF1\x11\xF1\x59\x19\xD0\x05\xB6\z
	\xA4\x82\x3F\x92\x9B\x4F\x19\xAF\xD5\x5E\x1C\xAB\x18\x81\x6D\xDA\z
	\x98\xAA\x07\xD8\x42\x02\x03\xA3\x01\x5B\x83\x12\xBE\x6F\x70\x45\z
	\xBE\x85\x31\x24\x8C\xB2\xE4\x4E\xC3\x7D\x0C\x55\xE2\xB4\xFF\xD5\z
	\x74\x5D\xBE\x72\x6F\x89\x7B\xF2\xFE\xB1\xDE\x80\xB1\x96\x16\x3B\z
	\xA7\x06\xDC\x9B\x35\x12\xC7\x25\x74\xF1\x9B\xC1\x94\x26\x69\xCF\z
	\xC1\x69\x9B\xE4\xD2\x4A\xF1\x9E\x86\x47\xBE\xEF\xE3\x25\x4F\x38\z
	\xC6\x9D\xC1\x0F\xB5\xD5\x8C\x8B\xCC\xA1\x0C\x24\x65\x9C\xAC\x77\z
	\x6F\x2C\xE9\x2D\x75\x02\x2B\x59\xAA\x84\x74\x4A\x83\xE4\xA6\x6E\z
	\xDC\xA9\xB0\x5C\xD4\xFB\x41\xBD\xDA\x88\xF9\x76\xB5\x53\x11\x83\z
	\x52\x51\x3E\x98\xAB\xDF\x66\xEE\x6D\xC6\x31\xA8\x10\x32\xB4\x2D\z
	\xC8\x27\x03\xB0\x3F\x21\xFB\x98\xC7\x7F\x59\xBF\xE4\x0E\xEF\xBE\z
	\xF3\x0B\xE0\xC6\xC2\x8F\xA8\x3D\x47\x91\xA7\xD5\x25\xA7\x0A\x93\z
	\x51\x63\xCA\x06\x6F\x82\x03\xE0\x67\x29\x29\x14\x70\x6E\x0E\x0A\z
	\x85\x0A\xB7\x27\xFC\x2F\xD2\x46\x38\x21\x1B\x2E\x26\xC9\x26\x5C\z
	\xFC\x6D\x2C\x4D\xED\x2A\xC4\x5A\x13\x0D\x38\x53\xDF\xB3\x95\x9D\z
	\x54\x73\x0A\x65\xDE\x63\xAF\x8B\xBB\x0A\x6A\x76\xA8\xB2\x77\x3C\z
	\x2E\xC9\xC2\x81\xE6\xAE\xED\x47\x85\x2C\x72\x92\x3B\x35\x82\x14\z
	\xA1\xE8\xBF\xA2\x64\x03\xF1\x4C\x4B\x66\x1A\xA8\x01\x30\x42\xBC\z
	\x70\x8B\x4B\xC2\x91\x97\xF8\xD0\xA3\x51\x6C\xC7\x30\xBE\x54\x06\z
	\x19\xE8\x92\xD1\x18\x52\xEF\xD6\x24\x06\x99\xD6\x10\xA9\x65\x55\z
	\x85\x35\x0E\xF4\x2A\x20\x71\x57\x70\xA0\x6A\x10\xB8\xD1\xBB\x32\z
	\x16\xC1\xA4\x19\xC8\xD0\xD2\xB8\x08\x6C\x37\x1E\x53\xAB\x41\x51\z
	\x4C\x77\x48\x27\x99\xEB\x8E\xDF\xB5\xBC\xB0\x34\xA8\x48\x9B\xE1\z
	\xB3\x0C\x1C\x39\x63\x5A\xC9\xC5\x4A\xAA\xD8\x4E\xCB\x8A\x41\xE3\z
	\x4F\xCA\x9C\x5B\x73\xE3\x63\x77\xF3\x6F\x2E\x68\xA3\xB8\xB2\xD6\z
	\xEE\x82\x8F\x74\xFC\xB2\xEF\x5D\x6F\x63\xA5\x78\x60\x2F\x17\x43\z
	\x14\x78\xC8\x84\x72\xAB\xF0\xA1\x08\x02\xC7\x8C\xEC\x39\x64\x1A\z
	\xFA\xFF\xBE\x90\x28\x1E\x63\x23\xEB\x6C\x50\xA4\xE9\xBD\x82\xDE\z
	\xF7\xA3\xF9\xBE\x15\x79\xC6\xB2\xF2\x78\x71\xC6\x2B\x53\x72\xE3\z
	\xCE\x3E\x27\xCA\x9C\x61\x26\xEA\xC7\xB8\x86\xD1\x07\xC2\xC0\x21\z
	\xD6\x7D\xDA\xEA\x1E\xEB\xE0\xCD\x7F\x4F\x7D\xF5\x78\xD1\x6E\xEE\z
	\xAA\x67\xF0\x06\xBA\x6F\x17\x72\xC5\x7D\x63\x0A\xA6\x98\xC8\xA2\z
	\x04\x98\x3F\x11\xAE\x0D\xF9\xBE\x35\x0B\x71\x1B\x1B\x47\x1C\x13\z
	\xF5\x77\xDB\x28\x84\x7D\x04\x23\x7B\xAB\xCA\x32\x93\x24\xC7\x40\z
	\x0A\xBE\x9E\x3C\xBC\xBE\xC9\x15\xC4\x67\x1D\x43\x4C\x0D\x10\x9C\z
	\xBE\xD4\xC5\x4C\xB6\x42\x3E\xCB\x9C\x29\x7F\x59\x2A\x7E\x65\xFC\z
	\xAB\x6F\xCB\x5F\xEC\xFA\xD6\x3A\x8C\x19\x44\x6C\x17\x58\x47\x4A")

local IV_512: buffer = buffer.fromstring("\x67\xE6\x09\x6A\x08\xC9\xBC\xF3\x85\xAE\x67\xBB\x3B\xA7\xCA\x84\z
	\x72\xF3\x6E\x3C\x2B\xF8\x94\xFE\x3A\xF5\x4F\xA5\xF1\x36\x1D\x5F\z
	\x7F\x52\x0E\x51\xD1\x82\xE6\xAD\x8C\x68\x05\x9B\x1F\x6C\x3E\x2B\z
	\xAB\xD9\x83\x1F\x6B\xBD\x41\xFB\x19\xCD\xE0\x5B\x79\x21\x7E\x13")

local IV_384: buffer = buffer.fromstring("\x5D\x9D\xBB\xCB\xD8\x9E\x05\xC1\x2A\x29\x9A\x62\x07\xD5\x7C\x36\z
	\x5A\x01\x59\x91\x17\xDD\x70\x30\xD8\xEC\x2F\x15\x39\x59\x0E\xF7\z
	\x67\x26\x33\x67\x31\x0B\xC0\xFF\x87\x4A\xB4\x8E\x11\x15\x58\x68\z
	\x0D\x2E\x0C\xDB\xA7\x8F\xF9\x64\x1D\x48\xB5\x47\xA4\x4F\xFA\xBE")

local STATE: buffer = buffer.create(64)
local TAIL: buffer = buffer.create(128)

local function Compress(Blocks: buffer, Offset: number, Length: number, State: buffer)
	local Buf: buffer = BUF
	for Position = Offset, Offset + Length - 1, 128 do
		buffer.writeu32(Buf, 64, bit32.byteswap(buffer.readu32(Blocks, Position + 0))); buffer.writeu32(Buf, 68, bit32.byteswap(buffer.readu32(Blocks, Position + 4)))
		buffer.writeu32(Buf, 72, bit32.byteswap(buffer.readu32(Blocks, Position + 8))); buffer.writeu32(Buf, 76, bit32.byteswap(buffer.readu32(Blocks, Position + 12)))
		buffer.writeu32(Buf, 80, bit32.byteswap(buffer.readu32(Blocks, Position + 16))); buffer.writeu32(Buf, 84, bit32.byteswap(buffer.readu32(Blocks, Position + 20)))
		buffer.writeu32(Buf, 88, bit32.byteswap(buffer.readu32(Blocks, Position + 24))); buffer.writeu32(Buf, 92, bit32.byteswap(buffer.readu32(Blocks, Position + 28)))
		buffer.writeu32(Buf, 96, bit32.byteswap(buffer.readu32(Blocks, Position + 32))); buffer.writeu32(Buf, 100, bit32.byteswap(buffer.readu32(Blocks, Position + 36)))
		buffer.writeu32(Buf, 104, bit32.byteswap(buffer.readu32(Blocks, Position + 40))); buffer.writeu32(Buf, 108, bit32.byteswap(buffer.readu32(Blocks, Position + 44)))
		buffer.writeu32(Buf, 112, bit32.byteswap(buffer.readu32(Blocks, Position + 48))); buffer.writeu32(Buf, 116, bit32.byteswap(buffer.readu32(Blocks, Position + 52)))
		buffer.writeu32(Buf, 120, bit32.byteswap(buffer.readu32(Blocks, Position + 56))); buffer.writeu32(Buf, 124, bit32.byteswap(buffer.readu32(Blocks, Position + 60)))
		buffer.writeu32(Buf, 128, bit32.byteswap(buffer.readu32(Blocks, Position + 64))); buffer.writeu32(Buf, 132, bit32.byteswap(buffer.readu32(Blocks, Position + 68)))
		buffer.writeu32(Buf, 136, bit32.byteswap(buffer.readu32(Blocks, Position + 72))); buffer.writeu32(Buf, 140, bit32.byteswap(buffer.readu32(Blocks, Position + 76)))
		buffer.writeu32(Buf, 144, bit32.byteswap(buffer.readu32(Blocks, Position + 80))); buffer.writeu32(Buf, 148, bit32.byteswap(buffer.readu32(Blocks, Position + 84)))
		buffer.writeu32(Buf, 152, bit32.byteswap(buffer.readu32(Blocks, Position + 88))); buffer.writeu32(Buf, 156, bit32.byteswap(buffer.readu32(Blocks, Position + 92)))
		buffer.writeu32(Buf, 160, bit32.byteswap(buffer.readu32(Blocks, Position + 96))); buffer.writeu32(Buf, 164, bit32.byteswap(buffer.readu32(Blocks, Position + 100)))
		buffer.writeu32(Buf, 168, bit32.byteswap(buffer.readu32(Blocks, Position + 104))); buffer.writeu32(Buf, 172, bit32.byteswap(buffer.readu32(Blocks, Position + 108)))
		buffer.writeu32(Buf, 176, bit32.byteswap(buffer.readu32(Blocks, Position + 112))); buffer.writeu32(Buf, 180, bit32.byteswap(buffer.readu32(Blocks, Position + 116)))
		buffer.writeu32(Buf, 184, bit32.byteswap(buffer.readu32(Blocks, Position + 120))); buffer.writeu32(Buf, 188, bit32.byteswap(buffer.readu32(Blocks, Position + 124)))
		for T = 192, 640, 64 do
			do
				local P15H, P15L = buffer.readu32(Buf, T - 120), buffer.readu32(Buf, T - 116)
				local Lo = buffer.readu32(Buf, T - 124) + buffer.readu32(Buf, T - 52) + bit32.bxor(bit32.bor(bit32.rshift(P15L, 1), bit32.lshift(P15H, 31)), bit32.bor(bit32.rshift(P15L, 8), bit32.lshift(P15H, 24)), bit32.bor(bit32.rshift(P15L, 7), bit32.lshift(P15H, 25)))
				local Hi = bit32.bor(bit32.bor(buffer.readu32(Buf, T - 128) + buffer.readu32(Buf, T - 56), 0) + bit32.bxor(bit32.bor(bit32.rshift(P15H, 1), bit32.lshift(P15L, 31)), bit32.bor(bit32.rshift(P15H, 8), bit32.lshift(P15L, 24)), bit32.rshift(P15H, 7)), 0)
				local P2H, P2L = buffer.readu32(Buf, T - 16), buffer.readu32(Buf, T - 12)
				Lo += bit32.bxor(bit32.bor(bit32.rshift(P2L, 19), bit32.lshift(P2H, 13)), bit32.bor(bit32.rshift(P2H, 29), bit32.lshift(P2L, 3)), bit32.bor(bit32.rshift(P2L, 6), bit32.lshift(P2H, 26)))
				Hi = bit32.bor(bit32.bor(Hi + bit32.bxor(bit32.bor(bit32.rshift(P2H, 19), bit32.lshift(P2L, 13)), bit32.bor(bit32.rshift(P2L, 29), bit32.lshift(P2H, 3)), bit32.rshift(P2H, 6)), 0) + math.floor(Lo * CARRY), 0)
				buffer.writeu32(Buf, T, Hi)
				buffer.writeu32(Buf, T + 4, Lo)
			end
			do
				local P15H, P15L = buffer.readu32(Buf, T - 112), buffer.readu32(Buf, T - 108)
				local Lo = buffer.readu32(Buf, T - 116) + buffer.readu32(Buf, T - 44) + bit32.bxor(bit32.bor(bit32.rshift(P15L, 1), bit32.lshift(P15H, 31)), bit32.bor(bit32.rshift(P15L, 8), bit32.lshift(P15H, 24)), bit32.bor(bit32.rshift(P15L, 7), bit32.lshift(P15H, 25)))
				local Hi = bit32.bor(bit32.bor(buffer.readu32(Buf, T - 120) + buffer.readu32(Buf, T - 48), 0) + bit32.bxor(bit32.bor(bit32.rshift(P15H, 1), bit32.lshift(P15L, 31)), bit32.bor(bit32.rshift(P15H, 8), bit32.lshift(P15L, 24)), bit32.rshift(P15H, 7)), 0)
				local P2H, P2L = buffer.readu32(Buf, T - 8), buffer.readu32(Buf, T - 4)
				Lo += bit32.bxor(bit32.bor(bit32.rshift(P2L, 19), bit32.lshift(P2H, 13)), bit32.bor(bit32.rshift(P2H, 29), bit32.lshift(P2L, 3)), bit32.bor(bit32.rshift(P2L, 6), bit32.lshift(P2H, 26)))
				Hi = bit32.bor(bit32.bor(Hi + bit32.bxor(bit32.bor(bit32.rshift(P2H, 19), bit32.lshift(P2L, 13)), bit32.bor(bit32.rshift(P2L, 29), bit32.lshift(P2H, 3)), bit32.rshift(P2H, 6)), 0) + math.floor(Lo * CARRY), 0)
				buffer.writeu32(Buf, T + 8, Hi)
				buffer.writeu32(Buf, T + 8 + 4, Lo)
			end
			do
				local P15H, P15L = buffer.readu32(Buf, T - 104), buffer.readu32(Buf, T - 100)
				local Lo = buffer.readu32(Buf, T - 108) + buffer.readu32(Buf, T - 36) + bit32.bxor(bit32.bor(bit32.rshift(P15L, 1), bit32.lshift(P15H, 31)), bit32.bor(bit32.rshift(P15L, 8), bit32.lshift(P15H, 24)), bit32.bor(bit32.rshift(P15L, 7), bit32.lshift(P15H, 25)))
				local Hi = bit32.bor(bit32.bor(buffer.readu32(Buf, T - 112) + buffer.readu32(Buf, T - 40), 0) + bit32.bxor(bit32.bor(bit32.rshift(P15H, 1), bit32.lshift(P15L, 31)), bit32.bor(bit32.rshift(P15H, 8), bit32.lshift(P15L, 24)), bit32.rshift(P15H, 7)), 0)
				local P2H, P2L = buffer.readu32(Buf, T), buffer.readu32(Buf, T + 4)
				Lo += bit32.bxor(bit32.bor(bit32.rshift(P2L, 19), bit32.lshift(P2H, 13)), bit32.bor(bit32.rshift(P2H, 29), bit32.lshift(P2L, 3)), bit32.bor(bit32.rshift(P2L, 6), bit32.lshift(P2H, 26)))
				Hi = bit32.bor(bit32.bor(Hi + bit32.bxor(bit32.bor(bit32.rshift(P2H, 19), bit32.lshift(P2L, 13)), bit32.bor(bit32.rshift(P2L, 29), bit32.lshift(P2H, 3)), bit32.rshift(P2H, 6)), 0) + math.floor(Lo * CARRY), 0)
				buffer.writeu32(Buf, T + 16, Hi)
				buffer.writeu32(Buf, T + 16 + 4, Lo)
			end
			do
				local P15H, P15L = buffer.readu32(Buf, T - 96), buffer.readu32(Buf, T - 92)
				local Lo = buffer.readu32(Buf, T - 100) + buffer.readu32(Buf, T - 28) + bit32.bxor(bit32.bor(bit32.rshift(P15L, 1), bit32.lshift(P15H, 31)), bit32.bor(bit32.rshift(P15L, 8), bit32.lshift(P15H, 24)), bit32.bor(bit32.rshift(P15L, 7), bit32.lshift(P15H, 25)))
				local Hi = bit32.bor(bit32.bor(buffer.readu32(Buf, T - 104) + buffer.readu32(Buf, T - 32), 0) + bit32.bxor(bit32.bor(bit32.rshift(P15H, 1), bit32.lshift(P15L, 31)), bit32.bor(bit32.rshift(P15H, 8), bit32.lshift(P15L, 24)), bit32.rshift(P15H, 7)), 0)
				local P2H, P2L = buffer.readu32(Buf, T + 8), buffer.readu32(Buf, T + 12)
				Lo += bit32.bxor(bit32.bor(bit32.rshift(P2L, 19), bit32.lshift(P2H, 13)), bit32.bor(bit32.rshift(P2H, 29), bit32.lshift(P2L, 3)), bit32.bor(bit32.rshift(P2L, 6), bit32.lshift(P2H, 26)))
				Hi = bit32.bor(bit32.bor(Hi + bit32.bxor(bit32.bor(bit32.rshift(P2H, 19), bit32.lshift(P2L, 13)), bit32.bor(bit32.rshift(P2L, 29), bit32.lshift(P2H, 3)), bit32.rshift(P2H, 6)), 0) + math.floor(Lo * CARRY), 0)
				buffer.writeu32(Buf, T + 24, Hi)
				buffer.writeu32(Buf, T + 24 + 4, Lo)
			end
			do
				local P15H, P15L = buffer.readu32(Buf, T - 88), buffer.readu32(Buf, T - 84)
				local Lo = buffer.readu32(Buf, T - 92) + buffer.readu32(Buf, T - 20) + bit32.bxor(bit32.bor(bit32.rshift(P15L, 1), bit32.lshift(P15H, 31)), bit32.bor(bit32.rshift(P15L, 8), bit32.lshift(P15H, 24)), bit32.bor(bit32.rshift(P15L, 7), bit32.lshift(P15H, 25)))
				local Hi = bit32.bor(bit32.bor(buffer.readu32(Buf, T - 96) + buffer.readu32(Buf, T - 24), 0) + bit32.bxor(bit32.bor(bit32.rshift(P15H, 1), bit32.lshift(P15L, 31)), bit32.bor(bit32.rshift(P15H, 8), bit32.lshift(P15L, 24)), bit32.rshift(P15H, 7)), 0)
				local P2H, P2L = buffer.readu32(Buf, T + 16), buffer.readu32(Buf, T + 20)
				Lo += bit32.bxor(bit32.bor(bit32.rshift(P2L, 19), bit32.lshift(P2H, 13)), bit32.bor(bit32.rshift(P2H, 29), bit32.lshift(P2L, 3)), bit32.bor(bit32.rshift(P2L, 6), bit32.lshift(P2H, 26)))
				Hi = bit32.bor(bit32.bor(Hi + bit32.bxor(bit32.bor(bit32.rshift(P2H, 19), bit32.lshift(P2L, 13)), bit32.bor(bit32.rshift(P2L, 29), bit32.lshift(P2H, 3)), bit32.rshift(P2H, 6)), 0) + math.floor(Lo * CARRY), 0)
				buffer.writeu32(Buf, T + 32, Hi)
				buffer.writeu32(Buf, T + 32 + 4, Lo)
			end
			do
				local P15H, P15L = buffer.readu32(Buf, T - 80), buffer.readu32(Buf, T - 76)
				local Lo = buffer.readu32(Buf, T - 84) + buffer.readu32(Buf, T - 12) + bit32.bxor(bit32.bor(bit32.rshift(P15L, 1), bit32.lshift(P15H, 31)), bit32.bor(bit32.rshift(P15L, 8), bit32.lshift(P15H, 24)), bit32.bor(bit32.rshift(P15L, 7), bit32.lshift(P15H, 25)))
				local Hi = bit32.bor(bit32.bor(buffer.readu32(Buf, T - 88) + buffer.readu32(Buf, T - 16), 0) + bit32.bxor(bit32.bor(bit32.rshift(P15H, 1), bit32.lshift(P15L, 31)), bit32.bor(bit32.rshift(P15H, 8), bit32.lshift(P15L, 24)), bit32.rshift(P15H, 7)), 0)
				local P2H, P2L = buffer.readu32(Buf, T + 24), buffer.readu32(Buf, T + 28)
				Lo += bit32.bxor(bit32.bor(bit32.rshift(P2L, 19), bit32.lshift(P2H, 13)), bit32.bor(bit32.rshift(P2H, 29), bit32.lshift(P2L, 3)), bit32.bor(bit32.rshift(P2L, 6), bit32.lshift(P2H, 26)))
				Hi = bit32.bor(bit32.bor(Hi + bit32.bxor(bit32.bor(bit32.rshift(P2H, 19), bit32.lshift(P2L, 13)), bit32.bor(bit32.rshift(P2L, 29), bit32.lshift(P2H, 3)), bit32.rshift(P2H, 6)), 0) + math.floor(Lo * CARRY), 0)
				buffer.writeu32(Buf, T + 40, Hi)
				buffer.writeu32(Buf, T + 40 + 4, Lo)
			end
			do
				local P15H, P15L = buffer.readu32(Buf, T - 72), buffer.readu32(Buf, T - 68)
				local Lo = buffer.readu32(Buf, T - 76) + buffer.readu32(Buf, T - 4) + bit32.bxor(bit32.bor(bit32.rshift(P15L, 1), bit32.lshift(P15H, 31)), bit32.bor(bit32.rshift(P15L, 8), bit32.lshift(P15H, 24)), bit32.bor(bit32.rshift(P15L, 7), bit32.lshift(P15H, 25)))
				local Hi = bit32.bor(bit32.bor(buffer.readu32(Buf, T - 80) + buffer.readu32(Buf, T - 8), 0) + bit32.bxor(bit32.bor(bit32.rshift(P15H, 1), bit32.lshift(P15L, 31)), bit32.bor(bit32.rshift(P15H, 8), bit32.lshift(P15L, 24)), bit32.rshift(P15H, 7)), 0)
				local P2H, P2L = buffer.readu32(Buf, T + 32), buffer.readu32(Buf, T + 36)
				Lo += bit32.bxor(bit32.bor(bit32.rshift(P2L, 19), bit32.lshift(P2H, 13)), bit32.bor(bit32.rshift(P2H, 29), bit32.lshift(P2L, 3)), bit32.bor(bit32.rshift(P2L, 6), bit32.lshift(P2H, 26)))
				Hi = bit32.bor(bit32.bor(Hi + bit32.bxor(bit32.bor(bit32.rshift(P2H, 19), bit32.lshift(P2L, 13)), bit32.bor(bit32.rshift(P2L, 29), bit32.lshift(P2H, 3)), bit32.rshift(P2H, 6)), 0) + math.floor(Lo * CARRY), 0)
				buffer.writeu32(Buf, T + 48, Hi)
				buffer.writeu32(Buf, T + 48 + 4, Lo)
			end
			do
				local P15H, P15L = buffer.readu32(Buf, T - 64), buffer.readu32(Buf, T - 60)
				local Lo = buffer.readu32(Buf, T - 68) + buffer.readu32(Buf, T + 4) + bit32.bxor(bit32.bor(bit32.rshift(P15L, 1), bit32.lshift(P15H, 31)), bit32.bor(bit32.rshift(P15L, 8), bit32.lshift(P15H, 24)), bit32.bor(bit32.rshift(P15L, 7), bit32.lshift(P15H, 25)))
				local Hi = bit32.bor(bit32.bor(buffer.readu32(Buf, T - 72) + buffer.readu32(Buf, T), 0) + bit32.bxor(bit32.bor(bit32.rshift(P15H, 1), bit32.lshift(P15L, 31)), bit32.bor(bit32.rshift(P15H, 8), bit32.lshift(P15L, 24)), bit32.rshift(P15H, 7)), 0)
				local P2H, P2L = buffer.readu32(Buf, T + 40), buffer.readu32(Buf, T + 44)
				Lo += bit32.bxor(bit32.bor(bit32.rshift(P2L, 19), bit32.lshift(P2H, 13)), bit32.bor(bit32.rshift(P2H, 29), bit32.lshift(P2L, 3)), bit32.bor(bit32.rshift(P2L, 6), bit32.lshift(P2H, 26)))
				Hi = bit32.bor(bit32.bor(Hi + bit32.bxor(bit32.bor(bit32.rshift(P2H, 19), bit32.lshift(P2L, 13)), bit32.bor(bit32.rshift(P2L, 29), bit32.lshift(P2H, 3)), bit32.rshift(P2H, 6)), 0) + math.floor(Lo * CARRY), 0)
				buffer.writeu32(Buf, T + 56, Hi)
				buffer.writeu32(Buf, T + 56 + 4, Lo)
			end
		end
		buffer.writef64(Buf, 0, buffer.readf64(State, 0))
		buffer.writef64(Buf, 8, buffer.readf64(State, 8))
		buffer.writef64(Buf, 16, buffer.readf64(State, 16))
		buffer.writef64(Buf, 24, buffer.readf64(State, 24))
		buffer.writef64(Buf, 32, buffer.readf64(State, 32))
		buffer.writef64(Buf, 40, buffer.readf64(State, 40))
		buffer.writef64(Buf, 48, buffer.readf64(State, 48))
		buffer.writef64(Buf, 56, buffer.readf64(State, 56))
		for Base = 64, 640, 64 do
			local S0H, S0L = buffer.readu32(Buf, 0), buffer.readu32(Buf, 4)
			local S1H, S1L = buffer.readu32(Buf, 8), buffer.readu32(Buf, 12)
			local S2H, S2L = buffer.readu32(Buf, 16), buffer.readu32(Buf, 20)
			local S3H, S3L = buffer.readu32(Buf, 24), buffer.readu32(Buf, 28)
			local S4H, S4L = buffer.readu32(Buf, 32), buffer.readu32(Buf, 36)
			local S5H, S5L = buffer.readu32(Buf, 40), buffer.readu32(Buf, 44)
			local S6H, S6L = buffer.readu32(Buf, 48), buffer.readu32(Buf, 52)
			local S7H, S7L = buffer.readu32(Buf, 56), buffer.readu32(Buf, 60)
			local BCH, BCL = bit32.bxor(S1H, S2H), bit32.bxor(S1L, S2L)
			do
				local T1L = S7L + buffer.readu32(Buf, Base + 644) + buffer.readu32(Buf, Base + 4) + bit32.bxor(S6L, bit32.band(S4L, bit32.bxor(S5L, S6L))) + bit32.bxor(bit32.bor(bit32.rshift(S4L, 14), bit32.lshift(S4H, 18)), bit32.bor(bit32.rshift(S4L, 18), bit32.lshift(S4H, 14)), bit32.bor(bit32.rshift(S4H, 9), bit32.lshift(S4L, 23)))
				local T1H = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7H + buffer.readu32(Buf, Base + 640), 0) + buffer.readu32(Buf, Base), 0) + bit32.bxor(S6H, bit32.band(S4H, bit32.bxor(S5H, S6H))), 0) + bit32.bxor(bit32.bor(bit32.rshift(S4H, 14), bit32.lshift(S4L, 18)), bit32.bor(bit32.rshift(S4H, 18), bit32.lshift(S4L, 14)), bit32.bor(bit32.rshift(S4L, 9), bit32.lshift(S4H, 23))), 0)
				local EL = S3L + T1L
				S3H = bit32.bor(bit32.bor(S3H + T1H, 0) + math.floor(EL * CARRY), 0)
				S3L = bit32.bor(EL, 0)
				local ABL = bit32.bxor(S0L, S1L)
				local AL = T1L + bit32.bxor(S1L, bit32.band(ABL, BCL)) + bit32.bxor(bit32.bor(bit32.rshift(S0L, 28), bit32.lshift(S0H, 4)), bit32.bor(bit32.rshift(S0H, 2), bit32.lshift(S0L, 30)), bit32.bor(bit32.rshift(S0H, 7), bit32.lshift(S0L, 25)))
				local ABH = bit32.bxor(S0H, S1H)
				S7H = bit32.bor(bit32.bor(bit32.bor(T1H + bit32.bxor(S1H, bit32.band(ABH, BCH)), 0) + bit32.bxor(bit32.bor(bit32.rshift(S0H, 28), bit32.lshift(S0L, 4)), bit32.bor(bit32.rshift(S0L, 2), bit32.lshift(S0H, 30)), bit32.bor(bit32.rshift(S0L, 7), bit32.lshift(S0H, 25))), 0) + math.floor(AL * CARRY), 0)
				S7L = bit32.bor(AL, 0)
				BCH, BCL = ABH, ABL
			end
			do
				local T1L = S6L + buffer.readu32(Buf, Base + 652) + buffer.readu32(Buf, Base + 12) + bit32.bxor(S5L, bit32.band(S3L, bit32.bxor(S4L, S5L))) + bit32.bxor(bit32.bor(bit32.rshift(S3L, 14), bit32.lshift(S3H, 18)), bit32.bor(bit32.rshift(S3L, 18), bit32.lshift(S3H, 14)), bit32.bor(bit32.rshift(S3H, 9), bit32.lshift(S3L, 23)))
				local T1H = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6H + buffer.readu32(Buf, Base + 648), 0) + buffer.readu32(Buf, Base + 8), 0) + bit32.bxor(S5H, bit32.band(S3H, bit32.bxor(S4H, S5H))), 0) + bit32.bxor(bit32.bor(bit32.rshift(S3H, 14), bit32.lshift(S3L, 18)), bit32.bor(bit32.rshift(S3H, 18), bit32.lshift(S3L, 14)), bit32.bor(bit32.rshift(S3L, 9), bit32.lshift(S3H, 23))), 0)
				local EL = S2L + T1L
				S2H = bit32.bor(bit32.bor(S2H + T1H, 0) + math.floor(EL * CARRY), 0)
				S2L = bit32.bor(EL, 0)
				local ABL = bit32.bxor(S7L, S0L)
				local AL = T1L + bit32.bxor(S0L, bit32.band(ABL, BCL)) + bit32.bxor(bit32.bor(bit32.rshift(S7L, 28), bit32.lshift(S7H, 4)), bit32.bor(bit32.rshift(S7H, 2), bit32.lshift(S7L, 30)), bit32.bor(bit32.rshift(S7H, 7), bit32.lshift(S7L, 25)))
				local ABH = bit32.bxor(S7H, S0H)
				S6H = bit32.bor(bit32.bor(bit32.bor(T1H + bit32.bxor(S0H, bit32.band(ABH, BCH)), 0) + bit32.bxor(bit32.bor(bit32.rshift(S7H, 28), bit32.lshift(S7L, 4)), bit32.bor(bit32.rshift(S7L, 2), bit32.lshift(S7H, 30)), bit32.bor(bit32.rshift(S7L, 7), bit32.lshift(S7H, 25))), 0) + math.floor(AL * CARRY), 0)
				S6L = bit32.bor(AL, 0)
				BCH, BCL = ABH, ABL
			end
			do
				local T1L = S5L + buffer.readu32(Buf, Base + 660) + buffer.readu32(Buf, Base + 20) + bit32.bxor(S4L, bit32.band(S2L, bit32.bxor(S3L, S4L))) + bit32.bxor(bit32.bor(bit32.rshift(S2L, 14), bit32.lshift(S2H, 18)), bit32.bor(bit32.rshift(S2L, 18), bit32.lshift(S2H, 14)), bit32.bor(bit32.rshift(S2H, 9), bit32.lshift(S2L, 23)))
				local T1H = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5H + buffer.readu32(Buf, Base + 656), 0) + buffer.readu32(Buf, Base + 16), 0) + bit32.bxor(S4H, bit32.band(S2H, bit32.bxor(S3H, S4H))), 0) + bit32.bxor(bit32.bor(bit32.rshift(S2H, 14), bit32.lshift(S2L, 18)), bit32.bor(bit32.rshift(S2H, 18), bit32.lshift(S2L, 14)), bit32.bor(bit32.rshift(S2L, 9), bit32.lshift(S2H, 23))), 0)
				local EL = S1L + T1L
				S1H = bit32.bor(bit32.bor(S1H + T1H, 0) + math.floor(EL * CARRY), 0)
				S1L = bit32.bor(EL, 0)
				local ABL = bit32.bxor(S6L, S7L)
				local AL = T1L + bit32.bxor(S7L, bit32.band(ABL, BCL)) + bit32.bxor(bit32.bor(bit32.rshift(S6L, 28), bit32.lshift(S6H, 4)), bit32.bor(bit32.rshift(S6H, 2), bit32.lshift(S6L, 30)), bit32.bor(bit32.rshift(S6H, 7), bit32.lshift(S6L, 25)))
				local ABH = bit32.bxor(S6H, S7H)
				S5H = bit32.bor(bit32.bor(bit32.bor(T1H + bit32.bxor(S7H, bit32.band(ABH, BCH)), 0) + bit32.bxor(bit32.bor(bit32.rshift(S6H, 28), bit32.lshift(S6L, 4)), bit32.bor(bit32.rshift(S6L, 2), bit32.lshift(S6H, 30)), bit32.bor(bit32.rshift(S6L, 7), bit32.lshift(S6H, 25))), 0) + math.floor(AL * CARRY), 0)
				S5L = bit32.bor(AL, 0)
				BCH, BCL = ABH, ABL
			end
			do
				local T1L = S4L + buffer.readu32(Buf, Base + 668) + buffer.readu32(Buf, Base + 28) + bit32.bxor(S3L, bit32.band(S1L, bit32.bxor(S2L, S3L))) + bit32.bxor(bit32.bor(bit32.rshift(S1L, 14), bit32.lshift(S1H, 18)), bit32.bor(bit32.rshift(S1L, 18), bit32.lshift(S1H, 14)), bit32.bor(bit32.rshift(S1H, 9), bit32.lshift(S1L, 23)))
				local T1H = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4H + buffer.readu32(Buf, Base + 664), 0) + buffer.readu32(Buf, Base + 24), 0) + bit32.bxor(S3H, bit32.band(S1H, bit32.bxor(S2H, S3H))), 0) + bit32.bxor(bit32.bor(bit32.rshift(S1H, 14), bit32.lshift(S1L, 18)), bit32.bor(bit32.rshift(S1H, 18), bit32.lshift(S1L, 14)), bit32.bor(bit32.rshift(S1L, 9), bit32.lshift(S1H, 23))), 0)
				local EL = S0L + T1L
				S0H = bit32.bor(bit32.bor(S0H + T1H, 0) + math.floor(EL * CARRY), 0)
				S0L = bit32.bor(EL, 0)
				local ABL = bit32.bxor(S5L, S6L)
				local AL = T1L + bit32.bxor(S6L, bit32.band(ABL, BCL)) + bit32.bxor(bit32.bor(bit32.rshift(S5L, 28), bit32.lshift(S5H, 4)), bit32.bor(bit32.rshift(S5H, 2), bit32.lshift(S5L, 30)), bit32.bor(bit32.rshift(S5H, 7), bit32.lshift(S5L, 25)))
				local ABH = bit32.bxor(S5H, S6H)
				S4H = bit32.bor(bit32.bor(bit32.bor(T1H + bit32.bxor(S6H, bit32.band(ABH, BCH)), 0) + bit32.bxor(bit32.bor(bit32.rshift(S5H, 28), bit32.lshift(S5L, 4)), bit32.bor(bit32.rshift(S5L, 2), bit32.lshift(S5H, 30)), bit32.bor(bit32.rshift(S5L, 7), bit32.lshift(S5H, 25))), 0) + math.floor(AL * CARRY), 0)
				S4L = bit32.bor(AL, 0)
				BCH, BCL = ABH, ABL
			end
			do
				local T1L = S3L + buffer.readu32(Buf, Base + 676) + buffer.readu32(Buf, Base + 36) + bit32.bxor(S2L, bit32.band(S0L, bit32.bxor(S1L, S2L))) + bit32.bxor(bit32.bor(bit32.rshift(S0L, 14), bit32.lshift(S0H, 18)), bit32.bor(bit32.rshift(S0L, 18), bit32.lshift(S0H, 14)), bit32.bor(bit32.rshift(S0H, 9), bit32.lshift(S0L, 23)))
				local T1H = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3H + buffer.readu32(Buf, Base + 672), 0) + buffer.readu32(Buf, Base + 32), 0) + bit32.bxor(S2H, bit32.band(S0H, bit32.bxor(S1H, S2H))), 0) + bit32.bxor(bit32.bor(bit32.rshift(S0H, 14), bit32.lshift(S0L, 18)), bit32.bor(bit32.rshift(S0H, 18), bit32.lshift(S0L, 14)), bit32.bor(bit32.rshift(S0L, 9), bit32.lshift(S0H, 23))), 0)
				local EL = S7L + T1L
				S7H = bit32.bor(bit32.bor(S7H + T1H, 0) + math.floor(EL * CARRY), 0)
				S7L = bit32.bor(EL, 0)
				local ABL = bit32.bxor(S4L, S5L)
				local AL = T1L + bit32.bxor(S5L, bit32.band(ABL, BCL)) + bit32.bxor(bit32.bor(bit32.rshift(S4L, 28), bit32.lshift(S4H, 4)), bit32.bor(bit32.rshift(S4H, 2), bit32.lshift(S4L, 30)), bit32.bor(bit32.rshift(S4H, 7), bit32.lshift(S4L, 25)))
				local ABH = bit32.bxor(S4H, S5H)
				S3H = bit32.bor(bit32.bor(bit32.bor(T1H + bit32.bxor(S5H, bit32.band(ABH, BCH)), 0) + bit32.bxor(bit32.bor(bit32.rshift(S4H, 28), bit32.lshift(S4L, 4)), bit32.bor(bit32.rshift(S4L, 2), bit32.lshift(S4H, 30)), bit32.bor(bit32.rshift(S4L, 7), bit32.lshift(S4H, 25))), 0) + math.floor(AL * CARRY), 0)
				S3L = bit32.bor(AL, 0)
				BCH, BCL = ABH, ABL
			end
			do
				local T1L = S2L + buffer.readu32(Buf, Base + 684) + buffer.readu32(Buf, Base + 44) + bit32.bxor(S1L, bit32.band(S7L, bit32.bxor(S0L, S1L))) + bit32.bxor(bit32.bor(bit32.rshift(S7L, 14), bit32.lshift(S7H, 18)), bit32.bor(bit32.rshift(S7L, 18), bit32.lshift(S7H, 14)), bit32.bor(bit32.rshift(S7H, 9), bit32.lshift(S7L, 23)))
				local T1H = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2H + buffer.readu32(Buf, Base + 680), 0) + buffer.readu32(Buf, Base + 40), 0) + bit32.bxor(S1H, bit32.band(S7H, bit32.bxor(S0H, S1H))), 0) + bit32.bxor(bit32.bor(bit32.rshift(S7H, 14), bit32.lshift(S7L, 18)), bit32.bor(bit32.rshift(S7H, 18), bit32.lshift(S7L, 14)), bit32.bor(bit32.rshift(S7L, 9), bit32.lshift(S7H, 23))), 0)
				local EL = S6L + T1L
				S6H = bit32.bor(bit32.bor(S6H + T1H, 0) + math.floor(EL * CARRY), 0)
				S6L = bit32.bor(EL, 0)
				local ABL = bit32.bxor(S3L, S4L)
				local AL = T1L + bit32.bxor(S4L, bit32.band(ABL, BCL)) + bit32.bxor(bit32.bor(bit32.rshift(S3L, 28), bit32.lshift(S3H, 4)), bit32.bor(bit32.rshift(S3H, 2), bit32.lshift(S3L, 30)), bit32.bor(bit32.rshift(S3H, 7), bit32.lshift(S3L, 25)))
				local ABH = bit32.bxor(S3H, S4H)
				S2H = bit32.bor(bit32.bor(bit32.bor(T1H + bit32.bxor(S4H, bit32.band(ABH, BCH)), 0) + bit32.bxor(bit32.bor(bit32.rshift(S3H, 28), bit32.lshift(S3L, 4)), bit32.bor(bit32.rshift(S3L, 2), bit32.lshift(S3H, 30)), bit32.bor(bit32.rshift(S3L, 7), bit32.lshift(S3H, 25))), 0) + math.floor(AL * CARRY), 0)
				S2L = bit32.bor(AL, 0)
				BCH, BCL = ABH, ABL
			end
			do
				local T1L = S1L + buffer.readu32(Buf, Base + 692) + buffer.readu32(Buf, Base + 52) + bit32.bxor(S0L, bit32.band(S6L, bit32.bxor(S7L, S0L))) + bit32.bxor(bit32.bor(bit32.rshift(S6L, 14), bit32.lshift(S6H, 18)), bit32.bor(bit32.rshift(S6L, 18), bit32.lshift(S6H, 14)), bit32.bor(bit32.rshift(S6H, 9), bit32.lshift(S6L, 23)))
				local T1H = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1H + buffer.readu32(Buf, Base + 688), 0) + buffer.readu32(Buf, Base + 48), 0) + bit32.bxor(S0H, bit32.band(S6H, bit32.bxor(S7H, S0H))), 0) + bit32.bxor(bit32.bor(bit32.rshift(S6H, 14), bit32.lshift(S6L, 18)), bit32.bor(bit32.rshift(S6H, 18), bit32.lshift(S6L, 14)), bit32.bor(bit32.rshift(S6L, 9), bit32.lshift(S6H, 23))), 0)
				local EL = S5L + T1L
				S5H = bit32.bor(bit32.bor(S5H + T1H, 0) + math.floor(EL * CARRY), 0)
				S5L = bit32.bor(EL, 0)
				local ABL = bit32.bxor(S2L, S3L)
				local AL = T1L + bit32.bxor(S3L, bit32.band(ABL, BCL)) + bit32.bxor(bit32.bor(bit32.rshift(S2L, 28), bit32.lshift(S2H, 4)), bit32.bor(bit32.rshift(S2H, 2), bit32.lshift(S2L, 30)), bit32.bor(bit32.rshift(S2H, 7), bit32.lshift(S2L, 25)))
				local ABH = bit32.bxor(S2H, S3H)
				S1H = bit32.bor(bit32.bor(bit32.bor(T1H + bit32.bxor(S3H, bit32.band(ABH, BCH)), 0) + bit32.bxor(bit32.bor(bit32.rshift(S2H, 28), bit32.lshift(S2L, 4)), bit32.bor(bit32.rshift(S2L, 2), bit32.lshift(S2H, 30)), bit32.bor(bit32.rshift(S2L, 7), bit32.lshift(S2H, 25))), 0) + math.floor(AL * CARRY), 0)
				S1L = bit32.bor(AL, 0)
				BCH, BCL = ABH, ABL
			end
			do
				local T1L = S0L + buffer.readu32(Buf, Base + 700) + buffer.readu32(Buf, Base + 60) + bit32.bxor(S7L, bit32.band(S5L, bit32.bxor(S6L, S7L))) + bit32.bxor(bit32.bor(bit32.rshift(S5L, 14), bit32.lshift(S5H, 18)), bit32.bor(bit32.rshift(S5L, 18), bit32.lshift(S5H, 14)), bit32.bor(bit32.rshift(S5H, 9), bit32.lshift(S5L, 23)))
				local T1H = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0H + buffer.readu32(Buf, Base + 696), 0) + buffer.readu32(Buf, Base + 56), 0) + bit32.bxor(S7H, bit32.band(S5H, bit32.bxor(S6H, S7H))), 0) + bit32.bxor(bit32.bor(bit32.rshift(S5H, 14), bit32.lshift(S5L, 18)), bit32.bor(bit32.rshift(S5H, 18), bit32.lshift(S5L, 14)), bit32.bor(bit32.rshift(S5L, 9), bit32.lshift(S5H, 23))), 0)
				local EL = S4L + T1L
				S4H = bit32.bor(bit32.bor(S4H + T1H, 0) + math.floor(EL * CARRY), 0)
				S4L = bit32.bor(EL, 0)
				local ABL = bit32.bxor(S1L, S2L)
				local AL = T1L + bit32.bxor(S2L, bit32.band(ABL, BCL)) + bit32.bxor(bit32.bor(bit32.rshift(S1L, 28), bit32.lshift(S1H, 4)), bit32.bor(bit32.rshift(S1H, 2), bit32.lshift(S1L, 30)), bit32.bor(bit32.rshift(S1H, 7), bit32.lshift(S1L, 25)))
				local ABH = bit32.bxor(S1H, S2H)
				S0H = bit32.bor(bit32.bor(bit32.bor(T1H + bit32.bxor(S2H, bit32.band(ABH, BCH)), 0) + bit32.bxor(bit32.bor(bit32.rshift(S1H, 28), bit32.lshift(S1L, 4)), bit32.bor(bit32.rshift(S1L, 2), bit32.lshift(S1H, 30)), bit32.bor(bit32.rshift(S1L, 7), bit32.lshift(S1H, 25))), 0) + math.floor(AL * CARRY), 0)
				S0L = bit32.bor(AL, 0)
				BCH, BCL = ABH, ABL
			end
			buffer.writeu32(Buf, 0, S0H); buffer.writeu32(Buf, 4, S0L)
			buffer.writeu32(Buf, 8, S1H); buffer.writeu32(Buf, 12, S1L)
			buffer.writeu32(Buf, 16, S2H); buffer.writeu32(Buf, 20, S2L)
			buffer.writeu32(Buf, 24, S3H); buffer.writeu32(Buf, 28, S3L)
			buffer.writeu32(Buf, 32, S4H); buffer.writeu32(Buf, 36, S4L)
			buffer.writeu32(Buf, 40, S5H); buffer.writeu32(Buf, 44, S5L)
			buffer.writeu32(Buf, 48, S6H); buffer.writeu32(Buf, 52, S6L)
			buffer.writeu32(Buf, 56, S7H); buffer.writeu32(Buf, 60, S7L)
		end
		do local SL = buffer.readu32(State, 4) + buffer.readu32(Buf, 4); buffer.writeu32(State, 0, bit32.bor(bit32.bor(buffer.readu32(State, 0) + buffer.readu32(Buf, 0), 0) + math.floor(SL * CARRY), 0)); buffer.writeu32(State, 4, SL) end
		do local SL = buffer.readu32(State, 12) + buffer.readu32(Buf, 12); buffer.writeu32(State, 8, bit32.bor(bit32.bor(buffer.readu32(State, 8) + buffer.readu32(Buf, 8), 0) + math.floor(SL * CARRY), 0)); buffer.writeu32(State, 12, SL) end
		do local SL = buffer.readu32(State, 20) + buffer.readu32(Buf, 20); buffer.writeu32(State, 16, bit32.bor(bit32.bor(buffer.readu32(State, 16) + buffer.readu32(Buf, 16), 0) + math.floor(SL * CARRY), 0)); buffer.writeu32(State, 20, SL) end
		do local SL = buffer.readu32(State, 28) + buffer.readu32(Buf, 28); buffer.writeu32(State, 24, bit32.bor(bit32.bor(buffer.readu32(State, 24) + buffer.readu32(Buf, 24), 0) + math.floor(SL * CARRY), 0)); buffer.writeu32(State, 28, SL) end
		do local SL = buffer.readu32(State, 36) + buffer.readu32(Buf, 36); buffer.writeu32(State, 32, bit32.bor(bit32.bor(buffer.readu32(State, 32) + buffer.readu32(Buf, 32), 0) + math.floor(SL * CARRY), 0)); buffer.writeu32(State, 36, SL) end
		do local SL = buffer.readu32(State, 44) + buffer.readu32(Buf, 44); buffer.writeu32(State, 40, bit32.bor(bit32.bor(buffer.readu32(State, 40) + buffer.readu32(Buf, 40), 0) + math.floor(SL * CARRY), 0)); buffer.writeu32(State, 44, SL) end
		do local SL = buffer.readu32(State, 52) + buffer.readu32(Buf, 52); buffer.writeu32(State, 48, bit32.bor(bit32.bor(buffer.readu32(State, 48) + buffer.readu32(Buf, 48), 0) + math.floor(SL * CARRY), 0)); buffer.writeu32(State, 52, SL) end
		do local SL = buffer.readu32(State, 60) + buffer.readu32(Buf, 60); buffer.writeu32(State, 56, bit32.bor(bit32.bor(buffer.readu32(State, 56) + buffer.readu32(Buf, 56), 0) + math.floor(SL * CARRY), 0)); buffer.writeu32(State, 60, SL) end
	end
end

local function Digest(Message: buffer, InitialState: buffer, OutputBytes: number, PrefixBytes: number?): buffer
	local State: buffer = STATE
	buffer.writef64(State, 0, buffer.readf64(InitialState, 0)); buffer.writef64(State, 8, buffer.readf64(InitialState, 8))
	buffer.writef64(State, 16, buffer.readf64(InitialState, 16)); buffer.writef64(State, 24, buffer.readf64(InitialState, 24))
	buffer.writef64(State, 32, buffer.readf64(InitialState, 32)); buffer.writef64(State, 40, buffer.readf64(InitialState, 40))
	buffer.writef64(State, 48, buffer.readf64(InitialState, 48)); buffer.writef64(State, 56, buffer.readf64(InitialState, 56))

	local MessageLength = buffer.len(Message)
	local TailLength = MessageLength % 128
	local FullBytes = MessageLength - TailLength

	if FullBytes > 0 then
		Compress(Message, 0, FullBytes, State)
	end

	local Tail: buffer = TAIL
	buffer.writef64(Tail, 0, 0); buffer.writef64(Tail, 8, 0); buffer.writef64(Tail, 16, 0); buffer.writef64(Tail, 24, 0)
	buffer.writef64(Tail, 32, 0); buffer.writef64(Tail, 40, 0); buffer.writef64(Tail, 48, 0); buffer.writef64(Tail, 56, 0)
	buffer.writef64(Tail, 64, 0); buffer.writef64(Tail, 72, 0); buffer.writef64(Tail, 80, 0); buffer.writef64(Tail, 88, 0)
	buffer.writef64(Tail, 96, 0); buffer.writef64(Tail, 104, 0); buffer.writef64(Tail, 112, 0); buffer.writef64(Tail, 120, 0)
	if TailLength > 0 then
		local CopyEnd = TailLength - TailLength % 8
		for Index = 0, CopyEnd - 8, 8 do
			buffer.writef64(Tail, Index, buffer.readf64(Message, FullBytes + Index))
		end
		for Index = CopyEnd, TailLength - 1 do
			buffer.writeu8(Tail, Index, buffer.readu8(Message, FullBytes + Index))
		end
	end
	buffer.writeu8(Tail, TailLength, 0x80)

	local BitLength = (MessageLength + (PrefixBytes or 0)) * 8
	if TailLength >= 112 then
		Compress(Tail, 0, 128, State)
		buffer.fill(Tail, 0, 0, 120)
	end
	buffer.writeu32(Tail, 120, bit32.byteswap(math.floor(BitLength * CARRY)))
	buffer.writeu32(Tail, 124, bit32.byteswap(BitLength))
	Compress(Tail, 0, 128, State)

	local Result = buffer.create(OutputBytes)
	for Offset = 0, OutputBytes - 4, 4 do
		buffer.writeu32(Result, Offset, bit32.byteswap(buffer.readu32(State, Offset)))
	end

	return Result
end

local function SHA512_Internal(Message: buffer): buffer
	return Digest(Message, IV_512, 64)
end

local function SHA512(Message: buffer): (string, buffer)
	local Result = Digest(Message, IV_512, 64)

	return ToHex(Result), Result
end

local function ClearCaches()
	buffer.fill(BUF, 0, 0, 704)
	buffer.fill(STATE, 0, 0)
	buffer.fill(TAIL, 0, 0)
end

return {
	SHA512 = SHA512,
	ClearCaches = ClearCaches,
	SHA512_Internal = SHA512_Internal,
	Digest_Internal = Digest,
	Compress_Internal = Compress,
	IV_384 = IV_384,
	IV_512 = IV_512,
}
