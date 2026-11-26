--[=[
	Cryptography library: AES-GCM (AES-128, AES-192, AES-256)

	Sizes:
		Init Vector: any non-zero length (12 bytes recommended)
		Key Size: 16 / 24 / 32 bytes
		Tag: 16 bytes

	Return type: Encrypt (buffer, buffer), Decrypt buffer?
	Decrypt returns nil when authentication fails, including tags
	that are not 16 bytes long.

	Layout notes:
		PAIR01 holds Te0[Low] xor Te1[High] (256 KB); Te2 xor Te3 is obtained
		by rotating PAIR01 by 16 bits, halving the round table working set so
		it stays L2-resident. One CtrPairs function handles all key sizes and
		precomputes rounds 1 and 2 per 256-block counter page. BYTE_TABLES
		(64 KB) is allocated lazily on the first cached key or >= 2 KB call.

	Example usage:
		local Key = CSPRNG.RandomBytes(32)
		local IV = CSPRNG.RandomBytes(12)

		local Message = "This is a secret message"
		local Plaintext = buffer.fromstring(Message)

		local AAD = buffer.fromstring("user:john,timestamp:456745683")
		local Ciphertext, Tag = AES.Encrypt(Plaintext, Key, IV, AAD)
		local Decrypted = AES.Decrypt(Ciphertext, Key, IV, Tag, AAD)
--]=]

--!strict
--!optimize 2
--!native

local AES = {}
local CtCompare = require("../Utilities/Functions").CtCompare

local SUBSTITUTION_BOX: buffer = buffer.create(256)
local TTABLE: buffer = buffer.create(4096)
local PAIR01: buffer = buffer.create(262144)
local RCON: buffer = buffer.create(10)

local ROUND_KEYS: buffer = buffer.create(240)
local CACHE_KEY: buffer = buffer.create(32)
local HASH_KEY: buffer = buffer.create(16)
local NIBBLE_TABLES: buffer = buffer.create(8192)
local ByteTables: buffer? = nil
local GHASH_STATE: buffer = buffer.create(16)
local GHASH_BLOCK: buffer = buffer.create(16)
local STATE_WORDS: buffer = buffer.create(64)
local PAGE_Q: buffer = buffer.create(16)
local KEYSTREAM: buffer = buffer.create(16)
local ZERO_BLOCK: buffer = buffer.create(16)
local EMPTY: buffer = buffer.create(0)

local CacheLength = 0
local CacheRounds = 0
local ByteTablesReady = false

do
	local PolynomialP = 1
	local PolynomialQ = 1
	buffer.writeu8(SUBSTITUTION_BOX, 0, 99)
	for _ = 1, 255 do
		PolynomialP = bit32.bxor(PolynomialP, PolynomialP * 2, PolynomialP < 128 and 0 or 27) % 256
		PolynomialQ = bit32.bxor(PolynomialQ, PolynomialQ * 2)
		PolynomialQ = bit32.bxor(PolynomialQ, PolynomialQ * 4)
		PolynomialQ = bit32.bxor(PolynomialQ, PolynomialQ * 16) % 256
		if PolynomialQ >= 128 then
			PolynomialQ = bit32.bxor(PolynomialQ, 9)
		end
		local TempValue = bit32.bxor(
			PolynomialQ,
			PolynomialQ % 128 * 2 + PolynomialQ / 128,
			PolynomialQ % 64 * 4 + PolynomialQ / 64,
			PolynomialQ % 32 * 8 + PolynomialQ / 32,
			PolynomialQ % 16 * 16 + PolynomialQ / 16,
			99
		)
		buffer.writeu8(SUBSTITUTION_BOX, PolynomialP, TempValue)
	end

	for B = 0, 255 do
		local S = buffer.readu8(SUBSTITUTION_BOX, B)
		local S2 = bit32.band(bit32.bxor(S * 2, if S >= 128 then 27 else 0), 255)
		local S3 = bit32.bxor(S2, S)
		local Base = B * 16
		buffer.writeu32(TTABLE, Base, bit32.bor(S2, bit32.lshift(S, 8), bit32.lshift(S, 16), bit32.lshift(S3, 24)))
		buffer.writeu32(TTABLE, Base + 4, bit32.bor(S3, bit32.lshift(S2, 8), bit32.lshift(S, 16), bit32.lshift(S, 24)))
		buffer.writeu32(TTABLE, Base + 8, bit32.bor(S, bit32.lshift(S3, 8), bit32.lshift(S2, 16), bit32.lshift(S, 24)))
		buffer.writeu32(TTABLE, Base + 12, bit32.bor(S, bit32.lshift(S, 8), bit32.lshift(S3, 16), bit32.lshift(S2, 24)))
	end

	local T: buffer = TTABLE
	local Pair01: buffer = PAIR01
	for High = 0, 255 do
		local Te1 = buffer.readu32(T, High * 16 + 4)
		local RowOffset = High * 1024
		for Low = 0, 252, 4 do
			local LowBase = Low * 16
			local Out = RowOffset + Low * 4
			buffer.writeu32(Pair01, Out, bit32.bxor(buffer.readu32(T, LowBase), Te1))
			buffer.writeu32(Pair01, Out + 4, bit32.bxor(buffer.readu32(T, LowBase + 16), Te1))
			buffer.writeu32(Pair01, Out + 8, bit32.bxor(buffer.readu32(T, LowBase + 32), Te1))
			buffer.writeu32(Pair01, Out + 12, bit32.bxor(buffer.readu32(T, LowBase + 48), Te1))
		end
	end

	local RoundConstant = 1
	for Index = 0, 9 do
		buffer.writeu8(RCON, Index, RoundConstant)
		RoundConstant = bit32.band(bit32.bxor(RoundConstant * 2, if RoundConstant >= 128 then 27 else 0), 255)
	end
end

local function ZeroBlock(Block: buffer)
	buffer.writeu32(Block, 0, 0)
	buffer.writeu32(Block, 4, 0)
	buffer.writeu32(Block, 8, 0)
	buffer.writeu32(Block, 12, 0)
end

local function SubWord(Box: buffer, Word: number): number
	return bit32.bor(
		buffer.readu8(Box, bit32.band(Word, 0xff)),
		bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(Word, 8), 0xff)), 8),
		bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(Word, 16), 0xff)), 16),
		bit32.lshift(buffer.readu8(Box, bit32.rshift(Word, 24)), 24)
	)
end

local function ExpandKeySchedule(Key: buffer, KeyLength: number, OutputBuffer: buffer)
	local Box: buffer = SUBSTITUTION_BOX
	local RoundConstants: buffer = RCON
	buffer.copy(OutputBuffer, 0, Key, 0, KeyLength)

	local Word = bit32.rrotate(buffer.readu32(OutputBuffer, KeyLength - 4), 8)
	local Step = 0

	if KeyLength == 32 then
		for KeyOffset = 32, 192, 32 do
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 32), SubWord(Box, Word), buffer.readu8(RoundConstants, Step))
			Step += 1
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			local W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 28), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, W1)
			local W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 24), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, W2)
			local W3 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 20), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, W3)

			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 16), SubWord(Box, W3))
			buffer.writeu32(OutputBuffer, KeyOffset + 16, Word)

			W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 20, W1)
			W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 24, W2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 28, Word)
			Word = bit32.rrotate(Word, 8)
		end

		Word = bit32.bxor(buffer.readu32(OutputBuffer, 192), SubWord(Box, Word), 64)
		buffer.writeu32(OutputBuffer, 224, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 196), Word)
		buffer.writeu32(OutputBuffer, 228, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 200), W1)
		buffer.writeu32(OutputBuffer, 232, W2)
		buffer.writeu32(OutputBuffer, 236, bit32.bxor(buffer.readu32(OutputBuffer, 204), W2))
	elseif KeyLength == 24 then
		for KeyOffset = 24, 168, 24 do
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 24), SubWord(Box, Word), buffer.readu8(RoundConstants, Step))
			Step += 1
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			local W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 20), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, W1)
			local W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 16), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, W2)
			local W3 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, W3)
			local W4 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), W3)
			buffer.writeu32(OutputBuffer, KeyOffset + 16, W4)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), W4)
			buffer.writeu32(OutputBuffer, KeyOffset + 20, Word)
			Word = bit32.rrotate(Word, 8)
		end

		Word = bit32.bxor(buffer.readu32(OutputBuffer, 168), SubWord(Box, Word), 128)
		buffer.writeu32(OutputBuffer, 192, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 172), Word)
		buffer.writeu32(OutputBuffer, 196, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 176), W1)
		buffer.writeu32(OutputBuffer, 200, W2)
		buffer.writeu32(OutputBuffer, 204, bit32.bxor(buffer.readu32(OutputBuffer, 180), W2))
	else
		for KeyOffset = 16, 144, 16 do
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 16), SubWord(Box, Word), buffer.readu8(RoundConstants, Step))
			Step += 1
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			local W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, W1)
			local W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, W2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, Word)
			Word = bit32.rrotate(Word, 8)
		end

		Word = bit32.bxor(buffer.readu32(OutputBuffer, 144), SubWord(Box, Word), 54)
		buffer.writeu32(OutputBuffer, 160, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 148), Word)
		buffer.writeu32(OutputBuffer, 164, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 152), W1)
		buffer.writeu32(OutputBuffer, 168, W2)
		buffer.writeu32(OutputBuffer, 172, bit32.bxor(buffer.readu32(OutputBuffer, 156), W2))
	end
end

local function PrepareRound1(J0: number, J1: number, J2: number): (number, number, number, number, number)
	local T: buffer = TTABLE
	local RK: buffer = ROUND_KEYS
	local S0 = bit32.bxor(J0, buffer.readu32(RK, 0))
	local S1 = bit32.bxor(J1, buffer.readu32(RK, 4))
	local S2 = bit32.bxor(J2, buffer.readu32(RK, 8))
	local K3 = buffer.readu32(RK, 12)
	local P0 = bit32.bxor(buffer.readu32(T, bit32.band(bit32.lshift(S0, 4), 0xff0)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S1, 4), 0xff0), 4)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S2, 12), 0xff0), 8)), buffer.readu32(RK, 16))
	local P1 = bit32.bxor(buffer.readu32(T, bit32.band(bit32.lshift(S1, 4), 0xff0)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S2, 4), 0xff0), 4)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S0, 20), 0xff0), 12)), buffer.readu32(RK, 20))
	local P2 = bit32.bxor(buffer.readu32(T, bit32.band(bit32.lshift(S2, 4), 0xff0)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S0, 12), 0xff0), 8)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S1, 20), 0xff0), 12)), buffer.readu32(RK, 24))
	local P3 = bit32.bxor(buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S0, 4), 0xff0), 4)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S1, 12), 0xff0), 8)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S2, 20), 0xff0), 12)), buffer.readu32(RK, 28))
	return P0, P1, P2, P3, K3
end

local function XorBlockWithP(Rounds: number, Input: buffer, Output: buffer, Position: number, P0: number, P1: number, P2: number, P3: number, K3: number, Counter: number)
	local T: buffer = TTABLE
	local T01: buffer = PAIR01
	local Box: buffer = SUBSTITUTION_BOX
	local RK: buffer = ROUND_KEYS
	local Last = Rounds * 16

	local VA = bit32.bxor(bit32.byteswap(Counter), K3)
	local RA0 = bit32.bxor(P0, buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(VA, 20), 0xff0), 12)))
	local RA1 = bit32.bxor(P1, buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(VA, 12), 0xff0), 8)))
	local RA2 = bit32.bxor(P2, buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(VA, 4), 0xff0), 4)))
	local RA3 = bit32.bxor(P3, buffer.readu32(T, bit32.band(bit32.lshift(VA, 4), 0xff0)))
	local SA0, SA1, SA2, SA3 = 0, 0, 0, 0
	do
		SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), 16), buffer.readu32(RK, 32))
		SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), 16), buffer.readu32(RK, 36))
		SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), 16), buffer.readu32(RK, 40))
		SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), 16), buffer.readu32(RK, 44))
	end
	do
		RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), 16), buffer.readu32(RK, 48))
		RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), 16), buffer.readu32(RK, 52))
		RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), 16), buffer.readu32(RK, 56))
		RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), 16), buffer.readu32(RK, 60))
	end
	do
		SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), 16), buffer.readu32(RK, 64))
		SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), 16), buffer.readu32(RK, 68))
		SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), 16), buffer.readu32(RK, 72))
		SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), 16), buffer.readu32(RK, 76))
	end
	do
		RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), 16), buffer.readu32(RK, 80))
		RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), 16), buffer.readu32(RK, 84))
		RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), 16), buffer.readu32(RK, 88))
		RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), 16), buffer.readu32(RK, 92))
	end
	do
		SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), 16), buffer.readu32(RK, 96))
		SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), 16), buffer.readu32(RK, 100))
		SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), 16), buffer.readu32(RK, 104))
		SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), 16), buffer.readu32(RK, 108))
	end
	do
		RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), 16), buffer.readu32(RK, 112))
		RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), 16), buffer.readu32(RK, 116))
		RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), 16), buffer.readu32(RK, 120))
		RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), 16), buffer.readu32(RK, 124))
	end
	do
		SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), 16), buffer.readu32(RK, 128))
		SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), 16), buffer.readu32(RK, 132))
		SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), 16), buffer.readu32(RK, 136))
		SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), 16), buffer.readu32(RK, 140))
	end
	do
		RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), 16), buffer.readu32(RK, 144))
		RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), 16), buffer.readu32(RK, 148))
		RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), 16), buffer.readu32(RK, 152))
		RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), 16), buffer.readu32(RK, 156))
	end
	if Rounds > 10 then
		do
			SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), 16), buffer.readu32(RK, 160))
			SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), 16), buffer.readu32(RK, 164))
			SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), 16), buffer.readu32(RK, 168))
			SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), 16), buffer.readu32(RK, 172))
		end
		do
			RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), 16), buffer.readu32(RK, 176))
			RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), 16), buffer.readu32(RK, 180))
			RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), 16), buffer.readu32(RK, 184))
			RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), 16), buffer.readu32(RK, 188))
		end
		if Rounds > 12 then
			do
				SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), 16), buffer.readu32(RK, 192))
				SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), 16), buffer.readu32(RK, 196))
				SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), 16), buffer.readu32(RK, 200))
				SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), 16), buffer.readu32(RK, 204))
			end
			do
				RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), 16), buffer.readu32(RK, 208))
				RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), 16), buffer.readu32(RK, 212))
				RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), 16), buffer.readu32(RK, 216))
				RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), 16), buffer.readu32(RK, 220))
			end
		end
	end
	buffer.writeu32(Output, Position + 0, bit32.bxor(buffer.readu32(Input, Position + 0), bit32.bor(buffer.readu8(Box, bit32.band(RA0, 0xff)), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(RA1, 8), 0xff)), 8), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(RA2, 16), 0xff)), 16), bit32.lshift(buffer.readu8(Box, bit32.rshift(RA3, 24)), 24)), buffer.readu32(RK, Last + 0)))
	buffer.writeu32(Output, Position + 4, bit32.bxor(buffer.readu32(Input, Position + 4), bit32.bor(buffer.readu8(Box, bit32.band(RA1, 0xff)), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(RA2, 8), 0xff)), 8), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(RA3, 16), 0xff)), 16), bit32.lshift(buffer.readu8(Box, bit32.rshift(RA0, 24)), 24)), buffer.readu32(RK, Last + 4)))
	buffer.writeu32(Output, Position + 8, bit32.bxor(buffer.readu32(Input, Position + 8), bit32.bor(buffer.readu8(Box, bit32.band(RA2, 0xff)), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(RA3, 8), 0xff)), 8), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(RA0, 16), 0xff)), 16), bit32.lshift(buffer.readu8(Box, bit32.rshift(RA1, 24)), 24)), buffer.readu32(RK, Last + 8)))
	buffer.writeu32(Output, Position + 12, bit32.bxor(buffer.readu32(Input, Position + 12), bit32.bor(buffer.readu8(Box, bit32.band(RA3, 0xff)), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(RA0, 8), 0xff)), 8), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(RA1, 16), 0xff)), 16), bit32.lshift(buffer.readu8(Box, bit32.rshift(RA2, 24)), 24)), buffer.readu32(RK, Last + 12)))
end

local function CtrWithP(Rounds: number, Input: buffer, Output: buffer, Length: number, P0: number, P1: number, P2: number, P3: number, K3: number, Counter: number)
	local T: buffer = TTABLE
	local T01: buffer = PAIR01
	local Box: buffer = SUBSTITUTION_BOX
	local RK: buffer = ROUND_KEYS
	local StateWords: buffer = STATE_WORDS
	local PageQ: buffer = PAGE_Q
	local K3Top = bit32.rshift(K3, 24)
	local Last = Rounds * 16

	local Offset = 0
	local C = Counter
	while Offset + 32 <= Length do
		local LowStart = bit32.band(C, 0xff)
		if LowStart == 255 then
			XorBlockWithP(Rounds, Input, Output, Offset, P0, P1, P2, P3, K3, C)
			Offset += 16
			C = (C + 1) % 4294967296
			continue
		end

		local VBase = bit32.bxor(bit32.byteswap(bit32.band(C, 0xffffff00)), K3)
		local A1 = bit32.bxor(P1, buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(VBase, 12), 0xff0), 8)))
		local A2 = bit32.bxor(P2, buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(VBase, 4), 0xff0), 4)))
		local A3 = bit32.bxor(P3, buffer.readu32(T, bit32.band(bit32.lshift(VBase, 4), 0xff0)))

		buffer.writeu32(PageQ, 0, bit32.bxor(buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(A1, 4), 0xff0), 4)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(A2, 0xff0000), bit32.band(A3, 0xff000000)), 14)), 16), buffer.readu32(RK, 32)))
		buffer.writeu32(PageQ, 4, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(A1, 0xff), bit32.band(A2, 0xff00)), 2)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(A3, 12), 0xff0), 8)), buffer.readu32(RK, 36)))
		buffer.writeu32(PageQ, 8, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(A2, 0xff), bit32.band(A3, 0xff00)), 2)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(A1, 20), 0xff0), 12)), buffer.readu32(RK, 40)))
		buffer.writeu32(PageQ, 12, bit32.bxor(buffer.readu32(T, bit32.band(bit32.lshift(A3, 4), 0xff0)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(A1, 0xff0000), bit32.band(A2, 0xff000000)), 14)), 16), buffer.readu32(RK, 44)))

		local MaxPairs = math.floor((256 - LowStart) / 2)
		local RemPairs = math.floor((Length - Offset) / 32)
		local Pairs = if MaxPairs < RemPairs then MaxPairs else RemPairs
		for Low = LowStart, LowStart + Pairs * 2 - 2, 2 do
			local Position = Offset
			do
				local A0 = bit32.bxor(P0, buffer.readu32(T, bit32.bor(bit32.lshift(bit32.bxor(Low, K3Top), 4), 12)))
				buffer.writeu32(StateWords, 32, bit32.bxor(buffer.readu32(PageQ, 0), buffer.readu32(T, bit32.band(bit32.lshift(A0, 4), 0xff0))))
				buffer.writeu32(StateWords, 36, bit32.bxor(buffer.readu32(PageQ, 4), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(A0, 20), 0xff0), 12))))
				buffer.writeu32(StateWords, 40, bit32.bxor(buffer.readu32(PageQ, 8), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(A0, 12), 0xff0), 8))))
				buffer.writeu32(StateWords, 44, bit32.bxor(buffer.readu32(PageQ, 12), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(A0, 4), 0xff0), 4))))

				local B0 = bit32.bxor(P0, buffer.readu32(T, bit32.bor(bit32.lshift(bit32.bxor(Low + 1, K3Top), 4), 12)))
				buffer.writeu32(StateWords, 48, bit32.bxor(buffer.readu32(PageQ, 0), buffer.readu32(T, bit32.band(bit32.lshift(B0, 4), 0xff0))))
				buffer.writeu32(StateWords, 52, bit32.bxor(buffer.readu32(PageQ, 4), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(B0, 20), 0xff0), 12))))
				buffer.writeu32(StateWords, 56, bit32.bxor(buffer.readu32(PageQ, 8), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(B0, 12), 0xff0), 8))))
				buffer.writeu32(StateWords, 60, bit32.bxor(buffer.readu32(PageQ, 12), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(B0, 4), 0xff0), 4))))
			end
			do
				buffer.writeu32(StateWords, 0, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 32), 0xff), bit32.band(buffer.readu32(StateWords, 36), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 40), 0xff0000), bit32.band(buffer.readu32(StateWords, 44), 0xff000000)), 14)), 16), buffer.readu32(RK, 48)))
				buffer.writeu32(StateWords, 4, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 36), 0xff), bit32.band(buffer.readu32(StateWords, 40), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 44), 0xff0000), bit32.band(buffer.readu32(StateWords, 32), 0xff000000)), 14)), 16), buffer.readu32(RK, 52)))
				buffer.writeu32(StateWords, 8, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 40), 0xff), bit32.band(buffer.readu32(StateWords, 44), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 32), 0xff0000), bit32.band(buffer.readu32(StateWords, 36), 0xff000000)), 14)), 16), buffer.readu32(RK, 56)))
				buffer.writeu32(StateWords, 12, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 44), 0xff), bit32.band(buffer.readu32(StateWords, 32), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 36), 0xff0000), bit32.band(buffer.readu32(StateWords, 40), 0xff000000)), 14)), 16), buffer.readu32(RK, 60)))
				buffer.writeu32(StateWords, 16, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 48), 0xff), bit32.band(buffer.readu32(StateWords, 52), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 56), 0xff0000), bit32.band(buffer.readu32(StateWords, 60), 0xff000000)), 14)), 16), buffer.readu32(RK, 48)))
				buffer.writeu32(StateWords, 20, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 52), 0xff), bit32.band(buffer.readu32(StateWords, 56), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 60), 0xff0000), bit32.band(buffer.readu32(StateWords, 48), 0xff000000)), 14)), 16), buffer.readu32(RK, 52)))
				buffer.writeu32(StateWords, 24, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 56), 0xff), bit32.band(buffer.readu32(StateWords, 60), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 48), 0xff0000), bit32.band(buffer.readu32(StateWords, 52), 0xff000000)), 14)), 16), buffer.readu32(RK, 56)))
				buffer.writeu32(StateWords, 28, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 60), 0xff), bit32.band(buffer.readu32(StateWords, 48), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 52), 0xff0000), bit32.band(buffer.readu32(StateWords, 56), 0xff000000)), 14)), 16), buffer.readu32(RK, 60)))
			end
			do
				buffer.writeu32(StateWords, 32, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 0), 0xff), bit32.band(buffer.readu32(StateWords, 4), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 8), 0xff0000), bit32.band(buffer.readu32(StateWords, 12), 0xff000000)), 14)), 16), buffer.readu32(RK, 64)))
				buffer.writeu32(StateWords, 36, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 4), 0xff), bit32.band(buffer.readu32(StateWords, 8), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 12), 0xff0000), bit32.band(buffer.readu32(StateWords, 0), 0xff000000)), 14)), 16), buffer.readu32(RK, 68)))
				buffer.writeu32(StateWords, 40, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 8), 0xff), bit32.band(buffer.readu32(StateWords, 12), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 0), 0xff0000), bit32.band(buffer.readu32(StateWords, 4), 0xff000000)), 14)), 16), buffer.readu32(RK, 72)))
				buffer.writeu32(StateWords, 44, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 12), 0xff), bit32.band(buffer.readu32(StateWords, 0), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 4), 0xff0000), bit32.band(buffer.readu32(StateWords, 8), 0xff000000)), 14)), 16), buffer.readu32(RK, 76)))
				buffer.writeu32(StateWords, 48, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 16), 0xff), bit32.band(buffer.readu32(StateWords, 20), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 24), 0xff0000), bit32.band(buffer.readu32(StateWords, 28), 0xff000000)), 14)), 16), buffer.readu32(RK, 64)))
				buffer.writeu32(StateWords, 52, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 20), 0xff), bit32.band(buffer.readu32(StateWords, 24), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 28), 0xff0000), bit32.band(buffer.readu32(StateWords, 16), 0xff000000)), 14)), 16), buffer.readu32(RK, 68)))
				buffer.writeu32(StateWords, 56, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 24), 0xff), bit32.band(buffer.readu32(StateWords, 28), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 16), 0xff0000), bit32.band(buffer.readu32(StateWords, 20), 0xff000000)), 14)), 16), buffer.readu32(RK, 72)))
				buffer.writeu32(StateWords, 60, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 28), 0xff), bit32.band(buffer.readu32(StateWords, 16), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 20), 0xff0000), bit32.band(buffer.readu32(StateWords, 24), 0xff000000)), 14)), 16), buffer.readu32(RK, 76)))
			end
			do
				buffer.writeu32(StateWords, 0, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 32), 0xff), bit32.band(buffer.readu32(StateWords, 36), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 40), 0xff0000), bit32.band(buffer.readu32(StateWords, 44), 0xff000000)), 14)), 16), buffer.readu32(RK, 80)))
				buffer.writeu32(StateWords, 4, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 36), 0xff), bit32.band(buffer.readu32(StateWords, 40), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 44), 0xff0000), bit32.band(buffer.readu32(StateWords, 32), 0xff000000)), 14)), 16), buffer.readu32(RK, 84)))
				buffer.writeu32(StateWords, 8, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 40), 0xff), bit32.band(buffer.readu32(StateWords, 44), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 32), 0xff0000), bit32.band(buffer.readu32(StateWords, 36), 0xff000000)), 14)), 16), buffer.readu32(RK, 88)))
				buffer.writeu32(StateWords, 12, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 44), 0xff), bit32.band(buffer.readu32(StateWords, 32), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 36), 0xff0000), bit32.band(buffer.readu32(StateWords, 40), 0xff000000)), 14)), 16), buffer.readu32(RK, 92)))
				buffer.writeu32(StateWords, 16, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 48), 0xff), bit32.band(buffer.readu32(StateWords, 52), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 56), 0xff0000), bit32.band(buffer.readu32(StateWords, 60), 0xff000000)), 14)), 16), buffer.readu32(RK, 80)))
				buffer.writeu32(StateWords, 20, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 52), 0xff), bit32.band(buffer.readu32(StateWords, 56), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 60), 0xff0000), bit32.band(buffer.readu32(StateWords, 48), 0xff000000)), 14)), 16), buffer.readu32(RK, 84)))
				buffer.writeu32(StateWords, 24, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 56), 0xff), bit32.band(buffer.readu32(StateWords, 60), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 48), 0xff0000), bit32.band(buffer.readu32(StateWords, 52), 0xff000000)), 14)), 16), buffer.readu32(RK, 88)))
				buffer.writeu32(StateWords, 28, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 60), 0xff), bit32.band(buffer.readu32(StateWords, 48), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 52), 0xff0000), bit32.band(buffer.readu32(StateWords, 56), 0xff000000)), 14)), 16), buffer.readu32(RK, 92)))
			end
			do
				buffer.writeu32(StateWords, 32, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 0), 0xff), bit32.band(buffer.readu32(StateWords, 4), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 8), 0xff0000), bit32.band(buffer.readu32(StateWords, 12), 0xff000000)), 14)), 16), buffer.readu32(RK, 96)))
				buffer.writeu32(StateWords, 36, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 4), 0xff), bit32.band(buffer.readu32(StateWords, 8), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 12), 0xff0000), bit32.band(buffer.readu32(StateWords, 0), 0xff000000)), 14)), 16), buffer.readu32(RK, 100)))
				buffer.writeu32(StateWords, 40, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 8), 0xff), bit32.band(buffer.readu32(StateWords, 12), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 0), 0xff0000), bit32.band(buffer.readu32(StateWords, 4), 0xff000000)), 14)), 16), buffer.readu32(RK, 104)))
				buffer.writeu32(StateWords, 44, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 12), 0xff), bit32.band(buffer.readu32(StateWords, 0), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 4), 0xff0000), bit32.band(buffer.readu32(StateWords, 8), 0xff000000)), 14)), 16), buffer.readu32(RK, 108)))
				buffer.writeu32(StateWords, 48, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 16), 0xff), bit32.band(buffer.readu32(StateWords, 20), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 24), 0xff0000), bit32.band(buffer.readu32(StateWords, 28), 0xff000000)), 14)), 16), buffer.readu32(RK, 96)))
				buffer.writeu32(StateWords, 52, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 20), 0xff), bit32.band(buffer.readu32(StateWords, 24), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 28), 0xff0000), bit32.band(buffer.readu32(StateWords, 16), 0xff000000)), 14)), 16), buffer.readu32(RK, 100)))
				buffer.writeu32(StateWords, 56, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 24), 0xff), bit32.band(buffer.readu32(StateWords, 28), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 16), 0xff0000), bit32.band(buffer.readu32(StateWords, 20), 0xff000000)), 14)), 16), buffer.readu32(RK, 104)))
				buffer.writeu32(StateWords, 60, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 28), 0xff), bit32.band(buffer.readu32(StateWords, 16), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 20), 0xff0000), bit32.band(buffer.readu32(StateWords, 24), 0xff000000)), 14)), 16), buffer.readu32(RK, 108)))
			end
			do
				buffer.writeu32(StateWords, 0, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 32), 0xff), bit32.band(buffer.readu32(StateWords, 36), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 40), 0xff0000), bit32.band(buffer.readu32(StateWords, 44), 0xff000000)), 14)), 16), buffer.readu32(RK, 112)))
				buffer.writeu32(StateWords, 4, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 36), 0xff), bit32.band(buffer.readu32(StateWords, 40), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 44), 0xff0000), bit32.band(buffer.readu32(StateWords, 32), 0xff000000)), 14)), 16), buffer.readu32(RK, 116)))
				buffer.writeu32(StateWords, 8, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 40), 0xff), bit32.band(buffer.readu32(StateWords, 44), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 32), 0xff0000), bit32.band(buffer.readu32(StateWords, 36), 0xff000000)), 14)), 16), buffer.readu32(RK, 120)))
				buffer.writeu32(StateWords, 12, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 44), 0xff), bit32.band(buffer.readu32(StateWords, 32), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 36), 0xff0000), bit32.band(buffer.readu32(StateWords, 40), 0xff000000)), 14)), 16), buffer.readu32(RK, 124)))
				buffer.writeu32(StateWords, 16, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 48), 0xff), bit32.band(buffer.readu32(StateWords, 52), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 56), 0xff0000), bit32.band(buffer.readu32(StateWords, 60), 0xff000000)), 14)), 16), buffer.readu32(RK, 112)))
				buffer.writeu32(StateWords, 20, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 52), 0xff), bit32.band(buffer.readu32(StateWords, 56), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 60), 0xff0000), bit32.band(buffer.readu32(StateWords, 48), 0xff000000)), 14)), 16), buffer.readu32(RK, 116)))
				buffer.writeu32(StateWords, 24, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 56), 0xff), bit32.band(buffer.readu32(StateWords, 60), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 48), 0xff0000), bit32.band(buffer.readu32(StateWords, 52), 0xff000000)), 14)), 16), buffer.readu32(RK, 120)))
				buffer.writeu32(StateWords, 28, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 60), 0xff), bit32.band(buffer.readu32(StateWords, 48), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 52), 0xff0000), bit32.band(buffer.readu32(StateWords, 56), 0xff000000)), 14)), 16), buffer.readu32(RK, 124)))
			end
			do
				buffer.writeu32(StateWords, 32, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 0), 0xff), bit32.band(buffer.readu32(StateWords, 4), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 8), 0xff0000), bit32.band(buffer.readu32(StateWords, 12), 0xff000000)), 14)), 16), buffer.readu32(RK, 128)))
				buffer.writeu32(StateWords, 36, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 4), 0xff), bit32.band(buffer.readu32(StateWords, 8), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 12), 0xff0000), bit32.band(buffer.readu32(StateWords, 0), 0xff000000)), 14)), 16), buffer.readu32(RK, 132)))
				buffer.writeu32(StateWords, 40, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 8), 0xff), bit32.band(buffer.readu32(StateWords, 12), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 0), 0xff0000), bit32.band(buffer.readu32(StateWords, 4), 0xff000000)), 14)), 16), buffer.readu32(RK, 136)))
				buffer.writeu32(StateWords, 44, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 12), 0xff), bit32.band(buffer.readu32(StateWords, 0), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 4), 0xff0000), bit32.band(buffer.readu32(StateWords, 8), 0xff000000)), 14)), 16), buffer.readu32(RK, 140)))
				buffer.writeu32(StateWords, 48, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 16), 0xff), bit32.band(buffer.readu32(StateWords, 20), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 24), 0xff0000), bit32.band(buffer.readu32(StateWords, 28), 0xff000000)), 14)), 16), buffer.readu32(RK, 128)))
				buffer.writeu32(StateWords, 52, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 20), 0xff), bit32.band(buffer.readu32(StateWords, 24), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 28), 0xff0000), bit32.band(buffer.readu32(StateWords, 16), 0xff000000)), 14)), 16), buffer.readu32(RK, 132)))
				buffer.writeu32(StateWords, 56, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 24), 0xff), bit32.band(buffer.readu32(StateWords, 28), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 16), 0xff0000), bit32.band(buffer.readu32(StateWords, 20), 0xff000000)), 14)), 16), buffer.readu32(RK, 136)))
				buffer.writeu32(StateWords, 60, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 28), 0xff), bit32.band(buffer.readu32(StateWords, 16), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 20), 0xff0000), bit32.band(buffer.readu32(StateWords, 24), 0xff000000)), 14)), 16), buffer.readu32(RK, 140)))
			end
			do
				buffer.writeu32(StateWords, 0, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 32), 0xff), bit32.band(buffer.readu32(StateWords, 36), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 40), 0xff0000), bit32.band(buffer.readu32(StateWords, 44), 0xff000000)), 14)), 16), buffer.readu32(RK, 144)))
				buffer.writeu32(StateWords, 4, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 36), 0xff), bit32.band(buffer.readu32(StateWords, 40), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 44), 0xff0000), bit32.band(buffer.readu32(StateWords, 32), 0xff000000)), 14)), 16), buffer.readu32(RK, 148)))
				buffer.writeu32(StateWords, 8, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 40), 0xff), bit32.band(buffer.readu32(StateWords, 44), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 32), 0xff0000), bit32.band(buffer.readu32(StateWords, 36), 0xff000000)), 14)), 16), buffer.readu32(RK, 152)))
				buffer.writeu32(StateWords, 12, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 44), 0xff), bit32.band(buffer.readu32(StateWords, 32), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 36), 0xff0000), bit32.band(buffer.readu32(StateWords, 40), 0xff000000)), 14)), 16), buffer.readu32(RK, 156)))
				buffer.writeu32(StateWords, 16, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 48), 0xff), bit32.band(buffer.readu32(StateWords, 52), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 56), 0xff0000), bit32.band(buffer.readu32(StateWords, 60), 0xff000000)), 14)), 16), buffer.readu32(RK, 144)))
				buffer.writeu32(StateWords, 20, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 52), 0xff), bit32.band(buffer.readu32(StateWords, 56), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 60), 0xff0000), bit32.band(buffer.readu32(StateWords, 48), 0xff000000)), 14)), 16), buffer.readu32(RK, 148)))
				buffer.writeu32(StateWords, 24, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 56), 0xff), bit32.band(buffer.readu32(StateWords, 60), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 48), 0xff0000), bit32.band(buffer.readu32(StateWords, 52), 0xff000000)), 14)), 16), buffer.readu32(RK, 152)))
				buffer.writeu32(StateWords, 28, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 60), 0xff), bit32.band(buffer.readu32(StateWords, 48), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 52), 0xff0000), bit32.band(buffer.readu32(StateWords, 56), 0xff000000)), 14)), 16), buffer.readu32(RK, 156)))
			end
			if Rounds > 10 then
				do
					buffer.writeu32(StateWords, 32, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 0), 0xff), bit32.band(buffer.readu32(StateWords, 4), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 8), 0xff0000), bit32.band(buffer.readu32(StateWords, 12), 0xff000000)), 14)), 16), buffer.readu32(RK, 160)))
					buffer.writeu32(StateWords, 36, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 4), 0xff), bit32.band(buffer.readu32(StateWords, 8), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 12), 0xff0000), bit32.band(buffer.readu32(StateWords, 0), 0xff000000)), 14)), 16), buffer.readu32(RK, 164)))
					buffer.writeu32(StateWords, 40, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 8), 0xff), bit32.band(buffer.readu32(StateWords, 12), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 0), 0xff0000), bit32.band(buffer.readu32(StateWords, 4), 0xff000000)), 14)), 16), buffer.readu32(RK, 168)))
					buffer.writeu32(StateWords, 44, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 12), 0xff), bit32.band(buffer.readu32(StateWords, 0), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 4), 0xff0000), bit32.band(buffer.readu32(StateWords, 8), 0xff000000)), 14)), 16), buffer.readu32(RK, 172)))
					buffer.writeu32(StateWords, 48, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 16), 0xff), bit32.band(buffer.readu32(StateWords, 20), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 24), 0xff0000), bit32.band(buffer.readu32(StateWords, 28), 0xff000000)), 14)), 16), buffer.readu32(RK, 160)))
					buffer.writeu32(StateWords, 52, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 20), 0xff), bit32.band(buffer.readu32(StateWords, 24), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 28), 0xff0000), bit32.band(buffer.readu32(StateWords, 16), 0xff000000)), 14)), 16), buffer.readu32(RK, 164)))
					buffer.writeu32(StateWords, 56, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 24), 0xff), bit32.band(buffer.readu32(StateWords, 28), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 16), 0xff0000), bit32.band(buffer.readu32(StateWords, 20), 0xff000000)), 14)), 16), buffer.readu32(RK, 168)))
					buffer.writeu32(StateWords, 60, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 28), 0xff), bit32.band(buffer.readu32(StateWords, 16), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 20), 0xff0000), bit32.band(buffer.readu32(StateWords, 24), 0xff000000)), 14)), 16), buffer.readu32(RK, 172)))
				end
				do
					buffer.writeu32(StateWords, 0, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 32), 0xff), bit32.band(buffer.readu32(StateWords, 36), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 40), 0xff0000), bit32.band(buffer.readu32(StateWords, 44), 0xff000000)), 14)), 16), buffer.readu32(RK, 176)))
					buffer.writeu32(StateWords, 4, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 36), 0xff), bit32.band(buffer.readu32(StateWords, 40), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 44), 0xff0000), bit32.band(buffer.readu32(StateWords, 32), 0xff000000)), 14)), 16), buffer.readu32(RK, 180)))
					buffer.writeu32(StateWords, 8, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 40), 0xff), bit32.band(buffer.readu32(StateWords, 44), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 32), 0xff0000), bit32.band(buffer.readu32(StateWords, 36), 0xff000000)), 14)), 16), buffer.readu32(RK, 184)))
					buffer.writeu32(StateWords, 12, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 44), 0xff), bit32.band(buffer.readu32(StateWords, 32), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 36), 0xff0000), bit32.band(buffer.readu32(StateWords, 40), 0xff000000)), 14)), 16), buffer.readu32(RK, 188)))
					buffer.writeu32(StateWords, 16, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 48), 0xff), bit32.band(buffer.readu32(StateWords, 52), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 56), 0xff0000), bit32.band(buffer.readu32(StateWords, 60), 0xff000000)), 14)), 16), buffer.readu32(RK, 176)))
					buffer.writeu32(StateWords, 20, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 52), 0xff), bit32.band(buffer.readu32(StateWords, 56), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 60), 0xff0000), bit32.band(buffer.readu32(StateWords, 48), 0xff000000)), 14)), 16), buffer.readu32(RK, 180)))
					buffer.writeu32(StateWords, 24, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 56), 0xff), bit32.band(buffer.readu32(StateWords, 60), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 48), 0xff0000), bit32.band(buffer.readu32(StateWords, 52), 0xff000000)), 14)), 16), buffer.readu32(RK, 184)))
					buffer.writeu32(StateWords, 28, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 60), 0xff), bit32.band(buffer.readu32(StateWords, 48), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 52), 0xff0000), bit32.band(buffer.readu32(StateWords, 56), 0xff000000)), 14)), 16), buffer.readu32(RK, 188)))
				end
				if Rounds > 12 then
					do
						buffer.writeu32(StateWords, 32, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 0), 0xff), bit32.band(buffer.readu32(StateWords, 4), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 8), 0xff0000), bit32.band(buffer.readu32(StateWords, 12), 0xff000000)), 14)), 16), buffer.readu32(RK, 192)))
						buffer.writeu32(StateWords, 36, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 4), 0xff), bit32.band(buffer.readu32(StateWords, 8), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 12), 0xff0000), bit32.band(buffer.readu32(StateWords, 0), 0xff000000)), 14)), 16), buffer.readu32(RK, 196)))
						buffer.writeu32(StateWords, 40, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 8), 0xff), bit32.band(buffer.readu32(StateWords, 12), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 0), 0xff0000), bit32.band(buffer.readu32(StateWords, 4), 0xff000000)), 14)), 16), buffer.readu32(RK, 200)))
						buffer.writeu32(StateWords, 44, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 12), 0xff), bit32.band(buffer.readu32(StateWords, 0), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 4), 0xff0000), bit32.band(buffer.readu32(StateWords, 8), 0xff000000)), 14)), 16), buffer.readu32(RK, 204)))
						buffer.writeu32(StateWords, 48, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 16), 0xff), bit32.band(buffer.readu32(StateWords, 20), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 24), 0xff0000), bit32.band(buffer.readu32(StateWords, 28), 0xff000000)), 14)), 16), buffer.readu32(RK, 192)))
						buffer.writeu32(StateWords, 52, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 20), 0xff), bit32.band(buffer.readu32(StateWords, 24), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 28), 0xff0000), bit32.band(buffer.readu32(StateWords, 16), 0xff000000)), 14)), 16), buffer.readu32(RK, 196)))
						buffer.writeu32(StateWords, 56, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 24), 0xff), bit32.band(buffer.readu32(StateWords, 28), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 16), 0xff0000), bit32.band(buffer.readu32(StateWords, 20), 0xff000000)), 14)), 16), buffer.readu32(RK, 200)))
						buffer.writeu32(StateWords, 60, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 28), 0xff), bit32.band(buffer.readu32(StateWords, 16), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 20), 0xff0000), bit32.band(buffer.readu32(StateWords, 24), 0xff000000)), 14)), 16), buffer.readu32(RK, 204)))
					end
					do
						buffer.writeu32(StateWords, 0, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 32), 0xff), bit32.band(buffer.readu32(StateWords, 36), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 40), 0xff0000), bit32.band(buffer.readu32(StateWords, 44), 0xff000000)), 14)), 16), buffer.readu32(RK, 208)))
						buffer.writeu32(StateWords, 4, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 36), 0xff), bit32.band(buffer.readu32(StateWords, 40), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 44), 0xff0000), bit32.band(buffer.readu32(StateWords, 32), 0xff000000)), 14)), 16), buffer.readu32(RK, 212)))
						buffer.writeu32(StateWords, 8, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 40), 0xff), bit32.band(buffer.readu32(StateWords, 44), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 32), 0xff0000), bit32.band(buffer.readu32(StateWords, 36), 0xff000000)), 14)), 16), buffer.readu32(RK, 216)))
						buffer.writeu32(StateWords, 12, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 44), 0xff), bit32.band(buffer.readu32(StateWords, 32), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 36), 0xff0000), bit32.band(buffer.readu32(StateWords, 40), 0xff000000)), 14)), 16), buffer.readu32(RK, 220)))
						buffer.writeu32(StateWords, 16, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 48), 0xff), bit32.band(buffer.readu32(StateWords, 52), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 56), 0xff0000), bit32.band(buffer.readu32(StateWords, 60), 0xff000000)), 14)), 16), buffer.readu32(RK, 208)))
						buffer.writeu32(StateWords, 20, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 52), 0xff), bit32.band(buffer.readu32(StateWords, 56), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 60), 0xff0000), bit32.band(buffer.readu32(StateWords, 48), 0xff000000)), 14)), 16), buffer.readu32(RK, 212)))
						buffer.writeu32(StateWords, 24, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 56), 0xff), bit32.band(buffer.readu32(StateWords, 60), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 48), 0xff0000), bit32.band(buffer.readu32(StateWords, 52), 0xff000000)), 14)), 16), buffer.readu32(RK, 216)))
						buffer.writeu32(StateWords, 28, bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 60), 0xff), bit32.band(buffer.readu32(StateWords, 48), 0xff00)), 2)), bit32.lrotate(buffer.readu32(T01, bit32.rshift(bit32.bor(bit32.band(buffer.readu32(StateWords, 52), 0xff0000), bit32.band(buffer.readu32(StateWords, 56), 0xff000000)), 14)), 16), buffer.readu32(RK, 220)))
					end
				end
			end
			buffer.writeu32(Output, Position + 0, bit32.bxor(buffer.readu32(Input, Position + 0), bit32.bor(buffer.readu8(Box, bit32.band(buffer.readu32(StateWords, 0), 0xff)), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 4), 8), 0xff)), 8), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 8), 16), 0xff)), 16), bit32.lshift(buffer.readu8(Box, bit32.rshift(buffer.readu32(StateWords, 12), 24)), 24)), buffer.readu32(RK, Last + 0)))
			buffer.writeu32(Output, Position + 4, bit32.bxor(buffer.readu32(Input, Position + 4), bit32.bor(buffer.readu8(Box, bit32.band(buffer.readu32(StateWords, 4), 0xff)), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 8), 8), 0xff)), 8), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 12), 16), 0xff)), 16), bit32.lshift(buffer.readu8(Box, bit32.rshift(buffer.readu32(StateWords, 0), 24)), 24)), buffer.readu32(RK, Last + 4)))
			buffer.writeu32(Output, Position + 8, bit32.bxor(buffer.readu32(Input, Position + 8), bit32.bor(buffer.readu8(Box, bit32.band(buffer.readu32(StateWords, 8), 0xff)), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 12), 8), 0xff)), 8), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 0), 16), 0xff)), 16), bit32.lshift(buffer.readu8(Box, bit32.rshift(buffer.readu32(StateWords, 4), 24)), 24)), buffer.readu32(RK, Last + 8)))
			buffer.writeu32(Output, Position + 12, bit32.bxor(buffer.readu32(Input, Position + 12), bit32.bor(buffer.readu8(Box, bit32.band(buffer.readu32(StateWords, 12), 0xff)), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 0), 8), 0xff)), 8), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 4), 16), 0xff)), 16), bit32.lshift(buffer.readu8(Box, bit32.rshift(buffer.readu32(StateWords, 8), 24)), 24)), buffer.readu32(RK, Last + 12)))
			buffer.writeu32(Output, Position + 16, bit32.bxor(buffer.readu32(Input, Position + 16), bit32.bor(buffer.readu8(Box, bit32.band(buffer.readu32(StateWords, 16), 0xff)), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 20), 8), 0xff)), 8), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 24), 16), 0xff)), 16), bit32.lshift(buffer.readu8(Box, bit32.rshift(buffer.readu32(StateWords, 28), 24)), 24)), buffer.readu32(RK, Last + 0)))
			buffer.writeu32(Output, Position + 20, bit32.bxor(buffer.readu32(Input, Position + 20), bit32.bor(buffer.readu8(Box, bit32.band(buffer.readu32(StateWords, 20), 0xff)), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 24), 8), 0xff)), 8), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 28), 16), 0xff)), 16), bit32.lshift(buffer.readu8(Box, bit32.rshift(buffer.readu32(StateWords, 16), 24)), 24)), buffer.readu32(RK, Last + 4)))
			buffer.writeu32(Output, Position + 24, bit32.bxor(buffer.readu32(Input, Position + 24), bit32.bor(buffer.readu8(Box, bit32.band(buffer.readu32(StateWords, 24), 0xff)), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 28), 8), 0xff)), 8), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 16), 16), 0xff)), 16), bit32.lshift(buffer.readu8(Box, bit32.rshift(buffer.readu32(StateWords, 20), 24)), 24)), buffer.readu32(RK, Last + 8)))
			buffer.writeu32(Output, Position + 28, bit32.bxor(buffer.readu32(Input, Position + 28), bit32.bor(buffer.readu8(Box, bit32.band(buffer.readu32(StateWords, 28), 0xff)), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 16), 8), 0xff)), 8), bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(buffer.readu32(StateWords, 20), 16), 0xff)), 16), bit32.lshift(buffer.readu8(Box, bit32.rshift(buffer.readu32(StateWords, 24), 24)), 24)), buffer.readu32(RK, Last + 12)))
			Offset += 32
		end
		C = (C + Pairs * 2) % 4294967296
	end

	while Offset < Length do
		local Remaining = Length - Offset
		if Remaining < 16 then
			local Block: buffer = KEYSTREAM
			ZeroBlock(Block)
			buffer.copy(Block, 0, Input, Offset, Remaining)
			XorBlockWithP(Rounds, Block, Block, 0, P0, P1, P2, P3, K3, C)
			buffer.copy(Output, Offset, Block, 0, Remaining)
		else
			XorBlockWithP(Rounds, Input, Output, Offset, P0, P1, P2, P3, K3, C)
		end
		Offset += 16
		C = (C + 1) % 4294967296
	end
end

local function BuildNibbleTables()
	local Tables: buffer = NIBBLE_TABLES
	local HashKey: buffer = HASH_KEY
	local V0 = bit32.byteswap(buffer.readu32(HashKey, 0))
	local V1 = bit32.byteswap(buffer.readu32(HashKey, 4))
	local V2 = bit32.byteswap(buffer.readu32(HashKey, 8))
	local V3 = bit32.byteswap(buffer.readu32(HashKey, 12))

	for Base = 0, 8191, 256 do
		local A0, A1, A2, A3 = bit32.byteswap(V0), bit32.byteswap(V1), bit32.byteswap(V2), bit32.byteswap(V3)
		local Mask = bit32.band(bit32.arshift(bit32.lshift(V3, 31), 31), 0xe1000000)
		V3 = bit32.bor(bit32.rshift(V3, 1), bit32.lshift(V2, 31))
		V2 = bit32.bor(bit32.rshift(V2, 1), bit32.lshift(V1, 31))
		V1 = bit32.bor(bit32.rshift(V1, 1), bit32.lshift(V0, 31))
		V0 = bit32.bxor(bit32.rshift(V0, 1), Mask)
		local B0, B1, B2, B3 = bit32.byteswap(V0), bit32.byteswap(V1), bit32.byteswap(V2), bit32.byteswap(V3)
		Mask = bit32.band(bit32.arshift(bit32.lshift(V3, 31), 31), 0xe1000000)
		V3 = bit32.bor(bit32.rshift(V3, 1), bit32.lshift(V2, 31))
		V2 = bit32.bor(bit32.rshift(V2, 1), bit32.lshift(V1, 31))
		V1 = bit32.bor(bit32.rshift(V1, 1), bit32.lshift(V0, 31))
		V0 = bit32.bxor(bit32.rshift(V0, 1), Mask)
		local C0, C1, C2, C3 = bit32.byteswap(V0), bit32.byteswap(V1), bit32.byteswap(V2), bit32.byteswap(V3)
		Mask = bit32.band(bit32.arshift(bit32.lshift(V3, 31), 31), 0xe1000000)
		V3 = bit32.bor(bit32.rshift(V3, 1), bit32.lshift(V2, 31))
		V2 = bit32.bor(bit32.rshift(V2, 1), bit32.lshift(V1, 31))
		V1 = bit32.bor(bit32.rshift(V1, 1), bit32.lshift(V0, 31))
		V0 = bit32.bxor(bit32.rshift(V0, 1), Mask)
		local D0, D1, D2, D3 = bit32.byteswap(V0), bit32.byteswap(V1), bit32.byteswap(V2), bit32.byteswap(V3)
		Mask = bit32.band(bit32.arshift(bit32.lshift(V3, 31), 31), 0xe1000000)
		V3 = bit32.bor(bit32.rshift(V3, 1), bit32.lshift(V2, 31))
		V2 = bit32.bor(bit32.rshift(V2, 1), bit32.lshift(V1, 31))
		V1 = bit32.bor(bit32.rshift(V1, 1), bit32.lshift(V0, 31))
		V0 = bit32.bxor(bit32.rshift(V0, 1), Mask)

		buffer.writeu32(Tables, Base, 0)
		buffer.writeu32(Tables, Base + 4, 0)
		buffer.writeu32(Tables, Base + 8, 0)
		buffer.writeu32(Tables, Base + 12, 0)
		buffer.writeu32(Tables, Base + 16, D0)
		buffer.writeu32(Tables, Base + 20, D1)
		buffer.writeu32(Tables, Base + 24, D2)
		buffer.writeu32(Tables, Base + 28, D3)
		buffer.writeu32(Tables, Base + 32, C0)
		buffer.writeu32(Tables, Base + 36, C1)
		buffer.writeu32(Tables, Base + 40, C2)
		buffer.writeu32(Tables, Base + 44, C3)
		buffer.writeu32(Tables, Base + 48, bit32.bxor(C0, D0))
		buffer.writeu32(Tables, Base + 52, bit32.bxor(C1, D1))
		buffer.writeu32(Tables, Base + 56, bit32.bxor(C2, D2))
		buffer.writeu32(Tables, Base + 60, bit32.bxor(C3, D3))
		buffer.writeu32(Tables, Base + 64, B0)
		buffer.writeu32(Tables, Base + 68, B1)
		buffer.writeu32(Tables, Base + 72, B2)
		buffer.writeu32(Tables, Base + 76, B3)
		buffer.writeu32(Tables, Base + 80, bit32.bxor(B0, D0))
		buffer.writeu32(Tables, Base + 84, bit32.bxor(B1, D1))
		buffer.writeu32(Tables, Base + 88, bit32.bxor(B2, D2))
		buffer.writeu32(Tables, Base + 92, bit32.bxor(B3, D3))
		buffer.writeu32(Tables, Base + 96, bit32.bxor(B0, C0))
		buffer.writeu32(Tables, Base + 100, bit32.bxor(B1, C1))
		buffer.writeu32(Tables, Base + 104, bit32.bxor(B2, C2))
		buffer.writeu32(Tables, Base + 108, bit32.bxor(B3, C3))
		buffer.writeu32(Tables, Base + 112, bit32.bxor(B0, C0, D0))
		buffer.writeu32(Tables, Base + 116, bit32.bxor(B1, C1, D1))
		buffer.writeu32(Tables, Base + 120, bit32.bxor(B2, C2, D2))
		buffer.writeu32(Tables, Base + 124, bit32.bxor(B3, C3, D3))
		buffer.writeu32(Tables, Base + 128, A0)
		buffer.writeu32(Tables, Base + 132, A1)
		buffer.writeu32(Tables, Base + 136, A2)
		buffer.writeu32(Tables, Base + 140, A3)
		buffer.writeu32(Tables, Base + 144, bit32.bxor(A0, D0))
		buffer.writeu32(Tables, Base + 148, bit32.bxor(A1, D1))
		buffer.writeu32(Tables, Base + 152, bit32.bxor(A2, D2))
		buffer.writeu32(Tables, Base + 156, bit32.bxor(A3, D3))
		buffer.writeu32(Tables, Base + 160, bit32.bxor(A0, C0))
		buffer.writeu32(Tables, Base + 164, bit32.bxor(A1, C1))
		buffer.writeu32(Tables, Base + 168, bit32.bxor(A2, C2))
		buffer.writeu32(Tables, Base + 172, bit32.bxor(A3, C3))
		buffer.writeu32(Tables, Base + 176, bit32.bxor(A0, C0, D0))
		buffer.writeu32(Tables, Base + 180, bit32.bxor(A1, C1, D1))
		buffer.writeu32(Tables, Base + 184, bit32.bxor(A2, C2, D2))
		buffer.writeu32(Tables, Base + 188, bit32.bxor(A3, C3, D3))
		buffer.writeu32(Tables, Base + 192, bit32.bxor(A0, B0))
		buffer.writeu32(Tables, Base + 196, bit32.bxor(A1, B1))
		buffer.writeu32(Tables, Base + 200, bit32.bxor(A2, B2))
		buffer.writeu32(Tables, Base + 204, bit32.bxor(A3, B3))
		buffer.writeu32(Tables, Base + 208, bit32.bxor(A0, B0, D0))
		buffer.writeu32(Tables, Base + 212, bit32.bxor(A1, B1, D1))
		buffer.writeu32(Tables, Base + 216, bit32.bxor(A2, B2, D2))
		buffer.writeu32(Tables, Base + 220, bit32.bxor(A3, B3, D3))
		buffer.writeu32(Tables, Base + 224, bit32.bxor(A0, B0, C0))
		buffer.writeu32(Tables, Base + 228, bit32.bxor(A1, B1, C1))
		buffer.writeu32(Tables, Base + 232, bit32.bxor(A2, B2, C2))
		buffer.writeu32(Tables, Base + 236, bit32.bxor(A3, B3, C3))
		buffer.writeu32(Tables, Base + 240, bit32.bxor(A0, B0, C0, D0))
		buffer.writeu32(Tables, Base + 244, bit32.bxor(A1, B1, C1, D1))
		buffer.writeu32(Tables, Base + 248, bit32.bxor(A2, B2, C2, D2))
		buffer.writeu32(Tables, Base + 252, bit32.bxor(A3, B3, C3, D3))
	end
end

local function BuildByteTables(): buffer
	local Nibbles: buffer = NIBBLE_TABLES
	local Bytes = ByteTables
	if not Bytes then
		Bytes = buffer.create(65536)
		ByteTables = Bytes
	end
	local TargetBytes: buffer = Bytes :: buffer
	for Position = 0, 15 do
		local HighBase = Position * 512
		local LowBase = HighBase + 256
		local OutBase = Position * 4096
		buffer.copy(TargetBytes, OutBase, Nibbles, LowBase, 256)
		for High = 1, 15 do
			local HighOffset = HighBase + High * 16
			local A0 = buffer.readu32(Nibbles, HighOffset)
			local A1 = buffer.readu32(Nibbles, HighOffset + 4)
			local A2 = buffer.readu32(Nibbles, HighOffset + 8)
			local A3 = buffer.readu32(Nibbles, HighOffset + 12)
			local Target = OutBase + High * 256
			for Low = 0, 224, 32 do
				local LowOffset = LowBase + Low
				local Entry = Target + Low
				buffer.writeu32(TargetBytes, Entry, bit32.bxor(A0, buffer.readu32(Nibbles, LowOffset)))
				buffer.writeu32(TargetBytes, Entry + 4, bit32.bxor(A1, buffer.readu32(Nibbles, LowOffset + 4)))
				buffer.writeu32(TargetBytes, Entry + 8, bit32.bxor(A2, buffer.readu32(Nibbles, LowOffset + 8)))
				buffer.writeu32(TargetBytes, Entry + 12, bit32.bxor(A3, buffer.readu32(Nibbles, LowOffset + 12)))
				buffer.writeu32(TargetBytes, Entry + 16, bit32.bxor(A0, buffer.readu32(Nibbles, LowOffset + 16)))
				buffer.writeu32(TargetBytes, Entry + 20, bit32.bxor(A1, buffer.readu32(Nibbles, LowOffset + 20)))
				buffer.writeu32(TargetBytes, Entry + 24, bit32.bxor(A2, buffer.readu32(Nibbles, LowOffset + 24)))
				buffer.writeu32(TargetBytes, Entry + 28, bit32.bxor(A3, buffer.readu32(Nibbles, LowOffset + 28)))
			end
		end
	end
	ByteTablesReady = true
	return TargetBytes
end

local function GhashNibbles(Data: buffer, Offset: number, Length: number)
	local State: buffer = GHASH_STATE
	local T: buffer = NIBBLE_TABLES
	local Z0 = buffer.readu32(State, 0)
	local Z1 = buffer.readu32(State, 4)
	local Z2 = buffer.readu32(State, 8)
	local Z3 = buffer.readu32(State, 12)
	for Position = Offset, Offset + Length - 16, 16 do
		local X0 = bit32.bxor(Z0, buffer.readu32(Data, Position + 0))
		local X1 = bit32.bxor(Z1, buffer.readu32(Data, Position + 4))
		local X2 = bit32.bxor(Z2, buffer.readu32(Data, Position + 8))
		local X3 = bit32.bxor(Z3, buffer.readu32(Data, Position + 12))
		do
			local H = bit32.band(X0, 0xf0)
			local L = bit32.bor(bit32.band(bit32.lshift(X0, 4), 0xf0), 256)
			Z0 = bit32.bxor(buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(bit32.rshift(X0, 8), 0xf0), 512)
			local L = bit32.bor(bit32.band(bit32.rshift(X0, 4), 0xf0), 768)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(bit32.rshift(X0, 16), 0xf0), 1024)
			local L = bit32.bor(bit32.band(bit32.rshift(X0, 12), 0xf0), 1280)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(bit32.rshift(X0, 24), 0xf0), 1536)
			local L = bit32.bor(bit32.band(bit32.rshift(X0, 20), 0xf0), 1792)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(X1, 0xf0), 2048)
			local L = bit32.bor(bit32.band(bit32.lshift(X1, 4), 0xf0), 2304)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(bit32.rshift(X1, 8), 0xf0), 2560)
			local L = bit32.bor(bit32.band(bit32.rshift(X1, 4), 0xf0), 2816)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(bit32.rshift(X1, 16), 0xf0), 3072)
			local L = bit32.bor(bit32.band(bit32.rshift(X1, 12), 0xf0), 3328)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(bit32.rshift(X1, 24), 0xf0), 3584)
			local L = bit32.bor(bit32.band(bit32.rshift(X1, 20), 0xf0), 3840)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(X2, 0xf0), 4096)
			local L = bit32.bor(bit32.band(bit32.lshift(X2, 4), 0xf0), 4352)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(bit32.rshift(X2, 8), 0xf0), 4608)
			local L = bit32.bor(bit32.band(bit32.rshift(X2, 4), 0xf0), 4864)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(bit32.rshift(X2, 16), 0xf0), 5120)
			local L = bit32.bor(bit32.band(bit32.rshift(X2, 12), 0xf0), 5376)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(bit32.rshift(X2, 24), 0xf0), 5632)
			local L = bit32.bor(bit32.band(bit32.rshift(X2, 20), 0xf0), 5888)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(X3, 0xf0), 6144)
			local L = bit32.bor(bit32.band(bit32.lshift(X3, 4), 0xf0), 6400)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(bit32.rshift(X3, 8), 0xf0), 6656)
			local L = bit32.bor(bit32.band(bit32.rshift(X3, 4), 0xf0), 6912)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(bit32.rshift(X3, 16), 0xf0), 7168)
			local L = bit32.bor(bit32.band(bit32.rshift(X3, 12), 0xf0), 7424)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
		do
			local H = bit32.bor(bit32.band(bit32.rshift(X3, 24), 0xf0), 7680)
			local L = bit32.bor(bit32.band(bit32.rshift(X3, 20), 0xf0), 7936)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
		end
	end
	buffer.writeu32(State, 0, Z0)
	buffer.writeu32(State, 4, Z1)
	buffer.writeu32(State, 8, Z2)
	buffer.writeu32(State, 12, Z3)
end

local function GhashBytes(T: buffer, Data: buffer, Offset: number, Length: number)
	local State: buffer = GHASH_STATE
	local Z0 = buffer.readu32(State, 0)
	local Z1 = buffer.readu32(State, 4)
	local Z2 = buffer.readu32(State, 8)
	local Z3 = buffer.readu32(State, 12)
	local End = Offset + Length
	local Position = Offset
	while Position + 32 <= End do
		local X0 = bit32.bxor(Z0, buffer.readu32(Data, Position + 0))
		local X1 = bit32.bxor(Z1, buffer.readu32(Data, Position + 4))
		local X2 = bit32.bxor(Z2, buffer.readu32(Data, Position + 8))
		local X3 = bit32.bxor(Z3, buffer.readu32(Data, Position + 12))
		do
			local E = bit32.band(bit32.lshift(X0, 4), 0xff0)
			Z0 = buffer.readu32(T, E)
			Z1 = buffer.readu32(T, bit32.bor(E, 4))
			Z2 = buffer.readu32(T, bit32.bor(E, 8))
			Z3 = buffer.readu32(T, bit32.bor(E, 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X0, 4), 0xff0), 4096)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X0, 12), 0xff0), 8192)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X0, 20), 0xff0), 12288)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.lshift(X1, 4), 0xff0), 16384)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X1, 4), 0xff0), 20480)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X1, 12), 0xff0), 24576)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X1, 20), 0xff0), 28672)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.lshift(X2, 4), 0xff0), 32768)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X2, 4), 0xff0), 36864)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X2, 12), 0xff0), 40960)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X2, 20), 0xff0), 45056)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.lshift(X3, 4), 0xff0), 49152)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X3, 4), 0xff0), 53248)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X3, 12), 0xff0), 57344)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X3, 20), 0xff0), 61440)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		local Y0 = bit32.bxor(Z0, buffer.readu32(Data, Position + 16))
		local Y1 = bit32.bxor(Z1, buffer.readu32(Data, Position + 20))
		local Y2 = bit32.bxor(Z2, buffer.readu32(Data, Position + 24))
		local Y3 = bit32.bxor(Z3, buffer.readu32(Data, Position + 28))
		do
			local E = bit32.band(bit32.lshift(Y0, 4), 0xff0)
			Z0 = buffer.readu32(T, E)
			Z1 = buffer.readu32(T, bit32.bor(E, 4))
			Z2 = buffer.readu32(T, bit32.bor(E, 8))
			Z3 = buffer.readu32(T, bit32.bor(E, 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(Y0, 4), 0xff0), 4096)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(Y0, 12), 0xff0), 8192)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(Y0, 20), 0xff0), 12288)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.lshift(Y1, 4), 0xff0), 16384)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(Y1, 4), 0xff0), 20480)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(Y1, 12), 0xff0), 24576)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(Y1, 20), 0xff0), 28672)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.lshift(Y2, 4), 0xff0), 32768)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(Y2, 4), 0xff0), 36864)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(Y2, 12), 0xff0), 40960)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(Y2, 20), 0xff0), 45056)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.lshift(Y3, 4), 0xff0), 49152)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(Y3, 4), 0xff0), 53248)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(Y3, 12), 0xff0), 57344)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(Y3, 20), 0xff0), 61440)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, bit32.bor(E, 4)))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, bit32.bor(E, 8)))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, bit32.bor(E, 12)))
		end
		Position += 32
	end
	if Position + 16 <= End then
		local W0 = bit32.bxor(Z0, buffer.readu32(Data, Position + 0))
		local W1 = bit32.bxor(Z1, buffer.readu32(Data, Position + 4))
		local W2 = bit32.bxor(Z2, buffer.readu32(Data, Position + 8))
		local W3 = bit32.bxor(Z3, buffer.readu32(Data, Position + 12))
		do
			local E = bit32.band(bit32.lshift(W0, 4), 0xff0)
			Z0 = buffer.readu32(T, E)
			Z1 = buffer.readu32(T, E + 4)
			Z2 = buffer.readu32(T, E + 8)
			Z3 = buffer.readu32(T, E + 12)
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(W0, 4), 0xff0), 4096)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(W0, 12), 0xff0), 8192)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(W0, 20), 0xff0), 12288)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.lshift(W1, 4), 0xff0), 16384)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(W1, 4), 0xff0), 20480)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(W1, 12), 0xff0), 24576)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(W1, 20), 0xff0), 28672)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.lshift(W2, 4), 0xff0), 32768)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(W2, 4), 0xff0), 36864)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(W2, 12), 0xff0), 40960)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(W2, 20), 0xff0), 45056)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.lshift(W3, 4), 0xff0), 49152)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(W3, 4), 0xff0), 53248)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(W3, 12), 0xff0), 57344)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(W3, 20), 0xff0), 61440)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
	end
	buffer.writeu32(State, 0, Z0)
	buffer.writeu32(State, 4, Z1)
	buffer.writeu32(State, 8, Z2)
	buffer.writeu32(State, 12, Z3)
end

local function KeySetup(Key: buffer, KeyLength: number): (number, boolean)
	local CacheKey: buffer = CACHE_KEY
	if CacheLength == KeyLength then
		local Difference = 0
		for Offset = 0, KeyLength - 4, 4 do
			Difference = bit32.bor(Difference, bit32.bxor(buffer.readu32(Key, Offset), buffer.readu32(CacheKey, Offset)))
		end
		if Difference == 0 then
			return CacheRounds, true
		end
	end

	local Rounds = if KeyLength == 16 then 10 elseif KeyLength == 24 then 12 else 14
	ExpandKeySchedule(Key, KeyLength, ROUND_KEYS)
	local P0, P1, P2, P3, K3 = PrepareRound1(0, 0, 0)
	XorBlockWithP(Rounds, ZERO_BLOCK, HASH_KEY, 0, P0, P1, P2, P3, K3, 0)
	BuildNibbleTables()
	ByteTablesReady = false

	buffer.copy(CacheKey, 0, Key, 0, KeyLength)
	CacheLength = KeyLength
	CacheRounds = Rounds

	return Rounds, false
end

local function PrepareTailBlock(Data: buffer, FullBytes: number, TailLength: number): buffer
	local Block: buffer = GHASH_BLOCK
	ZeroBlock(Block)
	buffer.copy(Block, 0, Data, FullBytes, TailLength)
	return Block
end

local function PrepareLengthBlock(FirstBytes: number, SecondBytes: number): buffer
	local Block: buffer = GHASH_BLOCK
	local FirstBits = FirstBytes * 8
	local SecondBits = SecondBytes * 8
	buffer.writeu32(Block, 0, bit32.byteswap(math.floor(FirstBits * 2 ^ -32)))
	buffer.writeu32(Block, 4, bit32.byteswap(FirstBits % 4294967296))
	buffer.writeu32(Block, 8, bit32.byteswap(math.floor(SecondBits * 2 ^ -32)))
	buffer.writeu32(Block, 12, bit32.byteswap(SecondBits % 4294967296))
	return Block
end

local function Ghash(Tables: buffer?, Data: buffer, Offset: number, Length: number)
	if Tables then
		GhashBytes(Tables, Data, Offset, Length)
	else
		GhashNibbles(Data, Offset, Length)
	end
end

local function GhashPadded(Tables: buffer?, Data: buffer, Length: number)
	local Tail = bit32.band(Length, 15)
	local Full = Length - Tail
	if Full > 0 then
		Ghash(Tables, Data, 0, Full)
	end
	if Tail > 0 then
		Ghash(Tables, PrepareTailBlock(Data, Full, Tail), 0, 16)
	end
end

local function PrepareCounter(IV: buffer, IVLength: number): (number, number, number, number)
	if IVLength == 12 then
		return buffer.readu32(IV, 0), buffer.readu32(IV, 4), buffer.readu32(IV, 8), 1
	end

	local State: buffer = GHASH_STATE
	ZeroBlock(State)
	GhashPadded(nil, IV, IVLength)
	Ghash(nil, PrepareLengthBlock(0, IVLength), 0, 16)

	return buffer.readu32(State, 0), buffer.readu32(State, 4), buffer.readu32(State, 8), bit32.byteswap(buffer.readu32(State, 12))
end

local function AuthenticationTag(Rounds: number, CacheHit: boolean, AAD: buffer, AADLength: number, Ciphertext: buffer, CiphertextLength: number, P0: number, P1: number, P2: number, P3: number, K3: number, Counter: number): buffer
	local Tables: buffer? = if ByteTablesReady then ByteTables else nil
	if not Tables and (CacheHit or (AADLength + CiphertextLength) >= 2048) then
		Tables = BuildByteTables()
	end

	local State: buffer = GHASH_STATE
	ZeroBlock(State)
	GhashPadded(Tables, AAD, AADLength)
	GhashPadded(Tables, Ciphertext, CiphertextLength)
	Ghash(Tables, PrepareLengthBlock(AADLength, CiphertextLength), 0, 16)

	local Tag = buffer.create(16)
	XorBlockWithP(Rounds, State, Tag, 0, P0, P1, P2, P3, K3, Counter)
	return Tag
end

function AES.Encrypt(Plaintext: buffer, Key: buffer, IV: buffer, AAD: buffer?): (buffer, buffer)
	if typeof(Key) ~= "buffer" then
		error("Key must be a buffer", 2)
	end

	if typeof(IV) ~= "buffer" then
		error("IV must be a buffer", 2)
	end

	if typeof(Plaintext) ~= "buffer" then
		error("Plaintext must be a buffer", 2)
	end

	if AAD ~= nil and typeof(AAD) ~= "buffer" then
		error("AAD must be a buffer", 2)
	end

	local KeyLength = buffer.len(Key)
	if KeyLength ~= 16 and KeyLength ~= 24 and KeyLength ~= 32 then
		error("Key must be 16, 24, or 32 bytes", 2)
	end

	local IVLength = buffer.len(IV)
	if IVLength == 0 then
		error("IV cannot be empty", 2)
	end

	local Rounds, CacheHit = KeySetup(Key, KeyLength)
	local J0, J1, J2, Counter = PrepareCounter(IV, IVLength)
	local P0, P1, P2, P3, K3 = PrepareRound1(J0, J1, J2)

	local AuthData = AAD or EMPTY
	local AADLength = if AAD then buffer.len(AAD) else 0
	local PlainLength = buffer.len(Plaintext)
	local Ciphertext = buffer.create(PlainLength)
	if PlainLength > 0 then
		CtrWithP(Rounds, Plaintext, Ciphertext, PlainLength, P0, P1, P2, P3, K3, (Counter + 1) % 4294967296)
	end

	local Tag = AuthenticationTag(Rounds, CacheHit, AuthData, AADLength, Ciphertext, PlainLength, P0, P1, P2, P3, K3, Counter)

	return Ciphertext, Tag
end

function AES.Decrypt(Ciphertext: buffer, Key: buffer, IV: buffer, Tag: buffer, AAD: buffer?): buffer?
	if typeof(Key) ~= "buffer" then
		error("Key must be a buffer", 2)
	end

	local KeyLength = buffer.len(Key)
	if KeyLength ~= 16 and KeyLength ~= 24 and KeyLength ~= 32 then
		error("Key must be 16, 24, or 32 bytes", 2)
	end

	if typeof(Ciphertext) ~= "buffer" or typeof(IV) ~= "buffer" or typeof(Tag) ~= "buffer" then
		return nil
	end

	if AAD ~= nil and typeof(AAD) ~= "buffer" then
		return nil
	end

	local IVLength = buffer.len(IV)
	if IVLength == 0 or buffer.len(Tag) ~= 16 then
		return nil
	end

	local Rounds, CacheHit = KeySetup(Key, KeyLength)
	local J0, J1, J2, Counter = PrepareCounter(IV, IVLength)
	local P0, P1, P2, P3, K3 = PrepareRound1(J0, J1, J2)

	local AuthData = AAD or EMPTY
	local AADLength = if AAD then buffer.len(AAD) else 0
	local CipherLength = buffer.len(Ciphertext)
	local ComputedTag = AuthenticationTag(Rounds, CacheHit, AuthData, AADLength, Ciphertext, CipherLength, P0, P1, P2, P3, K3, Counter)

	if not CtCompare(Tag, ComputedTag) then
		return nil
	end

	local Plaintext = buffer.create(CipherLength)
	if CipherLength > 0 then
		CtrWithP(Rounds, Ciphertext, Plaintext, CipherLength, P0, P1, P2, P3, K3, (Counter + 1) % 4294967296)
	end

	return Plaintext
end

return AES
