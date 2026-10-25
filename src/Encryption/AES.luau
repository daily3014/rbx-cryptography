--[=[
	Cryptography library: AES

	Sizes:
		Init Vector: any non-zero length (12 bytes recommended)
		Key Size: 16 / 24 / 32 bytes
		Tag: 16 bytes

	Return type: Encrypt (buffer, buffer), Decrypt buffer?
	Decrypt returns nil when authentication fails, including tags
	that are not 16 bytes long.

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

local SUBSTITUTION_BOX = buffer.create(256)
local TTABLE = buffer.create(4096)

local ROUND_KEYS = buffer.create(240)
local CACHE_KEY = buffer.create(32)
local HASH_KEY = buffer.create(16)
local NIBBLE_TABLES = buffer.create(8192)
local BYTE_TABLES = buffer.create(65536)
local GHASH_STATE = buffer.create(16)
local GHASH_BLOCK = buffer.create(16)
local KEYSTREAM = buffer.create(64)
local ZERO_BLOCK = buffer.create(16)
local EMPTY = buffer.create(0)

local CacheLength = 0
local CacheRounds = 0
local ByteTablesReady = false

do
	local function GaloisFieldMultiply(FirstValue: number, SecondValue: number): number
		local Product = 0
		for _ = 0, 7 do
			if SecondValue % 2 == 1 then
				Product = bit32.bxor(Product, FirstValue)
			end
			FirstValue = FirstValue >= 128 and bit32.bxor(FirstValue * 2 % 256, 27) or FirstValue * 2 % 256
			SecondValue = math.floor(SecondValue / 2)
		end
		return Product
	end

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
		local S2 = GaloisFieldMultiply(2, S)
		local S3 = bit32.bxor(S2, S)
		local Base = B * 16
		buffer.writeu32(TTABLE, Base, bit32.bor(S2, bit32.lshift(S, 8), bit32.lshift(S, 16), bit32.lshift(S3, 24)))
		buffer.writeu32(TTABLE, Base + 4, bit32.bor(S3, bit32.lshift(S2, 8), bit32.lshift(S, 16), bit32.lshift(S, 24)))
		buffer.writeu32(TTABLE, Base + 8, bit32.bor(S, bit32.lshift(S3, 8), bit32.lshift(S2, 16), bit32.lshift(S, 24)))
		buffer.writeu32(TTABLE, Base + 12, bit32.bor(S, bit32.lshift(S, 8), bit32.lshift(S3, 16), bit32.lshift(S2, 24)))
	end
end

local PAIR01 = buffer.create(262144)
local PAIR23 = buffer.create(262144)
local SBOX16 = buffer.create(131072)

do
	local T, Box = TTABLE, SUBSTITUTION_BOX
	for High = 0, 255 do
		local Te1 = buffer.readu32(T, High * 16 + 4)
		local Te3 = buffer.readu32(T, High * 16 + 12)
		local SHigh = buffer.readu8(Box, High) * 256
		local Row = High * 256
		for Low = 0, 255 do
			local Index = Row + Low
			buffer.writeu32(PAIR01, Index * 4, bit32.bxor(buffer.readu32(T, Low * 16), Te1))
			buffer.writeu32(PAIR23, Index * 4, bit32.bxor(buffer.readu32(T, Low * 16 + 8), Te3))
			buffer.writeu16(SBOX16, Index * 2, SHigh + buffer.readu8(Box, Low))
		end
	end
end

local function SubWord(Word: number): number
	local Box = SUBSTITUTION_BOX
	return bit32.bor(
		buffer.readu8(Box, bit32.band(Word, 0xff)),
		bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(Word, 8), 0xff)), 8),
		bit32.lshift(buffer.readu8(Box, bit32.band(bit32.rshift(Word, 16), 0xff)), 16),
		bit32.lshift(buffer.readu8(Box, bit32.rshift(Word, 24)), 24))
end

local function ExpandKeySchedule(Key: buffer, KeyLength: number, OutputBuffer: buffer)
	buffer.copy(OutputBuffer, 0, Key, 0, KeyLength)

	local Word = bit32.rrotate(buffer.readu32(OutputBuffer, KeyLength - 4), 8)
	local RoundConstant = 0.5

	if KeyLength == 32 then
		for KeyOffset = 32, 192, 32 do
			RoundConstant = RoundConstant * 2 % 229
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 32), SubWord(Word), RoundConstant)
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			local W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 28), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, W1)
			local W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 24), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, W2)
			local W3 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 20), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, W3)

			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 16), SubWord(W3))
			buffer.writeu32(OutputBuffer, KeyOffset + 16, Word)

			W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 20, W1)
			W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 24, W2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 28, Word)
			Word = bit32.rrotate(Word, 8)
		end

		Word = bit32.bxor(buffer.readu32(OutputBuffer, 192), SubWord(Word), 64)
		buffer.writeu32(OutputBuffer, 224, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 196), Word)
		buffer.writeu32(OutputBuffer, 228, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 200), W1)
		buffer.writeu32(OutputBuffer, 232, W2)
		buffer.writeu32(OutputBuffer, 236, bit32.bxor(buffer.readu32(OutputBuffer, 204), W2))
	elseif KeyLength == 24 then
		for KeyOffset = 24, 168, 24 do
			RoundConstant = RoundConstant * 2 % 229
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 24), SubWord(Word), RoundConstant)
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

		Word = bit32.bxor(buffer.readu32(OutputBuffer, 168), SubWord(Word), 128)
		buffer.writeu32(OutputBuffer, 192, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 172), Word)
		buffer.writeu32(OutputBuffer, 196, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 176), W1)
		buffer.writeu32(OutputBuffer, 200, W2)
		buffer.writeu32(OutputBuffer, 204, bit32.bxor(buffer.readu32(OutputBuffer, 180), W2))
	else
		for KeyOffset = 16, 144, 16 do
			RoundConstant = RoundConstant * 2 % 229
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 16), SubWord(Word), RoundConstant)
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			local W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, W1)
			local W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, W2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, Word)
			Word = bit32.rrotate(Word, 8)
		end

		Word = bit32.bxor(buffer.readu32(OutputBuffer, 144), SubWord(Word), 54)
		buffer.writeu32(OutputBuffer, 160, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 148), Word)
		buffer.writeu32(OutputBuffer, 164, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 152), W1)
		buffer.writeu32(OutputBuffer, 168, W2)
		buffer.writeu32(OutputBuffer, 172, bit32.bxor(buffer.readu32(OutputBuffer, 156), W2))
	end
end

local function Ctr(Rounds: number, Input: buffer, Output: buffer, Length: number, J0: number, J1: number, J2: number, Counter: number)
	local T = TTABLE
	local T01, T23, S16 = PAIR01, PAIR23, SBOX16
	local RK = ROUND_KEYS
	local S0, S1, S2 = bit32.bxor(J0, buffer.readu32(RK, 0)), bit32.bxor(J1, buffer.readu32(RK, 4)), bit32.bxor(J2, buffer.readu32(RK, 8))
	local K3 = buffer.readu32(RK, 12)
	local P0 = bit32.bxor(buffer.readu32(T, bit32.band(bit32.lshift(S0, 4), 0xff0)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S1, 4), 0xff0), 4)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S2, 12), 0xff0), 8)), buffer.readu32(RK, 16))
	local P1 = bit32.bxor(buffer.readu32(T, bit32.band(bit32.lshift(S1, 4), 0xff0)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S2, 4), 0xff0), 4)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S0, 20), 0xff0), 12)), buffer.readu32(RK, 20))
	local P2 = bit32.bxor(buffer.readu32(T, bit32.band(bit32.lshift(S2, 4), 0xff0)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S0, 12), 0xff0), 8)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S1, 20), 0xff0), 12)), buffer.readu32(RK, 24))
	local P3 = bit32.bxor(buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S0, 4), 0xff0), 4)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S1, 12), 0xff0), 8)), buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(S2, 20), 0xff0), 12)), buffer.readu32(RK, 28))
	local Last = Rounds * 16
	local Offset = 0
	while Offset + 32 <= Length do
		local Position = Offset
		do
			local VA = bit32.bxor(bit32.byteswap(Counter), K3)
			local RA0 = bit32.bxor(P0, buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(VA, 20), 0xff0), 12)))
			local RA1 = bit32.bxor(P1, buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(VA, 12), 0xff0), 8)))
			local RA2 = bit32.bxor(P2, buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(VA, 4), 0xff0), 4)))
			local RA3 = bit32.bxor(P3, buffer.readu32(T, bit32.band(bit32.lshift(VA, 4), 0xff0)))
			local SA0, SA1, SA2, SA3 = 0, 0, 0, 0
			local VB = bit32.bxor(bit32.byteswap(Counter + 1), K3)
			local RB0 = bit32.bxor(P0, buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(VB, 20), 0xff0), 12)))
			local RB1 = bit32.bxor(P1, buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(VB, 12), 0xff0), 8)))
			local RB2 = bit32.bxor(P2, buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(VB, 4), 0xff0), 4)))
			local RB3 = bit32.bxor(P3, buffer.readu32(T, bit32.band(bit32.lshift(VB, 4), 0xff0)))
			local SB0, SB1, SB2, SB3 = 0, 0, 0, 0
			do
				SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), buffer.readu32(RK, 32))
				SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), buffer.readu32(RK, 36))
				SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), buffer.readu32(RK, 40))
				SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), buffer.readu32(RK, 44))
				SB0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB0, 0xff), bit32.band(RB1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB2, 0xff0000), bit32.band(RB3, 0xff000000)), 14)), buffer.readu32(RK, 32))
				SB1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB1, 0xff), bit32.band(RB2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB3, 0xff0000), bit32.band(RB0, 0xff000000)), 14)), buffer.readu32(RK, 36))
				SB2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB2, 0xff), bit32.band(RB3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB0, 0xff0000), bit32.band(RB1, 0xff000000)), 14)), buffer.readu32(RK, 40))
				SB3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB3, 0xff), bit32.band(RB0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB1, 0xff0000), bit32.band(RB2, 0xff000000)), 14)), buffer.readu32(RK, 44))
			end
			do
				RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), buffer.readu32(RK, 48))
				RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), buffer.readu32(RK, 52))
				RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), buffer.readu32(RK, 56))
				RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), buffer.readu32(RK, 60))
				RB0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB0, 0xff), bit32.band(SB1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB2, 0xff0000), bit32.band(SB3, 0xff000000)), 14)), buffer.readu32(RK, 48))
				RB1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB1, 0xff), bit32.band(SB2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB3, 0xff0000), bit32.band(SB0, 0xff000000)), 14)), buffer.readu32(RK, 52))
				RB2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB2, 0xff), bit32.band(SB3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB0, 0xff0000), bit32.band(SB1, 0xff000000)), 14)), buffer.readu32(RK, 56))
				RB3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB3, 0xff), bit32.band(SB0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB1, 0xff0000), bit32.band(SB2, 0xff000000)), 14)), buffer.readu32(RK, 60))
			end
			do
				SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), buffer.readu32(RK, 64))
				SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), buffer.readu32(RK, 68))
				SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), buffer.readu32(RK, 72))
				SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), buffer.readu32(RK, 76))
				SB0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB0, 0xff), bit32.band(RB1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB2, 0xff0000), bit32.band(RB3, 0xff000000)), 14)), buffer.readu32(RK, 64))
				SB1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB1, 0xff), bit32.band(RB2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB3, 0xff0000), bit32.band(RB0, 0xff000000)), 14)), buffer.readu32(RK, 68))
				SB2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB2, 0xff), bit32.band(RB3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB0, 0xff0000), bit32.band(RB1, 0xff000000)), 14)), buffer.readu32(RK, 72))
				SB3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB3, 0xff), bit32.band(RB0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB1, 0xff0000), bit32.band(RB2, 0xff000000)), 14)), buffer.readu32(RK, 76))
			end
			do
				RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), buffer.readu32(RK, 80))
				RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), buffer.readu32(RK, 84))
				RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), buffer.readu32(RK, 88))
				RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), buffer.readu32(RK, 92))
				RB0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB0, 0xff), bit32.band(SB1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB2, 0xff0000), bit32.band(SB3, 0xff000000)), 14)), buffer.readu32(RK, 80))
				RB1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB1, 0xff), bit32.band(SB2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB3, 0xff0000), bit32.band(SB0, 0xff000000)), 14)), buffer.readu32(RK, 84))
				RB2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB2, 0xff), bit32.band(SB3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB0, 0xff0000), bit32.band(SB1, 0xff000000)), 14)), buffer.readu32(RK, 88))
				RB3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB3, 0xff), bit32.band(SB0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB1, 0xff0000), bit32.band(SB2, 0xff000000)), 14)), buffer.readu32(RK, 92))
			end
			do
				SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), buffer.readu32(RK, 96))
				SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), buffer.readu32(RK, 100))
				SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), buffer.readu32(RK, 104))
				SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), buffer.readu32(RK, 108))
				SB0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB0, 0xff), bit32.band(RB1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB2, 0xff0000), bit32.band(RB3, 0xff000000)), 14)), buffer.readu32(RK, 96))
				SB1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB1, 0xff), bit32.band(RB2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB3, 0xff0000), bit32.band(RB0, 0xff000000)), 14)), buffer.readu32(RK, 100))
				SB2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB2, 0xff), bit32.band(RB3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB0, 0xff0000), bit32.band(RB1, 0xff000000)), 14)), buffer.readu32(RK, 104))
				SB3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB3, 0xff), bit32.band(RB0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB1, 0xff0000), bit32.band(RB2, 0xff000000)), 14)), buffer.readu32(RK, 108))
			end
			do
				RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), buffer.readu32(RK, 112))
				RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), buffer.readu32(RK, 116))
				RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), buffer.readu32(RK, 120))
				RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), buffer.readu32(RK, 124))
				RB0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB0, 0xff), bit32.band(SB1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB2, 0xff0000), bit32.band(SB3, 0xff000000)), 14)), buffer.readu32(RK, 112))
				RB1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB1, 0xff), bit32.band(SB2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB3, 0xff0000), bit32.band(SB0, 0xff000000)), 14)), buffer.readu32(RK, 116))
				RB2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB2, 0xff), bit32.band(SB3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB0, 0xff0000), bit32.band(SB1, 0xff000000)), 14)), buffer.readu32(RK, 120))
				RB3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB3, 0xff), bit32.band(SB0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB1, 0xff0000), bit32.band(SB2, 0xff000000)), 14)), buffer.readu32(RK, 124))
			end
			do
				SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), buffer.readu32(RK, 128))
				SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), buffer.readu32(RK, 132))
				SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), buffer.readu32(RK, 136))
				SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), buffer.readu32(RK, 140))
				SB0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB0, 0xff), bit32.band(RB1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB2, 0xff0000), bit32.band(RB3, 0xff000000)), 14)), buffer.readu32(RK, 128))
				SB1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB1, 0xff), bit32.band(RB2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB3, 0xff0000), bit32.band(RB0, 0xff000000)), 14)), buffer.readu32(RK, 132))
				SB2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB2, 0xff), bit32.band(RB3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB0, 0xff0000), bit32.band(RB1, 0xff000000)), 14)), buffer.readu32(RK, 136))
				SB3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB3, 0xff), bit32.band(RB0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB1, 0xff0000), bit32.band(RB2, 0xff000000)), 14)), buffer.readu32(RK, 140))
			end
			do
				RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), buffer.readu32(RK, 144))
				RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), buffer.readu32(RK, 148))
				RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), buffer.readu32(RK, 152))
				RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), buffer.readu32(RK, 156))
				RB0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB0, 0xff), bit32.band(SB1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB2, 0xff0000), bit32.band(SB3, 0xff000000)), 14)), buffer.readu32(RK, 144))
				RB1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB1, 0xff), bit32.band(SB2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB3, 0xff0000), bit32.band(SB0, 0xff000000)), 14)), buffer.readu32(RK, 148))
				RB2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB2, 0xff), bit32.band(SB3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB0, 0xff0000), bit32.band(SB1, 0xff000000)), 14)), buffer.readu32(RK, 152))
				RB3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB3, 0xff), bit32.band(SB0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB1, 0xff0000), bit32.band(SB2, 0xff000000)), 14)), buffer.readu32(RK, 156))
			end
			if Rounds > 10 then
				do
					SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), buffer.readu32(RK, 160))
					SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), buffer.readu32(RK, 164))
					SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), buffer.readu32(RK, 168))
					SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), buffer.readu32(RK, 172))
					SB0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB0, 0xff), bit32.band(RB1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB2, 0xff0000), bit32.band(RB3, 0xff000000)), 14)), buffer.readu32(RK, 160))
					SB1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB1, 0xff), bit32.band(RB2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB3, 0xff0000), bit32.band(RB0, 0xff000000)), 14)), buffer.readu32(RK, 164))
					SB2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB2, 0xff), bit32.band(RB3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB0, 0xff0000), bit32.band(RB1, 0xff000000)), 14)), buffer.readu32(RK, 168))
					SB3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB3, 0xff), bit32.band(RB0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB1, 0xff0000), bit32.band(RB2, 0xff000000)), 14)), buffer.readu32(RK, 172))
				end
				do
					RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), buffer.readu32(RK, 176))
					RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), buffer.readu32(RK, 180))
					RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), buffer.readu32(RK, 184))
					RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), buffer.readu32(RK, 188))
					RB0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB0, 0xff), bit32.band(SB1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB2, 0xff0000), bit32.band(SB3, 0xff000000)), 14)), buffer.readu32(RK, 176))
					RB1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB1, 0xff), bit32.band(SB2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB3, 0xff0000), bit32.band(SB0, 0xff000000)), 14)), buffer.readu32(RK, 180))
					RB2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB2, 0xff), bit32.band(SB3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB0, 0xff0000), bit32.band(SB1, 0xff000000)), 14)), buffer.readu32(RK, 184))
					RB3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB3, 0xff), bit32.band(SB0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB1, 0xff0000), bit32.band(SB2, 0xff000000)), 14)), buffer.readu32(RK, 188))
				end
				if Rounds > 12 then
					do
						SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), buffer.readu32(RK, 192))
						SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), buffer.readu32(RK, 196))
						SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), buffer.readu32(RK, 200))
						SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), buffer.readu32(RK, 204))
						SB0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB0, 0xff), bit32.band(RB1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB2, 0xff0000), bit32.band(RB3, 0xff000000)), 14)), buffer.readu32(RK, 192))
						SB1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB1, 0xff), bit32.band(RB2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB3, 0xff0000), bit32.band(RB0, 0xff000000)), 14)), buffer.readu32(RK, 196))
						SB2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB2, 0xff), bit32.band(RB3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB0, 0xff0000), bit32.band(RB1, 0xff000000)), 14)), buffer.readu32(RK, 200))
						SB3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RB3, 0xff), bit32.band(RB0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RB1, 0xff0000), bit32.band(RB2, 0xff000000)), 14)), buffer.readu32(RK, 204))
					end
					do
						RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), buffer.readu32(RK, 208))
						RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), buffer.readu32(RK, 212))
						RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), buffer.readu32(RK, 216))
						RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), buffer.readu32(RK, 220))
						RB0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB0, 0xff), bit32.band(SB1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB2, 0xff0000), bit32.band(SB3, 0xff000000)), 14)), buffer.readu32(RK, 208))
						RB1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB1, 0xff), bit32.band(SB2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB3, 0xff0000), bit32.band(SB0, 0xff000000)), 14)), buffer.readu32(RK, 212))
						RB2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB2, 0xff), bit32.band(SB3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB0, 0xff0000), bit32.band(SB1, 0xff000000)), 14)), buffer.readu32(RK, 216))
						RB3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SB3, 0xff), bit32.band(SB0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SB1, 0xff0000), bit32.band(SB2, 0xff000000)), 14)), buffer.readu32(RK, 220))
					end
				end
			end
			local ZA0 = bit32.bxor(buffer.readu16(S16, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 1)), bit32.lshift(buffer.readu16(S16, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 15)), 16), buffer.readu32(RK, Last + 0))
			local ZA1 = bit32.bxor(buffer.readu16(S16, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 1)), bit32.lshift(buffer.readu16(S16, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 15)), 16), buffer.readu32(RK, Last + 4))
			local ZA2 = bit32.bxor(buffer.readu16(S16, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 1)), bit32.lshift(buffer.readu16(S16, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 15)), 16), buffer.readu32(RK, Last + 8))
			local ZA3 = bit32.bxor(buffer.readu16(S16, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 1)), bit32.lshift(buffer.readu16(S16, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 15)), 16), buffer.readu32(RK, Last + 12))
			local ZB0 = bit32.bxor(buffer.readu16(S16, bit32.lshift(bit32.bor(bit32.band(RB0, 0xff), bit32.band(RB1, 0xff00)), 1)), bit32.lshift(buffer.readu16(S16, bit32.rshift(bit32.bor(bit32.band(RB2, 0xff0000), bit32.band(RB3, 0xff000000)), 15)), 16), buffer.readu32(RK, Last + 0))
			local ZB1 = bit32.bxor(buffer.readu16(S16, bit32.lshift(bit32.bor(bit32.band(RB1, 0xff), bit32.band(RB2, 0xff00)), 1)), bit32.lshift(buffer.readu16(S16, bit32.rshift(bit32.bor(bit32.band(RB3, 0xff0000), bit32.band(RB0, 0xff000000)), 15)), 16), buffer.readu32(RK, Last + 4))
			local ZB2 = bit32.bxor(buffer.readu16(S16, bit32.lshift(bit32.bor(bit32.band(RB2, 0xff), bit32.band(RB3, 0xff00)), 1)), bit32.lshift(buffer.readu16(S16, bit32.rshift(bit32.bor(bit32.band(RB0, 0xff0000), bit32.band(RB1, 0xff000000)), 15)), 16), buffer.readu32(RK, Last + 8))
			local ZB3 = bit32.bxor(buffer.readu16(S16, bit32.lshift(bit32.bor(bit32.band(RB3, 0xff), bit32.band(RB0, 0xff00)), 1)), bit32.lshift(buffer.readu16(S16, bit32.rshift(bit32.bor(bit32.band(RB1, 0xff0000), bit32.band(RB2, 0xff000000)), 15)), 16), buffer.readu32(RK, Last + 12))
			buffer.writeu32(Output, Position + 0, bit32.bxor(buffer.readu32(Input, Position + 0), ZA0))
			buffer.writeu32(Output, Position + 4, bit32.bxor(buffer.readu32(Input, Position + 4), ZA1))
			buffer.writeu32(Output, Position + 8, bit32.bxor(buffer.readu32(Input, Position + 8), ZA2))
			buffer.writeu32(Output, Position + 12, bit32.bxor(buffer.readu32(Input, Position + 12), ZA3))
			buffer.writeu32(Output, Position + 16 + 0, bit32.bxor(buffer.readu32(Input, Position + 16 + 0), ZB0))
			buffer.writeu32(Output, Position + 16 + 4, bit32.bxor(buffer.readu32(Input, Position + 16 + 4), ZB1))
			buffer.writeu32(Output, Position + 16 + 8, bit32.bxor(buffer.readu32(Input, Position + 16 + 8), ZB2))
			buffer.writeu32(Output, Position + 16 + 12, bit32.bxor(buffer.readu32(Input, Position + 16 + 12), ZB3))
		end
		Offset += 32
		Counter = (Counter + 2) % 4294967296
	end
	while Offset < Length do
		local Remaining = Length - Offset
		local Source, Target, Position = Input, Output, Offset
		if Remaining < 16 then
			local Block = KEYSTREAM
			buffer.fill(Block, 0, 0, 16)
			buffer.copy(Block, 0, Input, Offset, Remaining)
			Source, Target, Position = Block, Block, 0
		end
		do
			local VA = bit32.bxor(bit32.byteswap(Counter), K3)
			local RA0 = bit32.bxor(P0, buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(VA, 20), 0xff0), 12)))
			local RA1 = bit32.bxor(P1, buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(VA, 12), 0xff0), 8)))
			local RA2 = bit32.bxor(P2, buffer.readu32(T, bit32.bor(bit32.band(bit32.rshift(VA, 4), 0xff0), 4)))
			local RA3 = bit32.bxor(P3, buffer.readu32(T, bit32.band(bit32.lshift(VA, 4), 0xff0)))
			local SA0, SA1, SA2, SA3 = 0, 0, 0, 0
			do
				SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), buffer.readu32(RK, 32))
				SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), buffer.readu32(RK, 36))
				SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), buffer.readu32(RK, 40))
				SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), buffer.readu32(RK, 44))
			end
			do
				RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), buffer.readu32(RK, 48))
				RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), buffer.readu32(RK, 52))
				RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), buffer.readu32(RK, 56))
				RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), buffer.readu32(RK, 60))
			end
			do
				SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), buffer.readu32(RK, 64))
				SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), buffer.readu32(RK, 68))
				SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), buffer.readu32(RK, 72))
				SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), buffer.readu32(RK, 76))
			end
			do
				RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), buffer.readu32(RK, 80))
				RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), buffer.readu32(RK, 84))
				RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), buffer.readu32(RK, 88))
				RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), buffer.readu32(RK, 92))
			end
			do
				SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), buffer.readu32(RK, 96))
				SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), buffer.readu32(RK, 100))
				SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), buffer.readu32(RK, 104))
				SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), buffer.readu32(RK, 108))
			end
			do
				RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), buffer.readu32(RK, 112))
				RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), buffer.readu32(RK, 116))
				RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), buffer.readu32(RK, 120))
				RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), buffer.readu32(RK, 124))
			end
			do
				SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), buffer.readu32(RK, 128))
				SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), buffer.readu32(RK, 132))
				SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), buffer.readu32(RK, 136))
				SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), buffer.readu32(RK, 140))
			end
			do
				RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), buffer.readu32(RK, 144))
				RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), buffer.readu32(RK, 148))
				RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), buffer.readu32(RK, 152))
				RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), buffer.readu32(RK, 156))
			end
			if Rounds > 10 then
				do
					SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), buffer.readu32(RK, 160))
					SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), buffer.readu32(RK, 164))
					SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), buffer.readu32(RK, 168))
					SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), buffer.readu32(RK, 172))
				end
				do
					RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), buffer.readu32(RK, 176))
					RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), buffer.readu32(RK, 180))
					RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), buffer.readu32(RK, 184))
					RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), buffer.readu32(RK, 188))
				end
				if Rounds > 12 then
					do
						SA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 14)), buffer.readu32(RK, 192))
						SA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 14)), buffer.readu32(RK, 196))
						SA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 14)), buffer.readu32(RK, 200))
						SA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 14)), buffer.readu32(RK, 204))
					end
					do
						RA0 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA0, 0xff), bit32.band(SA1, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA2, 0xff0000), bit32.band(SA3, 0xff000000)), 14)), buffer.readu32(RK, 208))
						RA1 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA1, 0xff), bit32.band(SA2, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA3, 0xff0000), bit32.band(SA0, 0xff000000)), 14)), buffer.readu32(RK, 212))
						RA2 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA2, 0xff), bit32.band(SA3, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA0, 0xff0000), bit32.band(SA1, 0xff000000)), 14)), buffer.readu32(RK, 216))
						RA3 = bit32.bxor(buffer.readu32(T01, bit32.lshift(bit32.bor(bit32.band(SA3, 0xff), bit32.band(SA0, 0xff00)), 2)), buffer.readu32(T23, bit32.rshift(bit32.bor(bit32.band(SA1, 0xff0000), bit32.band(SA2, 0xff000000)), 14)), buffer.readu32(RK, 220))
					end
				end
			end
			local ZA0 = bit32.bxor(buffer.readu16(S16, bit32.lshift(bit32.bor(bit32.band(RA0, 0xff), bit32.band(RA1, 0xff00)), 1)), bit32.lshift(buffer.readu16(S16, bit32.rshift(bit32.bor(bit32.band(RA2, 0xff0000), bit32.band(RA3, 0xff000000)), 15)), 16), buffer.readu32(RK, Last + 0))
			local ZA1 = bit32.bxor(buffer.readu16(S16, bit32.lshift(bit32.bor(bit32.band(RA1, 0xff), bit32.band(RA2, 0xff00)), 1)), bit32.lshift(buffer.readu16(S16, bit32.rshift(bit32.bor(bit32.band(RA3, 0xff0000), bit32.band(RA0, 0xff000000)), 15)), 16), buffer.readu32(RK, Last + 4))
			local ZA2 = bit32.bxor(buffer.readu16(S16, bit32.lshift(bit32.bor(bit32.band(RA2, 0xff), bit32.band(RA3, 0xff00)), 1)), bit32.lshift(buffer.readu16(S16, bit32.rshift(bit32.bor(bit32.band(RA0, 0xff0000), bit32.band(RA1, 0xff000000)), 15)), 16), buffer.readu32(RK, Last + 8))
			local ZA3 = bit32.bxor(buffer.readu16(S16, bit32.lshift(bit32.bor(bit32.band(RA3, 0xff), bit32.band(RA0, 0xff00)), 1)), bit32.lshift(buffer.readu16(S16, bit32.rshift(bit32.bor(bit32.band(RA1, 0xff0000), bit32.band(RA2, 0xff000000)), 15)), 16), buffer.readu32(RK, Last + 12))
			buffer.writeu32(Target, Position + 0, bit32.bxor(buffer.readu32(Source, Position + 0), ZA0))
			buffer.writeu32(Target, Position + 4, bit32.bxor(buffer.readu32(Source, Position + 4), ZA1))
			buffer.writeu32(Target, Position + 8, bit32.bxor(buffer.readu32(Source, Position + 8), ZA2))
			buffer.writeu32(Target, Position + 12, bit32.bxor(buffer.readu32(Source, Position + 12), ZA3))
		end
		if Remaining < 16 then
			buffer.copy(Output, Offset, KEYSTREAM, 0, Remaining)
		end
		Offset += 16
		Counter = (Counter + 1) % 4294967296
	end
end

local function BuildNibbleTables()
	local Tables = NIBBLE_TABLES
	local V0 = bit32.byteswap(buffer.readu32(HASH_KEY, 0))
	local V1 = bit32.byteswap(buffer.readu32(HASH_KEY, 4))
	local V2 = bit32.byteswap(buffer.readu32(HASH_KEY, 8))
	local V3 = bit32.byteswap(buffer.readu32(HASH_KEY, 12))

	for Base = 0, 8191, 256 do
		local A0, A1, A2, A3 = bit32.byteswap(V0), bit32.byteswap(V1), bit32.byteswap(V2), bit32.byteswap(V3)
		local Carry = bit32.band(V3, 1)
		V3 = bit32.bor(bit32.rshift(V3, 1), bit32.lshift(V2, 31))
		V2 = bit32.bor(bit32.rshift(V2, 1), bit32.lshift(V1, 31))
		V1 = bit32.bor(bit32.rshift(V1, 1), bit32.lshift(V0, 31))
		V0 = bit32.bxor(bit32.rshift(V0, 1), Carry * 0xe1000000)
		local B0, B1, B2, B3 = bit32.byteswap(V0), bit32.byteswap(V1), bit32.byteswap(V2), bit32.byteswap(V3)
		Carry = bit32.band(V3, 1)
		V3 = bit32.bor(bit32.rshift(V3, 1), bit32.lshift(V2, 31))
		V2 = bit32.bor(bit32.rshift(V2, 1), bit32.lshift(V1, 31))
		V1 = bit32.bor(bit32.rshift(V1, 1), bit32.lshift(V0, 31))
		V0 = bit32.bxor(bit32.rshift(V0, 1), Carry * 0xe1000000)
		local C0, C1, C2, C3 = bit32.byteswap(V0), bit32.byteswap(V1), bit32.byteswap(V2), bit32.byteswap(V3)
		Carry = bit32.band(V3, 1)
		V3 = bit32.bor(bit32.rshift(V3, 1), bit32.lshift(V2, 31))
		V2 = bit32.bor(bit32.rshift(V2, 1), bit32.lshift(V1, 31))
		V1 = bit32.bor(bit32.rshift(V1, 1), bit32.lshift(V0, 31))
		V0 = bit32.bxor(bit32.rshift(V0, 1), Carry * 0xe1000000)
		local D0, D1, D2, D3 = bit32.byteswap(V0), bit32.byteswap(V1), bit32.byteswap(V2), bit32.byteswap(V3)
		Carry = bit32.band(V3, 1)
		V3 = bit32.bor(bit32.rshift(V3, 1), bit32.lshift(V2, 31))
		V2 = bit32.bor(bit32.rshift(V2, 1), bit32.lshift(V1, 31))
		V1 = bit32.bor(bit32.rshift(V1, 1), bit32.lshift(V0, 31))
		V0 = bit32.bxor(bit32.rshift(V0, 1), Carry * 0xe1000000)

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

local function BuildByteTables()
	local Nibbles = NIBBLE_TABLES
	local Bytes = BYTE_TABLES
	for Position = 0, 15 do
		local HighBase = Position * 512
		local LowBase = HighBase + 256
		local OutBase = Position * 4096
		for High = 0, 15 do
			local HighOffset = HighBase + High * 16
			local A0 = buffer.readu32(Nibbles, HighOffset)
			local A1 = buffer.readu32(Nibbles, HighOffset + 4)
			local A2 = buffer.readu32(Nibbles, HighOffset + 8)
			local A3 = buffer.readu32(Nibbles, HighOffset + 12)
			local Target = OutBase + High * 256
			for Low = 0, 240, 16 do
				local LowOffset = LowBase + Low
				local Entry = Target + Low
				buffer.writeu32(Bytes, Entry, bit32.bxor(A0, buffer.readu32(Nibbles, LowOffset)))
				buffer.writeu32(Bytes, Entry + 4, bit32.bxor(A1, buffer.readu32(Nibbles, LowOffset + 4)))
				buffer.writeu32(Bytes, Entry + 8, bit32.bxor(A2, buffer.readu32(Nibbles, LowOffset + 8)))
				buffer.writeu32(Bytes, Entry + 12, bit32.bxor(A3, buffer.readu32(Nibbles, LowOffset + 12)))
			end
		end
	end
	ByteTablesReady = true
end

local function GhashNibbles(Data: buffer, Offset: number, Length: number)
	local State = GHASH_STATE
	local T = NIBBLE_TABLES
	local Z0 = buffer.readu32(State, 0)
	local Z1 = buffer.readu32(State, 4)
	local Z2 = buffer.readu32(State, 8)
	local Z3 = buffer.readu32(State, 12)
	for Position = Offset, Offset + Length - 16, 16 do
		local X0 = bit32.bxor(Z0, buffer.readu32(Data, Position + 0))
		local X1 = bit32.bxor(Z1, buffer.readu32(Data, Position + 4))
		local X2 = bit32.bxor(Z2, buffer.readu32(Data, Position + 8))
		local X3 = bit32.bxor(Z3, buffer.readu32(Data, Position + 12))
		Z0, Z1, Z2, Z3 = 0, 0, 0, 0
		do
			local H = bit32.bor(bit32.band(X0, 0xf0), 0)
			local L = bit32.bor(bit32.band(bit32.lshift(X0, 4), 0xf0), 256)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, H), buffer.readu32(T, L))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, H + 4), buffer.readu32(T, L + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, H + 8), buffer.readu32(T, L + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, H + 12), buffer.readu32(T, L + 12))
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

local function GhashBytes(Data: buffer, Offset: number, Length: number)
	local State = GHASH_STATE
	local T = BYTE_TABLES
	local Z0 = buffer.readu32(State, 0)
	local Z1 = buffer.readu32(State, 4)
	local Z2 = buffer.readu32(State, 8)
	local Z3 = buffer.readu32(State, 12)
	for Position = Offset, Offset + Length - 16, 16 do
		local X0 = bit32.bxor(Z0, buffer.readu32(Data, Position + 0))
		local X1 = bit32.bxor(Z1, buffer.readu32(Data, Position + 4))
		local X2 = bit32.bxor(Z2, buffer.readu32(Data, Position + 8))
		local X3 = bit32.bxor(Z3, buffer.readu32(Data, Position + 12))
		Z0, Z1, Z2, Z3 = 0, 0, 0, 0
		do
			local E = bit32.bor(bit32.band(bit32.lshift(X0, 4), 0xff0), 0)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X0, 4), 0xff0), 4096)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X0, 12), 0xff0), 8192)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X0, 20), 0xff0), 12288)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.lshift(X1, 4), 0xff0), 16384)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X1, 4), 0xff0), 20480)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X1, 12), 0xff0), 24576)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X1, 20), 0xff0), 28672)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.lshift(X2, 4), 0xff0), 32768)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X2, 4), 0xff0), 36864)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X2, 12), 0xff0), 40960)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X2, 20), 0xff0), 45056)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.lshift(X3, 4), 0xff0), 49152)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X3, 4), 0xff0), 53248)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X3, 12), 0xff0), 57344)
			Z0 = bit32.bxor(Z0, buffer.readu32(T, E))
			Z1 = bit32.bxor(Z1, buffer.readu32(T, E + 4))
			Z2 = bit32.bxor(Z2, buffer.readu32(T, E + 8))
			Z3 = bit32.bxor(Z3, buffer.readu32(T, E + 12))
		end
		do
			local E = bit32.bor(bit32.band(bit32.rshift(X3, 20), 0xff0), 61440)
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
	if CacheLength == KeyLength then
		local Difference = 0
		for Offset = 0, KeyLength - 4, 4 do
			Difference = bit32.bor(Difference, bit32.bxor(buffer.readu32(Key, Offset), buffer.readu32(CACHE_KEY, Offset)))
		end
		if Difference == 0 then
			return CacheRounds, true
		end
	end

	local Rounds = if KeyLength == 16 then 10 elseif KeyLength == 24 then 12 else 14
	ExpandKeySchedule(Key, KeyLength, ROUND_KEYS)
	Ctr(Rounds, ZERO_BLOCK, HASH_KEY, 16, 0, 0, 0, 0)
	BuildNibbleTables()
	ByteTablesReady = false

	buffer.copy(CACHE_KEY, 0, Key, 0, KeyLength)
	CacheLength = KeyLength
	CacheRounds = Rounds

	return Rounds, false
end

local function GhashPadded(Hash: (buffer, number, number) -> (), Data: buffer, Length: number)
	local TailLength = Length % 16
	local FullBytes = Length - TailLength
	if FullBytes > 0 then
		Hash(Data, 0, FullBytes)
	end
	if TailLength > 0 then
		local Block = GHASH_BLOCK
		buffer.fill(Block, 0, 0, 16)
		buffer.copy(Block, 0, Data, FullBytes, TailLength)
		Hash(Block, 0, 16)
	end
end

local function LengthBlock(Hash: (buffer, number, number) -> (), FirstBytes: number, SecondBytes: number)
	local Block = GHASH_BLOCK
	local FirstBits = FirstBytes * 8
	local SecondBits = SecondBytes * 8
	buffer.writeu32(Block, 0, bit32.byteswap(math.floor(FirstBits * 2 ^ -32)))
	buffer.writeu32(Block, 4, bit32.byteswap(FirstBits % 4294967296))
	buffer.writeu32(Block, 8, bit32.byteswap(math.floor(SecondBits * 2 ^ -32)))
	buffer.writeu32(Block, 12, bit32.byteswap(SecondBits % 4294967296))
	Hash(Block, 0, 16)
end

local function PrepareCounter(IV: buffer, IVLength: number): (number, number, number, number)
	if IVLength == 12 then
		return buffer.readu32(IV, 0), buffer.readu32(IV, 4), buffer.readu32(IV, 8), 1
	end

	buffer.fill(GHASH_STATE, 0, 0, 16)
	GhashPadded(GhashNibbles, IV, IVLength)
	LengthBlock(GhashNibbles, 0, IVLength)
	local State = GHASH_STATE
	return buffer.readu32(State, 0), buffer.readu32(State, 4), buffer.readu32(State, 8), bit32.byteswap(buffer.readu32(State, 12))
end

local function AuthenticationTag(Rounds: number, CacheHit: boolean, AAD: buffer, AADLength: number, Ciphertext: buffer, CiphertextLength: number, J0: number, J1: number, J2: number, Counter: number): buffer
	local Hash = GhashNibbles
	if ByteTablesReady then
		Hash = GhashBytes
	elseif CacheHit or (AADLength + CiphertextLength) // 16 >= 128 then
		BuildByteTables()
		Hash = GhashBytes
	end

	buffer.fill(GHASH_STATE, 0, 0, 16)
	GhashPadded(Hash, AAD, AADLength)
	GhashPadded(Hash, Ciphertext, CiphertextLength)
	LengthBlock(Hash, AADLength, CiphertextLength)

	local Tag = buffer.create(16)
	Ctr(Rounds, GHASH_STATE, Tag, 16, J0, J1, J2, Counter)
	return Tag
end

function AES.Encrypt(Plaintext: buffer, Key: buffer, IV: buffer, AAD: buffer?): (buffer, buffer)
	if not Key or typeof(Key) ~= "buffer" then
		error("Key must be a buffer", 2)
	end

	if not IV or typeof(IV) ~= "buffer" then
		error("IV must be a buffer", 2)
	end

	if not Plaintext or typeof(Plaintext) ~= "buffer" then
		error("Plaintext must be a buffer", 2)
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

	local AuthData = AAD or EMPTY
	local PlainLength = buffer.len(Plaintext)
	local Ciphertext = buffer.create(PlainLength)
	if PlainLength > 0 then
		Ctr(Rounds, Plaintext, Ciphertext, PlainLength, J0, J1, J2, (Counter + 1) % 4294967296)
	end

	local Tag = AuthenticationTag(Rounds, CacheHit, AuthData, buffer.len(AuthData), Ciphertext, PlainLength, J0, J1, J2, Counter)

	return Ciphertext, Tag
end

function AES.Decrypt(Ciphertext: buffer, Key: buffer, IV: buffer, Tag: buffer, AAD: buffer?): buffer?
	if not Key or typeof(Key) ~= "buffer" then
		error("Key must be a buffer", 2)
	end

	if not IV or typeof(IV) ~= "buffer" then
		error("IV must be a buffer", 2)
	end

	if not Ciphertext or typeof(Ciphertext) ~= "buffer" then
		error("Ciphertext must be a buffer", 2)
	end

	if not Tag or typeof(Tag) ~= "buffer" then
		error("Tag must be a buffer", 2)
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

	local AuthData = AAD or EMPTY
	local CipherLength = buffer.len(Ciphertext)
	local ComputedTag = AuthenticationTag(Rounds, CacheHit, AuthData, buffer.len(AuthData), Ciphertext, CipherLength, J0, J1, J2, Counter)

	if not CtCompare(Tag, ComputedTag) then
		return nil
	end

	local Plaintext = buffer.create(CipherLength)
	if CipherLength > 0 then
		Ctr(Rounds, Ciphertext, Plaintext, CipherLength, J0, J1, J2, (Counter + 1) % 4294967296)
	end

	return Plaintext
end

return AES
