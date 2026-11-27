--[=[
	Cryptography library: SHA256

	Sizes:
		Digest: 32 bytes
	
	Return type: (string, buffer)
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Hash, HashBuffer = SHA256(Message)
--]=]

--!strict
--!optimize 2
--!native

local Conversions = require("../../Utilities/Conversions")
local ToHex = Conversions.ToHex

local CARRY = 2 ^ -32

local IV_256: buffer = buffer.fromstring("\x67\xE6\x09\x6A\x85\xAE\x67\xBB\x72\xF3\x6E\x3C\x3A\xF5\x4F\xA5\z
	\x7F\x52\x0E\x51\x8C\x68\x05\x9B\xAB\xD9\x83\x1F\x19\xCD\xE0\x5B")
local IV_224: buffer = buffer.fromstring("\xD8\x9E\x05\xC1\x07\xD5\x7C\x36\x17\xDD\x70\x30\x39\x59\x0E\xF7\z
	\x31\x0B\xC0\xFF\x11\x15\x58\x68\xA7\x8F\xF9\x64\xA4\x4F\xFA\xBE")

local STATE: buffer = buffer.create(32)
local TAIL: buffer = buffer.create(64)

local function Compress(Blocks: buffer, Offset: number, Length: number, State: buffer)
	for Position = Offset, Offset + Length - 1, 64 do
		local S0 = buffer.readu32(State, 0)
		local S1 = buffer.readu32(State, 4)
		local S2 = buffer.readu32(State, 8)
		local S3 = buffer.readu32(State, 12)
		local S4 = buffer.readu32(State, 16)
		local S5 = buffer.readu32(State, 20)
		local S6 = buffer.readu32(State, 24)
		local S7 = buffer.readu32(State, 28)
		local BC = bit32.bxor(S1, S2)
		local W0 = bit32.byteswap(buffer.readu32(Blocks, Position + 0))
		do
			local AB = bit32.bxor(S0, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0x428a2f98, 0) + W0, 0) + bit32.bxor(S6, bit32.band(S4, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(S4, 6), bit32.rrotate(S4, 11), bit32.rrotate(S4, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S0, 2), bit32.rrotate(S0, 13), bit32.rrotate(S0, 22)), 0)
			BC = AB
		end
		local W1 = bit32.byteswap(buffer.readu32(Blocks, Position + 4))
		do
			local AB = bit32.bxor(S7, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0x71374491, 0) + W1, 0) + bit32.bxor(S5, bit32.band(S3, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(S3, 6), bit32.rrotate(S3, 11), bit32.rrotate(S3, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S7, 2), bit32.rrotate(S7, 13), bit32.rrotate(S7, 22)), 0)
			BC = AB
		end
		local W2 = bit32.byteswap(buffer.readu32(Blocks, Position + 8))
		do
			local AB = bit32.bxor(S6, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0xb5c0fbcf, 0) + W2, 0) + bit32.bxor(S4, bit32.band(S2, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(S2, 6), bit32.rrotate(S2, 11), bit32.rrotate(S2, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S6, 2), bit32.rrotate(S6, 13), bit32.rrotate(S6, 22)), 0)
			BC = AB
		end
		local W3 = bit32.byteswap(buffer.readu32(Blocks, Position + 12))
		do
			local AB = bit32.bxor(S5, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0xe9b5dba5, 0) + W3, 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(S1, 6), bit32.rrotate(S1, 11), bit32.rrotate(S1, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S5, 2), bit32.rrotate(S5, 13), bit32.rrotate(S5, 22)), 0)
			BC = AB
		end
		local W4 = bit32.byteswap(buffer.readu32(Blocks, Position + 16))
		do
			local AB = bit32.bxor(S4, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x3956c25b, 0) + W4, 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(S0, 6), bit32.rrotate(S0, 11), bit32.rrotate(S0, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S4, 2), bit32.rrotate(S4, 13), bit32.rrotate(S4, 22)), 0)
			BC = AB
		end
		local W5 = bit32.byteswap(buffer.readu32(Blocks, Position + 20))
		do
			local AB = bit32.bxor(S3, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x59f111f1, 0) + W5, 0) + bit32.bxor(S1, bit32.band(S7, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(S7, 6), bit32.rrotate(S7, 11), bit32.rrotate(S7, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S3, 2), bit32.rrotate(S3, 13), bit32.rrotate(S3, 22)), 0)
			BC = AB
		end
		local W6 = bit32.byteswap(buffer.readu32(Blocks, Position + 24))
		do
			local AB = bit32.bxor(S2, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x923f82a4, 0) + W6, 0) + bit32.bxor(S0, bit32.band(S6, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(S6, 6), bit32.rrotate(S6, 11), bit32.rrotate(S6, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S2, 2), bit32.rrotate(S2, 13), bit32.rrotate(S2, 22)), 0)
			BC = AB
		end
		local W7 = bit32.byteswap(buffer.readu32(Blocks, Position + 28))
		do
			local AB = bit32.bxor(S1, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0xab1c5ed5, 0) + W7, 0) + bit32.bxor(S7, bit32.band(S5, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(S5, 6), bit32.rrotate(S5, 11), bit32.rrotate(S5, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S1, 2), bit32.rrotate(S1, 13), bit32.rrotate(S1, 22)), 0)
			BC = AB
		end
		local W8 = bit32.byteswap(buffer.readu32(Blocks, Position + 32))
		do
			local AB = bit32.bxor(S0, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0xd807aa98, 0) + W8, 0) + bit32.bxor(S6, bit32.band(S4, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(S4, 6), bit32.rrotate(S4, 11), bit32.rrotate(S4, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S0, 2), bit32.rrotate(S0, 13), bit32.rrotate(S0, 22)), 0)
			BC = AB
		end
		local W9 = bit32.byteswap(buffer.readu32(Blocks, Position + 36))
		do
			local AB = bit32.bxor(S7, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0x12835b01, 0) + W9, 0) + bit32.bxor(S5, bit32.band(S3, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(S3, 6), bit32.rrotate(S3, 11), bit32.rrotate(S3, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S7, 2), bit32.rrotate(S7, 13), bit32.rrotate(S7, 22)), 0)
			BC = AB
		end
		local W10 = bit32.byteswap(buffer.readu32(Blocks, Position + 40))
		do
			local AB = bit32.bxor(S6, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0x243185be, 0) + W10, 0) + bit32.bxor(S4, bit32.band(S2, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(S2, 6), bit32.rrotate(S2, 11), bit32.rrotate(S2, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S6, 2), bit32.rrotate(S6, 13), bit32.rrotate(S6, 22)), 0)
			BC = AB
		end
		local W11 = bit32.byteswap(buffer.readu32(Blocks, Position + 44))
		do
			local AB = bit32.bxor(S5, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x550c7dc3, 0) + W11, 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(S1, 6), bit32.rrotate(S1, 11), bit32.rrotate(S1, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S5, 2), bit32.rrotate(S5, 13), bit32.rrotate(S5, 22)), 0)
			BC = AB
		end
		local W12 = bit32.byteswap(buffer.readu32(Blocks, Position + 48))
		do
			local AB = bit32.bxor(S4, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x72be5d74, 0) + W12, 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(S0, 6), bit32.rrotate(S0, 11), bit32.rrotate(S0, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S4, 2), bit32.rrotate(S4, 13), bit32.rrotate(S4, 22)), 0)
			BC = AB
		end
		local W13 = bit32.byteswap(buffer.readu32(Blocks, Position + 52))
		do
			local AB = bit32.bxor(S3, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x80deb1fe, 0) + W13, 0) + bit32.bxor(S1, bit32.band(S7, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(S7, 6), bit32.rrotate(S7, 11), bit32.rrotate(S7, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S3, 2), bit32.rrotate(S3, 13), bit32.rrotate(S3, 22)), 0)
			BC = AB
		end
		local W14 = bit32.byteswap(buffer.readu32(Blocks, Position + 56))
		do
			local AB = bit32.bxor(S2, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x9bdc06a7, 0) + W14, 0) + bit32.bxor(S0, bit32.band(S6, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(S6, 6), bit32.rrotate(S6, 11), bit32.rrotate(S6, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S2, 2), bit32.rrotate(S2, 13), bit32.rrotate(S2, 22)), 0)
			BC = AB
		end
		local W15 = bit32.byteswap(buffer.readu32(Blocks, Position + 60))
		do
			local AB = bit32.bxor(S1, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0xc19bf174, 0) + W15, 0) + bit32.bxor(S7, bit32.band(S5, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(S5, 6), bit32.rrotate(S5, 11), bit32.rrotate(S5, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S1, 2), bit32.rrotate(S1, 13), bit32.rrotate(S1, 22)), 0)
			BC = AB
		end
		do
			W0 = bit32.bor(bit32.bor(bit32.bor(W0 + W9, 0) + bit32.bxor(bit32.rrotate(W1, 7), bit32.rrotate(W1, 18), bit32.rshift(W1, 3)), 0) + bit32.bxor(bit32.rrotate(W14, 17), bit32.rrotate(W14, 19), bit32.rshift(W14, 10)), 0)
			local AB = bit32.bxor(S0, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0xe49b69c1, 0) + W0, 0) + bit32.bxor(S6, bit32.band(S4, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(S4, 6), bit32.rrotate(S4, 11), bit32.rrotate(S4, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S0, 2), bit32.rrotate(S0, 13), bit32.rrotate(S0, 22)), 0)
			BC = AB
		end
		do
			W1 = bit32.bor(bit32.bor(bit32.bor(W1 + W10, 0) + bit32.bxor(bit32.rrotate(W2, 7), bit32.rrotate(W2, 18), bit32.rshift(W2, 3)), 0) + bit32.bxor(bit32.rrotate(W15, 17), bit32.rrotate(W15, 19), bit32.rshift(W15, 10)), 0)
			local AB = bit32.bxor(S7, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0xefbe4786, 0) + W1, 0) + bit32.bxor(S5, bit32.band(S3, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(S3, 6), bit32.rrotate(S3, 11), bit32.rrotate(S3, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S7, 2), bit32.rrotate(S7, 13), bit32.rrotate(S7, 22)), 0)
			BC = AB
		end
		do
			W2 = bit32.bor(bit32.bor(bit32.bor(W2 + W11, 0) + bit32.bxor(bit32.rrotate(W3, 7), bit32.rrotate(W3, 18), bit32.rshift(W3, 3)), 0) + bit32.bxor(bit32.rrotate(W0, 17), bit32.rrotate(W0, 19), bit32.rshift(W0, 10)), 0)
			local AB = bit32.bxor(S6, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0x0fc19dc6, 0) + W2, 0) + bit32.bxor(S4, bit32.band(S2, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(S2, 6), bit32.rrotate(S2, 11), bit32.rrotate(S2, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S6, 2), bit32.rrotate(S6, 13), bit32.rrotate(S6, 22)), 0)
			BC = AB
		end
		do
			W3 = bit32.bor(bit32.bor(bit32.bor(W3 + W12, 0) + bit32.bxor(bit32.rrotate(W4, 7), bit32.rrotate(W4, 18), bit32.rshift(W4, 3)), 0) + bit32.bxor(bit32.rrotate(W1, 17), bit32.rrotate(W1, 19), bit32.rshift(W1, 10)), 0)
			local AB = bit32.bxor(S5, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x240ca1cc, 0) + W3, 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(S1, 6), bit32.rrotate(S1, 11), bit32.rrotate(S1, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S5, 2), bit32.rrotate(S5, 13), bit32.rrotate(S5, 22)), 0)
			BC = AB
		end
		do
			W4 = bit32.bor(bit32.bor(bit32.bor(W4 + W13, 0) + bit32.bxor(bit32.rrotate(W5, 7), bit32.rrotate(W5, 18), bit32.rshift(W5, 3)), 0) + bit32.bxor(bit32.rrotate(W2, 17), bit32.rrotate(W2, 19), bit32.rshift(W2, 10)), 0)
			local AB = bit32.bxor(S4, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x2de92c6f, 0) + W4, 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(S0, 6), bit32.rrotate(S0, 11), bit32.rrotate(S0, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S4, 2), bit32.rrotate(S4, 13), bit32.rrotate(S4, 22)), 0)
			BC = AB
		end
		do
			W5 = bit32.bor(bit32.bor(bit32.bor(W5 + W14, 0) + bit32.bxor(bit32.rrotate(W6, 7), bit32.rrotate(W6, 18), bit32.rshift(W6, 3)), 0) + bit32.bxor(bit32.rrotate(W3, 17), bit32.rrotate(W3, 19), bit32.rshift(W3, 10)), 0)
			local AB = bit32.bxor(S3, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x4a7484aa, 0) + W5, 0) + bit32.bxor(S1, bit32.band(S7, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(S7, 6), bit32.rrotate(S7, 11), bit32.rrotate(S7, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S3, 2), bit32.rrotate(S3, 13), bit32.rrotate(S3, 22)), 0)
			BC = AB
		end
		do
			W6 = bit32.bor(bit32.bor(bit32.bor(W6 + W15, 0) + bit32.bxor(bit32.rrotate(W7, 7), bit32.rrotate(W7, 18), bit32.rshift(W7, 3)), 0) + bit32.bxor(bit32.rrotate(W4, 17), bit32.rrotate(W4, 19), bit32.rshift(W4, 10)), 0)
			local AB = bit32.bxor(S2, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x5cb0a9dc, 0) + W6, 0) + bit32.bxor(S0, bit32.band(S6, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(S6, 6), bit32.rrotate(S6, 11), bit32.rrotate(S6, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S2, 2), bit32.rrotate(S2, 13), bit32.rrotate(S2, 22)), 0)
			BC = AB
		end
		do
			W7 = bit32.bor(bit32.bor(bit32.bor(W7 + W0, 0) + bit32.bxor(bit32.rrotate(W8, 7), bit32.rrotate(W8, 18), bit32.rshift(W8, 3)), 0) + bit32.bxor(bit32.rrotate(W5, 17), bit32.rrotate(W5, 19), bit32.rshift(W5, 10)), 0)
			local AB = bit32.bxor(S1, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x76f988da, 0) + W7, 0) + bit32.bxor(S7, bit32.band(S5, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(S5, 6), bit32.rrotate(S5, 11), bit32.rrotate(S5, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S1, 2), bit32.rrotate(S1, 13), bit32.rrotate(S1, 22)), 0)
			BC = AB
		end
		do
			W8 = bit32.bor(bit32.bor(bit32.bor(W8 + W1, 0) + bit32.bxor(bit32.rrotate(W9, 7), bit32.rrotate(W9, 18), bit32.rshift(W9, 3)), 0) + bit32.bxor(bit32.rrotate(W6, 17), bit32.rrotate(W6, 19), bit32.rshift(W6, 10)), 0)
			local AB = bit32.bxor(S0, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0x983e5152, 0) + W8, 0) + bit32.bxor(S6, bit32.band(S4, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(S4, 6), bit32.rrotate(S4, 11), bit32.rrotate(S4, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S0, 2), bit32.rrotate(S0, 13), bit32.rrotate(S0, 22)), 0)
			BC = AB
		end
		do
			W9 = bit32.bor(bit32.bor(bit32.bor(W9 + W2, 0) + bit32.bxor(bit32.rrotate(W10, 7), bit32.rrotate(W10, 18), bit32.rshift(W10, 3)), 0) + bit32.bxor(bit32.rrotate(W7, 17), bit32.rrotate(W7, 19), bit32.rshift(W7, 10)), 0)
			local AB = bit32.bxor(S7, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0xa831c66d, 0) + W9, 0) + bit32.bxor(S5, bit32.band(S3, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(S3, 6), bit32.rrotate(S3, 11), bit32.rrotate(S3, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S7, 2), bit32.rrotate(S7, 13), bit32.rrotate(S7, 22)), 0)
			BC = AB
		end
		do
			W10 = bit32.bor(bit32.bor(bit32.bor(W10 + W3, 0) + bit32.bxor(bit32.rrotate(W11, 7), bit32.rrotate(W11, 18), bit32.rshift(W11, 3)), 0) + bit32.bxor(bit32.rrotate(W8, 17), bit32.rrotate(W8, 19), bit32.rshift(W8, 10)), 0)
			local AB = bit32.bxor(S6, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0xb00327c8, 0) + W10, 0) + bit32.bxor(S4, bit32.band(S2, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(S2, 6), bit32.rrotate(S2, 11), bit32.rrotate(S2, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S6, 2), bit32.rrotate(S6, 13), bit32.rrotate(S6, 22)), 0)
			BC = AB
		end
		do
			W11 = bit32.bor(bit32.bor(bit32.bor(W11 + W4, 0) + bit32.bxor(bit32.rrotate(W12, 7), bit32.rrotate(W12, 18), bit32.rshift(W12, 3)), 0) + bit32.bxor(bit32.rrotate(W9, 17), bit32.rrotate(W9, 19), bit32.rshift(W9, 10)), 0)
			local AB = bit32.bxor(S5, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0xbf597fc7, 0) + W11, 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(S1, 6), bit32.rrotate(S1, 11), bit32.rrotate(S1, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S5, 2), bit32.rrotate(S5, 13), bit32.rrotate(S5, 22)), 0)
			BC = AB
		end
		do
			W12 = bit32.bor(bit32.bor(bit32.bor(W12 + W5, 0) + bit32.bxor(bit32.rrotate(W13, 7), bit32.rrotate(W13, 18), bit32.rshift(W13, 3)), 0) + bit32.bxor(bit32.rrotate(W10, 17), bit32.rrotate(W10, 19), bit32.rshift(W10, 10)), 0)
			local AB = bit32.bxor(S4, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0xc6e00bf3, 0) + W12, 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(S0, 6), bit32.rrotate(S0, 11), bit32.rrotate(S0, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S4, 2), bit32.rrotate(S4, 13), bit32.rrotate(S4, 22)), 0)
			BC = AB
		end
		do
			W13 = bit32.bor(bit32.bor(bit32.bor(W13 + W6, 0) + bit32.bxor(bit32.rrotate(W14, 7), bit32.rrotate(W14, 18), bit32.rshift(W14, 3)), 0) + bit32.bxor(bit32.rrotate(W11, 17), bit32.rrotate(W11, 19), bit32.rshift(W11, 10)), 0)
			local AB = bit32.bxor(S3, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0xd5a79147, 0) + W13, 0) + bit32.bxor(S1, bit32.band(S7, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(S7, 6), bit32.rrotate(S7, 11), bit32.rrotate(S7, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S3, 2), bit32.rrotate(S3, 13), bit32.rrotate(S3, 22)), 0)
			BC = AB
		end
		do
			W14 = bit32.bor(bit32.bor(bit32.bor(W14 + W7, 0) + bit32.bxor(bit32.rrotate(W15, 7), bit32.rrotate(W15, 18), bit32.rshift(W15, 3)), 0) + bit32.bxor(bit32.rrotate(W12, 17), bit32.rrotate(W12, 19), bit32.rshift(W12, 10)), 0)
			local AB = bit32.bxor(S2, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x06ca6351, 0) + W14, 0) + bit32.bxor(S0, bit32.band(S6, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(S6, 6), bit32.rrotate(S6, 11), bit32.rrotate(S6, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S2, 2), bit32.rrotate(S2, 13), bit32.rrotate(S2, 22)), 0)
			BC = AB
		end
		do
			W15 = bit32.bor(bit32.bor(bit32.bor(W15 + W8, 0) + bit32.bxor(bit32.rrotate(W0, 7), bit32.rrotate(W0, 18), bit32.rshift(W0, 3)), 0) + bit32.bxor(bit32.rrotate(W13, 17), bit32.rrotate(W13, 19), bit32.rshift(W13, 10)), 0)
			local AB = bit32.bxor(S1, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x14292967, 0) + W15, 0) + bit32.bxor(S7, bit32.band(S5, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(S5, 6), bit32.rrotate(S5, 11), bit32.rrotate(S5, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S1, 2), bit32.rrotate(S1, 13), bit32.rrotate(S1, 22)), 0)
			BC = AB
		end
		do
			W0 = bit32.bor(bit32.bor(bit32.bor(W0 + W9, 0) + bit32.bxor(bit32.rrotate(W1, 7), bit32.rrotate(W1, 18), bit32.rshift(W1, 3)), 0) + bit32.bxor(bit32.rrotate(W14, 17), bit32.rrotate(W14, 19), bit32.rshift(W14, 10)), 0)
			local AB = bit32.bxor(S0, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0x27b70a85, 0) + W0, 0) + bit32.bxor(S6, bit32.band(S4, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(S4, 6), bit32.rrotate(S4, 11), bit32.rrotate(S4, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S0, 2), bit32.rrotate(S0, 13), bit32.rrotate(S0, 22)), 0)
			BC = AB
		end
		do
			W1 = bit32.bor(bit32.bor(bit32.bor(W1 + W10, 0) + bit32.bxor(bit32.rrotate(W2, 7), bit32.rrotate(W2, 18), bit32.rshift(W2, 3)), 0) + bit32.bxor(bit32.rrotate(W15, 17), bit32.rrotate(W15, 19), bit32.rshift(W15, 10)), 0)
			local AB = bit32.bxor(S7, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0x2e1b2138, 0) + W1, 0) + bit32.bxor(S5, bit32.band(S3, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(S3, 6), bit32.rrotate(S3, 11), bit32.rrotate(S3, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S7, 2), bit32.rrotate(S7, 13), bit32.rrotate(S7, 22)), 0)
			BC = AB
		end
		do
			W2 = bit32.bor(bit32.bor(bit32.bor(W2 + W11, 0) + bit32.bxor(bit32.rrotate(W3, 7), bit32.rrotate(W3, 18), bit32.rshift(W3, 3)), 0) + bit32.bxor(bit32.rrotate(W0, 17), bit32.rrotate(W0, 19), bit32.rshift(W0, 10)), 0)
			local AB = bit32.bxor(S6, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0x4d2c6dfc, 0) + W2, 0) + bit32.bxor(S4, bit32.band(S2, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(S2, 6), bit32.rrotate(S2, 11), bit32.rrotate(S2, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S6, 2), bit32.rrotate(S6, 13), bit32.rrotate(S6, 22)), 0)
			BC = AB
		end
		do
			W3 = bit32.bor(bit32.bor(bit32.bor(W3 + W12, 0) + bit32.bxor(bit32.rrotate(W4, 7), bit32.rrotate(W4, 18), bit32.rshift(W4, 3)), 0) + bit32.bxor(bit32.rrotate(W1, 17), bit32.rrotate(W1, 19), bit32.rshift(W1, 10)), 0)
			local AB = bit32.bxor(S5, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x53380d13, 0) + W3, 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(S1, 6), bit32.rrotate(S1, 11), bit32.rrotate(S1, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S5, 2), bit32.rrotate(S5, 13), bit32.rrotate(S5, 22)), 0)
			BC = AB
		end
		do
			W4 = bit32.bor(bit32.bor(bit32.bor(W4 + W13, 0) + bit32.bxor(bit32.rrotate(W5, 7), bit32.rrotate(W5, 18), bit32.rshift(W5, 3)), 0) + bit32.bxor(bit32.rrotate(W2, 17), bit32.rrotate(W2, 19), bit32.rshift(W2, 10)), 0)
			local AB = bit32.bxor(S4, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x650a7354, 0) + W4, 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(S0, 6), bit32.rrotate(S0, 11), bit32.rrotate(S0, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S4, 2), bit32.rrotate(S4, 13), bit32.rrotate(S4, 22)), 0)
			BC = AB
		end
		do
			W5 = bit32.bor(bit32.bor(bit32.bor(W5 + W14, 0) + bit32.bxor(bit32.rrotate(W6, 7), bit32.rrotate(W6, 18), bit32.rshift(W6, 3)), 0) + bit32.bxor(bit32.rrotate(W3, 17), bit32.rrotate(W3, 19), bit32.rshift(W3, 10)), 0)
			local AB = bit32.bxor(S3, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x766a0abb, 0) + W5, 0) + bit32.bxor(S1, bit32.band(S7, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(S7, 6), bit32.rrotate(S7, 11), bit32.rrotate(S7, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S3, 2), bit32.rrotate(S3, 13), bit32.rrotate(S3, 22)), 0)
			BC = AB
		end
		do
			W6 = bit32.bor(bit32.bor(bit32.bor(W6 + W15, 0) + bit32.bxor(bit32.rrotate(W7, 7), bit32.rrotate(W7, 18), bit32.rshift(W7, 3)), 0) + bit32.bxor(bit32.rrotate(W4, 17), bit32.rrotate(W4, 19), bit32.rshift(W4, 10)), 0)
			local AB = bit32.bxor(S2, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x81c2c92e, 0) + W6, 0) + bit32.bxor(S0, bit32.band(S6, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(S6, 6), bit32.rrotate(S6, 11), bit32.rrotate(S6, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S2, 2), bit32.rrotate(S2, 13), bit32.rrotate(S2, 22)), 0)
			BC = AB
		end
		do
			W7 = bit32.bor(bit32.bor(bit32.bor(W7 + W0, 0) + bit32.bxor(bit32.rrotate(W8, 7), bit32.rrotate(W8, 18), bit32.rshift(W8, 3)), 0) + bit32.bxor(bit32.rrotate(W5, 17), bit32.rrotate(W5, 19), bit32.rshift(W5, 10)), 0)
			local AB = bit32.bxor(S1, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x92722c85, 0) + W7, 0) + bit32.bxor(S7, bit32.band(S5, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(S5, 6), bit32.rrotate(S5, 11), bit32.rrotate(S5, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S1, 2), bit32.rrotate(S1, 13), bit32.rrotate(S1, 22)), 0)
			BC = AB
		end
		do
			W8 = bit32.bor(bit32.bor(bit32.bor(W8 + W1, 0) + bit32.bxor(bit32.rrotate(W9, 7), bit32.rrotate(W9, 18), bit32.rshift(W9, 3)), 0) + bit32.bxor(bit32.rrotate(W6, 17), bit32.rrotate(W6, 19), bit32.rshift(W6, 10)), 0)
			local AB = bit32.bxor(S0, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0xa2bfe8a1, 0) + W8, 0) + bit32.bxor(S6, bit32.band(S4, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(S4, 6), bit32.rrotate(S4, 11), bit32.rrotate(S4, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S0, 2), bit32.rrotate(S0, 13), bit32.rrotate(S0, 22)), 0)
			BC = AB
		end
		do
			W9 = bit32.bor(bit32.bor(bit32.bor(W9 + W2, 0) + bit32.bxor(bit32.rrotate(W10, 7), bit32.rrotate(W10, 18), bit32.rshift(W10, 3)), 0) + bit32.bxor(bit32.rrotate(W7, 17), bit32.rrotate(W7, 19), bit32.rshift(W7, 10)), 0)
			local AB = bit32.bxor(S7, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0xa81a664b, 0) + W9, 0) + bit32.bxor(S5, bit32.band(S3, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(S3, 6), bit32.rrotate(S3, 11), bit32.rrotate(S3, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S7, 2), bit32.rrotate(S7, 13), bit32.rrotate(S7, 22)), 0)
			BC = AB
		end
		do
			W10 = bit32.bor(bit32.bor(bit32.bor(W10 + W3, 0) + bit32.bxor(bit32.rrotate(W11, 7), bit32.rrotate(W11, 18), bit32.rshift(W11, 3)), 0) + bit32.bxor(bit32.rrotate(W8, 17), bit32.rrotate(W8, 19), bit32.rshift(W8, 10)), 0)
			local AB = bit32.bxor(S6, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0xc24b8b70, 0) + W10, 0) + bit32.bxor(S4, bit32.band(S2, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(S2, 6), bit32.rrotate(S2, 11), bit32.rrotate(S2, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S6, 2), bit32.rrotate(S6, 13), bit32.rrotate(S6, 22)), 0)
			BC = AB
		end
		do
			W11 = bit32.bor(bit32.bor(bit32.bor(W11 + W4, 0) + bit32.bxor(bit32.rrotate(W12, 7), bit32.rrotate(W12, 18), bit32.rshift(W12, 3)), 0) + bit32.bxor(bit32.rrotate(W9, 17), bit32.rrotate(W9, 19), bit32.rshift(W9, 10)), 0)
			local AB = bit32.bxor(S5, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0xc76c51a3, 0) + W11, 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(S1, 6), bit32.rrotate(S1, 11), bit32.rrotate(S1, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S5, 2), bit32.rrotate(S5, 13), bit32.rrotate(S5, 22)), 0)
			BC = AB
		end
		do
			W12 = bit32.bor(bit32.bor(bit32.bor(W12 + W5, 0) + bit32.bxor(bit32.rrotate(W13, 7), bit32.rrotate(W13, 18), bit32.rshift(W13, 3)), 0) + bit32.bxor(bit32.rrotate(W10, 17), bit32.rrotate(W10, 19), bit32.rshift(W10, 10)), 0)
			local AB = bit32.bxor(S4, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0xd192e819, 0) + W12, 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(S0, 6), bit32.rrotate(S0, 11), bit32.rrotate(S0, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S4, 2), bit32.rrotate(S4, 13), bit32.rrotate(S4, 22)), 0)
			BC = AB
		end
		do
			W13 = bit32.bor(bit32.bor(bit32.bor(W13 + W6, 0) + bit32.bxor(bit32.rrotate(W14, 7), bit32.rrotate(W14, 18), bit32.rshift(W14, 3)), 0) + bit32.bxor(bit32.rrotate(W11, 17), bit32.rrotate(W11, 19), bit32.rshift(W11, 10)), 0)
			local AB = bit32.bxor(S3, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0xd6990624, 0) + W13, 0) + bit32.bxor(S1, bit32.band(S7, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(S7, 6), bit32.rrotate(S7, 11), bit32.rrotate(S7, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S3, 2), bit32.rrotate(S3, 13), bit32.rrotate(S3, 22)), 0)
			BC = AB
		end
		do
			W14 = bit32.bor(bit32.bor(bit32.bor(W14 + W7, 0) + bit32.bxor(bit32.rrotate(W15, 7), bit32.rrotate(W15, 18), bit32.rshift(W15, 3)), 0) + bit32.bxor(bit32.rrotate(W12, 17), bit32.rrotate(W12, 19), bit32.rshift(W12, 10)), 0)
			local AB = bit32.bxor(S2, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0xf40e3585, 0) + W14, 0) + bit32.bxor(S0, bit32.band(S6, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(S6, 6), bit32.rrotate(S6, 11), bit32.rrotate(S6, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S2, 2), bit32.rrotate(S2, 13), bit32.rrotate(S2, 22)), 0)
			BC = AB
		end
		do
			W15 = bit32.bor(bit32.bor(bit32.bor(W15 + W8, 0) + bit32.bxor(bit32.rrotate(W0, 7), bit32.rrotate(W0, 18), bit32.rshift(W0, 3)), 0) + bit32.bxor(bit32.rrotate(W13, 17), bit32.rrotate(W13, 19), bit32.rshift(W13, 10)), 0)
			local AB = bit32.bxor(S1, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x106aa070, 0) + W15, 0) + bit32.bxor(S7, bit32.band(S5, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(S5, 6), bit32.rrotate(S5, 11), bit32.rrotate(S5, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S1, 2), bit32.rrotate(S1, 13), bit32.rrotate(S1, 22)), 0)
			BC = AB
		end
		do
			W0 = bit32.bor(bit32.bor(bit32.bor(W0 + W9, 0) + bit32.bxor(bit32.rrotate(W1, 7), bit32.rrotate(W1, 18), bit32.rshift(W1, 3)), 0) + bit32.bxor(bit32.rrotate(W14, 17), bit32.rrotate(W14, 19), bit32.rshift(W14, 10)), 0)
			local AB = bit32.bxor(S0, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0x19a4c116, 0) + W0, 0) + bit32.bxor(S6, bit32.band(S4, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(S4, 6), bit32.rrotate(S4, 11), bit32.rrotate(S4, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S0, 2), bit32.rrotate(S0, 13), bit32.rrotate(S0, 22)), 0)
			BC = AB
		end
		do
			W1 = bit32.bor(bit32.bor(bit32.bor(W1 + W10, 0) + bit32.bxor(bit32.rrotate(W2, 7), bit32.rrotate(W2, 18), bit32.rshift(W2, 3)), 0) + bit32.bxor(bit32.rrotate(W15, 17), bit32.rrotate(W15, 19), bit32.rshift(W15, 10)), 0)
			local AB = bit32.bxor(S7, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0x1e376c08, 0) + W1, 0) + bit32.bxor(S5, bit32.band(S3, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(S3, 6), bit32.rrotate(S3, 11), bit32.rrotate(S3, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S7, 2), bit32.rrotate(S7, 13), bit32.rrotate(S7, 22)), 0)
			BC = AB
		end
		do
			W2 = bit32.bor(bit32.bor(bit32.bor(W2 + W11, 0) + bit32.bxor(bit32.rrotate(W3, 7), bit32.rrotate(W3, 18), bit32.rshift(W3, 3)), 0) + bit32.bxor(bit32.rrotate(W0, 17), bit32.rrotate(W0, 19), bit32.rshift(W0, 10)), 0)
			local AB = bit32.bxor(S6, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0x2748774c, 0) + W2, 0) + bit32.bxor(S4, bit32.band(S2, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(S2, 6), bit32.rrotate(S2, 11), bit32.rrotate(S2, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S6, 2), bit32.rrotate(S6, 13), bit32.rrotate(S6, 22)), 0)
			BC = AB
		end
		do
			W3 = bit32.bor(bit32.bor(bit32.bor(W3 + W12, 0) + bit32.bxor(bit32.rrotate(W4, 7), bit32.rrotate(W4, 18), bit32.rshift(W4, 3)), 0) + bit32.bxor(bit32.rrotate(W1, 17), bit32.rrotate(W1, 19), bit32.rshift(W1, 10)), 0)
			local AB = bit32.bxor(S5, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x34b0bcb5, 0) + W3, 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(S1, 6), bit32.rrotate(S1, 11), bit32.rrotate(S1, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S5, 2), bit32.rrotate(S5, 13), bit32.rrotate(S5, 22)), 0)
			BC = AB
		end
		do
			W4 = bit32.bor(bit32.bor(bit32.bor(W4 + W13, 0) + bit32.bxor(bit32.rrotate(W5, 7), bit32.rrotate(W5, 18), bit32.rshift(W5, 3)), 0) + bit32.bxor(bit32.rrotate(W2, 17), bit32.rrotate(W2, 19), bit32.rshift(W2, 10)), 0)
			local AB = bit32.bxor(S4, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x391c0cb3, 0) + W4, 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(S0, 6), bit32.rrotate(S0, 11), bit32.rrotate(S0, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S4, 2), bit32.rrotate(S4, 13), bit32.rrotate(S4, 22)), 0)
			BC = AB
		end
		do
			W5 = bit32.bor(bit32.bor(bit32.bor(W5 + W14, 0) + bit32.bxor(bit32.rrotate(W6, 7), bit32.rrotate(W6, 18), bit32.rshift(W6, 3)), 0) + bit32.bxor(bit32.rrotate(W3, 17), bit32.rrotate(W3, 19), bit32.rshift(W3, 10)), 0)
			local AB = bit32.bxor(S3, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x4ed8aa4a, 0) + W5, 0) + bit32.bxor(S1, bit32.band(S7, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(S7, 6), bit32.rrotate(S7, 11), bit32.rrotate(S7, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S3, 2), bit32.rrotate(S3, 13), bit32.rrotate(S3, 22)), 0)
			BC = AB
		end
		do
			W6 = bit32.bor(bit32.bor(bit32.bor(W6 + W15, 0) + bit32.bxor(bit32.rrotate(W7, 7), bit32.rrotate(W7, 18), bit32.rshift(W7, 3)), 0) + bit32.bxor(bit32.rrotate(W4, 17), bit32.rrotate(W4, 19), bit32.rshift(W4, 10)), 0)
			local AB = bit32.bxor(S2, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x5b9cca4f, 0) + W6, 0) + bit32.bxor(S0, bit32.band(S6, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(S6, 6), bit32.rrotate(S6, 11), bit32.rrotate(S6, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S2, 2), bit32.rrotate(S2, 13), bit32.rrotate(S2, 22)), 0)
			BC = AB
		end
		do
			W7 = bit32.bor(bit32.bor(bit32.bor(W7 + W0, 0) + bit32.bxor(bit32.rrotate(W8, 7), bit32.rrotate(W8, 18), bit32.rshift(W8, 3)), 0) + bit32.bxor(bit32.rrotate(W5, 17), bit32.rrotate(W5, 19), bit32.rshift(W5, 10)), 0)
			local AB = bit32.bxor(S1, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x682e6ff3, 0) + W7, 0) + bit32.bxor(S7, bit32.band(S5, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(S5, 6), bit32.rrotate(S5, 11), bit32.rrotate(S5, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S1, 2), bit32.rrotate(S1, 13), bit32.rrotate(S1, 22)), 0)
			BC = AB
		end
		do
			W8 = bit32.bor(bit32.bor(bit32.bor(W8 + W1, 0) + bit32.bxor(bit32.rrotate(W9, 7), bit32.rrotate(W9, 18), bit32.rshift(W9, 3)), 0) + bit32.bxor(bit32.rrotate(W6, 17), bit32.rrotate(W6, 19), bit32.rshift(W6, 10)), 0)
			local AB = bit32.bxor(S0, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0x748f82ee, 0) + W8, 0) + bit32.bxor(S6, bit32.band(S4, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(S4, 6), bit32.rrotate(S4, 11), bit32.rrotate(S4, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S0, 2), bit32.rrotate(S0, 13), bit32.rrotate(S0, 22)), 0)
			BC = AB
		end
		do
			W9 = bit32.bor(bit32.bor(bit32.bor(W9 + W2, 0) + bit32.bxor(bit32.rrotate(W10, 7), bit32.rrotate(W10, 18), bit32.rshift(W10, 3)), 0) + bit32.bxor(bit32.rrotate(W7, 17), bit32.rrotate(W7, 19), bit32.rshift(W7, 10)), 0)
			local AB = bit32.bxor(S7, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0x78a5636f, 0) + W9, 0) + bit32.bxor(S5, bit32.band(S3, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(S3, 6), bit32.rrotate(S3, 11), bit32.rrotate(S3, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S7, 2), bit32.rrotate(S7, 13), bit32.rrotate(S7, 22)), 0)
			BC = AB
		end
		do
			W10 = bit32.bor(bit32.bor(bit32.bor(W10 + W3, 0) + bit32.bxor(bit32.rrotate(W11, 7), bit32.rrotate(W11, 18), bit32.rshift(W11, 3)), 0) + bit32.bxor(bit32.rrotate(W8, 17), bit32.rrotate(W8, 19), bit32.rshift(W8, 10)), 0)
			local AB = bit32.bxor(S6, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0x84c87814, 0) + W10, 0) + bit32.bxor(S4, bit32.band(S2, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(S2, 6), bit32.rrotate(S2, 11), bit32.rrotate(S2, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S6, 2), bit32.rrotate(S6, 13), bit32.rrotate(S6, 22)), 0)
			BC = AB
		end
		do
			W11 = bit32.bor(bit32.bor(bit32.bor(W11 + W4, 0) + bit32.bxor(bit32.rrotate(W12, 7), bit32.rrotate(W12, 18), bit32.rshift(W12, 3)), 0) + bit32.bxor(bit32.rrotate(W9, 17), bit32.rrotate(W9, 19), bit32.rshift(W9, 10)), 0)
			local AB = bit32.bxor(S5, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x8cc70208, 0) + W11, 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(S1, 6), bit32.rrotate(S1, 11), bit32.rrotate(S1, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S5, 2), bit32.rrotate(S5, 13), bit32.rrotate(S5, 22)), 0)
			BC = AB
		end
		do
			W12 = bit32.bor(bit32.bor(bit32.bor(W12 + W5, 0) + bit32.bxor(bit32.rrotate(W13, 7), bit32.rrotate(W13, 18), bit32.rshift(W13, 3)), 0) + bit32.bxor(bit32.rrotate(W10, 17), bit32.rrotate(W10, 19), bit32.rshift(W10, 10)), 0)
			local AB = bit32.bxor(S4, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x90befffa, 0) + W12, 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(S0, 6), bit32.rrotate(S0, 11), bit32.rrotate(S0, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S4, 2), bit32.rrotate(S4, 13), bit32.rrotate(S4, 22)), 0)
			BC = AB
		end
		do
			W13 = bit32.bor(bit32.bor(bit32.bor(W13 + W6, 0) + bit32.bxor(bit32.rrotate(W14, 7), bit32.rrotate(W14, 18), bit32.rshift(W14, 3)), 0) + bit32.bxor(bit32.rrotate(W11, 17), bit32.rrotate(W11, 19), bit32.rshift(W11, 10)), 0)
			local AB = bit32.bxor(S3, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0xa4506ceb, 0) + W13, 0) + bit32.bxor(S1, bit32.band(S7, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(S7, 6), bit32.rrotate(S7, 11), bit32.rrotate(S7, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S3, 2), bit32.rrotate(S3, 13), bit32.rrotate(S3, 22)), 0)
			BC = AB
		end
		do
			W14 = bit32.bor(bit32.bor(bit32.bor(W14 + W7, 0) + bit32.bxor(bit32.rrotate(W15, 7), bit32.rrotate(W15, 18), bit32.rshift(W15, 3)), 0) + bit32.bxor(bit32.rrotate(W12, 17), bit32.rrotate(W12, 19), bit32.rshift(W12, 10)), 0)
			local AB = bit32.bxor(S2, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0xbef9a3f7, 0) + W14, 0) + bit32.bxor(S0, bit32.band(S6, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(S6, 6), bit32.rrotate(S6, 11), bit32.rrotate(S6, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S2, 2), bit32.rrotate(S2, 13), bit32.rrotate(S2, 22)), 0)
			BC = AB
		end
		do
			W15 = bit32.bor(bit32.bor(bit32.bor(W15 + W8, 0) + bit32.bxor(bit32.rrotate(W0, 7), bit32.rrotate(W0, 18), bit32.rshift(W0, 3)), 0) + bit32.bxor(bit32.rrotate(W13, 17), bit32.rrotate(W13, 19), bit32.rshift(W13, 10)), 0)
			local AB = bit32.bxor(S1, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0xc67178f2, 0) + W15, 0) + bit32.bxor(S7, bit32.band(S5, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(S5, 6), bit32.rrotate(S5, 11), bit32.rrotate(S5, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(S1, 2), bit32.rrotate(S1, 13), bit32.rrotate(S1, 22)), 0)
			BC = AB
		end
		buffer.writeu32(State, 0, bit32.bor(buffer.readu32(State, 0) + S0, 0))
		buffer.writeu32(State, 4, bit32.bor(buffer.readu32(State, 4) + S1, 0))
		buffer.writeu32(State, 8, bit32.bor(buffer.readu32(State, 8) + S2, 0))
		buffer.writeu32(State, 12, bit32.bor(buffer.readu32(State, 12) + S3, 0))
		buffer.writeu32(State, 16, bit32.bor(buffer.readu32(State, 16) + S4, 0))
		buffer.writeu32(State, 20, bit32.bor(buffer.readu32(State, 20) + S5, 0))
		buffer.writeu32(State, 24, bit32.bor(buffer.readu32(State, 24) + S6, 0))
		buffer.writeu32(State, 28, bit32.bor(buffer.readu32(State, 28) + S7, 0))
	end
end

local function Digest(Message: buffer, InitialState: buffer, OutputBytes: number, PrefixBytes: number?): buffer
	local State: buffer = STATE
	buffer.writef64(State, 0, buffer.readf64(InitialState, 0)); buffer.writef64(State, 8, buffer.readf64(InitialState, 8))
	buffer.writef64(State, 16, buffer.readf64(InitialState, 16)); buffer.writef64(State, 24, buffer.readf64(InitialState, 24))

	local MessageLength = buffer.len(Message)
	local TailLength = MessageLength % 64
	local FullBytes = MessageLength - TailLength

	if FullBytes > 0 then
		Compress(Message, 0, FullBytes, State)
	end

	local Tail: buffer = TAIL
	buffer.writef64(Tail, 0, 0); buffer.writef64(Tail, 8, 0); buffer.writef64(Tail, 16, 0); buffer.writef64(Tail, 24, 0)
	buffer.writef64(Tail, 32, 0); buffer.writef64(Tail, 40, 0); buffer.writef64(Tail, 48, 0); buffer.writef64(Tail, 56, 0)
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
	if TailLength >= 56 then
		Compress(Tail, 0, 64, State)
		buffer.fill(Tail, 0, 0, 56)
	end
	buffer.writeu32(Tail, 56, bit32.byteswap(math.floor(BitLength * CARRY)))
	buffer.writeu32(Tail, 60, bit32.byteswap(BitLength))
	Compress(Tail, 0, 64, State)

	local Result = buffer.create(OutputBytes)
	if OutputBytes == 32 or OutputBytes == 28 then
		buffer.writeu32(Result, 0, bit32.byteswap(buffer.readu32(State, 0))); buffer.writeu32(Result, 4, bit32.byteswap(buffer.readu32(State, 4)))
		buffer.writeu32(Result, 8, bit32.byteswap(buffer.readu32(State, 8))); buffer.writeu32(Result, 12, bit32.byteswap(buffer.readu32(State, 12)))
		buffer.writeu32(Result, 16, bit32.byteswap(buffer.readu32(State, 16))); buffer.writeu32(Result, 20, bit32.byteswap(buffer.readu32(State, 20)))
		buffer.writeu32(Result, 24, bit32.byteswap(buffer.readu32(State, 24)))
		if OutputBytes == 32 then
			buffer.writeu32(Result, 28, bit32.byteswap(buffer.readu32(State, 28)))
		end
	else
		for Offset = 0, OutputBytes - 4, 4 do
			buffer.writeu32(Result, Offset, bit32.byteswap(buffer.readu32(State, Offset)))
		end
	end

	return Result
end

local function SHA256(Message: buffer): (string, buffer)
	local Result = Digest(Message, IV_256, 32)
	return ToHex(Result), Result
end

return {
	SHA256 = SHA256,
	Digest_Internal = Digest,
	Compress_Internal = Compress,
	IV_256 = IV_256,
	IV_224 = IV_224,
}
