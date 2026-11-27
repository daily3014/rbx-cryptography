--[=[
	Cryptography library: MD5

	⚠️ WARNING: MD5 is cryptographically broken!
	Only use for legacy compatibility, checksums, or non-security purposes.
	For security, use SHA256 or higher. ⚠️

	Return type: (string, buffer)
	Usage:
		local Message = buffer.fromstring("Hello World")
		local Hash, HashBuffer = MD5(Message)
--]=]

--!strict
--!optimize 2
--!native

local Conversions = require("../Utilities/Conversions")
local ToHex = Conversions.ToHex

local STATE: buffer = buffer.create(16)
local TAIL: buffer = buffer.create(128)

local function Compress(Blocks: buffer, Offset: number, Length: number, State: buffer): ()
	for Position = Offset, Offset + Length - 1, 64 do
		local S0 = buffer.readu32(State, 0)
		local S1 = buffer.readu32(State, 4)
		local S2 = buffer.readu32(State, 8)
		local S3 = buffer.readu32(State, 12)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0xd76aa478, 0) + buffer.readu32(Blocks, Position + 0), 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0), 7), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0xe8c7b756, 0) + buffer.readu32(Blocks, Position + 4), 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0), 12), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0x242070db, 0) + buffer.readu32(Blocks, Position + 8), 0) + bit32.bxor(S1, bit32.band(S3, bit32.bxor(S0, S1))), 0), 17), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0xc1bdceee, 0) + buffer.readu32(Blocks, Position + 12), 0) + bit32.bxor(S0, bit32.band(S2, bit32.bxor(S3, S0))), 0), 22), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0xf57c0faf, 0) + buffer.readu32(Blocks, Position + 16), 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0), 7), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0x4787c62a, 0) + buffer.readu32(Blocks, Position + 20), 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0), 12), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0xa8304613, 0) + buffer.readu32(Blocks, Position + 24), 0) + bit32.bxor(S1, bit32.band(S3, bit32.bxor(S0, S1))), 0), 17), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0xfd469501, 0) + buffer.readu32(Blocks, Position + 28), 0) + bit32.bxor(S0, bit32.band(S2, bit32.bxor(S3, S0))), 0), 22), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0x698098d8, 0) + buffer.readu32(Blocks, Position + 32), 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0), 7), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0x8b44f7af, 0) + buffer.readu32(Blocks, Position + 36), 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0), 12), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0xffff5bb1, 0) + buffer.readu32(Blocks, Position + 40), 0) + bit32.bxor(S1, bit32.band(S3, bit32.bxor(S0, S1))), 0), 17), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0x895cd7be, 0) + buffer.readu32(Blocks, Position + 44), 0) + bit32.bxor(S0, bit32.band(S2, bit32.bxor(S3, S0))), 0), 22), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0x6b901122, 0) + buffer.readu32(Blocks, Position + 48), 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0), 7), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0xfd987193, 0) + buffer.readu32(Blocks, Position + 52), 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0), 12), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0xa679438e, 0) + buffer.readu32(Blocks, Position + 56), 0) + bit32.bxor(S1, bit32.band(S3, bit32.bxor(S0, S1))), 0), 17), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0x49b40821, 0) + buffer.readu32(Blocks, Position + 60), 0) + bit32.bxor(S0, bit32.band(S2, bit32.bxor(S3, S0))), 0), 22), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0xf61e2562, 0) + buffer.readu32(Blocks, Position + 4), 0) + bit32.bor(bit32.band(S2, bit32.bnot(S3)), bit32.band(S1, S3)), 0), 5), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0xc040b340, 0) + buffer.readu32(Blocks, Position + 24), 0) + bit32.bor(bit32.band(S1, bit32.bnot(S2)), bit32.band(S0, S2)), 0), 9), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0x265e5a51, 0) + buffer.readu32(Blocks, Position + 44), 0) + bit32.bor(bit32.band(S0, bit32.bnot(S1)), bit32.band(S3, S1)), 0), 14), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0xe9b6c7aa, 0) + buffer.readu32(Blocks, Position + 0), 0) + bit32.bor(bit32.band(S3, bit32.bnot(S0)), bit32.band(S2, S0)), 0), 20), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0xd62f105d, 0) + buffer.readu32(Blocks, Position + 20), 0) + bit32.bor(bit32.band(S2, bit32.bnot(S3)), bit32.band(S1, S3)), 0), 5), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0x02441453, 0) + buffer.readu32(Blocks, Position + 40), 0) + bit32.bor(bit32.band(S1, bit32.bnot(S2)), bit32.band(S0, S2)), 0), 9), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0xd8a1e681, 0) + buffer.readu32(Blocks, Position + 60), 0) + bit32.bor(bit32.band(S0, bit32.bnot(S1)), bit32.band(S3, S1)), 0), 14), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0xe7d3fbc8, 0) + buffer.readu32(Blocks, Position + 16), 0) + bit32.bor(bit32.band(S3, bit32.bnot(S0)), bit32.band(S2, S0)), 0), 20), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0x21e1cde6, 0) + buffer.readu32(Blocks, Position + 36), 0) + bit32.bor(bit32.band(S2, bit32.bnot(S3)), bit32.band(S1, S3)), 0), 5), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0xc33707d6, 0) + buffer.readu32(Blocks, Position + 56), 0) + bit32.bor(bit32.band(S1, bit32.bnot(S2)), bit32.band(S0, S2)), 0), 9), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0xf4d50d87, 0) + buffer.readu32(Blocks, Position + 12), 0) + bit32.bor(bit32.band(S0, bit32.bnot(S1)), bit32.band(S3, S1)), 0), 14), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0x455a14ed, 0) + buffer.readu32(Blocks, Position + 32), 0) + bit32.bor(bit32.band(S3, bit32.bnot(S0)), bit32.band(S2, S0)), 0), 20), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0xa9e3e905, 0) + buffer.readu32(Blocks, Position + 52), 0) + bit32.bor(bit32.band(S2, bit32.bnot(S3)), bit32.band(S1, S3)), 0), 5), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0xfcefa3f8, 0) + buffer.readu32(Blocks, Position + 8), 0) + bit32.bor(bit32.band(S1, bit32.bnot(S2)), bit32.band(S0, S2)), 0), 9), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0x676f02d9, 0) + buffer.readu32(Blocks, Position + 28), 0) + bit32.bor(bit32.band(S0, bit32.bnot(S1)), bit32.band(S3, S1)), 0), 14), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0x8d2a4c8a, 0) + buffer.readu32(Blocks, Position + 48), 0) + bit32.bor(bit32.band(S3, bit32.bnot(S0)), bit32.band(S2, S0)), 0), 20), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0xfffa3942, 0) + buffer.readu32(Blocks, Position + 20), 0) + bit32.bxor(S2, S3, S1), 0), 4), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0x8771f681, 0) + buffer.readu32(Blocks, Position + 32), 0) + bit32.bxor(S1, S2, S0), 0), 11), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0x6d9d6122, 0) + buffer.readu32(Blocks, Position + 44), 0) + bit32.bxor(S0, S1, S3), 0), 16), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0xfde5380c, 0) + buffer.readu32(Blocks, Position + 56), 0) + bit32.bxor(S3, S0, S2), 0), 23), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0xa4beea44, 0) + buffer.readu32(Blocks, Position + 4), 0) + bit32.bxor(S2, S3, S1), 0), 4), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0x4bdecfa9, 0) + buffer.readu32(Blocks, Position + 16), 0) + bit32.bxor(S1, S2, S0), 0), 11), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0xf6bb4b60, 0) + buffer.readu32(Blocks, Position + 28), 0) + bit32.bxor(S0, S1, S3), 0), 16), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0xbebfbc70, 0) + buffer.readu32(Blocks, Position + 40), 0) + bit32.bxor(S3, S0, S2), 0), 23), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0x289b7ec6, 0) + buffer.readu32(Blocks, Position + 52), 0) + bit32.bxor(S2, S3, S1), 0), 4), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0xeaa127fa, 0) + buffer.readu32(Blocks, Position + 0), 0) + bit32.bxor(S1, S2, S0), 0), 11), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0xd4ef3085, 0) + buffer.readu32(Blocks, Position + 12), 0) + bit32.bxor(S0, S1, S3), 0), 16), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0x04881d05, 0) + buffer.readu32(Blocks, Position + 24), 0) + bit32.bxor(S3, S0, S2), 0), 23), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0xd9d4d039, 0) + buffer.readu32(Blocks, Position + 36), 0) + bit32.bxor(S2, S3, S1), 0), 4), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0xe6db99e5, 0) + buffer.readu32(Blocks, Position + 48), 0) + bit32.bxor(S1, S2, S0), 0), 11), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0x1fa27cf8, 0) + buffer.readu32(Blocks, Position + 60), 0) + bit32.bxor(S0, S1, S3), 0), 16), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0xc4ac5665, 0) + buffer.readu32(Blocks, Position + 8), 0) + bit32.bxor(S3, S0, S2), 0), 23), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0xf4292244, 0) + buffer.readu32(Blocks, Position + 0), 0) + bit32.bxor(S2, bit32.bor(S1, bit32.bnot(S3))), 0), 6), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0x432aff97, 0) + buffer.readu32(Blocks, Position + 28), 0) + bit32.bxor(S1, bit32.bor(S0, bit32.bnot(S2))), 0), 10), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0xab9423a7, 0) + buffer.readu32(Blocks, Position + 56), 0) + bit32.bxor(S0, bit32.bor(S3, bit32.bnot(S1))), 0), 15), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0xfc93a039, 0) + buffer.readu32(Blocks, Position + 20), 0) + bit32.bxor(S3, bit32.bor(S2, bit32.bnot(S0))), 0), 21), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0x655b59c3, 0) + buffer.readu32(Blocks, Position + 48), 0) + bit32.bxor(S2, bit32.bor(S1, bit32.bnot(S3))), 0), 6), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0x8f0ccc92, 0) + buffer.readu32(Blocks, Position + 12), 0) + bit32.bxor(S1, bit32.bor(S0, bit32.bnot(S2))), 0), 10), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0xffeff47d, 0) + buffer.readu32(Blocks, Position + 40), 0) + bit32.bxor(S0, bit32.bor(S3, bit32.bnot(S1))), 0), 15), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0x85845dd1, 0) + buffer.readu32(Blocks, Position + 4), 0) + bit32.bxor(S3, bit32.bor(S2, bit32.bnot(S0))), 0), 21), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0x6fa87e4f, 0) + buffer.readu32(Blocks, Position + 32), 0) + bit32.bxor(S2, bit32.bor(S1, bit32.bnot(S3))), 0), 6), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0xfe2ce6e0, 0) + buffer.readu32(Blocks, Position + 60), 0) + bit32.bxor(S1, bit32.bor(S0, bit32.bnot(S2))), 0), 10), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0xa3014314, 0) + buffer.readu32(Blocks, Position + 24), 0) + bit32.bxor(S0, bit32.bor(S3, bit32.bnot(S1))), 0), 15), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0x4e0811a1, 0) + buffer.readu32(Blocks, Position + 52), 0) + bit32.bxor(S3, bit32.bor(S2, bit32.bnot(S0))), 0), 21), 0)
		S0 = bit32.bor(S1 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S0 + 0xf7537e82, 0) + buffer.readu32(Blocks, Position + 16), 0) + bit32.bxor(S2, bit32.bor(S1, bit32.bnot(S3))), 0), 6), 0)
		S3 = bit32.bor(S0 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S3 + 0xbd3af235, 0) + buffer.readu32(Blocks, Position + 44), 0) + bit32.bxor(S1, bit32.bor(S0, bit32.bnot(S2))), 0), 10), 0)
		S2 = bit32.bor(S3 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S2 + 0x2ad7d2bb, 0) + buffer.readu32(Blocks, Position + 8), 0) + bit32.bxor(S0, bit32.bor(S3, bit32.bnot(S1))), 0), 15), 0)
		S1 = bit32.bor(S2 + bit32.lrotate(bit32.bor(bit32.bor(bit32.bor(S1 + 0xeb86d391, 0) + buffer.readu32(Blocks, Position + 36), 0) + bit32.bxor(S3, bit32.bor(S2, bit32.bnot(S0))), 0), 21), 0)
		buffer.writeu32(State, 0, bit32.bor(buffer.readu32(State, 0) + S0, 0))
		buffer.writeu32(State, 4, bit32.bor(buffer.readu32(State, 4) + S1, 0))
		buffer.writeu32(State, 8, bit32.bor(buffer.readu32(State, 8) + S2, 0))
		buffer.writeu32(State, 12, bit32.bor(buffer.readu32(State, 12) + S3, 0))
	end
end

local function ClearBlock64(Tail: buffer, Offset: number): ()
	buffer.writef64(Tail, Offset, 0)
	buffer.writef64(Tail, Offset + 8, 0)
	buffer.writef64(Tail, Offset + 16, 0)
	buffer.writef64(Tail, Offset + 24, 0)
	buffer.writef64(Tail, Offset + 32, 0)
	buffer.writef64(Tail, Offset + 40, 0)
	buffer.writef64(Tail, Offset + 48, 0)
	buffer.writef64(Tail, Offset + 56, 0)
end

local function FeedSalted(Message: buffer, MessageLength: number, Salt: buffer, SaltLength: number, State: buffer, Tail: buffer): number
	local MsgTail = bit32.band(MessageLength, 63)
	local MsgFull = MessageLength - MsgTail
	if MsgFull > 0 then
		Compress(Message, 0, MsgFull, State)
	end

	if MsgTail == 0 then
		local SaltTail = bit32.band(SaltLength, 63)
		local SaltFull = SaltLength - SaltTail
		if SaltFull > 0 then
			Compress(Salt, 0, SaltFull, State)
		end
		ClearBlock64(Tail, 0)
		if SaltTail >= 56 then
			ClearBlock64(Tail, 64)
		end
		if SaltTail > 0 then
			buffer.copy(Tail, 0, Salt, SaltFull, SaltTail)
		end
		return SaltTail
	elseif MsgTail + SaltLength < 64 then
		local TotalTail = MsgTail + SaltLength
		ClearBlock64(Tail, 0)
		if TotalTail >= 56 then
			ClearBlock64(Tail, 64)
		end
		buffer.copy(Tail, 0, Message, MsgFull, MsgTail)
		buffer.copy(Tail, MsgTail, Salt, 0, SaltLength)
		return TotalTail
	else
		local Need = 64 - MsgTail
		buffer.copy(Tail, 0, Message, MsgFull, MsgTail)
		buffer.copy(Tail, MsgTail, Salt, 0, Need)
		Compress(Tail, 0, 64, State)
		local SaltRemaining = SaltLength - Need
		local SaltTail = bit32.band(SaltRemaining, 63)
		local SaltFull = SaltRemaining - SaltTail
		if SaltFull > 0 then
			Compress(Salt, Need, SaltFull, State)
		end
		ClearBlock64(Tail, 0)
		if SaltTail >= 56 then
			ClearBlock64(Tail, 64)
		end
		if SaltTail > 0 then
			buffer.copy(Tail, 0, Salt, Need + SaltFull, SaltTail)
		end
		return SaltTail
	end
end

local function MD5(Message: buffer, Salt: buffer?): (string, buffer)
	local State = STATE
	buffer.writeu32(State, 0, 0x67452301)
	buffer.writeu32(State, 4, 0xefcdab89)
	buffer.writeu32(State, 8, 0x98badcfe)
	buffer.writeu32(State, 12, 0x10325476)

	local MessageLength = buffer.len(Message)
	local SaltLength = if Salt then buffer.len(Salt) else 0
	local Tail = TAIL
	local TailLength: number

	if Salt and SaltLength > 0 then
		TailLength = FeedSalted(Message, MessageLength, Salt, SaltLength, State, Tail)
	else
		TailLength = bit32.band(MessageLength, 63)
		local FullBytes = MessageLength - TailLength
		if FullBytes > 0 then
			Compress(Message, 0, FullBytes, State)
		end
		ClearBlock64(Tail, 0)
		if TailLength >= 56 then
			ClearBlock64(Tail, 64)
		end
		if TailLength > 0 then
			buffer.copy(Tail, 0, Message, FullBytes, TailLength)
		end
	end

	local TailBytes = if TailLength < 56 then 64 else 128
	buffer.writeu8(Tail, TailLength, 0x80)

	local BitLength = (MessageLength + SaltLength) * 8
	buffer.writeu32(Tail, TailBytes - 8, BitLength)
	buffer.writeu32(Tail, TailBytes - 4, math.floor(BitLength * 2 ^ -32))
	Compress(Tail, 0, TailBytes, State)

	local Result = buffer.create(16)
	buffer.writef64(Result, 0, buffer.readf64(State, 0))
	buffer.writef64(Result, 8, buffer.readf64(State, 8))

	return ToHex(Result), Result
end

return MD5
