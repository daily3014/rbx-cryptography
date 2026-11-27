--[=[
	Cryptography library: SHA1

	⚠️ WARNING: SHA1 is cryptographically broken!
	Only use for legacy compatibility, checksums, or non-security purposes.
	For security, use SHA256 or higher. ⚠️

	Sizes:
		Digest: 20 bytes

	Return type: (string, buffer)
	Example usage:
		local Message = buffer.fromstring("Hello World")

		--------Usage Case 1--------
		local Hash, HashBuffer = SHA1(Message)

		--------Usage Case 2--------
		local OptionalSalt = buffer.fromstring("Salty")
		local Hash, HashBuffer = SHA1(Message, OptionalSalt)
--]=]

--!strict
--!optimize 2
--!native

local Conversions = require("../Utilities/Conversions")
local ToHex = Conversions.ToHex

local STATE: buffer = buffer.create(20)
local TAIL: buffer = buffer.create(128)

local function Compress(Blocks: buffer, Offset: number, Length: number, State: buffer): ()
	for Position = Offset, Offset + Length - 1, 64 do
		local S0 = buffer.readu32(State, 0)
		local S1 = buffer.readu32(State, 4)
		local S2 = buffer.readu32(State, 8)
		local S3 = buffer.readu32(State, 12)
		local S4 = buffer.readu32(State, 16)
		local W0 = bit32.byteswap(buffer.readu32(Blocks, Position + 0))
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x5a827999, 0) + W0, 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		local W1 = bit32.byteswap(buffer.readu32(Blocks, Position + 4))
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x5a827999, 0) + W1, 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		local W2 = bit32.byteswap(buffer.readu32(Blocks, Position + 8))
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x5a827999, 0) + W2, 0) + bit32.bxor(S1, bit32.band(S4, bit32.bxor(S0, S1))), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		local W3 = bit32.byteswap(buffer.readu32(Blocks, Position + 12))
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x5a827999, 0) + W3, 0) + bit32.bxor(S0, bit32.band(S3, bit32.bxor(S4, S0))), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		local W4 = bit32.byteswap(buffer.readu32(Blocks, Position + 16))
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x5a827999, 0) + W4, 0) + bit32.bxor(S4, bit32.band(S2, bit32.bxor(S3, S4))), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		local W5 = bit32.byteswap(buffer.readu32(Blocks, Position + 20))
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x5a827999, 0) + W5, 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		local W6 = bit32.byteswap(buffer.readu32(Blocks, Position + 24))
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x5a827999, 0) + W6, 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		local W7 = bit32.byteswap(buffer.readu32(Blocks, Position + 28))
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x5a827999, 0) + W7, 0) + bit32.bxor(S1, bit32.band(S4, bit32.bxor(S0, S1))), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		local W8 = bit32.byteswap(buffer.readu32(Blocks, Position + 32))
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x5a827999, 0) + W8, 0) + bit32.bxor(S0, bit32.band(S3, bit32.bxor(S4, S0))), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		local W9 = bit32.byteswap(buffer.readu32(Blocks, Position + 36))
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x5a827999, 0) + W9, 0) + bit32.bxor(S4, bit32.band(S2, bit32.bxor(S3, S4))), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		local W10 = bit32.byteswap(buffer.readu32(Blocks, Position + 40))
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x5a827999, 0) + W10, 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		local W11 = bit32.byteswap(buffer.readu32(Blocks, Position + 44))
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x5a827999, 0) + W11, 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		local W12 = bit32.byteswap(buffer.readu32(Blocks, Position + 48))
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x5a827999, 0) + W12, 0) + bit32.bxor(S1, bit32.band(S4, bit32.bxor(S0, S1))), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		local W13 = bit32.byteswap(buffer.readu32(Blocks, Position + 52))
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x5a827999, 0) + W13, 0) + bit32.bxor(S0, bit32.band(S3, bit32.bxor(S4, S0))), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		local W14 = bit32.byteswap(buffer.readu32(Blocks, Position + 56))
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x5a827999, 0) + W14, 0) + bit32.bxor(S4, bit32.band(S2, bit32.bxor(S3, S4))), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		local W15 = bit32.byteswap(buffer.readu32(Blocks, Position + 60))
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x5a827999, 0) + W15, 0) + bit32.bxor(S3, bit32.band(S1, bit32.bxor(S2, S3))), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		W0 = bit32.lrotate(bit32.bxor(W13, W8, W2, W0), 1)
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x5a827999, 0) + W0, 0) + bit32.bxor(S2, bit32.band(S0, bit32.bxor(S1, S2))), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		W1 = bit32.lrotate(bit32.bxor(W14, W9, W3, W1), 1)
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x5a827999, 0) + W1, 0) + bit32.bxor(S1, bit32.band(S4, bit32.bxor(S0, S1))), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		W2 = bit32.lrotate(bit32.bxor(W15, W10, W4, W2), 1)
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x5a827999, 0) + W2, 0) + bit32.bxor(S0, bit32.band(S3, bit32.bxor(S4, S0))), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		W3 = bit32.lrotate(bit32.bxor(W0, W11, W5, W3), 1)
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x5a827999, 0) + W3, 0) + bit32.bxor(S4, bit32.band(S2, bit32.bxor(S3, S4))), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		W4 = bit32.lrotate(bit32.bxor(W1, W12, W6, W4), 1)
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x6ed9eba1, 0) + W4, 0) + bit32.bxor(S1, S2, S3), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		W5 = bit32.lrotate(bit32.bxor(W2, W13, W7, W5), 1)
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x6ed9eba1, 0) + W5, 0) + bit32.bxor(S0, S1, S2), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		W6 = bit32.lrotate(bit32.bxor(W3, W14, W8, W6), 1)
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x6ed9eba1, 0) + W6, 0) + bit32.bxor(S4, S0, S1), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		W7 = bit32.lrotate(bit32.bxor(W4, W15, W9, W7), 1)
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x6ed9eba1, 0) + W7, 0) + bit32.bxor(S3, S4, S0), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		W8 = bit32.lrotate(bit32.bxor(W5, W0, W10, W8), 1)
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x6ed9eba1, 0) + W8, 0) + bit32.bxor(S2, S3, S4), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		W9 = bit32.lrotate(bit32.bxor(W6, W1, W11, W9), 1)
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x6ed9eba1, 0) + W9, 0) + bit32.bxor(S1, S2, S3), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		W10 = bit32.lrotate(bit32.bxor(W7, W2, W12, W10), 1)
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x6ed9eba1, 0) + W10, 0) + bit32.bxor(S0, S1, S2), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		W11 = bit32.lrotate(bit32.bxor(W8, W3, W13, W11), 1)
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x6ed9eba1, 0) + W11, 0) + bit32.bxor(S4, S0, S1), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		W12 = bit32.lrotate(bit32.bxor(W9, W4, W14, W12), 1)
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x6ed9eba1, 0) + W12, 0) + bit32.bxor(S3, S4, S0), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		W13 = bit32.lrotate(bit32.bxor(W10, W5, W15, W13), 1)
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x6ed9eba1, 0) + W13, 0) + bit32.bxor(S2, S3, S4), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		W14 = bit32.lrotate(bit32.bxor(W11, W6, W0, W14), 1)
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x6ed9eba1, 0) + W14, 0) + bit32.bxor(S1, S2, S3), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		W15 = bit32.lrotate(bit32.bxor(W12, W7, W1, W15), 1)
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x6ed9eba1, 0) + W15, 0) + bit32.bxor(S0, S1, S2), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		W0 = bit32.lrotate(bit32.bxor(W13, W8, W2, W0), 1)
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x6ed9eba1, 0) + W0, 0) + bit32.bxor(S4, S0, S1), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		W1 = bit32.lrotate(bit32.bxor(W14, W9, W3, W1), 1)
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x6ed9eba1, 0) + W1, 0) + bit32.bxor(S3, S4, S0), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		W2 = bit32.lrotate(bit32.bxor(W15, W10, W4, W2), 1)
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x6ed9eba1, 0) + W2, 0) + bit32.bxor(S2, S3, S4), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		W3 = bit32.lrotate(bit32.bxor(W0, W11, W5, W3), 1)
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x6ed9eba1, 0) + W3, 0) + bit32.bxor(S1, S2, S3), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		W4 = bit32.lrotate(bit32.bxor(W1, W12, W6, W4), 1)
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x6ed9eba1, 0) + W4, 0) + bit32.bxor(S0, S1, S2), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		W5 = bit32.lrotate(bit32.bxor(W2, W13, W7, W5), 1)
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x6ed9eba1, 0) + W5, 0) + bit32.bxor(S4, S0, S1), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		W6 = bit32.lrotate(bit32.bxor(W3, W14, W8, W6), 1)
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x6ed9eba1, 0) + W6, 0) + bit32.bxor(S3, S4, S0), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		W7 = bit32.lrotate(bit32.bxor(W4, W15, W9, W7), 1)
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x6ed9eba1, 0) + W7, 0) + bit32.bxor(S2, S3, S4), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		W8 = bit32.lrotate(bit32.bxor(W5, W0, W10, W8), 1)
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x8f1bbcdc, 0) + W8, 0) + bit32.bor(bit32.band(S1, S2), bit32.band(S3, bit32.bor(S1, S2))), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		W9 = bit32.lrotate(bit32.bxor(W6, W1, W11, W9), 1)
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x8f1bbcdc, 0) + W9, 0) + bit32.bor(bit32.band(S0, S1), bit32.band(S2, bit32.bor(S0, S1))), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		W10 = bit32.lrotate(bit32.bxor(W7, W2, W12, W10), 1)
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x8f1bbcdc, 0) + W10, 0) + bit32.bor(bit32.band(S4, S0), bit32.band(S1, bit32.bor(S4, S0))), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		W11 = bit32.lrotate(bit32.bxor(W8, W3, W13, W11), 1)
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x8f1bbcdc, 0) + W11, 0) + bit32.bor(bit32.band(S3, S4), bit32.band(S0, bit32.bor(S3, S4))), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		W12 = bit32.lrotate(bit32.bxor(W9, W4, W14, W12), 1)
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x8f1bbcdc, 0) + W12, 0) + bit32.bor(bit32.band(S2, S3), bit32.band(S4, bit32.bor(S2, S3))), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		W13 = bit32.lrotate(bit32.bxor(W10, W5, W15, W13), 1)
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x8f1bbcdc, 0) + W13, 0) + bit32.bor(bit32.band(S1, S2), bit32.band(S3, bit32.bor(S1, S2))), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		W14 = bit32.lrotate(bit32.bxor(W11, W6, W0, W14), 1)
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x8f1bbcdc, 0) + W14, 0) + bit32.bor(bit32.band(S0, S1), bit32.band(S2, bit32.bor(S0, S1))), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		W15 = bit32.lrotate(bit32.bxor(W12, W7, W1, W15), 1)
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x8f1bbcdc, 0) + W15, 0) + bit32.bor(bit32.band(S4, S0), bit32.band(S1, bit32.bor(S4, S0))), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		W0 = bit32.lrotate(bit32.bxor(W13, W8, W2, W0), 1)
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x8f1bbcdc, 0) + W0, 0) + bit32.bor(bit32.band(S3, S4), bit32.band(S0, bit32.bor(S3, S4))), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		W1 = bit32.lrotate(bit32.bxor(W14, W9, W3, W1), 1)
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x8f1bbcdc, 0) + W1, 0) + bit32.bor(bit32.band(S2, S3), bit32.band(S4, bit32.bor(S2, S3))), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		W2 = bit32.lrotate(bit32.bxor(W15, W10, W4, W2), 1)
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x8f1bbcdc, 0) + W2, 0) + bit32.bor(bit32.band(S1, S2), bit32.band(S3, bit32.bor(S1, S2))), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		W3 = bit32.lrotate(bit32.bxor(W0, W11, W5, W3), 1)
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x8f1bbcdc, 0) + W3, 0) + bit32.bor(bit32.band(S0, S1), bit32.band(S2, bit32.bor(S0, S1))), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		W4 = bit32.lrotate(bit32.bxor(W1, W12, W6, W4), 1)
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x8f1bbcdc, 0) + W4, 0) + bit32.bor(bit32.band(S4, S0), bit32.band(S1, bit32.bor(S4, S0))), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		W5 = bit32.lrotate(bit32.bxor(W2, W13, W7, W5), 1)
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x8f1bbcdc, 0) + W5, 0) + bit32.bor(bit32.band(S3, S4), bit32.band(S0, bit32.bor(S3, S4))), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		W6 = bit32.lrotate(bit32.bxor(W3, W14, W8, W6), 1)
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x8f1bbcdc, 0) + W6, 0) + bit32.bor(bit32.band(S2, S3), bit32.band(S4, bit32.bor(S2, S3))), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		W7 = bit32.lrotate(bit32.bxor(W4, W15, W9, W7), 1)
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x8f1bbcdc, 0) + W7, 0) + bit32.bor(bit32.band(S1, S2), bit32.band(S3, bit32.bor(S1, S2))), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		W8 = bit32.lrotate(bit32.bxor(W5, W0, W10, W8), 1)
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x8f1bbcdc, 0) + W8, 0) + bit32.bor(bit32.band(S0, S1), bit32.band(S2, bit32.bor(S0, S1))), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		W9 = bit32.lrotate(bit32.bxor(W6, W1, W11, W9), 1)
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x8f1bbcdc, 0) + W9, 0) + bit32.bor(bit32.band(S4, S0), bit32.band(S1, bit32.bor(S4, S0))), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		W10 = bit32.lrotate(bit32.bxor(W7, W2, W12, W10), 1)
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x8f1bbcdc, 0) + W10, 0) + bit32.bor(bit32.band(S3, S4), bit32.band(S0, bit32.bor(S3, S4))), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		W11 = bit32.lrotate(bit32.bxor(W8, W3, W13, W11), 1)
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x8f1bbcdc, 0) + W11, 0) + bit32.bor(bit32.band(S2, S3), bit32.band(S4, bit32.bor(S2, S3))), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		W12 = bit32.lrotate(bit32.bxor(W9, W4, W14, W12), 1)
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0xca62c1d6, 0) + W12, 0) + bit32.bxor(S1, S2, S3), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		W13 = bit32.lrotate(bit32.bxor(W10, W5, W15, W13), 1)
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0xca62c1d6, 0) + W13, 0) + bit32.bxor(S0, S1, S2), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		W14 = bit32.lrotate(bit32.bxor(W11, W6, W0, W14), 1)
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0xca62c1d6, 0) + W14, 0) + bit32.bxor(S4, S0, S1), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		W15 = bit32.lrotate(bit32.bxor(W12, W7, W1, W15), 1)
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0xca62c1d6, 0) + W15, 0) + bit32.bxor(S3, S4, S0), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		W0 = bit32.lrotate(bit32.bxor(W13, W8, W2, W0), 1)
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0xca62c1d6, 0) + W0, 0) + bit32.bxor(S2, S3, S4), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		W1 = bit32.lrotate(bit32.bxor(W14, W9, W3, W1), 1)
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0xca62c1d6, 0) + W1, 0) + bit32.bxor(S1, S2, S3), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		W2 = bit32.lrotate(bit32.bxor(W15, W10, W4, W2), 1)
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0xca62c1d6, 0) + W2, 0) + bit32.bxor(S0, S1, S2), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		W3 = bit32.lrotate(bit32.bxor(W0, W11, W5, W3), 1)
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0xca62c1d6, 0) + W3, 0) + bit32.bxor(S4, S0, S1), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		W4 = bit32.lrotate(bit32.bxor(W1, W12, W6, W4), 1)
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0xca62c1d6, 0) + W4, 0) + bit32.bxor(S3, S4, S0), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		W5 = bit32.lrotate(bit32.bxor(W2, W13, W7, W5), 1)
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0xca62c1d6, 0) + W5, 0) + bit32.bxor(S2, S3, S4), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		W6 = bit32.lrotate(bit32.bxor(W3, W14, W8, W6), 1)
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0xca62c1d6, 0) + W6, 0) + bit32.bxor(S1, S2, S3), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		W7 = bit32.lrotate(bit32.bxor(W4, W15, W9, W7), 1)
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0xca62c1d6, 0) + W7, 0) + bit32.bxor(S0, S1, S2), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		W8 = bit32.lrotate(bit32.bxor(W5, W0, W10, W8), 1)
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0xca62c1d6, 0) + W8, 0) + bit32.bxor(S4, S0, S1), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		W9 = bit32.lrotate(bit32.bxor(W6, W1, W11, W9), 1)
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0xca62c1d6, 0) + W9, 0) + bit32.bxor(S3, S4, S0), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		W10 = bit32.lrotate(bit32.bxor(W7, W2, W12, W10), 1)
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0xca62c1d6, 0) + W10, 0) + bit32.bxor(S2, S3, S4), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		W11 = bit32.lrotate(bit32.bxor(W8, W3, W13, W11), 1)
		S4 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0xca62c1d6, 0) + W11, 0) + bit32.bxor(S1, S2, S3), 0) + bit32.lrotate(S0, 5), 0)
		S1 = bit32.lrotate(S1, 30)
		W12 = bit32.lrotate(bit32.bxor(W9, W4, W14, W12), 1)
		S3 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0xca62c1d6, 0) + W12, 0) + bit32.bxor(S0, S1, S2), 0) + bit32.lrotate(S4, 5), 0)
		S0 = bit32.lrotate(S0, 30)
		W13 = bit32.lrotate(bit32.bxor(W10, W5, W15, W13), 1)
		S2 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0xca62c1d6, 0) + W13, 0) + bit32.bxor(S4, S0, S1), 0) + bit32.lrotate(S3, 5), 0)
		S4 = bit32.lrotate(S4, 30)
		W14 = bit32.lrotate(bit32.bxor(W11, W6, W0, W14), 1)
		S1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0xca62c1d6, 0) + W14, 0) + bit32.bxor(S3, S4, S0), 0) + bit32.lrotate(S2, 5), 0)
		S3 = bit32.lrotate(S3, 30)
		W15 = bit32.lrotate(bit32.bxor(W12, W7, W1, W15), 1)
		S0 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0xca62c1d6, 0) + W15, 0) + bit32.bxor(S2, S3, S4), 0) + bit32.lrotate(S1, 5), 0)
		S2 = bit32.lrotate(S2, 30)
		buffer.writeu32(State, 0, bit32.bor(buffer.readu32(State, 0) + S0, 0))
		buffer.writeu32(State, 4, bit32.bor(buffer.readu32(State, 4) + S1, 0))
		buffer.writeu32(State, 8, bit32.bor(buffer.readu32(State, 8) + S2, 0))
		buffer.writeu32(State, 12, bit32.bor(buffer.readu32(State, 12) + S3, 0))
		buffer.writeu32(State, 16, bit32.bor(buffer.readu32(State, 16) + S4, 0))
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

local function SHA1(Message: buffer, Salt: buffer?): (string, buffer)
	local State = STATE
	buffer.writeu32(State, 0, 0x67452301)
	buffer.writeu32(State, 4, 0xefcdab89)
	buffer.writeu32(State, 8, 0x98badcfe)
	buffer.writeu32(State, 12, 0x10325476)
	buffer.writeu32(State, 16, 0xc3d2e1f0)

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
	buffer.writeu32(Tail, TailBytes - 8, bit32.byteswap(math.floor(BitLength * 2 ^ -32)))
	buffer.writeu32(Tail, TailBytes - 4, bit32.byteswap(BitLength))
	Compress(Tail, 0, TailBytes, State)

	local Result = buffer.create(20)
	buffer.writeu32(Result, 0, bit32.byteswap(buffer.readu32(State, 0)))
	buffer.writeu32(Result, 4, bit32.byteswap(buffer.readu32(State, 4)))
	buffer.writeu32(Result, 8, bit32.byteswap(buffer.readu32(State, 8)))
	buffer.writeu32(Result, 12, bit32.byteswap(buffer.readu32(State, 12)))
	buffer.writeu32(Result, 16, bit32.byteswap(buffer.readu32(State, 16)))

	return ToHex(Result), Result
end

return SHA1
