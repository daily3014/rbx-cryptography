--[=[
	Cryptography library: SHA-256 compression shared by SHA224 and SHA256

	Example usage:
		local Digest = SHA256Core.Digest_Internal(Message, InitialState, 32)
--]=]

--!strict
--!optimize 2
--!native

local CARRY = 2 ^ -32

local IV_256 = buffer.create(32) do
	buffer.writeu32(IV_256, 0, 0x6a09e667)
	buffer.writeu32(IV_256, 4, 0xbb67ae85)
	buffer.writeu32(IV_256, 8, 0x3c6ef372)
	buffer.writeu32(IV_256, 12, 0xa54ff53a)
	buffer.writeu32(IV_256, 16, 0x510e527f)
	buffer.writeu32(IV_256, 20, 0x9b05688c)
	buffer.writeu32(IV_256, 24, 0x1f83d9ab)
	buffer.writeu32(IV_256, 28, 0x5be0cd19)
end

local IV_224 = buffer.create(32) do
	buffer.writeu32(IV_224, 0, 0xc1059ed8)
	buffer.writeu32(IV_224, 4, 0x367cd507)
	buffer.writeu32(IV_224, 8, 0x3070dd17)
	buffer.writeu32(IV_224, 12, 0xf70e5939)
	buffer.writeu32(IV_224, 16, 0xffc00b31)
	buffer.writeu32(IV_224, 20, 0x68581511)
	buffer.writeu32(IV_224, 24, 0x64f98fa7)
	buffer.writeu32(IV_224, 28, 0xbefa4fa4)
end

local STATE = buffer.create(32)
local TAIL = buffer.create(128)

local function Compress(Blocks: buffer, Offset: number, Length: number, State: buffer)
	local S0 = buffer.readu32(State, 0)
	local S1 = buffer.readu32(State, 4)
	local S2 = buffer.readu32(State, 8)
	local S3 = buffer.readu32(State, 12)
	local S4 = buffer.readu32(State, 16)
	local S5 = buffer.readu32(State, 20)
	local S6 = buffer.readu32(State, 24)
	local S7 = buffer.readu32(State, 28)
	for Position = Offset, Offset + Length - 1, 64 do
		local O0 = S0
		local O1 = S1
		local O2 = S2
		local O3 = S3
		local O4 = S4
		local O5 = S5
		local O6 = S6
		local O7 = S7
		local W0 = bit32.byteswap(buffer.readu32(Blocks, Position + 0))
		local W1 = bit32.byteswap(buffer.readu32(Blocks, Position + 4))
		local W2 = bit32.byteswap(buffer.readu32(Blocks, Position + 8))
		local W3 = bit32.byteswap(buffer.readu32(Blocks, Position + 12))
		local W4 = bit32.byteswap(buffer.readu32(Blocks, Position + 16))
		local W5 = bit32.byteswap(buffer.readu32(Blocks, Position + 20))
		local W6 = bit32.byteswap(buffer.readu32(Blocks, Position + 24))
		local W7 = bit32.byteswap(buffer.readu32(Blocks, Position + 28))
		local W8 = bit32.byteswap(buffer.readu32(Blocks, Position + 32))
		local W9 = bit32.byteswap(buffer.readu32(Blocks, Position + 36))
		local W10 = bit32.byteswap(buffer.readu32(Blocks, Position + 40))
		local W11 = bit32.byteswap(buffer.readu32(Blocks, Position + 44))
		local W12 = bit32.byteswap(buffer.readu32(Blocks, Position + 48))
		local W13 = bit32.byteswap(buffer.readu32(Blocks, Position + 52))
		local W14 = bit32.byteswap(buffer.readu32(Blocks, Position + 56))
		local W15 = bit32.byteswap(buffer.readu32(Blocks, Position + 60))
		local BC = bit32.bxor(S1, S2)
		do
			local E, A = S4, S0
			local AB = bit32.bxor(A, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0x428a2f98, 0) + W0, 0) + bit32.bxor(S6, bit32.band(E, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S3, S7
			local AB = bit32.bxor(A, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0x71374491, 0) + W1, 0) + bit32.bxor(S5, bit32.band(E, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S2, S6
			local AB = bit32.bxor(A, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0xb5c0fbcf, 0) + W2, 0) + bit32.bxor(S4, bit32.band(E, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S1, S5
			local AB = bit32.bxor(A, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0xe9b5dba5, 0) + W3, 0) + bit32.bxor(S3, bit32.band(E, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S0, S4
			local AB = bit32.bxor(A, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x3956c25b, 0) + W4, 0) + bit32.bxor(S2, bit32.band(E, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S7, S3
			local AB = bit32.bxor(A, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x59f111f1, 0) + W5, 0) + bit32.bxor(S1, bit32.band(E, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S6, S2
			local AB = bit32.bxor(A, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x923f82a4, 0) + W6, 0) + bit32.bxor(S0, bit32.band(E, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S5, S1
			local AB = bit32.bxor(A, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0xab1c5ed5, 0) + W7, 0) + bit32.bxor(S7, bit32.band(E, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S4, S0
			local AB = bit32.bxor(A, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0xd807aa98, 0) + W8, 0) + bit32.bxor(S6, bit32.band(E, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S3, S7
			local AB = bit32.bxor(A, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0x12835b01, 0) + W9, 0) + bit32.bxor(S5, bit32.band(E, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S2, S6
			local AB = bit32.bxor(A, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0x243185be, 0) + W10, 0) + bit32.bxor(S4, bit32.band(E, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S1, S5
			local AB = bit32.bxor(A, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x550c7dc3, 0) + W11, 0) + bit32.bxor(S3, bit32.band(E, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S0, S4
			local AB = bit32.bxor(A, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x72be5d74, 0) + W12, 0) + bit32.bxor(S2, bit32.band(E, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S7, S3
			local AB = bit32.bxor(A, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x80deb1fe, 0) + W13, 0) + bit32.bxor(S1, bit32.band(E, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S6, S2
			local AB = bit32.bxor(A, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x9bdc06a7, 0) + W14, 0) + bit32.bxor(S0, bit32.band(E, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			local E, A = S5, S1
			local AB = bit32.bxor(A, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0xc19bf174, 0) + W15, 0) + bit32.bxor(S7, bit32.band(E, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W0 = bit32.bor(W0 + W9 + bit32.bxor(bit32.rrotate(W1, 7), bit32.rrotate(W1, 18), bit32.rshift(W1, 3)) + bit32.bxor(bit32.rrotate(W14, 17), bit32.rrotate(W14, 19), bit32.rshift(W14, 10)), 0)
			local E, A = S4, S0
			local AB = bit32.bxor(A, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0xe49b69c1, 0) + W0, 0) + bit32.bxor(S6, bit32.band(E, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W1 = bit32.bor(W1 + W10 + bit32.bxor(bit32.rrotate(W2, 7), bit32.rrotate(W2, 18), bit32.rshift(W2, 3)) + bit32.bxor(bit32.rrotate(W15, 17), bit32.rrotate(W15, 19), bit32.rshift(W15, 10)), 0)
			local E, A = S3, S7
			local AB = bit32.bxor(A, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0xefbe4786, 0) + W1, 0) + bit32.bxor(S5, bit32.band(E, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W2 = bit32.bor(W2 + W11 + bit32.bxor(bit32.rrotate(W3, 7), bit32.rrotate(W3, 18), bit32.rshift(W3, 3)) + bit32.bxor(bit32.rrotate(W0, 17), bit32.rrotate(W0, 19), bit32.rshift(W0, 10)), 0)
			local E, A = S2, S6
			local AB = bit32.bxor(A, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0x0fc19dc6, 0) + W2, 0) + bit32.bxor(S4, bit32.band(E, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W3 = bit32.bor(W3 + W12 + bit32.bxor(bit32.rrotate(W4, 7), bit32.rrotate(W4, 18), bit32.rshift(W4, 3)) + bit32.bxor(bit32.rrotate(W1, 17), bit32.rrotate(W1, 19), bit32.rshift(W1, 10)), 0)
			local E, A = S1, S5
			local AB = bit32.bxor(A, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x240ca1cc, 0) + W3, 0) + bit32.bxor(S3, bit32.band(E, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W4 = bit32.bor(W4 + W13 + bit32.bxor(bit32.rrotate(W5, 7), bit32.rrotate(W5, 18), bit32.rshift(W5, 3)) + bit32.bxor(bit32.rrotate(W2, 17), bit32.rrotate(W2, 19), bit32.rshift(W2, 10)), 0)
			local E, A = S0, S4
			local AB = bit32.bxor(A, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x2de92c6f, 0) + W4, 0) + bit32.bxor(S2, bit32.band(E, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W5 = bit32.bor(W5 + W14 + bit32.bxor(bit32.rrotate(W6, 7), bit32.rrotate(W6, 18), bit32.rshift(W6, 3)) + bit32.bxor(bit32.rrotate(W3, 17), bit32.rrotate(W3, 19), bit32.rshift(W3, 10)), 0)
			local E, A = S7, S3
			local AB = bit32.bxor(A, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x4a7484aa, 0) + W5, 0) + bit32.bxor(S1, bit32.band(E, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W6 = bit32.bor(W6 + W15 + bit32.bxor(bit32.rrotate(W7, 7), bit32.rrotate(W7, 18), bit32.rshift(W7, 3)) + bit32.bxor(bit32.rrotate(W4, 17), bit32.rrotate(W4, 19), bit32.rshift(W4, 10)), 0)
			local E, A = S6, S2
			local AB = bit32.bxor(A, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x5cb0a9dc, 0) + W6, 0) + bit32.bxor(S0, bit32.band(E, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W7 = bit32.bor(W7 + W0 + bit32.bxor(bit32.rrotate(W8, 7), bit32.rrotate(W8, 18), bit32.rshift(W8, 3)) + bit32.bxor(bit32.rrotate(W5, 17), bit32.rrotate(W5, 19), bit32.rshift(W5, 10)), 0)
			local E, A = S5, S1
			local AB = bit32.bxor(A, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x76f988da, 0) + W7, 0) + bit32.bxor(S7, bit32.band(E, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W8 = bit32.bor(W8 + W1 + bit32.bxor(bit32.rrotate(W9, 7), bit32.rrotate(W9, 18), bit32.rshift(W9, 3)) + bit32.bxor(bit32.rrotate(W6, 17), bit32.rrotate(W6, 19), bit32.rshift(W6, 10)), 0)
			local E, A = S4, S0
			local AB = bit32.bxor(A, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0x983e5152, 0) + W8, 0) + bit32.bxor(S6, bit32.band(E, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W9 = bit32.bor(W9 + W2 + bit32.bxor(bit32.rrotate(W10, 7), bit32.rrotate(W10, 18), bit32.rshift(W10, 3)) + bit32.bxor(bit32.rrotate(W7, 17), bit32.rrotate(W7, 19), bit32.rshift(W7, 10)), 0)
			local E, A = S3, S7
			local AB = bit32.bxor(A, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0xa831c66d, 0) + W9, 0) + bit32.bxor(S5, bit32.band(E, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W10 = bit32.bor(W10 + W3 + bit32.bxor(bit32.rrotate(W11, 7), bit32.rrotate(W11, 18), bit32.rshift(W11, 3)) + bit32.bxor(bit32.rrotate(W8, 17), bit32.rrotate(W8, 19), bit32.rshift(W8, 10)), 0)
			local E, A = S2, S6
			local AB = bit32.bxor(A, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0xb00327c8, 0) + W10, 0) + bit32.bxor(S4, bit32.band(E, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W11 = bit32.bor(W11 + W4 + bit32.bxor(bit32.rrotate(W12, 7), bit32.rrotate(W12, 18), bit32.rshift(W12, 3)) + bit32.bxor(bit32.rrotate(W9, 17), bit32.rrotate(W9, 19), bit32.rshift(W9, 10)), 0)
			local E, A = S1, S5
			local AB = bit32.bxor(A, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0xbf597fc7, 0) + W11, 0) + bit32.bxor(S3, bit32.band(E, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W12 = bit32.bor(W12 + W5 + bit32.bxor(bit32.rrotate(W13, 7), bit32.rrotate(W13, 18), bit32.rshift(W13, 3)) + bit32.bxor(bit32.rrotate(W10, 17), bit32.rrotate(W10, 19), bit32.rshift(W10, 10)), 0)
			local E, A = S0, S4
			local AB = bit32.bxor(A, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0xc6e00bf3, 0) + W12, 0) + bit32.bxor(S2, bit32.band(E, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W13 = bit32.bor(W13 + W6 + bit32.bxor(bit32.rrotate(W14, 7), bit32.rrotate(W14, 18), bit32.rshift(W14, 3)) + bit32.bxor(bit32.rrotate(W11, 17), bit32.rrotate(W11, 19), bit32.rshift(W11, 10)), 0)
			local E, A = S7, S3
			local AB = bit32.bxor(A, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0xd5a79147, 0) + W13, 0) + bit32.bxor(S1, bit32.band(E, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W14 = bit32.bor(W14 + W7 + bit32.bxor(bit32.rrotate(W15, 7), bit32.rrotate(W15, 18), bit32.rshift(W15, 3)) + bit32.bxor(bit32.rrotate(W12, 17), bit32.rrotate(W12, 19), bit32.rshift(W12, 10)), 0)
			local E, A = S6, S2
			local AB = bit32.bxor(A, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x06ca6351, 0) + W14, 0) + bit32.bxor(S0, bit32.band(E, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W15 = bit32.bor(W15 + W8 + bit32.bxor(bit32.rrotate(W0, 7), bit32.rrotate(W0, 18), bit32.rshift(W0, 3)) + bit32.bxor(bit32.rrotate(W13, 17), bit32.rrotate(W13, 19), bit32.rshift(W13, 10)), 0)
			local E, A = S5, S1
			local AB = bit32.bxor(A, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x14292967, 0) + W15, 0) + bit32.bxor(S7, bit32.band(E, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W0 = bit32.bor(W0 + W9 + bit32.bxor(bit32.rrotate(W1, 7), bit32.rrotate(W1, 18), bit32.rshift(W1, 3)) + bit32.bxor(bit32.rrotate(W14, 17), bit32.rrotate(W14, 19), bit32.rshift(W14, 10)), 0)
			local E, A = S4, S0
			local AB = bit32.bxor(A, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0x27b70a85, 0) + W0, 0) + bit32.bxor(S6, bit32.band(E, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W1 = bit32.bor(W1 + W10 + bit32.bxor(bit32.rrotate(W2, 7), bit32.rrotate(W2, 18), bit32.rshift(W2, 3)) + bit32.bxor(bit32.rrotate(W15, 17), bit32.rrotate(W15, 19), bit32.rshift(W15, 10)), 0)
			local E, A = S3, S7
			local AB = bit32.bxor(A, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0x2e1b2138, 0) + W1, 0) + bit32.bxor(S5, bit32.band(E, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W2 = bit32.bor(W2 + W11 + bit32.bxor(bit32.rrotate(W3, 7), bit32.rrotate(W3, 18), bit32.rshift(W3, 3)) + bit32.bxor(bit32.rrotate(W0, 17), bit32.rrotate(W0, 19), bit32.rshift(W0, 10)), 0)
			local E, A = S2, S6
			local AB = bit32.bxor(A, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0x4d2c6dfc, 0) + W2, 0) + bit32.bxor(S4, bit32.band(E, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W3 = bit32.bor(W3 + W12 + bit32.bxor(bit32.rrotate(W4, 7), bit32.rrotate(W4, 18), bit32.rshift(W4, 3)) + bit32.bxor(bit32.rrotate(W1, 17), bit32.rrotate(W1, 19), bit32.rshift(W1, 10)), 0)
			local E, A = S1, S5
			local AB = bit32.bxor(A, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x53380d13, 0) + W3, 0) + bit32.bxor(S3, bit32.band(E, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W4 = bit32.bor(W4 + W13 + bit32.bxor(bit32.rrotate(W5, 7), bit32.rrotate(W5, 18), bit32.rshift(W5, 3)) + bit32.bxor(bit32.rrotate(W2, 17), bit32.rrotate(W2, 19), bit32.rshift(W2, 10)), 0)
			local E, A = S0, S4
			local AB = bit32.bxor(A, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x650a7354, 0) + W4, 0) + bit32.bxor(S2, bit32.band(E, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W5 = bit32.bor(W5 + W14 + bit32.bxor(bit32.rrotate(W6, 7), bit32.rrotate(W6, 18), bit32.rshift(W6, 3)) + bit32.bxor(bit32.rrotate(W3, 17), bit32.rrotate(W3, 19), bit32.rshift(W3, 10)), 0)
			local E, A = S7, S3
			local AB = bit32.bxor(A, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x766a0abb, 0) + W5, 0) + bit32.bxor(S1, bit32.band(E, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W6 = bit32.bor(W6 + W15 + bit32.bxor(bit32.rrotate(W7, 7), bit32.rrotate(W7, 18), bit32.rshift(W7, 3)) + bit32.bxor(bit32.rrotate(W4, 17), bit32.rrotate(W4, 19), bit32.rshift(W4, 10)), 0)
			local E, A = S6, S2
			local AB = bit32.bxor(A, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x81c2c92e, 0) + W6, 0) + bit32.bxor(S0, bit32.band(E, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W7 = bit32.bor(W7 + W0 + bit32.bxor(bit32.rrotate(W8, 7), bit32.rrotate(W8, 18), bit32.rshift(W8, 3)) + bit32.bxor(bit32.rrotate(W5, 17), bit32.rrotate(W5, 19), bit32.rshift(W5, 10)), 0)
			local E, A = S5, S1
			local AB = bit32.bxor(A, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x92722c85, 0) + W7, 0) + bit32.bxor(S7, bit32.band(E, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W8 = bit32.bor(W8 + W1 + bit32.bxor(bit32.rrotate(W9, 7), bit32.rrotate(W9, 18), bit32.rshift(W9, 3)) + bit32.bxor(bit32.rrotate(W6, 17), bit32.rrotate(W6, 19), bit32.rshift(W6, 10)), 0)
			local E, A = S4, S0
			local AB = bit32.bxor(A, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0xa2bfe8a1, 0) + W8, 0) + bit32.bxor(S6, bit32.band(E, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W9 = bit32.bor(W9 + W2 + bit32.bxor(bit32.rrotate(W10, 7), bit32.rrotate(W10, 18), bit32.rshift(W10, 3)) + bit32.bxor(bit32.rrotate(W7, 17), bit32.rrotate(W7, 19), bit32.rshift(W7, 10)), 0)
			local E, A = S3, S7
			local AB = bit32.bxor(A, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0xa81a664b, 0) + W9, 0) + bit32.bxor(S5, bit32.band(E, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W10 = bit32.bor(W10 + W3 + bit32.bxor(bit32.rrotate(W11, 7), bit32.rrotate(W11, 18), bit32.rshift(W11, 3)) + bit32.bxor(bit32.rrotate(W8, 17), bit32.rrotate(W8, 19), bit32.rshift(W8, 10)), 0)
			local E, A = S2, S6
			local AB = bit32.bxor(A, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0xc24b8b70, 0) + W10, 0) + bit32.bxor(S4, bit32.band(E, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W11 = bit32.bor(W11 + W4 + bit32.bxor(bit32.rrotate(W12, 7), bit32.rrotate(W12, 18), bit32.rshift(W12, 3)) + bit32.bxor(bit32.rrotate(W9, 17), bit32.rrotate(W9, 19), bit32.rshift(W9, 10)), 0)
			local E, A = S1, S5
			local AB = bit32.bxor(A, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0xc76c51a3, 0) + W11, 0) + bit32.bxor(S3, bit32.band(E, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W12 = bit32.bor(W12 + W5 + bit32.bxor(bit32.rrotate(W13, 7), bit32.rrotate(W13, 18), bit32.rshift(W13, 3)) + bit32.bxor(bit32.rrotate(W10, 17), bit32.rrotate(W10, 19), bit32.rshift(W10, 10)), 0)
			local E, A = S0, S4
			local AB = bit32.bxor(A, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0xd192e819, 0) + W12, 0) + bit32.bxor(S2, bit32.band(E, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W13 = bit32.bor(W13 + W6 + bit32.bxor(bit32.rrotate(W14, 7), bit32.rrotate(W14, 18), bit32.rshift(W14, 3)) + bit32.bxor(bit32.rrotate(W11, 17), bit32.rrotate(W11, 19), bit32.rshift(W11, 10)), 0)
			local E, A = S7, S3
			local AB = bit32.bxor(A, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0xd6990624, 0) + W13, 0) + bit32.bxor(S1, bit32.band(E, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W14 = bit32.bor(W14 + W7 + bit32.bxor(bit32.rrotate(W15, 7), bit32.rrotate(W15, 18), bit32.rshift(W15, 3)) + bit32.bxor(bit32.rrotate(W12, 17), bit32.rrotate(W12, 19), bit32.rshift(W12, 10)), 0)
			local E, A = S6, S2
			local AB = bit32.bxor(A, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0xf40e3585, 0) + W14, 0) + bit32.bxor(S0, bit32.band(E, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W15 = bit32.bor(W15 + W8 + bit32.bxor(bit32.rrotate(W0, 7), bit32.rrotate(W0, 18), bit32.rshift(W0, 3)) + bit32.bxor(bit32.rrotate(W13, 17), bit32.rrotate(W13, 19), bit32.rshift(W13, 10)), 0)
			local E, A = S5, S1
			local AB = bit32.bxor(A, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x106aa070, 0) + W15, 0) + bit32.bxor(S7, bit32.band(E, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W0 = bit32.bor(W0 + W9 + bit32.bxor(bit32.rrotate(W1, 7), bit32.rrotate(W1, 18), bit32.rshift(W1, 3)) + bit32.bxor(bit32.rrotate(W14, 17), bit32.rrotate(W14, 19), bit32.rshift(W14, 10)), 0)
			local E, A = S4, S0
			local AB = bit32.bxor(A, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0x19a4c116, 0) + W0, 0) + bit32.bxor(S6, bit32.band(E, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W1 = bit32.bor(W1 + W10 + bit32.bxor(bit32.rrotate(W2, 7), bit32.rrotate(W2, 18), bit32.rshift(W2, 3)) + bit32.bxor(bit32.rrotate(W15, 17), bit32.rrotate(W15, 19), bit32.rshift(W15, 10)), 0)
			local E, A = S3, S7
			local AB = bit32.bxor(A, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0x1e376c08, 0) + W1, 0) + bit32.bxor(S5, bit32.band(E, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W2 = bit32.bor(W2 + W11 + bit32.bxor(bit32.rrotate(W3, 7), bit32.rrotate(W3, 18), bit32.rshift(W3, 3)) + bit32.bxor(bit32.rrotate(W0, 17), bit32.rrotate(W0, 19), bit32.rshift(W0, 10)), 0)
			local E, A = S2, S6
			local AB = bit32.bxor(A, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0x2748774c, 0) + W2, 0) + bit32.bxor(S4, bit32.band(E, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W3 = bit32.bor(W3 + W12 + bit32.bxor(bit32.rrotate(W4, 7), bit32.rrotate(W4, 18), bit32.rshift(W4, 3)) + bit32.bxor(bit32.rrotate(W1, 17), bit32.rrotate(W1, 19), bit32.rshift(W1, 10)), 0)
			local E, A = S1, S5
			local AB = bit32.bxor(A, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x34b0bcb5, 0) + W3, 0) + bit32.bxor(S3, bit32.band(E, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W4 = bit32.bor(W4 + W13 + bit32.bxor(bit32.rrotate(W5, 7), bit32.rrotate(W5, 18), bit32.rshift(W5, 3)) + bit32.bxor(bit32.rrotate(W2, 17), bit32.rrotate(W2, 19), bit32.rshift(W2, 10)), 0)
			local E, A = S0, S4
			local AB = bit32.bxor(A, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x391c0cb3, 0) + W4, 0) + bit32.bxor(S2, bit32.band(E, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W5 = bit32.bor(W5 + W14 + bit32.bxor(bit32.rrotate(W6, 7), bit32.rrotate(W6, 18), bit32.rshift(W6, 3)) + bit32.bxor(bit32.rrotate(W3, 17), bit32.rrotate(W3, 19), bit32.rshift(W3, 10)), 0)
			local E, A = S7, S3
			local AB = bit32.bxor(A, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0x4ed8aa4a, 0) + W5, 0) + bit32.bxor(S1, bit32.band(E, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W6 = bit32.bor(W6 + W15 + bit32.bxor(bit32.rrotate(W7, 7), bit32.rrotate(W7, 18), bit32.rshift(W7, 3)) + bit32.bxor(bit32.rrotate(W4, 17), bit32.rrotate(W4, 19), bit32.rshift(W4, 10)), 0)
			local E, A = S6, S2
			local AB = bit32.bxor(A, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0x5b9cca4f, 0) + W6, 0) + bit32.bxor(S0, bit32.band(E, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W7 = bit32.bor(W7 + W0 + bit32.bxor(bit32.rrotate(W8, 7), bit32.rrotate(W8, 18), bit32.rshift(W8, 3)) + bit32.bxor(bit32.rrotate(W5, 17), bit32.rrotate(W5, 19), bit32.rshift(W5, 10)), 0)
			local E, A = S5, S1
			local AB = bit32.bxor(A, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0x682e6ff3, 0) + W7, 0) + bit32.bxor(S7, bit32.band(E, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W8 = bit32.bor(W8 + W1 + bit32.bxor(bit32.rrotate(W9, 7), bit32.rrotate(W9, 18), bit32.rshift(W9, 3)) + bit32.bxor(bit32.rrotate(W6, 17), bit32.rrotate(W6, 19), bit32.rshift(W6, 10)), 0)
			local E, A = S4, S0
			local AB = bit32.bxor(A, S1)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S7 + 0x748f82ee, 0) + W8, 0) + bit32.bxor(S6, bit32.band(E, bit32.bxor(S5, S6))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S3 = bit32.bor(S3 + T1, 0)
			S7 = bit32.bor(bit32.bor(T1 + bit32.bxor(S1, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W9 = bit32.bor(W9 + W2 + bit32.bxor(bit32.rrotate(W10, 7), bit32.rrotate(W10, 18), bit32.rshift(W10, 3)) + bit32.bxor(bit32.rrotate(W7, 17), bit32.rrotate(W7, 19), bit32.rshift(W7, 10)), 0)
			local E, A = S3, S7
			local AB = bit32.bxor(A, S0)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S6 + 0x78a5636f, 0) + W9, 0) + bit32.bxor(S5, bit32.band(E, bit32.bxor(S4, S5))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S2 = bit32.bor(S2 + T1, 0)
			S6 = bit32.bor(bit32.bor(T1 + bit32.bxor(S0, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W10 = bit32.bor(W10 + W3 + bit32.bxor(bit32.rrotate(W11, 7), bit32.rrotate(W11, 18), bit32.rshift(W11, 3)) + bit32.bxor(bit32.rrotate(W8, 17), bit32.rrotate(W8, 19), bit32.rshift(W8, 10)), 0)
			local E, A = S2, S6
			local AB = bit32.bxor(A, S7)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S5 + 0x84c87814, 0) + W10, 0) + bit32.bxor(S4, bit32.band(E, bit32.bxor(S3, S4))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S1 = bit32.bor(S1 + T1, 0)
			S5 = bit32.bor(bit32.bor(T1 + bit32.bxor(S7, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W11 = bit32.bor(W11 + W4 + bit32.bxor(bit32.rrotate(W12, 7), bit32.rrotate(W12, 18), bit32.rshift(W12, 3)) + bit32.bxor(bit32.rrotate(W9, 17), bit32.rrotate(W9, 19), bit32.rshift(W9, 10)), 0)
			local E, A = S1, S5
			local AB = bit32.bxor(A, S6)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S4 + 0x8cc70208, 0) + W11, 0) + bit32.bxor(S3, bit32.band(E, bit32.bxor(S2, S3))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S0 = bit32.bor(S0 + T1, 0)
			S4 = bit32.bor(bit32.bor(T1 + bit32.bxor(S6, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W12 = bit32.bor(W12 + W5 + bit32.bxor(bit32.rrotate(W13, 7), bit32.rrotate(W13, 18), bit32.rshift(W13, 3)) + bit32.bxor(bit32.rrotate(W10, 17), bit32.rrotate(W10, 19), bit32.rshift(W10, 10)), 0)
			local E, A = S0, S4
			local AB = bit32.bxor(A, S5)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S3 + 0x90befffa, 0) + W12, 0) + bit32.bxor(S2, bit32.band(E, bit32.bxor(S1, S2))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S7 = bit32.bor(S7 + T1, 0)
			S3 = bit32.bor(bit32.bor(T1 + bit32.bxor(S5, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W13 = bit32.bor(W13 + W6 + bit32.bxor(bit32.rrotate(W14, 7), bit32.rrotate(W14, 18), bit32.rshift(W14, 3)) + bit32.bxor(bit32.rrotate(W11, 17), bit32.rrotate(W11, 19), bit32.rshift(W11, 10)), 0)
			local E, A = S7, S3
			local AB = bit32.bxor(A, S4)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S2 + 0xa4506ceb, 0) + W13, 0) + bit32.bxor(S1, bit32.band(E, bit32.bxor(S0, S1))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S6 = bit32.bor(S6 + T1, 0)
			S2 = bit32.bor(bit32.bor(T1 + bit32.bxor(S4, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W14 = bit32.bor(W14 + W7 + bit32.bxor(bit32.rrotate(W15, 7), bit32.rrotate(W15, 18), bit32.rshift(W15, 3)) + bit32.bxor(bit32.rrotate(W12, 17), bit32.rrotate(W12, 19), bit32.rshift(W12, 10)), 0)
			local E, A = S6, S2
			local AB = bit32.bxor(A, S3)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S1 + 0xbef9a3f7, 0) + W14, 0) + bit32.bxor(S0, bit32.band(E, bit32.bxor(S7, S0))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S5 = bit32.bor(S5 + T1, 0)
			S1 = bit32.bor(bit32.bor(T1 + bit32.bxor(S3, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		do
			W15 = bit32.bor(W15 + W8 + bit32.bxor(bit32.rrotate(W0, 7), bit32.rrotate(W0, 18), bit32.rshift(W0, 3)) + bit32.bxor(bit32.rrotate(W13, 17), bit32.rrotate(W13, 19), bit32.rshift(W13, 10)), 0)
			local E, A = S5, S1
			local AB = bit32.bxor(A, S2)
			local T1 = bit32.bor(bit32.bor(bit32.bor(bit32.bor(S0 + 0xc67178f2, 0) + W15, 0) + bit32.bxor(S7, bit32.band(E, bit32.bxor(S6, S7))), 0) + bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25)), 0)
			S4 = bit32.bor(S4 + T1, 0)
			S0 = bit32.bor(bit32.bor(T1 + bit32.bxor(S2, bit32.band(AB, BC)), 0) + bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22)), 0)
			BC = AB
		end
		S0 = bit32.bor(O0 + S0, 0)
		S1 = bit32.bor(O1 + S1, 0)
		S2 = bit32.bor(O2 + S2, 0)
		S3 = bit32.bor(O3 + S3, 0)
		S4 = bit32.bor(O4 + S4, 0)
		S5 = bit32.bor(O5 + S5, 0)
		S6 = bit32.bor(O6 + S6, 0)
		S7 = bit32.bor(O7 + S7, 0)
	end
	buffer.writeu32(State, 0, S0)
	buffer.writeu32(State, 4, S1)
	buffer.writeu32(State, 8, S2)
	buffer.writeu32(State, 12, S3)
	buffer.writeu32(State, 16, S4)
	buffer.writeu32(State, 20, S5)
	buffer.writeu32(State, 24, S6)
	buffer.writeu32(State, 28, S7)
end

local function Digest(Message: buffer, InitialState: buffer, OutputBytes: number): buffer
	local State = STATE
	buffer.copy(State, 0, InitialState, 0, 32)

	local MessageLength = buffer.len(Message)
	local TailLength = MessageLength % 64
	local FullBytes = MessageLength - TailLength

	if FullBytes > 0 then
		Compress(Message, 0, FullBytes, State)
	end

	local Tail = TAIL
	local TailBytes = if TailLength < 56 then 64 else 128
	buffer.fill(Tail, 0, 0, TailBytes)
	if TailLength > 0 then
		buffer.copy(Tail, 0, Message, FullBytes, TailLength)
	end
	buffer.writeu8(Tail, TailLength, 0x80)

	local BitLength = MessageLength * 8
	buffer.writeu32(Tail, TailBytes - 8, bit32.byteswap(math.floor(BitLength * CARRY)))
	buffer.writeu32(Tail, TailBytes - 4, bit32.byteswap(BitLength))
	Compress(Tail, 0, TailBytes, State)

	local Result = buffer.create(OutputBytes)
	for Offset = 0, OutputBytes - 4, 4 do
		buffer.writeu32(Result, Offset, bit32.byteswap(buffer.readu32(State, Offset)))
	end

	return Result
end

return {
	Digest_Internal = Digest,
	IV_256 = IV_256,
	IV_224 = IV_224,
}
