--[=[
	Cryptography library: BLAKE2b Luau path, used by Blake2b when EncodingService can't serve a call

	Example usage:
		local Digest = Blake2bCore.Digest(Message, 64, Key)
--]=]

--!strict
--!optimize 2
--!native

local BLOCK_SIZE_BYTES = 128

local CARRY = 2 ^ -32

local STATE = buffer.create(64)
local FINAL_BLOCK = buffer.create(BLOCK_SIZE_BYTES)

local function Compress(State: buffer, Blocks: buffer, Offset: number, BlockCount: number, StartCounter: number, Final: boolean)
	local H0L, H0H = buffer.readu32(State, 0), buffer.readu32(State, 4)
	local H1L, H1H = buffer.readu32(State, 8), buffer.readu32(State, 12)
	local H2L, H2H = buffer.readu32(State, 16), buffer.readu32(State, 20)
	local H3L, H3H = buffer.readu32(State, 24), buffer.readu32(State, 28)
	local H4L, H4H = buffer.readu32(State, 32), buffer.readu32(State, 36)
	local H5L, H5H = buffer.readu32(State, 40), buffer.readu32(State, 44)
	local H6L, H6H = buffer.readu32(State, 48), buffer.readu32(State, 52)
	local H7L, H7H = buffer.readu32(State, 56), buffer.readu32(State, 60)
	local FinalMask = if Final then 0xFFFFFFFF else 0
	for Block = 0, BlockCount - 1 do
		local Position = Offset + Block * 128
		local Counter = StartCounter + Block * 128
		local CounterL = Counter % 0x100000000
		local CounterH = (Counter - CounterL) * CARRY
		local ML0, MH0 = buffer.readu32(Blocks, Position + 0), buffer.readu32(Blocks, Position + 4)
		local ML1, MH1 = buffer.readu32(Blocks, Position + 8), buffer.readu32(Blocks, Position + 12)
		local ML2, MH2 = buffer.readu32(Blocks, Position + 16), buffer.readu32(Blocks, Position + 20)
		local ML3, MH3 = buffer.readu32(Blocks, Position + 24), buffer.readu32(Blocks, Position + 28)
		local ML4, MH4 = buffer.readu32(Blocks, Position + 32), buffer.readu32(Blocks, Position + 36)
		local ML5, MH5 = buffer.readu32(Blocks, Position + 40), buffer.readu32(Blocks, Position + 44)
		local ML6, MH6 = buffer.readu32(Blocks, Position + 48), buffer.readu32(Blocks, Position + 52)
		local ML7, MH7 = buffer.readu32(Blocks, Position + 56), buffer.readu32(Blocks, Position + 60)
		local ML8, MH8 = buffer.readu32(Blocks, Position + 64), buffer.readu32(Blocks, Position + 68)
		local ML9, MH9 = buffer.readu32(Blocks, Position + 72), buffer.readu32(Blocks, Position + 76)
		local ML10, MH10 = buffer.readu32(Blocks, Position + 80), buffer.readu32(Blocks, Position + 84)
		local ML11, MH11 = buffer.readu32(Blocks, Position + 88), buffer.readu32(Blocks, Position + 92)
		local ML12, MH12 = buffer.readu32(Blocks, Position + 96), buffer.readu32(Blocks, Position + 100)
		local ML13, MH13 = buffer.readu32(Blocks, Position + 104), buffer.readu32(Blocks, Position + 108)
		local ML14, MH14 = buffer.readu32(Blocks, Position + 112), buffer.readu32(Blocks, Position + 116)
		local ML15, MH15 = buffer.readu32(Blocks, Position + 120), buffer.readu32(Blocks, Position + 124)
		local V00H, V00L = H0H, H0L
		local V01H, V01L = H1H, H1L
		local V02H, V02L = H2H, H2L
		local V03H, V03L = H3H, H3L
		local V04H, V04L = H4H, H4L
		local V05H, V05L = H5H, H5L
		local V06H, V06L = H6H, H6L
		local V07H, V07L = H7H, H7L
		local V08H, V08L = 0x6a09e667, 0xf3bcc908
		local V09H, V09L = 0xbb67ae85, 0x84caa73b
		local V10H, V10L = 0x3c6ef372, 0xfe94f82b
		local V11H, V11L = 0xa54ff53a, 0x5f1d36f1
		local V12H, V12L = bit32.bxor(0x510e527f, CounterH), bit32.bxor(0xade682d1, CounterL)
		local V13H, V13L = 0x9b05688c, 0x2b3e6c1f
		local V14H, V14L = bit32.bxor(0x1f83d9ab, FinalMask), bit32.bxor(0xfb41bd6b, FinalMask)
		local V15H, V15L = 0x5be0cd19, 0x137e2179
		do
			do
			local S1 = bit32.bor(V00L + ML0, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH0, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML0), bit32.band(bit32.bor(V00L, ML0), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML1, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH1, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML1), bit32.band(bit32.bor(V00L, ML1), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML2, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH2, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML2), bit32.band(bit32.bor(V01L, ML2), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML3, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH3, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML3), bit32.band(bit32.bor(V01L, ML3), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML4, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH4, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML4), bit32.band(bit32.bor(V02L, ML4), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML5, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH5, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML5), bit32.band(bit32.bor(V02L, ML5), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML6, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH6, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML6), bit32.band(bit32.bor(V03L, ML6), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML7, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH7, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML7), bit32.band(bit32.bor(V03L, ML7), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V00L + ML8, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH8, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML8), bit32.band(bit32.bor(V00L, ML8), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML9, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH9, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML9), bit32.band(bit32.bor(V00L, ML9), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML10, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH10, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML10), bit32.band(bit32.bor(V01L, ML10), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML11, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH11, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML11), bit32.band(bit32.bor(V01L, ML11), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML12, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH12, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML12), bit32.band(bit32.bor(V02L, ML12), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML13, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH13, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML13), bit32.band(bit32.bor(V02L, ML13), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML14, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH14, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML14), bit32.band(bit32.bor(V03L, ML14), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML15, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH15, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML15), bit32.band(bit32.bor(V03L, ML15), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
		end
		do
			do
			local S1 = bit32.bor(V00L + ML14, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH14, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML14), bit32.band(bit32.bor(V00L, ML14), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML10, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH10, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML10), bit32.band(bit32.bor(V00L, ML10), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML4, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH4, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML4), bit32.band(bit32.bor(V01L, ML4), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML8, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH8, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML8), bit32.band(bit32.bor(V01L, ML8), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML9, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH9, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML9), bit32.band(bit32.bor(V02L, ML9), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML15, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH15, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML15), bit32.band(bit32.bor(V02L, ML15), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML13, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH13, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML13), bit32.band(bit32.bor(V03L, ML13), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML6, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH6, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML6), bit32.band(bit32.bor(V03L, ML6), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V00L + ML1, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH1, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML1), bit32.band(bit32.bor(V00L, ML1), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML12, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH12, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML12), bit32.band(bit32.bor(V00L, ML12), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML0, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH0, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML0), bit32.band(bit32.bor(V01L, ML0), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML2, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH2, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML2), bit32.band(bit32.bor(V01L, ML2), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML11, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH11, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML11), bit32.band(bit32.bor(V02L, ML11), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML7, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH7, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML7), bit32.band(bit32.bor(V02L, ML7), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML5, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH5, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML5), bit32.band(bit32.bor(V03L, ML5), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML3, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH3, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML3), bit32.band(bit32.bor(V03L, ML3), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
		end
		do
			do
			local S1 = bit32.bor(V00L + ML11, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH11, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML11), bit32.band(bit32.bor(V00L, ML11), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML8, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH8, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML8), bit32.band(bit32.bor(V00L, ML8), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML12, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH12, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML12), bit32.band(bit32.bor(V01L, ML12), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML0, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH0, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML0), bit32.band(bit32.bor(V01L, ML0), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML5, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH5, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML5), bit32.band(bit32.bor(V02L, ML5), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML2, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH2, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML2), bit32.band(bit32.bor(V02L, ML2), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML15, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH15, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML15), bit32.band(bit32.bor(V03L, ML15), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML13, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH13, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML13), bit32.band(bit32.bor(V03L, ML13), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V00L + ML10, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH10, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML10), bit32.band(bit32.bor(V00L, ML10), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML14, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH14, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML14), bit32.band(bit32.bor(V00L, ML14), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML3, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH3, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML3), bit32.band(bit32.bor(V01L, ML3), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML6, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH6, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML6), bit32.band(bit32.bor(V01L, ML6), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML7, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH7, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML7), bit32.band(bit32.bor(V02L, ML7), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML1, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH1, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML1), bit32.band(bit32.bor(V02L, ML1), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML9, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH9, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML9), bit32.band(bit32.bor(V03L, ML9), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML4, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH4, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML4), bit32.band(bit32.bor(V03L, ML4), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
		end
		do
			do
			local S1 = bit32.bor(V00L + ML7, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH7, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML7), bit32.band(bit32.bor(V00L, ML7), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML9, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH9, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML9), bit32.band(bit32.bor(V00L, ML9), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML3, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH3, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML3), bit32.band(bit32.bor(V01L, ML3), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML1, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH1, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML1), bit32.band(bit32.bor(V01L, ML1), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML13, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH13, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML13), bit32.band(bit32.bor(V02L, ML13), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML12, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH12, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML12), bit32.band(bit32.bor(V02L, ML12), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML11, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH11, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML11), bit32.band(bit32.bor(V03L, ML11), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML14, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH14, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML14), bit32.band(bit32.bor(V03L, ML14), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V00L + ML2, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH2, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML2), bit32.band(bit32.bor(V00L, ML2), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML6, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH6, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML6), bit32.band(bit32.bor(V00L, ML6), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML5, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH5, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML5), bit32.band(bit32.bor(V01L, ML5), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML10, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH10, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML10), bit32.band(bit32.bor(V01L, ML10), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML4, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH4, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML4), bit32.band(bit32.bor(V02L, ML4), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML0, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH0, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML0), bit32.band(bit32.bor(V02L, ML0), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML15, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH15, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML15), bit32.band(bit32.bor(V03L, ML15), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML8, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH8, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML8), bit32.band(bit32.bor(V03L, ML8), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
		end
		do
			do
			local S1 = bit32.bor(V00L + ML9, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH9, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML9), bit32.band(bit32.bor(V00L, ML9), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML0, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH0, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML0), bit32.band(bit32.bor(V00L, ML0), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML5, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH5, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML5), bit32.band(bit32.bor(V01L, ML5), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML7, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH7, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML7), bit32.band(bit32.bor(V01L, ML7), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML2, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH2, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML2), bit32.band(bit32.bor(V02L, ML2), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML4, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH4, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML4), bit32.band(bit32.bor(V02L, ML4), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML10, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH10, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML10), bit32.band(bit32.bor(V03L, ML10), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML15, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH15, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML15), bit32.band(bit32.bor(V03L, ML15), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V00L + ML14, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH14, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML14), bit32.band(bit32.bor(V00L, ML14), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML1, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH1, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML1), bit32.band(bit32.bor(V00L, ML1), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML11, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH11, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML11), bit32.band(bit32.bor(V01L, ML11), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML12, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH12, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML12), bit32.band(bit32.bor(V01L, ML12), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML6, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH6, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML6), bit32.band(bit32.bor(V02L, ML6), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML8, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH8, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML8), bit32.band(bit32.bor(V02L, ML8), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML3, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH3, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML3), bit32.band(bit32.bor(V03L, ML3), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML13, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH13, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML13), bit32.band(bit32.bor(V03L, ML13), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
		end
		do
			do
			local S1 = bit32.bor(V00L + ML2, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH2, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML2), bit32.band(bit32.bor(V00L, ML2), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML12, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH12, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML12), bit32.band(bit32.bor(V00L, ML12), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML6, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH6, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML6), bit32.band(bit32.bor(V01L, ML6), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML10, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH10, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML10), bit32.band(bit32.bor(V01L, ML10), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML0, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH0, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML0), bit32.band(bit32.bor(V02L, ML0), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML11, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH11, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML11), bit32.band(bit32.bor(V02L, ML11), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML8, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH8, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML8), bit32.band(bit32.bor(V03L, ML8), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML3, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH3, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML3), bit32.band(bit32.bor(V03L, ML3), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V00L + ML4, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH4, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML4), bit32.band(bit32.bor(V00L, ML4), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML13, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH13, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML13), bit32.band(bit32.bor(V00L, ML13), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML7, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH7, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML7), bit32.band(bit32.bor(V01L, ML7), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML5, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH5, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML5), bit32.band(bit32.bor(V01L, ML5), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML15, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH15, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML15), bit32.band(bit32.bor(V02L, ML15), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML14, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH14, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML14), bit32.band(bit32.bor(V02L, ML14), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML1, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH1, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML1), bit32.band(bit32.bor(V03L, ML1), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML9, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH9, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML9), bit32.band(bit32.bor(V03L, ML9), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
		end
		if Position < 0 then break end
		do
			do
			local S1 = bit32.bor(V00L + ML12, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH12, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML12), bit32.band(bit32.bor(V00L, ML12), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML5, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH5, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML5), bit32.band(bit32.bor(V00L, ML5), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML1, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH1, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML1), bit32.band(bit32.bor(V01L, ML1), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML15, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH15, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML15), bit32.band(bit32.bor(V01L, ML15), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML14, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH14, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML14), bit32.band(bit32.bor(V02L, ML14), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML13, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH13, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML13), bit32.band(bit32.bor(V02L, ML13), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML4, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH4, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML4), bit32.band(bit32.bor(V03L, ML4), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML10, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH10, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML10), bit32.band(bit32.bor(V03L, ML10), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V00L + ML0, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH0, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML0), bit32.band(bit32.bor(V00L, ML0), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML7, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH7, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML7), bit32.band(bit32.bor(V00L, ML7), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML6, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH6, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML6), bit32.band(bit32.bor(V01L, ML6), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML3, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH3, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML3), bit32.band(bit32.bor(V01L, ML3), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML9, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH9, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML9), bit32.band(bit32.bor(V02L, ML9), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML2, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH2, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML2), bit32.band(bit32.bor(V02L, ML2), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML8, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH8, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML8), bit32.band(bit32.bor(V03L, ML8), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML11, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH11, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML11), bit32.band(bit32.bor(V03L, ML11), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
		end
		do
			do
			local S1 = bit32.bor(V00L + ML13, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH13, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML13), bit32.band(bit32.bor(V00L, ML13), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML11, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH11, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML11), bit32.band(bit32.bor(V00L, ML11), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML7, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH7, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML7), bit32.band(bit32.bor(V01L, ML7), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML14, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH14, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML14), bit32.band(bit32.bor(V01L, ML14), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML12, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH12, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML12), bit32.band(bit32.bor(V02L, ML12), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML1, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH1, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML1), bit32.band(bit32.bor(V02L, ML1), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML3, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH3, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML3), bit32.band(bit32.bor(V03L, ML3), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML9, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH9, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML9), bit32.band(bit32.bor(V03L, ML9), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V00L + ML5, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH5, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML5), bit32.band(bit32.bor(V00L, ML5), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML0, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH0, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML0), bit32.band(bit32.bor(V00L, ML0), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML15, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH15, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML15), bit32.band(bit32.bor(V01L, ML15), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML4, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH4, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML4), bit32.band(bit32.bor(V01L, ML4), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML8, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH8, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML8), bit32.band(bit32.bor(V02L, ML8), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML6, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH6, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML6), bit32.band(bit32.bor(V02L, ML6), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML2, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH2, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML2), bit32.band(bit32.bor(V03L, ML2), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML10, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH10, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML10), bit32.band(bit32.bor(V03L, ML10), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
		end
		do
			do
			local S1 = bit32.bor(V00L + ML6, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH6, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML6), bit32.band(bit32.bor(V00L, ML6), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML15, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH15, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML15), bit32.band(bit32.bor(V00L, ML15), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML14, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH14, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML14), bit32.band(bit32.bor(V01L, ML14), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML9, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH9, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML9), bit32.band(bit32.bor(V01L, ML9), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML11, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH11, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML11), bit32.band(bit32.bor(V02L, ML11), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML3, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH3, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML3), bit32.band(bit32.bor(V02L, ML3), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML0, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH0, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML0), bit32.band(bit32.bor(V03L, ML0), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML8, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH8, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML8), bit32.band(bit32.bor(V03L, ML8), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V00L + ML12, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH12, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML12), bit32.band(bit32.bor(V00L, ML12), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML2, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH2, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML2), bit32.band(bit32.bor(V00L, ML2), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML13, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH13, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML13), bit32.band(bit32.bor(V01L, ML13), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML7, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH7, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML7), bit32.band(bit32.bor(V01L, ML7), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML1, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH1, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML1), bit32.band(bit32.bor(V02L, ML1), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML4, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH4, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML4), bit32.band(bit32.bor(V02L, ML4), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML10, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH10, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML10), bit32.band(bit32.bor(V03L, ML10), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML5, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH5, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML5), bit32.band(bit32.bor(V03L, ML5), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
		end
		do
			do
			local S1 = bit32.bor(V00L + ML10, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH10, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML10), bit32.band(bit32.bor(V00L, ML10), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML2, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH2, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML2), bit32.band(bit32.bor(V00L, ML2), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML8, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH8, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML8), bit32.band(bit32.bor(V01L, ML8), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML4, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH4, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML4), bit32.band(bit32.bor(V01L, ML4), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML7, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH7, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML7), bit32.band(bit32.bor(V02L, ML7), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML6, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH6, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML6), bit32.band(bit32.bor(V02L, ML6), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML1, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH1, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML1), bit32.band(bit32.bor(V03L, ML1), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML5, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH5, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML5), bit32.band(bit32.bor(V03L, ML5), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V00L + ML15, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH15, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML15), bit32.band(bit32.bor(V00L, ML15), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML11, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH11, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML11), bit32.band(bit32.bor(V00L, ML11), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML9, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH9, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML9), bit32.band(bit32.bor(V01L, ML9), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML14, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH14, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML14), bit32.band(bit32.bor(V01L, ML14), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML3, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH3, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML3), bit32.band(bit32.bor(V02L, ML3), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML12, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH12, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML12), bit32.band(bit32.bor(V02L, ML12), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML13, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH13, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML13), bit32.band(bit32.bor(V03L, ML13), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML0, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH0, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML0), bit32.band(bit32.bor(V03L, ML0), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
		end
		do
			do
			local S1 = bit32.bor(V00L + ML0, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH0, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML0), bit32.band(bit32.bor(V00L, ML0), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML1, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH1, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML1), bit32.band(bit32.bor(V00L, ML1), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML2, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH2, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML2), bit32.band(bit32.bor(V01L, ML2), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML3, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH3, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML3), bit32.band(bit32.bor(V01L, ML3), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML4, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH4, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML4), bit32.band(bit32.bor(V02L, ML4), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML5, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH5, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML5), bit32.band(bit32.bor(V02L, ML5), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML6, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH6, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML6), bit32.band(bit32.bor(V03L, ML6), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML7, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH7, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML7), bit32.band(bit32.bor(V03L, ML7), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V00L + ML8, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH8, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML8), bit32.band(bit32.bor(V00L, ML8), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML9, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH9, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML9), bit32.band(bit32.bor(V00L, ML9), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML10, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH10, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML10), bit32.band(bit32.bor(V01L, ML10), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML11, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH11, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML11), bit32.band(bit32.bor(V01L, ML11), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML12, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH12, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML12), bit32.band(bit32.bor(V02L, ML12), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML13, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH13, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML13), bit32.band(bit32.bor(V02L, ML13), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML14, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH14, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML14), bit32.band(bit32.bor(V03L, ML14), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML15, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH15, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML15), bit32.band(bit32.bor(V03L, ML15), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
		end
		do
			do
			local S1 = bit32.bor(V00L + ML14, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH14, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML14), bit32.band(bit32.bor(V00L, ML14), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML10, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH10, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML10), bit32.band(bit32.bor(V00L, ML10), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V12H, V00H), bit32.bxor(V12L, V00L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V12L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V12L), bit32.band(bit32.bor(V08L, V12L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V04H, V08H), bit32.bxor(V04L, V08L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML4, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH4, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML4), bit32.band(bit32.bor(V01L, ML4), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML8, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH8, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML8), bit32.band(bit32.bor(V01L, ML8), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V13H, V01H), bit32.bxor(V13L, V01L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V13L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V13L), bit32.band(bit32.bor(V09L, V13L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V05H, V09H), bit32.bxor(V05L, V09L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML9, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH9, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML9), bit32.band(bit32.bor(V02L, ML9), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML15, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH15, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML15), bit32.band(bit32.bor(V02L, ML15), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V14H, V02H), bit32.bxor(V14L, V02L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V14L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V14L), bit32.band(bit32.bor(V10L, V14L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V06H, V10H), bit32.bxor(V06L, V10L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML13, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH13, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML13), bit32.band(bit32.bor(V03L, ML13), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML6, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH6, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML6), bit32.band(bit32.bor(V03L, ML6), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V15H, V03H), bit32.bxor(V15L, V03L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V15L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V15L), bit32.band(bit32.bor(V11L, V15L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V07H, V11H), bit32.bxor(V07L, V11L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V00L + ML1, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH1, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML1), bit32.band(bit32.bor(V00L, ML1), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH32, XL32 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H, V15L = XL32, XH32
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH24, XL24 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V05L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V00L + ML12, 0)
			local H1 = bit32.bor(bit32.bor(V00H + MH12, 0) + bit32.rshift(bit32.bor(bit32.band(V00L, ML12), bit32.band(bit32.bor(V00L, ML12), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V05L, 0)
			V00H = bit32.bor(bit32.bor(H1 + V05H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V05L), bit32.band(bit32.bor(S1, V05L), bit32.bnot(S2))), 31), 0)
			V00L = S2
			local XH16, XL16 = bit32.bxor(V15H, V00H), bit32.bxor(V15L, V00L)
			V15H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V15L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V10L + V15L, 0)
			V10H = bit32.bor(bit32.bor(V10H + V15H, 0) + bit32.rshift(bit32.bor(bit32.band(V10L, V15L), bit32.band(bit32.bor(V10L, V15L), bit32.bnot(T))), 31), 0)
			V10L = T
			local XH63, XL63 = bit32.bxor(V05H, V10H), bit32.bxor(V05L, V10L)
			V05H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V05L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V01L + ML0, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH0, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML0), bit32.band(bit32.bor(V01L, ML0), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH32, XL32 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H, V12L = XL32, XH32
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH24, XL24 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V06L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V01L + ML2, 0)
			local H1 = bit32.bor(bit32.bor(V01H + MH2, 0) + bit32.rshift(bit32.bor(bit32.band(V01L, ML2), bit32.band(bit32.bor(V01L, ML2), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V06L, 0)
			V01H = bit32.bor(bit32.bor(H1 + V06H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V06L), bit32.band(bit32.bor(S1, V06L), bit32.bnot(S2))), 31), 0)
			V01L = S2
			local XH16, XL16 = bit32.bxor(V12H, V01H), bit32.bxor(V12L, V01L)
			V12H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V12L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V11L + V12L, 0)
			V11H = bit32.bor(bit32.bor(V11H + V12H, 0) + bit32.rshift(bit32.bor(bit32.band(V11L, V12L), bit32.band(bit32.bor(V11L, V12L), bit32.bnot(T))), 31), 0)
			V11L = T
			local XH63, XL63 = bit32.bxor(V06H, V11H), bit32.bxor(V06L, V11L)
			V06H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V06L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V02L + ML11, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH11, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML11), bit32.band(bit32.bor(V02L, ML11), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH32, XL32 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H, V13L = XL32, XH32
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH24, XL24 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V07L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V02L + ML7, 0)
			local H1 = bit32.bor(bit32.bor(V02H + MH7, 0) + bit32.rshift(bit32.bor(bit32.band(V02L, ML7), bit32.band(bit32.bor(V02L, ML7), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V07L, 0)
			V02H = bit32.bor(bit32.bor(H1 + V07H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V07L), bit32.band(bit32.bor(S1, V07L), bit32.bnot(S2))), 31), 0)
			V02L = S2
			local XH16, XL16 = bit32.bxor(V13H, V02H), bit32.bxor(V13L, V02L)
			V13H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V13L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V08L + V13L, 0)
			V08H = bit32.bor(bit32.bor(V08H + V13H, 0) + bit32.rshift(bit32.bor(bit32.band(V08L, V13L), bit32.band(bit32.bor(V08L, V13L), bit32.bnot(T))), 31), 0)
			V08L = T
			local XH63, XL63 = bit32.bxor(V07H, V08H), bit32.bxor(V07L, V08L)
			V07H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V07L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
			do
			local S1 = bit32.bor(V03L + ML5, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH5, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML5), bit32.band(bit32.bor(V03L, ML5), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH32, XL32 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H, V14L = XL32, XH32
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH24, XL24 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.rshift(XH24, 24), bit32.lshift(XL24, 8))
			V04L = bit32.bor(bit32.rshift(XL24, 24), bit32.lshift(XH24, 8))
			end
			do
			local S1 = bit32.bor(V03L + ML3, 0)
			local H1 = bit32.bor(bit32.bor(V03H + MH3, 0) + bit32.rshift(bit32.bor(bit32.band(V03L, ML3), bit32.band(bit32.bor(V03L, ML3), bit32.bnot(S1))), 31), 0)
			local S2 = bit32.bor(S1 + V04L, 0)
			V03H = bit32.bor(bit32.bor(H1 + V04H, 0) + bit32.rshift(bit32.bor(bit32.band(S1, V04L), bit32.band(bit32.bor(S1, V04L), bit32.bnot(S2))), 31), 0)
			V03L = S2
			local XH16, XL16 = bit32.bxor(V14H, V03H), bit32.bxor(V14L, V03L)
			V14H = bit32.bor(bit32.rshift(XH16, 16), bit32.lshift(XL16, 16))
			V14L = bit32.bor(bit32.rshift(XL16, 16), bit32.lshift(XH16, 16))
			local T = bit32.bor(V09L + V14L, 0)
			V09H = bit32.bor(bit32.bor(V09H + V14H, 0) + bit32.rshift(bit32.bor(bit32.band(V09L, V14L), bit32.band(bit32.bor(V09L, V14L), bit32.bnot(T))), 31), 0)
			V09L = T
			local XH63, XL63 = bit32.bxor(V04H, V09H), bit32.bxor(V04L, V09L)
			V04H = bit32.bor(bit32.lshift(XH63, 1), bit32.rshift(XL63, 31))
			V04L = bit32.bor(bit32.lshift(XL63, 1), bit32.rshift(XH63, 31))
			end
		end
		H0H = bit32.bxor(H0H, V00H, V08H)
		H0L = bit32.bxor(H0L, V00L, V08L)
		H1H = bit32.bxor(H1H, V01H, V09H)
		H1L = bit32.bxor(H1L, V01L, V09L)
		H2H = bit32.bxor(H2H, V02H, V10H)
		H2L = bit32.bxor(H2L, V02L, V10L)
		H3H = bit32.bxor(H3H, V03H, V11H)
		H3L = bit32.bxor(H3L, V03L, V11L)
		H4H = bit32.bxor(H4H, V04H, V12H)
		H4L = bit32.bxor(H4L, V04L, V12L)
		H5H = bit32.bxor(H5H, V05H, V13H)
		H5L = bit32.bxor(H5L, V05L, V13L)
		H6H = bit32.bxor(H6H, V06H, V14H)
		H6L = bit32.bxor(H6L, V06L, V14L)
		H7H = bit32.bxor(H7H, V07H, V15H)
		H7L = bit32.bxor(H7L, V07L, V15L)
	end
	buffer.writeu32(State, 0, H0L); buffer.writeu32(State, 4, H0H)
	buffer.writeu32(State, 8, H1L); buffer.writeu32(State, 12, H1H)
	buffer.writeu32(State, 16, H2L); buffer.writeu32(State, 20, H2H)
	buffer.writeu32(State, 24, H3L); buffer.writeu32(State, 28, H3H)
	buffer.writeu32(State, 32, H4L); buffer.writeu32(State, 36, H4H)
	buffer.writeu32(State, 40, H5L); buffer.writeu32(State, 44, H5H)
	buffer.writeu32(State, 48, H6L); buffer.writeu32(State, 52, H6H)
	buffer.writeu32(State, 56, H7L); buffer.writeu32(State, 60, H7H)
end

local function HashDigest(InputData: buffer, OutputLength: number, KeyData: buffer?): buffer
	local State = STATE
	local KeyLength = if KeyData then buffer.len(KeyData) else 0
	buffer.writeu32(State, 0, bit32.bxor(0xf3bcc908, 0x01010000, KeyLength * 256, OutputLength))
	buffer.writeu32(State, 4, 0x6a09e667)
	buffer.writeu32(State, 8, 0x84caa73b)
	buffer.writeu32(State, 12, 0xbb67ae85)
	buffer.writeu32(State, 16, 0xfe94f82b)
	buffer.writeu32(State, 20, 0x3c6ef372)
	buffer.writeu32(State, 24, 0x5f1d36f1)
	buffer.writeu32(State, 28, 0xa54ff53a)
	buffer.writeu32(State, 32, 0xade682d1)
	buffer.writeu32(State, 36, 0x510e527f)
	buffer.writeu32(State, 40, 0x2b3e6c1f)
	buffer.writeu32(State, 44, 0x9b05688c)
	buffer.writeu32(State, 48, 0xfb41bd6b)
	buffer.writeu32(State, 52, 0x1f83d9ab)
	buffer.writeu32(State, 56, 0x137e2179)
	buffer.writeu32(State, 60, 0x5be0cd19)
	local DataLength = buffer.len(InputData)
	local Final = FINAL_BLOCK
	local Counter = 0

	if KeyData and KeyLength > 0 then
		buffer.fill(Final, 0, 0, BLOCK_SIZE_BYTES)
		buffer.copy(Final, 0, KeyData, 0, KeyLength)
		Counter = BLOCK_SIZE_BYTES
		Compress(State, Final, 0, 1, Counter, DataLength == 0)
	end

	if KeyLength == 0 or DataLength > 0 then
		local LastLength = if DataLength == 0 then 0 else (DataLength - 1) % BLOCK_SIZE_BYTES + 1
		local FullBlocks = (DataLength - LastLength) // BLOCK_SIZE_BYTES

		if FullBlocks > 0 then
			Compress(State, InputData, 0, FullBlocks, Counter + BLOCK_SIZE_BYTES, false)
			Counter += FullBlocks * BLOCK_SIZE_BYTES
		end

		buffer.fill(Final, 0, 0, BLOCK_SIZE_BYTES)
		if LastLength > 0 then
			buffer.copy(Final, 0, InputData, DataLength - LastLength, LastLength)
		end
		Compress(State, Final, 0, 1, Counter + LastLength, true)
	end

	local Digest = buffer.create(OutputLength)
	buffer.copy(Digest, 0, State, 0, OutputLength)

	return Digest
end

return {
	Digest = HashDigest,
}
