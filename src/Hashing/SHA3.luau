--[=[
	Cryptography library: Keccak/SHA-3

	Sizes:
		SHA3-224 Digest: 28 bytes
		SHA3-256 Digest: 32 bytes
		SHA3-384 Digest: 48 bytes
		SHA3-512 Digest: 64 bytes
		SHAKE128 Digest: variable
		SHAKE256 Digest: variable

	Return type: (string, buffer)
	Example usage:
		local Message = buffer.fromstring("Hello World")

		local Hash1, HashBuffer1 = SHA3.SHA3_256(Message)
		local Hash2, HashBuffer2 = SHA3.SHAKE128(Message, 32)
--]=]

--!strict
--!optimize 2
--!native

local Conversions = require("../Utilities/Conversions")
local ToHex = Conversions.ToHex

local SHA3 = {}

local WORK: buffer = buffer.create(432)
buffer.writestring(WORK, 240,
	"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x89\x00\x00\x00" ..
	"\x00\x00\x00\x00\x8B\x00\x00\x80\x00\x00\x00\x00\x80\x80\x00\x80" ..
	"\x01\x00\x00\x00\x8B\x00\x00\x00\x01\x00\x00\x00\x00\x80\x00\x00" ..
	"\x01\x00\x00\x00\x88\x80\x00\x80\x01\x00\x00\x00\x82\x00\x00\x80" ..
	"\x00\x00\x00\x00\x0B\x00\x00\x00\x00\x00\x00\x00\x0A\x00\x00\x00" ..
	"\x01\x00\x00\x00\x82\x80\x00\x00\x00\x00\x00\x00\x03\x80\x00\x00" ..
	"\x01\x00\x00\x00\x8B\x80\x00\x00\x01\x00\x00\x00\x0B\x00\x00\x80" ..
	"\x01\x00\x00\x00\x8A\x00\x00\x80\x01\x00\x00\x00\x81\x00\x00\x80" ..
	"\x00\x00\x00\x00\x81\x00\x00\x80\x00\x00\x00\x00\x08\x00\x00\x80" ..
	"\x00\x00\x00\x00\x83\x00\x00\x00\x00\x00\x00\x00\x03\x80\x00\x80" ..
	"\x01\x00\x00\x00\x88\x80\x00\x80\x00\x00\x00\x00\x88\x00\x00\x80" ..
	"\x01\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x82\x80\x00\x80"
)

local STATE_A: buffer = buffer.create(100)
local STATE_B: buffer = buffer.create(100)

local function ZeroState(StateA: buffer, StateB: buffer)
	buffer.writef64(StateA, 0, 0); buffer.writef64(StateA, 8, 0); buffer.writef64(StateA, 16, 0); buffer.writef64(StateA, 24, 0)
	buffer.writef64(StateA, 32, 0); buffer.writef64(StateA, 40, 0); buffer.writef64(StateA, 48, 0); buffer.writef64(StateA, 56, 0)
	buffer.writef64(StateA, 64, 0); buffer.writef64(StateA, 72, 0); buffer.writef64(StateA, 80, 0); buffer.writef64(StateA, 88, 0)
	buffer.writeu32(StateA, 96, 0)
	buffer.writef64(StateB, 0, 0); buffer.writef64(StateB, 8, 0); buffer.writef64(StateB, 16, 0); buffer.writef64(StateB, 24, 0)
	buffer.writef64(StateB, 32, 0); buffer.writef64(StateB, 40, 0); buffer.writef64(StateB, 48, 0); buffer.writef64(StateB, 56, 0)
	buffer.writef64(StateB, 64, 0); buffer.writef64(StateB, 72, 0); buffer.writef64(StateB, 80, 0); buffer.writef64(StateB, 88, 0)
	buffer.writeu32(StateB, 96, 0)
end

local function Permute(StateA: buffer, StateB: buffer)
	local Work: buffer = WORK
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
	for RoundIndex = 240, 416, 16 do
		do
			local CA0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(StateA, 20), buffer.readu32(StateA, 40), buffer.readu32(StateA, 60), buffer.readu32(StateA, 80))
			local CA1 = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(StateA, 24), buffer.readu32(StateA, 44), buffer.readu32(StateA, 64), buffer.readu32(StateA, 84))
			local CA2 = bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(StateA, 28), buffer.readu32(StateA, 48), buffer.readu32(StateA, 68), buffer.readu32(StateA, 88))
			local CA3 = bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(StateA, 32), buffer.readu32(StateA, 52), buffer.readu32(StateA, 72), buffer.readu32(StateA, 92))
			local CA4 = bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(StateA, 36), buffer.readu32(StateA, 56), buffer.readu32(StateA, 76), buffer.readu32(StateA, 96))
			do
				local CB = bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(StateB, 20), buffer.readu32(StateB, 40), buffer.readu32(StateB, 60), buffer.readu32(StateB, 80))
				buffer.writeu32(Work, 16, bit32.bxor(CA3, bit32.lrotate(CB, 1)))
				buffer.writeu32(Work, 24, bit32.bxor(CB, CA2))
			end
			do
				local CB = bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(StateB, 24), buffer.readu32(StateB, 44), buffer.readu32(StateB, 64), buffer.readu32(StateB, 84))
				buffer.writeu32(Work, 0, bit32.bxor(CA4, bit32.lrotate(CB, 1)))
				buffer.writeu32(Work, 28, bit32.bxor(CB, CA3))
			end
			do
				local CB = bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(StateB, 28), buffer.readu32(StateB, 48), buffer.readu32(StateB, 68), buffer.readu32(StateB, 88))
				buffer.writeu32(Work, 4, bit32.bxor(CA0, bit32.lrotate(CB, 1)))
				buffer.writeu32(Work, 32, bit32.bxor(CB, CA4))
			end
			do
				local CB = bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(StateB, 32), buffer.readu32(StateB, 52), buffer.readu32(StateB, 72), buffer.readu32(StateB, 92))
				buffer.writeu32(Work, 8, bit32.bxor(CA1, bit32.lrotate(CB, 1)))
				buffer.writeu32(Work, 36, bit32.bxor(CB, CA0))
			end
			do
				local CB = bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(StateB, 36), buffer.readu32(StateB, 56), buffer.readu32(StateB, 76), buffer.readu32(StateB, 96))
				buffer.writeu32(Work, 12, bit32.bxor(CA2, bit32.lrotate(CB, 1)))
				buffer.writeu32(Work, 20, bit32.bxor(CB, CA1))
			end
			if RoundIndex < 0 then break end
			do
				local P0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(Work, 0))
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 24), buffer.readu32(Work, 4)), 22)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 48), buffer.readu32(Work, 28)), 22)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 72), buffer.readu32(Work, 32)), 11)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 96), buffer.readu32(Work, 16)), 7)
				buffer.writeu32(Work, 40, bit32.bxor(P0, bit32.bor(P1, P2), buffer.readu32(Work, RoundIndex)))
				buffer.writeu32(Work, 44, bit32.bxor(P1, bit32.bor(bit32.bnot(P2), P3)))
				buffer.writeu32(Work, 48, bit32.bxor(P2, bit32.band(P3, P4)))
				buffer.writeu32(Work, 52, bit32.bxor(P3, bit32.bor(P4, P0)))
				buffer.writeu32(Work, 56, bit32.bxor(P4, bit32.band(P0, P1)))
			end
			do
				local P0 = bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(Work, 20))
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 24), buffer.readu32(Work, 24)), 22)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 48), buffer.readu32(Work, 8)), 21)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 72), buffer.readu32(Work, 12)), 10)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 96), buffer.readu32(Work, 36)), 7)
				buffer.writeu32(Work, 140, bit32.bxor(P0, bit32.bor(P1, P2), buffer.readu32(Work, RoundIndex + 4)))
				buffer.writeu32(Work, 144, bit32.bxor(P1, bit32.bor(bit32.bnot(P2), P3)))
				buffer.writeu32(Work, 148, bit32.bxor(P2, bit32.band(P3, P4)))
				buffer.writeu32(Work, 152, bit32.bxor(P3, bit32.bor(P4, P0)))
				buffer.writeu32(Work, 156, bit32.bxor(P4, bit32.band(P0, P1)))
			end
			do
				local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(Work, 12)), 14)
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 36), buffer.readu32(Work, 16)), 10)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 40), buffer.readu32(Work, 20)), 2)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 64), buffer.readu32(Work, 24)), 23)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 88), buffer.readu32(Work, 28)), 31)
				buffer.writeu32(Work, 60, bit32.bxor(P0, bit32.bor(P1, P2)))
				buffer.writeu32(Work, 64, bit32.bxor(P1, bit32.band(P2, P3)))
				buffer.writeu32(Work, 68, bit32.bxor(P2, bit32.bor(P3, bit32.bnot(P4))))
				buffer.writeu32(Work, 72, bit32.bxor(P3, bit32.bor(P4, P0)))
				buffer.writeu32(Work, 76, bit32.bxor(P4, bit32.band(P0, P1)))
			end
			do
				local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(Work, 32)), 14)
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 36), buffer.readu32(Work, 36)), 10)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 40), buffer.readu32(Work, 0)), 1)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 64), buffer.readu32(Work, 4)), 22)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 88), buffer.readu32(Work, 8)), 30)
				buffer.writeu32(Work, 160, bit32.bxor(P0, bit32.bor(P1, P2)))
				buffer.writeu32(Work, 164, bit32.bxor(P1, bit32.band(P2, P3)))
				buffer.writeu32(Work, 168, bit32.bxor(P2, bit32.bor(P3, bit32.bnot(P4))))
				buffer.writeu32(Work, 172, bit32.bxor(P3, bit32.bor(P4, P0)))
				buffer.writeu32(Work, 176, bit32.bxor(P4, bit32.band(P0, P1)))
			end
			do
				local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(Work, 24)), 1)
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 28), buffer.readu32(Work, 8)), 3)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 52), buffer.readu32(Work, 32)), 13)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 76), buffer.readu32(Work, 16)), 4)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 80), buffer.readu32(Work, 0)), 9)
				buffer.writeu32(Work, 80, bit32.bxor(P0, bit32.bor(P1, P2)))
				buffer.writeu32(Work, 84, bit32.bxor(P1, bit32.band(P2, P3)))
				buffer.writeu32(Work, 88, bit32.bxor(P2, bit32.band(bit32.bnot(P3), P4)))
				buffer.writeu32(Work, 92, bit32.bxor(bit32.bnot(P3), bit32.bor(P4, P0)))
				buffer.writeu32(Work, 96, bit32.bxor(P4, bit32.band(P0, P1)))
			end
			do
				local P0 = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(Work, 4))
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 28), buffer.readu32(Work, 28)), 3)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 52), buffer.readu32(Work, 12)), 12)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 76), buffer.readu32(Work, 36)), 4)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 80), buffer.readu32(Work, 20)), 9)
				buffer.writeu32(Work, 180, bit32.bxor(P0, bit32.bor(P1, P2)))
				buffer.writeu32(Work, 184, bit32.bxor(P1, bit32.band(P2, P3)))
				buffer.writeu32(Work, 188, bit32.bxor(P2, bit32.band(bit32.bnot(P3), P4)))
				buffer.writeu32(Work, 192, bit32.bxor(bit32.bnot(P3), bit32.bor(P4, P0)))
				buffer.writeu32(Work, 196, bit32.bxor(P4, bit32.band(P0, P1)))
			end
			do
				local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(Work, 36)), 14)
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 20), buffer.readu32(Work, 0)), 18)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 44), buffer.readu32(Work, 4)), 5)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 68), buffer.readu32(Work, 28)), 8)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 92), buffer.readu32(Work, 12)), 28)
				buffer.writeu32(Work, 100, bit32.bxor(P0, bit32.band(P1, P2)))
				buffer.writeu32(Work, 104, bit32.bxor(P1, bit32.bor(P2, P3)))
				buffer.writeu32(Work, 108, bit32.bxor(P2, bit32.bor(bit32.bnot(P3), P4)))
				buffer.writeu32(Work, 112, bit32.bxor(bit32.bnot(P3), bit32.band(P4, P0)))
				buffer.writeu32(Work, 116, bit32.bxor(P4, bit32.bor(P0, P1)))
			end
			do
				local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(Work, 16)), 13)
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 20), buffer.readu32(Work, 20)), 18)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 44), buffer.readu32(Work, 24)), 5)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 68), buffer.readu32(Work, 8)), 7)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 92), buffer.readu32(Work, 32)), 28)
				buffer.writeu32(Work, 200, bit32.bxor(P0, bit32.band(P1, P2)))
				buffer.writeu32(Work, 204, bit32.bxor(P1, bit32.bor(P2, P3)))
				buffer.writeu32(Work, 208, bit32.bxor(P2, bit32.bor(bit32.bnot(P3), P4)))
				buffer.writeu32(Work, 212, bit32.bxor(bit32.bnot(P3), bit32.band(P4, P0)))
				buffer.writeu32(Work, 216, bit32.bxor(P4, bit32.bor(P0, P1)))
			end
			do
				local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(Work, 8)), 31)
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 32), buffer.readu32(Work, 32)), 28)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 56), buffer.readu32(Work, 36)), 20)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 60), buffer.readu32(Work, 20)), 21)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 84), buffer.readu32(Work, 4)), 1)
				buffer.writeu32(Work, 120, bit32.bxor(P0, bit32.band(bit32.bnot(P1), P2)))
				buffer.writeu32(Work, 124, bit32.bxor(bit32.bnot(P1), bit32.bor(P2, P3)))
				buffer.writeu32(Work, 128, bit32.bxor(P2, bit32.band(P3, P4)))
				buffer.writeu32(Work, 132, bit32.bxor(P3, bit32.bor(P4, P0)))
				buffer.writeu32(Work, 136, bit32.bxor(P4, bit32.band(P0, P1)))
			end
			do
				local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(Work, 28)), 31)
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 32), buffer.readu32(Work, 12)), 27)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 56), buffer.readu32(Work, 16)), 19)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 60), buffer.readu32(Work, 0)), 20)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 84), buffer.readu32(Work, 24)), 1)
				buffer.writeu32(Work, 220, bit32.bxor(P0, bit32.band(bit32.bnot(P1), P2)))
				buffer.writeu32(Work, 224, bit32.bxor(bit32.bnot(P1), bit32.bor(P2, P3)))
				buffer.writeu32(Work, 228, bit32.bxor(P2, bit32.band(P3, P4)))
				buffer.writeu32(Work, 232, bit32.bxor(P3, bit32.bor(P4, P0)))
				buffer.writeu32(Work, 236, bit32.bxor(P4, bit32.band(P0, P1)))
			end
		end
		if RoundIndex < 0 then break end
		do
			local CA0 = bit32.bxor(buffer.readu32(Work, 40), buffer.readu32(Work, 60), buffer.readu32(Work, 80), buffer.readu32(Work, 100), buffer.readu32(Work, 120))
			local CA1 = bit32.bxor(buffer.readu32(Work, 44), buffer.readu32(Work, 64), buffer.readu32(Work, 84), buffer.readu32(Work, 104), buffer.readu32(Work, 124))
			local CA2 = bit32.bxor(buffer.readu32(Work, 48), buffer.readu32(Work, 68), buffer.readu32(Work, 88), buffer.readu32(Work, 108), buffer.readu32(Work, 128))
			local CA3 = bit32.bxor(buffer.readu32(Work, 52), buffer.readu32(Work, 72), buffer.readu32(Work, 92), buffer.readu32(Work, 112), buffer.readu32(Work, 132))
			local CA4 = bit32.bxor(buffer.readu32(Work, 56), buffer.readu32(Work, 76), buffer.readu32(Work, 96), buffer.readu32(Work, 116), buffer.readu32(Work, 136))
			do
				local CB = bit32.bxor(buffer.readu32(Work, 140), buffer.readu32(Work, 160), buffer.readu32(Work, 180), buffer.readu32(Work, 200), buffer.readu32(Work, 220))
				buffer.writeu32(Work, 16, bit32.bxor(CA3, bit32.lrotate(CB, 1)))
				buffer.writeu32(Work, 24, bit32.bxor(CB, CA2))
			end
			do
				local CB = bit32.bxor(buffer.readu32(Work, 144), buffer.readu32(Work, 164), buffer.readu32(Work, 184), buffer.readu32(Work, 204), buffer.readu32(Work, 224))
				buffer.writeu32(Work, 0, bit32.bxor(CA4, bit32.lrotate(CB, 1)))
				buffer.writeu32(Work, 28, bit32.bxor(CB, CA3))
			end
			do
				local CB = bit32.bxor(buffer.readu32(Work, 148), buffer.readu32(Work, 168), buffer.readu32(Work, 188), buffer.readu32(Work, 208), buffer.readu32(Work, 228))
				buffer.writeu32(Work, 4, bit32.bxor(CA0, bit32.lrotate(CB, 1)))
				buffer.writeu32(Work, 32, bit32.bxor(CB, CA4))
			end
			do
				local CB = bit32.bxor(buffer.readu32(Work, 152), buffer.readu32(Work, 172), buffer.readu32(Work, 192), buffer.readu32(Work, 212), buffer.readu32(Work, 232))
				buffer.writeu32(Work, 8, bit32.bxor(CA1, bit32.lrotate(CB, 1)))
				buffer.writeu32(Work, 36, bit32.bxor(CB, CA0))
			end
			do
				local CB = bit32.bxor(buffer.readu32(Work, 156), buffer.readu32(Work, 176), buffer.readu32(Work, 196), buffer.readu32(Work, 216), buffer.readu32(Work, 236))
				buffer.writeu32(Work, 12, bit32.bxor(CA2, bit32.lrotate(CB, 1)))
				buffer.writeu32(Work, 20, bit32.bxor(CB, CA1))
			end
			if RoundIndex < 0 then break end
			do
				local P0 = bit32.bxor(buffer.readu32(Work, 40), buffer.readu32(Work, 0))
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 64), buffer.readu32(Work, 4)), 22)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 188), buffer.readu32(Work, 28)), 22)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 212), buffer.readu32(Work, 32)), 11)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 136), buffer.readu32(Work, 16)), 7)
				buffer.writeu32(StateA, 0, bit32.bxor(P0, bit32.bor(P1, P2), buffer.readu32(Work, RoundIndex + 8)))
				buffer.writeu32(StateA, 4, bit32.bxor(P1, bit32.bor(bit32.bnot(P2), P3)))
				buffer.writeu32(StateA, 8, bit32.bxor(P2, bit32.band(P3, P4)))
				buffer.writeu32(StateA, 12, bit32.bxor(P3, bit32.bor(P4, P0)))
				buffer.writeu32(StateA, 16, bit32.bxor(P4, bit32.band(P0, P1)))
			end
			do
				local P0 = bit32.bxor(buffer.readu32(Work, 140), buffer.readu32(Work, 20))
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 164), buffer.readu32(Work, 24)), 22)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 88), buffer.readu32(Work, 8)), 21)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 112), buffer.readu32(Work, 12)), 10)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 236), buffer.readu32(Work, 36)), 7)
				buffer.writeu32(StateB, 0, bit32.bxor(P0, bit32.bor(P1, P2), buffer.readu32(Work, RoundIndex + 12)))
				buffer.writeu32(StateB, 4, bit32.bxor(P1, bit32.bor(bit32.bnot(P2), P3)))
				buffer.writeu32(StateB, 8, bit32.bxor(P2, bit32.band(P3, P4)))
				buffer.writeu32(StateB, 12, bit32.bxor(P3, bit32.bor(P4, P0)))
				buffer.writeu32(StateB, 16, bit32.bxor(P4, bit32.band(P0, P1)))
			end
			do
				local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 52), buffer.readu32(Work, 12)), 14)
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 76), buffer.readu32(Work, 16)), 10)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 180), buffer.readu32(Work, 20)), 2)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 204), buffer.readu32(Work, 24)), 23)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 228), buffer.readu32(Work, 28)), 31)
				buffer.writeu32(StateA, 20, bit32.bxor(P0, bit32.bor(P1, P2)))
				buffer.writeu32(StateA, 24, bit32.bxor(P1, bit32.band(P2, P3)))
				buffer.writeu32(StateA, 28, bit32.bxor(P2, bit32.bor(P3, bit32.bnot(P4))))
				buffer.writeu32(StateA, 32, bit32.bxor(P3, bit32.bor(P4, P0)))
				buffer.writeu32(StateA, 36, bit32.bxor(P4, bit32.band(P0, P1)))
			end
			do
				local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 152), buffer.readu32(Work, 32)), 14)
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 176), buffer.readu32(Work, 36)), 10)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 80), buffer.readu32(Work, 0)), 1)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 104), buffer.readu32(Work, 4)), 22)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 128), buffer.readu32(Work, 8)), 30)
				buffer.writeu32(StateB, 20, bit32.bxor(P0, bit32.bor(P1, P2)))
				buffer.writeu32(StateB, 24, bit32.bxor(P1, bit32.band(P2, P3)))
				buffer.writeu32(StateB, 28, bit32.bxor(P2, bit32.bor(P3, bit32.bnot(P4))))
				buffer.writeu32(StateB, 32, bit32.bxor(P3, bit32.bor(P4, P0)))
				buffer.writeu32(StateB, 36, bit32.bxor(P4, bit32.band(P0, P1)))
			end
			do
				local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 144), buffer.readu32(Work, 24)), 1)
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 68), buffer.readu32(Work, 8)), 3)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 192), buffer.readu32(Work, 32)), 13)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 116), buffer.readu32(Work, 16)), 4)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 120), buffer.readu32(Work, 0)), 9)
				buffer.writeu32(StateA, 40, bit32.bxor(P0, bit32.bor(P1, P2)))
				buffer.writeu32(StateA, 44, bit32.bxor(P1, bit32.band(P2, P3)))
				buffer.writeu32(StateA, 48, bit32.bxor(P2, bit32.band(bit32.bnot(P3), P4)))
				buffer.writeu32(StateA, 52, bit32.bxor(bit32.bnot(P3), bit32.bor(P4, P0)))
				buffer.writeu32(StateA, 56, bit32.bxor(P4, bit32.band(P0, P1)))
			end
			do
				local P0 = bit32.bxor(buffer.readu32(Work, 44), buffer.readu32(Work, 4))
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 168), buffer.readu32(Work, 28)), 3)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 92), buffer.readu32(Work, 12)), 12)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 216), buffer.readu32(Work, 36)), 4)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 220), buffer.readu32(Work, 20)), 9)
				buffer.writeu32(StateB, 40, bit32.bxor(P0, bit32.bor(P1, P2)))
				buffer.writeu32(StateB, 44, bit32.bxor(P1, bit32.band(P2, P3)))
				buffer.writeu32(StateB, 48, bit32.bxor(P2, bit32.band(bit32.bnot(P3), P4)))
				buffer.writeu32(StateB, 52, bit32.bxor(bit32.bnot(P3), bit32.bor(P4, P0)))
				buffer.writeu32(StateB, 56, bit32.bxor(P4, bit32.band(P0, P1)))
			end
			do
				local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 156), buffer.readu32(Work, 36)), 14)
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 60), buffer.readu32(Work, 0)), 18)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 84), buffer.readu32(Work, 4)), 5)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 208), buffer.readu32(Work, 28)), 8)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 132), buffer.readu32(Work, 12)), 28)
				buffer.writeu32(StateA, 60, bit32.bxor(P0, bit32.band(P1, P2)))
				buffer.writeu32(StateA, 64, bit32.bxor(P1, bit32.bor(P2, P3)))
				buffer.writeu32(StateA, 68, bit32.bxor(P2, bit32.bor(bit32.bnot(P3), P4)))
				buffer.writeu32(StateA, 72, bit32.bxor(bit32.bnot(P3), bit32.band(P4, P0)))
				buffer.writeu32(StateA, 76, bit32.bxor(P4, bit32.bor(P0, P1)))
			end
			do
				local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 56), buffer.readu32(Work, 16)), 13)
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 160), buffer.readu32(Work, 20)), 18)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 184), buffer.readu32(Work, 24)), 5)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 108), buffer.readu32(Work, 8)), 7)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 232), buffer.readu32(Work, 32)), 28)
				buffer.writeu32(StateB, 60, bit32.bxor(P0, bit32.band(P1, P2)))
				buffer.writeu32(StateB, 64, bit32.bxor(P1, bit32.bor(P2, P3)))
				buffer.writeu32(StateB, 68, bit32.bxor(P2, bit32.bor(bit32.bnot(P3), P4)))
				buffer.writeu32(StateB, 72, bit32.bxor(bit32.bnot(P3), bit32.band(P4, P0)))
				buffer.writeu32(StateB, 76, bit32.bxor(P4, bit32.bor(P0, P1)))
			end
			do
				local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 48), buffer.readu32(Work, 8)), 31)
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 172), buffer.readu32(Work, 32)), 28)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 196), buffer.readu32(Work, 36)), 20)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 200), buffer.readu32(Work, 20)), 21)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 124), buffer.readu32(Work, 4)), 1)
				buffer.writeu32(StateA, 80, bit32.bxor(P0, bit32.band(bit32.bnot(P1), P2)))
				buffer.writeu32(StateA, 84, bit32.bxor(bit32.bnot(P1), bit32.bor(P2, P3)))
				buffer.writeu32(StateA, 88, bit32.bxor(P2, bit32.band(P3, P4)))
				buffer.writeu32(StateA, 92, bit32.bxor(P3, bit32.bor(P4, P0)))
				buffer.writeu32(StateA, 96, bit32.bxor(P4, bit32.band(P0, P1)))
			end
			do
				local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 148), buffer.readu32(Work, 28)), 31)
				local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 72), buffer.readu32(Work, 12)), 27)
				local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 96), buffer.readu32(Work, 16)), 19)
				local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 100), buffer.readu32(Work, 0)), 20)
				local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 224), buffer.readu32(Work, 24)), 1)
				buffer.writeu32(StateB, 80, bit32.bxor(P0, bit32.band(bit32.bnot(P1), P2)))
				buffer.writeu32(StateB, 84, bit32.bxor(bit32.bnot(P1), bit32.bor(P2, P3)))
				buffer.writeu32(StateB, 88, bit32.bxor(P2, bit32.band(P3, P4)))
				buffer.writeu32(StateB, 92, bit32.bxor(P3, bit32.bor(P4, P0)))
				buffer.writeu32(StateB, 96, bit32.bxor(P4, bit32.band(P0, P1)))
			end
		end
	end
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
end

local function Keccak(StateA: buffer, StateB: buffer, Input: buffer, Offset: number, Size: number, BlockSizeInBytes: number, Fresh: boolean?)
	local Work: buffer = WORK
	if Fresh then
		ZeroState(StateA, StateB)
	end
	if Size <= 0 then
		return
	end
	local RateLanes = BlockSizeInBytes // 8
	local EndUnroll = (RateLanes // 4) * 16
	local EndAll = RateLanes * 4
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
	for Position = Offset, Offset + Size - 1, BlockSizeInBytes do
		local Pos = Position
		local StateOff = 0
		while StateOff < EndUnroll do
			do
				local Lo, Hi = buffer.readu32(Input, Pos + 0), buffer.readu32(Input, Pos + 0 + 4)
				local T: number
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
				buffer.writeu32(StateA, StateOff + 0, bit32.bxor(buffer.readu32(StateA, StateOff + 0), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
				buffer.writeu32(StateB, StateOff + 0, bit32.bxor(buffer.readu32(StateB, StateOff + 0), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
			end
			do
				local Lo, Hi = buffer.readu32(Input, Pos + 8), buffer.readu32(Input, Pos + 8 + 4)
				local T: number
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
				buffer.writeu32(StateA, StateOff + 4, bit32.bxor(buffer.readu32(StateA, StateOff + 4), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
				buffer.writeu32(StateB, StateOff + 4, bit32.bxor(buffer.readu32(StateB, StateOff + 4), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
			end
			do
				local Lo, Hi = buffer.readu32(Input, Pos + 16), buffer.readu32(Input, Pos + 16 + 4)
				local T: number
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
				buffer.writeu32(StateA, StateOff + 8, bit32.bxor(buffer.readu32(StateA, StateOff + 8), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
				buffer.writeu32(StateB, StateOff + 8, bit32.bxor(buffer.readu32(StateB, StateOff + 8), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
			end
			do
				local Lo, Hi = buffer.readu32(Input, Pos + 24), buffer.readu32(Input, Pos + 24 + 4)
				local T: number
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
				buffer.writeu32(StateA, StateOff + 12, bit32.bxor(buffer.readu32(StateA, StateOff + 12), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
				buffer.writeu32(StateB, StateOff + 12, bit32.bxor(buffer.readu32(StateB, StateOff + 12), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
			end
			Pos += 32
			StateOff += 16
		end
		while StateOff < EndAll do
			do
				local Lo, Hi = buffer.readu32(Input, Pos), buffer.readu32(Input, Pos + 4)
				local T: number
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
				T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
				T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
				buffer.writeu32(StateA, StateOff, bit32.bxor(buffer.readu32(StateA, StateOff), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
				buffer.writeu32(StateB, StateOff, bit32.bxor(buffer.readu32(StateB, StateOff), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
			end
			Pos += 8
			StateOff += 4
		end
		for RoundIndex = 240, 416, 16 do
			do
				local CA0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(StateA, 20), buffer.readu32(StateA, 40), buffer.readu32(StateA, 60), buffer.readu32(StateA, 80))
				local CA1 = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(StateA, 24), buffer.readu32(StateA, 44), buffer.readu32(StateA, 64), buffer.readu32(StateA, 84))
				local CA2 = bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(StateA, 28), buffer.readu32(StateA, 48), buffer.readu32(StateA, 68), buffer.readu32(StateA, 88))
				local CA3 = bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(StateA, 32), buffer.readu32(StateA, 52), buffer.readu32(StateA, 72), buffer.readu32(StateA, 92))
				local CA4 = bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(StateA, 36), buffer.readu32(StateA, 56), buffer.readu32(StateA, 76), buffer.readu32(StateA, 96))
				do
					local CB = bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(StateB, 20), buffer.readu32(StateB, 40), buffer.readu32(StateB, 60), buffer.readu32(StateB, 80))
					buffer.writeu32(Work, 16, bit32.bxor(CA3, bit32.lrotate(CB, 1)))
					buffer.writeu32(Work, 24, bit32.bxor(CB, CA2))
				end
				do
					local CB = bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(StateB, 24), buffer.readu32(StateB, 44), buffer.readu32(StateB, 64), buffer.readu32(StateB, 84))
					buffer.writeu32(Work, 0, bit32.bxor(CA4, bit32.lrotate(CB, 1)))
					buffer.writeu32(Work, 28, bit32.bxor(CB, CA3))
				end
				do
					local CB = bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(StateB, 28), buffer.readu32(StateB, 48), buffer.readu32(StateB, 68), buffer.readu32(StateB, 88))
					buffer.writeu32(Work, 4, bit32.bxor(CA0, bit32.lrotate(CB, 1)))
					buffer.writeu32(Work, 32, bit32.bxor(CB, CA4))
				end
				do
					local CB = bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(StateB, 32), buffer.readu32(StateB, 52), buffer.readu32(StateB, 72), buffer.readu32(StateB, 92))
					buffer.writeu32(Work, 8, bit32.bxor(CA1, bit32.lrotate(CB, 1)))
					buffer.writeu32(Work, 36, bit32.bxor(CB, CA0))
				end
				do
					local CB = bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(StateB, 36), buffer.readu32(StateB, 56), buffer.readu32(StateB, 76), buffer.readu32(StateB, 96))
					buffer.writeu32(Work, 12, bit32.bxor(CA2, bit32.lrotate(CB, 1)))
					buffer.writeu32(Work, 20, bit32.bxor(CB, CA1))
				end
				if RoundIndex < 0 then break end
				do
					local P0 = bit32.bxor(buffer.readu32(StateA, 0), buffer.readu32(Work, 0))
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 24), buffer.readu32(Work, 4)), 22)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 48), buffer.readu32(Work, 28)), 22)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 72), buffer.readu32(Work, 32)), 11)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 96), buffer.readu32(Work, 16)), 7)
					buffer.writeu32(Work, 40, bit32.bxor(P0, bit32.bor(P1, P2), buffer.readu32(Work, RoundIndex)))
					buffer.writeu32(Work, 44, bit32.bxor(P1, bit32.bor(bit32.bnot(P2), P3)))
					buffer.writeu32(Work, 48, bit32.bxor(P2, bit32.band(P3, P4)))
					buffer.writeu32(Work, 52, bit32.bxor(P3, bit32.bor(P4, P0)))
					buffer.writeu32(Work, 56, bit32.bxor(P4, bit32.band(P0, P1)))
				end
				do
					local P0 = bit32.bxor(buffer.readu32(StateB, 0), buffer.readu32(Work, 20))
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 24), buffer.readu32(Work, 24)), 22)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 48), buffer.readu32(Work, 8)), 21)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 72), buffer.readu32(Work, 12)), 10)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 96), buffer.readu32(Work, 36)), 7)
					buffer.writeu32(Work, 140, bit32.bxor(P0, bit32.bor(P1, P2), buffer.readu32(Work, RoundIndex + 4)))
					buffer.writeu32(Work, 144, bit32.bxor(P1, bit32.bor(bit32.bnot(P2), P3)))
					buffer.writeu32(Work, 148, bit32.bxor(P2, bit32.band(P3, P4)))
					buffer.writeu32(Work, 152, bit32.bxor(P3, bit32.bor(P4, P0)))
					buffer.writeu32(Work, 156, bit32.bxor(P4, bit32.band(P0, P1)))
				end
				do
					local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 12), buffer.readu32(Work, 12)), 14)
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 36), buffer.readu32(Work, 16)), 10)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 40), buffer.readu32(Work, 20)), 2)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 64), buffer.readu32(Work, 24)), 23)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 88), buffer.readu32(Work, 28)), 31)
					buffer.writeu32(Work, 60, bit32.bxor(P0, bit32.bor(P1, P2)))
					buffer.writeu32(Work, 64, bit32.bxor(P1, bit32.band(P2, P3)))
					buffer.writeu32(Work, 68, bit32.bxor(P2, bit32.bor(P3, bit32.bnot(P4))))
					buffer.writeu32(Work, 72, bit32.bxor(P3, bit32.bor(P4, P0)))
					buffer.writeu32(Work, 76, bit32.bxor(P4, bit32.band(P0, P1)))
				end
				do
					local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 12), buffer.readu32(Work, 32)), 14)
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 36), buffer.readu32(Work, 36)), 10)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 40), buffer.readu32(Work, 0)), 1)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 64), buffer.readu32(Work, 4)), 22)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 88), buffer.readu32(Work, 8)), 30)
					buffer.writeu32(Work, 160, bit32.bxor(P0, bit32.bor(P1, P2)))
					buffer.writeu32(Work, 164, bit32.bxor(P1, bit32.band(P2, P3)))
					buffer.writeu32(Work, 168, bit32.bxor(P2, bit32.bor(P3, bit32.bnot(P4))))
					buffer.writeu32(Work, 172, bit32.bxor(P3, bit32.bor(P4, P0)))
					buffer.writeu32(Work, 176, bit32.bxor(P4, bit32.band(P0, P1)))
				end
				do
					local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 4), buffer.readu32(Work, 24)), 1)
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 28), buffer.readu32(Work, 8)), 3)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 52), buffer.readu32(Work, 32)), 13)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 76), buffer.readu32(Work, 16)), 4)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 80), buffer.readu32(Work, 0)), 9)
					buffer.writeu32(Work, 80, bit32.bxor(P0, bit32.bor(P1, P2)))
					buffer.writeu32(Work, 84, bit32.bxor(P1, bit32.band(P2, P3)))
					buffer.writeu32(Work, 88, bit32.bxor(P2, bit32.band(bit32.bnot(P3), P4)))
					buffer.writeu32(Work, 92, bit32.bxor(bit32.bnot(P3), bit32.bor(P4, P0)))
					buffer.writeu32(Work, 96, bit32.bxor(P4, bit32.band(P0, P1)))
				end
				do
					local P0 = bit32.bxor(buffer.readu32(StateA, 4), buffer.readu32(Work, 4))
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 28), buffer.readu32(Work, 28)), 3)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 52), buffer.readu32(Work, 12)), 12)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 76), buffer.readu32(Work, 36)), 4)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 80), buffer.readu32(Work, 20)), 9)
					buffer.writeu32(Work, 180, bit32.bxor(P0, bit32.bor(P1, P2)))
					buffer.writeu32(Work, 184, bit32.bxor(P1, bit32.band(P2, P3)))
					buffer.writeu32(Work, 188, bit32.bxor(P2, bit32.band(bit32.bnot(P3), P4)))
					buffer.writeu32(Work, 192, bit32.bxor(bit32.bnot(P3), bit32.bor(P4, P0)))
					buffer.writeu32(Work, 196, bit32.bxor(P4, bit32.band(P0, P1)))
				end
				do
					local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 16), buffer.readu32(Work, 36)), 14)
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 20), buffer.readu32(Work, 0)), 18)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 44), buffer.readu32(Work, 4)), 5)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 68), buffer.readu32(Work, 28)), 8)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 92), buffer.readu32(Work, 12)), 28)
					buffer.writeu32(Work, 100, bit32.bxor(P0, bit32.band(P1, P2)))
					buffer.writeu32(Work, 104, bit32.bxor(P1, bit32.bor(P2, P3)))
					buffer.writeu32(Work, 108, bit32.bxor(P2, bit32.bor(bit32.bnot(P3), P4)))
					buffer.writeu32(Work, 112, bit32.bxor(bit32.bnot(P3), bit32.band(P4, P0)))
					buffer.writeu32(Work, 116, bit32.bxor(P4, bit32.bor(P0, P1)))
				end
				do
					local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 16), buffer.readu32(Work, 16)), 13)
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 20), buffer.readu32(Work, 20)), 18)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 44), buffer.readu32(Work, 24)), 5)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 68), buffer.readu32(Work, 8)), 7)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 92), buffer.readu32(Work, 32)), 28)
					buffer.writeu32(Work, 200, bit32.bxor(P0, bit32.band(P1, P2)))
					buffer.writeu32(Work, 204, bit32.bxor(P1, bit32.bor(P2, P3)))
					buffer.writeu32(Work, 208, bit32.bxor(P2, bit32.bor(bit32.bnot(P3), P4)))
					buffer.writeu32(Work, 212, bit32.bxor(bit32.bnot(P3), bit32.band(P4, P0)))
					buffer.writeu32(Work, 216, bit32.bxor(P4, bit32.bor(P0, P1)))
				end
				do
					local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 8), buffer.readu32(Work, 8)), 31)
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 32), buffer.readu32(Work, 32)), 28)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 56), buffer.readu32(Work, 36)), 20)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 60), buffer.readu32(Work, 20)), 21)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 84), buffer.readu32(Work, 4)), 1)
					buffer.writeu32(Work, 120, bit32.bxor(P0, bit32.band(bit32.bnot(P1), P2)))
					buffer.writeu32(Work, 124, bit32.bxor(bit32.bnot(P1), bit32.bor(P2, P3)))
					buffer.writeu32(Work, 128, bit32.bxor(P2, bit32.band(P3, P4)))
					buffer.writeu32(Work, 132, bit32.bxor(P3, bit32.bor(P4, P0)))
					buffer.writeu32(Work, 136, bit32.bxor(P4, bit32.band(P0, P1)))
				end
				do
					local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 8), buffer.readu32(Work, 28)), 31)
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 32), buffer.readu32(Work, 12)), 27)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 56), buffer.readu32(Work, 16)), 19)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(StateA, 60), buffer.readu32(Work, 0)), 20)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(StateB, 84), buffer.readu32(Work, 24)), 1)
					buffer.writeu32(Work, 220, bit32.bxor(P0, bit32.band(bit32.bnot(P1), P2)))
					buffer.writeu32(Work, 224, bit32.bxor(bit32.bnot(P1), bit32.bor(P2, P3)))
					buffer.writeu32(Work, 228, bit32.bxor(P2, bit32.band(P3, P4)))
					buffer.writeu32(Work, 232, bit32.bxor(P3, bit32.bor(P4, P0)))
					buffer.writeu32(Work, 236, bit32.bxor(P4, bit32.band(P0, P1)))
				end
			end
			if RoundIndex < 0 then break end
			do
				local CA0 = bit32.bxor(buffer.readu32(Work, 40), buffer.readu32(Work, 60), buffer.readu32(Work, 80), buffer.readu32(Work, 100), buffer.readu32(Work, 120))
				local CA1 = bit32.bxor(buffer.readu32(Work, 44), buffer.readu32(Work, 64), buffer.readu32(Work, 84), buffer.readu32(Work, 104), buffer.readu32(Work, 124))
				local CA2 = bit32.bxor(buffer.readu32(Work, 48), buffer.readu32(Work, 68), buffer.readu32(Work, 88), buffer.readu32(Work, 108), buffer.readu32(Work, 128))
				local CA3 = bit32.bxor(buffer.readu32(Work, 52), buffer.readu32(Work, 72), buffer.readu32(Work, 92), buffer.readu32(Work, 112), buffer.readu32(Work, 132))
				local CA4 = bit32.bxor(buffer.readu32(Work, 56), buffer.readu32(Work, 76), buffer.readu32(Work, 96), buffer.readu32(Work, 116), buffer.readu32(Work, 136))
				do
					local CB = bit32.bxor(buffer.readu32(Work, 140), buffer.readu32(Work, 160), buffer.readu32(Work, 180), buffer.readu32(Work, 200), buffer.readu32(Work, 220))
					buffer.writeu32(Work, 16, bit32.bxor(CA3, bit32.lrotate(CB, 1)))
					buffer.writeu32(Work, 24, bit32.bxor(CB, CA2))
				end
				do
					local CB = bit32.bxor(buffer.readu32(Work, 144), buffer.readu32(Work, 164), buffer.readu32(Work, 184), buffer.readu32(Work, 204), buffer.readu32(Work, 224))
					buffer.writeu32(Work, 0, bit32.bxor(CA4, bit32.lrotate(CB, 1)))
					buffer.writeu32(Work, 28, bit32.bxor(CB, CA3))
				end
				do
					local CB = bit32.bxor(buffer.readu32(Work, 148), buffer.readu32(Work, 168), buffer.readu32(Work, 188), buffer.readu32(Work, 208), buffer.readu32(Work, 228))
					buffer.writeu32(Work, 4, bit32.bxor(CA0, bit32.lrotate(CB, 1)))
					buffer.writeu32(Work, 32, bit32.bxor(CB, CA4))
				end
				do
					local CB = bit32.bxor(buffer.readu32(Work, 152), buffer.readu32(Work, 172), buffer.readu32(Work, 192), buffer.readu32(Work, 212), buffer.readu32(Work, 232))
					buffer.writeu32(Work, 8, bit32.bxor(CA1, bit32.lrotate(CB, 1)))
					buffer.writeu32(Work, 36, bit32.bxor(CB, CA0))
				end
				do
					local CB = bit32.bxor(buffer.readu32(Work, 156), buffer.readu32(Work, 176), buffer.readu32(Work, 196), buffer.readu32(Work, 216), buffer.readu32(Work, 236))
					buffer.writeu32(Work, 12, bit32.bxor(CA2, bit32.lrotate(CB, 1)))
					buffer.writeu32(Work, 20, bit32.bxor(CB, CA1))
				end
				if RoundIndex < 0 then break end
				do
					local P0 = bit32.bxor(buffer.readu32(Work, 40), buffer.readu32(Work, 0))
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 64), buffer.readu32(Work, 4)), 22)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 188), buffer.readu32(Work, 28)), 22)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 212), buffer.readu32(Work, 32)), 11)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 136), buffer.readu32(Work, 16)), 7)
					buffer.writeu32(StateA, 0, bit32.bxor(P0, bit32.bor(P1, P2), buffer.readu32(Work, RoundIndex + 8)))
					buffer.writeu32(StateA, 4, bit32.bxor(P1, bit32.bor(bit32.bnot(P2), P3)))
					buffer.writeu32(StateA, 8, bit32.bxor(P2, bit32.band(P3, P4)))
					buffer.writeu32(StateA, 12, bit32.bxor(P3, bit32.bor(P4, P0)))
					buffer.writeu32(StateA, 16, bit32.bxor(P4, bit32.band(P0, P1)))
				end
				do
					local P0 = bit32.bxor(buffer.readu32(Work, 140), buffer.readu32(Work, 20))
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 164), buffer.readu32(Work, 24)), 22)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 88), buffer.readu32(Work, 8)), 21)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 112), buffer.readu32(Work, 12)), 10)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 236), buffer.readu32(Work, 36)), 7)
					buffer.writeu32(StateB, 0, bit32.bxor(P0, bit32.bor(P1, P2), buffer.readu32(Work, RoundIndex + 12)))
					buffer.writeu32(StateB, 4, bit32.bxor(P1, bit32.bor(bit32.bnot(P2), P3)))
					buffer.writeu32(StateB, 8, bit32.bxor(P2, bit32.band(P3, P4)))
					buffer.writeu32(StateB, 12, bit32.bxor(P3, bit32.bor(P4, P0)))
					buffer.writeu32(StateB, 16, bit32.bxor(P4, bit32.band(P0, P1)))
				end
				do
					local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 52), buffer.readu32(Work, 12)), 14)
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 76), buffer.readu32(Work, 16)), 10)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 180), buffer.readu32(Work, 20)), 2)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 204), buffer.readu32(Work, 24)), 23)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 228), buffer.readu32(Work, 28)), 31)
					buffer.writeu32(StateA, 20, bit32.bxor(P0, bit32.bor(P1, P2)))
					buffer.writeu32(StateA, 24, bit32.bxor(P1, bit32.band(P2, P3)))
					buffer.writeu32(StateA, 28, bit32.bxor(P2, bit32.bor(P3, bit32.bnot(P4))))
					buffer.writeu32(StateA, 32, bit32.bxor(P3, bit32.bor(P4, P0)))
					buffer.writeu32(StateA, 36, bit32.bxor(P4, bit32.band(P0, P1)))
				end
				do
					local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 152), buffer.readu32(Work, 32)), 14)
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 176), buffer.readu32(Work, 36)), 10)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 80), buffer.readu32(Work, 0)), 1)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 104), buffer.readu32(Work, 4)), 22)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 128), buffer.readu32(Work, 8)), 30)
					buffer.writeu32(StateB, 20, bit32.bxor(P0, bit32.bor(P1, P2)))
					buffer.writeu32(StateB, 24, bit32.bxor(P1, bit32.band(P2, P3)))
					buffer.writeu32(StateB, 28, bit32.bxor(P2, bit32.bor(P3, bit32.bnot(P4))))
					buffer.writeu32(StateB, 32, bit32.bxor(P3, bit32.bor(P4, P0)))
					buffer.writeu32(StateB, 36, bit32.bxor(P4, bit32.band(P0, P1)))
				end
				do
					local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 144), buffer.readu32(Work, 24)), 1)
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 68), buffer.readu32(Work, 8)), 3)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 192), buffer.readu32(Work, 32)), 13)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 116), buffer.readu32(Work, 16)), 4)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 120), buffer.readu32(Work, 0)), 9)
					buffer.writeu32(StateA, 40, bit32.bxor(P0, bit32.bor(P1, P2)))
					buffer.writeu32(StateA, 44, bit32.bxor(P1, bit32.band(P2, P3)))
					buffer.writeu32(StateA, 48, bit32.bxor(P2, bit32.band(bit32.bnot(P3), P4)))
					buffer.writeu32(StateA, 52, bit32.bxor(bit32.bnot(P3), bit32.bor(P4, P0)))
					buffer.writeu32(StateA, 56, bit32.bxor(P4, bit32.band(P0, P1)))
				end
				do
					local P0 = bit32.bxor(buffer.readu32(Work, 44), buffer.readu32(Work, 4))
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 168), buffer.readu32(Work, 28)), 3)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 92), buffer.readu32(Work, 12)), 12)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 216), buffer.readu32(Work, 36)), 4)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 220), buffer.readu32(Work, 20)), 9)
					buffer.writeu32(StateB, 40, bit32.bxor(P0, bit32.bor(P1, P2)))
					buffer.writeu32(StateB, 44, bit32.bxor(P1, bit32.band(P2, P3)))
					buffer.writeu32(StateB, 48, bit32.bxor(P2, bit32.band(bit32.bnot(P3), P4)))
					buffer.writeu32(StateB, 52, bit32.bxor(bit32.bnot(P3), bit32.bor(P4, P0)))
					buffer.writeu32(StateB, 56, bit32.bxor(P4, bit32.band(P0, P1)))
				end
				do
					local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 156), buffer.readu32(Work, 36)), 14)
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 60), buffer.readu32(Work, 0)), 18)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 84), buffer.readu32(Work, 4)), 5)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 208), buffer.readu32(Work, 28)), 8)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 132), buffer.readu32(Work, 12)), 28)
					buffer.writeu32(StateA, 60, bit32.bxor(P0, bit32.band(P1, P2)))
					buffer.writeu32(StateA, 64, bit32.bxor(P1, bit32.bor(P2, P3)))
					buffer.writeu32(StateA, 68, bit32.bxor(P2, bit32.bor(bit32.bnot(P3), P4)))
					buffer.writeu32(StateA, 72, bit32.bxor(bit32.bnot(P3), bit32.band(P4, P0)))
					buffer.writeu32(StateA, 76, bit32.bxor(P4, bit32.bor(P0, P1)))
				end
				do
					local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 56), buffer.readu32(Work, 16)), 13)
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 160), buffer.readu32(Work, 20)), 18)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 184), buffer.readu32(Work, 24)), 5)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 108), buffer.readu32(Work, 8)), 7)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 232), buffer.readu32(Work, 32)), 28)
					buffer.writeu32(StateB, 60, bit32.bxor(P0, bit32.band(P1, P2)))
					buffer.writeu32(StateB, 64, bit32.bxor(P1, bit32.bor(P2, P3)))
					buffer.writeu32(StateB, 68, bit32.bxor(P2, bit32.bor(bit32.bnot(P3), P4)))
					buffer.writeu32(StateB, 72, bit32.bxor(bit32.bnot(P3), bit32.band(P4, P0)))
					buffer.writeu32(StateB, 76, bit32.bxor(P4, bit32.bor(P0, P1)))
				end
				do
					local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 48), buffer.readu32(Work, 8)), 31)
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 172), buffer.readu32(Work, 32)), 28)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 196), buffer.readu32(Work, 36)), 20)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 200), buffer.readu32(Work, 20)), 21)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 124), buffer.readu32(Work, 4)), 1)
					buffer.writeu32(StateA, 80, bit32.bxor(P0, bit32.band(bit32.bnot(P1), P2)))
					buffer.writeu32(StateA, 84, bit32.bxor(bit32.bnot(P1), bit32.bor(P2, P3)))
					buffer.writeu32(StateA, 88, bit32.bxor(P2, bit32.band(P3, P4)))
					buffer.writeu32(StateA, 92, bit32.bxor(P3, bit32.bor(P4, P0)))
					buffer.writeu32(StateA, 96, bit32.bxor(P4, bit32.band(P0, P1)))
				end
				do
					local P0 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 148), buffer.readu32(Work, 28)), 31)
					local P1 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 72), buffer.readu32(Work, 12)), 27)
					local P2 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 96), buffer.readu32(Work, 16)), 19)
					local P3 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 100), buffer.readu32(Work, 0)), 20)
					local P4 = bit32.lrotate(bit32.bxor(buffer.readu32(Work, 224), buffer.readu32(Work, 24)), 1)
					buffer.writeu32(StateB, 80, bit32.bxor(P0, bit32.band(bit32.bnot(P1), P2)))
					buffer.writeu32(StateB, 84, bit32.bxor(bit32.bnot(P1), bit32.bor(P2, P3)))
					buffer.writeu32(StateB, 88, bit32.bxor(P2, bit32.band(P3, P4)))
					buffer.writeu32(StateB, 92, bit32.bxor(P3, bit32.bor(P4, P0)))
					buffer.writeu32(StateB, 96, bit32.bxor(P4, bit32.band(P0, P1)))
				end
			end
		end
	end
	buffer.writeu32(StateA, 4, bit32.bnot(buffer.readu32(StateA, 4))); buffer.writeu32(StateB, 4, bit32.bnot(buffer.readu32(StateB, 4)))
	buffer.writeu32(StateA, 8, bit32.bnot(buffer.readu32(StateA, 8))); buffer.writeu32(StateB, 8, bit32.bnot(buffer.readu32(StateB, 8)))
	buffer.writeu32(StateA, 32, bit32.bnot(buffer.readu32(StateA, 32))); buffer.writeu32(StateB, 32, bit32.bnot(buffer.readu32(StateB, 32)))
	buffer.writeu32(StateA, 48, bit32.bnot(buffer.readu32(StateA, 48))); buffer.writeu32(StateB, 48, bit32.bnot(buffer.readu32(StateB, 48)))
	buffer.writeu32(StateA, 68, bit32.bnot(buffer.readu32(StateA, 68))); buffer.writeu32(StateB, 68, bit32.bnot(buffer.readu32(StateB, 68)))
	buffer.writeu32(StateA, 80, bit32.bnot(buffer.readu32(StateA, 80))); buffer.writeu32(StateB, 80, bit32.bnot(buffer.readu32(StateB, 80)))
end

local function Extract(StateA: buffer, StateB: buffer, Output: buffer, OutputOffset: number, ByteCount: number)
	local FullLanes = ByteCount // 8
	local OutPos = OutputOffset
	local StateOff = 0
	local End8 = (FullLanes // 8) * 32
	local EndAll = FullLanes * 4
	while StateOff < End8 do
		do
			local A, B = buffer.readu32(StateA, StateOff + 0), buffer.readu32(StateB, StateOff + 0)
			local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
			local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			buffer.writeu32(Output, OutPos + 0, Lo)
			buffer.writeu32(Output, OutPos + 0 + 4, Hi)
		end
		do
			local A, B = buffer.readu32(StateA, StateOff + 4), buffer.readu32(StateB, StateOff + 4)
			local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
			local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			buffer.writeu32(Output, OutPos + 8, Lo)
			buffer.writeu32(Output, OutPos + 8 + 4, Hi)
		end
		do
			local A, B = buffer.readu32(StateA, StateOff + 8), buffer.readu32(StateB, StateOff + 8)
			local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
			local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			buffer.writeu32(Output, OutPos + 16, Lo)
			buffer.writeu32(Output, OutPos + 16 + 4, Hi)
		end
		do
			local A, B = buffer.readu32(StateA, StateOff + 12), buffer.readu32(StateB, StateOff + 12)
			local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
			local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			buffer.writeu32(Output, OutPos + 24, Lo)
			buffer.writeu32(Output, OutPos + 24 + 4, Hi)
		end
		do
			local A, B = buffer.readu32(StateA, StateOff + 16), buffer.readu32(StateB, StateOff + 16)
			local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
			local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			buffer.writeu32(Output, OutPos + 32, Lo)
			buffer.writeu32(Output, OutPos + 32 + 4, Hi)
		end
		do
			local A, B = buffer.readu32(StateA, StateOff + 20), buffer.readu32(StateB, StateOff + 20)
			local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
			local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			buffer.writeu32(Output, OutPos + 40, Lo)
			buffer.writeu32(Output, OutPos + 40 + 4, Hi)
		end
		do
			local A, B = buffer.readu32(StateA, StateOff + 24), buffer.readu32(StateB, StateOff + 24)
			local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
			local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			buffer.writeu32(Output, OutPos + 48, Lo)
			buffer.writeu32(Output, OutPos + 48 + 4, Hi)
		end
		do
			local A, B = buffer.readu32(StateA, StateOff + 28), buffer.readu32(StateB, StateOff + 28)
			local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
			local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			buffer.writeu32(Output, OutPos + 56, Lo)
			buffer.writeu32(Output, OutPos + 56 + 4, Hi)
		end
		OutPos += 64
		StateOff += 32
	end
	if StateOff + 16 <= EndAll then
		do
			local A, B = buffer.readu32(StateA, StateOff + 0), buffer.readu32(StateB, StateOff + 0)
			local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
			local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			buffer.writeu32(Output, OutPos + 0, Lo)
			buffer.writeu32(Output, OutPos + 0 + 4, Hi)
		end
		do
			local A, B = buffer.readu32(StateA, StateOff + 4), buffer.readu32(StateB, StateOff + 4)
			local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
			local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			buffer.writeu32(Output, OutPos + 8, Lo)
			buffer.writeu32(Output, OutPos + 8 + 4, Hi)
		end
		do
			local A, B = buffer.readu32(StateA, StateOff + 8), buffer.readu32(StateB, StateOff + 8)
			local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
			local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			buffer.writeu32(Output, OutPos + 16, Lo)
			buffer.writeu32(Output, OutPos + 16 + 4, Hi)
		end
		do
			local A, B = buffer.readu32(StateA, StateOff + 12), buffer.readu32(StateB, StateOff + 12)
			local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
			local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			buffer.writeu32(Output, OutPos + 24, Lo)
			buffer.writeu32(Output, OutPos + 24 + 4, Hi)
		end
		OutPos += 32
		StateOff += 16
	end
	while StateOff < EndAll do
		do
			local A, B = buffer.readu32(StateA, StateOff), buffer.readu32(StateB, StateOff)
			local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
			local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			buffer.writeu32(Output, OutPos, Lo)
			buffer.writeu32(Output, OutPos + 4, Hi)
		end
		OutPos += 8
		StateOff += 4
	end

	local Remaining = ByteCount - FullLanes * 8
	if Remaining > 0 then
		local A, B = buffer.readu32(StateA, EndAll), buffer.readu32(StateB, EndAll)
		local Lo = bit32.bor(bit32.band(A, 0xFFFF), bit32.lshift(B, 16))
		local Hi = bit32.bor(bit32.rshift(A, 16), bit32.band(B, 0xFFFF0000))
		local T: number
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
		for Index = 0, Remaining - 1 do
			local Word = if Index < 4 then Lo else Hi
			buffer.writeu8(Output, OutPos + Index, bit32.extract(Word, (Index % 4) * 8, 8))
		end
	end
end

local function ProcessSpongeInto(Message: buffer, MessageOffset: number, MessageLength: number, RateBytes: number, Output: buffer, OutputOffset: number, OutputBytes: number, DomainSeparator: number)
	local StateA: buffer = STATE_A
	local StateB: buffer = STATE_B

	local TailLength = MessageLength % RateBytes
	local FullBytes = MessageLength - TailLength

	if FullBytes > 0 then
		Keccak(StateA, StateB, Message, MessageOffset, FullBytes, RateBytes, true)
	else
		ZeroState(StateA, StateB)
	end

	local TailLanes = TailLength // 8
	local Pos = MessageOffset + FullBytes
	local StateOff = 0
	local TailEnd = TailLanes * 4
	while StateOff < TailEnd do
		do
			local Lo, Hi = buffer.readu32(Message, Pos), buffer.readu32(Message, Pos + 4)
			local T: number
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
			T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))
			buffer.writeu32(StateA, StateOff, bit32.bxor(buffer.readu32(StateA, StateOff), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
			buffer.writeu32(StateB, StateOff, bit32.bxor(buffer.readu32(StateB, StateOff), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
		end
		Pos += 8
		StateOff += 4
	end

	local Rem = TailLength - TailLanes * 8
	if Rem == 0 then
		local DomA = if DomainSeparator == 0x06 then 2 else 7
		local DomB = if DomainSeparator == 0x06 then 1 else 3
		buffer.writeu32(StateA, TailEnd, bit32.bxor(buffer.readu32(StateA, TailEnd), DomA))
		buffer.writeu32(StateB, TailEnd, bit32.bxor(buffer.readu32(StateB, TailEnd), DomB))
	else
		local Lo = 0
		local Hi = 0
		if Rem >= 4 then
			Lo = buffer.readu32(Message, Pos)
			local Shift = 0
			for Index = 4, Rem - 1 do
				Hi = bit32.bor(Hi, bit32.lshift(buffer.readu8(Message, Pos + Index), Shift))
				Shift += 8
			end
			Hi = bit32.bor(Hi, bit32.lshift(DomainSeparator, Shift))
		else
			local Shift = 0
			for Index = 0, Rem - 1 do
				Lo = bit32.bor(Lo, bit32.lshift(buffer.readu8(Message, Pos + Index), Shift))
				Shift += 8
			end
			Lo = bit32.bor(Lo, bit32.lshift(DomainSeparator, Shift))
		end

		local T: number
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 1)), 0x22222222); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 1))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 2)), 0x0C0C0C0C); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 2))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 4)), 0x00F000F0); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 4))
		T = bit32.band(bit32.bxor(Lo, bit32.rshift(Lo, 8)), 0x0000FF00); Lo = bit32.bxor(Lo, T, bit32.lshift(T, 8))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 1)), 0x22222222); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 1))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 2)), 0x0C0C0C0C); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 2))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 4)), 0x00F000F0); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 4))
		T = bit32.band(bit32.bxor(Hi, bit32.rshift(Hi, 8)), 0x0000FF00); Hi = bit32.bxor(Hi, T, bit32.lshift(T, 8))

		buffer.writeu32(StateA, TailEnd, bit32.bxor(buffer.readu32(StateA, TailEnd), bit32.band(Lo, 0xFFFF), bit32.lshift(Hi, 16)))
		buffer.writeu32(StateB, TailEnd, bit32.bxor(buffer.readu32(StateB, TailEnd), bit32.rshift(Lo, 16), bit32.band(Hi, 0xFFFF0000)))
	end

	local LastOff = (RateBytes // 8) * 4 - 4
	buffer.writeu32(StateB, LastOff, bit32.bxor(buffer.readu32(StateB, LastOff), 0x80000000))

	Permute(StateA, StateB)

	if OutputBytes <= RateBytes then
		Extract(StateA, StateB, Output, OutputOffset, OutputBytes)
		return
	end

	local Written = 0
	while true do
		local BytesThisRound = math.min(RateBytes, OutputBytes - Written)
		Extract(StateA, StateB, Output, OutputOffset + Written, BytesThisRound)
		Written += BytesThisRound

		if Written >= OutputBytes then
			break
		end

		Permute(StateA, StateB)
	end
end

local function ProcessSponge(Message: buffer, RateBytes: number, OutputBytes: number, DomainSeparator: number): buffer
	local Output = buffer.create(OutputBytes)
	ProcessSpongeInto(Message, 0, buffer.len(Message), RateBytes, Output, 0, OutputBytes, DomainSeparator)
	return Output
end

SHA3.Keccak_Internal = Keccak
SHA3.Permute_Internal = Permute
SHA3.Extract_Internal = Extract

function SHA3.SHA3_256_Into(Message: buffer, Offset: number, Length: number, Output: buffer, OutputOffset: number)
	ProcessSpongeInto(Message, Offset, Length, 136, Output, OutputOffset, 32, 0x06)
end

function SHA3.SHA3_512_Into(Message: buffer, Offset: number, Length: number, Output: buffer, OutputOffset: number)
	ProcessSpongeInto(Message, Offset, Length, 72, Output, OutputOffset, 64, 0x06)
end

function SHA3.SHAKE256_Into(Message: buffer, Offset: number, Length: number, Output: buffer, OutputOffset: number, OutputBytes: number)
	ProcessSpongeInto(Message, Offset, Length, 136, Output, OutputOffset, OutputBytes, 0x1F)
end

function SHA3.SHA3_256_Internal(Message: buffer): buffer
	return ProcessSponge(Message, 136, 32, 0x06)
end

function SHA3.SHA3_512_Internal(Message: buffer): buffer
	return ProcessSponge(Message, 72, 64, 0x06)
end

function SHA3.SHAKE256_Internal(Message: buffer, OutputBytes: number): buffer
	return ProcessSponge(Message, 136, OutputBytes, 0x1F)
end

function SHA3.SHA3_224(Message: buffer): (string, buffer)
	local Buf = ProcessSponge(Message, 144, 28, 0x06)
	return ToHex(Buf), Buf
end

function SHA3.SHA3_256(Message: buffer): (string, buffer)
	local Buf = ProcessSponge(Message, 136, 32, 0x06)
	return ToHex(Buf), Buf
end

function SHA3.SHA3_384(Message: buffer): (string, buffer)
	local Buf = ProcessSponge(Message, 104, 48, 0x06)
	return ToHex(Buf), Buf
end

function SHA3.SHA3_512(Message: buffer): (string, buffer)
	local Buf = ProcessSponge(Message, 72, 64, 0x06)
	return ToHex(Buf), Buf
end

function SHA3.SHAKE128(Message: buffer, OutputBytes: number): (string, buffer)
	if type(OutputBytes) ~= "number" or OutputBytes < 0 or OutputBytes ~= math.floor(OutputBytes) then
		error(`OutputBytes must be a non-negative integer, got {OutputBytes}`, 2)
	end

	local Buf = ProcessSponge(Message, 168, OutputBytes, 0x1F)
	return ToHex(Buf), Buf
end

function SHA3.SHAKE256(Message: buffer, OutputBytes: number): (string, buffer)
	if type(OutputBytes) ~= "number" or OutputBytes < 0 or OutputBytes ~= math.floor(OutputBytes) then
		error(`OutputBytes must be a non-negative integer, got {OutputBytes}`, 2)
	end

	local Buf = ProcessSponge(Message, 136, OutputBytes, 0x1F)
	return ToHex(Buf), Buf
end

function SHA3.ClearCaches()
	buffer.fill(STATE_A, 0, 0)
	buffer.fill(STATE_B, 0, 0)
	buffer.fill(WORK, 0, 0, 240)
end

return SHA3
