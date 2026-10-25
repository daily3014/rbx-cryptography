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

local CONSTANTS = buffer.create(640) do
	buffer.writeu32(CONSTANTS, 0, 0x428a2f98); buffer.writeu32(CONSTANTS, 4, 0xd728ae22)
	buffer.writeu32(CONSTANTS, 8, 0x71374491); buffer.writeu32(CONSTANTS, 12, 0x23ef65cd)
	buffer.writeu32(CONSTANTS, 16, 0xb5c0fbcf); buffer.writeu32(CONSTANTS, 20, 0xec4d3b2f)
	buffer.writeu32(CONSTANTS, 24, 0xe9b5dba5); buffer.writeu32(CONSTANTS, 28, 0x8189dbbc)
	buffer.writeu32(CONSTANTS, 32, 0x3956c25b); buffer.writeu32(CONSTANTS, 36, 0xf348b538)
	buffer.writeu32(CONSTANTS, 40, 0x59f111f1); buffer.writeu32(CONSTANTS, 44, 0xb605d019)
	buffer.writeu32(CONSTANTS, 48, 0x923f82a4); buffer.writeu32(CONSTANTS, 52, 0xaf194f9b)
	buffer.writeu32(CONSTANTS, 56, 0xab1c5ed5); buffer.writeu32(CONSTANTS, 60, 0xda6d8118)
	buffer.writeu32(CONSTANTS, 64, 0xd807aa98); buffer.writeu32(CONSTANTS, 68, 0xa3030242)
	buffer.writeu32(CONSTANTS, 72, 0x12835b01); buffer.writeu32(CONSTANTS, 76, 0x45706fbe)
	buffer.writeu32(CONSTANTS, 80, 0x243185be); buffer.writeu32(CONSTANTS, 84, 0x4ee4b28c)
	buffer.writeu32(CONSTANTS, 88, 0x550c7dc3); buffer.writeu32(CONSTANTS, 92, 0xd5ffb4e2)
	buffer.writeu32(CONSTANTS, 96, 0x72be5d74); buffer.writeu32(CONSTANTS, 100, 0xf27b896f)
	buffer.writeu32(CONSTANTS, 104, 0x80deb1fe); buffer.writeu32(CONSTANTS, 108, 0x3b1696b1)
	buffer.writeu32(CONSTANTS, 112, 0x9bdc06a7); buffer.writeu32(CONSTANTS, 116, 0x25c71235)
	buffer.writeu32(CONSTANTS, 120, 0xc19bf174); buffer.writeu32(CONSTANTS, 124, 0xcf692694)
	buffer.writeu32(CONSTANTS, 128, 0xe49b69c1); buffer.writeu32(CONSTANTS, 132, 0x9ef14ad2)
	buffer.writeu32(CONSTANTS, 136, 0xefbe4786); buffer.writeu32(CONSTANTS, 140, 0x384f25e3)
	buffer.writeu32(CONSTANTS, 144, 0x0fc19dc6); buffer.writeu32(CONSTANTS, 148, 0x8b8cd5b5)
	buffer.writeu32(CONSTANTS, 152, 0x240ca1cc); buffer.writeu32(CONSTANTS, 156, 0x77ac9c65)
	buffer.writeu32(CONSTANTS, 160, 0x2de92c6f); buffer.writeu32(CONSTANTS, 164, 0x592b0275)
	buffer.writeu32(CONSTANTS, 168, 0x4a7484aa); buffer.writeu32(CONSTANTS, 172, 0x6ea6e483)
	buffer.writeu32(CONSTANTS, 176, 0x5cb0a9dc); buffer.writeu32(CONSTANTS, 180, 0xbd41fbd4)
	buffer.writeu32(CONSTANTS, 184, 0x76f988da); buffer.writeu32(CONSTANTS, 188, 0x831153b5)
	buffer.writeu32(CONSTANTS, 192, 0x983e5152); buffer.writeu32(CONSTANTS, 196, 0xee66dfab)
	buffer.writeu32(CONSTANTS, 200, 0xa831c66d); buffer.writeu32(CONSTANTS, 204, 0x2db43210)
	buffer.writeu32(CONSTANTS, 208, 0xb00327c8); buffer.writeu32(CONSTANTS, 212, 0x98fb213f)
	buffer.writeu32(CONSTANTS, 216, 0xbf597fc7); buffer.writeu32(CONSTANTS, 220, 0xbeef0ee4)
	buffer.writeu32(CONSTANTS, 224, 0xc6e00bf3); buffer.writeu32(CONSTANTS, 228, 0x3da88fc2)
	buffer.writeu32(CONSTANTS, 232, 0xd5a79147); buffer.writeu32(CONSTANTS, 236, 0x930aa725)
	buffer.writeu32(CONSTANTS, 240, 0x06ca6351); buffer.writeu32(CONSTANTS, 244, 0xe003826f)
	buffer.writeu32(CONSTANTS, 248, 0x14292967); buffer.writeu32(CONSTANTS, 252, 0x0a0e6e70)
	buffer.writeu32(CONSTANTS, 256, 0x27b70a85); buffer.writeu32(CONSTANTS, 260, 0x46d22ffc)
	buffer.writeu32(CONSTANTS, 264, 0x2e1b2138); buffer.writeu32(CONSTANTS, 268, 0x5c26c926)
	buffer.writeu32(CONSTANTS, 272, 0x4d2c6dfc); buffer.writeu32(CONSTANTS, 276, 0x5ac42aed)
	buffer.writeu32(CONSTANTS, 280, 0x53380d13); buffer.writeu32(CONSTANTS, 284, 0x9d95b3df)
	buffer.writeu32(CONSTANTS, 288, 0x650a7354); buffer.writeu32(CONSTANTS, 292, 0x8baf63de)
	buffer.writeu32(CONSTANTS, 296, 0x766a0abb); buffer.writeu32(CONSTANTS, 300, 0x3c77b2a8)
	buffer.writeu32(CONSTANTS, 304, 0x81c2c92e); buffer.writeu32(CONSTANTS, 308, 0x47edaee6)
	buffer.writeu32(CONSTANTS, 312, 0x92722c85); buffer.writeu32(CONSTANTS, 316, 0x1482353b)
	buffer.writeu32(CONSTANTS, 320, 0xa2bfe8a1); buffer.writeu32(CONSTANTS, 324, 0x4cf10364)
	buffer.writeu32(CONSTANTS, 328, 0xa81a664b); buffer.writeu32(CONSTANTS, 332, 0xbc423001)
	buffer.writeu32(CONSTANTS, 336, 0xc24b8b70); buffer.writeu32(CONSTANTS, 340, 0xd0f89791)
	buffer.writeu32(CONSTANTS, 344, 0xc76c51a3); buffer.writeu32(CONSTANTS, 348, 0x0654be30)
	buffer.writeu32(CONSTANTS, 352, 0xd192e819); buffer.writeu32(CONSTANTS, 356, 0xd6ef5218)
	buffer.writeu32(CONSTANTS, 360, 0xd6990624); buffer.writeu32(CONSTANTS, 364, 0x5565a910)
	buffer.writeu32(CONSTANTS, 368, 0xf40e3585); buffer.writeu32(CONSTANTS, 372, 0x5771202a)
	buffer.writeu32(CONSTANTS, 376, 0x106aa070); buffer.writeu32(CONSTANTS, 380, 0x32bbd1b8)
	buffer.writeu32(CONSTANTS, 384, 0x19a4c116); buffer.writeu32(CONSTANTS, 388, 0xb8d2d0c8)
	buffer.writeu32(CONSTANTS, 392, 0x1e376c08); buffer.writeu32(CONSTANTS, 396, 0x5141ab53)
	buffer.writeu32(CONSTANTS, 400, 0x2748774c); buffer.writeu32(CONSTANTS, 404, 0xdf8eeb99)
	buffer.writeu32(CONSTANTS, 408, 0x34b0bcb5); buffer.writeu32(CONSTANTS, 412, 0xe19b48a8)
	buffer.writeu32(CONSTANTS, 416, 0x391c0cb3); buffer.writeu32(CONSTANTS, 420, 0xc5c95a63)
	buffer.writeu32(CONSTANTS, 424, 0x4ed8aa4a); buffer.writeu32(CONSTANTS, 428, 0xe3418acb)
	buffer.writeu32(CONSTANTS, 432, 0x5b9cca4f); buffer.writeu32(CONSTANTS, 436, 0x7763e373)
	buffer.writeu32(CONSTANTS, 440, 0x682e6ff3); buffer.writeu32(CONSTANTS, 444, 0xd6b2b8a3)
	buffer.writeu32(CONSTANTS, 448, 0x748f82ee); buffer.writeu32(CONSTANTS, 452, 0x5defb2fc)
	buffer.writeu32(CONSTANTS, 456, 0x78a5636f); buffer.writeu32(CONSTANTS, 460, 0x43172f60)
	buffer.writeu32(CONSTANTS, 464, 0x84c87814); buffer.writeu32(CONSTANTS, 468, 0xa1f0ab72)
	buffer.writeu32(CONSTANTS, 472, 0x8cc70208); buffer.writeu32(CONSTANTS, 476, 0x1a6439ec)
	buffer.writeu32(CONSTANTS, 480, 0x90befffa); buffer.writeu32(CONSTANTS, 484, 0x23631e28)
	buffer.writeu32(CONSTANTS, 488, 0xa4506ceb); buffer.writeu32(CONSTANTS, 492, 0xde82bde9)
	buffer.writeu32(CONSTANTS, 496, 0xbef9a3f7); buffer.writeu32(CONSTANTS, 500, 0xb2c67915)
	buffer.writeu32(CONSTANTS, 504, 0xc67178f2); buffer.writeu32(CONSTANTS, 508, 0xe372532b)
	buffer.writeu32(CONSTANTS, 512, 0xca273ece); buffer.writeu32(CONSTANTS, 516, 0xea26619c)
	buffer.writeu32(CONSTANTS, 520, 0xd186b8c7); buffer.writeu32(CONSTANTS, 524, 0x21c0c207)
	buffer.writeu32(CONSTANTS, 528, 0xeada7dd6); buffer.writeu32(CONSTANTS, 532, 0xcde0eb1e)
	buffer.writeu32(CONSTANTS, 536, 0xf57d4f7f); buffer.writeu32(CONSTANTS, 540, 0xee6ed178)
	buffer.writeu32(CONSTANTS, 544, 0x06f067aa); buffer.writeu32(CONSTANTS, 548, 0x72176fba)
	buffer.writeu32(CONSTANTS, 552, 0x0a637dc5); buffer.writeu32(CONSTANTS, 556, 0xa2c898a6)
	buffer.writeu32(CONSTANTS, 560, 0x113f9804); buffer.writeu32(CONSTANTS, 564, 0xbef90dae)
	buffer.writeu32(CONSTANTS, 568, 0x1b710b35); buffer.writeu32(CONSTANTS, 572, 0x131c471b)
	buffer.writeu32(CONSTANTS, 576, 0x28db77f5); buffer.writeu32(CONSTANTS, 580, 0x23047d84)
	buffer.writeu32(CONSTANTS, 584, 0x32caab7b); buffer.writeu32(CONSTANTS, 588, 0x40c72493)
	buffer.writeu32(CONSTANTS, 592, 0x3c9ebe0a); buffer.writeu32(CONSTANTS, 596, 0x15c9bebc)
	buffer.writeu32(CONSTANTS, 600, 0x431d67c4); buffer.writeu32(CONSTANTS, 604, 0x9c100d4c)
	buffer.writeu32(CONSTANTS, 608, 0x4cc5d4be); buffer.writeu32(CONSTANTS, 612, 0xcb3e42b6)
	buffer.writeu32(CONSTANTS, 616, 0x597f299c); buffer.writeu32(CONSTANTS, 620, 0xfc657e2a)
	buffer.writeu32(CONSTANTS, 624, 0x5fcb6fab); buffer.writeu32(CONSTANTS, 628, 0x3ad6faec)
	buffer.writeu32(CONSTANTS, 632, 0x6c44198c); buffer.writeu32(CONSTANTS, 636, 0x4a475817)
end

local IV_512 = buffer.create(64) do
	buffer.writeu32(IV_512, 0, 0x6a09e667)
	buffer.writeu32(IV_512, 4, 0xf3bcc908)
	buffer.writeu32(IV_512, 8, 0xbb67ae85)
	buffer.writeu32(IV_512, 12, 0x84caa73b)
	buffer.writeu32(IV_512, 16, 0x3c6ef372)
	buffer.writeu32(IV_512, 20, 0xfe94f82b)
	buffer.writeu32(IV_512, 24, 0xa54ff53a)
	buffer.writeu32(IV_512, 28, 0x5f1d36f1)
	buffer.writeu32(IV_512, 32, 0x510e527f)
	buffer.writeu32(IV_512, 36, 0xade682d1)
	buffer.writeu32(IV_512, 40, 0x9b05688c)
	buffer.writeu32(IV_512, 44, 0x2b3e6c1f)
	buffer.writeu32(IV_512, 48, 0x1f83d9ab)
	buffer.writeu32(IV_512, 52, 0xfb41bd6b)
	buffer.writeu32(IV_512, 56, 0x5be0cd19)
	buffer.writeu32(IV_512, 60, 0x137e2179)
end

local IV_384 = buffer.create(64) do
	buffer.writeu32(IV_384, 0, 0xcbbb9d5d)
	buffer.writeu32(IV_384, 4, 0xc1059ed8)
	buffer.writeu32(IV_384, 8, 0x629a292a)
	buffer.writeu32(IV_384, 12, 0x367cd507)
	buffer.writeu32(IV_384, 16, 0x9159015a)
	buffer.writeu32(IV_384, 20, 0x3070dd17)
	buffer.writeu32(IV_384, 24, 0x152fecd8)
	buffer.writeu32(IV_384, 28, 0xf70e5939)
	buffer.writeu32(IV_384, 32, 0x67332667)
	buffer.writeu32(IV_384, 36, 0xffc00b31)
	buffer.writeu32(IV_384, 40, 0x8eb44a87)
	buffer.writeu32(IV_384, 44, 0x68581511)
	buffer.writeu32(IV_384, 48, 0xdb0c2e0d)
	buffer.writeu32(IV_384, 52, 0x64f98fa7)
	buffer.writeu32(IV_384, 56, 0x47b5481d)
	buffer.writeu32(IV_384, 60, 0xbefa4fa4)
end

local SCHEDULE = buffer.create(640)
local STATE = buffer.create(64)
local TAIL = buffer.create(256)

local function Compress(Blocks: buffer, Offset: number, Length: number, State: buffer)
	local S0H, S0L = buffer.readu32(State, 0), buffer.readu32(State, 4)
	local S1H, S1L = buffer.readu32(State, 8), buffer.readu32(State, 12)
	local S2H, S2L = buffer.readu32(State, 16), buffer.readu32(State, 20)
	local S3H, S3L = buffer.readu32(State, 24), buffer.readu32(State, 28)
	local S4H, S4L = buffer.readu32(State, 32), buffer.readu32(State, 36)
	local S5H, S5L = buffer.readu32(State, 40), buffer.readu32(State, 44)
	local S6H, S6L = buffer.readu32(State, 48), buffer.readu32(State, 52)
	local S7H, S7L = buffer.readu32(State, 56), buffer.readu32(State, 60)
	local Schedule, Constants = SCHEDULE, CONSTANTS
	for Position = Offset, Offset + Length - 1, 128 do
		for T = 0, 120, 8 do
			buffer.writeu32(Schedule, T, bit32.byteswap(buffer.readu32(Blocks, Position + T)))
			buffer.writeu32(Schedule, T + 4, bit32.byteswap(buffer.readu32(Blocks, Position + T + 4)))
		end
		for T = 128, 632, 8 do
			local P15H, P15L = buffer.readu32(Schedule, T - 120), buffer.readu32(Schedule, T - 116)
			local P2H, P2L = buffer.readu32(Schedule, T - 16), buffer.readu32(Schedule, T - 12)
			local Lo = buffer.readu32(Schedule, T - 124) + buffer.readu32(Schedule, T - 52)
				+ bit32.bxor(bit32.bor(bit32.rshift(P15L, 1), bit32.lshift(P15H, 31)), bit32.bor(bit32.rshift(P15L, 8), bit32.lshift(P15H, 24)), bit32.bor(bit32.rshift(P15L, 7), bit32.lshift(P15H, 25)))
				+ bit32.bxor(bit32.bor(bit32.rshift(P2L, 19), bit32.lshift(P2H, 13)), bit32.bor(bit32.rshift(P2H, 29), bit32.lshift(P2L, 3)), bit32.bor(bit32.rshift(P2L, 6), bit32.lshift(P2H, 26)))
			local Hi = buffer.readu32(Schedule, T - 128) + buffer.readu32(Schedule, T - 56)
				+ bit32.bxor(bit32.bor(bit32.rshift(P15H, 1), bit32.lshift(P15L, 31)), bit32.bor(bit32.rshift(P15H, 8), bit32.lshift(P15L, 24)), bit32.rshift(P15H, 7))
				+ bit32.bxor(bit32.bor(bit32.rshift(P2H, 19), bit32.lshift(P2L, 13)), bit32.bor(bit32.rshift(P2L, 29), bit32.lshift(P2H, 3)), bit32.rshift(P2H, 6))
				+ math.floor(Lo * CARRY)
			buffer.writeu32(Schedule, T, Hi)
			buffer.writeu32(Schedule, T + 4, Lo)
		end
		local O0H, O0L = S0H, S0L
		local O1H, O1L = S1H, S1L
		local O2H, O2L = S2H, S2L
		local O3H, O3L = S3H, S3L
		local O4H, O4L = S4H, S4L
		local O5H, O5L = S5H, S5L
		local O6H, O6L = S6H, S6L
		local O7H, O7L = S7H, S7L
		for Base = 0, 576, 64 do
			local BCH, BCL = bit32.bxor(S1H, S2H), bit32.bxor(S1L, S2L)
			do
				local EH, EL = S4H, S4L
				local AH, AL = S0H, S0L
				local ABH, ABL = bit32.bxor(AH, S1H), bit32.bxor(AL, S1L)
				local KH, KL = buffer.readu32(Constants, Base), buffer.readu32(Constants, Base + 4)
				local WH, WL = buffer.readu32(Schedule, Base), buffer.readu32(Schedule, Base + 4)
				local CH, CL = bit32.bxor(S6H, bit32.band(EH, bit32.bxor(S5H, S6H))), bit32.bxor(S6L, bit32.band(EL, bit32.bxor(S5L, S6L)))
				local XH, XL = bit32.bxor(bit32.bor(bit32.rshift(EH, 14), bit32.lshift(EL, 18)), bit32.bor(bit32.rshift(EH, 18), bit32.lshift(EL, 14)), bit32.bor(bit32.rshift(EL, 9), bit32.lshift(EH, 23))), bit32.bxor(bit32.bor(bit32.rshift(EL, 14), bit32.lshift(EH, 18)), bit32.bor(bit32.rshift(EL, 18), bit32.lshift(EH, 14)), bit32.bor(bit32.rshift(EH, 9), bit32.lshift(EL, 23)))
				local T1H, T1L = S7H, S7L
				do
					local SumL = bit32.bor(T1L + KL, 0)
					T1H = bit32.bor(bit32.bor(T1H + KH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, KL), bit32.band(bit32.bor(T1L, KL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + WL, 0)
					T1H = bit32.bor(bit32.bor(T1H + WH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, WL), bit32.band(bit32.bor(T1L, WL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + CL, 0)
					T1H = bit32.bor(bit32.bor(T1H + CH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, CL), bit32.band(bit32.bor(T1L, CL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + XL, 0)
					T1H = bit32.bor(bit32.bor(T1H + XH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, XL), bit32.band(bit32.bor(T1L, XL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(S3L + T1L, 0)
					S3H = bit32.bor(bit32.bor(S3H + T1H, 0) + bit32.rshift(bit32.bor(bit32.band(S3L, T1L), bit32.band(bit32.bor(S3L, T1L), bit32.bnot(SumL))), 31), 0)
					S3L = SumL
				end
				local MH, ML = bit32.bxor(S1H, bit32.band(ABH, BCH)), bit32.bxor(S1L, bit32.band(ABL, BCL))
				local YH, YL = bit32.bxor(bit32.bor(bit32.rshift(AH, 28), bit32.lshift(AL, 4)), bit32.bor(bit32.rshift(AL, 2), bit32.lshift(AH, 30)), bit32.bor(bit32.rshift(AL, 7), bit32.lshift(AH, 25))), bit32.bxor(bit32.bor(bit32.rshift(AL, 28), bit32.lshift(AH, 4)), bit32.bor(bit32.rshift(AH, 2), bit32.lshift(AL, 30)), bit32.bor(bit32.rshift(AH, 7), bit32.lshift(AL, 25)))
				do
					local SumL = bit32.bor(T1L + ML, 0)
					T1H = bit32.bor(bit32.bor(T1H + MH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, ML), bit32.band(bit32.bor(T1L, ML), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + YL, 0)
					S7H = bit32.bor(bit32.bor(T1H + YH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, YL), bit32.band(bit32.bor(T1L, YL), bit32.bnot(SumL))), 31), 0)
					S7L = SumL
				end
				BCH, BCL = ABH, ABL
			end
			do
				local EH, EL = S3H, S3L
				local AH, AL = S7H, S7L
				local ABH, ABL = bit32.bxor(AH, S0H), bit32.bxor(AL, S0L)
				local KH, KL = buffer.readu32(Constants, Base + 8), buffer.readu32(Constants, Base + 8 + 4)
				local WH, WL = buffer.readu32(Schedule, Base + 8), buffer.readu32(Schedule, Base + 8 + 4)
				local CH, CL = bit32.bxor(S5H, bit32.band(EH, bit32.bxor(S4H, S5H))), bit32.bxor(S5L, bit32.band(EL, bit32.bxor(S4L, S5L)))
				local XH, XL = bit32.bxor(bit32.bor(bit32.rshift(EH, 14), bit32.lshift(EL, 18)), bit32.bor(bit32.rshift(EH, 18), bit32.lshift(EL, 14)), bit32.bor(bit32.rshift(EL, 9), bit32.lshift(EH, 23))), bit32.bxor(bit32.bor(bit32.rshift(EL, 14), bit32.lshift(EH, 18)), bit32.bor(bit32.rshift(EL, 18), bit32.lshift(EH, 14)), bit32.bor(bit32.rshift(EH, 9), bit32.lshift(EL, 23)))
				local T1H, T1L = S6H, S6L
				do
					local SumL = bit32.bor(T1L + KL, 0)
					T1H = bit32.bor(bit32.bor(T1H + KH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, KL), bit32.band(bit32.bor(T1L, KL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + WL, 0)
					T1H = bit32.bor(bit32.bor(T1H + WH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, WL), bit32.band(bit32.bor(T1L, WL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + CL, 0)
					T1H = bit32.bor(bit32.bor(T1H + CH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, CL), bit32.band(bit32.bor(T1L, CL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + XL, 0)
					T1H = bit32.bor(bit32.bor(T1H + XH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, XL), bit32.band(bit32.bor(T1L, XL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(S2L + T1L, 0)
					S2H = bit32.bor(bit32.bor(S2H + T1H, 0) + bit32.rshift(bit32.bor(bit32.band(S2L, T1L), bit32.band(bit32.bor(S2L, T1L), bit32.bnot(SumL))), 31), 0)
					S2L = SumL
				end
				local MH, ML = bit32.bxor(S0H, bit32.band(ABH, BCH)), bit32.bxor(S0L, bit32.band(ABL, BCL))
				local YH, YL = bit32.bxor(bit32.bor(bit32.rshift(AH, 28), bit32.lshift(AL, 4)), bit32.bor(bit32.rshift(AL, 2), bit32.lshift(AH, 30)), bit32.bor(bit32.rshift(AL, 7), bit32.lshift(AH, 25))), bit32.bxor(bit32.bor(bit32.rshift(AL, 28), bit32.lshift(AH, 4)), bit32.bor(bit32.rshift(AH, 2), bit32.lshift(AL, 30)), bit32.bor(bit32.rshift(AH, 7), bit32.lshift(AL, 25)))
				do
					local SumL = bit32.bor(T1L + ML, 0)
					T1H = bit32.bor(bit32.bor(T1H + MH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, ML), bit32.band(bit32.bor(T1L, ML), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + YL, 0)
					S6H = bit32.bor(bit32.bor(T1H + YH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, YL), bit32.band(bit32.bor(T1L, YL), bit32.bnot(SumL))), 31), 0)
					S6L = SumL
				end
				BCH, BCL = ABH, ABL
			end
			do
				local EH, EL = S2H, S2L
				local AH, AL = S6H, S6L
				local ABH, ABL = bit32.bxor(AH, S7H), bit32.bxor(AL, S7L)
				local KH, KL = buffer.readu32(Constants, Base + 16), buffer.readu32(Constants, Base + 16 + 4)
				local WH, WL = buffer.readu32(Schedule, Base + 16), buffer.readu32(Schedule, Base + 16 + 4)
				local CH, CL = bit32.bxor(S4H, bit32.band(EH, bit32.bxor(S3H, S4H))), bit32.bxor(S4L, bit32.band(EL, bit32.bxor(S3L, S4L)))
				local XH, XL = bit32.bxor(bit32.bor(bit32.rshift(EH, 14), bit32.lshift(EL, 18)), bit32.bor(bit32.rshift(EH, 18), bit32.lshift(EL, 14)), bit32.bor(bit32.rshift(EL, 9), bit32.lshift(EH, 23))), bit32.bxor(bit32.bor(bit32.rshift(EL, 14), bit32.lshift(EH, 18)), bit32.bor(bit32.rshift(EL, 18), bit32.lshift(EH, 14)), bit32.bor(bit32.rshift(EH, 9), bit32.lshift(EL, 23)))
				local T1H, T1L = S5H, S5L
				do
					local SumL = bit32.bor(T1L + KL, 0)
					T1H = bit32.bor(bit32.bor(T1H + KH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, KL), bit32.band(bit32.bor(T1L, KL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + WL, 0)
					T1H = bit32.bor(bit32.bor(T1H + WH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, WL), bit32.band(bit32.bor(T1L, WL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + CL, 0)
					T1H = bit32.bor(bit32.bor(T1H + CH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, CL), bit32.band(bit32.bor(T1L, CL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + XL, 0)
					T1H = bit32.bor(bit32.bor(T1H + XH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, XL), bit32.band(bit32.bor(T1L, XL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(S1L + T1L, 0)
					S1H = bit32.bor(bit32.bor(S1H + T1H, 0) + bit32.rshift(bit32.bor(bit32.band(S1L, T1L), bit32.band(bit32.bor(S1L, T1L), bit32.bnot(SumL))), 31), 0)
					S1L = SumL
				end
				local MH, ML = bit32.bxor(S7H, bit32.band(ABH, BCH)), bit32.bxor(S7L, bit32.band(ABL, BCL))
				local YH, YL = bit32.bxor(bit32.bor(bit32.rshift(AH, 28), bit32.lshift(AL, 4)), bit32.bor(bit32.rshift(AL, 2), bit32.lshift(AH, 30)), bit32.bor(bit32.rshift(AL, 7), bit32.lshift(AH, 25))), bit32.bxor(bit32.bor(bit32.rshift(AL, 28), bit32.lshift(AH, 4)), bit32.bor(bit32.rshift(AH, 2), bit32.lshift(AL, 30)), bit32.bor(bit32.rshift(AH, 7), bit32.lshift(AL, 25)))
				do
					local SumL = bit32.bor(T1L + ML, 0)
					T1H = bit32.bor(bit32.bor(T1H + MH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, ML), bit32.band(bit32.bor(T1L, ML), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + YL, 0)
					S5H = bit32.bor(bit32.bor(T1H + YH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, YL), bit32.band(bit32.bor(T1L, YL), bit32.bnot(SumL))), 31), 0)
					S5L = SumL
				end
				BCH, BCL = ABH, ABL
			end
			do
				local EH, EL = S1H, S1L
				local AH, AL = S5H, S5L
				local ABH, ABL = bit32.bxor(AH, S6H), bit32.bxor(AL, S6L)
				local KH, KL = buffer.readu32(Constants, Base + 24), buffer.readu32(Constants, Base + 24 + 4)
				local WH, WL = buffer.readu32(Schedule, Base + 24), buffer.readu32(Schedule, Base + 24 + 4)
				local CH, CL = bit32.bxor(S3H, bit32.band(EH, bit32.bxor(S2H, S3H))), bit32.bxor(S3L, bit32.band(EL, bit32.bxor(S2L, S3L)))
				local XH, XL = bit32.bxor(bit32.bor(bit32.rshift(EH, 14), bit32.lshift(EL, 18)), bit32.bor(bit32.rshift(EH, 18), bit32.lshift(EL, 14)), bit32.bor(bit32.rshift(EL, 9), bit32.lshift(EH, 23))), bit32.bxor(bit32.bor(bit32.rshift(EL, 14), bit32.lshift(EH, 18)), bit32.bor(bit32.rshift(EL, 18), bit32.lshift(EH, 14)), bit32.bor(bit32.rshift(EH, 9), bit32.lshift(EL, 23)))
				local T1H, T1L = S4H, S4L
				do
					local SumL = bit32.bor(T1L + KL, 0)
					T1H = bit32.bor(bit32.bor(T1H + KH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, KL), bit32.band(bit32.bor(T1L, KL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + WL, 0)
					T1H = bit32.bor(bit32.bor(T1H + WH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, WL), bit32.band(bit32.bor(T1L, WL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + CL, 0)
					T1H = bit32.bor(bit32.bor(T1H + CH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, CL), bit32.band(bit32.bor(T1L, CL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + XL, 0)
					T1H = bit32.bor(bit32.bor(T1H + XH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, XL), bit32.band(bit32.bor(T1L, XL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(S0L + T1L, 0)
					S0H = bit32.bor(bit32.bor(S0H + T1H, 0) + bit32.rshift(bit32.bor(bit32.band(S0L, T1L), bit32.band(bit32.bor(S0L, T1L), bit32.bnot(SumL))), 31), 0)
					S0L = SumL
				end
				local MH, ML = bit32.bxor(S6H, bit32.band(ABH, BCH)), bit32.bxor(S6L, bit32.band(ABL, BCL))
				local YH, YL = bit32.bxor(bit32.bor(bit32.rshift(AH, 28), bit32.lshift(AL, 4)), bit32.bor(bit32.rshift(AL, 2), bit32.lshift(AH, 30)), bit32.bor(bit32.rshift(AL, 7), bit32.lshift(AH, 25))), bit32.bxor(bit32.bor(bit32.rshift(AL, 28), bit32.lshift(AH, 4)), bit32.bor(bit32.rshift(AH, 2), bit32.lshift(AL, 30)), bit32.bor(bit32.rshift(AH, 7), bit32.lshift(AL, 25)))
				do
					local SumL = bit32.bor(T1L + ML, 0)
					T1H = bit32.bor(bit32.bor(T1H + MH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, ML), bit32.band(bit32.bor(T1L, ML), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + YL, 0)
					S4H = bit32.bor(bit32.bor(T1H + YH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, YL), bit32.band(bit32.bor(T1L, YL), bit32.bnot(SumL))), 31), 0)
					S4L = SumL
				end
				BCH, BCL = ABH, ABL
			end
			do
				local EH, EL = S0H, S0L
				local AH, AL = S4H, S4L
				local ABH, ABL = bit32.bxor(AH, S5H), bit32.bxor(AL, S5L)
				local KH, KL = buffer.readu32(Constants, Base + 32), buffer.readu32(Constants, Base + 32 + 4)
				local WH, WL = buffer.readu32(Schedule, Base + 32), buffer.readu32(Schedule, Base + 32 + 4)
				local CH, CL = bit32.bxor(S2H, bit32.band(EH, bit32.bxor(S1H, S2H))), bit32.bxor(S2L, bit32.band(EL, bit32.bxor(S1L, S2L)))
				local XH, XL = bit32.bxor(bit32.bor(bit32.rshift(EH, 14), bit32.lshift(EL, 18)), bit32.bor(bit32.rshift(EH, 18), bit32.lshift(EL, 14)), bit32.bor(bit32.rshift(EL, 9), bit32.lshift(EH, 23))), bit32.bxor(bit32.bor(bit32.rshift(EL, 14), bit32.lshift(EH, 18)), bit32.bor(bit32.rshift(EL, 18), bit32.lshift(EH, 14)), bit32.bor(bit32.rshift(EH, 9), bit32.lshift(EL, 23)))
				local T1H, T1L = S3H, S3L
				do
					local SumL = bit32.bor(T1L + KL, 0)
					T1H = bit32.bor(bit32.bor(T1H + KH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, KL), bit32.band(bit32.bor(T1L, KL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + WL, 0)
					T1H = bit32.bor(bit32.bor(T1H + WH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, WL), bit32.band(bit32.bor(T1L, WL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + CL, 0)
					T1H = bit32.bor(bit32.bor(T1H + CH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, CL), bit32.band(bit32.bor(T1L, CL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + XL, 0)
					T1H = bit32.bor(bit32.bor(T1H + XH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, XL), bit32.band(bit32.bor(T1L, XL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(S7L + T1L, 0)
					S7H = bit32.bor(bit32.bor(S7H + T1H, 0) + bit32.rshift(bit32.bor(bit32.band(S7L, T1L), bit32.band(bit32.bor(S7L, T1L), bit32.bnot(SumL))), 31), 0)
					S7L = SumL
				end
				local MH, ML = bit32.bxor(S5H, bit32.band(ABH, BCH)), bit32.bxor(S5L, bit32.band(ABL, BCL))
				local YH, YL = bit32.bxor(bit32.bor(bit32.rshift(AH, 28), bit32.lshift(AL, 4)), bit32.bor(bit32.rshift(AL, 2), bit32.lshift(AH, 30)), bit32.bor(bit32.rshift(AL, 7), bit32.lshift(AH, 25))), bit32.bxor(bit32.bor(bit32.rshift(AL, 28), bit32.lshift(AH, 4)), bit32.bor(bit32.rshift(AH, 2), bit32.lshift(AL, 30)), bit32.bor(bit32.rshift(AH, 7), bit32.lshift(AL, 25)))
				do
					local SumL = bit32.bor(T1L + ML, 0)
					T1H = bit32.bor(bit32.bor(T1H + MH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, ML), bit32.band(bit32.bor(T1L, ML), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + YL, 0)
					S3H = bit32.bor(bit32.bor(T1H + YH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, YL), bit32.band(bit32.bor(T1L, YL), bit32.bnot(SumL))), 31), 0)
					S3L = SumL
				end
				BCH, BCL = ABH, ABL
			end
			do
				local EH, EL = S7H, S7L
				local AH, AL = S3H, S3L
				local ABH, ABL = bit32.bxor(AH, S4H), bit32.bxor(AL, S4L)
				local KH, KL = buffer.readu32(Constants, Base + 40), buffer.readu32(Constants, Base + 40 + 4)
				local WH, WL = buffer.readu32(Schedule, Base + 40), buffer.readu32(Schedule, Base + 40 + 4)
				local CH, CL = bit32.bxor(S1H, bit32.band(EH, bit32.bxor(S0H, S1H))), bit32.bxor(S1L, bit32.band(EL, bit32.bxor(S0L, S1L)))
				local XH, XL = bit32.bxor(bit32.bor(bit32.rshift(EH, 14), bit32.lshift(EL, 18)), bit32.bor(bit32.rshift(EH, 18), bit32.lshift(EL, 14)), bit32.bor(bit32.rshift(EL, 9), bit32.lshift(EH, 23))), bit32.bxor(bit32.bor(bit32.rshift(EL, 14), bit32.lshift(EH, 18)), bit32.bor(bit32.rshift(EL, 18), bit32.lshift(EH, 14)), bit32.bor(bit32.rshift(EH, 9), bit32.lshift(EL, 23)))
				local T1H, T1L = S2H, S2L
				do
					local SumL = bit32.bor(T1L + KL, 0)
					T1H = bit32.bor(bit32.bor(T1H + KH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, KL), bit32.band(bit32.bor(T1L, KL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + WL, 0)
					T1H = bit32.bor(bit32.bor(T1H + WH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, WL), bit32.band(bit32.bor(T1L, WL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + CL, 0)
					T1H = bit32.bor(bit32.bor(T1H + CH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, CL), bit32.band(bit32.bor(T1L, CL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + XL, 0)
					T1H = bit32.bor(bit32.bor(T1H + XH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, XL), bit32.band(bit32.bor(T1L, XL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(S6L + T1L, 0)
					S6H = bit32.bor(bit32.bor(S6H + T1H, 0) + bit32.rshift(bit32.bor(bit32.band(S6L, T1L), bit32.band(bit32.bor(S6L, T1L), bit32.bnot(SumL))), 31), 0)
					S6L = SumL
				end
				local MH, ML = bit32.bxor(S4H, bit32.band(ABH, BCH)), bit32.bxor(S4L, bit32.band(ABL, BCL))
				local YH, YL = bit32.bxor(bit32.bor(bit32.rshift(AH, 28), bit32.lshift(AL, 4)), bit32.bor(bit32.rshift(AL, 2), bit32.lshift(AH, 30)), bit32.bor(bit32.rshift(AL, 7), bit32.lshift(AH, 25))), bit32.bxor(bit32.bor(bit32.rshift(AL, 28), bit32.lshift(AH, 4)), bit32.bor(bit32.rshift(AH, 2), bit32.lshift(AL, 30)), bit32.bor(bit32.rshift(AH, 7), bit32.lshift(AL, 25)))
				do
					local SumL = bit32.bor(T1L + ML, 0)
					T1H = bit32.bor(bit32.bor(T1H + MH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, ML), bit32.band(bit32.bor(T1L, ML), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + YL, 0)
					S2H = bit32.bor(bit32.bor(T1H + YH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, YL), bit32.band(bit32.bor(T1L, YL), bit32.bnot(SumL))), 31), 0)
					S2L = SumL
				end
				BCH, BCL = ABH, ABL
			end
			do
				local EH, EL = S6H, S6L
				local AH, AL = S2H, S2L
				local ABH, ABL = bit32.bxor(AH, S3H), bit32.bxor(AL, S3L)
				local KH, KL = buffer.readu32(Constants, Base + 48), buffer.readu32(Constants, Base + 48 + 4)
				local WH, WL = buffer.readu32(Schedule, Base + 48), buffer.readu32(Schedule, Base + 48 + 4)
				local CH, CL = bit32.bxor(S0H, bit32.band(EH, bit32.bxor(S7H, S0H))), bit32.bxor(S0L, bit32.band(EL, bit32.bxor(S7L, S0L)))
				local XH, XL = bit32.bxor(bit32.bor(bit32.rshift(EH, 14), bit32.lshift(EL, 18)), bit32.bor(bit32.rshift(EH, 18), bit32.lshift(EL, 14)), bit32.bor(bit32.rshift(EL, 9), bit32.lshift(EH, 23))), bit32.bxor(bit32.bor(bit32.rshift(EL, 14), bit32.lshift(EH, 18)), bit32.bor(bit32.rshift(EL, 18), bit32.lshift(EH, 14)), bit32.bor(bit32.rshift(EH, 9), bit32.lshift(EL, 23)))
				local T1H, T1L = S1H, S1L
				do
					local SumL = bit32.bor(T1L + KL, 0)
					T1H = bit32.bor(bit32.bor(T1H + KH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, KL), bit32.band(bit32.bor(T1L, KL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + WL, 0)
					T1H = bit32.bor(bit32.bor(T1H + WH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, WL), bit32.band(bit32.bor(T1L, WL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + CL, 0)
					T1H = bit32.bor(bit32.bor(T1H + CH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, CL), bit32.band(bit32.bor(T1L, CL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + XL, 0)
					T1H = bit32.bor(bit32.bor(T1H + XH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, XL), bit32.band(bit32.bor(T1L, XL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(S5L + T1L, 0)
					S5H = bit32.bor(bit32.bor(S5H + T1H, 0) + bit32.rshift(bit32.bor(bit32.band(S5L, T1L), bit32.band(bit32.bor(S5L, T1L), bit32.bnot(SumL))), 31), 0)
					S5L = SumL
				end
				local MH, ML = bit32.bxor(S3H, bit32.band(ABH, BCH)), bit32.bxor(S3L, bit32.band(ABL, BCL))
				local YH, YL = bit32.bxor(bit32.bor(bit32.rshift(AH, 28), bit32.lshift(AL, 4)), bit32.bor(bit32.rshift(AL, 2), bit32.lshift(AH, 30)), bit32.bor(bit32.rshift(AL, 7), bit32.lshift(AH, 25))), bit32.bxor(bit32.bor(bit32.rshift(AL, 28), bit32.lshift(AH, 4)), bit32.bor(bit32.rshift(AH, 2), bit32.lshift(AL, 30)), bit32.bor(bit32.rshift(AH, 7), bit32.lshift(AL, 25)))
				do
					local SumL = bit32.bor(T1L + ML, 0)
					T1H = bit32.bor(bit32.bor(T1H + MH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, ML), bit32.band(bit32.bor(T1L, ML), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + YL, 0)
					S1H = bit32.bor(bit32.bor(T1H + YH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, YL), bit32.band(bit32.bor(T1L, YL), bit32.bnot(SumL))), 31), 0)
					S1L = SumL
				end
				BCH, BCL = ABH, ABL
			end
			do
				local EH, EL = S5H, S5L
				local AH, AL = S1H, S1L
				local ABH, ABL = bit32.bxor(AH, S2H), bit32.bxor(AL, S2L)
				local KH, KL = buffer.readu32(Constants, Base + 56), buffer.readu32(Constants, Base + 56 + 4)
				local WH, WL = buffer.readu32(Schedule, Base + 56), buffer.readu32(Schedule, Base + 56 + 4)
				local CH, CL = bit32.bxor(S7H, bit32.band(EH, bit32.bxor(S6H, S7H))), bit32.bxor(S7L, bit32.band(EL, bit32.bxor(S6L, S7L)))
				local XH, XL = bit32.bxor(bit32.bor(bit32.rshift(EH, 14), bit32.lshift(EL, 18)), bit32.bor(bit32.rshift(EH, 18), bit32.lshift(EL, 14)), bit32.bor(bit32.rshift(EL, 9), bit32.lshift(EH, 23))), bit32.bxor(bit32.bor(bit32.rshift(EL, 14), bit32.lshift(EH, 18)), bit32.bor(bit32.rshift(EL, 18), bit32.lshift(EH, 14)), bit32.bor(bit32.rshift(EH, 9), bit32.lshift(EL, 23)))
				local T1H, T1L = S0H, S0L
				do
					local SumL = bit32.bor(T1L + KL, 0)
					T1H = bit32.bor(bit32.bor(T1H + KH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, KL), bit32.band(bit32.bor(T1L, KL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + WL, 0)
					T1H = bit32.bor(bit32.bor(T1H + WH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, WL), bit32.band(bit32.bor(T1L, WL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + CL, 0)
					T1H = bit32.bor(bit32.bor(T1H + CH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, CL), bit32.band(bit32.bor(T1L, CL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + XL, 0)
					T1H = bit32.bor(bit32.bor(T1H + XH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, XL), bit32.band(bit32.bor(T1L, XL), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(S4L + T1L, 0)
					S4H = bit32.bor(bit32.bor(S4H + T1H, 0) + bit32.rshift(bit32.bor(bit32.band(S4L, T1L), bit32.band(bit32.bor(S4L, T1L), bit32.bnot(SumL))), 31), 0)
					S4L = SumL
				end
				local MH, ML = bit32.bxor(S2H, bit32.band(ABH, BCH)), bit32.bxor(S2L, bit32.band(ABL, BCL))
				local YH, YL = bit32.bxor(bit32.bor(bit32.rshift(AH, 28), bit32.lshift(AL, 4)), bit32.bor(bit32.rshift(AL, 2), bit32.lshift(AH, 30)), bit32.bor(bit32.rshift(AL, 7), bit32.lshift(AH, 25))), bit32.bxor(bit32.bor(bit32.rshift(AL, 28), bit32.lshift(AH, 4)), bit32.bor(bit32.rshift(AH, 2), bit32.lshift(AL, 30)), bit32.bor(bit32.rshift(AH, 7), bit32.lshift(AL, 25)))
				do
					local SumL = bit32.bor(T1L + ML, 0)
					T1H = bit32.bor(bit32.bor(T1H + MH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, ML), bit32.band(bit32.bor(T1L, ML), bit32.bnot(SumL))), 31), 0)
					T1L = SumL
				end
				do
					local SumL = bit32.bor(T1L + YL, 0)
					S0H = bit32.bor(bit32.bor(T1H + YH, 0) + bit32.rshift(bit32.bor(bit32.band(T1L, YL), bit32.band(bit32.bor(T1L, YL), bit32.bnot(SumL))), 31), 0)
					S0L = SumL
				end
				BCH, BCL = ABH, ABL
			end
		end
		local Sum0 = bit32.bor(O0L + S0L, 0)
		S0H = bit32.bor(bit32.bor(O0H + S0H, 0) + bit32.rshift(bit32.bor(bit32.band(O0L, S0L), bit32.band(bit32.bor(O0L, S0L), bit32.bnot(Sum0))), 31), 0)
		S0L = Sum0
		local Sum1 = bit32.bor(O1L + S1L, 0)
		S1H = bit32.bor(bit32.bor(O1H + S1H, 0) + bit32.rshift(bit32.bor(bit32.band(O1L, S1L), bit32.band(bit32.bor(O1L, S1L), bit32.bnot(Sum1))), 31), 0)
		S1L = Sum1
		local Sum2 = bit32.bor(O2L + S2L, 0)
		S2H = bit32.bor(bit32.bor(O2H + S2H, 0) + bit32.rshift(bit32.bor(bit32.band(O2L, S2L), bit32.band(bit32.bor(O2L, S2L), bit32.bnot(Sum2))), 31), 0)
		S2L = Sum2
		local Sum3 = bit32.bor(O3L + S3L, 0)
		S3H = bit32.bor(bit32.bor(O3H + S3H, 0) + bit32.rshift(bit32.bor(bit32.band(O3L, S3L), bit32.band(bit32.bor(O3L, S3L), bit32.bnot(Sum3))), 31), 0)
		S3L = Sum3
		local Sum4 = bit32.bor(O4L + S4L, 0)
		S4H = bit32.bor(bit32.bor(O4H + S4H, 0) + bit32.rshift(bit32.bor(bit32.band(O4L, S4L), bit32.band(bit32.bor(O4L, S4L), bit32.bnot(Sum4))), 31), 0)
		S4L = Sum4
		local Sum5 = bit32.bor(O5L + S5L, 0)
		S5H = bit32.bor(bit32.bor(O5H + S5H, 0) + bit32.rshift(bit32.bor(bit32.band(O5L, S5L), bit32.band(bit32.bor(O5L, S5L), bit32.bnot(Sum5))), 31), 0)
		S5L = Sum5
		local Sum6 = bit32.bor(O6L + S6L, 0)
		S6H = bit32.bor(bit32.bor(O6H + S6H, 0) + bit32.rshift(bit32.bor(bit32.band(O6L, S6L), bit32.band(bit32.bor(O6L, S6L), bit32.bnot(Sum6))), 31), 0)
		S6L = Sum6
		local Sum7 = bit32.bor(O7L + S7L, 0)
		S7H = bit32.bor(bit32.bor(O7H + S7H, 0) + bit32.rshift(bit32.bor(bit32.band(O7L, S7L), bit32.band(bit32.bor(O7L, S7L), bit32.bnot(Sum7))), 31), 0)
		S7L = Sum7
	end
	buffer.writeu32(State, 0, S0H); buffer.writeu32(State, 4, S0L)
	buffer.writeu32(State, 8, S1H); buffer.writeu32(State, 12, S1L)
	buffer.writeu32(State, 16, S2H); buffer.writeu32(State, 20, S2L)
	buffer.writeu32(State, 24, S3H); buffer.writeu32(State, 28, S3L)
	buffer.writeu32(State, 32, S4H); buffer.writeu32(State, 36, S4L)
	buffer.writeu32(State, 40, S5H); buffer.writeu32(State, 44, S5L)
	buffer.writeu32(State, 48, S6H); buffer.writeu32(State, 52, S6L)
	buffer.writeu32(State, 56, S7H); buffer.writeu32(State, 60, S7L)
end

local function Digest(Message: buffer, InitialState: buffer, OutputBytes: number): buffer
	local State = STATE
	buffer.copy(State, 0, InitialState, 0, 64)

	local MessageLength = buffer.len(Message)
	local TailLength = MessageLength % 128
	local FullBytes = MessageLength - TailLength

	if FullBytes > 0 then
		Compress(Message, 0, FullBytes, State)
	end

	local Tail = TAIL
	local TailBytes = if TailLength < 112 then 128 else 256
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

local function SHA512_Internal(Message: buffer): buffer
	return Digest(Message, IV_512, 64)
end

local function SHA512(Message: buffer): (string, buffer)
	local Result = Digest(Message, IV_512, 64)

	return ToHex(Result), Result
end

return {
	SHA512 = SHA512,
	SHA512_Internal = SHA512_Internal,
	Digest_Internal = Digest,
	IV_384 = IV_384,
}
