--[=[
	Bitsliced AES core (4 blocks in parallel via 8x i64 registers).
	Direct port of BearSSL aes_ct64. Encrypt-only.

	Layout: state is 8 i64s q[0..7]. After interleave_in + ortho, q[i] holds
	bit-plane i across all 64 bytes (4 blocks × 16 bytes).

	Public:
		KeySchedule(Key: buffer): (skey: {integer}, NumRounds: number)
		EncryptBlock(SkeyExp: {integer}, NumRounds: number, In: buffer, InOff: number, Out: buffer, OutOff: number)
		EncryptBlocks4(SkeyExp: {integer}, NumRounds: number, In: buffer, InOff: number, Out: buffer, OutOff: number)
--]=]

--!strict
--!optimize 2
--!native

local AESBS = {}

local M_55 = 0x5555555555555555i
local M_AA: integer = -6148914691236517206i  -- 0xAAAAAAAAAAAAAAAA
local M_33 = 0x3333333333333333i
local M_CC: integer = -3689348814741910324i  -- 0xCCCCCCCCCCCCCCCC
local M_0F = 0x0F0F0F0F0F0F0F0Fi
local M_F0: integer = -1085102592571150096i  -- 0xF0F0F0F0F0F0F0F0
local M_INTERLEAVE_16 = 0x0000FFFF0000FFFFi
local M_INTERLEAVE_8 = 0x00FF00FF00FF00FFi
local M_BIT0 = 0x1111111111111111i
local M_BIT1 = 0x2222222222222222i
local M_BIT2 = 0x4444444444444444i
local M_BIT3: integer = -8608480567731124088i  -- 0x8888888888888888

------------------------------------------------------------------
-- ortho: bit transposition between byte-major and bit-plane-major
------------------------------------------------------------------

local function Swap2(X: integer, Y: integer): (integer, integer)
	local A, B = X, Y
	local NewX = integer.bor(integer.band(A, M_55), integer.lshift(integer.band(B, M_55), 1i))
	local NewY = integer.bor(integer.rshift(integer.band(A, M_AA), 1i), integer.band(B, M_AA))
	return NewX, NewY
end

local function Swap4(X: integer, Y: integer): (integer, integer)
	local A, B = X, Y
	local NewX = integer.bor(integer.band(A, M_33), integer.lshift(integer.band(B, M_33), 2i))
	local NewY = integer.bor(integer.rshift(integer.band(A, M_CC), 2i), integer.band(B, M_CC))
	return NewX, NewY
end

local function Swap8(X: integer, Y: integer): (integer, integer)
	local A, B = X, Y
	local NewX = integer.bor(integer.band(A, M_0F), integer.lshift(integer.band(B, M_0F), 4i))
	local NewY = integer.bor(integer.rshift(integer.band(A, M_F0), 4i), integer.band(B, M_F0))
	return NewX, NewY
end

local function Ortho(Q: {integer})
	Q[1], Q[2] = Swap2(Q[1], Q[2])
	Q[3], Q[4] = Swap2(Q[3], Q[4])
	Q[5], Q[6] = Swap2(Q[5], Q[6])
	Q[7], Q[8] = Swap2(Q[7], Q[8])

	Q[1], Q[3] = Swap4(Q[1], Q[3])
	Q[2], Q[4] = Swap4(Q[2], Q[4])
	Q[5], Q[7] = Swap4(Q[5], Q[7])
	Q[6], Q[8] = Swap4(Q[6], Q[8])

	Q[1], Q[5] = Swap8(Q[1], Q[5])
	Q[2], Q[6] = Swap8(Q[2], Q[6])
	Q[3], Q[7] = Swap8(Q[3], Q[7])
	Q[4], Q[8] = Swap8(Q[4], Q[8])
end

------------------------------------------------------------------
-- interleave_in / interleave_out
------------------------------------------------------------------

local function InterleaveIn(W0: integer, W1: integer, W2: integer, W3: integer): (integer, integer)
	local X0 = integer.band(integer.bor(W0, integer.lshift(W0, 16i)), M_INTERLEAVE_16)
	local X1 = integer.band(integer.bor(W1, integer.lshift(W1, 16i)), M_INTERLEAVE_16)
	local X2 = integer.band(integer.bor(W2, integer.lshift(W2, 16i)), M_INTERLEAVE_16)
	local X3 = integer.band(integer.bor(W3, integer.lshift(W3, 16i)), M_INTERLEAVE_16)

	X0 = integer.band(integer.bor(X0, integer.lshift(X0, 8i)), M_INTERLEAVE_8)
	X1 = integer.band(integer.bor(X1, integer.lshift(X1, 8i)), M_INTERLEAVE_8)
	X2 = integer.band(integer.bor(X2, integer.lshift(X2, 8i)), M_INTERLEAVE_8)
	X3 = integer.band(integer.bor(X3, integer.lshift(X3, 8i)), M_INTERLEAVE_8)

	local Q0 = integer.bor(X0, integer.lshift(X2, 8i))
	local Q1 = integer.bor(X1, integer.lshift(X3, 8i))
	return Q0, Q1
end

local function InterleaveOut(Q0: integer, Q1: integer): (integer, integer, integer, integer)
	local X0 = integer.band(Q0, M_INTERLEAVE_8)
	local X1 = integer.band(Q1, M_INTERLEAVE_8)
	local X2 = integer.band(integer.rshift(Q0, 8i), M_INTERLEAVE_8)
	local X3 = integer.band(integer.rshift(Q1, 8i), M_INTERLEAVE_8)

	X0 = integer.band(integer.bor(X0, integer.rshift(X0, 8i)), M_INTERLEAVE_16)
	X1 = integer.band(integer.bor(X1, integer.rshift(X1, 8i)), M_INTERLEAVE_16)
	X2 = integer.band(integer.bor(X2, integer.rshift(X2, 8i)), M_INTERLEAVE_16)
	X3 = integer.band(integer.bor(X3, integer.rshift(X3, 8i)), M_INTERLEAVE_16)

	local W0 = integer.bor(X0, integer.rshift(X0, 16i))
	local W1 = integer.bor(X1, integer.rshift(X1, 16i))
	local W2 = integer.bor(X2, integer.rshift(X2, 16i))
	local W3 = integer.bor(X3, integer.rshift(X3, 16i))
	return W0, W1, W2, W3
end

------------------------------------------------------------------
-- Bitsliced S-box (Boyar-Peralta 2009)
------------------------------------------------------------------

local function BitsliceSbox(Q: {integer})
	local X0 = Q[8]
	local X1 = Q[7]
	local X2 = Q[6]
	local X3 = Q[5]
	local X4 = Q[4]
	local X5 = Q[3]
	local X6 = Q[2]
	local X7 = Q[1]

	-- Top linear transformation
	local Y14 = integer.bxor(X3, X5)
	local Y13 = integer.bxor(X0, X6)
	local Y9 = integer.bxor(X0, X3)
	local Y8 = integer.bxor(X0, X5)
	local T0 = integer.bxor(X1, X2)
	local Y1 = integer.bxor(T0, X7)
	local Y4 = integer.bxor(Y1, X3)
	local Y12 = integer.bxor(Y13, Y14)
	local Y2 = integer.bxor(Y1, X0)
	local Y5 = integer.bxor(Y1, X6)
	local Y3 = integer.bxor(Y5, Y8)
	local T1 = integer.bxor(X4, Y12)
	local Y15 = integer.bxor(T1, X5)
	local Y20 = integer.bxor(T1, X1)
	local Y6 = integer.bxor(Y15, X7)
	local Y10 = integer.bxor(Y15, T0)
	local Y11 = integer.bxor(Y20, Y9)
	local Y7 = integer.bxor(X7, Y11)
	local Y17 = integer.bxor(Y10, Y11)
	local Y19 = integer.bxor(Y10, Y8)
	local Y16 = integer.bxor(T0, Y11)
	local Y21 = integer.bxor(Y13, Y16)
	local Y18 = integer.bxor(X0, Y16)

	-- Non-linear section
	local T2 = integer.band(Y12, Y15)
	local T3 = integer.band(Y3, Y6)
	local T4 = integer.bxor(T3, T2)
	local T5 = integer.band(Y4, X7)
	local T6 = integer.bxor(T5, T2)
	local T7 = integer.band(Y13, Y16)
	local T8 = integer.band(Y5, Y1)
	local T9 = integer.bxor(T8, T7)
	local T10 = integer.band(Y2, Y7)
	local T11 = integer.bxor(T10, T7)
	local T12 = integer.band(Y9, Y11)
	local T13 = integer.band(Y14, Y17)
	local T14 = integer.bxor(T13, T12)
	local T15 = integer.band(Y8, Y10)
	local T16 = integer.bxor(T15, T12)
	local T17 = integer.bxor(T4, T14)
	local T18 = integer.bxor(T6, T16)
	local T19 = integer.bxor(T9, T14)
	local T20 = integer.bxor(T11, T16)
	local T21 = integer.bxor(T17, Y20)
	local T22 = integer.bxor(T18, Y19)
	local T23 = integer.bxor(T19, Y21)
	local T24 = integer.bxor(T20, Y18)

	local T25 = integer.bxor(T21, T22)
	local T26 = integer.band(T21, T23)
	local T27 = integer.bxor(T24, T26)
	local T28 = integer.band(T25, T27)
	local T29 = integer.bxor(T28, T22)
	local T30 = integer.bxor(T23, T24)
	local T31 = integer.bxor(T22, T26)
	local T32 = integer.band(T31, T30)
	local T33 = integer.bxor(T32, T24)
	local T34 = integer.bxor(T23, T33)
	local T35 = integer.bxor(T27, T33)
	local T36 = integer.band(T24, T35)
	local T37 = integer.bxor(T36, T34)
	local T38 = integer.bxor(T27, T36)
	local T39 = integer.band(T29, T38)
	local T40 = integer.bxor(T25, T39)

	local T41 = integer.bxor(T40, T37)
	local T42 = integer.bxor(T29, T33)
	local T43 = integer.bxor(T29, T40)
	local T44 = integer.bxor(T33, T37)
	local T45 = integer.bxor(T42, T41)
	local Z0 = integer.band(T44, Y15)
	local Z1 = integer.band(T37, Y6)
	local Z2 = integer.band(T33, X7)
	local Z3 = integer.band(T43, Y16)
	local Z4 = integer.band(T40, Y1)
	local Z5 = integer.band(T29, Y7)
	local Z6 = integer.band(T42, Y11)
	local Z7 = integer.band(T45, Y17)
	local Z8 = integer.band(T41, Y10)
	local Z9 = integer.band(T44, Y12)
	local Z10 = integer.band(T37, Y3)
	local Z11 = integer.band(T33, Y4)
	local Z12 = integer.band(T43, Y13)
	local Z13 = integer.band(T40, Y5)
	local Z14 = integer.band(T29, Y2)
	local Z15 = integer.band(T42, Y9)
	local Z16 = integer.band(T45, Y14)
	local Z17 = integer.band(T41, Y8)

	-- Bottom linear transformation
	local T46 = integer.bxor(Z15, Z16)
	local T47 = integer.bxor(Z10, Z11)
	local T48 = integer.bxor(Z5, Z13)
	local T49 = integer.bxor(Z9, Z10)
	local T50 = integer.bxor(Z2, Z12)
	local T51 = integer.bxor(Z2, Z5)
	local T52 = integer.bxor(Z7, Z8)
	local T53 = integer.bxor(Z0, Z3)
	local T54 = integer.bxor(Z6, Z7)
	local T55 = integer.bxor(Z16, Z17)
	local T56 = integer.bxor(Z12, T48)
	local T57 = integer.bxor(T50, T53)
	local T58 = integer.bxor(Z4, T46)
	local T59 = integer.bxor(Z3, T54)
	local T60 = integer.bxor(T46, T57)
	local T61 = integer.bxor(Z14, T57)
	local T62 = integer.bxor(T52, T58)
	local T63 = integer.bxor(T49, T58)
	local T64 = integer.bxor(Z4, T59)
	local T65 = integer.bxor(T61, T62)
	local T66 = integer.bxor(Z1, T63)
	local S0 = integer.bxor(T59, T63)
	local S6 = integer.bxor(T56, integer.bnot(T62))
	local S7 = integer.bxor(T48, integer.bnot(T60))
	local T67 = integer.bxor(T64, T65)
	local S3 = integer.bxor(T53, T66)
	local S4 = integer.bxor(T51, T66)
	local S5 = integer.bxor(T47, T65)
	local S1 = integer.bxor(T64, integer.bnot(S3))
	local S2 = integer.bxor(T55, integer.bnot(T67))

	Q[8] = S0
	Q[7] = S1
	Q[6] = S2
	Q[5] = S3
	Q[4] = S4
	Q[3] = S5
	Q[2] = S6
	Q[1] = S7
end

------------------------------------------------------------------
-- ShiftRows
------------------------------------------------------------------

local M_SR_LO = 0x000000000000FFFFi
local M_SR_FFF00000 = 0x00000000FFF00000i
local M_SR_000F0000 = 0x00000000000F0000i
local M_SR_FF40 = 0x0000FF0000000000i
local M_SR_FF32 = 0x000000FF00000000i
local M_SR_F60: integer = -1152921504606846976i  -- 0xF000000000000000
local M_SR_FFF48 = 0x0FFF000000000000i

local function ShiftRows(Q: {integer})
	for I = 1, 8 do
		local X = Q[I]
		Q[I] = integer.bor(integer.bor(integer.bor(integer.bor(integer.bor(integer.bor(
			integer.band(X, M_SR_LO),
			integer.rshift(integer.band(X, M_SR_FFF00000), 4i)),
			integer.lshift(integer.band(X, M_SR_000F0000), 12i)),
			integer.rshift(integer.band(X, M_SR_FF40), 8i)),
			integer.lshift(integer.band(X, M_SR_FF32), 8i)),
			integer.rshift(integer.band(X, M_SR_F60), 12i)),
			integer.lshift(integer.band(X, M_SR_FFF48), 4i))
	end
end

------------------------------------------------------------------
-- MixColumns
------------------------------------------------------------------

local function MixColumns(Q: {integer})
	local Q0 = Q[1]
	local Q1 = Q[2]
	local Q2 = Q[3]
	local Q3 = Q[4]
	local Q4 = Q[5]
	local Q5 = Q[6]
	local Q6 = Q[7]
	local Q7 = Q[8]

	local R0 = integer.bor(integer.rshift(Q0, 16i), integer.lshift(Q0, 48i))
	local R1 = integer.bor(integer.rshift(Q1, 16i), integer.lshift(Q1, 48i))
	local R2 = integer.bor(integer.rshift(Q2, 16i), integer.lshift(Q2, 48i))
	local R3 = integer.bor(integer.rshift(Q3, 16i), integer.lshift(Q3, 48i))
	local R4 = integer.bor(integer.rshift(Q4, 16i), integer.lshift(Q4, 48i))
	local R5 = integer.bor(integer.rshift(Q5, 16i), integer.lshift(Q5, 48i))
	local R6 = integer.bor(integer.rshift(Q6, 16i), integer.lshift(Q6, 48i))
	local R7 = integer.bor(integer.rshift(Q7, 16i), integer.lshift(Q7, 48i))

	Q[1] = integer.bxor(integer.bxor(integer.bxor(Q7, R7), R0), integer.lrotate(integer.bxor(Q0, R0), 32i))
	Q[2] = integer.bxor(integer.bxor(integer.bxor(integer.bxor(integer.bxor(Q0, R0), Q7), R7), R1), integer.lrotate(integer.bxor(Q1, R1), 32i))
	Q[3] = integer.bxor(integer.bxor(integer.bxor(Q1, R1), R2), integer.lrotate(integer.bxor(Q2, R2), 32i))
	Q[4] = integer.bxor(integer.bxor(integer.bxor(integer.bxor(integer.bxor(Q2, R2), Q7), R7), R3), integer.lrotate(integer.bxor(Q3, R3), 32i))
	Q[5] = integer.bxor(integer.bxor(integer.bxor(integer.bxor(integer.bxor(Q3, R3), Q7), R7), R4), integer.lrotate(integer.bxor(Q4, R4), 32i))
	Q[6] = integer.bxor(integer.bxor(integer.bxor(Q4, R4), R5), integer.lrotate(integer.bxor(Q5, R5), 32i))
	Q[7] = integer.bxor(integer.bxor(integer.bxor(Q5, R5), R6), integer.lrotate(integer.bxor(Q6, R6), 32i))
	Q[8] = integer.bxor(integer.bxor(integer.bxor(Q6, R6), R7), integer.lrotate(integer.bxor(Q7, R7), 32i))
end

------------------------------------------------------------------
-- AddRoundKey
------------------------------------------------------------------

local function AddRoundKey(Q: {integer}, Skey: {integer}, Offset: number)
	Q[1] = integer.bxor(Q[1], Skey[Offset + 1])
	Q[2] = integer.bxor(Q[2], Skey[Offset + 2])
	Q[3] = integer.bxor(Q[3], Skey[Offset + 3])
	Q[4] = integer.bxor(Q[4], Skey[Offset + 4])
	Q[5] = integer.bxor(Q[5], Skey[Offset + 5])
	Q[6] = integer.bxor(Q[6], Skey[Offset + 6])
	Q[7] = integer.bxor(Q[7], Skey[Offset + 7])
	Q[8] = integer.bxor(Q[8], Skey[Offset + 8])
end

------------------------------------------------------------------
-- Single-word Sbox (used by key schedule)
------------------------------------------------------------------

local function SubWord(X: integer): integer
	local Q: {integer} = {X, 0i, 0i, 0i, 0i, 0i, 0i, 0i}
	Ortho(Q)
	BitsliceSbox(Q)
	Ortho(Q)
	return Q[1]
end

------------------------------------------------------------------
-- Key schedule
------------------------------------------------------------------

local RCON = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36}

local function KeySchedule(Key: buffer): ({integer}, number)
	local KeyLen = buffer.len(Key)
	local NumRounds: number
	if KeyLen == 16 then NumRounds = 10
	elseif KeyLen == 24 then NumRounds = 12
	elseif KeyLen == 32 then NumRounds = 14
	else error(`bad key length {KeyLen}`) end

	local Nk = KeyLen // 4
	local Nkf = (NumRounds + 1) * 4

	-- Read raw key as u32 array (little-endian)
	local Skey32: {integer} = table.create(Nkf, 0i) :: {integer}
	for I = 0, Nk - 1 do
		Skey32[I + 1] = integer.create(buffer.readu32(Key, I * 4)) :: integer
	end

	local Tmp: integer = Skey32[Nk]
	local J = 0
	local K = 1
	for I = Nk, Nkf - 1 do
		if J == 0 then
			Tmp = integer.bor(integer.lshift(Tmp, 24i), integer.rshift(integer.band(Tmp, 0xFFFFFFFFi), 8i))
			Tmp = integer.band(Tmp, 0xFFFFFFFFi)
			Tmp = integer.bxor(SubWord(Tmp), integer.create(RCON[K]) :: integer)
		elseif Nk > 6 and J == 4 then
			Tmp = SubWord(Tmp)
		end
		Tmp = integer.bxor(Tmp, Skey32[I - Nk + 1])
		Tmp = integer.band(Tmp, 0xFFFFFFFFi)
		Skey32[I + 1] = Tmp
		J += 1
		if J == Nk then
			J = 0
			K += 1
		end
	end

	-- Convert each 4-word round key to bitsliced form (compressed: 2 i64 per round key)
	local CompSkey: {integer} = table.create((NumRounds + 1) * 2, 0i) :: {integer}
	for I = 0, Nkf - 1, 4 do
		local Q0, Q4 = InterleaveIn(Skey32[I + 1], Skey32[I + 2], Skey32[I + 3], Skey32[I + 4])
		local Q: {integer} = {Q0, Q0, Q0, Q0, Q4, Q4, Q4, Q4}
		Ortho(Q)
		local J2 = (I // 4) * 2
		CompSkey[J2 + 1] = integer.bor(integer.bor(integer.bor(
			integer.band(Q[1], M_BIT0),
			integer.band(Q[2], M_BIT1)),
			integer.band(Q[3], M_BIT2)),
			integer.band(Q[4], M_BIT3))
		CompSkey[J2 + 2] = integer.bor(integer.bor(integer.bor(
			integer.band(Q[5], M_BIT0),
			integer.band(Q[6], M_BIT1)),
			integer.band(Q[7], M_BIT2)),
			integer.band(Q[8], M_BIT3))
	end

	-- Expand compressed schedule to full 8 i64 per round (skey_expand)
	local SkeyExp: {integer} = table.create((NumRounds + 1) * 8, 0i) :: {integer}
	local N = (NumRounds + 1) * 2
	local V = 0
	for U = 1, N do
		local C = CompSkey[U]
		local X0 = integer.band(C, M_BIT0)
		local X1 = integer.rshift(integer.band(C, M_BIT1), 1i)
		local X2 = integer.rshift(integer.band(C, M_BIT2), 2i)
		local X3 = integer.rshift(integer.band(C, M_BIT3), 3i)
		SkeyExp[V + 1] = integer.sub(integer.lshift(X0, 4i), X0)
		SkeyExp[V + 2] = integer.sub(integer.lshift(X1, 4i), X1)
		SkeyExp[V + 3] = integer.sub(integer.lshift(X2, 4i), X2)
		SkeyExp[V + 4] = integer.sub(integer.lshift(X3, 4i), X3)
		V += 4
	end

	return SkeyExp, NumRounds
end

AESBS.KeySchedule = KeySchedule

------------------------------------------------------------------
-- Encrypt 4 blocks at once
------------------------------------------------------------------

local function BitsliceEncrypt(NumRounds: number, SkeyExp: {integer}, Q: {integer})
	AddRoundKey(Q, SkeyExp, 0)
	for U = 1, NumRounds - 1 do
		BitsliceSbox(Q)
		ShiftRows(Q)
		MixColumns(Q)
		AddRoundKey(Q, SkeyExp, U * 8)
	end
	BitsliceSbox(Q)
	ShiftRows(Q)
	AddRoundKey(Q, SkeyExp, NumRounds * 8)
end

function AESBS.EncryptBlocks4(SkeyExp: {integer}, NumRounds: number,
	In: buffer, InOff: number, Out: buffer, OutOff: number)
	-- Load 4 blocks (16 bytes each = 4 u32 each)
	local W: {integer} = table.create(16, 0i) :: {integer}
	for I = 0, 15 do
		W[I + 1] = integer.create(buffer.readu32(In, InOff + I * 4)) :: integer
	end

	local Q: {integer} = table.create(8, 0i) :: {integer}
	for I = 0, 3 do
		local Q0, Q1 = InterleaveIn(W[I * 4 + 1], W[I * 4 + 2], W[I * 4 + 3], W[I * 4 + 4])
		Q[I + 1] = Q0
		Q[I + 5] = Q1
	end
	Ortho(Q)

	BitsliceEncrypt(NumRounds, SkeyExp, Q)

	Ortho(Q)
	for I = 0, 3 do
		local W0, W1, W2, W3 = InterleaveOut(Q[I + 1], Q[I + 5])
		buffer.writeu32(Out, OutOff + (I * 4 + 0) * 4, integer.tonumber(integer.band(W0, 0xFFFFFFFFi)))
		buffer.writeu32(Out, OutOff + (I * 4 + 1) * 4, integer.tonumber(integer.band(W1, 0xFFFFFFFFi)))
		buffer.writeu32(Out, OutOff + (I * 4 + 2) * 4, integer.tonumber(integer.band(W2, 0xFFFFFFFFi)))
		buffer.writeu32(Out, OutOff + (I * 4 + 3) * 4, integer.tonumber(integer.band(W3, 0xFFFFFFFFi)))
	end
end

-- Single-block: just put it in slot 0, ignore other 3 outputs
function AESBS.EncryptBlock(SkeyExp: {integer}, NumRounds: number,
	In: buffer, InOff: number, Out: buffer, OutOff: number)
	local Padded = buffer.create(64)
	buffer.copy(Padded, 0, In, InOff, 16)
	local Tmp = buffer.create(64)
	AESBS.EncryptBlocks4(SkeyExp, NumRounds, Padded, 0, Tmp, 0)
	buffer.copy(Out, OutOff, Tmp, 0, 16)
end

return AESBS
