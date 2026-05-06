--[=[
	Bitsliced AES core v2: 8 named locals (no table indexing in hot loop),
	multi-return for sub-functions.
--]=]

--!strict
--!optimize 2
--!native

local AESBS = {}

local M_55 = 0x5555555555555555i
local M_AA: integer = -6148914691236517206i
local M_33 = 0x3333333333333333i
local M_CC: integer = -3689348814741910324i
local M_0F = 0x0F0F0F0F0F0F0F0Fi
local M_F0: integer = -1085102592571150096i
local M_INTERLEAVE_16 = 0x0000FFFF0000FFFFi
local M_INTERLEAVE_8 = 0x00FF00FF00FF00FFi
local M_BIT0 = 0x1111111111111111i
local M_BIT1 = 0x2222222222222222i
local M_BIT2 = 0x4444444444444444i
local M_BIT3: integer = -8608480567731124088i

local M_SR_LO = 0x000000000000FFFFi
local M_SR_FFF00000 = 0x00000000FFF00000i
local M_SR_000F0000 = 0x00000000000F0000i
local M_SR_FF40 = 0x0000FF0000000000i
local M_SR_FF32 = 0x000000FF00000000i
local M_SR_F60: integer = -1152921504606846976i
local M_SR_FFF48 = 0x0FFF000000000000i

------------------------------------------------------------------
-- Ortho: 8-arg multi-return form
------------------------------------------------------------------

local function Ortho8(Q0: integer, Q1: integer, Q2: integer, Q3: integer,
	Q4: integer, Q5: integer, Q6: integer, Q7: integer):
	(integer, integer, integer, integer, integer, integer, integer, integer)
	-- SWAP2 pairs: (0,1), (2,3), (4,5), (6,7)
	local A, B
	A, B = Q0, Q1
	Q0 = integer.bor(integer.band(A, M_55), integer.lshift(integer.band(B, M_55), 1i))
	Q1 = integer.bor(integer.rshift(integer.band(A, M_AA), 1i), integer.band(B, M_AA))
	A, B = Q2, Q3
	Q2 = integer.bor(integer.band(A, M_55), integer.lshift(integer.band(B, M_55), 1i))
	Q3 = integer.bor(integer.rshift(integer.band(A, M_AA), 1i), integer.band(B, M_AA))
	A, B = Q4, Q5
	Q4 = integer.bor(integer.band(A, M_55), integer.lshift(integer.band(B, M_55), 1i))
	Q5 = integer.bor(integer.rshift(integer.band(A, M_AA), 1i), integer.band(B, M_AA))
	A, B = Q6, Q7
	Q6 = integer.bor(integer.band(A, M_55), integer.lshift(integer.band(B, M_55), 1i))
	Q7 = integer.bor(integer.rshift(integer.band(A, M_AA), 1i), integer.band(B, M_AA))

	-- SWAP4 pairs: (0,2), (1,3), (4,6), (5,7)
	A, B = Q0, Q2
	Q0 = integer.bor(integer.band(A, M_33), integer.lshift(integer.band(B, M_33), 2i))
	Q2 = integer.bor(integer.rshift(integer.band(A, M_CC), 2i), integer.band(B, M_CC))
	A, B = Q1, Q3
	Q1 = integer.bor(integer.band(A, M_33), integer.lshift(integer.band(B, M_33), 2i))
	Q3 = integer.bor(integer.rshift(integer.band(A, M_CC), 2i), integer.band(B, M_CC))
	A, B = Q4, Q6
	Q4 = integer.bor(integer.band(A, M_33), integer.lshift(integer.band(B, M_33), 2i))
	Q6 = integer.bor(integer.rshift(integer.band(A, M_CC), 2i), integer.band(B, M_CC))
	A, B = Q5, Q7
	Q5 = integer.bor(integer.band(A, M_33), integer.lshift(integer.band(B, M_33), 2i))
	Q7 = integer.bor(integer.rshift(integer.band(A, M_CC), 2i), integer.band(B, M_CC))

	-- SWAP8 pairs: (0,4), (1,5), (2,6), (3,7)
	A, B = Q0, Q4
	Q0 = integer.bor(integer.band(A, M_0F), integer.lshift(integer.band(B, M_0F), 4i))
	Q4 = integer.bor(integer.rshift(integer.band(A, M_F0), 4i), integer.band(B, M_F0))
	A, B = Q1, Q5
	Q1 = integer.bor(integer.band(A, M_0F), integer.lshift(integer.band(B, M_0F), 4i))
	Q5 = integer.bor(integer.rshift(integer.band(A, M_F0), 4i), integer.band(B, M_F0))
	A, B = Q2, Q6
	Q2 = integer.bor(integer.band(A, M_0F), integer.lshift(integer.band(B, M_0F), 4i))
	Q6 = integer.bor(integer.rshift(integer.band(A, M_F0), 4i), integer.band(B, M_F0))
	A, B = Q3, Q7
	Q3 = integer.bor(integer.band(A, M_0F), integer.lshift(integer.band(B, M_0F), 4i))
	Q7 = integer.bor(integer.rshift(integer.band(A, M_F0), 4i), integer.band(B, M_F0))

	return Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7
end

------------------------------------------------------------------
-- InterleaveIn / Out (unchanged from V1)
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
	return integer.bor(X0, integer.lshift(X2, 8i)), integer.bor(X1, integer.lshift(X3, 8i))
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
	return integer.bor(X0, integer.rshift(X0, 16i)),
		integer.bor(X1, integer.rshift(X1, 16i)),
		integer.bor(X2, integer.rshift(X2, 16i)),
		integer.bor(X3, integer.rshift(X3, 16i))
end

------------------------------------------------------------------
-- Sbox8: takes/returns 8 values directly
------------------------------------------------------------------

local function Sbox8(Q0: integer, Q1: integer, Q2: integer, Q3: integer,
	Q4: integer, Q5: integer, Q6: integer, Q7: integer):
	(integer, integer, integer, integer, integer, integer, integer, integer)
	-- Per BearSSL: x0 = q[7] (high), x7 = q[0] (low). So:
	-- X0=Q7 X1=Q6 X2=Q5 X3=Q4 X4=Q3 X5=Q2 X6=Q1 X7=Q0
	local X0 = Q7
	local X1 = Q6
	local X2 = Q5
	local X3 = Q4
	local X4 = Q3
	local X5 = Q2
	local X6 = Q1
	local X7 = Q0

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

	-- Q[7]=S0, Q[6]=S1, Q[5]=S2, Q[4]=S3, Q[3]=S4, Q[2]=S5, Q[1]=S6, Q[0]=S7
	-- Mapping back: Q0=S7, Q1=S6, Q2=S5, Q3=S4, Q4=S3, Q5=S2, Q6=S1, Q7=S0
	return S7, S6, S5, S4, S3, S2, S1, S0
end

------------------------------------------------------------------
-- ShiftRows8 (per-limb transformation, multi-return)
------------------------------------------------------------------

local function ShiftRow1(X: integer): integer
	return integer.bor(integer.bor(integer.bor(integer.bor(integer.bor(integer.bor(
		integer.band(X, M_SR_LO),
		integer.rshift(integer.band(X, M_SR_FFF00000), 4i)),
		integer.lshift(integer.band(X, M_SR_000F0000), 12i)),
		integer.rshift(integer.band(X, M_SR_FF40), 8i)),
		integer.lshift(integer.band(X, M_SR_FF32), 8i)),
		integer.rshift(integer.band(X, M_SR_F60), 12i)),
		integer.lshift(integer.band(X, M_SR_FFF48), 4i))
end

------------------------------------------------------------------
-- MixColumns8: multi-return form
------------------------------------------------------------------

local function MixColumns8(Q0: integer, Q1: integer, Q2: integer, Q3: integer,
	Q4: integer, Q5: integer, Q6: integer, Q7: integer):
	(integer, integer, integer, integer, integer, integer, integer, integer)
	local R0 = integer.bor(integer.rshift(Q0, 16i), integer.lshift(Q0, 48i))
	local R1 = integer.bor(integer.rshift(Q1, 16i), integer.lshift(Q1, 48i))
	local R2 = integer.bor(integer.rshift(Q2, 16i), integer.lshift(Q2, 48i))
	local R3 = integer.bor(integer.rshift(Q3, 16i), integer.lshift(Q3, 48i))
	local R4 = integer.bor(integer.rshift(Q4, 16i), integer.lshift(Q4, 48i))
	local R5 = integer.bor(integer.rshift(Q5, 16i), integer.lshift(Q5, 48i))
	local R6 = integer.bor(integer.rshift(Q6, 16i), integer.lshift(Q6, 48i))
	local R7 = integer.bor(integer.rshift(Q7, 16i), integer.lshift(Q7, 48i))

	local N0 = integer.bxor(Q7, R7, R0, integer.lrotate(integer.bxor(Q0, R0), 32i))
	local N1 = integer.bxor(Q0, R0, Q7, R7, R1, integer.lrotate(integer.bxor(Q1, R1), 32i))
	local N2 = integer.bxor(Q1, R1, R2, integer.lrotate(integer.bxor(Q2, R2), 32i))
	local N3 = integer.bxor(Q2, R2, Q7, R7, R3, integer.lrotate(integer.bxor(Q3, R3), 32i))
	local N4 = integer.bxor(Q3, R3, Q7, R7, R4, integer.lrotate(integer.bxor(Q4, R4), 32i))
	local N5 = integer.bxor(Q4, R4, R5, integer.lrotate(integer.bxor(Q5, R5), 32i))
	local N6 = integer.bxor(Q5, R5, R6, integer.lrotate(integer.bxor(Q6, R6), 32i))
	local N7 = integer.bxor(Q6, R6, R7, integer.lrotate(integer.bxor(Q7, R7), 32i))
	return N0, N1, N2, N3, N4, N5, N6, N7
end

------------------------------------------------------------------
-- Single-word Sbox (for key schedule)
------------------------------------------------------------------

local function SubWord(X: integer): integer
	-- Build q with X in q[0], rest 0, ortho, sbox, ortho back, return q[0]
	local Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7 = X, 0i, 0i, 0i, 0i, 0i, 0i, 0i
	Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7 = Ortho8(Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7)
	Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7 = Sbox8(Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7)
	Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7 = Ortho8(Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7)
	return Q0
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
		if J == Nk then J = 0; K += 1 end
	end

	local CompSkey: {integer} = table.create((NumRounds + 1) * 2, 0i) :: {integer}
	for I = 0, Nkf - 1, 4 do
		local Q0a, Q4a = InterleaveIn(Skey32[I + 1], Skey32[I + 2], Skey32[I + 3], Skey32[I + 4])
		local Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7 = Ortho8(Q0a, Q0a, Q0a, Q0a, Q4a, Q4a, Q4a, Q4a)
		local J2 = (I // 4) * 2
		CompSkey[J2 + 1] = integer.bor(integer.bor(integer.bor(
			integer.band(Q0, M_BIT0), integer.band(Q1, M_BIT1)),
			integer.band(Q2, M_BIT2)), integer.band(Q3, M_BIT3))
		CompSkey[J2 + 2] = integer.bor(integer.bor(integer.bor(
			integer.band(Q4, M_BIT0), integer.band(Q5, M_BIT1)),
			integer.band(Q6, M_BIT2)), integer.band(Q7, M_BIT3))
	end

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
-- EncryptBlocks4: holds Q0..Q7 as locals throughout
------------------------------------------------------------------

function AESBS.EncryptBlocks4(SkeyExp: {integer}, NumRounds: number,
	In: buffer, InOff: number, Out: buffer, OutOff: number)
	-- Load 4 blocks
	local W0 = integer.create(buffer.readu32(In, InOff)) :: integer
	local W1 = integer.create(buffer.readu32(In, InOff + 4)) :: integer
	local W2 = integer.create(buffer.readu32(In, InOff + 8)) :: integer
	local W3 = integer.create(buffer.readu32(In, InOff + 12)) :: integer
	local W4 = integer.create(buffer.readu32(In, InOff + 16)) :: integer
	local W5 = integer.create(buffer.readu32(In, InOff + 20)) :: integer
	local W6 = integer.create(buffer.readu32(In, InOff + 24)) :: integer
	local W7 = integer.create(buffer.readu32(In, InOff + 28)) :: integer
	local W8 = integer.create(buffer.readu32(In, InOff + 32)) :: integer
	local W9 = integer.create(buffer.readu32(In, InOff + 36)) :: integer
	local W10 = integer.create(buffer.readu32(In, InOff + 40)) :: integer
	local W11 = integer.create(buffer.readu32(In, InOff + 44)) :: integer
	local W12 = integer.create(buffer.readu32(In, InOff + 48)) :: integer
	local W13 = integer.create(buffer.readu32(In, InOff + 52)) :: integer
	local W14 = integer.create(buffer.readu32(In, InOff + 56)) :: integer
	local W15 = integer.create(buffer.readu32(In, InOff + 60)) :: integer

	local Q0, Q4 = InterleaveIn(W0, W1, W2, W3)
	local Q1, Q5 = InterleaveIn(W4, W5, W6, W7)
	local Q2, Q6 = InterleaveIn(W8, W9, W10, W11)
	local Q3, Q7 = InterleaveIn(W12, W13, W14, W15)
	Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7 = Ortho8(Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7)

	-- AddRoundKey 0
	Q0 = integer.bxor(Q0, SkeyExp[1])
	Q1 = integer.bxor(Q1, SkeyExp[2])
	Q2 = integer.bxor(Q2, SkeyExp[3])
	Q3 = integer.bxor(Q3, SkeyExp[4])
	Q4 = integer.bxor(Q4, SkeyExp[5])
	Q5 = integer.bxor(Q5, SkeyExp[6])
	Q6 = integer.bxor(Q6, SkeyExp[7])
	Q7 = integer.bxor(Q7, SkeyExp[8])

	for U = 1, NumRounds - 1 do
		Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7 = Sbox8(Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7)
		Q0 = ShiftRow1(Q0)
		Q1 = ShiftRow1(Q1)
		Q2 = ShiftRow1(Q2)
		Q3 = ShiftRow1(Q3)
		Q4 = ShiftRow1(Q4)
		Q5 = ShiftRow1(Q5)
		Q6 = ShiftRow1(Q6)
		Q7 = ShiftRow1(Q7)
		Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7 = MixColumns8(Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7)
		local KO = U * 8
		Q0 = integer.bxor(Q0, SkeyExp[KO + 1])
		Q1 = integer.bxor(Q1, SkeyExp[KO + 2])
		Q2 = integer.bxor(Q2, SkeyExp[KO + 3])
		Q3 = integer.bxor(Q3, SkeyExp[KO + 4])
		Q4 = integer.bxor(Q4, SkeyExp[KO + 5])
		Q5 = integer.bxor(Q5, SkeyExp[KO + 6])
		Q6 = integer.bxor(Q6, SkeyExp[KO + 7])
		Q7 = integer.bxor(Q7, SkeyExp[KO + 8])
	end

	-- Final round (no MixColumns)
	Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7 = Sbox8(Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7)
	Q0 = ShiftRow1(Q0)
	Q1 = ShiftRow1(Q1)
	Q2 = ShiftRow1(Q2)
	Q3 = ShiftRow1(Q3)
	Q4 = ShiftRow1(Q4)
	Q5 = ShiftRow1(Q5)
	Q6 = ShiftRow1(Q6)
	Q7 = ShiftRow1(Q7)
	local KO = NumRounds * 8
	Q0 = integer.bxor(Q0, SkeyExp[KO + 1])
	Q1 = integer.bxor(Q1, SkeyExp[KO + 2])
	Q2 = integer.bxor(Q2, SkeyExp[KO + 3])
	Q3 = integer.bxor(Q3, SkeyExp[KO + 4])
	Q4 = integer.bxor(Q4, SkeyExp[KO + 5])
	Q5 = integer.bxor(Q5, SkeyExp[KO + 6])
	Q6 = integer.bxor(Q6, SkeyExp[KO + 7])
	Q7 = integer.bxor(Q7, SkeyExp[KO + 8])

	Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7 = Ortho8(Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7)

	local A0, A1, A2, A3 = InterleaveOut(Q0, Q4)
	local B0, B1, B2, B3 = InterleaveOut(Q1, Q5)
	local C0, C1, C2, C3 = InterleaveOut(Q2, Q6)
	local D0, D1, D2, D3 = InterleaveOut(Q3, Q7)

	buffer.writeu32(Out, OutOff, integer.tonumber(integer.band(A0, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 4, integer.tonumber(integer.band(A1, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 8, integer.tonumber(integer.band(A2, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 12, integer.tonumber(integer.band(A3, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 16, integer.tonumber(integer.band(B0, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 20, integer.tonumber(integer.band(B1, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 24, integer.tonumber(integer.band(B2, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 28, integer.tonumber(integer.band(B3, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 32, integer.tonumber(integer.band(C0, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 36, integer.tonumber(integer.band(C1, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 40, integer.tonumber(integer.band(C2, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 44, integer.tonumber(integer.band(C3, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 48, integer.tonumber(integer.band(D0, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 52, integer.tonumber(integer.band(D1, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 56, integer.tonumber(integer.band(D2, 0xFFFFFFFFi)))
	buffer.writeu32(Out, OutOff + 60, integer.tonumber(integer.band(D3, 0xFFFFFFFFi)))
end

function AESBS.EncryptBlock(SkeyExp: {integer}, NumRounds: number,
	In: buffer, InOff: number, Out: buffer, OutOff: number)
	local Padded = buffer.create(64)
	buffer.copy(Padded, 0, In, InOff, 16)
	local Tmp = buffer.create(64)
	AESBS.EncryptBlocks4(SkeyExp, NumRounds, Padded, 0, Tmp, 0)
	buffer.copy(Out, OutOff, Tmp, 0, 16)
end

return AESBS
