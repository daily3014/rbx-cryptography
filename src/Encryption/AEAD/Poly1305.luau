--[=[
	Cryptography library: Poly1305

	Sizes:
		Key: 32 bytes
		Tag: 16 bytes

	Return type: buffer
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Key = buffer.fromstring(string.rep("k", 32))

		local Tag = Poly1305.Tag(Message, Key)
--]=]

--!strict
--!optimize 2
--!native

local TAG_SIZE = 16
local BLOCK_SIZE = 16
local POLY1305_KEY_SIZE = 32
local HIGH_BIT = 2 ^ 128

local CONTEXT = buffer.create(352)
local TAIL = buffer.create(BLOCK_SIZE)

local function DecodeKey(Key: buffer): (number, number, number, number, number, number, number, number, number, number, number)
	local W0 = bit32.band(buffer.readu32(Key, 0), 0x0fffffff)
	local W1 = bit32.band(buffer.readu32(Key, 4), 0x0ffffffc)
	local W2 = bit32.band(buffer.readu32(Key, 8), 0x0ffffffc)
	local W3 = bit32.band(buffer.readu32(Key, 12), 0x0ffffffc)

	local A0 = bit32.band(W0, 0x3fffff)
	local A1 = bit32.bor(bit32.rshift(W0, 22), bit32.lshift(bit32.band(W1, 0xfff), 10)) * 2 ^ 22
	local A2 = bit32.bor(bit32.rshift(W1, 12), bit32.lshift(bit32.band(W2, 3), 20)) * 2 ^ 44
	local A3 = bit32.band(bit32.rshift(W2, 2), 0x3fffff) * 2 ^ 66
	local A4 = bit32.bor(bit32.rshift(W2, 24), bit32.lshift(bit32.band(W3, 0x3fff), 8)) * 2 ^ 88
	local A5 = bit32.rshift(W3, 14) * 2 ^ 110

	local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
	local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
	local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
	local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
	local R0 = A0 - C0
	local R1 = (A1 - C1) + C0
	local R2 = (A2 - C2) + C1
	local R3 = (A3 - C3) + C2
	local R4 = (A4 - C4) + C3
	local R5 = A5 + C4

	return R0, R1, R2, R3, R4, R5,
		R1 * (5 * 2 ^ -130),
		R2 * (5 * 2 ^ -130),
		R3 * (5 * 2 ^ -130),
		R4 * (5 * 2 ^ -130),
		R5 * (5 * 2 ^ -130)
end

local function MulLimbs(Context: buffer, AOff: number, BOff: number, OutOff: number)
	local X0, X1, X2, X3, X4, X5 = buffer.readf64(Context, AOff), buffer.readf64(Context, AOff + 8), buffer.readf64(Context, AOff + 16), buffer.readf64(Context, AOff + 24), buffer.readf64(Context, AOff + 32), buffer.readf64(Context, AOff + 40)
	local R0, R1, R2, R3, R4, R5 = buffer.readf64(Context, BOff), buffer.readf64(Context, BOff + 8), buffer.readf64(Context, BOff + 16), buffer.readf64(Context, BOff + 24), buffer.readf64(Context, BOff + 32), buffer.readf64(Context, BOff + 40)
	local S1, S2, S3, S4, S5 = buffer.readf64(Context, BOff + 48), buffer.readf64(Context, BOff + 56), buffer.readf64(Context, BOff + 64), buffer.readf64(Context, BOff + 72), buffer.readf64(Context, BOff + 80)
	local A0 = ((X0 * R0 + X1 * S5) + (X2 * S4 + X3 * S3)) + (X4 * S2 + X5 * S1)
	local A1 = ((X0 * R1 + X1 * R0) + (X2 * S5 + X3 * S4)) + (X4 * S3 + X5 * S2)
	local A2 = ((X0 * R2 + X1 * R1) + (X2 * R0 + X3 * S5)) + (X4 * S4 + X5 * S3)
	local A3 = ((X0 * R3 + X1 * R2) + (X2 * R1 + X3 * R0)) + (X4 * S5 + X5 * S4)
	local A4 = ((X0 * R4 + X1 * R3) + (X2 * R2 + X3 * R1)) + (X4 * R0 + X5 * S5)
	local A5 = ((X0 * R5 + X1 * R4) + (X2 * R3 + X3 * R2)) + (X4 * R1 + X5 * R0)
	local Q0, Q1, Q2, Q3, Q4, Q5
	local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
	local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
	local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
	local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
	local C5 = A5 + 3 * 2 ^ 181 - 3 * 2 ^ 181
	local B0 = (A0 - C0) + C5 * (5 * 2 ^ -130)
	local B1 = (A1 - C1) + C0
	local B2 = (A2 - C2) + C1
	local B3 = (A3 - C3) + C2
	local B4 = (A4 - C4) + C3
	local B5 = (A5 - C5) + C4
	local D0 = B0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	local D1 = B1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
	local D2 = B2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
	local D3 = B3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
	local D4 = B4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
	local D5 = B5 + 3 * 2 ^ 181 - 3 * 2 ^ 181
	Q0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
	Q1 = (B1 - D1) + D0
	Q2 = (B2 - D2) + D1
	Q3 = (B3 - D3) + D2
	Q4 = (B4 - D4) + D3
	Q5 = (B5 - D5) + D4
	buffer.writef64(Context, OutOff, Q0)
	buffer.writef64(Context, OutOff + 8, Q1)
	buffer.writef64(Context, OutOff + 16, Q2)
	buffer.writef64(Context, OutOff + 24, Q3)
	buffer.writef64(Context, OutOff + 32, Q4)
	buffer.writef64(Context, OutOff + 40, Q5)
	buffer.writef64(Context, OutOff + 48, Q1 * (5 * 2 ^ -130))
	buffer.writef64(Context, OutOff + 56, Q2 * (5 * 2 ^ -130))
	buffer.writef64(Context, OutOff + 64, Q3 * (5 * 2 ^ -130))
	buffer.writef64(Context, OutOff + 72, Q4 * (5 * 2 ^ -130))
	buffer.writef64(Context, OutOff + 80, Q5 * (5 * 2 ^ -130))
end

local function PreparePowers(Context: buffer, R0: number, R1: number, R2: number, R3: number, R4: number, R5: number, S1: number, S2: number, S3: number, S4: number, S5: number)
	buffer.writef64(Context, 0, R0)
	buffer.writef64(Context, 8, R1)
	buffer.writef64(Context, 16, R2)
	buffer.writef64(Context, 24, R3)
	buffer.writef64(Context, 32, R4)
	buffer.writef64(Context, 40, R5)
	buffer.writef64(Context, 48, S1)
	buffer.writef64(Context, 56, S2)
	buffer.writef64(Context, 64, S3)
	buffer.writef64(Context, 72, S4)
	buffer.writef64(Context, 80, S5)
	MulLimbs(Context, 0, 0, 88)
	MulLimbs(Context, 0, 88, 176)
	MulLimbs(Context, 88, 88, 264)
end

local function CopyTail(Tail: buffer, Data: buffer, Offset: number, TailLength: number)
	buffer.writef64(Tail, 0, 0)
	buffer.writef64(Tail, 8, 0)
	local Pos = 0
	while Pos + 4 <= TailLength do
		buffer.writeu32(Tail, Pos, buffer.readu32(Data, Offset + Pos))
		Pos += 4
	end
	while Pos < TailLength do
		buffer.writeu8(Tail, Pos, buffer.readu8(Data, Offset + Pos))
		Pos += 1
	end
end

local function AbsorbRegs(Data: buffer, Offset: number, EndPos: number, HighBit: number, H0: number, H1: number, H2: number, H3: number, H4: number, H5: number, R0: number, R1: number, R2: number, R3: number, R4: number, R5: number, S1: number, S2: number, S3: number, S4: number, S5: number): (number, number, number, number, number, number)
	for Position = Offset, EndPos - 16, 16 do
		local M0 = buffer.readu32(Data, Position)
		local M1 = buffer.readu32(Data, Position + 4)
		local M2 = buffer.readu32(Data, Position + 8)
		local M3 = buffer.readu32(Data, Position + 12)
		local X0 = H0 + bit32.band(M0, 0x3fffff)
		local X1 = H1 + bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
		local X2 = H2 + bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
		local X3 = H3 + bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
		local X4 = H4 + bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
		local X5 = H5 + (bit32.rshift(M3, 14) * 2 ^ 110 + HighBit)
		local A0 = ((X0 * R0 + X1 * S5) + (X2 * S4 + X3 * S3)) + (X4 * S2 + X5 * S1)
		local A1 = ((X0 * R1 + X1 * R0) + (X2 * S5 + X3 * S4)) + (X4 * S3 + X5 * S2)
		local A2 = ((X0 * R2 + X1 * R1) + (X2 * R0 + X3 * S5)) + (X4 * S4 + X5 * S3)
		local A3 = ((X0 * R3 + X1 * R2) + (X2 * R1 + X3 * R0)) + (X4 * S5 + X5 * S4)
		local A4 = ((X0 * R4 + X1 * R3) + (X2 * R2 + X3 * R1)) + (X4 * R0 + X5 * S5)
		local A5 = ((X0 * R5 + X1 * R4) + (X2 * R3 + X3 * R2)) + (X4 * R1 + X5 * R0)
		local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
		local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
		local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
		local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
		local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
		local C5 = A5 + 3 * 2 ^ 181 - 3 * 2 ^ 181
		local B0 = (A0 - C0) + C5 * (5 * 2 ^ -130)
		local B1 = (A1 - C1) + C0
		local B2 = (A2 - C2) + C1
		local B3 = (A3 - C3) + C2
		local B4 = (A4 - C4) + C3
		local B5 = (A5 - C5) + C4
		local D0 = B0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
		local D1 = B1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
		local D2 = B2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
		local D3 = B3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
		local D4 = B4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
		local D5 = B5 + 3 * 2 ^ 181 - 3 * 2 ^ 181
		H0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
		H1 = (B1 - D1) + D0
		H2 = (B2 - D2) + D1
		H3 = (B3 - D3) + D2
		H4 = (B4 - D4) + D3
		H5 = (B5 - D5) + D4
	end
	return H0, H1, H2, H3, H4, H5
end

local function AbsorbBatch(Context: buffer, Data: buffer, BatchBytes: number, HighBit: number, H0: number, H1: number, H2: number, H3: number, H4: number, H5: number): (number, number, number, number, number, number)
	for Position = 0, BatchBytes - 64, 64 do
		local A0, A1, A2, A3, A4, A5 = 0, 0, 0, 0, 0, 0
		do
			local M0 = buffer.readu32(Data, Position + 48)
			local M1 = buffer.readu32(Data, Position + 48 + 4)
			local M2 = buffer.readu32(Data, Position + 48 + 8)
			local M3 = buffer.readu32(Data, Position + 48 + 12)
			local X0 = bit32.band(M0, 0x3fffff)
			local X1 = bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
			local X2 = bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
			local X3 = bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
			local X4 = bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
			local X5 = bit32.rshift(M3, 14) * 2 ^ 110 + HighBit
			local P10, P11, P12, P13, P14, P15 = buffer.readf64(Context, 0), buffer.readf64(Context, 8), buffer.readf64(Context, 16), buffer.readf64(Context, 24), buffer.readf64(Context, 32), buffer.readf64(Context, 40)
			local P1S1, P1S2, P1S3, P1S4, P1S5 = buffer.readf64(Context, 48), buffer.readf64(Context, 56), buffer.readf64(Context, 64), buffer.readf64(Context, 72), buffer.readf64(Context, 80)
			A0 = ((X0 * P10 + X1 * P1S5) + (X2 * P1S4 + X3 * P1S3)) + (X4 * P1S2 + X5 * P1S1)
			A1 = ((X0 * P11 + X1 * P10) + (X2 * P1S5 + X3 * P1S4)) + (X4 * P1S3 + X5 * P1S2)
			A2 = ((X0 * P12 + X1 * P11) + (X2 * P10 + X3 * P1S5)) + (X4 * P1S4 + X5 * P1S3)
			A3 = ((X0 * P13 + X1 * P12) + (X2 * P11 + X3 * P10)) + (X4 * P1S5 + X5 * P1S4)
			A4 = ((X0 * P14 + X1 * P13) + (X2 * P12 + X3 * P11)) + (X4 * P10 + X5 * P1S5)
			A5 = ((X0 * P15 + X1 * P14) + (X2 * P13 + X3 * P12)) + (X4 * P11 + X5 * P10)
		end
		do
			local M0 = buffer.readu32(Data, Position + 32)
			local M1 = buffer.readu32(Data, Position + 32 + 4)
			local M2 = buffer.readu32(Data, Position + 32 + 8)
			local M3 = buffer.readu32(Data, Position + 32 + 12)
			local X0 = bit32.band(M0, 0x3fffff)
			local X1 = bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
			local X2 = bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
			local X3 = bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
			local X4 = bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
			local X5 = bit32.rshift(M3, 14) * 2 ^ 110 + HighBit
			local P20, P21, P22, P23, P24, P25 = buffer.readf64(Context, 88), buffer.readf64(Context, 96), buffer.readf64(Context, 104), buffer.readf64(Context, 112), buffer.readf64(Context, 120), buffer.readf64(Context, 128)
			local P2S1, P2S2, P2S3, P2S4, P2S5 = buffer.readf64(Context, 136), buffer.readf64(Context, 144), buffer.readf64(Context, 152), buffer.readf64(Context, 160), buffer.readf64(Context, 168)
			A0 += ((X0 * P20 + X1 * P2S5) + (X2 * P2S4 + X3 * P2S3)) + (X4 * P2S2 + X5 * P2S1)
			A1 += ((X0 * P21 + X1 * P20) + (X2 * P2S5 + X3 * P2S4)) + (X4 * P2S3 + X5 * P2S2)
			A2 += ((X0 * P22 + X1 * P21) + (X2 * P20 + X3 * P2S5)) + (X4 * P2S4 + X5 * P2S3)
			A3 += ((X0 * P23 + X1 * P22) + (X2 * P21 + X3 * P20)) + (X4 * P2S5 + X5 * P2S4)
			A4 += ((X0 * P24 + X1 * P23) + (X2 * P22 + X3 * P21)) + (X4 * P20 + X5 * P2S5)
			A5 += ((X0 * P25 + X1 * P24) + (X2 * P23 + X3 * P22)) + (X4 * P21 + X5 * P20)
		end
		do
			local M0 = buffer.readu32(Data, Position + 16)
			local M1 = buffer.readu32(Data, Position + 16 + 4)
			local M2 = buffer.readu32(Data, Position + 16 + 8)
			local M3 = buffer.readu32(Data, Position + 16 + 12)
			local X0 = bit32.band(M0, 0x3fffff)
			local X1 = bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
			local X2 = bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
			local X3 = bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
			local X4 = bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
			local X5 = bit32.rshift(M3, 14) * 2 ^ 110 + HighBit
			local P30, P31, P32, P33, P34, P35 = buffer.readf64(Context, 176), buffer.readf64(Context, 184), buffer.readf64(Context, 192), buffer.readf64(Context, 200), buffer.readf64(Context, 208), buffer.readf64(Context, 216)
			local P3S1, P3S2, P3S3, P3S4, P3S5 = buffer.readf64(Context, 224), buffer.readf64(Context, 232), buffer.readf64(Context, 240), buffer.readf64(Context, 248), buffer.readf64(Context, 256)
			A0 += ((X0 * P30 + X1 * P3S5) + (X2 * P3S4 + X3 * P3S3)) + (X4 * P3S2 + X5 * P3S1)
			A1 += ((X0 * P31 + X1 * P30) + (X2 * P3S5 + X3 * P3S4)) + (X4 * P3S3 + X5 * P3S2)
			A2 += ((X0 * P32 + X1 * P31) + (X2 * P30 + X3 * P3S5)) + (X4 * P3S4 + X5 * P3S3)
			A3 += ((X0 * P33 + X1 * P32) + (X2 * P31 + X3 * P30)) + (X4 * P3S5 + X5 * P3S4)
			A4 += ((X0 * P34 + X1 * P33) + (X2 * P32 + X3 * P31)) + (X4 * P30 + X5 * P3S5)
			A5 += ((X0 * P35 + X1 * P34) + (X2 * P33 + X3 * P32)) + (X4 * P31 + X5 * P30)
		end
		do
			local M0 = buffer.readu32(Data, Position)
			local M1 = buffer.readu32(Data, Position + 4)
			local M2 = buffer.readu32(Data, Position + 8)
			local M3 = buffer.readu32(Data, Position + 12)
			local X0 = H0 + bit32.band(M0, 0x3fffff)
			local X1 = H1 + bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
			local X2 = H2 + bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
			local X3 = H3 + bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
			local X4 = H4 + bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
			local X5 = H5 + (bit32.rshift(M3, 14) * 2 ^ 110 + HighBit)
			local P40, P41, P42, P43, P44, P45 = buffer.readf64(Context, 264), buffer.readf64(Context, 272), buffer.readf64(Context, 280), buffer.readf64(Context, 288), buffer.readf64(Context, 296), buffer.readf64(Context, 304)
			local P4S1, P4S2, P4S3, P4S4, P4S5 = buffer.readf64(Context, 312), buffer.readf64(Context, 320), buffer.readf64(Context, 328), buffer.readf64(Context, 336), buffer.readf64(Context, 344)
			A0 += ((X0 * P40 + X1 * P4S5) + (X2 * P4S4 + X3 * P4S3)) + (X4 * P4S2 + X5 * P4S1)
			A1 += ((X0 * P41 + X1 * P40) + (X2 * P4S5 + X3 * P4S4)) + (X4 * P4S3 + X5 * P4S2)
			A2 += ((X0 * P42 + X1 * P41) + (X2 * P40 + X3 * P4S5)) + (X4 * P4S4 + X5 * P4S3)
			A3 += ((X0 * P43 + X1 * P42) + (X2 * P41 + X3 * P40)) + (X4 * P4S5 + X5 * P4S4)
			A4 += ((X0 * P44 + X1 * P43) + (X2 * P42 + X3 * P41)) + (X4 * P40 + X5 * P4S5)
			A5 += ((X0 * P45 + X1 * P44) + (X2 * P43 + X3 * P42)) + (X4 * P41 + X5 * P40)
		end
		local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
		local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
		local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
		local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
		local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
		local C5 = A5 + 3 * 2 ^ 181 - 3 * 2 ^ 181
		local B0 = (A0 - C0) + C5 * (5 * 2 ^ -130)
		local B1 = (A1 - C1) + C0
		local B2 = (A2 - C2) + C1
		local B3 = (A3 - C3) + C2
		local B4 = (A4 - C4) + C3
		local B5 = (A5 - C5) + C4
		local D0 = B0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
		local D1 = B1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
		local D2 = B2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
		local D3 = B3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
		local D4 = B4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
		local D5 = B5 + 3 * 2 ^ 181 - 3 * 2 ^ 181
		H0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
		H1 = (B1 - D1) + D0
		H2 = (B2 - D2) + D1
		H3 = (B3 - D3) + D2
		H4 = (B4 - D4) + D3
		H5 = (B5 - D5) + D4
	end
	return H0, H1, H2, H3, H4, H5
end

local function FinalizeFromRegs(H0: number, H1: number, H2: number, H3: number, H4: number, H5: number, Key: buffer): (number, number, number, number)
	repeat
		local C0 = math.floor(H0 * 2 ^ -22) * 2 ^ 22
		H0 -= C0
		H1 += C0
		local C1 = math.floor(H1 * 2 ^ -44) * 2 ^ 44
		H1 -= C1
		H2 += C1
		local C2 = math.floor(H2 * 2 ^ -66) * 2 ^ 66
		H2 -= C2
		H3 += C2
		local C3 = math.floor(H3 * 2 ^ -88) * 2 ^ 88
		H3 -= C3
		H4 += C3
		local C4 = math.floor(H4 * 2 ^ -110) * 2 ^ 110
		H4 -= C4
		H5 += C4
		local C5 = math.floor(H5 * 2 ^ -130)
		H5 -= C5 * 2 ^ 130
		H0 += C5 * 5
	until C5 == 0 and H0 >= 0 and H0 < 2 ^ 22

	local Sum = H0 + H1
	local High = math.floor(Sum * 2 ^ -32) * 2 ^ 32
	local Word0 = Sum - High
	Sum = High + H2
	High = math.floor(Sum * 2 ^ -64) * 2 ^ 64
	local Word1 = (Sum - High) * 2 ^ -32
	Sum = High + H3 + H4
	High = math.floor(Sum * 2 ^ -96) * 2 ^ 96
	local Word2 = (Sum - High) * 2 ^ -64
	Sum = High + H5
	local Top = math.floor(Sum * 2 ^ -128) * 2 ^ 128
	local Word3 = (Sum - Top) * 2 ^ -96

	if Top == 3 * 2 ^ 128 and Word3 == 0xffffffff and Word2 == 0xffffffff and Word1 == 0xffffffff and Word0 >= 0xfffffffb then
		Word0 -= 0xfffffffb
		Word1, Word2, Word3 = 0, 0, 0
	end

	local C0 = Word0 + buffer.readu32(Key, 16)
	local W0 = bit32.bor(C0, 0)
	local C1 = Word1 + buffer.readu32(Key, 20) + (if C0 >= 2 ^ 32 then 1 else 0)
	local W1 = bit32.bor(C1, 0)
	local C2 = Word2 + buffer.readu32(Key, 24) + (if C1 >= 2 ^ 32 then 1 else 0)
	local W2 = bit32.bor(C2, 0)
	local C3 = Word3 + buffer.readu32(Key, 28) + (if C2 >= 2 ^ 32 then 1 else 0)
	local W3 = bit32.bor(C3, 0)
	return W0, W1, W2, W3
end

local function AeadHash(Key: buffer, AdditionalData: buffer, Ciphertext: buffer): (number, number, number, number)
	local R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5 = DecodeKey(Key)
	local H0, H1, H2, H3, H4, H5 = 0, 0, 0, 0, 0, 0
	local PowersReady = false

	local AadLen = buffer.len(AdditionalData)
	if AadLen > 0 then
		local TailLength = AadLen % BLOCK_SIZE
		local FullBytes = AadLen - TailLength
		if FullBytes > 0 then
			local BlockCount = FullBytes // BLOCK_SIZE
			if BlockCount >= 20 then
				PreparePowers(CONTEXT, R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5)
				PowersReady = true
				local BatchBytes = (BlockCount - BlockCount % 4) * BLOCK_SIZE
				H0, H1, H2, H3, H4, H5 = AbsorbBatch(CONTEXT, AdditionalData, BatchBytes, HIGH_BIT, H0, H1, H2, H3, H4, H5)
				if BatchBytes < FullBytes then
					H0, H1, H2, H3, H4, H5 = AbsorbRegs(AdditionalData, BatchBytes, FullBytes, HIGH_BIT, H0, H1, H2, H3, H4, H5, R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5)
				end
			else
				H0, H1, H2, H3, H4, H5 = AbsorbRegs(AdditionalData, 0, FullBytes, HIGH_BIT, H0, H1, H2, H3, H4, H5, R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5)
			end
		end
		if TailLength > 0 then
			local Tail = TAIL
			CopyTail(Tail, AdditionalData, FullBytes, TailLength)
			H0, H1, H2, H3, H4, H5 = AbsorbRegs(Tail, 0, BLOCK_SIZE, HIGH_BIT, H0, H1, H2, H3, H4, H5, R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5)
		end
	end

	local CtLen = buffer.len(Ciphertext)
	if CtLen > 0 then
		local TailLength = CtLen % BLOCK_SIZE
		local FullBytes = CtLen - TailLength
		if FullBytes > 0 then
			local BlockCount = FullBytes // BLOCK_SIZE
			if BlockCount >= 20 then
				if not PowersReady then
					PreparePowers(CONTEXT, R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5)
				end
				local BatchBytes = (BlockCount - BlockCount % 4) * BLOCK_SIZE
				H0, H1, H2, H3, H4, H5 = AbsorbBatch(CONTEXT, Ciphertext, BatchBytes, HIGH_BIT, H0, H1, H2, H3, H4, H5)
				if BatchBytes < FullBytes then
					H0, H1, H2, H3, H4, H5 = AbsorbRegs(Ciphertext, BatchBytes, FullBytes, HIGH_BIT, H0, H1, H2, H3, H4, H5, R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5)
				end
			else
				H0, H1, H2, H3, H4, H5 = AbsorbRegs(Ciphertext, 0, FullBytes, HIGH_BIT, H0, H1, H2, H3, H4, H5, R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5)
			end
		end
		if TailLength > 0 then
			local Tail = TAIL
			CopyTail(Tail, Ciphertext, FullBytes, TailLength)
			H0, H1, H2, H3, H4, H5 = AbsorbRegs(Tail, 0, BLOCK_SIZE, HIGH_BIT, H0, H1, H2, H3, H4, H5, R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5)
		end
	end

	local Lengths = TAIL
	buffer.writeu32(Lengths, 0, AadLen)
	buffer.writeu32(Lengths, 4, 0)
	buffer.writeu32(Lengths, 8, CtLen)
	buffer.writeu32(Lengths, 12, 0)
	H0, H1, H2, H3, H4, H5 = AbsorbRegs(Lengths, 0, BLOCK_SIZE, HIGH_BIT, H0, H1, H2, H3, H4, H5, R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5)

	return FinalizeFromRegs(H0, H1, H2, H3, H4, H5, Key)
end

local Poly1305 = {}

function Poly1305.Tag(Message: buffer, Key: buffer): buffer
	if Message == nil then
		error("Message cannot be nil", 2)
	end
	if typeof(Message) ~= "buffer" then
		error(`Message must be a buffer, got {typeof(Message)}`, 2)
	end
	if Key == nil then
		error("Key cannot be nil", 2)
	end
	if typeof(Key) ~= "buffer" then
		error(`Key must be a buffer, got {typeof(Key)}`, 2)
	end
	local KeyLength = buffer.len(Key)
	if KeyLength ~= POLY1305_KEY_SIZE then
		error(`Key must be exactly {POLY1305_KEY_SIZE} bytes long, got {KeyLength} bytes`, 2)
	end

	local R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5 = DecodeKey(Key)
	local H0, H1, H2, H3, H4, H5 = 0, 0, 0, 0, 0, 0

	local Length = buffer.len(Message)
	local TailLength = Length % BLOCK_SIZE
	local FullBytes = Length - TailLength

	if FullBytes > 0 then
		local BlockCount = FullBytes // BLOCK_SIZE
		if BlockCount >= 20 then
			PreparePowers(CONTEXT, R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5)
			local BatchBytes = (BlockCount - BlockCount % 4) * BLOCK_SIZE
			H0, H1, H2, H3, H4, H5 = AbsorbBatch(CONTEXT, Message, BatchBytes, HIGH_BIT, H0, H1, H2, H3, H4, H5)
			if BatchBytes < FullBytes then
				H0, H1, H2, H3, H4, H5 = AbsorbRegs(Message, BatchBytes, FullBytes, HIGH_BIT, H0, H1, H2, H3, H4, H5, R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5)
			end
		else
			H0, H1, H2, H3, H4, H5 = AbsorbRegs(Message, 0, FullBytes, HIGH_BIT, H0, H1, H2, H3, H4, H5, R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5)
		end
	end

	if TailLength > 0 then
		local Tail = TAIL
		CopyTail(Tail, Message, FullBytes, TailLength)
		buffer.writeu8(Tail, TailLength, 1)
		H0, H1, H2, H3, H4, H5 = AbsorbRegs(Tail, 0, BLOCK_SIZE, 0, H0, H1, H2, H3, H4, H5, R0, R1, R2, R3, R4, R5, S1, S2, S3, S4, S5)
	end

	local W0, W1, W2, W3 = FinalizeFromRegs(H0, H1, H2, H3, H4, H5, Key)
	local Output = buffer.create(TAG_SIZE)
	buffer.writeu32(Output, 0, W0)
	buffer.writeu32(Output, 4, W1)
	buffer.writeu32(Output, 8, W2)
	buffer.writeu32(Output, 12, W3)
	return Output
end

function Poly1305.AeadTag(Key: buffer, AdditionalData: buffer, Ciphertext: buffer): buffer
	local W0, W1, W2, W3 = AeadHash(Key, AdditionalData, Ciphertext)
	local Output = buffer.create(TAG_SIZE)
	buffer.writeu32(Output, 0, W0)
	buffer.writeu32(Output, 4, W1)
	buffer.writeu32(Output, 8, W2)
	buffer.writeu32(Output, 12, W3)
	return Output
end

function Poly1305.AeadVerify(Key: buffer, AdditionalData: buffer, Ciphertext: buffer, Tag: buffer): boolean
	local W0, W1, W2, W3 = AeadHash(Key, AdditionalData, Ciphertext)
	local Diff = bit32.bor(
		bit32.bxor(W0, buffer.readu32(Tag, 0)),
		bit32.bxor(W1, buffer.readu32(Tag, 4)),
		bit32.bxor(W2, buffer.readu32(Tag, 8)),
		bit32.bxor(W3, buffer.readu32(Tag, 12))
	)
	return Diff == 0
end

return Poly1305
