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

local CONTEXT = buffer.create(232)
local TAIL = buffer.create(BLOCK_SIZE)

local function Setup(Key: buffer, Context: buffer)
	local W0 = bit32.band(buffer.readu32(Key, 0), 0x0fffffff)
	local W1 = bit32.band(buffer.readu32(Key, 4), 0x0ffffffc)
	local W2 = bit32.band(buffer.readu32(Key, 8), 0x0ffffffc)
	local W3 = bit32.band(buffer.readu32(Key, 12), 0x0ffffffc)

	local R1 = bit32.bor(bit32.rshift(W0, 22), bit32.lshift(bit32.band(W1, 0xfff), 10)) * 2 ^ 22
	local R2 = bit32.bor(bit32.rshift(W1, 12), bit32.lshift(bit32.band(W2, 3), 20)) * 2 ^ 44
	local R3 = bit32.band(bit32.rshift(W2, 2), 0x3fffff) * 2 ^ 66
	local R4 = bit32.bor(bit32.rshift(W2, 24), bit32.lshift(bit32.band(W3, 0x3fff), 8)) * 2 ^ 88
	local R5 = bit32.rshift(W3, 14) * 2 ^ 110

	buffer.fill(Context, 0, 0, 48)
	buffer.writef64(Context, 48, bit32.band(W0, 0x3fffff))
	buffer.writef64(Context, 56, R1)
	buffer.writef64(Context, 64, R2)
	buffer.writef64(Context, 72, R3)
	buffer.writef64(Context, 80, R4)
	buffer.writef64(Context, 88, R5)
	buffer.writef64(Context, 96, R1 * (5 * 2 ^ -130))
	buffer.writef64(Context, 104, R2 * (5 * 2 ^ -130))
	buffer.writef64(Context, 112, R3 * (5 * 2 ^ -130))
	buffer.writef64(Context, 120, R4 * (5 * 2 ^ -130))
	buffer.writef64(Context, 128, R5 * (5 * 2 ^ -130))
	buffer.writef64(Context, 224, 0)
end

local function Absorb(Context: buffer, Data: buffer, Offset: number, Length: number, HighBit: number)
	local H0 = buffer.readf64(Context, 0)
	local H1 = buffer.readf64(Context, 8)
	local H2 = buffer.readf64(Context, 16)
	local H3 = buffer.readf64(Context, 24)
	local H4 = buffer.readf64(Context, 32)
	local H5 = buffer.readf64(Context, 40)
	local R0 = buffer.readf64(Context, 48)
	local R1 = buffer.readf64(Context, 56)
	local R2 = buffer.readf64(Context, 64)
	local R3 = buffer.readf64(Context, 72)
	local R4 = buffer.readf64(Context, 80)
	local R5 = buffer.readf64(Context, 88)
	local S1 = buffer.readf64(Context, 96)
	local S2 = buffer.readf64(Context, 104)
	local S3 = buffer.readf64(Context, 112)
	local S4 = buffer.readf64(Context, 120)
	local S5 = buffer.readf64(Context, 128)

	local BlockCount = Length // BLOCK_SIZE
	if BlockCount >= 16 then
		if buffer.readf64(Context, 224) == 0 then
			local X0, X1, X2, X3, X4, X5 = R0, R1, R2, R3, R4, R5
			local Q0, Q1, Q2, Q3, Q4, Q5
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
			local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
			local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
			Q0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
			Q1 = (B1 - D1) + D0
			Q2 = (B2 - D2) + D1
			Q3 = (B3 - D3) + D2
			Q4 = (B4 - D4) + D3
			Q5 = (B5 - D5) + D4
			buffer.writef64(Context, 136, Q0)
			buffer.writef64(Context, 144, Q1)
			buffer.writef64(Context, 152, Q2)
			buffer.writef64(Context, 160, Q3)
			buffer.writef64(Context, 168, Q4)
			buffer.writef64(Context, 176, Q5)
			buffer.writef64(Context, 184, Q1 * (5 * 2 ^ -130))
			buffer.writef64(Context, 192, Q2 * (5 * 2 ^ -130))
			buffer.writef64(Context, 200, Q3 * (5 * 2 ^ -130))
			buffer.writef64(Context, 208, Q4 * (5 * 2 ^ -130))
			buffer.writef64(Context, 216, Q5 * (5 * 2 ^ -130))
			buffer.writef64(Context, 224, 1)
		end
		local Q0 = buffer.readf64(Context, 136)
		local Q1 = buffer.readf64(Context, 144)
		local Q2 = buffer.readf64(Context, 152)
		local Q3 = buffer.readf64(Context, 160)
		local Q4 = buffer.readf64(Context, 168)
		local Q5 = buffer.readf64(Context, 176)
		local T1 = buffer.readf64(Context, 184)
		local T2 = buffer.readf64(Context, 192)
		local T3 = buffer.readf64(Context, 200)
		local T4 = buffer.readf64(Context, 208)
		local T5 = buffer.readf64(Context, 216)
		local G0, G1, G2, G3, G4, G5 = 0, 0, 0, 0, 0, 0
		local PairBytes = (BlockCount - BlockCount % 2) * BLOCK_SIZE
		local LastPair = Offset + PairBytes - 32
		local Groups = (PairBytes // 32 - 1) // 4
		local GroupEnd = Offset + Groups * 128
		for Position = Offset, GroupEnd - 128, 128 do
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
				local A0 = ((X0 * Q0 + X1 * T5) + (X2 * T4 + X3 * T3)) + (X4 * T2 + X5 * T1)
				local A1 = ((X0 * Q1 + X1 * Q0) + (X2 * T5 + X3 * T4)) + (X4 * T3 + X5 * T2)
				local A2 = ((X0 * Q2 + X1 * Q1) + (X2 * Q0 + X3 * T5)) + (X4 * T4 + X5 * T3)
				local A3 = ((X0 * Q3 + X1 * Q2) + (X2 * Q1 + X3 * Q0)) + (X4 * T5 + X5 * T4)
				local A4 = ((X0 * Q4 + X1 * Q3) + (X2 * Q2 + X3 * Q1)) + (X4 * Q0 + X5 * T5)
				local A5 = ((X0 * Q5 + X1 * Q4) + (X2 * Q3 + X3 * Q2)) + (X4 * Q1 + X5 * Q0)
				local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
				local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
				local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
				local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
				local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				H0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				H1 = (B1 - D1) + D0
				H2 = (B2 - D2) + D1
				H3 = (B3 - D3) + D2
				H4 = (B4 - D4) + D3
				H5 = (B5 - D5) + D4
			end
			do
				local M0 = buffer.readu32(Data, Position + 16)
				local M1 = buffer.readu32(Data, Position + 16 + 4)
				local M2 = buffer.readu32(Data, Position + 16 + 8)
				local M3 = buffer.readu32(Data, Position + 16 + 12)
				local X0 = G0 + bit32.band(M0, 0x3fffff)
				local X1 = G1 + bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
				local X2 = G2 + bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
				local X3 = G3 + bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
				local X4 = G4 + bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
				local X5 = G5 + (bit32.rshift(M3, 14) * 2 ^ 110 + HighBit)
				local A0 = ((X0 * Q0 + X1 * T5) + (X2 * T4 + X3 * T3)) + (X4 * T2 + X5 * T1)
				local A1 = ((X0 * Q1 + X1 * Q0) + (X2 * T5 + X3 * T4)) + (X4 * T3 + X5 * T2)
				local A2 = ((X0 * Q2 + X1 * Q1) + (X2 * Q0 + X3 * T5)) + (X4 * T4 + X5 * T3)
				local A3 = ((X0 * Q3 + X1 * Q2) + (X2 * Q1 + X3 * Q0)) + (X4 * T5 + X5 * T4)
				local A4 = ((X0 * Q4 + X1 * Q3) + (X2 * Q2 + X3 * Q1)) + (X4 * Q0 + X5 * T5)
				local A5 = ((X0 * Q5 + X1 * Q4) + (X2 * Q3 + X3 * Q2)) + (X4 * Q1 + X5 * Q0)
				local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
				local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
				local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
				local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
				local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				G0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				G1 = (B1 - D1) + D0
				G2 = (B2 - D2) + D1
				G3 = (B3 - D3) + D2
				G4 = (B4 - D4) + D3
				G5 = (B5 - D5) + D4
			end
			do
				local M0 = buffer.readu32(Data, Position + 32)
				local M1 = buffer.readu32(Data, Position + 32 + 4)
				local M2 = buffer.readu32(Data, Position + 32 + 8)
				local M3 = buffer.readu32(Data, Position + 32 + 12)
				local X0 = H0 + bit32.band(M0, 0x3fffff)
				local X1 = H1 + bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
				local X2 = H2 + bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
				local X3 = H3 + bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
				local X4 = H4 + bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
				local X5 = H5 + (bit32.rshift(M3, 14) * 2 ^ 110 + HighBit)
				local A0 = ((X0 * Q0 + X1 * T5) + (X2 * T4 + X3 * T3)) + (X4 * T2 + X5 * T1)
				local A1 = ((X0 * Q1 + X1 * Q0) + (X2 * T5 + X3 * T4)) + (X4 * T3 + X5 * T2)
				local A2 = ((X0 * Q2 + X1 * Q1) + (X2 * Q0 + X3 * T5)) + (X4 * T4 + X5 * T3)
				local A3 = ((X0 * Q3 + X1 * Q2) + (X2 * Q1 + X3 * Q0)) + (X4 * T5 + X5 * T4)
				local A4 = ((X0 * Q4 + X1 * Q3) + (X2 * Q2 + X3 * Q1)) + (X4 * Q0 + X5 * T5)
				local A5 = ((X0 * Q5 + X1 * Q4) + (X2 * Q3 + X3 * Q2)) + (X4 * Q1 + X5 * Q0)
				local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
				local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
				local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
				local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
				local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				H0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				H1 = (B1 - D1) + D0
				H2 = (B2 - D2) + D1
				H3 = (B3 - D3) + D2
				H4 = (B4 - D4) + D3
				H5 = (B5 - D5) + D4
			end
			do
				local M0 = buffer.readu32(Data, Position + 32 + 16)
				local M1 = buffer.readu32(Data, Position + 32 + 16 + 4)
				local M2 = buffer.readu32(Data, Position + 32 + 16 + 8)
				local M3 = buffer.readu32(Data, Position + 32 + 16 + 12)
				local X0 = G0 + bit32.band(M0, 0x3fffff)
				local X1 = G1 + bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
				local X2 = G2 + bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
				local X3 = G3 + bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
				local X4 = G4 + bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
				local X5 = G5 + (bit32.rshift(M3, 14) * 2 ^ 110 + HighBit)
				local A0 = ((X0 * Q0 + X1 * T5) + (X2 * T4 + X3 * T3)) + (X4 * T2 + X5 * T1)
				local A1 = ((X0 * Q1 + X1 * Q0) + (X2 * T5 + X3 * T4)) + (X4 * T3 + X5 * T2)
				local A2 = ((X0 * Q2 + X1 * Q1) + (X2 * Q0 + X3 * T5)) + (X4 * T4 + X5 * T3)
				local A3 = ((X0 * Q3 + X1 * Q2) + (X2 * Q1 + X3 * Q0)) + (X4 * T5 + X5 * T4)
				local A4 = ((X0 * Q4 + X1 * Q3) + (X2 * Q2 + X3 * Q1)) + (X4 * Q0 + X5 * T5)
				local A5 = ((X0 * Q5 + X1 * Q4) + (X2 * Q3 + X3 * Q2)) + (X4 * Q1 + X5 * Q0)
				local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
				local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
				local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
				local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
				local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				G0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				G1 = (B1 - D1) + D0
				G2 = (B2 - D2) + D1
				G3 = (B3 - D3) + D2
				G4 = (B4 - D4) + D3
				G5 = (B5 - D5) + D4
			end
			do
				local M0 = buffer.readu32(Data, Position + 64)
				local M1 = buffer.readu32(Data, Position + 64 + 4)
				local M2 = buffer.readu32(Data, Position + 64 + 8)
				local M3 = buffer.readu32(Data, Position + 64 + 12)
				local X0 = H0 + bit32.band(M0, 0x3fffff)
				local X1 = H1 + bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
				local X2 = H2 + bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
				local X3 = H3 + bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
				local X4 = H4 + bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
				local X5 = H5 + (bit32.rshift(M3, 14) * 2 ^ 110 + HighBit)
				local A0 = ((X0 * Q0 + X1 * T5) + (X2 * T4 + X3 * T3)) + (X4 * T2 + X5 * T1)
				local A1 = ((X0 * Q1 + X1 * Q0) + (X2 * T5 + X3 * T4)) + (X4 * T3 + X5 * T2)
				local A2 = ((X0 * Q2 + X1 * Q1) + (X2 * Q0 + X3 * T5)) + (X4 * T4 + X5 * T3)
				local A3 = ((X0 * Q3 + X1 * Q2) + (X2 * Q1 + X3 * Q0)) + (X4 * T5 + X5 * T4)
				local A4 = ((X0 * Q4 + X1 * Q3) + (X2 * Q2 + X3 * Q1)) + (X4 * Q0 + X5 * T5)
				local A5 = ((X0 * Q5 + X1 * Q4) + (X2 * Q3 + X3 * Q2)) + (X4 * Q1 + X5 * Q0)
				local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
				local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
				local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
				local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
				local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				H0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				H1 = (B1 - D1) + D0
				H2 = (B2 - D2) + D1
				H3 = (B3 - D3) + D2
				H4 = (B4 - D4) + D3
				H5 = (B5 - D5) + D4
			end
			do
				local M0 = buffer.readu32(Data, Position + 64 + 16)
				local M1 = buffer.readu32(Data, Position + 64 + 16 + 4)
				local M2 = buffer.readu32(Data, Position + 64 + 16 + 8)
				local M3 = buffer.readu32(Data, Position + 64 + 16 + 12)
				local X0 = G0 + bit32.band(M0, 0x3fffff)
				local X1 = G1 + bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
				local X2 = G2 + bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
				local X3 = G3 + bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
				local X4 = G4 + bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
				local X5 = G5 + (bit32.rshift(M3, 14) * 2 ^ 110 + HighBit)
				local A0 = ((X0 * Q0 + X1 * T5) + (X2 * T4 + X3 * T3)) + (X4 * T2 + X5 * T1)
				local A1 = ((X0 * Q1 + X1 * Q0) + (X2 * T5 + X3 * T4)) + (X4 * T3 + X5 * T2)
				local A2 = ((X0 * Q2 + X1 * Q1) + (X2 * Q0 + X3 * T5)) + (X4 * T4 + X5 * T3)
				local A3 = ((X0 * Q3 + X1 * Q2) + (X2 * Q1 + X3 * Q0)) + (X4 * T5 + X5 * T4)
				local A4 = ((X0 * Q4 + X1 * Q3) + (X2 * Q2 + X3 * Q1)) + (X4 * Q0 + X5 * T5)
				local A5 = ((X0 * Q5 + X1 * Q4) + (X2 * Q3 + X3 * Q2)) + (X4 * Q1 + X5 * Q0)
				local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
				local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
				local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
				local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
				local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				G0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				G1 = (B1 - D1) + D0
				G2 = (B2 - D2) + D1
				G3 = (B3 - D3) + D2
				G4 = (B4 - D4) + D3
				G5 = (B5 - D5) + D4
			end
			do
				local M0 = buffer.readu32(Data, Position + 96)
				local M1 = buffer.readu32(Data, Position + 96 + 4)
				local M2 = buffer.readu32(Data, Position + 96 + 8)
				local M3 = buffer.readu32(Data, Position + 96 + 12)
				local X0 = H0 + bit32.band(M0, 0x3fffff)
				local X1 = H1 + bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
				local X2 = H2 + bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
				local X3 = H3 + bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
				local X4 = H4 + bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
				local X5 = H5 + (bit32.rshift(M3, 14) * 2 ^ 110 + HighBit)
				local A0 = ((X0 * Q0 + X1 * T5) + (X2 * T4 + X3 * T3)) + (X4 * T2 + X5 * T1)
				local A1 = ((X0 * Q1 + X1 * Q0) + (X2 * T5 + X3 * T4)) + (X4 * T3 + X5 * T2)
				local A2 = ((X0 * Q2 + X1 * Q1) + (X2 * Q0 + X3 * T5)) + (X4 * T4 + X5 * T3)
				local A3 = ((X0 * Q3 + X1 * Q2) + (X2 * Q1 + X3 * Q0)) + (X4 * T5 + X5 * T4)
				local A4 = ((X0 * Q4 + X1 * Q3) + (X2 * Q2 + X3 * Q1)) + (X4 * Q0 + X5 * T5)
				local A5 = ((X0 * Q5 + X1 * Q4) + (X2 * Q3 + X3 * Q2)) + (X4 * Q1 + X5 * Q0)
				local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
				local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
				local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
				local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
				local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				H0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				H1 = (B1 - D1) + D0
				H2 = (B2 - D2) + D1
				H3 = (B3 - D3) + D2
				H4 = (B4 - D4) + D3
				H5 = (B5 - D5) + D4
			end
			do
				local M0 = buffer.readu32(Data, Position + 96 + 16)
				local M1 = buffer.readu32(Data, Position + 96 + 16 + 4)
				local M2 = buffer.readu32(Data, Position + 96 + 16 + 8)
				local M3 = buffer.readu32(Data, Position + 96 + 16 + 12)
				local X0 = G0 + bit32.band(M0, 0x3fffff)
				local X1 = G1 + bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
				local X2 = G2 + bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
				local X3 = G3 + bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
				local X4 = G4 + bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
				local X5 = G5 + (bit32.rshift(M3, 14) * 2 ^ 110 + HighBit)
				local A0 = ((X0 * Q0 + X1 * T5) + (X2 * T4 + X3 * T3)) + (X4 * T2 + X5 * T1)
				local A1 = ((X0 * Q1 + X1 * Q0) + (X2 * T5 + X3 * T4)) + (X4 * T3 + X5 * T2)
				local A2 = ((X0 * Q2 + X1 * Q1) + (X2 * Q0 + X3 * T5)) + (X4 * T4 + X5 * T3)
				local A3 = ((X0 * Q3 + X1 * Q2) + (X2 * Q1 + X3 * Q0)) + (X4 * T5 + X5 * T4)
				local A4 = ((X0 * Q4 + X1 * Q3) + (X2 * Q2 + X3 * Q1)) + (X4 * Q0 + X5 * T5)
				local A5 = ((X0 * Q5 + X1 * Q4) + (X2 * Q3 + X3 * Q2)) + (X4 * Q1 + X5 * Q0)
				local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
				local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
				local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
				local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
				local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				G0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				G1 = (B1 - D1) + D0
				G2 = (B2 - D2) + D1
				G3 = (B3 - D3) + D2
				G4 = (B4 - D4) + D3
				G5 = (B5 - D5) + D4
			end
		end
		for Position = GroupEnd, LastPair - 32, 32 do
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
				local A0 = ((X0 * Q0 + X1 * T5) + (X2 * T4 + X3 * T3)) + (X4 * T2 + X5 * T1)
				local A1 = ((X0 * Q1 + X1 * Q0) + (X2 * T5 + X3 * T4)) + (X4 * T3 + X5 * T2)
				local A2 = ((X0 * Q2 + X1 * Q1) + (X2 * Q0 + X3 * T5)) + (X4 * T4 + X5 * T3)
				local A3 = ((X0 * Q3 + X1 * Q2) + (X2 * Q1 + X3 * Q0)) + (X4 * T5 + X5 * T4)
				local A4 = ((X0 * Q4 + X1 * Q3) + (X2 * Q2 + X3 * Q1)) + (X4 * Q0 + X5 * T5)
				local A5 = ((X0 * Q5 + X1 * Q4) + (X2 * Q3 + X3 * Q2)) + (X4 * Q1 + X5 * Q0)
				local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
				local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
				local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
				local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
				local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				H0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				H1 = (B1 - D1) + D0
				H2 = (B2 - D2) + D1
				H3 = (B3 - D3) + D2
				H4 = (B4 - D4) + D3
				H5 = (B5 - D5) + D4
			end
			do
				local M0 = buffer.readu32(Data, Position + 16)
				local M1 = buffer.readu32(Data, Position + 16 + 4)
				local M2 = buffer.readu32(Data, Position + 16 + 8)
				local M3 = buffer.readu32(Data, Position + 16 + 12)
				local X0 = G0 + bit32.band(M0, 0x3fffff)
				local X1 = G1 + bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
				local X2 = G2 + bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
				local X3 = G3 + bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
				local X4 = G4 + bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
				local X5 = G5 + (bit32.rshift(M3, 14) * 2 ^ 110 + HighBit)
				local A0 = ((X0 * Q0 + X1 * T5) + (X2 * T4 + X3 * T3)) + (X4 * T2 + X5 * T1)
				local A1 = ((X0 * Q1 + X1 * Q0) + (X2 * T5 + X3 * T4)) + (X4 * T3 + X5 * T2)
				local A2 = ((X0 * Q2 + X1 * Q1) + (X2 * Q0 + X3 * T5)) + (X4 * T4 + X5 * T3)
				local A3 = ((X0 * Q3 + X1 * Q2) + (X2 * Q1 + X3 * Q0)) + (X4 * T5 + X5 * T4)
				local A4 = ((X0 * Q4 + X1 * Q3) + (X2 * Q2 + X3 * Q1)) + (X4 * Q0 + X5 * T5)
				local A5 = ((X0 * Q5 + X1 * Q4) + (X2 * Q3 + X3 * Q2)) + (X4 * Q1 + X5 * Q0)
				local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
				local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
				local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
				local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
				local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				G0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				G1 = (B1 - D1) + D0
				G2 = (B2 - D2) + D1
				G3 = (B3 - D3) + D2
				G4 = (B4 - D4) + D3
				G5 = (B5 - D5) + D4
			end
		end
		do
			local M0 = buffer.readu32(Data, LastPair)
			local M1 = buffer.readu32(Data, LastPair + 4)
			local M2 = buffer.readu32(Data, LastPair + 8)
			local M3 = buffer.readu32(Data, LastPair + 12)
			local X0 = H0 + bit32.band(M0, 0x3fffff)
			local X1 = H1 + bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
			local X2 = H2 + bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
			local X3 = H3 + bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
			local X4 = H4 + bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
			local X5 = H5 + (bit32.rshift(M3, 14) * 2 ^ 110 + HighBit)
			local A0 = ((X0 * Q0 + X1 * T5) + (X2 * T4 + X3 * T3)) + (X4 * T2 + X5 * T1)
			local A1 = ((X0 * Q1 + X1 * Q0) + (X2 * T5 + X3 * T4)) + (X4 * T3 + X5 * T2)
			local A2 = ((X0 * Q2 + X1 * Q1) + (X2 * Q0 + X3 * T5)) + (X4 * T4 + X5 * T3)
			local A3 = ((X0 * Q3 + X1 * Q2) + (X2 * Q1 + X3 * Q0)) + (X4 * T5 + X5 * T4)
			local A4 = ((X0 * Q4 + X1 * Q3) + (X2 * Q2 + X3 * Q1)) + (X4 * Q0 + X5 * T5)
			local A5 = ((X0 * Q5 + X1 * Q4) + (X2 * Q3 + X3 * Q2)) + (X4 * Q1 + X5 * Q0)
			local C0 = A0 + 3 * 2 ^ 73 - 3 * 2 ^ 73
			local C1 = A1 + 3 * 2 ^ 95 - 3 * 2 ^ 95
			local C2 = A2 + 3 * 2 ^ 117 - 3 * 2 ^ 117
			local C3 = A3 + 3 * 2 ^ 139 - 3 * 2 ^ 139
			local C4 = A4 + 3 * 2 ^ 161 - 3 * 2 ^ 161
			local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
			local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
			H0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
			H1 = (B1 - D1) + D0
			H2 = (B2 - D2) + D1
			H3 = (B3 - D3) + D2
			H4 = (B4 - D4) + D3
			H5 = (B5 - D5) + D4
		end
		do
			local M0 = buffer.readu32(Data, LastPair + 16)
			local M1 = buffer.readu32(Data, LastPair + 16 + 4)
			local M2 = buffer.readu32(Data, LastPair + 16 + 8)
			local M3 = buffer.readu32(Data, LastPair + 16 + 12)
			local X0 = G0 + bit32.band(M0, 0x3fffff)
			local X1 = G1 + bit32.bor(bit32.rshift(M0, 22), bit32.lshift(bit32.band(M1, 0xfff), 10)) * 2 ^ 22
			local X2 = G2 + bit32.bor(bit32.rshift(M1, 12), bit32.lshift(bit32.band(M2, 3), 20)) * 2 ^ 44
			local X3 = G3 + bit32.band(bit32.rshift(M2, 2), 0x3fffff) * 2 ^ 66
			local X4 = G4 + bit32.bor(bit32.rshift(M2, 24), bit32.lshift(bit32.band(M3, 0x3fff), 8)) * 2 ^ 88
			local X5 = G5 + (bit32.rshift(M3, 14) * 2 ^ 110 + HighBit)
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
			local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
			local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
			G0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
			G1 = (B1 - D1) + D0
			G2 = (B2 - D2) + D1
			G3 = (B3 - D3) + D2
			G4 = (B4 - D4) + D3
			G5 = (B5 - D5) + D4
		end
		H0 += G0
		H1 += G1
		H2 += G2
		H3 += G3
		H4 += G4
		H5 += G5
		if BlockCount % 2 == 1 then
			do
				local M0 = buffer.readu32(Data, Offset + PairBytes)
				local M1 = buffer.readu32(Data, Offset + PairBytes + 4)
				local M2 = buffer.readu32(Data, Offset + PairBytes + 8)
				local M3 = buffer.readu32(Data, Offset + PairBytes + 12)
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
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				H0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				H1 = (B1 - D1) + D0
				H2 = (B2 - D2) + D1
				H3 = (B3 - D3) + D2
				H4 = (B4 - D4) + D3
				H5 = (B5 - D5) + D4
			end
		end
	else
		local GroupEnd = Offset + (BlockCount - BlockCount % 4) * BLOCK_SIZE
		for Position = Offset, GroupEnd - 64, 64 do
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
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				H0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				H1 = (B1 - D1) + D0
				H2 = (B2 - D2) + D1
				H3 = (B3 - D3) + D2
				H4 = (B4 - D4) + D3
				H5 = (B5 - D5) + D4
			end
			do
				local M0 = buffer.readu32(Data, Position + 16)
				local M1 = buffer.readu32(Data, Position + 16 + 4)
				local M2 = buffer.readu32(Data, Position + 16 + 8)
				local M3 = buffer.readu32(Data, Position + 16 + 12)
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
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				H0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				H1 = (B1 - D1) + D0
				H2 = (B2 - D2) + D1
				H3 = (B3 - D3) + D2
				H4 = (B4 - D4) + D3
				H5 = (B5 - D5) + D4
			end
			do
				local M0 = buffer.readu32(Data, Position + 32)
				local M1 = buffer.readu32(Data, Position + 32 + 4)
				local M2 = buffer.readu32(Data, Position + 32 + 8)
				local M3 = buffer.readu32(Data, Position + 32 + 12)
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
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				H0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				H1 = (B1 - D1) + D0
				H2 = (B2 - D2) + D1
				H3 = (B3 - D3) + D2
				H4 = (B4 - D4) + D3
				H5 = (B5 - D5) + D4
			end
			do
				local M0 = buffer.readu32(Data, Position + 48)
				local M1 = buffer.readu32(Data, Position + 48 + 4)
				local M2 = buffer.readu32(Data, Position + 48 + 8)
				local M3 = buffer.readu32(Data, Position + 48 + 12)
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
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				H0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				H1 = (B1 - D1) + D0
				H2 = (B2 - D2) + D1
				H3 = (B3 - D3) + D2
				H4 = (B4 - D4) + D3
				H5 = (B5 - D5) + D4
			end
		end
		for Position = GroupEnd, Offset + Length - BLOCK_SIZE, BLOCK_SIZE do
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
				local C5 = A5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
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
				local D5 = B5 + 3 * 2 ^ 183 - 3 * 2 ^ 183
				H0 = (B0 - D0) + D5 * (5 * 2 ^ -130)
				H1 = (B1 - D1) + D0
				H2 = (B2 - D2) + D1
				H3 = (B3 - D3) + D2
				H4 = (B4 - D4) + D3
				H5 = (B5 - D5) + D4
			end
		end
	end

	buffer.writef64(Context, 0, H0)
	buffer.writef64(Context, 8, H1)
	buffer.writef64(Context, 16, H2)
	buffer.writef64(Context, 24, H3)
	buffer.writef64(Context, 32, H4)
	buffer.writef64(Context, 40, H5)
end

local function AbsorbPadded(Context: buffer, Data: buffer)
	local Length = buffer.len(Data)
	local TailLength = Length % BLOCK_SIZE
	local FullBytes = Length - TailLength

	if FullBytes > 0 then
		Absorb(Context, Data, 0, FullBytes, HIGH_BIT)
	end

	if TailLength > 0 then
		local Tail = TAIL
		buffer.fill(Tail, 0, 0, BLOCK_SIZE)
		buffer.copy(Tail, 0, Data, FullBytes, TailLength)
		Absorb(Context, Tail, 0, BLOCK_SIZE, HIGH_BIT)
	end
end

local function Finalize(Context: buffer, Key: buffer): buffer
	local H0 = buffer.readf64(Context, 0)
	local H1 = buffer.readf64(Context, 8)
	local H2 = buffer.readf64(Context, 16)
	local H3 = buffer.readf64(Context, 24)
	local H4 = buffer.readf64(Context, 32)
	local H5 = buffer.readf64(Context, 40)

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

	local Output = buffer.create(TAG_SIZE)
	local Carry = Word0 + buffer.readu32(Key, 16)
	buffer.writeu32(Output, 0, Carry)
	Carry = Word1 + buffer.readu32(Key, 20) + (if Carry >= 2 ^ 32 then 1 else 0)
	buffer.writeu32(Output, 4, Carry)
	Carry = Word2 + buffer.readu32(Key, 24) + (if Carry >= 2 ^ 32 then 1 else 0)
	buffer.writeu32(Output, 8, Carry)
	Carry = Word3 + buffer.readu32(Key, 28) + (if Carry >= 2 ^ 32 then 1 else 0)
	buffer.writeu32(Output, 12, Carry)

	return Output
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

	local Context = CONTEXT
	Setup(Key, Context)

	local Length = buffer.len(Message)
	local TailLength = Length % BLOCK_SIZE
	local FullBytes = Length - TailLength

	if FullBytes > 0 then
		Absorb(Context, Message, 0, FullBytes, HIGH_BIT)
	end

	if TailLength > 0 then
		local Tail = TAIL
		buffer.fill(Tail, 0, 0, BLOCK_SIZE)
		buffer.copy(Tail, 0, Message, FullBytes, TailLength)
		buffer.writeu8(Tail, TailLength, 1)
		Absorb(Context, Tail, 0, BLOCK_SIZE, 0)
	end

	return Finalize(Context, Key)
end

function Poly1305.AeadTag(Key: buffer, AdditionalData: buffer, Ciphertext: buffer): buffer
	local Context = CONTEXT
	Setup(Key, Context)

	AbsorbPadded(Context, AdditionalData)
	AbsorbPadded(Context, Ciphertext)

	local Lengths = TAIL
	buffer.writeu32(Lengths, 0, buffer.len(AdditionalData))
	buffer.writeu32(Lengths, 4, 0)
	buffer.writeu32(Lengths, 8, buffer.len(Ciphertext))
	buffer.writeu32(Lengths, 12, 0)
	Absorb(Context, Lengths, 0, BLOCK_SIZE, HIGH_BIT)

	return Finalize(Context, Key)
end

return Poly1305

