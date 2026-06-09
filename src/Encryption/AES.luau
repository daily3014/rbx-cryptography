--[=[
	Cryptography library: AES
	
	Sizes:
		Init Vector: any non-zero length (12 bytes recommended)
		Key Size: 16 / 24 / 32 bytes
		Tag: 16 bytes
	
	Return type: Encrypt (buffer, buffer), Decrypt buffer?
	Decrypt returns nil when authentication fails, including tags
	that are not 16 bytes long.

	Example usage:
	local Key = CSPRNG.RandomBytes(32)
	local IV = CSPRNG.RandomBytes(12)

	local Message = "This is a secret message"
	local Plaintext = buffer.fromstring(Message)

	local AAD = buffer.fromstring("user:john,timestamp:456745683")
	local Ciphertext, Tag = AES.Encrypt(Plaintext, Key, IV, AAD)
	local Decrypted = AES.Decrypt(Ciphertext, Key, IV, Tag, AAD)
--]=]

--!strict
--!optimize 2
--!native

type Processor = (PlaintextBlock: buffer, PlaintextOffset: number, OutputBuffer: buffer, OutputOffset: number) -> ()

local AES = {}

local ALL_TABLES = buffer.create(32 * 16 * 16)
local DOUBLES = buffer.create(128 * 16)

local KEY_CONFIGS = {
	[16] = {ExpandedLength = 176, MaterialLength = 128},
	[24] = {ExpandedLength = 208, MaterialLength = 160},
	[32] = {ExpandedLength = 240, MaterialLength = 192}
}

local SUBSTITUTION_BOX = buffer.create(256)
local TTABLE0 = buffer.create(1024)
local TTABLE1 = buffer.create(1024)
local TTABLE2 = buffer.create(1024)
local TTABLE3 = buffer.create(1024)

do
	local function GaloisFieldMultiply(FirstValue: number, SecondValue: number): number
		local Product = 0
		for _ = 0, 7 do
			if SecondValue % 2 == 1 then
				Product = bit32.bxor(Product, FirstValue)
			end
			FirstValue = FirstValue >= 128 and bit32.bxor(FirstValue * 2 % 256, 27) or FirstValue * 2 % 256
			SecondValue = math.floor(SecondValue / 2)
		end
		return Product
	end

	local PolynomialP = 1
	local PolynomialQ = 1
	buffer.writeu8(SUBSTITUTION_BOX, 0, 99)
	for _ = 1, 255 do
		PolynomialP = bit32.bxor(PolynomialP, PolynomialP * 2, PolynomialP < 128 and 0 or 27) % 256
		PolynomialQ = bit32.bxor(PolynomialQ, PolynomialQ * 2)
		PolynomialQ = bit32.bxor(PolynomialQ, PolynomialQ * 4)
		PolynomialQ = bit32.bxor(PolynomialQ, PolynomialQ * 16) % 256
		if PolynomialQ >= 128 then
			PolynomialQ = bit32.bxor(PolynomialQ, 9)
		end
		local TempValue = bit32.bxor(
			PolynomialQ,
			PolynomialQ % 128 * 2 + PolynomialQ / 128,
			PolynomialQ % 64 * 4 + PolynomialQ / 64,
			PolynomialQ % 32 * 8 + PolynomialQ / 32,
			PolynomialQ % 16 * 16 + PolynomialQ / 16,
			99
		)
		buffer.writeu8(SUBSTITUTION_BOX, PolynomialP, TempValue)
	end

	for B = 0, 255 do
		local S = buffer.readu8(SUBSTITUTION_BOX, B)
		local S2 = GaloisFieldMultiply(2, S)
		local S3 = bit32.bxor(S2, S)
		buffer.writeu32(TTABLE0, B * 4, bit32.bor(S2, bit32.lshift(S, 8), bit32.lshift(S, 16), bit32.lshift(S3, 24)))
		buffer.writeu32(TTABLE1, B * 4, bit32.bor(S3, bit32.lshift(S2, 8), bit32.lshift(S, 16), bit32.lshift(S, 24)))
		buffer.writeu32(TTABLE2, B * 4, bit32.bor(S, bit32.lshift(S3, 8), bit32.lshift(S2, 16), bit32.lshift(S, 24)))
		buffer.writeu32(TTABLE3, B * 4, bit32.bor(S, bit32.lshift(S, 8), bit32.lshift(S3, 16), bit32.lshift(S2, 24)))
	end
end

local function SubWord(W: number): number
	return bit32.bor(
		buffer.readu8(SUBSTITUTION_BOX, bit32.band(W, 0xFF)),
		bit32.lshift(buffer.readu8(SUBSTITUTION_BOX, bit32.band(bit32.rshift(W, 8), 0xFF)), 8),
		bit32.lshift(buffer.readu8(SUBSTITUTION_BOX, bit32.band(bit32.rshift(W, 16), 0xFF)), 16),
		bit32.lshift(buffer.readu8(SUBSTITUTION_BOX, bit32.rshift(W, 24)), 24))
end

local function ExpandKeySchedule(Key: buffer, KeyLength: number, OutputBuffer: buffer): buffer
	buffer.copy(OutputBuffer, 0, Key, 0, KeyLength)

	local Word = bit32.rrotate(buffer.readu32(OutputBuffer, KeyLength - 4), 8)
	local RoundConstant = 0.5

	if KeyLength == 32 then
		for KeyOffset = 32, 192, 32 do
			RoundConstant = RoundConstant * 2 % 229
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 32), SubWord(Word), RoundConstant)
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			local W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 28), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, W1)
			local W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 24), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, W2)
			local W3 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 20), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, W3)

			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 16), SubWord(W3))
			buffer.writeu32(OutputBuffer, KeyOffset + 16, Word)

			W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 20, W1)
			W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 24, W2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 28, Word)
			Word = bit32.rrotate(Word, 8)
		end

		Word = bit32.bxor(buffer.readu32(OutputBuffer, 192), SubWord(Word), 64)
		buffer.writeu32(OutputBuffer, 224, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 196), Word)
		buffer.writeu32(OutputBuffer, 228, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 200), W1)
		buffer.writeu32(OutputBuffer, 232, W2)
		buffer.writeu32(OutputBuffer, 236, bit32.bxor(buffer.readu32(OutputBuffer, 204), W2))

	elseif KeyLength == 24 then
		for KeyOffset = 24, 168, 24 do
			RoundConstant = RoundConstant * 2 % 229
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 24), SubWord(Word), RoundConstant)
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			local W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 20), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, W1)
			local W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 16), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, W2)
			local W3 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, W3)
			local W4 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), W3)
			buffer.writeu32(OutputBuffer, KeyOffset + 16, W4)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), W4)
			buffer.writeu32(OutputBuffer, KeyOffset + 20, Word)
			Word = bit32.rrotate(Word, 8)
		end

		Word = bit32.bxor(buffer.readu32(OutputBuffer, 168), SubWord(Word), 128)
		buffer.writeu32(OutputBuffer, 192, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 172), Word)
		buffer.writeu32(OutputBuffer, 196, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 176), W1)
		buffer.writeu32(OutputBuffer, 200, W2)
		buffer.writeu32(OutputBuffer, 204, bit32.bxor(buffer.readu32(OutputBuffer, 180), W2))
	else
		for KeyOffset = 16, 144, 16 do
			RoundConstant = RoundConstant * 2 % 229
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 16), SubWord(Word), RoundConstant)
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			local W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, W1)
			local W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, W2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, Word)
			Word = bit32.rrotate(Word, 8)
		end

		Word = bit32.bxor(buffer.readu32(OutputBuffer, 144), SubWord(Word), 54)
		buffer.writeu32(OutputBuffer, 160, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 148), Word)
		buffer.writeu32(OutputBuffer, 164, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 152), W1)
		buffer.writeu32(OutputBuffer, 168, W2)
		buffer.writeu32(OutputBuffer, 172, bit32.bxor(buffer.readu32(OutputBuffer, 156), W2))
	end

	return OutputBuffer
end

local function EncryptBlock(RoundKeys: buffer, MaterialLength: number, Plaintext: buffer, PlaintextOffset: number, Output: buffer, OutputOffset: number)
	local Nr = MaterialLength / 16 + 2
	local LT0 = TTABLE0
	local LT1 = TTABLE1
	local LT2 = TTABLE2
	local LT3 = TTABLE3
	local LSBox = SUBSTITUTION_BOX

	local C0 = bit32.bxor(buffer.readu32(Plaintext, PlaintextOffset + 0), buffer.readu32(RoundKeys, 0))
	local C1 = bit32.bxor(buffer.readu32(Plaintext, PlaintextOffset + 4), buffer.readu32(RoundKeys, 4))
	local C2 = bit32.bxor(buffer.readu32(Plaintext, PlaintextOffset + 8), buffer.readu32(RoundKeys, 8))
	local C3 = bit32.bxor(buffer.readu32(Plaintext, PlaintextOffset + 12), buffer.readu32(RoundKeys, 12))

	for R = 1, Nr - 1 do
		local KOff = R * 16

		local A = bit32.band(C0, 0xFF)
		local B = bit32.band(bit32.rshift(C1, 8), 0xFF)
		local Cc = bit32.band(bit32.rshift(C2, 16), 0xFF)
		local D = bit32.rshift(C3, 24)
		local NewC0 = bit32.bxor(
			buffer.readu32(LT0, bit32.lshift(A, 2)),
			buffer.readu32(LT1, bit32.lshift(B, 2)),
			buffer.readu32(LT2, bit32.lshift(Cc, 2)),
			buffer.readu32(LT3, bit32.lshift(D, 2)),
			buffer.readu32(RoundKeys, KOff))

		A = bit32.band(C1, 0xFF)
		B = bit32.band(bit32.rshift(C2, 8), 0xFF)
		Cc = bit32.band(bit32.rshift(C3, 16), 0xFF)
		D = bit32.rshift(C0, 24)
		local NewC1 = bit32.bxor(
			buffer.readu32(LT0, bit32.lshift(A, 2)),
			buffer.readu32(LT1, bit32.lshift(B, 2)),
			buffer.readu32(LT2, bit32.lshift(Cc, 2)),
			buffer.readu32(LT3, bit32.lshift(D, 2)),
			buffer.readu32(RoundKeys, KOff + 4))

		A = bit32.band(C2, 0xFF)
		B = bit32.band(bit32.rshift(C3, 8), 0xFF)
		Cc = bit32.band(bit32.rshift(C0, 16), 0xFF)
		D = bit32.rshift(C1, 24)
		local NewC2 = bit32.bxor(
			buffer.readu32(LT0, bit32.lshift(A, 2)),
			buffer.readu32(LT1, bit32.lshift(B, 2)),
			buffer.readu32(LT2, bit32.lshift(Cc, 2)),
			buffer.readu32(LT3, bit32.lshift(D, 2)),
			buffer.readu32(RoundKeys, KOff + 8))

		A = bit32.band(C3, 0xFF)
		B = bit32.band(bit32.rshift(C0, 8), 0xFF)
		Cc = bit32.band(bit32.rshift(C1, 16), 0xFF)
		D = bit32.rshift(C2, 24)
		local NewC3 = bit32.bxor(
			buffer.readu32(LT0, bit32.lshift(A, 2)),
			buffer.readu32(LT1, bit32.lshift(B, 2)),
			buffer.readu32(LT2, bit32.lshift(Cc, 2)),
			buffer.readu32(LT3, bit32.lshift(D, 2)),
			buffer.readu32(RoundKeys, KOff + 12))

		C0, C1, C2, C3 = NewC0, NewC1, NewC2, NewC3
	end

	local KOff = Nr * 16

	local A = buffer.readu8(LSBox, bit32.band(C0, 0xFF))
	local B = buffer.readu8(LSBox, bit32.band(bit32.rshift(C1, 8), 0xFF))
	local Cc = buffer.readu8(LSBox, bit32.band(bit32.rshift(C2, 16), 0xFF))
	local D = buffer.readu8(LSBox, bit32.rshift(C3, 24))
	buffer.writeu32(Output, OutputOffset + 0, bit32.bxor(
		bit32.bor(A, bit32.lshift(B, 8), bit32.lshift(Cc, 16), bit32.lshift(D, 24)),
		buffer.readu32(RoundKeys, KOff)))

	A = buffer.readu8(LSBox, bit32.band(C1, 0xFF))
	B = buffer.readu8(LSBox, bit32.band(bit32.rshift(C2, 8), 0xFF))
	Cc = buffer.readu8(LSBox, bit32.band(bit32.rshift(C3, 16), 0xFF))
	D = buffer.readu8(LSBox, bit32.rshift(C0, 24))
	buffer.writeu32(Output, OutputOffset + 4, bit32.bxor(
		bit32.bor(A, bit32.lshift(B, 8), bit32.lshift(Cc, 16), bit32.lshift(D, 24)),
		buffer.readu32(RoundKeys, KOff + 4)))

	A = buffer.readu8(LSBox, bit32.band(C2, 0xFF))
	B = buffer.readu8(LSBox, bit32.band(bit32.rshift(C3, 8), 0xFF))
	Cc = buffer.readu8(LSBox, bit32.band(bit32.rshift(C0, 16), 0xFF))
	D = buffer.readu8(LSBox, bit32.rshift(C1, 24))
	buffer.writeu32(Output, OutputOffset + 8, bit32.bxor(
		bit32.bor(A, bit32.lshift(B, 8), bit32.lshift(Cc, 16), bit32.lshift(D, 24)),
		buffer.readu32(RoundKeys, KOff + 8)))

	A = buffer.readu8(LSBox, bit32.band(C3, 0xFF))
	B = buffer.readu8(LSBox, bit32.band(bit32.rshift(C0, 8), 0xFF))
	Cc = buffer.readu8(LSBox, bit32.band(bit32.rshift(C1, 16), 0xFF))
	D = buffer.readu8(LSBox, bit32.rshift(C2, 24))
	buffer.writeu32(Output, OutputOffset + 12, bit32.bxor(
		bit32.bor(A, bit32.lshift(B, 8), bit32.lshift(Cc, 16), bit32.lshift(D, 24)),
		buffer.readu32(RoundKeys, KOff + 12)))
end

local function ConstantTimeCompare(Buffer1: buffer, Buffer2: buffer): boolean
	local Length1 = buffer.len(Buffer1)
	local Length2 = buffer.len(Buffer2)
	if Length1 ~= Length2 then
		return false
	end

	local Difference = 0
	for Index = 0, Length1 - 1 do
		Difference = bit32.bor(Difference, bit32.bxor(
			buffer.readu8(Buffer1, Index),
			buffer.readu8(Buffer2, Index)
			))
	end

	return Difference == 0
end

local function BuildShoupTables(H: buffer): buffer
	local Doubles = DOUBLES
	local AllTables = ALL_TABLES

	buffer.copy(Doubles, 0, H, 0, 16)

	for I = 1, 127 do
		local PrevOffset = (I - 1) * 16
		local CurrOffset = I * 16

		local LSB = bit32.band(buffer.readu8(Doubles, PrevOffset + 15), 1)

		local Carry = 0
		for BytePos = 0, 15 do
			local B = buffer.readu8(Doubles, PrevOffset + BytePos)
			local NewCarry = bit32.lshift(bit32.band(B, 1), 7)
			buffer.writeu8(Doubles, CurrOffset + BytePos, bit32.bor(bit32.rshift(B, 1), Carry))
			Carry = NewCarry
		end

		if LSB == 1 then
			buffer.writeu8(Doubles, CurrOffset, bit32.bxor(buffer.readu8(Doubles, CurrOffset), 0xE1))
		end
	end

	for NibbleIdx = 0, 31 do
		local TableOffset = NibbleIdx * 256
		local DoubleBase = NibbleIdx * 64

		local A0 = buffer.readu32(Doubles, DoubleBase)
		local A1 = buffer.readu32(Doubles, DoubleBase + 4)
		local A2 = buffer.readu32(Doubles, DoubleBase + 8)
		local A3 = buffer.readu32(Doubles, DoubleBase + 12)
		local B0 = buffer.readu32(Doubles, DoubleBase + 16)
		local B1 = buffer.readu32(Doubles, DoubleBase + 20)
		local B2 = buffer.readu32(Doubles, DoubleBase + 24)
		local B3 = buffer.readu32(Doubles, DoubleBase + 28)
		local C0 = buffer.readu32(Doubles, DoubleBase + 32)
		local C1 = buffer.readu32(Doubles, DoubleBase + 36)
		local C2 = buffer.readu32(Doubles, DoubleBase + 40)
		local C3 = buffer.readu32(Doubles, DoubleBase + 44)
		local D0 = buffer.readu32(Doubles, DoubleBase + 48)
		local D1 = buffer.readu32(Doubles, DoubleBase + 52)
		local D2 = buffer.readu32(Doubles, DoubleBase + 56)
		local D3 = buffer.readu32(Doubles, DoubleBase + 60)

		buffer.writeu32(AllTables, TableOffset, 0)
		buffer.writeu32(AllTables, TableOffset + 4, 0)
		buffer.writeu32(AllTables, TableOffset + 8, 0)
		buffer.writeu32(AllTables, TableOffset + 12, 0)

		buffer.writeu32(AllTables, TableOffset + 16, D0)
		buffer.writeu32(AllTables, TableOffset + 20, D1)
		buffer.writeu32(AllTables, TableOffset + 24, D2)
		buffer.writeu32(AllTables, TableOffset + 28, D3)

		buffer.writeu32(AllTables, TableOffset + 32, C0)
		buffer.writeu32(AllTables, TableOffset + 36, C1)
		buffer.writeu32(AllTables, TableOffset + 40, C2)
		buffer.writeu32(AllTables, TableOffset + 44, C3)

		buffer.writeu32(AllTables, TableOffset + 48, bit32.bxor(C0, D0))
		buffer.writeu32(AllTables, TableOffset + 52, bit32.bxor(C1, D1))
		buffer.writeu32(AllTables, TableOffset + 56, bit32.bxor(C2, D2))
		buffer.writeu32(AllTables, TableOffset + 60, bit32.bxor(C3, D3))

		buffer.writeu32(AllTables, TableOffset + 64, B0)
		buffer.writeu32(AllTables, TableOffset + 68, B1)
		buffer.writeu32(AllTables, TableOffset + 72, B2)
		buffer.writeu32(AllTables, TableOffset + 76, B3)

		buffer.writeu32(AllTables, TableOffset + 80, bit32.bxor(B0, D0))
		buffer.writeu32(AllTables, TableOffset + 84, bit32.bxor(B1, D1))
		buffer.writeu32(AllTables, TableOffset + 88, bit32.bxor(B2, D2))
		buffer.writeu32(AllTables, TableOffset + 92, bit32.bxor(B3, D3))

		buffer.writeu32(AllTables, TableOffset + 96, bit32.bxor(B0, C0))
		buffer.writeu32(AllTables, TableOffset + 100, bit32.bxor(B1, C1))
		buffer.writeu32(AllTables, TableOffset + 104, bit32.bxor(B2, C2))
		buffer.writeu32(AllTables, TableOffset + 108, bit32.bxor(B3, C3))

		buffer.writeu32(AllTables, TableOffset + 112, bit32.bxor(B0, C0, D0))
		buffer.writeu32(AllTables, TableOffset + 116, bit32.bxor(B1, C1, D1))
		buffer.writeu32(AllTables, TableOffset + 120, bit32.bxor(B2, C2, D2))
		buffer.writeu32(AllTables, TableOffset + 124, bit32.bxor(B3, C3, D3))

		buffer.writeu32(AllTables, TableOffset + 128, A0)
		buffer.writeu32(AllTables, TableOffset + 132, A1)
		buffer.writeu32(AllTables, TableOffset + 136, A2)
		buffer.writeu32(AllTables, TableOffset + 140, A3)

		buffer.writeu32(AllTables, TableOffset + 144, bit32.bxor(A0, D0))
		buffer.writeu32(AllTables, TableOffset + 148, bit32.bxor(A1, D1))
		buffer.writeu32(AllTables, TableOffset + 152, bit32.bxor(A2, D2))
		buffer.writeu32(AllTables, TableOffset + 156, bit32.bxor(A3, D3))

		buffer.writeu32(AllTables, TableOffset + 160, bit32.bxor(A0, C0))
		buffer.writeu32(AllTables, TableOffset + 164, bit32.bxor(A1, C1))
		buffer.writeu32(AllTables, TableOffset + 168, bit32.bxor(A2, C2))
		buffer.writeu32(AllTables, TableOffset + 172, bit32.bxor(A3, C3))

		buffer.writeu32(AllTables, TableOffset + 176, bit32.bxor(A0, C0, D0))
		buffer.writeu32(AllTables, TableOffset + 180, bit32.bxor(A1, C1, D1))
		buffer.writeu32(AllTables, TableOffset + 184, bit32.bxor(A2, C2, D2))
		buffer.writeu32(AllTables, TableOffset + 188, bit32.bxor(A3, C3, D3))

		buffer.writeu32(AllTables, TableOffset + 192, bit32.bxor(A0, B0))
		buffer.writeu32(AllTables, TableOffset + 196, bit32.bxor(A1, B1))
		buffer.writeu32(AllTables, TableOffset + 200, bit32.bxor(A2, B2))
		buffer.writeu32(AllTables, TableOffset + 204, bit32.bxor(A3, B3))

		buffer.writeu32(AllTables, TableOffset + 208, bit32.bxor(A0, B0, D0))
		buffer.writeu32(AllTables, TableOffset + 212, bit32.bxor(A1, B1, D1))
		buffer.writeu32(AllTables, TableOffset + 216, bit32.bxor(A2, B2, D2))
		buffer.writeu32(AllTables, TableOffset + 220, bit32.bxor(A3, B3, D3))

		buffer.writeu32(AllTables, TableOffset + 224, bit32.bxor(A0, B0, C0))
		buffer.writeu32(AllTables, TableOffset + 228, bit32.bxor(A1, B1, C1))
		buffer.writeu32(AllTables, TableOffset + 232, bit32.bxor(A2, B2, C2))
		buffer.writeu32(AllTables, TableOffset + 236, bit32.bxor(A3, B3, C3))

		buffer.writeu32(AllTables, TableOffset + 240, bit32.bxor(bit32.bxor(A0, B0), bit32.bxor(C0, D0)))
		buffer.writeu32(AllTables, TableOffset + 244, bit32.bxor(bit32.bxor(A1, B1), bit32.bxor(C1, D1)))
		buffer.writeu32(AllTables, TableOffset + 248, bit32.bxor(bit32.bxor(A2, B2), bit32.bxor(C2, D2)))
		buffer.writeu32(AllTables, TableOffset + 252, bit32.bxor(bit32.bxor(A3, B3), bit32.bxor(C3, D3)))
	end

	return AllTables
end

local function GfMult(Y: buffer, Tables: buffer, Z: buffer)
	local ZLo, ZHi = 0i, 0i

	for ByteIdx = 0, 15 do
		local ByteVal = buffer.readu8(Y, ByteIdx)
		local BaseOffset = bit32.lshift(ByteIdx, 9)

		local HighOffset = bit32.bor(BaseOffset, bit32.band(ByteVal, 0xF0))
		ZLo = integer.bxor(ZLo, buffer.readinteger(Tables, HighOffset))
		ZHi = integer.bxor(ZHi, buffer.readinteger(Tables, HighOffset + 8))

		local LowOffset = bit32.bor(BaseOffset, 256, bit32.lshift(bit32.band(ByteVal, 0x0F), 4))
		ZLo = integer.bxor(ZLo, buffer.readinteger(Tables, LowOffset))
		ZHi = integer.bxor(ZHi, buffer.readinteger(Tables, LowOffset + 8))
	end

	buffer.writeinteger(Z, 0, ZLo)
	buffer.writeinteger(Z, 8, ZHi)
end

local function Ghash(Tables: buffer, X: buffer, XLen: number, Y: buffer)
	local M = math.floor(XLen / 16)
	local XPos = 0
	local Tmp = buffer.create(16)
	local GfMult = GfMult

	for _ = 1, M do
		buffer.writeu32(Y, 0, bit32.bxor(buffer.readu32(Y, 0), buffer.readu32(X, XPos)))
		buffer.writeu32(Y, 4, bit32.bxor(buffer.readu32(Y, 4), buffer.readu32(X, XPos + 4)))
		buffer.writeu32(Y, 8, bit32.bxor(buffer.readu32(Y, 8), buffer.readu32(X, XPos + 8)))
		buffer.writeu32(Y, 12, bit32.bxor(buffer.readu32(Y, 12), buffer.readu32(X, XPos + 12)))
		XPos += 16

		GfMult(Y, Tables, Tmp)

		buffer.writeu32(Y, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(Y, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(Y, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(Y, 12, buffer.readu32(Tmp, 12))
	end

	if XPos < XLen then
		local Last = XLen - XPos
		buffer.writeu32(Tmp, 0, 0)
		buffer.writeu32(Tmp, 4, 0)
		buffer.writeu32(Tmp, 8, 0)
		buffer.writeu32(Tmp, 12, 0)
		buffer.copy(Tmp, 0, X, XPos, Last)

		buffer.writeu32(Y, 0, bit32.bxor(buffer.readu32(Y, 0), buffer.readu32(Tmp, 0)))
		buffer.writeu32(Y, 4, bit32.bxor(buffer.readu32(Y, 4), buffer.readu32(Tmp, 4)))
		buffer.writeu32(Y, 8, bit32.bxor(buffer.readu32(Y, 8), buffer.readu32(Tmp, 8)))
		buffer.writeu32(Y, 12, bit32.bxor(buffer.readu32(Y, 12), buffer.readu32(Tmp, 12)))

		GfMult(Y, Tables, Tmp)

		buffer.writeu32(Y, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(Y, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(Y, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(Y, 12, buffer.readu32(Tmp, 12))
	end
end

local function Gctr(RoundKeys: buffer, KeyMaterialLength: number, ICB: buffer, X: buffer, XLen: number, Y: buffer)
	if XLen == 0 then
		return
	end

	local N = math.floor(XLen / 16)
	local CB = buffer.create(16)
	local Tmp = buffer.create(16)
	local XPos = 0
	local YPos = 0

	buffer.writeu32(CB, 0, buffer.readu32(ICB, 0))
	buffer.writeu32(CB, 4, buffer.readu32(ICB, 4))
	buffer.writeu32(CB, 8, buffer.readu32(ICB, 8))
	buffer.writeu32(CB, 12, buffer.readu32(ICB, 12))

	local Encrypt = EncryptBlock

	for I = 0, N - 1 do
		Encrypt(RoundKeys, KeyMaterialLength, CB, 0, Tmp, 0)

		buffer.writeu32(Y, YPos + 0, bit32.bxor(buffer.readu32(X, XPos + 0), buffer.readu32(Tmp, 0)))
		buffer.writeu32(Y, YPos + 4, bit32.bxor(buffer.readu32(X, XPos + 4), buffer.readu32(Tmp, 4)))
		buffer.writeu32(Y, YPos + 8, bit32.bxor(buffer.readu32(X, XPos + 8), buffer.readu32(Tmp, 8)))
		buffer.writeu32(Y, YPos + 12, bit32.bxor(buffer.readu32(X, XPos + 12), buffer.readu32(Tmp, 12)))

		XPos += 16
		YPos += 16

		local Val = bit32.byteswap(buffer.readu32(CB, 12))
		Val = (Val + 1) % 0x100000000
		buffer.writeu32(CB, 12, bit32.byteswap(Val))
	end

	local Last = XLen - XPos
	if Last > 0 then
		EncryptBlock(RoundKeys, KeyMaterialLength, CB, 0, Tmp, 0)
		for I = 0, Last - 1 do
			local XByte = buffer.readu8(X, XPos + I)
			local TmpByte = buffer.readu8(Tmp, I)
			buffer.writeu8(Y, YPos + I, bit32.bxor(XByte, TmpByte))
		end
	end
end

local function PrepareJ0(H: buffer, IV: buffer, IVLen: number, J0: buffer): buffer
	local Tables = BuildShoupTables(H)

	if IVLen == 12 then
		buffer.writeu32(J0, 0, buffer.readu32(IV, 0))
		buffer.writeu32(J0, 4, buffer.readu32(IV, 4))
		buffer.writeu32(J0, 8, buffer.readu32(IV, 8))
		buffer.writeu32(J0, 12, 0x01000000)
	else
		buffer.writeu32(J0, 0, 0)
		buffer.writeu32(J0, 4, 0)
		buffer.writeu32(J0, 8, 0)
		buffer.writeu32(J0, 12, 0)

		Ghash(Tables, IV, IVLen, J0)

		local LenBuf = buffer.create(16)
		local IVLenBits = IVLen * 8

		buffer.writeu32(LenBuf, 0, 0)
		buffer.writeu32(LenBuf, 4, 0)
		buffer.writeu32(LenBuf, 8, 0)
		buffer.writeu32(LenBuf, 12, bit32.byteswap(IVLenBits))

		Ghash(Tables, LenBuf, 16, J0)
	end

	return Tables
end

local function GcmGctr(RoundKeys: buffer, KeyMaterialLength: number, J0: buffer, Input: buffer, Len: number, Output: buffer)
	if Len == 0 then
		return
	end

	local J0Inc = buffer.create(16)

	buffer.writeu32(J0Inc, 0, buffer.readu32(J0, 0))
	buffer.writeu32(J0Inc, 4, buffer.readu32(J0, 4))
	buffer.writeu32(J0Inc, 8, buffer.readu32(J0, 8))
	buffer.writeu32(J0Inc, 12, buffer.readu32(J0, 12))

	local Val = bit32.byteswap(buffer.readu32(J0Inc, 12))
	Val = (Val + 1) % 0x100000000
	buffer.writeu32(J0Inc, 12, bit32.byteswap(Val))

	Gctr(RoundKeys, KeyMaterialLength, J0Inc, Input, Len, Output)
end

local function GcmHash(Tables: buffer, AAD: buffer, AADLen: number, Crypt: buffer, CryptLen: number, S: buffer)
	local Tmp = buffer.create(16)
	local GfMult = GfMult

	buffer.writeu32(S, 0, 0)
	buffer.writeu32(S, 4, 0)
	buffer.writeu32(S, 8, 0)
	buffer.writeu32(S, 12, 0)

	local M = math.floor(AADLen / 16)
	local XPos = 0

	for _ = 1, M do
		buffer.writeu32(S, 0, bit32.bxor(buffer.readu32(S, 0), buffer.readu32(AAD, XPos)))
		buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), buffer.readu32(AAD, XPos + 4)))
		buffer.writeu32(S, 8, bit32.bxor(buffer.readu32(S, 8), buffer.readu32(AAD, XPos + 8)))
		buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), buffer.readu32(AAD, XPos + 12)))
		XPos += 16

		GfMult(S, Tables, Tmp)

		buffer.writeu32(S, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(S, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(S, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(S, 12, buffer.readu32(Tmp, 12))
	end

	if XPos < AADLen then
		local Last = AADLen - XPos
		buffer.writeu32(Tmp, 0, 0)
		buffer.writeu32(Tmp, 4, 0)
		buffer.writeu32(Tmp, 8, 0)
		buffer.writeu32(Tmp, 12, 0)
		buffer.copy(Tmp, 0, AAD, XPos, Last)

		buffer.writeu32(S, 0, bit32.bxor(buffer.readu32(S, 0), buffer.readu32(Tmp, 0)))
		buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), buffer.readu32(Tmp, 4)))
		buffer.writeu32(S, 8, bit32.bxor(buffer.readu32(S, 8), buffer.readu32(Tmp, 8)))
		buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), buffer.readu32(Tmp, 12)))

		GfMult(S, Tables, Tmp)

		buffer.writeu32(S, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(S, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(S, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(S, 12, buffer.readu32(Tmp, 12))
	end

	M = math.floor(CryptLen / 16)
	XPos = 0

	for _ = 1, M do
		buffer.writeu32(S, 0, bit32.bxor(buffer.readu32(S, 0), buffer.readu32(Crypt, XPos)))
		buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), buffer.readu32(Crypt, XPos + 4)))
		buffer.writeu32(S, 8, bit32.bxor(buffer.readu32(S, 8), buffer.readu32(Crypt, XPos + 8)))
		buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), buffer.readu32(Crypt, XPos + 12)))
		XPos += 16

		GfMult(S, Tables, Tmp)

		buffer.writeu32(S, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(S, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(S, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(S, 12, buffer.readu32(Tmp, 12))
	end

	if XPos < CryptLen then
		local Last = CryptLen - XPos
		buffer.writeu32(Tmp, 0, 0)
		buffer.writeu32(Tmp, 4, 0)
		buffer.writeu32(Tmp, 8, 0)
		buffer.writeu32(Tmp, 12, 0)
		buffer.copy(Tmp, 0, Crypt, XPos, Last)

		buffer.writeu32(S, 0, bit32.bxor(buffer.readu32(S, 0), buffer.readu32(Tmp, 0)))
		buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), buffer.readu32(Tmp, 4)))
		buffer.writeu32(S, 8, bit32.bxor(buffer.readu32(S, 8), buffer.readu32(Tmp, 8)))
		buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), buffer.readu32(Tmp, 12)))

		GfMult(S, Tables, Tmp)

		buffer.writeu32(S, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(S, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(S, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(S, 12, buffer.readu32(Tmp, 12))
	end

	local AADLenBits = AADLen * 8
	local CryptLenBits = CryptLen * 8

	buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), bit32.byteswap(AADLenBits)))
	buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), bit32.byteswap(CryptLenBits)))

	GfMult(S, Tables, Tmp)

	buffer.writeu32(S, 0, buffer.readu32(Tmp, 0))
	buffer.writeu32(S, 4, buffer.readu32(Tmp, 4))
	buffer.writeu32(S, 8, buffer.readu32(Tmp, 8))
	buffer.writeu32(S, 12, buffer.readu32(Tmp, 12))
end

function AES.Encrypt(Plaintext: buffer, Key: buffer, IV: buffer, AAD: buffer?): (buffer, buffer)
	if not Key or typeof(Key) ~= "buffer" then
		error("Key must be a buffer", 2)
	end

	if not IV or typeof(IV) ~= "buffer" then
		error("IV must be a buffer", 2)
	end

	if not Plaintext or typeof(Plaintext) ~= "buffer" then
		error("Plaintext must be a buffer", 2)
	end

	local KeyLength = buffer.len(Key)
	if KeyLength ~= 16 and KeyLength ~= 24 and KeyLength ~= 32 then
		error("Key must be 16, 24, or 32 bytes", 2)
	end

	local IVLen = buffer.len(IV)
	if IVLen == 0 then
		error("IV cannot be empty", 2)
	end

	local KeyConfig = KEY_CONFIGS[KeyLength]
	local RoundKeys = ExpandKeySchedule(Key, KeyLength, buffer.create(KeyConfig.ExpandedLength))
	local KeyMaterialLength = KeyConfig.MaterialLength

	local AADLen = buffer.len(AAD or buffer.create(0))
	local PlainLen = buffer.len(Plaintext)
	local AuthData = AAD or buffer.create(0)

	local OutputBuffer = buffer.create(PlainLen)
	local OutputTag = buffer.create(16)

	local H = buffer.create(16)
	local J0 = buffer.create(16)
	local S = buffer.create(16)

	EncryptBlock(RoundKeys, KeyMaterialLength, H, 0, H, 0)
	local Tables = PrepareJ0(H, IV, IVLen, J0)
	GcmGctr(RoundKeys, KeyMaterialLength, J0, Plaintext, PlainLen, OutputBuffer)
	GcmHash(Tables, AuthData, AADLen, OutputBuffer, PlainLen, S)
	Gctr(RoundKeys, KeyMaterialLength, J0, S, 16, OutputTag)

	return OutputBuffer, OutputTag
end

function AES.Decrypt(Ciphertext: buffer, Key: buffer, IV: buffer, Tag: buffer, AAD: buffer?): buffer?
	if not Key or typeof(Key) ~= "buffer" then
		error("Key must be a buffer", 2)
	end

	if not IV or typeof(IV) ~= "buffer" then
		error("IV must be a buffer", 2)
	end

	if not Ciphertext or typeof(Ciphertext) ~= "buffer" then
		error("Ciphertext must be a buffer", 2)
	end

	if not Tag or typeof(Tag) ~= "buffer" then
		error("Tag must be a buffer", 2)
	end

	local KeyLength = buffer.len(Key)
	if KeyLength ~= 16 and KeyLength ~= 24 and KeyLength ~= 32 then
		error("Key must be 16, 24, or 32 bytes", 2)
	end

	local IVLen = buffer.len(IV)
	if IVLen == 0 then
		error("IV cannot be empty", 2)
	end

	local KeyConfig = KEY_CONFIGS[KeyLength]
	local RoundKeys = ExpandKeySchedule(Key, KeyLength, buffer.create(KeyConfig.ExpandedLength))
	local KeyMaterialLength = KeyConfig.MaterialLength

	local AADLen = buffer.len(AAD or buffer.create(0))
	local CryptLen = buffer.len(Ciphertext)
	local AuthData = AAD or buffer.create(0)

	local OutputBuffer = buffer.create(CryptLen)

	local H = buffer.create(16)
	local J0 = buffer.create(16)
	local S = buffer.create(16)
	local ComputedTag = buffer.create(16)

	EncryptBlock(RoundKeys, KeyMaterialLength, H, 0, H, 0)
	local Tables = PrepareJ0(H, IV, IVLen, J0)
	GcmGctr(RoundKeys, KeyMaterialLength, J0, Ciphertext, CryptLen, OutputBuffer)
	GcmHash(Tables, AuthData, AADLen, Ciphertext, CryptLen, S)
	Gctr(RoundKeys, KeyMaterialLength, J0, S, 16, ComputedTag)

	if not ConstantTimeCompare(Tag, ComputedTag) then
		return nil
	end

	return OutputBuffer
end

return AES