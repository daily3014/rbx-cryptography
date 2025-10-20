--[=[
	Cryptography library: AES
	
	Sizes:
		Init Vector: 16 bytes
		Key Size: 16 / 24 / 32 bytes
	
	Example usage:
	local Key = CSPRNG.RandomBytes(32)
	local IV = CSPRNG.RandomBytes(12)

	local Message = "This is a secret message"
	local Plaintext = buffer.fromstring(Message)

	local AAD = buffer.fromstring("user:john,timestamp:456745683")
	local Ciphertext, Tag = AES.Encrypt(Key, IV, Plaintext, AAD)
--]=]

--!strict
--!optimize 2
--!native

type Processor = (PlaintextBlock: buffer, PlaintextOffset: number, OutputBuffer: buffer, OutputOffset: number) -> ()

local AES = {}

local SBOX_16BIT = buffer.create(131072) 
local SMIX_TABLE0 = buffer.create(65536)
local SMIX_TABLE1 = buffer.create(65536)

local INVS_XOR_TABLE = buffer.create(65536)
local INVMIX_TABLE0 = buffer.create(65536)
local INVMIX_TABLE1 = buffer.create(65536)

local KEY_CONFIGS = {
	[16] = {ExpandedLength = 176, MaterialLength = 128},
	[24] = {ExpandedLength = 208, MaterialLength = 160},
	[32] = {ExpandedLength = 240, MaterialLength = 192}
}

local SUBSTITUTION_BOX, INVERSE_SUBSTITUTION_BOX = buffer.create(256), buffer.create(256) do
	local GaloisMultiply3, GaloisMultiply9, GaloisMultiply11 = buffer.create(256), buffer.create(256), buffer.create(256)
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
		buffer.writeu8(INVERSE_SUBSTITUTION_BOX, TempValue, PolynomialP)
		buffer.writeu8(GaloisMultiply3, PolynomialP, GaloisFieldMultiply(3, PolynomialP))
		buffer.writeu8(GaloisMultiply9, PolynomialP, GaloisFieldMultiply(9, PolynomialP))
		buffer.writeu8(GaloisMultiply11, PolynomialP, GaloisFieldMultiply(11, PolynomialP))
	end

	local TableIndex = 0
	for OuterIndex = 0, 255 do
		local PolynomialPOuter = buffer.readu8(SUBSTITUTION_BOX, OuterIndex)
		local PolynomialPBytes = PolynomialPOuter * 256
		local Galois2 = GaloisFieldMultiply(2, PolynomialPOuter)
		local Galois13 = GaloisFieldMultiply(13, OuterIndex)
		local Galois14 = GaloisFieldMultiply(14, OuterIndex)

		for InnerIndex = 0, 255 do
			local PolynomialQInner = buffer.readu8(SUBSTITUTION_BOX, InnerIndex)

			buffer.writeu16(SBOX_16BIT, TableIndex * 2, PolynomialPBytes + PolynomialQInner)
			buffer.writeu8(INVS_XOR_TABLE, TableIndex, buffer.readu8(INVERSE_SUBSTITUTION_BOX, bit32.bxor(OuterIndex, InnerIndex)))
			buffer.writeu8(SMIX_TABLE0, TableIndex, bit32.bxor(Galois2, buffer.readu8(GaloisMultiply3, PolynomialQInner)))
			buffer.writeu8(SMIX_TABLE1, TableIndex, bit32.bxor(PolynomialPOuter, PolynomialQInner))
			buffer.writeu8(INVMIX_TABLE0, TableIndex, bit32.bxor(Galois14, buffer.readu8(GaloisMultiply11, InnerIndex)))
			buffer.writeu8(INVMIX_TABLE1, TableIndex, bit32.bxor(Galois13, buffer.readu8(GaloisMultiply9, InnerIndex)))
			TableIndex += 1
		end
	end
end

local function ExpandKeySchedule(Key: buffer, KeyLength: number, OutputBuffer: buffer): buffer
	buffer.copy(OutputBuffer, 0, Key, 0, KeyLength)

	local Word = bit32.rrotate(buffer.readu32(OutputBuffer, KeyLength - 4), 8)
	local RoundConstant = 0.5
	local SBox_16 = SBOX_16BIT

	if KeyLength == 32 then
		for KeyOffset = 32, 192, 32 do
			RoundConstant = RoundConstant * 2 % 229
			local SBoxLookup = buffer.readu16(SBox_16, Word // 65536 * 2) * 65536 + buffer.readu16(SBox_16, Word % 65536 * 2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 32), SBoxLookup, RoundConstant)
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			local W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 28), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, W1)
			local W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 24), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, W2)
			local W3 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 20), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, W3)

			SBoxLookup = buffer.readu16(SBox_16, W3 // 65536 * 2) * 65536 + buffer.readu16(SBox_16, W3 % 65536 * 2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 16), SBoxLookup)
			buffer.writeu32(OutputBuffer, KeyOffset + 16, Word)

			W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 20, W1)
			W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 24, W2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 28, Word)
			Word = bit32.rrotate(Word, 8)
		end

		local SBoxLookup = buffer.readu16(SBox_16, Word // 65536 * 2) * 65536 + buffer.readu16(SBox_16, Word % 65536 * 2)
		Word = bit32.bxor(buffer.readu32(OutputBuffer, 192), SBoxLookup, 64)
		buffer.writeu32(OutputBuffer, 224, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 196), Word)
		buffer.writeu32(OutputBuffer, 228, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 200), W1)
		buffer.writeu32(OutputBuffer, 232, W2)
		buffer.writeu32(OutputBuffer, 236, bit32.bxor(buffer.readu32(OutputBuffer, 204), W2))

	elseif KeyLength == 24 then
		for KeyOffset = 24, 168, 24 do
			RoundConstant = RoundConstant * 2 % 229
			local SBoxLookup = buffer.readu16(SBox_16, Word // 65536 * 2) * 65536 + buffer.readu16(SBox_16, Word % 65536 * 2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 24), SBoxLookup, RoundConstant)
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

		local SBoxLookup = buffer.readu16(SBox_16, Word // 65536 * 2) * 65536 + buffer.readu16(SBox_16, Word % 65536 * 2)
		Word = bit32.bxor(buffer.readu32(OutputBuffer, 168), SBoxLookup, 128)
		buffer.writeu32(OutputBuffer, 192, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 172), Word)
		buffer.writeu32(OutputBuffer, 196, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 176), W1)
		buffer.writeu32(OutputBuffer, 200, W2)
		buffer.writeu32(OutputBuffer, 204, bit32.bxor(buffer.readu32(OutputBuffer, 180), W2))
	else
		for KeyOffset = 16, 144, 16 do
			RoundConstant = RoundConstant * 2 % 229
			local SBoxLookup = buffer.readu16(SBox_16, Word // 65536 * 2) * 65536 + buffer.readu16(SBox_16, Word % 65536 * 2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 16), SBoxLookup, RoundConstant)
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			local W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, W1)
			local W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, W2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, Word)
			Word = bit32.rrotate(Word, 8)
		end

		local SBoxLookup = buffer.readu16(SBox_16, Word // 65536 * 2) * 65536 + buffer.readu16(SBox_16, Word % 65536 * 2)
		Word = bit32.bxor(buffer.readu32(OutputBuffer, 144), SBoxLookup, 54)
		buffer.writeu32(OutputBuffer, 160, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 148), Word)
		buffer.writeu32(OutputBuffer, 164, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 152), W1)
		buffer.writeu32(OutputBuffer, 168, W2)
		buffer.writeu32(OutputBuffer, 172, bit32.bxor(buffer.readu32(OutputBuffer, 156), W2))
	end

	return OutputBuffer
end

local A0: number, A1: number, A2: number, A3: number, A4: number, A5: number, A6: number, A7: number, A8: number, A9: number, A10: number, A11: number, A12: number, A13: number, A14: number, A15: number
local function EncryptBlock(RoundKeys: buffer, MaterialLength: number, Plaintext: buffer, PlaintextOffset: number, Output: buffer, OutputOffset: number)
	A0 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset), buffer.readu8(RoundKeys, 0))
	A1 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 1), buffer.readu8(RoundKeys, 1))
	A2 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 2), buffer.readu8(RoundKeys, 2))
	A3 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 3), buffer.readu8(RoundKeys, 3))
	A4 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 4), buffer.readu8(RoundKeys, 4))
	A5 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 5), buffer.readu8(RoundKeys, 5))
	A6 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 6), buffer.readu8(RoundKeys, 6))
	A7 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 7), buffer.readu8(RoundKeys, 7))
	A8 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 8), buffer.readu8(RoundKeys, 8))
	A9 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 9), buffer.readu8(RoundKeys, 9))
	A10 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 10), buffer.readu8(RoundKeys, 10))
	A11 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 11), buffer.readu8(RoundKeys, 11))
	A12 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 12), buffer.readu8(RoundKeys, 12))
	A13 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 13), buffer.readu8(RoundKeys, 13))
	A14 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 14), buffer.readu8(RoundKeys, 14))
	A15 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 15), buffer.readu8(RoundKeys, 15))

	local B0: number, B1: number, B2: number, B3: number, B4: number, B5: number, B6: number, B7: number, B8: number, B9: number, B10: number, B11: number, B12: number, B13: number, B14: number, B15: number
		= A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15

	local I0: number = B0 * 256 + B5; local I1: number = B5 * 256 + B10; local I2: number = B10 * 256 + B15; local I3: number = B15 * 256 + B0
	local I4: number = B4 * 256 + B9; local I5: number = B9 * 256 + B14; local I6: number = B14 * 256 + B3; local I7: number = B3 * 256 + B4
	local I8: number = B8 * 256 + B13; local I9: number = B13 * 256 + B2; local I10: number = B2 * 256 + B7; local I11: number = B7 * 256 + B8
	local I12: number = B12 * 256 + B1; local I13: number = B1 * 256 + B6; local I14: number = B6 * 256 + B11; local I15: number = B11 * 256 + B12

	local Tbl0, Tbl1 = SMIX_TABLE0, SMIX_TABLE1
	for RoundOffset = 16, MaterialLength, 16 do
		B0 = bit32.bxor(buffer.readu8(Tbl0, I0), buffer.readu8(Tbl1, I2), buffer.readu8(RoundKeys, RoundOffset))
		B1 = bit32.bxor(buffer.readu8(Tbl0, I1), buffer.readu8(Tbl1, I3), buffer.readu8(RoundKeys, RoundOffset + 1))
		B2 = bit32.bxor(buffer.readu8(Tbl0, I2), buffer.readu8(Tbl1, I0), buffer.readu8(RoundKeys, RoundOffset + 2))
		B3 = bit32.bxor(buffer.readu8(Tbl0, I3), buffer.readu8(Tbl1, I1), buffer.readu8(RoundKeys, RoundOffset + 3))
		B4 = bit32.bxor(buffer.readu8(Tbl0, I4), buffer.readu8(Tbl1, I6), buffer.readu8(RoundKeys, RoundOffset + 4))
		B5 = bit32.bxor(buffer.readu8(Tbl0, I5), buffer.readu8(Tbl1, I7), buffer.readu8(RoundKeys, RoundOffset + 5))
		B6 = bit32.bxor(buffer.readu8(Tbl0, I6), buffer.readu8(Tbl1, I4), buffer.readu8(RoundKeys, RoundOffset + 6))
		B7 = bit32.bxor(buffer.readu8(Tbl0, I7), buffer.readu8(Tbl1, I5), buffer.readu8(RoundKeys, RoundOffset + 7))
		B8 = bit32.bxor(buffer.readu8(Tbl0, I8), buffer.readu8(Tbl1, I10), buffer.readu8(RoundKeys, RoundOffset + 8))
		B9 = bit32.bxor(buffer.readu8(Tbl0, I9), buffer.readu8(Tbl1, I11), buffer.readu8(RoundKeys, RoundOffset + 9))
		B10 = bit32.bxor(buffer.readu8(Tbl0, I10), buffer.readu8(Tbl1, I8), buffer.readu8(RoundKeys, RoundOffset + 10))
		B11 = bit32.bxor(buffer.readu8(Tbl0, I11), buffer.readu8(Tbl1, I9), buffer.readu8(RoundKeys, RoundOffset + 11))
		B12 = bit32.bxor(buffer.readu8(Tbl0, I12), buffer.readu8(Tbl1, I14), buffer.readu8(RoundKeys, RoundOffset + 12))
		B13 = bit32.bxor(buffer.readu8(Tbl0, I13), buffer.readu8(Tbl1, I15), buffer.readu8(RoundKeys, RoundOffset + 13))
		B14 = bit32.bxor(buffer.readu8(Tbl0, I14), buffer.readu8(Tbl1, I12), buffer.readu8(RoundKeys, RoundOffset + 14))
		B15 = bit32.bxor(buffer.readu8(Tbl0, I15), buffer.readu8(Tbl1, I13), buffer.readu8(RoundKeys, RoundOffset + 15))

		I0, I1, I2, I3 = B0 * 256 + B5, B5 * 256 + B10, B10 * 256 + B15, B15 * 256 + B0
		I4, I5, I6, I7 = B4 * 256 + B9, B9 * 256 + B14, B14 * 256 + B3, B3 * 256 + B4
		I8, I9, I10, I11 = B8 * 256 + B13, B13 * 256 + B2, B2 * 256 + B7, B7 * 256 + B8
		I12, I13, I14, I15 = B12 * 256 + B1, B1 * 256 + B6, B6 * 256 + B11, B11 * 256 + B12
	end

	buffer.writeu32(Output, OutputOffset, bit32.bxor(
		buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I15), buffer.readu8(SMIX_TABLE1, I13), buffer.readu8(RoundKeys, MaterialLength + 31)) * 512 + 
			bit32.bxor(buffer.readu8(Tbl0, I10), buffer.readu8(SMIX_TABLE1, I8), buffer.readu8(RoundKeys, MaterialLength + 26)) * 2) * 65536 + 
			buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I5), buffer.readu8(SMIX_TABLE1, I7), buffer.readu8(RoundKeys, MaterialLength + 21)) * 512 + 
				bit32.bxor(buffer.readu8(Tbl0, I0), buffer.readu8(SMIX_TABLE1, I2), buffer.readu8(RoundKeys, MaterialLength + 16)) * 2),
		buffer.readu32(RoundKeys, MaterialLength + 32)
		))

	buffer.writeu32(Output, OutputOffset + 4, bit32.bxor(
		buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I3), buffer.readu8(SMIX_TABLE1, I1), buffer.readu8(RoundKeys, MaterialLength + 19)) * 512 + 
			bit32.bxor(buffer.readu8(Tbl0, I14), buffer.readu8(SMIX_TABLE1, I12), buffer.readu8(RoundKeys, MaterialLength + 30)) * 2) * 65536 + 
			buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I9), buffer.readu8(SMIX_TABLE1, I11), buffer.readu8(RoundKeys, MaterialLength + 25)) * 512 + 
				bit32.bxor(buffer.readu8(Tbl0, I4), buffer.readu8(SMIX_TABLE1, I6), buffer.readu8(RoundKeys, MaterialLength + 20)) * 2),
		buffer.readu32(RoundKeys, MaterialLength + 36)
		))

	buffer.writeu32(Output, OutputOffset + 8, bit32.bxor(
		buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I7), buffer.readu8(SMIX_TABLE1, I5), buffer.readu8(RoundKeys, MaterialLength + 23)) * 512 + 
			bit32.bxor(buffer.readu8(Tbl0, I2), buffer.readu8(SMIX_TABLE1, I0), buffer.readu8(RoundKeys, MaterialLength + 18)) * 2) * 65536 + 
			buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I13), buffer.readu8(SMIX_TABLE1, I15), buffer.readu8(RoundKeys, MaterialLength + 29)) * 512 + 
				bit32.bxor(buffer.readu8(Tbl0, I8), buffer.readu8(SMIX_TABLE1, I10), buffer.readu8(RoundKeys, MaterialLength + 24)) * 2),
		buffer.readu32(RoundKeys, MaterialLength + 40)
		))

	buffer.writeu32(Output, OutputOffset + 12, bit32.bxor(
		buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I11), buffer.readu8(SMIX_TABLE1, I9), buffer.readu8(RoundKeys, MaterialLength + 27)) * 512 + 
			bit32.bxor(buffer.readu8(Tbl0, I6), buffer.readu8(SMIX_TABLE1, I4), buffer.readu8(RoundKeys, MaterialLength + 22)) * 2) * 65536 + 
			buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I1), buffer.readu8(SMIX_TABLE1, I3), buffer.readu8(RoundKeys, MaterialLength + 17)) * 512 + 
				bit32.bxor(buffer.readu8(Tbl0, I12), buffer.readu8(SMIX_TABLE1, I14), buffer.readu8(RoundKeys, MaterialLength + 28)) * 2),
		buffer.readu32(RoundKeys, MaterialLength + 44)
		))
end

local function ConstantTimeEquals(Buffer1: buffer, Buffer2: buffer, Length: number): boolean
	local Result = 0
	for I = 0, Length - 1 do
		local Byte1 = buffer.readu8(Buffer1, I)
		local Byte2 = buffer.readu8(Buffer2, I)
		Result = bit32.bor(Result, bit32.bxor(Byte1, Byte2))
	end

	return Result == 0
end

local function GfMult(X: buffer, Y: buffer, Z: buffer)
	local V = buffer.create(16)

	buffer.writeu32(Z, 0, 0)
	buffer.writeu32(Z, 4, 0)
	buffer.writeu32(Z, 8, 0)
	buffer.writeu32(Z, 12, 0)

	buffer.writeu32(V, 0, buffer.readu32(Y, 0))
	buffer.writeu32(V, 4, buffer.readu32(Y, 4))
	buffer.writeu32(V, 8, buffer.readu32(Y, 8))
	buffer.writeu32(V, 12, buffer.readu32(Y, 12))

	for I = 0, 15 do
		for J = 0, 7 do
			if bit32.band(buffer.readu8(X, I), bit32.lshift(1, 7 - J)) ~= 0 then
				buffer.writeu32(Z, 0, bit32.bxor(buffer.readu32(Z, 0), buffer.readu32(V, 0)))
				buffer.writeu32(Z, 4, bit32.bxor(buffer.readu32(Z, 4), buffer.readu32(V, 4)))
				buffer.writeu32(Z, 8, bit32.bxor(buffer.readu32(Z, 8), buffer.readu32(V, 8)))
				buffer.writeu32(Z, 12, bit32.bxor(buffer.readu32(Z, 12), buffer.readu32(V, 12)))
			end

			if buffer.readu8(V, 15) % 2 == 1 then
				local Val: number = 0

				Val = bit32.byteswap(buffer.readu32(V, 12))
				Val = bit32.rshift(Val, 1)
				if bit32.band(buffer.readu8(V, 11), 0x01) ~= 0 then
					Val = bit32.bor(Val, 0x80000000)
				end
				buffer.writeu32(V, 12, bit32.byteswap(Val))

				Val = bit32.byteswap(buffer.readu32(V, 8))
				Val = bit32.rshift(Val, 1)
				if bit32.band(buffer.readu8(V, 7), 0x01) ~= 0 then
					Val = bit32.bor(Val, 0x80000000)
				end
				buffer.writeu32(V, 8, bit32.byteswap(Val))

				Val = bit32.byteswap(buffer.readu32(V, 4))
				Val = bit32.rshift(Val, 1)
				if bit32.band(buffer.readu8(V, 3), 0x01) ~= 0 then
					Val = bit32.bor(Val, 0x80000000)
				end
				buffer.writeu32(V, 4, bit32.byteswap(Val))

				Val = bit32.byteswap(buffer.readu32(V, 0))
				Val = bit32.rshift(Val, 1)
				buffer.writeu32(V, 0, bit32.byteswap(Val))

				buffer.writeu8(V, 0, bit32.bxor(buffer.readu8(V, 0), 0xE1))
			else
				local Val: number = 0

				Val = bit32.byteswap(buffer.readu32(V, 12))
				Val = bit32.rshift(Val, 1)
				if bit32.band(buffer.readu8(V, 11), 0x01) ~= 0 then
					Val = bit32.bor(Val, 0x80000000)
				end
				buffer.writeu32(V, 12, bit32.byteswap(Val))

				Val = bit32.byteswap(buffer.readu32(V, 8))
				Val = bit32.rshift(Val, 1)
				if bit32.band(buffer.readu8(V, 7), 0x01) ~= 0 then
					Val = bit32.bor(Val, 0x80000000)
				end
				buffer.writeu32(V, 8, bit32.byteswap(Val))

				Val = bit32.byteswap(buffer.readu32(V, 4))
				Val = bit32.rshift(Val, 1)
				if bit32.band(buffer.readu8(V, 3), 0x01) ~= 0 then
					Val = bit32.bor(Val, 0x80000000)
				end
				buffer.writeu32(V, 4, bit32.byteswap(Val))

				Val = bit32.byteswap(buffer.readu32(V, 0))
				Val = bit32.rshift(Val, 1)
				buffer.writeu32(V, 0, bit32.byteswap(Val))
			end
		end
	end
end

local function Ghash(H: buffer, X: buffer, XLen: number, Y: buffer)
	local M = math.floor(XLen / 16)
	local XPos = 0
	local Tmp = buffer.create(16)

	for I = 0, M - 1 do
		buffer.writeu32(Y, 0, bit32.bxor(buffer.readu32(Y, 0), buffer.readu32(X, XPos)))
		buffer.writeu32(Y, 4, bit32.bxor(buffer.readu32(Y, 4), buffer.readu32(X, XPos + 4)))
		buffer.writeu32(Y, 8, bit32.bxor(buffer.readu32(Y, 8), buffer.readu32(X, XPos + 8)))
		buffer.writeu32(Y, 12, bit32.bxor(buffer.readu32(Y, 12), buffer.readu32(X, XPos + 12)))
		XPos += 16

		GfMult(Y, H, Tmp)
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

		for I = 0, Last - 1 do
			buffer.writeu8(Tmp, I, buffer.readu8(X, XPos + I))
		end

		buffer.writeu32(Y, 0, bit32.bxor(buffer.readu32(Y, 0), buffer.readu32(Tmp, 0)))
		buffer.writeu32(Y, 4, bit32.bxor(buffer.readu32(Y, 4), buffer.readu32(Tmp, 4)))
		buffer.writeu32(Y, 8, bit32.bxor(buffer.readu32(Y, 8), buffer.readu32(Tmp, 8)))
		buffer.writeu32(Y, 12, bit32.bxor(buffer.readu32(Y, 12), buffer.readu32(Tmp, 12)))

		GfMult(Y, H, Tmp)

		buffer.writeu32(Y, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(Y, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(Y, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(Y, 12, buffer.readu32(Tmp, 12))
	end
end

local function Gctr(EncryptionProcessor: Processor, ICB: buffer, X: buffer, XLen: number, Y: buffer)
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

	for I = 0, N - 1 do
		EncryptionProcessor(CB, 0, Tmp, 0)

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
		EncryptionProcessor(CB, 0, Tmp, 0)
		for I = 0, Last - 1 do
			local XByte = buffer.readu8(X, XPos + I)
			local TmpByte = buffer.readu8(Tmp, I)
			buffer.writeu8(Y, YPos + I, bit32.bxor(XByte, TmpByte))
		end
	end
end

local function PrepareJ0(IV: buffer, IVLen: number, H: buffer, J0: buffer)
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

		Ghash(H, IV, IVLen, J0)

		local LenBuf = buffer.create(16)
		local IVLenBits = IVLen * 8

		buffer.writeu32(LenBuf, 0, 0) 
		buffer.writeu32(LenBuf, 4, 0)
		buffer.writeu32(LenBuf, 8, 0)
		buffer.writeu32(LenBuf, 12, IVLenBits)

		Ghash(H, LenBuf, 16, J0)
	end
end

local function GcmGctr(EncryptionProcessor: Processor, J0: buffer, Input: buffer, Len: number, Output: buffer)
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

	Gctr(EncryptionProcessor, J0Inc, Input, Len, Output)
end

local function GcmHash(H: buffer, AAD: buffer, AADLen: number, Crypt: buffer, CryptLen: number, S: buffer)
	local LenBuf = buffer.create(16)

	buffer.writeu32(S, 0, 0)
	buffer.writeu32(S, 4, 0)
	buffer.writeu32(S, 8, 0)
	buffer.writeu32(S, 12, 0)

	local M = math.floor(AADLen / 16)
	local XPos = 0
	local Tmp = buffer.create(16)

	for I = 0, M - 1 do
		buffer.writeu32(S, 0, bit32.bxor(buffer.readu32(S, 0), buffer.readu32(AAD, XPos)))
		buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), buffer.readu32(AAD, XPos + 4)))
		buffer.writeu32(S, 8, bit32.bxor(buffer.readu32(S, 8), buffer.readu32(AAD, XPos + 8)))
		buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), buffer.readu32(AAD, XPos + 12)))
		XPos += 16

		GfMult(S, H, Tmp)

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

		for I = 0, Last - 1 do
			buffer.writeu8(Tmp, I, buffer.readu8(AAD, XPos + I))
		end

		buffer.writeu32(S, 0, bit32.bxor(buffer.readu32(S, 0), buffer.readu32(Tmp, 0)))
		buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), buffer.readu32(Tmp, 4)))
		buffer.writeu32(S, 8, bit32.bxor(buffer.readu32(S, 8), buffer.readu32(Tmp, 8)))
		buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), buffer.readu32(Tmp, 12)))

		GfMult(S, H, Tmp)

		buffer.writeu32(S, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(S, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(S, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(S, 12, buffer.readu32(Tmp, 12))
	end

	M = math.floor(CryptLen / 16)
	XPos = 0

	for I = 0, M - 1 do
		buffer.writeu32(S, 0, bit32.bxor(buffer.readu32(S, 0), buffer.readu32(Crypt, XPos)))
		buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), buffer.readu32(Crypt, XPos + 4)))
		buffer.writeu32(S, 8, bit32.bxor(buffer.readu32(S, 8), buffer.readu32(Crypt, XPos + 8)))
		buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), buffer.readu32(Crypt, XPos + 12)))
		XPos += 16

		GfMult(S, H, Tmp)
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

		for I = 0, Last - 1 do
			buffer.writeu8(Tmp, I, buffer.readu8(Crypt, XPos + I))
		end

		buffer.writeu32(S, 0, bit32.bxor(buffer.readu32(S, 0), buffer.readu32(Tmp, 0)))
		buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), buffer.readu32(Tmp, 4)))
		buffer.writeu32(S, 8, bit32.bxor(buffer.readu32(S, 8), buffer.readu32(Tmp, 8)))
		buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), buffer.readu32(Tmp, 12)))

		GfMult(S, H, Tmp)

		buffer.writeu32(S, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(S, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(S, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(S, 12, buffer.readu32(Tmp, 12))
	end

	local AADLenBits = AADLen * 8
	local CryptLenBits = CryptLen * 8

	buffer.writeu32(LenBuf, 0, 0)
	buffer.writeu32(LenBuf, 4, bit32.byteswap(AADLenBits))

	buffer.writeu32(LenBuf, 8, 0)
	buffer.writeu32(LenBuf, 12, bit32.byteswap(CryptLenBits))

	M = 1
	XPos = 0

	for I = 0, M - 1 do
		buffer.writeu32(S, 0, bit32.bxor(buffer.readu32(S, 0), buffer.readu32(LenBuf, XPos)))
		buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), buffer.readu32(LenBuf, XPos + 4)))
		buffer.writeu32(S, 8, bit32.bxor(buffer.readu32(S, 8), buffer.readu32(LenBuf, XPos + 8)))
		buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), buffer.readu32(LenBuf, XPos + 12)))
		XPos += 16

		GfMult(S, H, Tmp)

		buffer.writeu32(S, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(S, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(S, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(S, 12, buffer.readu32(Tmp, 12))
	end
end

function AES.Encrypt(Key: buffer, IV: buffer, Plaintext: buffer, AAD: buffer?): (buffer, buffer)
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

	local RoundKeysBuffer = ExpandKeySchedule(Key, KeyLength, buffer.create(KEY_CONFIGS[KeyLength].ExpandedLength))
	local KeyMaterialLength = KEY_CONFIGS[KeyLength].MaterialLength

	local function EncryptionProcessor(PlaintextBlock: buffer, PlaintextOffset: number, OutputBuffer: buffer, OutputOffset: number)
		EncryptBlock(RoundKeysBuffer, KeyMaterialLength, PlaintextBlock, PlaintextOffset, OutputBuffer, OutputOffset)
	end

	local IVLen = buffer.len(IV)
	local AADLen = buffer.len(AAD or buffer.create(0))
	local PlainLen = buffer.len(Plaintext)
	local AuthData = AAD or buffer.create(0)

	local OutputBuffer = buffer.create(PlainLen)
	local OutputTag = buffer.create(16)

	local H = buffer.create(16)
	local J0 = buffer.create(16)
	local S = buffer.create(16)

	EncryptionProcessor(H, 0, H, 0)
	PrepareJ0(IV, IVLen, H, J0)
	GcmGctr(EncryptionProcessor, J0, Plaintext, PlainLen, OutputBuffer)
	GcmHash(H, AuthData, AADLen, OutputBuffer, PlainLen, S)
	Gctr(EncryptionProcessor, J0, S, 16, OutputTag)

	return OutputBuffer, OutputTag
end

function AES.Decrypt(Key: buffer, IV: buffer, Ciphertext: buffer, Tag: buffer, AAD: buffer?): (boolean, buffer?)
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

	local RoundKeysBuffer = ExpandKeySchedule(Key, KeyLength, buffer.create(KEY_CONFIGS[KeyLength].ExpandedLength))
	local KeyMaterialLength = KEY_CONFIGS[KeyLength].MaterialLength

	local function EncryptionProcessor(PlaintextBlock: buffer, PlaintextOffset: number, OutputBuffer: buffer, OutputOffset: number)
		EncryptBlock(RoundKeysBuffer, KeyMaterialLength, PlaintextBlock, PlaintextOffset, OutputBuffer, OutputOffset)
	end

	local IVLen = buffer.len(IV)
	local AADLen = buffer.len(AAD or buffer.create(0))
	local CryptLen = buffer.len(Ciphertext)
	local TagLength = buffer.len(Tag)
	local AuthData = AAD or buffer.create(0)

	local OutputBuffer = buffer.create(CryptLen)

	local H = buffer.create(16)
	local J0 = buffer.create(16)
	local S = buffer.create(16)
	local ComputedTag = buffer.create(16)

	EncryptionProcessor(H, 0, H, 0)
	PrepareJ0(IV, IVLen, H, J0)
	GcmGctr(EncryptionProcessor, J0, Ciphertext, CryptLen, OutputBuffer)
	GcmHash(H, AuthData, AADLen, Ciphertext, CryptLen, S)
	Gctr(EncryptionProcessor, J0, S, 16, ComputedTag)

	if not ConstantTimeEquals(Tag, ComputedTag, TagLength) then
		return false
	end

	return true, OutputBuffer
end

return AES