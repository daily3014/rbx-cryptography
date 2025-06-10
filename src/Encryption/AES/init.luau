--[=[
	Cryptography library: AES
	
	Sizes:
		Init Vector: 16 bytes
		Key Size: 16 / 24 / 32 bytes
	
	Example usage:
		local Cipher = AES.New("your-32-byte-key-here-for-aes256", AES.Modes.CBC, AES.Pads.Pkcs7)
		
		-- Encrypt data
		local Plaintext = buffer.fromstring("Hello, World!")
		local IV = buffer.fromstring("0123456789ABCDEF")
		local Encrypted = Cipher:Encrypt(Plaintext, nil, IV)
		
		-- Decrypt data
		local Decrypted = Cipher:Decrypt(Encrypted, nil, IV)
--]=]

--!native
--!optimize 2
--!strict 

local CipherModes = require(script.Modes)
local PaddingSchemes = require(script.Pads)

local SBOX_16BIT = buffer.create(131072)   -- 16-bit S-box lookup
local SMIX_TABLE0 = buffer.create(65536)   -- 2*S(b0) ^ 3*S(b1)  
local SMIX_TABLE1 = buffer.create(65536)   -- S(b0) ^ S(b1)
local INVS_XOR_TABLE = buffer.create(65536) -- InvS(b0 ^ b1)
local INVMIX_TABLE0 = buffer.create(65536)  -- 14*b0 ^ 11*b1
local INVMIX_TABLE1 = buffer.create(65536)  -- 13*b0 ^ 9*b1

do
	local SubstitutionBox = buffer.create(256)
	local InverseSubstitutionBox = buffer.create(256)
	local GaloisMultiply3 = buffer.create(256)
	local GaloisMultiply9 = buffer.create(256)
	local GaloisMultiply11 = buffer.create(256)

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
	buffer.writeu8(SubstitutionBox, 0, 99)

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
		buffer.writeu8(SubstitutionBox, PolynomialP, TempValue)
		buffer.writeu8(InverseSubstitutionBox, TempValue, PolynomialP)
		buffer.writeu8(GaloisMultiply3, PolynomialP, GaloisFieldMultiply(3, PolynomialP))
		buffer.writeu8(GaloisMultiply9, PolynomialP, GaloisFieldMultiply(9, PolynomialP))
		buffer.writeu8(GaloisMultiply11, PolynomialP, GaloisFieldMultiply(11, PolynomialP))
	end

	local TableIndex = 0
	for OuterIndex = 0, 255 do
		local PolynomialP = buffer.readu8(SubstitutionBox, OuterIndex)
		local PolynomialPBytes = PolynomialP * 256
		local Galois2 = GaloisFieldMultiply(2, PolynomialP)
		local Galois13 = GaloisFieldMultiply(13, OuterIndex)
		local Galois14 = GaloisFieldMultiply(14, OuterIndex)

		for InnerIndex = 0, 255 do
			local PolynomialQ = buffer.readu8(SubstitutionBox, InnerIndex)

			buffer.writeu16(SBOX_16BIT, TableIndex * 2, PolynomialPBytes + PolynomialQ)
			buffer.writeu8(INVS_XOR_TABLE, TableIndex, buffer.readu8(InverseSubstitutionBox, bit32.bxor(OuterIndex, InnerIndex)))
			buffer.writeu8(SMIX_TABLE0, TableIndex, bit32.bxor(Galois2, buffer.readu8(GaloisMultiply3, PolynomialQ)))
			buffer.writeu8(SMIX_TABLE1, TableIndex, bit32.bxor(PolynomialP, PolynomialQ))
			buffer.writeu8(INVMIX_TABLE0, TableIndex, bit32.bxor(Galois14, buffer.readu8(GaloisMultiply11, InnerIndex)))
			buffer.writeu8(INVMIX_TABLE1, TableIndex, bit32.bxor(Galois13, buffer.readu8(GaloisMultiply9, InnerIndex)))
			TableIndex += 1
		end
	end
end

local function ExpandKeySchedule(Key: buffer | string, KeyLength: number, OutputBuffer: buffer, IsRawBuffer: boolean): buffer
	if IsRawBuffer then
		buffer.copy(OutputBuffer, 0, Key :: buffer, 0, KeyLength)
	else
		buffer.writestring(OutputBuffer, 0, Key :: string, KeyLength)
	end

	local Word = bit32.rrotate(buffer.readu32(OutputBuffer, KeyLength - 4), 8)
	local RoundConstant = 0.5

	if KeyLength == 32 then
		for KeyOffset = 32, 192, 32 do
			RoundConstant = RoundConstant * 2 % 229
			Word = bit32.bxor(
				buffer.readu32(OutputBuffer, KeyOffset - 32),
				buffer.readu16(SBOX_16BIT, math.floor(Word / 65536) * 2) * 65536 + buffer.readu16(SBOX_16BIT, Word % 65536 * 2),
				RoundConstant
			)
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 28), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, Word)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 24), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, Word)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 20), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, Word)

			Word = bit32.bxor(
				buffer.readu32(OutputBuffer, KeyOffset - 16),
				buffer.readu16(SBOX_16BIT, math.floor(Word / 65536) * 2) * 65536 + buffer.readu16(SBOX_16BIT, Word % 65536 * 2)
			)
			buffer.writeu32(OutputBuffer, KeyOffset + 16, Word)

			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 20, Word)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 24, Word)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 28, Word)
			Word = bit32.rrotate(Word, 8)
		end

		Word = bit32.bxor(
			buffer.readu32(OutputBuffer, 192),
			buffer.readu16(SBOX_16BIT, math.floor(Word / 65536) * 2) * 65536 + buffer.readu16(SBOX_16BIT, Word % 65536 * 2),
			64
		)
		buffer.writeu32(OutputBuffer, 224, Word)

		Word = bit32.bxor(buffer.readu32(OutputBuffer, 196), Word)
		buffer.writeu32(OutputBuffer, 228, Word)
		Word = bit32.bxor(buffer.readu32(OutputBuffer, 200), Word)
		buffer.writeu32(OutputBuffer, 232, Word)
		buffer.writeu32(OutputBuffer, 236, bit32.bxor(buffer.readu32(OutputBuffer, 204), Word))

	elseif KeyLength == 24 then
		for KeyOffset = 24, 168, 24 do
			RoundConstant = RoundConstant * 2 % 229
			Word = bit32.bxor(
				buffer.readu32(OutputBuffer, KeyOffset - 24),
				buffer.readu16(SBOX_16BIT, math.floor(Word / 65536) * 2) * 65536 + buffer.readu16(SBOX_16BIT, Word % 65536 * 2),
				RoundConstant
			)
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 20), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, Word)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 16), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, Word)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, Word)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 16, Word)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 20, Word)
			Word = bit32.rrotate(Word, 8)
		end

		Word = bit32.bxor(
			buffer.readu32(OutputBuffer, 168),
			buffer.readu16(SBOX_16BIT, math.floor(Word / 65536) * 2) * 65536 + buffer.readu16(SBOX_16BIT, Word % 65536 * 2),
			128
		)
		buffer.writeu32(OutputBuffer, 192, Word)

		Word = bit32.bxor(buffer.readu32(OutputBuffer, 172), Word)
		buffer.writeu32(OutputBuffer, 196, Word)
		Word = bit32.bxor(buffer.readu32(OutputBuffer, 176), Word)
		buffer.writeu32(OutputBuffer, 200, Word)
		buffer.writeu32(OutputBuffer, 204, bit32.bxor(buffer.readu32(OutputBuffer, 180), Word))

	else
		for KeyOffset = 16, 144, 16 do
			RoundConstant = RoundConstant * 2 % 229
			Word = bit32.bxor(
				buffer.readu32(OutputBuffer, KeyOffset - 16),
				buffer.readu16(SBOX_16BIT, math.floor(Word / 65536) * 2) * 65536 + buffer.readu16(SBOX_16BIT, Word % 65536 * 2),
				RoundConstant
			)
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, Word)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, Word)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, Word)
			Word = bit32.rrotate(Word, 8)
		end

		Word = bit32.bxor(
			buffer.readu32(OutputBuffer, 144),
			buffer.readu16(SBOX_16BIT, math.floor(Word / 65536) * 2) * 65536 + buffer.readu16(SBOX_16BIT, Word % 65536 * 2),
			54
		)
		buffer.writeu32(OutputBuffer, 160, Word)

		Word = bit32.bxor(buffer.readu32(OutputBuffer, 148), Word)
		buffer.writeu32(OutputBuffer, 164, Word)
		Word = bit32.bxor(buffer.readu32(OutputBuffer, 152), Word)
		buffer.writeu32(OutputBuffer, 168, Word)
		buffer.writeu32(OutputBuffer, 172, bit32.bxor(buffer.readu32(OutputBuffer, 156), Word))
	end

	return OutputBuffer
end

local function EncryptBlock(RoundKeys: buffer, MaterialLength: number, Plaintext: buffer, PlaintextOffset: number, Output: buffer, OutputOffset: number)
	local B0 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset), buffer.readu8(RoundKeys, 0))
	
	local B1 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 1), buffer.readu8(RoundKeys, 1))
	local B2 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 2), buffer.readu8(RoundKeys, 2))
	local B3 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 3), buffer.readu8(RoundKeys, 3))
	local B4 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 4), buffer.readu8(RoundKeys, 4))
	local B5 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 5), buffer.readu8(RoundKeys, 5))
	local B6 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 6), buffer.readu8(RoundKeys, 6))
	local B7 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 7), buffer.readu8(RoundKeys, 7))
	local B8 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 8), buffer.readu8(RoundKeys, 8))
	local B9 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 9), buffer.readu8(RoundKeys, 9))
	
	local B10 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 10), buffer.readu8(RoundKeys, 10))
	local B11 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 11), buffer.readu8(RoundKeys, 11))
	local B12 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 12), buffer.readu8(RoundKeys, 12))
	local B13 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 13), buffer.readu8(RoundKeys, 13))
	local B14 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 14), buffer.readu8(RoundKeys, 14))
	local B15 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 15), buffer.readu8(RoundKeys, 15))

	local I0 = B0 * 256 + B5; local I1 = B5 * 256 + B10; local I2 = B10 * 256 + B15; local I3 = B15 * 256 + B0
	local I4 = B4 * 256 + B9; local I5 = B9 * 256 + B14; local I6 = B14 * 256 + B3; local I7 = B3 * 256 + B4
	local I8 = B8 * 256 + B13; local I9 = B13 * 256 + B2; local I10 = B2 * 256 + B7; local I11 = B7 * 256 + B8
	local I12 = B12 * 256 + B1; local I13 = B1 * 256 + B6; local I14 = B6 * 256 + B11; local I15 = B11 * 256 + B12

	for RoundOffset = 16, MaterialLength, 16 do
		B0 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I0), buffer.readu8(SMIX_TABLE1, I2), buffer.readu8(RoundKeys, RoundOffset))
		B1 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I1), buffer.readu8(SMIX_TABLE1, I3), buffer.readu8(RoundKeys, RoundOffset + 1))
		B2 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I2), buffer.readu8(SMIX_TABLE1, I0), buffer.readu8(RoundKeys, RoundOffset + 2))
		B3 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I3), buffer.readu8(SMIX_TABLE1, I1), buffer.readu8(RoundKeys, RoundOffset + 3))
		B4 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I4), buffer.readu8(SMIX_TABLE1, I6), buffer.readu8(RoundKeys, RoundOffset + 4))
		B5 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I5), buffer.readu8(SMIX_TABLE1, I7), buffer.readu8(RoundKeys, RoundOffset + 5))
		B6 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I6), buffer.readu8(SMIX_TABLE1, I4), buffer.readu8(RoundKeys, RoundOffset + 6))
		B7 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I7), buffer.readu8(SMIX_TABLE1, I5), buffer.readu8(RoundKeys, RoundOffset + 7))
		
		B8 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I8), buffer.readu8(SMIX_TABLE1, I10), buffer.readu8(RoundKeys, RoundOffset + 8))
		B9 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I9), buffer.readu8(SMIX_TABLE1, I11), buffer.readu8(RoundKeys, RoundOffset + 9))
		
		B10 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I10), buffer.readu8(SMIX_TABLE1, I8), buffer.readu8(RoundKeys, RoundOffset + 10))
		B11 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I11), buffer.readu8(SMIX_TABLE1, I9), buffer.readu8(RoundKeys, RoundOffset + 11))
		
		B12 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I12), buffer.readu8(SMIX_TABLE1, I14), buffer.readu8(RoundKeys, RoundOffset + 12))
		B13 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I13), buffer.readu8(SMIX_TABLE1, I15), buffer.readu8(RoundKeys, RoundOffset + 13))
		B14 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I14), buffer.readu8(SMIX_TABLE1, I12), buffer.readu8(RoundKeys, RoundOffset + 14))
		B15 = bit32.bxor(buffer.readu8(SMIX_TABLE0, I15), buffer.readu8(SMIX_TABLE1, I13), buffer.readu8(RoundKeys, RoundOffset + 15))

		I0, I1, I2, I3 = B0 * 256 + B5, B5 * 256 + B10, B10 * 256 + B15, B15 * 256 + B0
		I4, I5, I6, I7 = B4 * 256 + B9, B9 * 256 + B14, B14 * 256 + B3, B3 * 256 + B4
		I8, I9, I10, I11 = B8 * 256 + B13, B13 * 256 + B2, B2 * 256 + B7, B7 * 256 + B8
		I12, I13, I14, I15 = B12 * 256 + B1, B1 * 256 + B6, B6 * 256 + B11, B11 * 256 + B12
	end

	buffer.writeu32(Output, OutputOffset, bit32.bxor(
		buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(SMIX_TABLE0, I15), buffer.readu8(SMIX_TABLE1, I13), buffer.readu8(RoundKeys, MaterialLength + 31)) * 512 + 
			bit32.bxor(buffer.readu8(SMIX_TABLE0, I10), buffer.readu8(SMIX_TABLE1, I8), buffer.readu8(RoundKeys, MaterialLength + 26)) * 2) * 65536 + 
			buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(SMIX_TABLE0, I5), buffer.readu8(SMIX_TABLE1, I7), buffer.readu8(RoundKeys, MaterialLength + 21)) * 512 + 
				bit32.bxor(buffer.readu8(SMIX_TABLE0, I0), buffer.readu8(SMIX_TABLE1, I2), buffer.readu8(RoundKeys, MaterialLength + 16)) * 2),
		buffer.readu32(RoundKeys, MaterialLength + 32)
		))

	buffer.writeu32(Output, OutputOffset + 4, bit32.bxor(
		buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(SMIX_TABLE0, I3), buffer.readu8(SMIX_TABLE1, I1), buffer.readu8(RoundKeys, MaterialLength + 19)) * 512 + 
			bit32.bxor(buffer.readu8(SMIX_TABLE0, I14), buffer.readu8(SMIX_TABLE1, I12), buffer.readu8(RoundKeys, MaterialLength + 30)) * 2) * 65536 + 
			buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(SMIX_TABLE0, I9), buffer.readu8(SMIX_TABLE1, I11), buffer.readu8(RoundKeys, MaterialLength + 25)) * 512 + 
				bit32.bxor(buffer.readu8(SMIX_TABLE0, I4), buffer.readu8(SMIX_TABLE1, I6), buffer.readu8(RoundKeys, MaterialLength + 20)) * 2),
		buffer.readu32(RoundKeys, MaterialLength + 36)
		))

	buffer.writeu32(Output, OutputOffset + 8, bit32.bxor(
		buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(SMIX_TABLE0, I7), buffer.readu8(SMIX_TABLE1, I5), buffer.readu8(RoundKeys, MaterialLength + 23)) * 512 + 
			bit32.bxor(buffer.readu8(SMIX_TABLE0, I2), buffer.readu8(SMIX_TABLE1, I0), buffer.readu8(RoundKeys, MaterialLength + 18)) * 2) * 65536 + 
			buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(SMIX_TABLE0, I13), buffer.readu8(SMIX_TABLE1, I15), buffer.readu8(RoundKeys, MaterialLength + 29)) * 512 + 
				bit32.bxor(buffer.readu8(SMIX_TABLE0, I8), buffer.readu8(SMIX_TABLE1, I10), buffer.readu8(RoundKeys, MaterialLength + 24)) * 2),
		buffer.readu32(RoundKeys, MaterialLength + 40)
		))

	buffer.writeu32(Output, OutputOffset + 12, bit32.bxor(
		buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(SMIX_TABLE0, I11), buffer.readu8(SMIX_TABLE1, I9), buffer.readu8(RoundKeys, MaterialLength + 27)) * 512 + 
			bit32.bxor(buffer.readu8(SMIX_TABLE0, I6), buffer.readu8(SMIX_TABLE1, I4), buffer.readu8(RoundKeys, MaterialLength + 22)) * 2) * 65536 + 
			buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(SMIX_TABLE0, I1), buffer.readu8(SMIX_TABLE1, I3), buffer.readu8(RoundKeys, MaterialLength + 17)) * 512 + 
				bit32.bxor(buffer.readu8(SMIX_TABLE0, I12), buffer.readu8(SMIX_TABLE1, I14), buffer.readu8(RoundKeys, MaterialLength + 28)) * 2),
		buffer.readu32(RoundKeys, MaterialLength + 44)
		))
end

local function DecryptBlock(RoundKeys: buffer, MaterialLength: number, Ciphertext: buffer, CiphertextOffset: number, Output: buffer, OutputOffset: number)
	local B0 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset) * 256 + buffer.readu8(RoundKeys, MaterialLength + 32)), buffer.readu8(RoundKeys, MaterialLength + 16))
	local B1 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 13) * 256 + buffer.readu8(RoundKeys, MaterialLength + 45)), buffer.readu8(RoundKeys, MaterialLength + 17))
	local B2 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 10) * 256 + buffer.readu8(RoundKeys, MaterialLength + 42)), buffer.readu8(RoundKeys, MaterialLength + 18))
	
	local B3 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 7) * 256 + buffer.readu8(RoundKeys, MaterialLength + 39)), buffer.readu8(RoundKeys, MaterialLength + 19))
	local B4 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 4) * 256 + buffer.readu8(RoundKeys, MaterialLength + 36)), buffer.readu8(RoundKeys, MaterialLength + 20))
	local B5 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 1) * 256 + buffer.readu8(RoundKeys, MaterialLength + 33)), buffer.readu8(RoundKeys, MaterialLength + 21))
	
	local B6 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 14) * 256 + buffer.readu8(RoundKeys, MaterialLength + 46)), buffer.readu8(RoundKeys, MaterialLength + 22))
	local B7 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 11) * 256 + buffer.readu8(RoundKeys, MaterialLength + 43)), buffer.readu8(RoundKeys, MaterialLength + 23))
	
	local B8 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 8) * 256 + buffer.readu8(RoundKeys, MaterialLength + 40)), buffer.readu8(RoundKeys, MaterialLength + 24))
	local B9 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 5) * 256 + buffer.readu8(RoundKeys, MaterialLength + 37)), buffer.readu8(RoundKeys, MaterialLength + 25))
	
	local B10 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 2) * 256 + buffer.readu8(RoundKeys, MaterialLength + 34)), buffer.readu8(RoundKeys, MaterialLength + 26))
	local B11 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 15) * 256 + buffer.readu8(RoundKeys, MaterialLength + 47)), buffer.readu8(RoundKeys, MaterialLength + 27))
	local B12 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 12) * 256 + buffer.readu8(RoundKeys, MaterialLength + 44)), buffer.readu8(RoundKeys, MaterialLength + 28))
	
	local B13 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 9) * 256 + buffer.readu8(RoundKeys, MaterialLength + 41)), buffer.readu8(RoundKeys, MaterialLength + 29))
	local B14 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 6) * 256 + buffer.readu8(RoundKeys, MaterialLength + 38)), buffer.readu8(RoundKeys, MaterialLength + 30))
	local B15 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(Ciphertext, CiphertextOffset + 3) * 256 + buffer.readu8(RoundKeys, MaterialLength + 35)), buffer.readu8(RoundKeys, MaterialLength + 31))

	local I0 = B0 * 256 + B1; local I1 = B1 * 256 + B2; local I2 = B2 * 256 + B3; local I3 = B3 * 256 + B0
	local I4 = B4 * 256 + B5; local I5 = B5 * 256 + B6; local I6 = B6 * 256 + B7; local I7 = B7 * 256 + B4
	local I8 = B8 * 256 + B9; local I9 = B9 * 256 + B10; local I10 = B10 * 256 + B11; local I11 = B11 * 256 + B8
	local I12 = B12 * 256 + B13; local I13 = B13 * 256 + B14; local I14 = B14 * 256 + B15; local I15 = B15 * 256 + B12

	for RoundOffset = MaterialLength, 16, -16 do
		B0 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I0) * 256 + buffer.readu8(INVMIX_TABLE1, I2)), buffer.readu8(RoundKeys, RoundOffset))
		B1 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I13) * 256 + buffer.readu8(INVMIX_TABLE1, I15)), buffer.readu8(RoundKeys, RoundOffset + 1))
		B2 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I10) * 256 + buffer.readu8(INVMIX_TABLE1, I8)), buffer.readu8(RoundKeys, RoundOffset + 2))
		
		B3 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I7) * 256 + buffer.readu8(INVMIX_TABLE1, I5)), buffer.readu8(RoundKeys, RoundOffset + 3))
		B4 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I4) * 256 + buffer.readu8(INVMIX_TABLE1, I6)), buffer.readu8(RoundKeys, RoundOffset + 4))
		B5 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I1) * 256 + buffer.readu8(INVMIX_TABLE1, I3)), buffer.readu8(RoundKeys, RoundOffset + 5))
		
		B6 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I14) * 256 + buffer.readu8(INVMIX_TABLE1, I12)), buffer.readu8(RoundKeys, RoundOffset + 6))
		
		B7 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I11) * 256 + buffer.readu8(INVMIX_TABLE1, I9)), buffer.readu8(RoundKeys, RoundOffset + 7))
		B8 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I8) * 256 + buffer.readu8(INVMIX_TABLE1, I10)), buffer.readu8(RoundKeys, RoundOffset + 8))
		
		B9 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I5) * 256 + buffer.readu8(INVMIX_TABLE1, I7)), buffer.readu8(RoundKeys, RoundOffset + 9))
		B10 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I2) * 256 + buffer.readu8(INVMIX_TABLE1, I0)), buffer.readu8(RoundKeys, RoundOffset + 10))
		
		B11 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I15) * 256 + buffer.readu8(INVMIX_TABLE1, I13)), buffer.readu8(RoundKeys, RoundOffset + 11))
		B12 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I12) * 256 + buffer.readu8(INVMIX_TABLE1, I14)), buffer.readu8(RoundKeys, RoundOffset + 12))
		
		B13 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I9) * 256 + buffer.readu8(INVMIX_TABLE1, I11)), buffer.readu8(RoundKeys, RoundOffset + 13))
		B14 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I6) * 256 + buffer.readu8(INVMIX_TABLE1, I4)), buffer.readu8(RoundKeys, RoundOffset + 14))
		B15 = bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I3) * 256 + buffer.readu8(INVMIX_TABLE1, I1)), buffer.readu8(RoundKeys, RoundOffset + 15))

		I0, I1, I2, I3 = B0 * 256 + B1, B1 * 256 + B2, B2 * 256 + B3, B3 * 256 + B0
		I4, I5, I6, I7 = B4 * 256 + B5, B5 * 256 + B6, B6 * 256 + B7, B7 * 256 + B4
		I8, I9, I10, I11 = B8 * 256 + B9, B9 * 256 + B10, B10 * 256 + B11, B11 * 256 + B8
		I12, I13, I14, I15 = B12 * 256 + B13, B13 * 256 + B14, B14 * 256 + B15, B15 * 256 + B12
	end

	buffer.writeu32(Output, OutputOffset, 
		bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I7) * 256 + buffer.readu8(INVMIX_TABLE1, I5)), buffer.readu8(RoundKeys, 3)) * 16777216 + 
			bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I10) * 256 + buffer.readu8(INVMIX_TABLE1, I8)), buffer.readu8(RoundKeys, 2)) * 65536 + 
			bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I13) * 256 + buffer.readu8(INVMIX_TABLE1, I15)), buffer.readu8(RoundKeys, 1)) * 256 + 
			bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I0) * 256 + buffer.readu8(INVMIX_TABLE1, I2)), buffer.readu8(RoundKeys, 0))
	)

	buffer.writeu32(Output, OutputOffset + 4, 
		bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I11) * 256 + buffer.readu8(INVMIX_TABLE1, I9)), buffer.readu8(RoundKeys, 7)) * 16777216 + 
			bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I14) * 256 + buffer.readu8(INVMIX_TABLE1, I12)), buffer.readu8(RoundKeys, 6)) * 65536 + 
			bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I1) * 256 + buffer.readu8(INVMIX_TABLE1, I3)), buffer.readu8(RoundKeys, 5)) * 256 + 
			bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I4) * 256 + buffer.readu8(INVMIX_TABLE1, I6)), buffer.readu8(RoundKeys, 4))
	)

	buffer.writeu32(Output, OutputOffset + 8, 
		bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I15) * 256 + buffer.readu8(INVMIX_TABLE1, I13)), buffer.readu8(RoundKeys, 11)) * 16777216 + 
			bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I2) * 256 + buffer.readu8(INVMIX_TABLE1, I0)), buffer.readu8(RoundKeys, 10)) * 65536 + 
			bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I5) * 256 + buffer.readu8(INVMIX_TABLE1, I7)), buffer.readu8(RoundKeys, 9)) * 256 + 
			bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I8) * 256 + buffer.readu8(INVMIX_TABLE1, I10)), buffer.readu8(RoundKeys, 8))
	)

	buffer.writeu32(Output, OutputOffset + 12, 
		bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I3) * 256 + buffer.readu8(INVMIX_TABLE1, I1)), buffer.readu8(RoundKeys, 15)) * 16777216 + 
			bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I6) * 256 + buffer.readu8(INVMIX_TABLE1, I4)), buffer.readu8(RoundKeys, 14)) * 65536 + 
			bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I9) * 256 + buffer.readu8(INVMIX_TABLE1, I11)), buffer.readu8(RoundKeys, 13)) * 256 + 
			bit32.bxor(buffer.readu8(INVS_XOR_TABLE, buffer.readu8(INVMIX_TABLE0, I12) * 256 + buffer.readu8(INVMIX_TABLE1, I14)), buffer.readu8(RoundKeys, 12))
	)
end



export type KeyLength = { ExpandedLength: number, MaterialLength: number }

export type Struct = {
	Key: string,
	RoundKeys: string,
	Length: number,
	Mode: CipherModes.SimpleModeStruct,
	Padding: PaddingSchemes.Struct,
	RoundKeysBuffer: buffer,
	KeyMaterialLength: number,
	SegmentSize: number
}

export type Impl = {
	__index: Impl,
	
	New: (MasterKey: buffer, OperationMode: CipherModes.SimpleModeStruct, PaddingScheme: PaddingSchemes.Struct) -> AesCipher,
	FromKey: (RoundKeysBuffer: buffer, OperationMode: CipherModes.SimpleModeStruct, PaddingScheme: PaddingSchemes.Struct) -> AesCipher,
	ValidateKeySize: (self: any, KeyLength: number) -> KeyLength,
	CreateBufferFromInput: (self: any, Input: buffer | string) -> buffer,
	
	ExpandMasterKey: (self: AesCipher, MasterKey: buffer | string, OutputBuffer: buffer?) -> buffer,
	Encrypt: (self: AesCipher, Plaintext: buffer, Output: buffer?, InitVector: buffer?, ...any) -> buffer,
	Decrypt: (self: AesCipher, Plaintext: buffer, Output: buffer?, InitVector: buffer?, ...any) -> buffer,
	EncryptBlock: (self: AesCipher, Plaintext: buffer, Offset: number, Output: buffer?, OutputOffset: number?) -> (),
	DecryptBlock: (self: AesCipher, Ciphertext: buffer, Offset: number, Output: buffer?, OutputOffset: number?) -> (),
	ExpandKey: (self: AesCipher, MasterKey: buffer, OutputBuffer: buffer?) -> buffer,
	
	Destroy: (self: AesCipher) -> ()
}

export type AesCipher = typeof(setmetatable({} :: Struct, {} :: Impl))

local AesCipher = {}
AesCipher.__index = AesCipher

function AesCipher:ValidateKeySize(KeyLength)
	local KeyConfigurations = {
		[16] = {ExpandedLength = 176, MaterialLength = 128},
		[24] = {ExpandedLength = 208, MaterialLength = 160},
		[32] = {ExpandedLength = 240, MaterialLength = 192}
	}
	
	return KeyConfigurations[KeyLength]
end

function AesCipher:ValidateRoundKeySize(RoundKeysLength)
	local RoundKeyConfigurations = {
		[176] = {MaterialLength = 128, OriginalKeyLength = 16},
		[208] = {MaterialLength = 160, OriginalKeyLength = 24},
		[240] = {MaterialLength = 192, OriginalKeyLength = 32}
	}
	
	return RoundKeyConfigurations[RoundKeysLength]
end

function AesCipher:CreateBufferFromInput(Input: buffer | string): buffer
	if typeof(Input) == "buffer" then
		return Input
	elseif typeof(Input) == "string" then
		return buffer.fromstring(Input)
	end
	
	return buffer.create(0)
end

function AesCipher:ExpandMasterKey(MasterKey: buffer | string, OutputBuffer: buffer?): buffer
	local KeyLength = if typeof(MasterKey) == "buffer" then buffer.len(MasterKey) else #MasterKey
	local KeyConfig = self:ValidateKeySize(KeyLength)
	return ExpandKeySchedule(MasterKey, KeyLength, OutputBuffer or buffer.create(KeyConfig.ExpandedLength), typeof(MasterKey) == "buffer")
end

function AesCipher.New(MasterKey: buffer | string, OperationMode: CipherModes.SimpleModeStruct, PaddingScheme: PaddingSchemes.Struct): AesCipher
	local self = setmetatable({}, AesCipher)

	local RoundKeysBuffer = self:ExpandMasterKey(MasterKey)
	local RoundKeysLength = buffer.len(RoundKeysBuffer)
	local KeyConfig = self:ValidateRoundKeySize(RoundKeysLength)

	self.Key = string.sub(buffer.tostring(RoundKeysBuffer), 1, KeyConfig.OriginalKeyLength)
	self.RoundKeys = buffer.tostring(RoundKeysBuffer)
	self.Length = RoundKeysLength
	self.Mode = OperationMode or CipherModes.ECB
	self.Padding = PaddingScheme or PaddingSchemes.Pkcs7
	self.RoundKeysBuffer = RoundKeysBuffer
	self.KeyMaterialLength = KeyConfig.MaterialLength
	self.SegmentSize = (self.Mode :: CipherModes.SimpleModeStruct2).SegmentSize or 16

	return (self :: any) :: AesCipher
end

function AesCipher:FromKey(RoundKeysBuffer: buffer, OperationMode: CipherModes.SimpleModeStruct, PaddingScheme: PaddingSchemes.Struct): AesCipher
	local self = setmetatable({}, AesCipher)

	local RoundKeysLength = buffer.len(RoundKeysBuffer)
	local KeyConfig = self:ValidateRoundKeySize(RoundKeysLength)

	self.Key = string.sub(buffer.tostring(RoundKeysBuffer), 1, KeyConfig.OriginalKeyLength)
	self.RoundKeys = buffer.tostring(RoundKeysBuffer)
	self.Length = RoundKeysLength
	self.Mode = OperationMode or CipherModes.ECB
	self.Padding = PaddingScheme or PaddingSchemes.Pkcs7
	self.RoundKeysBuffer = RoundKeysBuffer
	self.KeyMaterialLength = KeyConfig.MaterialLength
	self.SegmentSize = (self.Mode :: CipherModes.SimpleModeStruct2).SegmentSize or 16

	return (self :: any) :: AesCipher
end

function AesCipher:Encrypt(Plaintext: buffer, Output: buffer?, ...): buffer
	local InputBuffer = self:CreateBufferFromInput(Plaintext)
	local ValidOutput = typeof(Output) == "buffer" and Output or nil
	local Padded = self.Padding.Pad(InputBuffer, ValidOutput, self.SegmentSize)

	self.Mode.ForwardMode(function(PlaintextBlock, PlaintextOffset, OutputBuffer, OutputOffset)
		EncryptBlock(self.RoundKeysBuffer, self.KeyMaterialLength, PlaintextBlock, PlaintextOffset, OutputBuffer, OutputOffset)
	end, function(CiphertextBlock, CiphertextOffset, OutputBuffer, OutputOffset)
		DecryptBlock(self.RoundKeysBuffer, self.KeyMaterialLength, CiphertextBlock, CiphertextOffset, OutputBuffer, OutputOffset)
	end, self.Padding.Overwrite == false and InputBuffer or Padded, Padded, self.Mode, ...)

	return Padded
end

function AesCipher:Decrypt(Ciphertext: buffer, Output: buffer?, ...): buffer
	local CipherBuffer = self:CreateBufferFromInput(Ciphertext)
	local ValidOutput = typeof(Output) == "buffer" and Output or nil
	local Overwrite = self.Padding.Overwrite
	local OutputBuffer = Overwrite == nil and buffer.create(buffer.len(CipherBuffer))
		or Overwrite and CipherBuffer
		or ValidOutput or buffer.create(buffer.len(CipherBuffer))

	self.Mode.InverseMode(function(PlaintextBlock, PlaintextOffset, OutputBuffer, OutputOffset)
		EncryptBlock(self.RoundKeysBuffer, self.KeyMaterialLength, PlaintextBlock, PlaintextOffset, OutputBuffer, OutputOffset)
	end, function(CiphertextBlock, CiphertextOffset, OutputBuffer, OutputOffset)
		DecryptBlock(self.RoundKeysBuffer, self.KeyMaterialLength, CiphertextBlock, CiphertextOffset, OutputBuffer, OutputOffset)
	end, CipherBuffer, OutputBuffer, self.Mode, ...)

	return self.Padding.Unpad(OutputBuffer, ValidOutput, self.SegmentSize)
end

function AesCipher:EncryptBlock(Plaintext: buffer, Offset: number, Output: buffer?, OutputOffset: number)
	EncryptBlock(self.RoundKeysBuffer, self.KeyMaterialLength, Plaintext, Offset, Output or Plaintext, OutputOffset or Offset)
end

function AesCipher:DecryptBlock(Ciphertext: buffer, Offset: number, Output: buffer?, OutputOffset: number)
	DecryptBlock(self.RoundKeysBuffer, self.KeyMaterialLength, Ciphertext, Offset, Output or Ciphertext, OutputOffset or Offset)
end

function AesCipher:ExpandKey(MasterKey: buffer, OutputBuffer: buffer?): buffer
	return self:ExpandMasterKey(MasterKey, OutputBuffer)
end

function AesCipher:Destroy()
	setmetatable(self, nil)
end

return table.freeze({
	New = AesCipher.New,
	Modes = CipherModes,
	Pads = PaddingSchemes
})