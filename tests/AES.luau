--!strict
local Testing = require("./")

type TestVector = {
	Description: string,
	Key: string,
	Input: string,
	Expected: string,
	IV: string,
	AAD: string?,
	Tag: string
}

local AES_GCM = require("../Encryption/AES")

local function HexToBuf(Hex: string): buffer
	local Length = #Hex
	local Buffer = buffer.create(Length / 2)
	for Index = 0, Length - 2, 2 do
		buffer.writeu8(Buffer, Index / 2, tonumber(string.sub(Hex, Index + 1, Index + 2), 16) :: number)
	end

	return Buffer
end

local function BufToHex(Buffer: buffer): string
	local Hex = ""
	for Index = 0, buffer.len(Buffer) - 1 do
		Hex ..= string.format("%02x", buffer.readu8(Buffer, Index))
	end

	return Hex
end

local TestVectors = {
	{
		Description = "AES-128 GCM Test Case 1 Empty plaintext and AAD (NIST SP 800-38D)",
		Key = "00000000000000000000000000000000",
		Input = "",
		Expected = "",
		IV = "000000000000000000000000",
		AAD = "",
		Tag = "58e2fccefa7e3061367f1d57a4e7455a"
	},
	{
		Description = "AES-128 GCM Test Case 2 Single block plaintext (NIST SP 800-38D)",
		Key = "00000000000000000000000000000000",
		Input = "00000000000000000000000000000000",
		Expected = "0388dace60b6a392f328c2b971b2fe78",
		IV = "000000000000000000000000",
		AAD = "",
		Tag = "ab6e47d42cec13bdf53a67b21257bddf"
	},
	{
		Description = "AES-128 GCM Test Case 3 (NIST SP 800-38D)",
		Key = "feffe9928665731c6d6a8f9467308308",
		Input = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
		Expected = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
		IV = "cafebabefacedbaddecaf888",
		AAD = "",
		Tag = "4d5c2af327cd64a62cf35abd2ba6fab4"
	},
	{
		Description = "AES-192 GCM Test Case 1 (NIST SP 800-38D)",
		Key = "000000000000000000000000000000000000000000000000",
		Input = "00000000000000000000000000000000",
		Expected = "98e7247c07f0fe411c267e4384b0f600",
		IV = "000000000000000000000000",
		AAD = "",
		Tag = "2ff58d80033927ab8ef4d4587514f0fb"
	},
	{
		Description = "AES-256 GCM Test Case 1 (NIST SP 800-38D)",
		Key = "0000000000000000000000000000000000000000000000000000000000000000",
		Input = "00000000000000000000000000000000",
		Expected = "cea7403d4d606b6e074ec5d3baf39d18",
		IV = "000000000000000000000000",
		AAD = "",
		Tag = "d0d1c8a799996bf0265b98b5d48ab919"
	},
	{
		Description = "AES-128 GCM Test Case 4 96-bit IV (NIST SP 800-38D)",
		Key = "feffe9928665731c6d6a8f9467308308",
		Input = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		Expected = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
		IV = "cafebabefacedbaddecaf888",
		AAD = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
		Tag = "5bc94fbc3221a5db94fae95ae7121a47"
	}
}

local function RunGCMTest(TestVector: TestVector)
	local KeyBuf = HexToBuf(TestVector.Key)
	local InputBuf = HexToBuf(TestVector.Input)
	local IVBuf = HexToBuf(TestVector.IV)
	local AADBuf = HexToBuf(TestVector.AAD or "")
	local ExpectedTagBuf = HexToBuf(TestVector.Tag)

	local Ciphertext, Tag = AES_GCM.Encrypt(KeyBuf, IVBuf, InputBuf, AADBuf)

	local CiphertextHex = BufToHex(Ciphertext)
	Testing.Expect(CiphertextHex).ToBe(TestVector.Expected)

	local TagHex = BufToHex(Tag)
	Testing.Expect(TagHex).ToBe(TestVector.Tag)

	local Success, Decrypted = AES_GCM.Decrypt(KeyBuf, IVBuf, Ciphertext, AADBuf, Tag)
	if not Success or not Decrypted then
		error("Decryption failed")
	end
	
	local DecryptedHex = BufToHex(Decrypted)
	Testing.Expect(DecryptedHex).ToBe(TestVector.Input)
end

Testing.Describe("AES-GCM Encryption Tests", function()
	for Index, TestVector in TestVectors do
		Testing.Test(TestVector.Description, function()
			RunGCMTest(TestVector)
		end)
	end

	Testing.Test("GCM Authentication Failure Test", function()
		local KeyBuf = HexToBuf("feffe9928665731c6d6a8f9467308308")
		local InputBuf = HexToBuf("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
		local IVBuf = HexToBuf("cafebabefacedbaddecaf888")
		local AADBuf = HexToBuf("feedfacedeadbeeffeedfacedeadbeefabaddad2")
		local WrongTag = HexToBuf("00000000000000000000000000000000")

		local Ciphertext, CorrectTag = AES_GCM.Encrypt(KeyBuf, IVBuf, InputBuf, AADBuf)

		local Succes = AES_GCM.Decrypt(KeyBuf, IVBuf, Ciphertext, AADBuf, WrongTag)
		Testing.Expect(Succes).ToBe(false)
	end)

	Testing.Test("Invalid Key Size Test", function()
		local InvalidKeyBuf = HexToBuf("2b7e151628aed2a6abf7158809cf4f")
		local IVBuf = HexToBuf("000000000000000000000000")
		local InputBuf = HexToBuf("00000000000000000000000000000000")

		Testing.Expect(function()
			AES_GCM.Encrypt(InvalidKeyBuf, IVBuf, InputBuf)
		end).ToThrow("Key must be 16, 24, or 32 bytes")
	end)

	Testing.Test("Missing buffer Params Test", function()
		Testing.Expect(function()
			local N = nil
			AES_GCM.Encrypt(N, N, N)
		end).ToThrow("Key must be a buffer")
	end)
end)

Testing.Complete()

return 0
