--!strict
local Testing = require("./")

type TestVector = {
	Mode: "Encrypt" | "Decrypt",
	Description: string,
	Expected: string,
	Key: buffer?,
	Plaintext: string?,
}

type TestVectors = {[string]: TestVector}

local function FromHex(Hex: string): buffer
	local Length = #Hex
	local Buffer = buffer.create(Length / 2)
	for Index = 0, Length - 2, 2 do
		buffer.writeu8(Buffer, Index / 2, tonumber(string.sub(Hex, Index + 1, Index + 2), 16) :: number)
	end
	
	return Buffer
end

local function ToHex(Buffer: buffer): string
	local Hex = ""
	for Index = 0, buffer.len(Buffer) - 1 do
		Hex ..= string.format("%02x", buffer.readu8(Buffer, Index))
	end
	
	return Hex
end

local Speck = require("../Encryption/Speck")

local TestVectors: TestVectors = {
	["6561656e7320466174"] = {
		Mode = "Encrypt",
		Description = "Speck64/96 Official Test Vector [Encrypt]",
		Expected = "6c9475419f7952ec",
		Key = FromHex("0001020308094b10111213000000"),
		Plaintext = "6561656e7320466174"
	},

	["6c9475419f7952ec"] = {
		Mode = "Decrypt",
		Description = "Speck64/96 Official Test Vector [Decrypt]",
		Expected = "6561656e7320466174",
		Key = FromHex("0001020308094b10111213000000")
	},

	["2d43757474657233b"] = {
		Mode = "Encrypt",
		Description = "Speck64/128 Official Test Vector [Encrypt]",
		Expected = "8b024e4548a56f8c",
		Key = FromHex("000102030809040b101112131819141b"),
		Plaintext = "2d43757474657233b"
	},

	["8b024e4548a56f8c"] = {
		Mode = "Decrypt",
		Description = "Speck64/128 Official Test Vector [Decrypt]",
		Expected = "2d43757474657233b",
		Key = FromHex("000102030809040b101112131819141b")
	},

	["Hello!!!"] = {
		Mode = "Encrypt",
		Description = "Hello!!! [Encrypt]",
		Expected = "",
		Key = FromHex("0001020304050607")
	},

	["TestData"] = {
		Mode = "Encrypt",
		Description = "TestData [Encrypt]",
		Expected = "",
		Key = FromHex("0f0e0d0c0b0a0908")
	},

	["0000000000000000"] = {
		Mode = "Encrypt",
		Description = "All Zeros Block [Encrypt]",
		Expected = "",
		Key = FromHex("0000000000000000")
	},

	["ffffffffffffffff"] = {
		Mode = "Encrypt",
		Description = "All Ones Block [Encrypt]",
		Expected = "",
		Key = FromHex("ffffffffffffffff")
	}
}

local function StringToHex(Str: string): string
	local Hex = ""
	for Index = 1, #Str do
		Hex = Hex .. string.format("%02x", string.byte(Str, Index))
	end
	
	return Hex
end

local function HexToString(Hex: string): string
	local Str = ""
	for Index = 1, #Hex, 2 do
		local ByteValue = tonumber(string.sub(Hex, Index, Index + 1), 16)
		if ByteValue then
			Str = Str .. string.char(ByteValue)
		end
	end
	
	return Str
end

Testing.Describe("Speck Cipher Algorithm Tests", function()

	Testing.Test("Generate Expected Values For Custom Tests", function()
		local HelloEncrypted = Speck.Encrypt(
			buffer.fromstring("Hello!!!"),
			FromHex("0001020304050607")
		)
		local HelloHex = ToHex(HelloEncrypted)

		local HelloDecrypted = Speck.Decrypt(
			HelloEncrypted,
			FromHex("0001020304050607")
		)
		Testing.Expect(buffer.tostring(HelloDecrypted)).ToBe("Hello!!!")
	end)

	Testing.Test("Official Test Vector Round-trip", function()
		local Plaintext = FromHex("6561656e7320466174")
		local Key = FromHex("0001020308094b10111213000000")

		local Encrypted = Speck.Encrypt(Plaintext, Key)
		local Decrypted = Speck.Decrypt(Encrypted, Key)

		Testing.Expect(ToHex(Decrypted)).ToBe(ToHex(Plaintext))
	end)

	local RoundTripTests = {
		"Hello World!",
		"Test123",
		"A",
		"This is a longer test string to verify padding works correctly!",
		string.rep("X", 100),
		"SpeckCipher",
		"12345678",
		"abcdefgh"
	}

	for _, TestString in RoundTripTests do
		Testing.Test("Round-trip Test: " .. TestString:sub(1, 20) .. (TestString:len() > 20 and "..." or ""), function()
			local Key = FromHex("0001020304050607")
			local Plaintext = buffer.fromstring(TestString)

			local Encrypted = Speck.Encrypt(Plaintext, Key)
			local Decrypted = Speck.Decrypt(Encrypted, Key)

			Testing.Expect(buffer.tostring(Decrypted)).ToBe(TestString)
		end)
	end

	Testing.Test("Key Handling Tests", function()
		local Plaintext = buffer.fromstring("TestData")

		local ShortKey = buffer.fromstring("key")
		local Encrypted1 = Speck.Encrypt(Plaintext, ShortKey)
		local Decrypted1 = Speck.Decrypt(Encrypted1, ShortKey)
		Testing.Expect(buffer.tostring(Decrypted1)).ToBe("TestData")

		local LongKey = buffer.fromstring("this_is_a_very_long_key_that_exceeds_8_bytes")
		local Encrypted2 = Speck.Encrypt(Plaintext, LongKey)
		local Decrypted2 = Speck.Decrypt(Encrypted2, LongKey)
		Testing.Expect(buffer.tostring(Decrypted2)).ToBe("TestData")
	end)

	Testing.Test("Empty Input Test", function()
		local Key = FromHex("0001020304050607")
		local EmptyBuffer = buffer.create(0)

		local Encrypted = Speck.Encrypt(EmptyBuffer, Key)
		local Decrypted = Speck.Decrypt(Encrypted, Key)

		Testing.Expect(buffer.len(Decrypted)).ToBe(0)
	end)

	Testing.Test("Exact Block Size Test", function()
		local Key = FromHex("0001020304050607")
		local Plaintext = FromHex("0123456789abcdef")

		local Encrypted = Speck.Encrypt(Plaintext, Key)
		local Decrypted = Speck.Decrypt(Encrypted, Key)

		Testing.Expect(ToHex(Decrypted)).ToBe("0123456789abcdef")
	end)

	Testing.Test("Different Key Patterns", function()
		local Plaintext = buffer.fromstring("TestSpeck")

		local Keys = {
			FromHex("0123456789abcdef"),
			FromHex("fedcba9876543210"),
			FromHex("aaaaaaaaaaaaaaaa"),
			FromHex("5555555555555555"),
			FromHex("0f0f0f0f0f0f0f0f")
		}

		for Index, Key in Keys do
			local Encrypted = Speck.Encrypt(Plaintext, Key)
			local Decrypted = Speck.Decrypt(Encrypted, Key)
			Testing.Expect(buffer.tostring(Decrypted)).ToBe("TestSpeck")
		end
	end)

	Testing.Test("Large Data Test", function()
		local Key = FromHex("0001020304050607")
		local LargeText = string.rep("Speck64Encryption", 50)
		local Plaintext = buffer.fromstring(LargeText)

		local Encrypted = Speck.Encrypt(Plaintext, Key)
		local Decrypted = Speck.Decrypt(Encrypted, Key)

		Testing.Expect(buffer.tostring(Decrypted)).ToBe(LargeText)
	end)

	Testing.Test("Binary Data Test", function()
		local Key = FromHex("deadbeefcafebabe")
		local BinaryData = FromHex("00112233445566778899aabbccddeeff")

		local Encrypted = Speck.Encrypt(BinaryData, Key)
		local Decrypted = Speck.Decrypt(Encrypted, Key)

		Testing.Expect(ToHex(Decrypted)).ToBe("00112233445566778899aabbccddeeff")
	end)
end)

Testing.Complete()

return 0