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

local Simon = require("../Encryption/Simon")


Testing.Describe("Simon Cipher Algorithm Tests", function()

	Testing.Test("Generate Expected Values For Custom Tests", function()
		local HelloEncrypted = Simon.Encrypt(
			buffer.fromstring("Hello!!!"),
			FromHex("000102030405060708090a0b0c0d0e0f")
		)

		local HelloDecrypted = Simon.Decrypt(
			HelloEncrypted,
			FromHex("000102030405060708090a0b0c0d0e0f")
		)
		Testing.Expect(buffer.tostring(HelloDecrypted)).ToBe("Hello!!!")
	end)

	Testing.Test("Simon64/128 Official Test Vector [Encrypt]", function()
		local Plaintext = FromHex("75756e64206c696b65")
		local Key = FromHex("000102030809040b101112131819141b")

		local Encrypted = Simon.Encrypt(Plaintext, Key)
		local Decrypted = Simon.Decrypt(Encrypted, Key)

		Testing.Expect(ToHex(Decrypted)).ToBe(ToHex(Plaintext))
	end)

	local RoundTripTests = {
		"Hello World!",
		"Test123",
		"A",
		"This is a longer test string to verify padding works correctly!",
		string.rep("X", 100)
	}

	for _, TestString in RoundTripTests do
		Testing.Test("Round-trip Test: " .. TestString:sub(1, 20) .. (TestString:len() > 20 and "..." or ""), function()
			local Key = FromHex("000102030405060708090a0b0c0d0e0f")
			local Plaintext = buffer.fromstring(TestString)

			local Encrypted = Simon.Encrypt(Plaintext, Key)
			local Decrypted = Simon.Decrypt(Encrypted, Key)

			Testing.Expect(buffer.tostring(Decrypted)).ToBe(TestString)
		end)
	end

	Testing.Test("Key Handling Tests", function()
		local Plaintext = buffer.fromstring("TestData")

		local ShortKey = buffer.fromstring("short")
		local Encrypted1 = Simon.Encrypt(Plaintext, ShortKey)
		local Decrypted1 = Simon.Decrypt(Encrypted1, ShortKey)
		Testing.Expect(buffer.tostring(Decrypted1)).ToBe("TestData")

		local LongKey = buffer.fromstring("this_is_a_very_long_key_that_exceeds_16_bytes")
		local Encrypted2 = Simon.Encrypt(Plaintext, LongKey)
		local Decrypted2 = Simon.Decrypt(Encrypted2, LongKey)
		Testing.Expect(buffer.tostring(Decrypted2)).ToBe("TestData")
	end)

	Testing.Test("Empty Input Test", function()
		local Key = FromHex("000102030405060708090a0b0c0d0e0f")
		local EmptyBuffer = buffer.create(0)

		local Encrypted = Simon.Encrypt(EmptyBuffer, Key)
		local Decrypted = Simon.Decrypt(Encrypted, Key)

		Testing.Expect(buffer.len(Decrypted)).ToBe(0)
	end)

	Testing.Test("Exact Block Size Test", function()
		local Key = FromHex("000102030405060708090a0b0c0d0e0f")
		local Plaintext = FromHex("0123456789abcdef")

		local Encrypted = Simon.Encrypt(Plaintext, Key)
		local Decrypted = Simon.Decrypt(Encrypted, Key)

		Testing.Expect(ToHex(Decrypted)).ToBe("0123456789abcdef")
	end)
end)

Testing.Complete()

return 0