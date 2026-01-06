-- @ScriptType: ModuleScript
--!strict
local Testing = require("./")
type TestVector = {
	Description: string,
	Input: string,
	Key: string,
}

local function FromHex(Hex: string): buffer
	local Length = #Hex
	local Buffer = buffer.create(Length / 2)
	for Index = 0, Length - 2, 2 do
		buffer.writeu8(Buffer, Index / 2, tonumber(string.sub(Hex, Index + 1, Index + 2), 16) :: number)
	end

	return Buffer
end

local function ToHex(Buffer: buffer) : string
	local Hex = ""
	for Index = 0, buffer.len(Buffer) - 1 do
		Hex ..= string.format("%02x", buffer.readu8(Buffer, Index))
	end

	return Hex
end

local XOR = require("../Encryption/XOR")

local TestVectors: {TestVector} = {
	{
		Description = "Single byte key - Hello World!",
		Input = "Hello World!",
		Key = "X"
	},
	{
		Description = "Four byte key - Testing 1234",
		Input = "Testing 1234",
		Key = "ABCD"
	},
	{
		Description = "Three byte key - Hello World!",
		Input = "Hello World!",
		Key = "KEY"
	},
	{
		Description = "150 characters with 5 byte key",
		Input = string.rep("a", 150),
		Key = "@@@@@"
	},
	{
		Description = "Empty string",
		Input = "",
		Key = "KEY"
	},
	{
		Description = "Single character",
		Input = "A",
		Key = "C"
	},
	{
		Description = "Binary data",
		Input = "\xFF\x00\xFF\x00\xFF\x00\xFF\x00",
		Key = "\x55"
	},
	{
		Description = "Two byte key - Test Message",
		Input = "Test Message",
		Key = "AB"
	},
	{
		Description = "Key longer than message",
		Input = "Short",
		Key = "VeryLongKeyThatIsLongerThanMessage"
	},
	{
		Description = "String with null byte",
		Input = "Test\0Message",
		Key = "ABC"
	},
	{
		Description = "3 byte string",
		Input = "123",
		Key = "BAD"
	},
	{
		Description = "5 byte string",
		Input = "12345",
		Key = "BAD"
	},
	{
		Description = "17 byte key",
		Input = "This is a test message for XOR encryption",
		Key = "LARGEKEY12345678X"
	},
	{
		Description = "Key repetition pattern",
		Input = "ABCDEFGHIJKLMNOP",
		Key = "CAB"
	},
}

Testing.Describe("XOR Encryption Algorithm Tests", function()
	for _, Vector in TestVectors do
		Testing.Test(Vector.Description .. " [Encrypt/Decrypt Cycle]", function()
			local InputBuffer = buffer.fromstring(Vector.Input)
			local KeyBuffer = buffer.fromstring(Vector.Key)

			local Encrypted = XOR(InputBuffer, KeyBuffer)
			local Decrypted = XOR(Encrypted, KeyBuffer)

			Testing.Expect(buffer.tostring(Decrypted)).ToBe(Vector.Input)
		end)
	end

	Testing.Test("Deterministic output test", function()
		local Input = "Test String"
		local Key = "MyKey"
		local InputBuffer = buffer.fromstring(Input)
		local KeyBuffer = buffer.fromstring(Key)

		local Result1 = ToHex(XOR(InputBuffer, KeyBuffer))
		local Result2 = ToHex(XOR(InputBuffer, KeyBuffer))

		Testing.Expect(Result1).ToBe(Result2)
	end)

	Testing.Test("Known value: A XOR C = 02", function()
		local InputBuffer = buffer.fromstring("A")
		local KeyBuffer = buffer.fromstring("C")
		local Result = ToHex(XOR(InputBuffer, KeyBuffer))
		Testing.Expect(Result).ToBe("02")
	end)

	Testing.Test("Known value: 0xFF XOR 0x55 = 0xAA", function()
		local InputBuffer = buffer.fromstring("\xFF")
		local KeyBuffer = buffer.fromstring("\x55")
		local Result = ToHex(XOR(InputBuffer, KeyBuffer))
		Testing.Expect(Result).ToBe("aa")
	end)

	Testing.Test("Input buffer not modified", function()
		local Original = "Don't modify me :("
		local InputBuffer = buffer.fromstring(Original)
		local KeyBuffer = buffer.fromstring("KEY")

		local OriginalContent = buffer.tostring(InputBuffer)
		local _ = XOR(InputBuffer, KeyBuffer)

		Testing.Expect(buffer.tostring(InputBuffer)).ToBe(OriginalContent)
	end)

	Testing.Test("Large data test (10KB)", function()
		local LargeData = string.rep("X", 10240)
		local Key = "PerformanceTestKey"
		local InputBuffer = buffer.fromstring(LargeData)
		local KeyBuffer = buffer.fromstring(Key)

		local Encrypted = XOR(InputBuffer, KeyBuffer)
		local Decrypted = XOR(Encrypted, KeyBuffer)

		Testing.Expect(buffer.tostring(Decrypted)).ToBe(LargeData)
	end)

	Testing.Test("Single byte encryption", function()
		for Index = 0, 255 do
			local Byte = string.char(Index)
			local Key = string.char((Index + 1) % 256)
			local InputBuffer = buffer.fromstring(Byte)
			local KeyBuffer = buffer.fromstring(Key)

			local Encrypted = XOR(InputBuffer, KeyBuffer)
			local Decrypted = XOR(Encrypted, KeyBuffer)

			Testing.Expect(buffer.tostring(Decrypted)).ToBe(Byte)
		end
	end)
end)

Testing.Complete()

return 0