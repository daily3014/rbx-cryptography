--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)
local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local ChaCha20 = Cryptography.Encryption.ChaCha20

local function fromHex(hex: string): buffer
	local length = #hex
	local buf = buffer.create(length / 2)
	for index = 0, length - 2, 2 do
		buffer.writeu8(buf, index / 2, tonumber(string.sub(hex, index + 1, index + 2), 16) :: number)
	end
	return buf
end

local function toHex(buf: buffer): string
	local hex = ""
	for index = 0, buffer.len(buf) - 1 do
		hex ..= string.format("%02x", buffer.readu8(buf, index))
	end
	return hex
end

local defaultKey = buffer.fromstring("0123456789ABCDEF0123456789ABCDEF")
local defaultNonce = buffer.fromstring("Nonce12Bytes")

local encryptionTestCases = {
	{
		input = "Hello World!",
		description = "Hello World [Encrypt]",
		expected = "3b66fdac2bf5943d594b1bbb",
		key = defaultKey,
		nonce = defaultNonce,
		counter = nil,
	},
	{
		input = "Hello World",
		description = "Hello World with custom counter [Encrypt]",
		expected = "a55e9f612c550145b40da7",
		key = defaultKey,
		nonce = defaultNonce,
		counter = 15,
	},
	{
		input = string.rep("a", 150),
		description = "150 Characters [Encrypt]",
		expected = "1262f0a125b4a2334a461efb95e26869acc877bde19930e3cbdc404b73709904246201482ce7b5cb0cdc0dbbac79eb5fce3f364d515a7e262c909dda884d77e7dc4f87076265b90fd3cc4cc3cbd5d8482096116d134e4d6153379b5e9ab9df06614981b21f5981d5d97864437de0efeaf8a4470a789f85a43b657cad00992bb644955255e9f9ffb0c68bdfc0adae603d9f93890060ac",
		key = defaultKey,
		nonce = defaultNonce,
		counter = nil,
	},
}

local decryptionTestCases = {
	{
		input = "3b66fdac2bf5943d594b1bbb",
		description = "Hello World [Decrypt]",
		expected = "Hello World!",
		key = defaultKey,
		nonce = defaultNonce,
		counter = nil,
	},
	{
		input = "a55e9f612c550145b40da7",
		description = "Hello World with custom counter [Decrypt]",
		expected = "Hello World",
		key = defaultKey,
		nonce = defaultNonce,
		counter = 15,
	},
	{
		input = "1262f0a125b4a2334a461efb95e26869acc877bde19930e3cbdc404b73709904246201482ce7b5cb0cdc0dbbac79eb5fce3f364d515a7e262c909dda884d77e7dc4f87076265b90fd3cc4cc3cbd5d8482096116d134e4d6153379b5e9ab9df06614981b21f5981d5d97864437de0efeaf8a4470a789f85a43b657cad00992bb644955255e9f9ffb0c68bdfc0adae603d9f93890060ac",
		description = "150 Characters [Decrypt]",
		expected = string.rep("a", 150),
		key = defaultKey,
		nonce = defaultNonce,
		counter = nil,
	},
}

describe("ChaCha20", function()
	describe("Encryption", function()
		it.each(encryptionTestCases)("should encrypt $description correctly", function(testCase)
			local inputBuf = buffer.fromstring(testCase.input)
			local result = ChaCha20(inputBuf, testCase.key, testCase.nonce, testCase.counter)
			local resultHex = toHex(result)

			expect(resultHex).toBe(testCase.expected)
		end)
	end)

	describe("Decryption", function()
		it.each(decryptionTestCases)("should decrypt $description correctly", function(testCase)
			local inputBuf = fromHex(testCase.input)
			local result = ChaCha20(inputBuf, testCase.key, testCase.nonce, testCase.counter)
			local resultStr = buffer.tostring(result)

			expect(resultStr).toBe(testCase.expected)
		end)
	end)
end)
