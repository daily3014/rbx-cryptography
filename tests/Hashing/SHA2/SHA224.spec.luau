--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)

local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local SHA224 = Cryptography.Hashing.SHA2.SHA224

local testCases = {
	{ input = "", description = "Empty String", expected = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" },
	{
		input = "The quick brown fox jumps over the lazy dog.",
		description = "Pangramm Example",
		expected = "619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c",
	},
	{
		input = "Привет, мир!",
		description = "UTF-8 Example",
		expected = "941fd4cfe921e7a8ea1e1c6dd255b3c06d948fe7546bcd1d8deda161",
	},
	{
		input = "\0",
		description = "Null Terminator",
		expected = "fff9292b4201617bdc4d3053fce02734166a683d7d858a7f5f59b073",
	},
	{
		input = string.rep("a", 55),
		description = "Block of Characters",
		expected = "fb0bd626a70c28541dfa781bb5cc4d7d7f56622a58f01a0b1ddd646f",
	},
	{
		input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		description = "448 Bit",
		expected = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
	},
	{
		input = string.rep("a", 111),
		description = "111 Characters",
		expected = "4aeec1a49b2c1bc663abf2809b36faaa64359523d4f26d02dbc2cba3",
	},
	{
		input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		description = "896 Bits",
		expected = "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3",
	},
	{
		input = string.rep("a", 119),
		description = "119 Characters",
		expected = "e000e6709d26667b631faa7fc1bd404eb4774003c5fb4f51a0184875",
	},
	{
		input = string.rep("a", 239),
		description = "239 Characters",
		expected = "9da4e535cdffdbb7ee783ef7c6b61cbda7bcd4b15ce59d6ce5c2f099",
	},
	{
		input = string.rep("a", 1024),
		description = "Long String",
		expected = "dcbd9ce406352c2e127ce1cad5042c22dd28a0246dadefc12f384c2e",
	},
	{
		input = string.rep("a", 199999),
		description = "Really Long String",
		expected = "4fa3ff00143a30c4530a986cecb42ee2c2ae41b52faff36bfbee5152",
	},
	{
		input = string.rep("a", 1e6),
		description = "Million",
		expected = "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
	},
}

describe("SHA224", function()
	it.each(testCases)("should compute $description correctly", function(testCase)
		local result = SHA224(buffer.fromstring(testCase.input))
		expect(result).toBe(testCase.expected)
	end)
end)
