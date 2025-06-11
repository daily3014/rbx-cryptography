--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)
local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local SHA1 = Cryptography.Hashing.SHA1

local testCases = {
	{
		input = "",
		description = "Empty String",
		expected = "da39a3ee5e6b4b0d3255bfef95601890afd80709",
	},
	{
		input = "The quick brown fox jumps over the lazy dog.",
		description = "Pangramm Example",
		expected = "408d94384216f890ff7a0c3528e8bed1e0b01621",
	},
	{
		input = "Привет, мир!",
		description = "UTF-8 Example",
		expected = "0cb95b7891ff182f0972be8754ec934df65af21c",
	},
	{
		input = "\0",
		description = "Null Terminator",
		expected = "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
	},
	{
		input = string.rep("a", 55),
		description = "Block of Characters",
		expected = "c1c8bbdc22796e28c0e15163d20899b65621d65a",
	},
	{
		input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		description = "448 Bit",
		expected = "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
	},
	{
		input = string.rep("a", 111),
		description = "111 Characters",
		expected = "ac877859d427d9192054eea8feb3b8a403ef83a5",
	},
	{
		input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		description = "896 Bits",
		expected = "a49b2446a02c645bf419f995b67091253a04a259",
	},
	{
		input = string.rep("a", 119),
		description = "119 Characters",
		expected = "ee971065aaa017e0632a8ca6c77bb3bf8b1dfc56",
	},
	{
		input = string.rep("a", 239),
		description = "239 Characters",
		expected = "fdc30857cf7b957f47ebd8288d5e5d7426f44394",
	},
	{
		input = string.rep("a", 1024),
		description = "Long String",
		expected = "8eca554631df9ead14510e1a70ae48c70f9b9384",
	},
	{
		input = string.rep("a", 199999),
		description = "Really Long String",
		expected = "b673b36f4398c26070c29ade5193903b4e6455d9",
	},
	{
		input = string.rep("a", 1e6),
		description = "Million",
		expected = "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
	},
}

describe("SHA1", function()
	it.each(testCases)("should hash $description correctly", function(testCase)
		local inputBuffer = buffer.fromstring(testCase.input)
		local result = SHA1(inputBuffer)
		
		expect(result).toBe(testCase.expected)
	end)
end)