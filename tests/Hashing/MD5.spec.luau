--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)
local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local MD5 = Cryptography.Hashing.MD5

local testCases = {
	{
		input = "",
		description = "Empty String",
		expected = "d41d8cd98f00b204e9800998ecf8427e",
	},
	{
		input = "The quick brown fox jumps over the lazy dog.",
		description = "Pangramm Example",
		expected = "e4d909c290d0fb1ca068ffaddf22cbd0",
	},
	{
		input = "Привет, мир!",
		description = "UTF-8 Example",
		expected = "c446a2994f35689482651b7c7ba8b56c",
	},
	{
		input = "\0",
		description = "Null Terminator",
		expected = "93b885adfe0da089cdf634904fd59f71",
	},
	{
		input = string.rep("a", 55),
		description = "Block of Characters",
		expected = "ef1772b6dff9a122358552954ad0df65",
	},
	{
		input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		description = "448 Bit",
		expected = "8215ef0796a20bcaaae116d3876c664a",
	},
	{
		input = string.rep("a", 111),
		description = "111 Characters",
		expected = "089f243d1e831c5879aa375ee364a06e",
	},
	{
		input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		description = "896 Bits",
		expected = "03dd8807a93175fb062dfb55dc7d359c",
	},
	{
		input = string.rep("a", 119),
		description = "119 Characters",
		expected = "8a7bd0732ed6a28ce75f6dabc90e1613",
	},
	{
		input = string.rep("a", 239),
		description = "239 Characters",
		expected = "b7b40d64ffccebd78abcf522376b3aae",
	},
	{
		input = string.rep("a", 1024),
		description = "Long String",
		expected = "c9a34cfc85d982698c6ac89f76071abd",
	},
	{
		input = string.rep("a", 199999),
		description = "Really Long String",
		expected = "5b21a86f4bb0f3f703167705e5e673df",
	},
	{
		input = string.rep("a", 1e6),
		description = "Million",
		expected = "7707d6ae4e027c70eea2a935c2296f21",
	},
}

describe("MD5", function()
	it.each(testCases)("should hash $description correctly", function(testCase)
		local inputBuffer = buffer.fromstring(testCase.input)
		local result = MD5(inputBuffer)
		
		expect(result).toBe(testCase.expected)
	end)
end)