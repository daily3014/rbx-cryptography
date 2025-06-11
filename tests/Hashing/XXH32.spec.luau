--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)
local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local XXH32 = Cryptography.Hashing.XXH32

local unseededTestCases = {
	{
		input = "",
		description = "Empty String",
		expected = 0x02cc5d05,
	},
	{
		input = "abc",
		description = "Simple ABC",
		expected = 0x32d153ff,
	},
	{
		input = "foo",
		description = "Simple Foo",
		expected = 0xe20f0dd9,
	},
	{
		input = "bar",
		description = "Simple Bar",
		expected = 0x41a22b2c,
	},
	{
		input = "baz",
		description = "Simple Baz",
		expected = 0x9bab0987,
	},
	{
		input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		description = "448 Bit Alphabet",
		expected = 0x89ea60c3,
	},
	{
		input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		description = "896 Bit Alphabet",
		expected = 0x590b4165,
	},
	{
		input = "The Fitness-Gram Pacer Test is a multi-stage aerobic capacity test",
		description = "Fitness-Gram Test",
		expected = 0xbea696a7,
	},
	{
		input = string.rep("e", 199999),
		description = "Really Long String",
		expected = 0xb27dd558,
	},
	{
		input = string.rep("a", 1e6),
		description = "Million",
		expected = 0xe1155920,
	},
}

local seededTestCases = {
	{
		input = "",
		description = "Empty String with Seed",
		expected = 0xf6114164,
		seed = 0x02cc5d05,
	},
	{
		input = "abc",
		description = "Simple ABC with Seed",
		expected = 0x9041e0d8,
		seed = 0x32d153ff,
	},
	{
		input = "foo",
		description = "Simple Foo with Seed",
		expected = 0xf4d3f6c9,
		seed = 0xe20f0dd9,
	},
	{
		input = "bar",
		description = "Simple Bar with Seed",
		expected = 0x9ad4ead3,
		seed = 0x41a22b2c,
	},
	{
		input = "baz",
		description = "Simple Baz with Seed",
		expected = 0x23af9b99,
		seed = 0x9bab0987,
	},
	{
		input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		description = "448 Bit Alphabet with Seed",
		expected = 0x404871e3,
		seed = 0x89ea60c3,
	},
	{
		input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		description = "896 Bit Alphabet with Seed",
		expected = 0xc033cd93,
		seed = 0x590b4165,
	},
	{
		input = "The Fitness-Gram Pacer Test is a multi-stage aerobic capacity test",
		description = "Fitness-Gram Test with Seed",
		expected = 0x3c6ef7ed,
		seed = 0xbea696a7,
	},
	{
		input = string.rep("e", 199999),
		description = "Really Long String with Seed",
		expected = 0x6174a9bd,
		seed = 0xb27dd558,
	},
	{
		input = string.rep("a", 1e6),
		description = "Million with Seed",
		expected = 0xc0c7beae,
		seed = 0xe1155920,
	},
}

describe("XXH32", function()
	describe("Unseeded Hash", function()
		it.each(unseededTestCases)("should hash $description correctly", function(testCase)
			local inputBuffer = buffer.fromstring(testCase.input)
			local result = XXH32(inputBuffer)
			
			expect(result).toBe(testCase.expected)
		end)
	end)
	
	describe("Seeded Hash", function()
		it.each(seededTestCases)("should hash $description correctly", function(testCase)
			local inputBuffer = buffer.fromstring(testCase.input)
			local result = XXH32(inputBuffer, testCase.seed)
			
			expect(result).toBe(testCase.expected)
		end)
	end)
end)