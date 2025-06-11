--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)

local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local SHA512 = Cryptography.Hashing.SHA2.SHA512

local testCases = {
	{
		input = "",
		expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		description = "empty string",
	},
	{
		input = "The quick brown fox jumps over the lazy dog.",
		expected = "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed",
		description = "pangramm example",
	},
	{
		input = "Привет, мир!",
		expected = "72999100567a447d753427946f9de45255ab9ce1778f771b5c3d4663cbb53f8623e829655b3b3ca7bfe388510249f74e5d3a0e16c8be0ff2d0696abcb68a940e",
		description = "UTF-8 example",
	},
	{
		input = "\0",
		expected = "b8244d028981d693af7b456af8efa4cad63d282e19ff14942c246e50d9351d22704a802a71c3580b6370de4ceb293c324a8423342557d4e5c38438f0e36910ee",
		description = "null terminator",
	},
	{
		input = string.rep("a", 55),
		expected = "b0220c772cbf6c1822e2cb38a437d0e1d58772417a4bbb21c961364f8b6143e05aa6316dca8d1d7b19e16448419076395f6086cb55101fbd6d5497b148e1745f",
		description = "block of characters",
	},
	{
		input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		expected = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
		description = "448 bit",
	},
	{
		input = string.rep("a", 111),
		expected = "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2",
		description = "111 characters",
	},
	{
		input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		expected = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
		description = "896 bits",
	},
	{
		input = string.rep("a", 119),
		expected = "130396a75cb483f2eee8c56d8a668bb3d2641f5243212c0bee2bd33da096ad9eb8179fe18f9eaacf76e09fae9de4c3f14ba13341e345be05bf76c182cc3468cb",
		description = "119 characters",
	},
	{
		input = string.rep("a", 239),
		expected = "52c853cb8d907f3d4d6b889beb027985d7c273486d75f8baf26f80d24e90c74c6c3de3e22131582380a7d14d43f2941a31385439cd6ddc469f628015e50bf286",
		description = "239 characters",
	},
	{
		input = string.rep("a", 1024),
		expected = "74b22492e3b9a86a9c93c23a69f821ebafa429302c1f4054b4bc37356a4bae056d9ccbc6f24093a25704faaa72bd21a5f337ca9ec92f32369d24e6b9fae954d8",
		description = "long string",
	},
	{
		input = string.rep("a", 199999),
		expected = "24ff84cd80316c1f3591abf9f59c026eb8a22390f005acf1a2d21aa0d3433608cc8bdfebe07fbe2ced63f625b5675f5cdb21fdc9710f8ecd31dea524d282d284",
		description = "really long string",
	},
	{
		input = string.rep("a", 1e6),
		expected = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
		description = "million",
	},
}

describe("SHA512", function()
	it.each(testCases)("should hash $description correctly", function(testCase)
		local result = SHA512(buffer.fromstring(testCase.input))
		expect(result).toBe(testCase.expected)
	end)
end)
