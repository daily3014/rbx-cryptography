--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)

local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local SHA512_256 = Cryptography.Hashing.SHA2.SHA512_256

local testCases = {
	{
		input = "",
		expected = "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
		description = "empty string",
	},
	{
		input = "The quick brown fox jumps over the lazy dog.",
		expected = "1546741840f8a492b959d9b8b2344b9b0eb51b004bba35c0aebaac86d45264c3",
		description = "pangramm example",
	},
	{
		input = "Привет, мир!",
		expected = "2ecef582e43e1cf108c03f7f78da7f1c9908bce487738ee3e90bf0d548af6f29",
		description = "UTF-8 example",
	},
	{
		input = "\0",
		expected = "10baad1713566ac2333467bddb0597dec9066120dd72ac2dcb8394221dcbe43d",
		description = "null terminator",
	},
	{
		input = string.rep("a", 55),
		expected = "f6513468f05e7cec7d52fc337ef79dfa7c82520268d3aeba4002ead9a5642916",
		description = "block of characters",
	},
	{
		input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		expected = "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461",
		description = "448 bit",
	},
	{
		input = string.rep("a", 111),
		expected = "0239e429f98d0ed61ee8e2a7c30afe98c1c3a80ce5dff62a107e9c538f7632ce",
		description = "111 characters",
	},
	{
		input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		expected = "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
		description = "896 bits",
	},
	{
		input = string.rep("a", 119),
		expected = "6cb452f832033489de69b49d6a8e8a1e0018092f1986c132287f4ca4ab3ee545",
		description = "119 characters",
	},
	{
		input = string.rep("a", 239),
		expected = "78d0a1b37aaad84c89fff13cbe3cd3d1025bcdb648268f9102b7e7032bea7d2a",
		description = "239 characters",
	},
	{
		input = string.rep("a", 1024),
		expected = "fe25c1c9bbdd2fad014a4d33105227865256abab8cf01d4b6675a3f8b468626e",
		description = "long string",
	},
	{
		input = string.rep("a", 199999),
		expected = "02f7539fbbb32c2dbe4e217f8a37bdbc39e1950700daaf73884ee1e79f2b13c9",
		description = "really long string",
	},
	{
		input = string.rep("a", 1e6),
		expected = "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21",
		description = "million",
	},
}

describe("SHA512_256", function()
	it.each(testCases)("should hash $description correctly", function(testCase)
		local result = SHA512_256(buffer.fromstring(testCase.input))
		expect(result).toBe(testCase.expected)
	end)
end)
