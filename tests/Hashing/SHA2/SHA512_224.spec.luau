--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)

local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local SHA512_224 = Cryptography.Hashing.SHA2.SHA512_224

local testCases = {
	{
		input = "",
		expected = "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
		description = "empty string",
	},
	{
		input = "The quick brown fox jumps over the lazy dog.",
		expected = "6d6a9279495ec4061769752e7ff9c68b6b0b3c5a281b7917ce0572de",
		description = "pangramm example",
	},
	{
		input = "Привет, мир!",
		expected = "2ea5dce818e9db98e1c256580644c9b9b49e2d7fd0c8e499cbfad232",
		description = "UTF-8 example",
	},
	{
		input = "\0",
		expected = "283bb59af7081ed08197227d8f65b9591ffe1155be43e9550e57f941",
		description = "null terminator",
	},
	{
		input = string.rep("a", 55),
		expected = "70a40c59a45a82e85038580887f60fb8bb3d3a0562dceac4a909de2e",
		description = "block of characters",
	},
	{
		input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		expected = "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174",
		description = "448 bit",
	},
	{
		input = string.rep("a", 111),
		expected = "3ebe1b48e8c66acb9ae014db95b4bec93de7e9572bff41cf566bd7d0",
		description = "111 characters",
	},
	{
		input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		expected = "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9",
		description = "896 bits",
	},
	{
		input = string.rep("a", 119),
		expected = "3faf8c370047a31f89bd959c5af5a2328928fb13823f15826ce8c225",
		description = "119 characters",
	},
	{
		input = string.rep("a", 239),
		expected = "f0d8b2a6b6d937a8232af97907d0e8ab8b7a5d5f0b0b0c9ec2f4d8b0",
		description = "239 characters",
	},
	{
		input = string.rep("a", 1024),
		expected = "804ff477e0a6a6e8728f571147f6aa991354d0305ee611e790cd772c",
		description = "long string",
	},
	{
		input = string.rep("a", 199999),
		expected = "544e8e61bf9e4fa439cfe6bd0e08923d0da927bb154ebaee2b90ad58",
		description = "really long string",
	},
	{
		input = string.rep("a", 1e6),
		expected = "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287",
		description = "million",
	},
}

describe("SHA512_224", function()
	it.each(testCases)("should hash $description correctly", function(testCase)
		local result = SHA512_224(buffer.fromstring(testCase.input))
		expect(result).toBe(testCase.expected)
	end)
end)