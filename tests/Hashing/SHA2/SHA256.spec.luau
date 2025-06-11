--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)

local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local SHA256 = Cryptography.Hashing.SHA2.SHA256

local testCases = {
	{
		input = "",
		description = "Empty String",
		expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	},
	{
		input = "The quick brown fox jumps over the lazy dog.",
		description = "Pangramm Example",
		expected = "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
	},
	{
		input = "Привет, мир!",
		description = "UTF-8 Example",
		expected = "9a0af011605a6ab9022f248fb797064a42782210ac91e834348b3ef089313e5f",
	},
	{
		input = "\0",
		description = "Null Terminator",
		expected = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	},
	{
		input = string.rep("a", 55),
		description = "Block of Characters",
		expected = "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
	},
	{
		input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		description = "448 Bit",
		expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
	},
	{
		input = string.rep("a", 111),
		description = "111 Characters",
		expected = "6374f73208854473827f6f6a3f43b1f53eaa3b82c21c1a6d69a2110b2a79baad",
	},
	{
		input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		description = "896 Bits",
		expected = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
	},
	{
		input = string.rep("a", 119),
		description = "119 Characters",
		expected = "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb",
	},
	{
		input = string.rep("a", 239),
		description = "239 Characters",
		expected = "064b3d122abe25c36265f79fc794b0adf28a6c5e4fe8ed3661f2287e8cecadcc",
	},
	{
		input = string.rep("a", 1024),
		description = "Long String",
		expected = "2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a",
	},
	{
		input = string.rep("a", 199999),
		description = "Really Long String",
		expected = "6a2540f78c491a847183ac081f68c7f971806fbd346408aaefbf5d4edec3e901",
	},
	{
		input = string.rep("a", 1e6),
		description = "Million",
		expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
	},
}

describe("SHA256", function()
	it.each(testCases)("should compute $description correctly", function(testCase)
		local result = SHA256(buffer.fromstring(testCase.input))
		expect(result).toBe(testCase.expected)
	end)
end)