--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)

local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local Adler = Cryptography.Checksums.Adler

local testCases = {
	{ input = "", description = "Empty String", expected = 0x1 },
	{ input = "a", description = "Single Character", expected = 0x00620062 },
	--{"Привет, мир!", description = "UTF-8 Example", expected = 0xa0800d97 },
	{ input = "\0", description = "Null Terminator", expected = 0x00010001 },
	{ input = "Wikipedia", description = "Wikipedia Example", expected = 0x11e60398 },
	{ input = string.rep("a", 55), description = "Block of Characters", expected = 0x47d914d8 },
	{
		input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		description = "448 Bit",
		expected = 0x807416f9,
	},
	{ input = string.rep("a", 111), description = "111 Characters", expected = 0x343e2a10 },
	{ input = string.rep("a", 119), description = "119 Characters", expected = 0x92712d18 },
	{ input = string.rep("a", 239), description = "239 Characters", expected = 0x766d5a90 },
	{ input = string.rep("a", 1024), description = "Long String", expected = 0xf3788410 },
	{ input = string.rep("a", 199999), description = "Really Long String", expected = 0xb6551638 },
	{ input = string.rep("a", 1e6), description = "Million", expected = 0x15d870f9 },
}

describe("Adler", function()
	it.each(testCases)("should compute $description correctly", function(testCase)
		local result = Adler(buffer.fromstring(testCase.input))
		expect(result).toBe(testCase.expected)
	end)
end)
