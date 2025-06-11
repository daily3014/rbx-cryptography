--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)

local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local Base64 = Cryptography.Utilities.Base64

local testCases = {
	{
		decoded = "",
		encoded = "",
		description = "empty string",
	},
	{
		decoded = "The quick brown fox jumps over the lazy dog.",
		encoded = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4=",
		description = "pangramm",
	},
	{
		decoded = "Привет, мир!",
		encoded = "0J/RgNC40LLQtdGCLCDQvNC40YAh",
		description = "utf-8",
	},
	{
		decoded = string.rep("a", 55),
		encoded = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==",
		description = "block of characters",
	},
}

describe("Base64", function()
	describe("encode", function()
		it.each(testCases)("should encode $description correctly", function(testCase)
			local result = Base64.Encode(buffer.fromstring(testCase.decoded))
			expect(result).toBe(testCase.encoded)
		end)
	end)
	describe("decode", function()
		it.each(testCases)("should decode $description correctly", function(testCase)
			local result = Base64.Decode(buffer.fromstring(testCase.encoded))
			expect(result).toBe(testCase.decoded)
		end)
	end)
end)
