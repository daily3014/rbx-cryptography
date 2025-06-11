--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)

local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local Conversions = Cryptography.Utilities.Conversions

local testCases = {
	{ hex = "00", bytes = "\x00", buf = buffer.fromstring("\x00") },
	{ hex = "ff", bytes = "\xFF", buf = buffer.fromstring("\xFF") },
	{ hex = "deadbeef", bytes = "\xDE\xAD\xBE\xEF", buf = buffer.fromstring("\xDE\xAD\xBE\xEF") },
	{ hex = "00112233", bytes = "\x00\x11\x22\x33", buf = buffer.fromstring("\x00\x11\x22\x33") },
}

describe("Conversions", function()
	describe("ToHex", function()
		it.each(testCases)("should convert '$bytes' buffer to hex correctly", function(testCase)
			expect(Conversions.ToHex(testCase.buf)).toBe(testCase.hex)
		end)
	end)
	describe("FromHex", function()
		it.each(testCases)("should convert '$hex' hex to buffer correctly", function(testCase)
			expect(buffer.tostring(Conversions.FromHex(testCase.hex))).toBe(buffer.tostring(testCase.buf))
		end)
	end)
	describe("BytesStrToHex", function()
		it.each(testCases)("should convert '$bytes' bytes string to hex correctly", function(testCase)
			expect(Conversions.BytesStrToHex(testCase.bytes)).toBe(testCase.hex)
		end)
	end)
	describe("HexToBytesStr", function()
		it.each(testCases)("should convert '$hex' hex to bytes string correctly", function(testCase)
			expect(Conversions.HexToBytesStr(testCase.hex)).toBe(testCase.bytes)
		end)
	end)
end)
