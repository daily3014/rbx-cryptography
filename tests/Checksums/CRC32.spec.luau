--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)

local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local CRC32 = Cryptography.Checksums.CRC32

local testCases = {
	{
		input = "",
		description = "Empty String",
		iso = 0x00000000,
		jam = 0xFFFFFFFF,
	},
	{
		input = "The quick brown fox jumps over the lazy dog.",
		description = "pangramm",
		iso = 0x519025E9,
		jam = 0xAE6FDA16,
	},
	{
		input = "Привет, мир!",
		description = "utf-8 example",
		iso = 0x391651BC,
		jam = 0xC6E9AE43,
	},
	{
		input = "\0",
		description = "null terminator",
		iso = 0xD202EF8D,
		jam = 0x2DFD1072,
	},
	{
		input = string.rep("a", 55),
		description = "block of characters",
		iso = 0xAADFE34E,
		jam = 0x55201CB1,
	},
	{
		input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		description = "448 bit",
		iso = 0x171A3F5F,
		jam = 0xE8E5C0A0,
	},
	{
		input = string.rep("a", 111),
		description = "111 characters",
		iso = 0xD7EE9B8C,
		jam = 0x28116473,
	},
	{
		input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		description = "896 bits",
		iso = 0x191F3349,
		jam = 0xE6E0CCB6,
	},
	{
		input = string.rep("a", 119),
		description = "119 characters",
		iso = 0x4144EBAE,
		jam = 0xBEBB1451,
	},
	{
		input = string.rep("a", 239),
		description = "239 characters",
		iso = 0x5B34791C,
		jam = 0xA4CB86E3,
	},
	{
		input = string.rep("a", 1024),
		description = "1024 characters",
		iso = 0x7C5597B9,
		jam = 0x83AA6846,
	},
	{
		input = string.rep("a", 199999),
		description = "long string",
		iso = 0xB3D0F54D,
		jam = 0x4C2F0AB2,
	},
	{
		input = string.rep("a", 1e6),
		description = "million characters",
		iso = 0xDC25BFBC,
		jam = 0x23DA4043,
	},
}

describe("CRC32", function()
	describe("ISO-HDLC", function()
		describe("hex", function()
			it.each(testCases)("should compute $description correctly", function(testCase)
				local result = CRC32(buffer.fromstring(testCase.input), "Iso", true)
				expect(result).toBe(string.format("%08x", testCase.iso))
			end)
		end)
		describe("numeric", function()
			it.each(testCases)("should compute $description correctly", function(testCase)
				local result = CRC32(buffer.fromstring(testCase.input), "Iso", false)
				expect(result).toBe(testCase.iso)
			end)
		end)
	end)
	describe("JAM", function()
		describe("hex", function()
			it.each(testCases)("should compute $description correctly", function(testCase)
				local result = CRC32(buffer.fromstring(testCase.input), "Jam", true)
				expect(result).toBe(string.format("%08x", testCase.jam))
			end)
		end)
		describe("numeric", function()
			it.each(testCases)("should compute $description correctly", function(testCase)
				local result = CRC32(buffer.fromstring(testCase.input), "Jam", false)
				expect(result).toBe(testCase.jam)
			end)
		end)
	end)
end)
