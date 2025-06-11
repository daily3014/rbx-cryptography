--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)
local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local HMAC = Cryptography.Hashing.HMAC
local MD5 = Cryptography.Hashing.MD5
local SHA256 = Cryptography.Hashing.SHA2.SHA256
local SHA512 = Cryptography.Hashing.SHA2.SHA512

local hmacMD5TestCases = {
	{
		description = "HMAC-MD5 Test Case 1",
		message = "Hi There",
		key = string.rep("\x0b", 16),
		expected = "9294727a3638bb1c13f48ef8158bfc9d",
	},
	{
		description = "HMAC-MD5 Test Case 2",
		message = "what do ya want for nothing?",
		key = "Jefe",
		expected = "750c783e6ab0b503eaa86e310a5db738",
	},
	{
		description = "HMAC-MD5 Test Case 3",
		message = string.rep("\xdd", 50),
		key = string.rep("\xaa", 16),
		expected = "56be34521d144c88dbb8c733f0e8b3f6",
	},
	{
		description = "HMAC-MD5 Test Case 4",
		message = string.rep("\xcd", 50),
		key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
		expected = "697eaf0aca3a3aea3a75164746ffaa79",
	},
	{
		description = "HMAC-MD5 Test Case 5",
		message = "Test With Truncation",
		key = string.rep("\x0c", 16),
		expected = "56461ef2342edc00f9bab995690efd4c",
	},
	{
		description = "HMAC-MD5 Test Case 6",
		message = "Test Using Larger Than Block-Size Key - Hash Key First",
		key = string.rep("\xaa", 80),
		expected = "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
	},
	{
		description = "HMAC-MD5 Test Case 7",
		message = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
		key = string.rep("\xaa", 80),
		expected = "6f630fad67cda0ee1fb1f562db3aa53e",
	},
}

local hmacSHA256TestCases = {
	{
		description = "HMAC-SHA-256 Test Case 1",
		message = "Hi There",
		key = string.rep("\x0b", 20),
		expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
	},
	{
		description = "HMAC-SHA-256 Test Case 2",
		message = "what do ya want for nothing?",
		key = "Jefe",
		expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
	},
	{
		description = "HMAC-SHA-256 Test Case 3",
		message = string.rep("\xdd", 50),
		key = string.rep("\xaa", 20),
		expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
	},
	{
		description = "HMAC-SHA-256 Test Case 4",
		message = string.rep("\xcd", 50),
		key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
		expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
	},
	{
		description = "HMAC-SHA-256 Test Case 5 (Truncated)",
		message = "Test With Truncation",
		key = string.rep("\x0c", 20),
		expected = "a3b6167473100ee06e0c796c2955552b",
		truncate = true,
	},
	{
		description = "HMAC-SHA-256 Test Case 6",
		message = "Test Using Larger Than Block-Size Key - Hash Key First",
		key = string.rep("\xaa", 131),
		expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
	},
	{
		description = "HMAC-SHA-256 Test Case 7",
		message = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
		key = string.rep("\xaa", 131),
		expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
	},
}

local hmacSHA512TestCases = {
	{
		description = "HMAC-SHA-512 Test Case 1",
		message = "Hi There",
		key = string.rep("\x0b", 20),
		expected = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
	},
	{
		description = "HMAC-SHA-512 Test Case 2",
		message = "what do ya want for nothing?",
		key = "Jefe",
		expected = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
	},
	{
		description = "HMAC-SHA-512 Test Case 3",
		message = string.rep("\xdd", 50),
		key = string.rep("\xaa", 20),
		expected = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
	},
	{
		description = "HMAC-SHA-512 Test Case 4",
		message = string.rep("\xcd", 50),
		key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
		expected = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
	},
	{
		description = "HMAC-SHA-512 Test Case 5 (Truncated)",
		message = "Test With Truncation",
		key = string.rep("\x0c", 20),
		expected = "415fad6271580a531d4179bc891d87a6",
		truncate = true,
	},
	{
		description = "HMAC-SHA-512 Test Case 6",
		message = "Test Using Larger Than Block-Size Key - Hash Key First",
		key = string.rep("\xaa", 131),
		expected = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
	},
	{
		description = "HMAC-SHA-512 Test Case 7",
		message = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
		key = string.rep("\xaa", 131),
		expected = "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
	},
}

describe("HMAC", function()
	describe("HMAC-MD5 (RFC 2202)", function()
		it.each(hmacMD5TestCases)("should compute $description correctly", function(testCase)
			local messageBuffer = buffer.fromstring(testCase.message)
			local keyBuffer = buffer.fromstring(testCase.key)
			local hashFunction = function(message: buffer): string
				return MD5(message)
			end
			
			local result = HMAC.HMAC(messageBuffer, keyBuffer, hashFunction, 64)
			
			expect(result).toBe(testCase.expected)
		end)
	end)
	
	describe("HMAC-SHA256 (RFC 4231)", function()
		it.each(hmacSHA256TestCases)("should compute $description correctly", function(testCase)
			local messageBuffer = buffer.fromstring(testCase.message)
			local keyBuffer = buffer.fromstring(testCase.key)
			local hashFunction = function(message: buffer): string
				return SHA256(message)
			end
			
			local result = HMAC.HMAC(messageBuffer, keyBuffer, hashFunction, 64)
			
			if testCase.truncate then
				result = string.sub(result, 1, 32)
			end
			
			expect(result).toBe(testCase.expected)
		end)
	end)
	
	describe("HMAC-SHA512 (RFC 4231)", function()
		it.each(hmacSHA512TestCases)("should compute $description correctly", function(testCase)
			local messageBuffer = buffer.fromstring(testCase.message)
			local keyBuffer = buffer.fromstring(testCase.key)
			local hashFunction = function(message: buffer): string
				return SHA512(message)
			end
			
			local result = HMAC.HMAC(messageBuffer, keyBuffer, hashFunction, 128)
			
			if testCase.truncate then
				result = string.sub(result, 1, 32)
			end
			
			expect(result).toBe(testCase.expected)
		end)
	end)
	
	describe("PresetHMAC", function()
		it("should create a preset HMAC function that works correctly", function()
			local hashFunction = function(message: buffer): string
				return MD5(message)
			end
			local presetHMAC = HMAC.PresetHMAC(hashFunction, 64)
			
			local testMessage = buffer.fromstring("Test message")
			local testKey = buffer.fromstring("test key")
			local result = presetHMAC(testMessage, testKey)
			
			-- Verify it returns a string
			expect(type(result)).toBe("string")
			
			-- Verify it produces the same result as the regular HMAC function
			local expectedResult = HMAC.HMAC(testMessage, testKey, hashFunction, 64)
			expect(result).toBe(expectedResult)
		end)
	end)
end)