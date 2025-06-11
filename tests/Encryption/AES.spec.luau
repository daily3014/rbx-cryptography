--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)
local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local AES = Cryptography.Encryption.AES

local testCases = {
	{
		description = "AES-128 Single Block Encryption",
		key = "b2e231d5c056db0f58f1d87a7da1610d",
		input = "a4e25a670d18a86fed98b8f1c0d2da5b",
		expected = "898df1706c354123f7e08762290e4e42",
		mode = "ECB",
		padding = "None",
		blockMode = true,
	},
}

local ecbTestCases = {
	{
		description = "AES-256 ECB Mode Encryption",
		key = "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558",
		input = "00000000000000000000000000000000",
		expected = "46f2fb342d6f0ab477476fc501242c5f",
		mode = "ECB",
		padding = "None",
	},
}

local cbcTestCases = {
	{
		description = "AES-256 CBC Mode Encryption",
		key = "8000000000000000000000000000000000000000000000000000000000000000",
		input = "0000000000000000000000000000000000000000000000000000000000000001",
		expected = "e35a6dcb19b201a01ebcfa8aa22b575925feaa2c9229b2a308ec4d68efeffd9f",
		mode = "CBC",
		padding = "None",
	},
}

local pcbcTestCases = {
	{
		description = "AES-128 PCBC Mode Encryption",
		key = "42424242424242424242424242424242",
		input = "68656c6c6f20776f726c64212074686973206973206d7920706c61696e746578",
		expected = "c7fe247ef97b21f07cbdd26cb5d346bfab13156d0b2f05f91c4837db5157bad5",
		mode = "PCBC",
		iv = "24242424242424242424242424242424",
		padding = "None",
	},
}

local cfbTestCases = {
	{
		description = "AES-192 CFB Mode Encryption",
		key = "110e52b230ff77250a178734ce6917665871d8ace6233728",
		input = "1000000000000000000000000000000000000000000000000000000000000000",
		expected = "c2a36abc7e7cdbe2eb078f1a2c3f777d06c9cf5731d501daaa5fe5d606a33d85",
		mode = "CFB",
		padding = "None",
	},
}

local ofbTestCases = {
	{
		description = "AES-128 OFB Mode Encryption",
		key = "ff000000000000000000000000000000",
		input = "66428ac6a7b5ae282a0088a053c31b0ffdeca92fdbb660dc82419829877a8aee",
		expected = "d795d2e3cc9d53ad20d41ce25b0c0a5a6e2ea001b77ff16a2e06c1e07b53faee",
		mode = "OFB",
		padding = "None",
	},
}

local ctrTestCases = {
	{
		description = "AES-128 CTR Mode Encryption (Little Endian)",
		key = "42424242424242424242424242424242",
		input = "68656c6c6f20776f726c64212074686973206973206d7920706c61696e746578",
		expected = "3357121ebb5a29468bd861467596ce3da59bdee42dcc0614dea955368d8a5dc0",
		mode = "CTR",
		iv = "24242424242424242424242424242424",
		padding = "None",
	},
}

local function hexToBuf(hex: string): buffer
	local len = #hex
	local buf = buffer.create(len / 2)
	for i = 0, len - 2, 2 do
		buffer.writeu8(buf, i / 2, tonumber(string.sub(hex, i + 1, i + 2), 16) :: number)
	end
	return buf
end

local function bufToHex(buf: buffer): string
	local hex = ""
	for i = 0, buffer.len(buf) - 1 do
		hex ..= string.format("%02x", buffer.readu8(buf, i))
	end
	return hex
end

describe("AES", function()
	describe("Key Expansion", function()
		it("should expand keys correctly", function()
			local testKey = hexToBuf("b2e231d5c056db0f58f1d87a7da1610d")
			local cipher = AES.New(testKey, AES.Modes.ECB, AES.Pads.None)
			local expandedKey = cipher:ExpandKey(testKey)

			expect(cipher.RoundKeys).toBe(buffer.tostring(expandedKey))
		end)

		it("should maintain key expansion consistency", function()
			local testKey = hexToBuf("b2e231d5c056db0f58f1d87a7da1610d")
			local cipher1 = AES.New(testKey, AES.Modes.ECB, AES.Pads.None)
			local expandedKey = cipher1:ExpandKey(testKey)

			expect(cipher1.RoundKeys).toBe(buffer.tostring(expandedKey))
		end)
	end)

	describe("Block Encryption", function()
		it.each(testCases)("should encrypt $description correctly", function(testCase)
			local keyBuf = hexToBuf(testCase.key)
			local inputBuf = hexToBuf(testCase.input)
			local cipher = AES.New(keyBuf, AES.Modes[testCase.mode], AES.Pads[testCase.padding])

			cipher:EncryptBlock(inputBuf, 0)
			local resultHex = bufToHex(inputBuf)

			expect(resultHex).toBe(testCase.expected)
		end)
	end)

	describe("ECB Mode", function()
		it.each(ecbTestCases)("should encrypt $description correctly", function(testCase)
			local keyBuf = hexToBuf(testCase.key)
			local inputBuf = hexToBuf(testCase.input)
			local cipher = AES.New(keyBuf, AES.Modes[testCase.mode], AES.Pads[testCase.padding])

			local result = cipher:Encrypt(inputBuf)
			local resultHex = bufToHex(result)

			expect(resultHex).toBe(testCase.expected)
		end)
	end)

	describe("CBC Mode", function()
		it.each(cbcTestCases)("should encrypt $description correctly", function(testCase)
			local keyBuf = hexToBuf(testCase.key)
			local inputBuf = hexToBuf(testCase.input)
			local cipher = AES.New(keyBuf, AES.Modes[testCase.mode], AES.Pads[testCase.padding])

			local result = cipher:Encrypt(inputBuf)
			local resultHex = bufToHex(result)

			expect(resultHex).toBe(testCase.expected)
		end)
	end)

	describe("PCBC Mode", function()
		it.each(pcbcTestCases)("should encrypt $description correctly", function(testCase)
			local keyBuf = hexToBuf(testCase.key)
			local inputBuf = hexToBuf(testCase.input)
			local ivBuf = hexToBuf(testCase.iv)
			local cipher = AES.New(keyBuf, AES.Modes[testCase.mode], AES.Pads[testCase.padding])

			local result = cipher:Encrypt(inputBuf, nil, ivBuf)
			local resultHex = bufToHex(result)

			expect(resultHex).toBe(testCase.expected)
		end)
	end)

	describe("CFB Mode", function()
		it.each(cfbTestCases)("should encrypt $description correctly", function(testCase)
			local keyBuf = hexToBuf(testCase.key)
			local inputBuf = hexToBuf(testCase.input)
			local cipher = AES.New(keyBuf, AES.Modes[testCase.mode], AES.Pads[testCase.padding])

			local result = cipher:Encrypt(inputBuf)
			local resultHex = bufToHex(result)

			expect(resultHex).toBe(testCase.expected)
		end)
	end)

	describe("OFB Mode", function()
		it.each(ofbTestCases)("should encrypt $description correctly", function(testCase)
			local keyBuf = hexToBuf(testCase.key)
			local inputBuf = hexToBuf(testCase.input)
			local cipher = AES.New(keyBuf, AES.Modes[testCase.mode], AES.Pads[testCase.padding])

			local result = cipher:Encrypt(inputBuf)
			local resultHex = bufToHex(result)

			expect(resultHex).toBe(testCase.expected)
		end)
	end)

	describe("CTR Mode", function()
		it.each(ctrTestCases)("should encrypt $description correctly", function(testCase)
			local keyBuf = hexToBuf(testCase.key)
			local inputBuf = hexToBuf(testCase.input)

			local mode = AES.Modes.CTR
			mode.InitValue = string.rep("\36", 16)
			mode.LittleEndian = true

			local cipher = AES.New(keyBuf, mode, AES.Pads[testCase.padding])

			local result = cipher:Encrypt(inputBuf)
			local resultHex = bufToHex(result)

			expect(resultHex).toBe(testCase.expected)
		end)
	end)

	describe("Block Decryption", function()
		it("should decrypt blocks correctly", function()
			local testKey = hexToBuf("b2e231d5c056db0f58f1d87a7da1610d")
			local testBlock = hexToBuf("898df1706c354123f7e08762290e4e42")
			local cipher = AES.New(testKey, AES.Modes.ECB, AES.Pads.None)

			cipher:DecryptBlock(testBlock, 0)
			local resultHex = bufToHex(testBlock)

			expect(resultHex).toBe("a4e25a670d18a86fed98b8f1c0d2da5b")
		end)
	end)
end)
