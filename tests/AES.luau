--!strict
type TestVector = {
	Description: string,
	Key: string,
	Input: string,
	Expected: string,
	Mode: any?,
	IV: string?,
	Padding: any?,
}

type TestVectors = { [string]: TestVector }

local AlgorithmName = script.Parent.Name
local Algorithm = require(script.Parent)

local function HexToBuf(Hex: string): buffer
	local Len = #Hex
	local Buf = buffer.create(Len / 2)
	for I = 0, Len - 2, 2 do
		buffer.writeu8(Buf, I / 2, tonumber(string.sub(Hex, I + 1, I + 2), 16) :: number)
	end
	return Buf
end

local function BufToHex(Buf: buffer): string
	local Hex = ""
	for I = 0, buffer.len(Buf) - 1 do
		Hex ..= string.format("%02x", buffer.readu8(Buf, I))
	end
	return Hex
end

local TestVectors: TestVectors = {
	["AES128_Block_Encrypt"] = {
		Description = "AES-128 Single Block Encryption",
		Key = "b2e231d5c056db0f58f1d87a7da1610d",
		Input = "a4e25a670d18a86fed98b8f1c0d2da5b",
		Expected = "898df1706c354123f7e08762290e4e42",
	},

	-- ECB Mode Tests
	["ECB_256_Encrypt"] = {
		Description = "AES-256 ECB Mode Encryption",
		Key = "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558",
		Input = "00000000000000000000000000000000",
		Expected = "46f2fb342d6f0ab477476fc501242c5f",
		Mode = "ECB",
		Padding = "None",
	},

	-- CBC Mode Tests
	["CBC_256_Encrypt"] = {
		Description = "AES-256 CBC Mode Encryption",
		Key = "8000000000000000000000000000000000000000000000000000000000000000",
		Input = "0000000000000000000000000000000000000000000000000000000000000001",
		Expected = "e35a6dcb19b201a01ebcfa8aa22b575925feaa2c9229b2a308ec4d68efeffd9f",
		Mode = "CBC",
		Padding = "None",
	},

	-- PCBC Mode Tests
	["PCBC_128_Encrypt"] = {
		Description = "AES-128 PCBC Mode Encryption",
		Key = "42424242424242424242424242424242",
		Input = "68656c6c6f20776f726c64212074686973206973206d7920706c61696e746578",
		Expected = "c7fe247ef97b21f07cbdd26cb5d346bfab13156d0b2f05f91c4837db5157bad5",
		Mode = "PCBC",
		IV = "24242424242424242424242424242424",
		Padding = "None",
	},

	-- CFB Mode Tests
	["CFB_192_Encrypt"] = {
		Description = "AES-192 CFB Mode Encryption",
		Key = "110e52b230ff77250a178734ce6917665871d8ace6233728",
		Input = "1000000000000000000000000000000000000000000000000000000000000000",
		Expected = "c2a36abc7e7cdbe2eb078f1a2c3f777d06c9cf5731d501daaa5fe5d606a33d85",
		Mode = "CFB",
		Padding = "None",
	},

	-- OFB Mode Tests
	["OFB_128_Encrypt"] = {
		Description = "AES-128 OFB Mode Encryption",
		Key = "ff000000000000000000000000000000",
		Input = "66428ac6a7b5ae282a0088a053c31b0ffdeca92fdbb660dc82419829877a8aee",
		Expected = "d795d2e3cc9d53ad20d41ce25b0c0a5a6e2ea001b77ff16a2e06c1e07b53faee",
		Mode = "OFB",
		Padding = "None",
	},

	-- CTR Mode Tests
	["CTR_128_Encrypt"] = {
		Description = "AES-128 CTR Mode Encryption (Little Endian)",
		Key = "42424242424242424242424242424242",
		Input = "68656c6c6f20776f726c64212074686973206973206d7920706c61696e746578",
		Expected = "3357121ebb5a29468bd861467596ce3da59bdee42dcc0614dea955368d8a5dc0",
		Mode = "CTR",
		IV = "24242424242424242424242424242424",
		Padding = "None",
	},
}

local function TestKeyExpansion()
	local TestKey = HexToBuf("b2e231d5c056db0f58f1d87a7da1610d")
	local Cipher = Algorithm.New(TestKey, Algorithm.Modes.ECB, Algorithm.Pads.None)
	local ExpandedKey = Cipher:ExpandKey(TestKey)

	assert(Cipher.RoundKeys == buffer.tostring(ExpandedKey), "Key expansion test failed: Round keys don't match")
	warn(`{AlgorithmName}: Key Expansion test passed`)
end

local function TestCipherFromKey()
	local TestKey = HexToBuf("b2e231d5c056db0f58f1d87a7da1610d")
	local Cipher1 = Algorithm.New(TestKey, Algorithm.Modes.ECB, Algorithm.Pads.None)
	local ExpandedKey = Cipher1:ExpandKey(TestKey)

	assert(
		Cipher1.RoundKeys == buffer.tostring(ExpandedKey),
		"Key expansion consistency test failed: Round keys don't match"
	)
	warn(`{AlgorithmName}: Key Expansion Consistency test passed`)
end

TestKeyExpansion()
TestCipherFromKey()

for TestName, TestVector in TestVectors do
	local KeyBuf = HexToBuf(TestVector.Key)
	local InputBuf = HexToBuf(TestVector.Input)
	local Cipher

	if TestVector.Mode and TestVector.Padding then
		local Mode = Algorithm.Modes[TestVector.Mode]
		local Padding = Algorithm.Pads[TestVector.Padding]

		if TestVector.Mode == "CTR" and TestVector.IV then
			Mode = Algorithm.Modes.CTR
			Mode.InitValue = string.rep("\36", 16)
			Mode.LittleEndian = true
		end

		Cipher = Algorithm.New(KeyBuf, Mode, Padding)

		if TestVector.IV and TestVector.Mode ~= "CTR" then
			local IVBuf = HexToBuf(TestVector.IV)
			local Result = Cipher:Encrypt(InputBuf, nil, IVBuf)
			local ResultHex = BufToHex(Result)

			local ErrorMessage = string.format(
				"%s: Test '%s' (%s) produced incorrect result. Expected '%s', got '%s'",
				AlgorithmName,
				TestName,
				TestVector.Description,
				TestVector.Expected,
				ResultHex
			)

			assert(ResultHex == TestVector.Expected, ErrorMessage)
		else
			local Result = Cipher:Encrypt(InputBuf)
			local ResultHex = BufToHex(Result)

			local ErrorMessage = string.format(
				"%s: Test '%s' (%s) produced incorrect result. Expected '%s', got '%s'",
				AlgorithmName,
				TestName,
				TestVector.Description,
				TestVector.Expected,
				ResultHex
			)

			assert(ResultHex == TestVector.Expected, ErrorMessage)
		end
	else
		Cipher = Algorithm.New(KeyBuf, Algorithm.Modes.ECB, Algorithm.Pads.None)
		Cipher:EncryptBlock(InputBuf, 0)
		local ResultHex = BufToHex(InputBuf)

		local ErrorMessage = string.format(
			"%s: Test '%s' (%s) produced incorrect result. Expected '%s', got '%s'",
			AlgorithmName,
			TestName,
			TestVector.Description,
			TestVector.Expected,
			ResultHex
		)

		assert(ResultHex == TestVector.Expected, ErrorMessage)
	end

	warn(`{AlgorithmName}: Test '{TestVector.Description}' passed`)
end

warn(`{AlgorithmName}: Running decryption tests...`)

local TestKey = HexToBuf("b2e231d5c056db0f58f1d87a7da1610d")
local TestBlock = HexToBuf("898df1706c354123f7e08762290e4e42")
local Cipher = Algorithm.New(TestKey, Algorithm.Modes.ECB, Algorithm.Pads.None)
Cipher:DecryptBlock(TestBlock, 0)
assert(BufToHex(TestBlock) == "a4e25a670d18a86fed98b8f1c0d2da5b", "Block decryption test failed")
warn(`{AlgorithmName}: Block Decryption test passed`)

print(`[{AlgorithmName}] All test cases passed`)
return 0
