--[=[
	ChaCha20-Poly1305 & XChaCha20-Poly1305 Tadashi Test Suite

	Test Vector Sources:
		ChaCha20:  https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/chacha20_poly1305_test.json
		XChaCha20: https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/xchacha20_poly1305_test.json
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("./Bridge")
local IsCLI = Bridge.IsCLI
local Testing = require("./")

local AEAD: any = if IsCLI then require("../src/Encryption/AEAD") else require("../Encryption/AEAD")
local FromHex = Testing.FromHex
local BuffersEqual = Testing.BuffersEqual

type AeadTest = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	key: string,
	iv: string,
	aad: string?,
	msg: string,
	ct: string,
	tag: string,
	result: string,
}

type AeadGroup = {
	type: string,
	keySize: number,
	ivSize: number,
	tagSize: number,
	source: {name: string, version: string}?,
	tests: {AeadTest},
}

type AeadData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {AeadGroup},
}

local CHACHA20_URL = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/chacha20_poly1305_test.json"
local XCHACHA20_URL = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/xchacha20_poly1305_test.json"

local function FetchTestVectors(Url: string): AeadData
	local Response = Bridge.Get(Url)
	return Bridge.JSONDecode(Response) :: AeadData
end

local function RunAeadTests(Data: AeadData, IsXChaCha: boolean)
	for GroupIndex, Group in ipairs(Data.testGroups) do
		local IvSize = Group.ivSize
		local KeySize = Group.keySize
		local TagSize = Group.tagSize

		local SourceName = if Group.source then Group.source.name else "tadashi"

		Testing.Describe(`Group_{GroupIndex}: {KeySize}bit_Key_{IvSize}bit_IV_{TagSize}bit_Tag (Source: {SourceName})`, function()
			for _, Test in ipairs(Group.tests) do
				local TestId = Test.tcId
				local Comment = Test.comment or ""
				local ExpectedResult = Test.result

				local TestName = `Test_{TestId}`
				if Comment ~= "" then
					TestName = `Test_{TestId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local Key = FromHex(Test.key)
					local Iv = FromHex(Test.iv)
					local Aad = FromHex(Test.aad or "")
					local Msg = FromHex(Test.msg)
					local ExpectedCt = FromHex(Test.ct)
					local ExpectedTag = FromHex(Test.tag)

					if ExpectedResult == "valid" then
						local Ct, Tag
						if IsXChaCha then
							Ct, Tag = AEAD.Encrypt(Msg, Key, Iv, Aad, 20, true)
						else
							Ct, Tag = AEAD.Encrypt(Msg, Key, Iv, Aad)
						end

						Testing.Expect(BuffersEqual(Ct, ExpectedCt)).ToBe(true)
						Testing.Expect(BuffersEqual(Tag, ExpectedTag)).ToBe(true)

						local Plaintext
						if IsXChaCha then
							Plaintext = AEAD.Decrypt(Ct, Key, Iv, Tag, Aad, 20, true)
						else
							Plaintext = AEAD.Decrypt(Ct, Key, Iv, Tag, Aad)
						end

						Testing.Expect(Plaintext).ToBeDefined()
						if Plaintext then
							Testing.Expect(BuffersEqual(Plaintext, Msg)).ToBe(true)
						end
					elseif ExpectedResult == "invalid" then
						local Plaintext
						if IsXChaCha then
							Plaintext = AEAD.Decrypt(ExpectedCt, Key, Iv, ExpectedTag, Aad, 20, true)
						else
							Plaintext = AEAD.Decrypt(ExpectedCt, Key, Iv, ExpectedTag, Aad)
						end

						Testing.Expect(Plaintext).ToBeNil()
					end
				end)
			end
		end)
	end
end

Testing.Describe("ChaCha20-Poly1305 Tadashi Tests", function()
	local Data = FetchTestVectors(CHACHA20_URL)
	RunAeadTests(Data, false)
end)

Testing.Describe("XChaCha20-Poly1305 Tadashi Tests", function()
	local Data = FetchTestVectors(XCHACHA20_URL)
	RunAeadTests(Data, true)
end)

Testing.Complete()

return 0
