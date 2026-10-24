--[=[
	AES-GCM Tadashi Test Suite

	Test Vector Source:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/aes_gcm_test.json

	Covers AES-128/192/256 GCM with 96-bit IVs plus the non-96-bit IV path
	(64-bit, 128-bit, 480-bit), which forces the J0 = GHASH(IV) derivation.
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("../Bridge")
local Testing = require("../")

local AES = require("../../src/Encryption/AES")
local FromHex = Testing.FromHex
local BuffersEqual = Testing.BuffersEqual

type AesTest = {
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

type AesGroup = {
	type: string,
	keySize: number,
	ivSize: number,
	tagSize: number,
	tests: {AesTest},
}

type AesData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {AesGroup},
}

local AES_GCM_URL = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/aes_gcm_test.json"

Testing.Describe("AES-GCM Tadashi Tests", function()
	local Data = Bridge.JSONDecode(Bridge.Get(AES_GCM_URL)) :: AesData

	for GroupIndex, Group in ipairs(Data.testGroups) do
		local KeySize = Group.keySize
		local IvSize = Group.ivSize
		local TagSize = Group.tagSize

		Testing.Describe(`Group_{GroupIndex}: AES-GCM ({KeySize}bit_Key_{IvSize}bit_IV_{TagSize}bit_Tag)`, function()
			for _, Test in ipairs(Group.tests) do
				local Comment = Test.comment or ""
				local TestName = `Test_{Test.tcId}`
				if Comment ~= "" then
					TestName = `Test_{Test.tcId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local Key = FromHex(Test.key)
					local Iv = FromHex(Test.iv)
					local AadBuf = FromHex(Test.aad or "")
					local Aad: buffer? = if buffer.len(AadBuf) > 0 then AadBuf else nil
					local Msg = FromHex(Test.msg)
					local ExpectedCt = FromHex(Test.ct)
					local ExpectedTag = FromHex(Test.tag)

					if Test.result == "valid" then
						local Ct, Tag = AES.Encrypt(Msg, Key, Iv, Aad)
						Testing.Expect(BuffersEqual(Ct, ExpectedCt)).ToBe(true)
						Testing.Expect(BuffersEqual(Tag, ExpectedTag)).ToBe(true)

						local Plaintext = AES.Decrypt(Ct, Key, Iv, Tag, Aad)
						Testing.Expect(Plaintext).ToBeDefined()
						if Plaintext then
							Testing.Expect(BuffersEqual(Plaintext, Msg)).ToBe(true)
						end
					elseif Test.result == "invalid" then
						local Ok, Plaintext = pcall(AES.Decrypt, ExpectedCt, Key, Iv, ExpectedTag, Aad)
						Testing.Expect(Ok == false or Plaintext == nil).ToBe(true)
					elseif Test.result == "acceptable" then
						local Ok, Plaintext = pcall(AES.Decrypt, ExpectedCt, Key, Iv, ExpectedTag, Aad)
						local Rejected = Ok == false or Plaintext == nil
						local Matched = Ok and Plaintext ~= nil and BuffersEqual(Plaintext :: buffer, Msg)
						Testing.Expect(Rejected or Matched).ToBe(true)
					end
				end)
			end
		end)
	end
end)

Testing.Complete()

return 0
