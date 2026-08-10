--[=[
	ChaCha20 & XChaCha20 Stream Cipher Tadashi Test Suite

	The AEAD constructions (ChaCha20-Poly1305 and XChaCha20-Poly1305) live in
	tests/AEAD.luau. This file covers the raw stream ciphers.

	Test Vector Sources:
		ChaCha20:  https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/chacha20_test.json
		XChaCha20: https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/xchacha20_test.json
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("../Bridge")
local Testing = require("../")

local AEAD = require("../../src/Encryption/AEAD")
local FromHex = Testing.FromHex
local ToHex = Testing.ToHex

type ChaChaTest = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	key: string?,
	iv: string?,
	counter: number?,
	msg: string?,
	ct: string?,
	nonce: string?,
	subkey: string?,
	result: string,
}

type ChaChaGroup = {
	type: string,
	tests: {ChaChaTest},
}

type ChaChaData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {ChaChaGroup},
}

local CHACHA20_URL = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/chacha20_test.json"
local XCHACHA20_URL = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/xchacha20_test.json"

local function FetchTestVectors(Url: string): ChaChaData
	local Response = Bridge.Get(Url)
	return Bridge.JSONDecode(Response) :: ChaChaData
end

local function RunChaChaTests(Data: ChaChaData, IsXChaCha: boolean)
	for GroupIndex, Group in ipairs(Data.testGroups) do
		Testing.Describe(`Group_{GroupIndex}: {Data.algorithm} ({Group.type})`, function()
			for _, Test in ipairs(Group.tests) do
				local TestId = Test.tcId
				local Comment = Test.comment or ""

				local TestName = `Test_{TestId}`
				if Comment ~= "" then
					TestName = `Test_{TestId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local Key = FromHex(Test.key :: string)

					if Group.type == "HChaCha20" then
						local Nonce = FromHex(Test.nonce :: string)
						local Subkey = AEAD.Internal.HChaCha20(Key, Nonce, 20)
						Testing.Expect(ToHex(Subkey)).ToBe(Test.subkey :: string)
						return
					end

					local Iv = FromHex(Test.iv :: string)
					local Msg = FromHex(Test.msg :: string)
					local ExpectedCt = Test.ct :: string

					local Ct
					if IsXChaCha then
						Ct = AEAD.XChaCha20(Msg, Key, Iv, Test.counter :: number, 20)
					else
						Ct = AEAD.ChaCha20(Msg, Key, Iv, Test.counter :: number, 20)
					end

					Testing.Expect(ToHex(Ct)).ToBe(ExpectedCt)
				end)
			end
		end)
	end
end

Testing.Describe("ChaCha20 Tadashi Tests", function()
	local Data = FetchTestVectors(CHACHA20_URL)
	RunChaChaTests(Data, false)
end)

Testing.Describe("XChaCha20 Tadashi Tests", function()
	local Data = FetchTestVectors(XCHACHA20_URL)
	RunChaChaTests(Data, true)
end)

Testing.Complete()

return 0
