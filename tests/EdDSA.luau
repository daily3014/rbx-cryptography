--[=[
	Ed25519 Tadashi Test Suite

	Test Vector Source:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/ed25519_test.json
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("./Bridge")
local IsCLI = Bridge.IsCLI
local Testing = require("./")

local EDDSA: any = if IsCLI then require("../src/Verification/EdDSA") else require("../Verification/EdDSA")
local FromHex = Testing.FromHex
local BuffersEqual = Testing.BuffersEqual

type Ed25519Test = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	sk: string,
	pk: string,
	msg: string,
	sig: string,
	result: string,
}

type Ed25519Group = {
	type: string,
	keySize: number?,
	tests: {Ed25519Test},
}

type Ed25519Data = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {Ed25519Group},
}

local ED25519_URL = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/ed25519_test.json"

Testing.Describe("Ed25519 Tadashi Tests", function()
	local Data = Bridge.JSONDecode(Bridge.Get(ED25519_URL)) :: Ed25519Data

	for GroupIndex, Group in ipairs(Data.testGroups) do
		Testing.Describe(`Group_{GroupIndex}: {Data.algorithm}`, function()
			for _, Test in ipairs(Group.tests) do
				local Comment = Test.comment or ""
				local TestName = `Test_{Test.tcId}`
				if Comment ~= "" then
					TestName = `Test_{Test.tcId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local Pk = FromHex(Test.pk)
					local Msg = FromHex(Test.msg)
					local Sig = FromHex(Test.sig)

					if Test.sk and #Test.sk > 0 and Test.result == "valid" then
						local Sk = FromHex(Test.sk)
						local DerivedPk = EDDSA.PublicKey(Sk)
						Testing.Expect(BuffersEqual(DerivedPk, Pk)).ToBe(true)

						local DerivedSig = EDDSA.Sign(Msg, Sk, Pk)
						Testing.Expect(BuffersEqual(DerivedSig, Sig)).ToBe(true)
					end

					local Verified = EDDSA.Verify(Msg, Pk, Sig)
					Testing.Expect(Verified).ToBe(Test.result == "valid")
				end)
			end
		end)
	end
end)

Testing.Complete()

return 0
