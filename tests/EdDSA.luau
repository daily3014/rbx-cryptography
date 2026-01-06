--[=[
	Ed25519 Wycheproof Test Suite
	
	Test Vector Source:
		https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/ed25519_test.json
	
	Test Categories:
		Valid - Ordinary valid signatures
		InvalidSignature - Edge case values (0, group order)
		SignatureMalleability - S value range checks
		TruncatedSignature - Shortened signatures
		SignatureWithGarbage - Extra bytes appended
		InvalidEncoding - Malformed encodings
--]=]

--!strict
--!optimize 2

local Http = game:GetService("HttpService")

local Testing = require("./")
local Cryptography = require("../")

local Ed25519 = Cryptography.Verification.EdDSA
local Conversions = Cryptography.Utilities.Conversions
local FromHex = Conversions.FromHex

type PublicKeyInfo = {
	type: string,
	curve: string,
	keySize: number,
	pk: string,
}

type WycheproofTest = {
	tcId: number,
	comment: string?,
	flags: {string}?,
	msg: string,
	sig: string,
	result: string,
}

type WycheproofGroup = {
	type: string,
	source: {name: string, version: string}?,
	publicKey: PublicKeyInfo,
	publicKeyDer: string?,
	publicKeyPem: string?,
	tests: {WycheproofTest},
}

type WycheproofData = {
	algorithm: string,
	schema: string,
	numberOfTests: number,
	testGroups: {WycheproofGroup},
}

local WYCHEPROOF_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/ed25519_test.json"

local function FetchTestVectors(): WycheproofData
	local Response = Http:GetAsync(WYCHEPROOF_URL)
	return Http:JSONDecode(Response) :: WycheproofData
end

Testing.Describe("Ed25519 Wycheproof Tests", function()
	local Data = FetchTestVectors()

	for GroupIndex, Group in ipairs(Data.testGroups) do
		local PublicKeyHex = Group.publicKey.pk
		local PublicKeyBytes = FromHex(PublicKeyHex)
		local SourceName = if Group.source then Group.source.name else "unknown"

		Testing.Describe(`Group_{GroupIndex}: {Group.type} (Source: {SourceName})`, function()
			for _, Test in ipairs(Group.tests) do
				local TestId = Test.tcId
				local ExpectedResult = Test.result
				local Comment = Test.comment or ""

				local TestName = `Test_{TestId}`
				if Comment ~= "" then
					TestName = `Test_{TestId}_{Comment:sub(1, 30):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local MessageBytes = FromHex(Test.msg)
					local SignatureBytes = FromHex(Test.sig)

					local Success, IsValid = pcall(function()
						return Ed25519.Verify(PublicKeyBytes, MessageBytes, SignatureBytes)
					end)

					if ExpectedResult == "valid" then
						Testing.Expect(Success).ToBe(true)
						Testing.Expect(IsValid).ToBe(true)
					elseif ExpectedResult == "invalid" then
						local VerificationFailed = not Success or not IsValid
						Testing.Expect(VerificationFailed).ToBe(true)
					elseif ExpectedResult == "acceptable" then
						Testing.Expect(true).ToBe(true)
					end
				end)
			end
		end)
	end
end)

Testing.Complete()

return 0