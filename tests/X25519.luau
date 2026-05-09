--[=[
	X25519 Wycheproof Test Suite

	Test Vector Source:
		https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/x25519_test.json

	Test Categories:
		Normal - Standard valid test cases
		Ktv - Known test vectors from RFC 7748
		Twist - Public keys on the twist of Curve25519
		LowOrderPublic - Small subgroup attack vectors
		NonCanonicalPublic - Non-reduced public keys
		SmallPublicKey - Insecure public keys
		ZeroSharedSecret - Cases producing all-zero output
		EdgeCaseMultiplication / EdgeCasePrivateKey / EdgeCaseShared - Arithmetic edge cases
--]=]

--!strict
--!optimize 2
local Bridge = require("./Bridge")
local IsCLI = Bridge.IsCLI
local Testing = require("./")

local Cryptography = if IsCLI then require("../src") else require("../")
local X25519 = Cryptography.Verification.EdDSA.X25519
local FromHex = Testing.FromHex
local ToHex = Testing.ToHex

type XdhTest = {
	tcId: number,
	comment: string?,
	flags: {string}?,
	public: string,
	private: string,
	shared: string,
	result: string,
}

type XdhGroup = {
	type: string,
	curve: string,
	source: {name: string, version: string}?,
	tests: {XdhTest},
}

type XdhData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {XdhGroup},
}

local WYCHEPROOF_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/x25519_test.json"

local function FetchTestVectors(): XdhData
	local Response = Bridge.Get(WYCHEPROOF_URL)
	return Bridge.JSONDecode(Response) :: XdhData
end

Testing.Describe("X25519 Wycheproof Tests", function()
	local Data = FetchTestVectors()

	for GroupIndex, Group in ipairs(Data.testGroups) do
		local Curve = Group.curve
		local SourceName = if Group.source then Group.source.name else "unknown"

		Testing.Describe(`Group_{GroupIndex}: {Curve} (Source: {SourceName})`, function()
			for _, Test in ipairs(Group.tests) do
				local TestId = Test.tcId
				local Comment = Test.comment or ""
				local ExpectedResult = Test.result

				local TestName = `Test_{TestId}`
				if Comment ~= "" then
					TestName = `Test_{TestId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local PrivateKey = FromHex(Test.private)
					local PublicKey = FromHex(Test.public)
					local ExpectedShared = Test.shared:lower()

					local Ok, Result = pcall(function()
						local SharedSecret = X25519.Exchange(PrivateKey, PublicKey)
						return ToHex(SharedSecret):lower()
					end)

					if ExpectedResult == "valid" then
						Testing.Expect(Ok).ToBe(true)
						Testing.Expect(Result).ToBe(ExpectedShared)
					elseif ExpectedResult == "invalid" then
						local Failed = not Ok or Result ~= ExpectedShared
						Testing.Expect(Failed).ToBe(true)
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
