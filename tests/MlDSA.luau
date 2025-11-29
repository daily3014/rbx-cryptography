--[=[
	ML-DSA-87 Wycheproof Test Suite

	Test Vector Sources:
		Sign: https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/mldsa_87_sign_seed_test.json
		Verify: https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/mldsa_87_verify_test.json
	
	Test Categories:
		ValidSignature - Ordinary valid signatures
		ModifiedSignature - Bit-flipped signatures
		InvalidContext - Context exceeds 255 bytes
		InvalidHintsEncoding - Malformed hint encoding
		IncorrectPublicKeyLength / IncorrectSignatureLength - Wrong sizes
		BoundaryCondition / ManySteps - Edge cases
--]=]

--!strict
--!optimize 2

local Http = game:GetService("HttpService")

local Testing = require("./")
local Cryptography = require("../")

local MlDSA = Cryptography.Verification.MlDSA
local Conversions = Cryptography.Utilities.Conversions
local FromHex = Conversions.FromHex

type VerifyTest = {
	tcId: number,
	comment: string?,
	flags: {string}?,
	msg: string,
	sig: string,
	ctx: string?,
	result: string,
}

type VerifyGroup = {
	type: string,
	publicKey: string,
	tests: {VerifyTest},
}

type VerifyData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {VerifyGroup},
}

type SignTest = {
	tcId: number,
	comment: string?,
	flags: {string}?,
	msg: string,
	sig: string,
	ctx: string?,
	result: string?,
}

type SignGroup = {
	type: string,
	privateSeed: string,
	publicKey: string,
	source: {name: string, version: string}?,
	tests: {SignTest},
}

type SignData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {SignGroup},
}

local SIGN_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/mldsa_87_sign_seed_test.json"
local VERIFY_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/mldsa_87_verify_test.json"

local function BuffersEqual(A: buffer, B: buffer): boolean
	if buffer.len(A) ~= buffer.len(B) then
		return false
	end

	for Index = 0, buffer.len(A) - 1 do
		if buffer.readu8(A, Index) ~= buffer.readu8(B, Index) then
			return false
		end
	end

	return true
end

local function FetchVerifyVectors(): VerifyData
	local Response = Http:GetAsync(VERIFY_URL)
	return Http:JSONDecode(Response) :: VerifyData
end

local function FetchSignVectors(): SignData
	local Response = Http:GetAsync(SIGN_URL)
	return Http:JSONDecode(Response) :: SignData
end

Testing.Describe("ML-DSA-87 Wycheproof Tests", function()
	Testing.Describe("Verify Tests", function()
		local VerifyData = FetchVerifyVectors()

		for GroupIndex, Group in ipairs(VerifyData.testGroups) do
			local PublicKeyBytes = FromHex(Group.publicKey)

			Testing.Describe(`VerifyGroup_{GroupIndex}`, function()
				for _, Test in ipairs(Group.tests) do
					local TestId = Test.tcId
					local Comment = Test.comment or ""
					local Flags = Test.flags or {}

					local TestName = `Test_{TestId}`
					if Comment ~= "" then
						TestName = `Test_{TestId}_{Comment:sub(1, 25):gsub(" ", "_")}`
					end

					Testing.Test(TestName, function()
						local MessageBytes = FromHex(Test.msg)
						local SignatureBytes = FromHex(Test.sig)
						local Context = if Test.ctx then FromHex(Test.ctx) else buffer.create(0)
						local ExpectedResult = Test.result

						local Success, IsValid = pcall(function()
							return MlDSA.ML_DSA_87.Verify(PublicKeyBytes, MessageBytes, Context, SignatureBytes)
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

	Testing.Describe("Sign Tests", function()
		local SignData = FetchSignVectors()

		for GroupIndex, Group in ipairs(SignData.testGroups) do
			local PrivateSeedBytes = FromHex(Group.privateSeed)
			local ExpectedPubKeyBytes = FromHex(Group.publicKey)
			local SourceName = if Group.source then Group.source.name else "unknown"

			Testing.Describe(`SignGroup_{GroupIndex} (Source: {SourceName})`, function()
				Testing.Test("KeyGen_PublicKey_Match", function()
					local PubKey = buffer.create(MlDSA.ML_DSA_87.PubKeyByteLen)
					local SecKey = buffer.create(MlDSA.ML_DSA_87.SecKeyByteLen)
					MlDSA.ML_DSA_87.KeyGen(PrivateSeedBytes, PubKey, SecKey)

					Testing.Expect(BuffersEqual(PubKey, ExpectedPubKeyBytes)).ToBe(true)
				end)

				for _, Test in ipairs(Group.tests) do
					local TestId = Test.tcId
					local Comment = Test.comment or ""
					local Flags = Test.flags or {}
					local ExpectedResult = Test.result or "valid"

					local TestName = `Test_{TestId}`
					if Comment ~= "" then
						TestName = `Test_{TestId}_{Comment:sub(1, 25):gsub(" ", "_")}`
					end

					local HasInvalidContext = table.find(Flags, "InvalidContext") ~= nil

					Testing.Test(TestName, function()
						local MessageBytes = FromHex(Test.msg)
						local Context = if Test.ctx then FromHex(Test.ctx) else buffer.create(0)

						local PubKey = buffer.create(MlDSA.ML_DSA_87.PubKeyByteLen)
						local SecKey = buffer.create(MlDSA.ML_DSA_87.SecKeyByteLen)
						MlDSA.ML_DSA_87.KeyGen(PrivateSeedBytes, PubKey, SecKey)

						local ZeroRnd = buffer.create(32)
						local ComputedSig = buffer.create(MlDSA.ML_DSA_87.SigByteLen)

						local SignSuccess = MlDSA.ML_DSA_87.Sign(ZeroRnd, SecKey, MessageBytes, Context, ComputedSig)

						if HasInvalidContext or ExpectedResult == "invalid" then
							Testing.Expect(SignSuccess).ToBe(false)
						else
							Testing.Expect(SignSuccess).ToBe(true)

							local ExpectedSigBytes = FromHex(Test.sig)
							Testing.Expect(BuffersEqual(ComputedSig, ExpectedSigBytes)).ToBe(true)
						end
					end)
				end
			end)
		end
	end)
end)

Testing.Complete()

return 0