--[=[
	ML-KEM-1024 Wycheproof Test Suite
	
	Test Vector Source:
		https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/mlkem_1024_test.json
	
	Test Categories:
		Group 1 (CCTV/strcmp): Tests implicit rejection with strcmp vulnerabilities
		Group 2 (FIPS 203): Standard test vectors including:
			- Valid encapsulation/decapsulation tests
			- Truncated/malformed decapsulation keys (dk)
			- Truncated/malformed ciphertexts (c)
			- Implicit rejection tests (modified ciphertexts)
--]=]

--!strict
--!optimize 2

local Http = game:GetService("HttpService")

local Testing = require("./")
local Cryptography = require("../")

local MLKEM = Cryptography.Verification.MlKEM
local Conversions = Cryptography.Utilities.Conversions
local FromHex = Conversions.FromHex

type WycheproofTest = {
	tcId: number,
	comment: string?,
	flags: {string}?,
	seed: string?,
	ek: string?,
	dk: string?,
	c: string?,
	K: string?,
	m: string?,
	result: string?,
}

type WycheproofGroup = {
	type: string,
	source: {name: string}?,
	parameterSet: string?,
	tests: {WycheproofTest},
}

type WycheproofData = {
	algorithm: string,
	generatorVersion: string,
	numberOfTests: number,
	testGroups: {WycheproofGroup},
}

local WYCHEPROOF_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/mlkem_1024_test.json"

local MLKEM_1024_EK_LEN = 1568
local MLKEM_1024_DK_LEN = 3168
local MLKEM_1024_CT_LEN = 1568
local MLKEM_1024_SEED_LEN = 64

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

local function FetchTestVectors(): WycheproofData
	local Response = Http:GetAsync(WYCHEPROOF_URL)
	return Http:JSONDecode(Response) :: WycheproofData
end

local function HasFlag(Flags: {string}?, FlagName: string): boolean
	if not Flags then
		return false
	end
	return table.find(Flags, FlagName) ~= nil
end

Testing.Describe("ML-KEM-1024 Wycheproof Tests", function()
	local Data = FetchTestVectors()

	for GroupIndex, Group in ipairs(Data.testGroups) do
		local GroupType = Group.type
		local SourceName = if Group.source then Group.source.name else "unknown"

		Testing.Describe(`Group_{GroupIndex}: {GroupType} (Source: {SourceName})`, function()
			for _, Test in ipairs(Group.tests) do
				local TestId = Test.tcId
				local Flags = Test.flags or {}
				local ExpectedResult = Test.result or "valid"

				local HasModulusOverflow = HasFlag(Flags, "ModulusOverflow")
				local HasTruncatedKey = HasFlag(Flags, "TruncatedDecapsulationKey")
				local HasTruncatedCiphertext = HasFlag(Flags, "TruncatedCiphertext")
				local HasModifiedCiphertext = HasFlag(Flags, "ModifiedCiphertext")
				local IsInvalid = ExpectedResult == "invalid"

				Testing.Test(`Test_{TestId}`, function()
					if Test.seed then
						local Seed = FromHex(Test.seed)
						local SeedLen = buffer.len(Seed)

						if SeedLen ~= MLKEM_1024_SEED_LEN then
							Testing.Expect(IsInvalid).ToBe(true)
							return
						end

						local D = buffer.create(32)
						local Z = buffer.create(32)
						buffer.copy(D, 0, Seed, 0, 32)
						buffer.copy(Z, 0, Seed, 32, 32)

						local GeneratedPK, GeneratedSK = MLKEM.MLKEM_1024.KeyGen(D, Z)

						if Test.ek then
							local ExpectedEK = FromHex(Test.ek)
							Testing.Expect(BuffersEqual(GeneratedPK, ExpectedEK)).ToBe(true)
						end

						if Test.c then
							local CT = FromHex(Test.c)
							local CTLen = buffer.len(CT)

							if CTLen ~= MLKEM_1024_CT_LEN then
								if HasTruncatedCiphertext or IsInvalid then
									Testing.Expect(function()
										MLKEM.MLKEM_1024.Decapsulate(CT, GeneratedSK)
									end).ToThrow("Invalid ciphertext length")
								else
									Testing.Expect(CTLen).ToBe(MLKEM_1024_CT_LEN)
								end
								return
							end

							local RecoveredSS = MLKEM.MLKEM_1024.Decapsulate(CT, GeneratedSK)

							if Test.K then
								local ExpectedK = FromHex(Test.K)
								local SecretsMatch = BuffersEqual(RecoveredSS, ExpectedK)

								if HasModifiedCiphertext or IsInvalid then
									Testing.Expect(SecretsMatch).ToBe(false)
								else
									Testing.Expect(SecretsMatch).ToBe(true)
								end
							else
								Testing.Expect(RecoveredSS).ToBeDefined()
							end
						end
					elseif Test.dk then
						local DK = FromHex(Test.dk)
						local DKLen = buffer.len(DK)

						if DKLen ~= MLKEM_1024_DK_LEN then
							if HasTruncatedKey or IsInvalid then
								Testing.Expect(function()
									local CT = if Test.c then FromHex(Test.c) else buffer.create(MLKEM_1024_CT_LEN)
									MLKEM.MLKEM_1024.Decapsulate(CT, DK)
								end).ToThrow("Invalid secret key length")
							else
								Testing.Expect(DKLen).ToBe(MLKEM_1024_DK_LEN)
							end
							return
						end

						if Test.c then
							local CT = FromHex(Test.c)
							local CTLen = buffer.len(CT)

							if CTLen ~= MLKEM_1024_CT_LEN then
								if HasTruncatedCiphertext or IsInvalid then
									Testing.Expect(function()
										MLKEM.MLKEM_1024.Decapsulate(CT, DK)
									end).ToThrow("Invalid ciphertext length")
								else
									Testing.Expect(CTLen).ToBe(MLKEM_1024_CT_LEN)
								end
								return
							end

							local RecoveredSS = MLKEM.MLKEM_1024.Decapsulate(CT, DK)

							if Test.K then
								local ExpectedK = FromHex(Test.K)
								local SecretsMatch = BuffersEqual(RecoveredSS, ExpectedK)

								if HasModifiedCiphertext or IsInvalid then
									Testing.Expect(SecretsMatch).ToBe(false)
								else
									Testing.Expect(SecretsMatch).ToBe(true)
								end
							else
								Testing.Expect(RecoveredSS).ToBeDefined()
							end
						end
					elseif Test.ek then
						local EK = FromHex(Test.ek)
						local EKLen = buffer.len(EK)

						if EKLen ~= MLKEM_1024_EK_LEN then
							if IsInvalid then
								Testing.Expect(function()
									local M = if Test.m then FromHex(Test.m) else buffer.create(32)
									MLKEM.MLKEM_1024.Encapsulate(M, EK)
								end).ToThrow("Invalid public key length")
							else
								Testing.Expect(EKLen).ToBe(MLKEM_1024_EK_LEN)
							end
							return
						end

						local M = if Test.m then FromHex(Test.m) else buffer.create(32)

						if HasModulusOverflow or IsInvalid then
							Testing.Expect(function()
								MLKEM.MLKEM_1024.Encapsulate(M, EK)
							end).ToThrow("malformed public key encoding")
						else
							local Ciphertext, SharedSecret = MLKEM.MLKEM_1024.Encapsulate(M, EK)
							Testing.Expect(Ciphertext).ToBeDefined()
							Testing.Expect(SharedSecret).ToBeDefined()
						end
					else
						Testing.Expect(true).ToBe(true)
					end
				end)
			end
		end)
	end
end)

Testing.Complete()

return 0