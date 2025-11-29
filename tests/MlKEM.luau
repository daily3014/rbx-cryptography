--[=[
	ML-KEM-1024 Wycheproof Test Suite
	
	Test Vector Source:
		https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/mlkem_1024_test.json
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
	tests: {WycheproofTest},
}

type WycheproofData = {
	algorithm: string,
	generatorVersion: string,
	numberOfTests: number,
	testGroups: {WycheproofGroup},
}

local WYCHEPROOF_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/mlkem_1024_test.json"

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

Testing.Describe("ML-KEM-1024 Wycheproof Tests", function()
	local Data = FetchTestVectors()

	for GroupIndex, Group in ipairs(Data.testGroups) do
		local GroupType = Group.type
		local SourceName = if Group.source then Group.source.name else "unknown"

		Testing.Describe(`Group_{GroupIndex}: {GroupType} (Source: {SourceName})`, function()
			for _, Test in ipairs(Group.tests) do
				local TestId = Test.tcId
				local Flags = Test.flags or {}
				local HasModulusOverflow = table.find(Flags, "ModulusOverflow") ~= nil

				if not Test.seed then
					Testing.Test(`Test_{TestId}_ValidationOnly`, function()
						if Test.ek and Test.m then
							local EK = FromHex(Test.ek)
							local M = FromHex(Test.m)
							local ExpectedResult = Test.result

							if HasModulusOverflow or ExpectedResult == "invalid" then
								Testing.Expect(function()
									MLKEM.MLKEM_1024.Encapsulate(EK, M)
								end).ToThrow()
							else
								local Ciphertext, SharedSecret = MLKEM.MLKEM_1024.Encapsulate(EK, M)
								Testing.Expect(Ciphertext).ToBeDefined()
								Testing.Expect(SharedSecret).ToBeDefined()
							end
						elseif Test.ek then
							local EK = FromHex(Test.ek)
							local SeedM = buffer.create(32)

							if HasModulusOverflow then
								Testing.Expect(function()
									MLKEM.MLKEM_1024.Encapsulate(EK, SeedM)
								end).ToThrow()
							else
								local Success, _ = pcall(function()
									return MLKEM.MLKEM_1024.Encapsulate(EK, SeedM)
								end)
								Testing.Expect(Success).ToBe(true)
							end
						end
					end)
				else
					Testing.Test(`Test_{TestId}`, function()
						local Seed = FromHex(Test.seed :: string)
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
							local ExpectedCT = FromHex(Test.c)
							local RecoveredSS = MLKEM.MLKEM_1024.Decapsulate(GeneratedSK, ExpectedCT)

							if Test.K then
								local ExpectedK = FromHex(Test.K)
								Testing.Expect(BuffersEqual(RecoveredSS, ExpectedK)).ToBe(true)
							else
								Testing.Expect(RecoveredSS).ToBeDefined()
							end
						end
					end)
				end
			end
		end)
	end
end)

Testing.Complete()

return 0