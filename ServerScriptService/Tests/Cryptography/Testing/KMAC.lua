-- @ScriptType: ModuleScript
--[=[
	KMAC Wycheproof Test Suite
	
	Validates KMAC implementations against Google's Wycheproof test vectors.
	Covers MAC generation and verification with various key and message sizes.
	
	Test Vector Sources:
		KMAC128 (no customization): https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/kmac128_no_customization_test.json
		KMAC256 (no customization): https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/kmac256_no_customization_test.json
	
	Test Categories:
		Pseudorandom - Various input sizes for correctness testing
		ModifiedTag - Tampered MACs to verify full tag checking
--]=]

--!strict
--!optimize 2

local Http = game:GetService("HttpService")

local Testing = require("./")
local Cryptography = require("../")
local KMAC = Cryptography.Hashing.KMAC
local Conversions = Cryptography.Utilities.Conversions
local FromHex = Conversions.FromHex

type MacTest = {
	tcId: number,
	comment: string?,
	flags: {string}?,
	key: string,
	msg: string,
	tag: string,
	result: string,
}

type MacGroup = {
	type: string,
	keySize: number,
	tagSize: number,
	source: {name: string, version: string}?,
	tests: {MacTest},
}

type MacData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {MacGroup},
}

type KmacConfig = {
	Name: string,
	Url: string,
	KmacFunc: (buffer, buffer, buffer, buffer?) -> (string, buffer),
}

local KMAC_CONFIGS: {KmacConfig} = {
	{
		Name = "KMAC128",
		Url = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/kmac128_no_customization_test.json",
		KmacFunc = KMAC.KMAC128,
	},
	{
		Name = "KMAC256",
		Url = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/kmac256_no_customization_test.json",
		KmacFunc = KMAC.KMAC256,
	},
}

local function FetchTestVectors(Url: string): MacData
	local Response = Http:GetAsync(Url)
	return Http:JSONDecode(Response) :: MacData
end

local function RunKmacTests(Config: KmacConfig)
	Testing.Describe(`{Config.Name} Wycheproof Tests`, function()
		local Data = FetchTestVectors(Config.Url)

		for GroupIndex, Group in ipairs(Data.testGroups) do
			local KeySize = Group.keySize
			local TagSize = Group.tagSize
			local SourceName = if Group.source then Group.source.name else "unknown"

			Testing.Describe(`Group_{GroupIndex}: {KeySize}bit_Key_{TagSize}bit_Tag (Source: {SourceName})`, function()
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
						local Msg = FromHex(Test.msg)
						local ExpectedTag = Test.tag:lower()
						local ExpectedTagBytes = TagSize // 8

						local Output = buffer.create(ExpectedTagBytes)

						local ComputeOk, Result, _ = pcall(function()
							return Config.KmacFunc(Msg, Key, Output, buffer.create(0))
						end)

						if ExpectedResult == "valid" then
							Testing.Expect(ComputeOk).ToBe(true)
							Testing.Expect(Result).ToBeDefined()

							if ComputeOk and Result then
								local ComputedTag = Result:lower()
								Testing.Expect(ComputedTag).ToBe(ExpectedTag)
							end
						elseif ExpectedResult == "invalid" then
							if ComputeOk and Result then
								local ComputedTag = Result:lower()
								Testing.Expect(ComputedTag).Never.ToBe(ExpectedTag)
							else
								Testing.Expect(true).ToBe(true)
							end
						elseif ExpectedResult == "acceptable" then
							Testing.Expect(true).ToBe(true)
						end
					end)
				end
			end)
		end
	end)
end

for _, Config in ipairs(KMAC_CONFIGS) do
	RunKmacTests(Config)
end

Testing.Complete()

return 0