--[=[
	HMAC Wycheproof Test Suite
	
	Validates HMAC implementations against Google's Wycheproof test vectors.
	Covers MAC generation and verification with various key and message sizes.
	
	Test Vector Sources:
		HMAC-SHA-256: https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/hmac_sha256_test.json
		HMAC-SHA3-512: https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/hmac_sha3_512_test.json
	
	Test Categories:
		Pseudorandom - Various input sizes for correctness testing
		ModifiedTag - Tampered MACs to verify full tag checking
	
	Endianness Note:
		SHA-256 uses big-endian output (default for HMAC)
		SHA3-512 uses little-endian output (requires explicit false parameter)
		This test suite validates both work correctly.
--]=]

--!strict
--!optimize 2

local Http = game:GetService("HttpService")

local Testing = require("./")
local Cryptography = require("../")
local HMAC = Cryptography.Hashing.HMAC
local SHA2 = Cryptography.Hashing.SHA2
local SHA3 = Cryptography.Hashing.SHA3
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

type HmacConfig = {
	Name: string,
	Url: string,
	HashFunc: (buffer, buffer?) -> (string, buffer),
	BlockSize: number,
	BigEndian: boolean,
}

local HMAC_CONFIGS: {HmacConfig} = {
	{
		Name = "HMAC-SHA-256",
		Url = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/hmac_sha256_test.json",
		HashFunc = SHA2.SHA256,
		BlockSize = 64,
		BigEndian = true,
	},
	{
		Name = "HMAC-SHA3-512",
		Url = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/hmac_sha3_512_test.json",
		HashFunc = SHA3.SHA3_512,
		BlockSize = 72,
		BigEndian = false,
	},
}

local function FetchTestVectors(Url: string): MacData
	local Response = Http:GetAsync(Url)
	return Http:JSONDecode(Response) :: MacData
end

local function RunHmacTests(Config: HmacConfig)
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

						local ComputeOk, Result, _ = pcall(function()
							return HMAC(Msg, Key, Config.HashFunc, Config.BlockSize, Config.BigEndian)
						end)

						if ExpectedResult == "valid" then
							Testing.Expect(ComputeOk).ToBe(true)
							Testing.Expect(Result).ToBeDefined()

							if ComputeOk and Result then
								local ComputedTag = string.sub(Result:lower(), 1, ExpectedTagBytes * 2)
								Testing.Expect(ComputedTag).ToBe(ExpectedTag)
							end
						elseif ExpectedResult == "invalid" then
							if ComputeOk and Result then
								local ComputedTag = string.sub(Result:lower(), 1, ExpectedTagBytes * 2)
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

for _, Config in ipairs(HMAC_CONFIGS) do
	RunHmacTests(Config)
end

Testing.Complete()

return 0