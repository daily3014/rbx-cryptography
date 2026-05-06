--[=[
	HKDF Wycheproof Test Suite
	
	Validates HKDF implementation against Google's Wycheproof test vectors.
	Covers extract-then-expand key derivation with various IKM, salt, info, and output sizes.
	
	Test Vector Sources:
		HKDF-SHA-256: https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/hkdf_sha256_test.json
		HKDF-SHA-512: https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/hkdf_sha512_test.json
	
	Test Categories:
		Normal : Standard derivation with various parameter sizes
		Edge cases : Empty salt, empty info, large output sizes, salt length variations
--]=]

--!strict
--!optimize 2
local Bridge = require("./Bridge")
local IsCLI = Bridge.IsCLI
local Testing = require("./")

local Cryptography = if IsCLI then require("../src") else require("../")
local HKDF = Cryptography.Hashing.HKDF
local SHA2 = Cryptography.Hashing.SHA2
local Conversions = Cryptography.Utilities.Conversions
local FromHex = Conversions.FromHex
local ToHex = Conversions.ToHex

type HkdfTest = {
	tcId: number,
	comment: string?,
	flags: {string}?,
	ikm: string,
	salt: string,
	info: string,
	size: number,
	okm: string,
	result: string,
}

type HkdfGroup = {
	type: string,
	keySize: number,
	tests: {HkdfTest},
}

type HkdfData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {HkdfGroup},
}

type HkdfConfig = {
	Name: string,
	Url: string,
	HashFunc: (buffer, buffer?) -> (string, buffer),
	BlockSize: number,
	HashLength: number,
	BigEndian: boolean,
}

local HKDF_CONFIGS: {HkdfConfig} = {
	{
		Name = "HKDF-SHA-256",
		Url = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/hkdf_sha256_test.json",
		HashFunc = SHA2.SHA256,
		BlockSize = 64,
		HashLength = 32,
		BigEndian = true,
	},
	{
		Name = "HKDF-SHA-512",
		Url = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/hkdf_sha512_test.json",
		HashFunc = SHA2.SHA512,
		BlockSize = 128,
		HashLength = 64,
		BigEndian = true,
	},
}

local function FetchTestVectors(Url: string): HkdfData
	local Response = Bridge.Get(Url)
	return Bridge.JSONDecode(Response) :: HkdfData
end

local function RunHkdfTests(Config: HkdfConfig)
	Testing.Describe(`{Config.Name} Wycheproof Tests`, function()
		local Data = FetchTestVectors(Config.Url)

		for GroupIndex, Group in ipairs(Data.testGroups) do
			local KeySize = Group.keySize

			Testing.Describe(`Group_{GroupIndex}: {KeySize}bit_Key`, function()
				for _, Test in ipairs(Group.tests) do
					local TestId = Test.tcId
					local Comment = Test.comment or ""
					local ExpectedResult = Test.result

					local TestName = `Test_{TestId}`
					if Comment ~= "" then
						TestName = `Test_{TestId}_{Comment:sub(1, 25):gsub(" ", "_")}`
					end

					Testing.Test(TestName, function()
						local IKM = FromHex(Test.ikm)
						local Salt = if #Test.salt > 0 then FromHex(Test.salt) else nil
						local Info = if #Test.info > 0 then FromHex(Test.info) else nil
						local Size = Test.size
						local ExpectedOkm = Test.okm:lower()

						local ComputeOk, Result = pcall(function()
							return HKDF(IKM, Salt, Info, Size, Config.HashFunc, Config.BlockSize, Config.HashLength, Config.BigEndian)
						end)

						if ExpectedResult == "valid" then
							Testing.Expect(ComputeOk).ToBe(true)
							Testing.Expect(Result).ToBeDefined()

							if ComputeOk and Result then
								local ComputedOkm = ToHex(Result):lower()
								Testing.Expect(ComputedOkm).ToBe(ExpectedOkm)
							end
						elseif ExpectedResult == "invalid" then
							if ComputeOk and Result then
								local ComputedOkm = ToHex(Result):lower()
								Testing.Expect(ComputedOkm).Never.ToBe(ExpectedOkm)
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

for _, Config in ipairs(HKDF_CONFIGS) do
	RunHkdfTests(Config)
end

Testing.Complete()

return 0
