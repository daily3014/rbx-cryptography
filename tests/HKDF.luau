--[=[
	HKDF Tadashi Test Suite

	Test Vector Sources:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/hkdf_sha256_test.json
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/hkdf_sha512_test.json
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("./Bridge")
local IsCLI = Bridge.IsCLI
local Testing = require("./")

local HKDF: any = if IsCLI then require("../src/Hashing/HKDF") else require("../Hashing/HKDF")
local SHA2: any = if IsCLI then require("../src/Hashing/SHA2") else require("../Hashing/SHA2")
local FromHex = Testing.FromHex
local ToHex = Testing.ToHex

type HkdfTest = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	ikm: string,
	salt: string,
	info: string,
	outputLen: number,
	okm: string,
	result: string,
}

type HkdfGroup = {
	type: string,
	hashLen: number,
	blockSize: number,
	tests: {HkdfTest},
}

type HkdfData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {HkdfGroup},
}

local HKDF_VARIANTS = {
	{
		Name = "HKDF-SHA256",
		Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/hkdf_sha256_test.json",
		HashFn = SHA2.SHA256,
		BlockSize = 64,
		HashLen = 32,
	},
	{
		Name = "HKDF-SHA512",
		Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/hkdf_sha512_test.json",
		HashFn = SHA2.SHA512,
		BlockSize = 128,
		HashLen = 64,
	},
}

local function FetchTestVectors(Url: string): HkdfData
	local Response = Bridge.Get(Url)
	return Bridge.JSONDecode(Response) :: HkdfData
end

local function RunHkdfTests(Data: HkdfData, HashFn: any, BlockSize: number, HashLen: number)
	for GroupIndex, Group in ipairs(Data.testGroups) do
		Testing.Describe(`Group_{GroupIndex}: {Data.algorithm}`, function()
			for _, Test in ipairs(Group.tests) do
				local TestId = Test.tcId
				local Comment = Test.comment or ""

				local TestName = `Test_{TestId}`
				if Comment ~= "" then
					TestName = `Test_{TestId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local Ikm = FromHex(Test.ikm)
					local SaltBuf = FromHex(Test.salt)
					local InfoBuf = FromHex(Test.info)
					local Salt: buffer? = if buffer.len(SaltBuf) > 0 then SaltBuf else nil
					local Info: buffer? = if buffer.len(InfoBuf) > 0 then InfoBuf else nil

					local Okm = HKDF(Ikm, Salt, Info, Test.outputLen, HashFn, BlockSize, HashLen)
					Testing.Expect(ToHex(Okm)).ToBe(Test.okm)
				end)
			end
		end)
	end
end

for _, Variant in ipairs(HKDF_VARIANTS) do
	Testing.Describe(`{Variant.Name} Tadashi Tests`, function()
		RunHkdfTests(FetchTestVectors(Variant.Url), Variant.HashFn, Variant.BlockSize, Variant.HashLen)
	end)
end

Testing.Complete()

return 0
