--[=[
	SHA-3 Family Tadashi Test Suite

	Covers SHA3-224, SHA3-256, SHA3-384, SHA3-512 and the SHAKE128 / SHAKE256
	extendable-output functions, all per FIPS 202.

	Test Vector Sources:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/sha3_224_test.json
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/sha3_256_test.json
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/sha3_384_test.json
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/sha3_512_test.json
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/shake128_test.json
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/shake256_test.json
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("./Bridge")
local IsCLI = Bridge.IsCLI
local Testing = require("./")

local SHA3: any = if IsCLI then require("../src/Hashing/SHA3") else require("../Hashing/SHA3")
local FromHex = Testing.FromHex

type DigestTest = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	msg: string,
	outputLen: number?,
	digest: string,
	result: string,
}

type DigestGroup = {
	type: string,
	digestSize: number?,
	rate: number,
	tests: {DigestTest},
}

type DigestData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {DigestGroup},
}

local SHA3_URLS = {
	{Name = "SHA3-224", Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/sha3_224_test.json", Fn = SHA3.SHA3_224},
	{Name = "SHA3-256", Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/sha3_256_test.json", Fn = SHA3.SHA3_256},
	{Name = "SHA3-384", Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/sha3_384_test.json", Fn = SHA3.SHA3_384},
	{Name = "SHA3-512", Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/sha3_512_test.json", Fn = SHA3.SHA3_512},
}

local SHAKE_URLS = {
	{Name = "SHAKE128", Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/shake128_test.json", Fn = SHA3.SHAKE128},
	{Name = "SHAKE256", Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/shake256_test.json", Fn = SHA3.SHAKE256},
}

local function FetchTestVectors(Url: string): DigestData
	local Response = Bridge.Get(Url)
	return Bridge.JSONDecode(Response) :: DigestData
end

local function RunSha3Tests(Data: DigestData, HashFn: (buffer) -> string)
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
					local Msg = FromHex(Test.msg)
					local Digest = HashFn(Msg)
					Testing.Expect(Digest).ToBe(Test.digest)
				end)
			end
		end)
	end
end

local function RunShakeTests(Data: DigestData, ShakeFn: (buffer, number) -> string)
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
					local Msg = FromHex(Test.msg)
					local Digest = ShakeFn(Msg, Test.outputLen :: number)
					Testing.Expect(Digest).ToBe(Test.digest)
				end)
			end
		end)
	end
end

for _, Entry in ipairs(SHA3_URLS) do
	Testing.Describe(`{Entry.Name} Tadashi Tests`, function()
		RunSha3Tests(FetchTestVectors(Entry.Url), Entry.Fn)
	end)
end

for _, Entry in ipairs(SHAKE_URLS) do
	Testing.Describe(`{Entry.Name} Tadashi Tests`, function()
		RunShakeTests(FetchTestVectors(Entry.Url), Entry.Fn)
	end)
end

Testing.Complete()

return 0
