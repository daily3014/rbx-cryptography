--[=[
	HMAC Tadashi Test Suite

	Test Vector Sources:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/hmac_sha256_test.json
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/hmac_sha512_test.json
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("./Bridge")
local IsCLI = Bridge.IsCLI
local Testing = require("./")

local HMAC: any = if IsCLI then require("../src/Hashing/HMAC") else require("../Hashing/HMAC")
local SHA2: any = if IsCLI then require("../src/Hashing/SHA2") else require("../Hashing/SHA2")
local FromHex = Testing.FromHex

type HmacTest = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	key: string,
	msg: string,
	tag: string,
	result: string,
}

type HmacGroup = {
	type: string,
	tagSize: number,
	blockSize: number,
	tests: {HmacTest},
}

type HmacData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {HmacGroup},
}

local HMAC_VARIANTS = {
	{
		Name = "HMAC-SHA256",
		Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/hmac_sha256_test.json",
		HashFn = SHA2.SHA256,
		BlockSize = 64,
	},
	{
		Name = "HMAC-SHA512",
		Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/hmac_sha512_test.json",
		HashFn = SHA2.SHA512,
		BlockSize = 128,
	},
}

local function FetchTestVectors(Url: string): HmacData
	local Response = Bridge.Get(Url)
	return Bridge.JSONDecode(Response) :: HmacData
end

local function RunHmacTests(Data: HmacData, HashFn: any, BlockSize: number)
	for GroupIndex, Group in ipairs(Data.testGroups) do
		Testing.Describe(`Group_{GroupIndex}: {Data.algorithm} ({Group.tagSize}-bit tag)`, function()
			for _, Test in ipairs(Group.tests) do
				local TestId = Test.tcId
				local Comment = Test.comment or ""

				local TestName = `Test_{TestId}`
				if Comment ~= "" then
					TestName = `Test_{TestId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local Key = FromHex(Test.key)
					local Msg = FromHex(Test.msg)
					local Tag = HMAC(Msg, Key, HashFn, BlockSize)
					Testing.Expect(Tag).ToBe(Test.tag)
				end)
			end
		end)
	end
end

for _, Variant in ipairs(HMAC_VARIANTS) do
	Testing.Describe(`{Variant.Name} Tadashi Tests`, function()
		RunHmacTests(FetchTestVectors(Variant.Url), Variant.HashFn, Variant.BlockSize)
	end)
end

Testing.Complete()

return 0
