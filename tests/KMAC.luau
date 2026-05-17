--[=[
	KMAC Tadashi Test Suite

	Test Vector Sources:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/kmac128_test.json
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/kmac256_test.json
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("./Bridge")
local IsCLI = Bridge.IsCLI
local Testing = require("./")

local KMAC: any = if IsCLI then require("../src/Hashing/KMAC") else require("../Hashing/KMAC")
local FromHex = Testing.FromHex

type KmacTest = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	key: string,
	msg: string,
	custom: string,
	outputLen: number,
	tag: string,
	result: string,
}

type KmacGroup = {
	type: string,
	rate: number,
	tests: {KmacTest},
}

type KmacData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {KmacGroup},
}

local KMAC_VARIANTS = {
	{
		Name = "KMAC128",
		Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/kmac128_test.json",
		Fn = KMAC.KMAC128,
	},
	{
		Name = "KMAC256",
		Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/kmac256_test.json",
		Fn = KMAC.KMAC256,
	},
}

local function FetchTestVectors(Url: string): KmacData
	local Response = Bridge.Get(Url)
	return Bridge.JSONDecode(Response) :: KmacData
end

local function RunKmacTests(Data: KmacData, KmacFn: any)
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
					local Key = FromHex(Test.key)
					local Msg = FromHex(Test.msg)
					local Custom = FromHex(Test.custom)
					local Output = buffer.create(Test.outputLen)
					local Tag = KmacFn(Msg, Key, Output, Custom)
					Testing.Expect(Tag).ToBe(Test.tag)
				end)
			end
		end)
	end
end

for _, Variant in ipairs(KMAC_VARIANTS) do
	Testing.Describe(`{Variant.Name} Tadashi Tests`, function()
		RunKmacTests(FetchTestVectors(Variant.Url), Variant.Fn)
	end)
end

Testing.Complete()

return 0
