--[=[
	SHA-384 Tadashi Test Suite

	Test Vector Source:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/sha384_test.json
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("../Bridge")
local Testing = require("../")

local SHA384 = require("../../src/Hashing/SHA2/SHA384")
local FromHex = Testing.FromHex

type HashTest = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	msg: string,
	digest: string,
	result: string,
}

type HashGroup = {
	type: string,
	digestSize: number,
	blockSize: number,
	tests: {HashTest},
}

type HashData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {HashGroup},
}

local SHA384_URL = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/sha384_test.json"

Testing.Describe("SHA-384 Tadashi Tests", function()
	local Data = Bridge.JSONDecode(Bridge.Get(SHA384_URL)) :: HashData

	for GroupIndex, Group in ipairs(Data.testGroups) do
		Testing.Describe(`Group_{GroupIndex}: {Data.algorithm} ({Group.digestSize}-bit digest)`, function()
			for _, Test in ipairs(Group.tests) do
				local Comment = Test.comment or ""
				local TestName = `Test_{Test.tcId}`
				if Comment ~= "" then
					TestName = `Test_{Test.tcId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					Testing.Expect((SHA384(FromHex(Test.msg)))).ToBe(Test.digest)
				end)
			end
		end)
	end
end)

Testing.Complete()

return 0
