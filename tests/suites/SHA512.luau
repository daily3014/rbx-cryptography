--[=[
	SHA-512 Tadashi Test Suite

	Test Vector Source:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/sha512_test.json
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("../Bridge")
local Testing = require("../")

local SHA512 = require("../../src/Hashing/SHA2/SHA512").SHA512
local FromHex = Testing.FromHex

type HashTest = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	msg: string?,
	msgPattern: {pattern: string, length: number}?,
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

local SHA512_URL = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/sha512_test.json"

Testing.Describe("SHA-512 Tadashi Tests", function()
	local Data = Bridge.JSONDecode(Bridge.Get(SHA512_URL)) :: HashData

	for GroupIndex, Group in ipairs(Data.testGroups) do
		Testing.Describe(`Group_{GroupIndex}: {Data.algorithm} ({Group.digestSize}-bit digest)`, function()
			for _, Test in ipairs(Group.tests) do
				local Comment = Test.comment or ""
				local TestName = `Test_{Test.tcId}`
				if Comment ~= "" then
					TestName = `Test_{Test.tcId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local Msg = if Test.msgPattern
						then Testing.ExpandPattern(Test.msgPattern.pattern, Test.msgPattern.length)
						else FromHex(Test.msg :: string)
					Testing.Expect((SHA512(Msg))).ToBe(Test.digest)
				end)
			end
		end)
	end
end)

Testing.Complete()

return 0
