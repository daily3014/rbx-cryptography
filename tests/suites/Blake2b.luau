--[=[
	BLAKE2b Tadashi Test Suite

	Test Vector Source:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/blake2b_test.json
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("../Bridge")
local Testing = require("../")

local Blake2b = require("../../src/Hashing/Blake2b")
local FromHex = Testing.FromHex

type Blake2bTest = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	key: string,
	msg: string,
	outputLen: number,
	digest: string,
	result: string,
}

type Blake2bGroup = {
	type: string,
	tests: {Blake2bTest},
}

type Blake2bData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {Blake2bGroup},
}

local BLAKE2B_URL = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/blake2b_test.json"

Testing.Describe("BLAKE2b Tadashi Tests", function()
	local Data = Bridge.JSONDecode(Bridge.Get(BLAKE2B_URL)) :: Blake2bData

	for GroupIndex, Group in ipairs(Data.testGroups) do
		Testing.Describe(`Group_{GroupIndex}: {Data.algorithm}`, function()
			for _, Test in ipairs(Group.tests) do
				local Comment = Test.comment or ""
				local TestName = `Test_{Test.tcId}`
				if Comment ~= "" then
					TestName = `Test_{Test.tcId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local KeyBytes = FromHex(Test.key)
					local Key: buffer? = if buffer.len(KeyBytes) > 0 then KeyBytes else nil
					local Digest = Blake2b.Digest(FromHex(Test.msg), Test.outputLen, Key)
					Testing.Expect(Digest).ToBe(Test.digest)
				end)
			end
		end)
	end
end)

Testing.Complete()

return 0
