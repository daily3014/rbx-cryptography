--[=[
	BLAKE3 Tadashi Test Suite

	Test Vector Source:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/blake3_test.json
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("../Bridge")
local Testing = require("../")

local Blake3 = require("../../src/Hashing/Blake3")
local FromHex = Testing.FromHex

type Blake3Test = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	key: string,
	context: string,
	msg: string?,
	msgPattern: {pattern: string, length: number}?,
	outputLen: number?,
	digest: string,
	result: string,
}

type Blake3Group = {
	type: string,
	tests: {Blake3Test},
}

type Blake3Data = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {Blake3Group},
}

local BLAKE3_URL = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/blake3_test.json"

Testing.Describe("BLAKE3 Tadashi Tests", function()
	local Data = Bridge.JSONDecode(Bridge.Get(BLAKE3_URL)) :: Blake3Data

	for GroupIndex, Group in ipairs(Data.testGroups) do
		Testing.Describe(`Group_{GroupIndex}: {Data.algorithm}`, function()
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
					local Digest: string

					if Test.context and #Test.context > 0 then
						local Fn = Blake3.DeriveKey(FromHex(Test.context))
						Digest = Fn(Msg, Test.outputLen)
					elseif Test.key and #Test.key > 0 then
						Digest = Blake3.DigestKeyed(Msg, FromHex(Test.key), Test.outputLen)
					else
						Digest = Blake3.Digest(Msg, Test.outputLen)
					end

					Testing.Expect(Digest).ToBe(Test.digest)
				end)
			end
		end)
	end
end)

Testing.Complete()

return 0
