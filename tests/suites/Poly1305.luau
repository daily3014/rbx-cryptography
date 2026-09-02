--[=[
	Poly1305 Tadashi Test Suite

	Test Vector Source:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/poly1305_test.json
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("../Bridge")
local Testing = require("../")

local Poly1305 = require("../../src/Encryption/AEAD/Poly1305").Tag
local FromHex = Testing.FromHex
local ToHex = Testing.ToHex

type PolyTest = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	key: string,
	msg: string,
	tag: string,
	result: string,
}

type PolyGroup = {
	type: string,
	keySize: number,
	tagSize: number,
	tests: {PolyTest},
}

type PolyData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {PolyGroup},
}

local POLY1305_URL = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/poly1305_test.json"

Testing.Describe("Poly1305 Tadashi Tests", function()
	local Data = Bridge.JSONDecode(Bridge.Get(POLY1305_URL)) :: PolyData

	for GroupIndex, Group in ipairs(Data.testGroups) do
		Testing.Describe(`Group_{GroupIndex}: {Data.algorithm}`, function()
			for _, Test in ipairs(Group.tests) do
				local Comment = Test.comment or ""
				local TestName = `Test_{Test.tcId}`
				if Comment ~= "" then
					TestName = `Test_{Test.tcId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local Tag = Poly1305(FromHex(Test.msg), FromHex(Test.key))
					Testing.Expect(ToHex(Tag)).ToBe(Test.tag)
				end)
			end
		end)
	end
end)

Testing.Complete()

return 0
