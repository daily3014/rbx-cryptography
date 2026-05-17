--[=[
	Argon2id Tadashi Test Suite

	Test Vector Source:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/argon2id_test.json
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("./Bridge")
local IsCLI = Bridge.IsCLI
local Testing = require("./")

local Argon2id: any = if IsCLI then require("../src/Hashing/Argon2id") else require("../Hashing/Argon2id")
local FromHex = Testing.FromHex

type ArgonTest = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	password: string,
	salt: string,
	secret: string,
	ad: string,
	t: number,
	m: number,
	p: number,
	outputLen: number,
	tag: string,
	result: string,
}

type ArgonGroup = {
	type: string,
	version: number,
	tests: {ArgonTest},
}

type ArgonData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {ArgonGroup},
}

local ARGON2ID_URL = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/argon2id_test.json"

Testing.Describe("Argon2id Tadashi Tests", function()
	local Data = Bridge.JSONDecode(Bridge.Get(ARGON2ID_URL)) :: ArgonData

	for GroupIndex, Group in ipairs(Data.testGroups) do
		Testing.Describe(`Group_{GroupIndex}: {Data.algorithm} (version 0x{string.format("%X", Group.version)})`, function()
			for _, Test in ipairs(Group.tests) do
				local Comment = Test.comment or ""
				local TestName = `Test_{Test.tcId}`
				if Comment ~= "" then
					TestName = `Test_{Test.tcId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local SecretBuf = FromHex(Test.secret)
					local AdBuf = FromHex(Test.ad)

					local Options: any = {
						TimeCost = Test.t,
						MemoryCost = Test.m,
						Parallelism = Test.p,
						OutputLength = Test.outputLen,
					}
					if buffer.len(SecretBuf) > 0 then
						Options.Secret = SecretBuf
					end
					if buffer.len(AdBuf) > 0 then
						Options.AssociatedData = AdBuf
					end

					local Tag = Argon2id(FromHex(Test.password), FromHex(Test.salt), Options)
					Testing.Expect(Tag).ToBe(Test.tag)
				end)
			end
		end)
	end
end)

Testing.Complete()

return 0
