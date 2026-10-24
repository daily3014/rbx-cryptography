--[=[
	X25519 Tadashi Test Suite

	Test Vector Source:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/x25519_test.json
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("../Bridge")
local Testing = require("../")

local X25519 = require("../../src/Verification/EdDSA/X25519")
local FromHex = Testing.FromHex
local ToHex = Testing.ToHex

type X25519Test = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	sk: string,
	pk: string,
	iterations: number?,
	shared: string,
	result: string,
}

type X25519Group = {
	type: string,
	keySize: number?,
	tests: {X25519Test},
}

type X25519Data = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {X25519Group},
}

local ZERO_SHARED = string.rep("00", 32)
local X25519_URL = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/x25519_test.json"

Testing.Describe("X25519 Tadashi Tests", function()
	local Data = Bridge.JSONDecode(Bridge.Get(X25519_URL)) :: X25519Data

	for GroupIndex, Group in ipairs(Data.testGroups) do
		Testing.Describe(`Group_{GroupIndex}: {Data.algorithm}`, function()
			for _, Test in ipairs(Group.tests) do
				local Comment = Test.comment or ""
				local TestName = `Test_{Test.tcId}`
				if Comment ~= "" then
					TestName = `Test_{Test.tcId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					if Test.shared == ZERO_SHARED then
						Testing.Expect(function()
							X25519.Exchange(FromHex(Test.sk), FromHex(Test.pk))
						end).ToThrow()
					elseif Test.iterations then
						local K = FromHex(Test.sk)
						local U = FromHex(Test.pk)
						for _ = 1, Test.iterations do
							local Out = X25519.Exchange(K, U)
							K, U = Out, K
						end
						Testing.Expect(ToHex(K)).ToBe(Test.shared)
					else
						local Shared = X25519.Exchange(FromHex(Test.sk), FromHex(Test.pk))
						Testing.Expect(ToHex(Shared)).ToBe(Test.shared)
					end
				end)
			end
		end)
	end
end)

Testing.Complete()

return 0
