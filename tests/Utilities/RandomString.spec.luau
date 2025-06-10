--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)

local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local RandomString = Cryptography.Utilities.RandomString

describe("RandomString", function()
	it("should generate a random string of the specified length", function()
		for length = 1, 100, 9 do
			local randomStr = RandomString(length)
			expect(#randomStr).toBe(length)
		end
	end)
	it("should generate characters within the ASCII range 36-122", function()
		for length = 1, 30 do
			local randomStr = RandomString(length)
			for i = 1, #randomStr do
				local charCode = string.byte(randomStr, i)
				expect(charCode).toBeGreaterThanOrEqual(36)
				expect(charCode).toBeLessThanOrEqual(122)
			end
		end
	end)
end)
