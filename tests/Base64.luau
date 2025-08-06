--!strict
local Testing = require("./")
type TestVector = {
	Description: string,
	Expected: string,
	Algorithm: "Encode" | "Decode"
}

type TestVectors = {[string]: TestVector}

local Algorithm = require("../Utilities/Base64")
local TestVectors: TestVectors = {
	["VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4="] = { Algorithm = "Decode", Description = "Pangramm Example [Decode]", Expected = "The quick brown fox jumps over the lazy dog." },
	["0J/RgNC40LLQtdGCLCDQvNC40YAh"] = { Algorithm = "Decode", Description = "UTF-8 Example [Decode]", Expected = "Привет, мир!" },
	["YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ=="] = { Algorithm = "Decode", Description = "Block of Characters [Decode]", Expected = string.rep("a", 55) },
	["The quick brown fox jumps over the lazy dog."] = { Algorithm = "Encode", Description = "Pangramm Example [Encode]", Expected = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4=" },
	["Привет, мир!"] = { Algorithm = "Encode", Description = "UTF-8 Example [Encode]", Expected = "0J/RgNC40LLQtdGCLCDQvNC40YAh" },
	[string.rep("a", 55)] = { Algorithm = "Encode", Description = "Block of Characters [Encode]", Expected = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==" },
	["SGVsbG8gV29ybGQ="] = { Algorithm = "Decode", Description = "Hello World [Decode]", Expected = "Hello World" },
	["Hello World"] = { Algorithm = "Encode", Description = "Hello World [Encode]", Expected = "SGVsbG8gV29ybGQ=" }	
}

Testing.Describe("Base64 Algorithm Tests", function()
	for TestString, Info in TestVectors do
		Testing.Test(Info.Description, function()
			local Result
			if Info.Algorithm == "Decode" then
				Result = Algorithm.Decode(buffer.fromstring(TestString)) 
			elseif Info.Algorithm == "Encode" then
				Result = buffer.tostring(Algorithm.Encode(buffer.fromstring(TestString)))
			end
			Testing.Expect(Result).ToBe(Info.Expected)
		end)
	end
end)

Testing.Complete()

return 0