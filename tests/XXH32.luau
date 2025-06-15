--!strict
local Testing = require("./")
type TestVector = {
	Description: string,
	Expected: number,
	Seed: number?
}

type TestVectors = {[string]: TestVector}
local Algorithm = require("../Hashing/XXH32")

local TestVectors: TestVectors = {
	[""] = { Description = "Empty String", Expected = 0x02cc5d05 },
	["abc"] = { Description = "Simple ABC", Expected = 0x32d153ff },
	["foo"] = { Description = "Simple Foo", Expected = 0xe20f0dd9 },
	["bar"] = { Description = "Simple Bar", Expected = 0x41a22b2c },
	["baz"] = { Description = "Simple Baz", Expected = 0x9bab0987 },
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = { Description = "448 Bit Alphabet", Expected = 0x89ea60c3 },
	["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] = { Description = "896 Bit Alphabet", Expected = 0x590b4165 },
	["The Fitness-Gram Pacer Test is a multi-stage aerobic capacity test"] = { Description = "Fitness-Gram Test", Expected = 0xbea696a7 },
	[string.rep("e", 199999)] = { Description = "Really Long String", Expected = 0xb27dd558 },
	[string.rep("a", 1e6)] = { Description = "Million", Expected = 0xe1155920 },
}

local SeededTestVectors: TestVectors = {
	[""] = { Description = "Empty String with Seed", Expected = 0xf6114164, Seed = 0x02cc5d05 },
	["abc"] = { Description = "Simple ABC with Seed", Expected = 0x9041e0d8, Seed = 0x32d153ff },
	["foo"] = { Description = "Simple Foo with Seed", Expected = 0xf4d3f6c9, Seed = 0xe20f0dd9 },
	["bar"] = { Description = "Simple Bar with Seed", Expected = 0x9ad4ead3, Seed = 0x41a22b2c },
	["baz"] = { Description = "Simple Baz with Seed", Expected = 0x23af9b99, Seed = 0x9bab0987 },
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = { Description = "448 Bit Alphabet with Seed", Expected = 0x404871e3, Seed = 0x89ea60c3 },
	["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] = { Description = "896 Bit Alphabet with Seed", Expected = 0xc033cd93, Seed = 0x590b4165 },
	["The Fitness-Gram Pacer Test is a multi-stage aerobic capacity test"] = { Description = "Fitness-Gram Test with Seed", Expected = 0x3c6ef7ed, Seed = 0xbea696a7 },
	[string.rep("e", 199999)] = { Description = "Really Long String with Seed", Expected = 0x6174a9bd, Seed = 0xb27dd558 },
	[string.rep("a", 1e6)] = { Description = "Million with Seed", Expected = 0xc0c7beae, Seed = 0xe1155920 },
}

Testing.Describe("xxHash32 Algorithm Tests", function()
	for TestString, Info in TestVectors do
		Testing.Test(Info.Description, function()
			local Result = Algorithm(buffer.fromstring(TestString), Info.Seed)
			Testing.Expect(Result).ToBe(Info.Expected)
		end)
	end
end)

Testing.Describe("xxHash32 Seeded Algorithm Tests", function()
	for TestString, Info in SeededTestVectors do
		Testing.Test(Info.Description, function()
			local Result = Algorithm(buffer.fromstring(TestString), Info.Seed)
			Testing.Expect(Result).ToBe(Info.Expected)
		end)
	end
end)

Testing.Complete()

return 0