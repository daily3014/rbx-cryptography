-- @ScriptType: ModuleScript
--!strict

local Testing = require("./")

type TestVector = {
	Description: string,
	Expected: number,
	Seed: number
}

type TestVectors = {[string]: TestVector}

local Algorithm = require("../Hashing/Murmur")

local TestVectors: TestVectors = {
	[""] = { 
		Description = "Empty String (Seed 0x00)", 
		Expected = 0x00000000, 
		Seed = 0x00 
	},
	["hello"] = { 
		Description = "Hello (Seed 0x00)", 
		Expected = 0x248bfa47, 
		Seed = 0x00 
	},
	["hello, world"] = { 
		Description = "Hello, world (Seed 0x00)", 
		Expected = 0x149bbb7f, 
		Seed = 0x00 
	},
	["19 Jan 2038 at 3:14:07 AM"] = { 
		Description = "Date String (Seed 0x00)", 
		Expected = 0xe31e8a70, 
		Seed = 0x00 
	},
	["The quick brown fox jumps over the lazy dog."] = { 
		Description = "Quick Brown Fox (Seed 0x00)", 
		Expected = 0xd5c48bfc, 
		Seed = 0x00 
	},
}

local SeededTestVectors1: TestVectors = {
	[""] = { 
		Description = "Empty String (Seed 0x01)", 
		Expected = 0x514e28b7, 
		Seed = 0x01 
	},
	["hello"] = { 
		Description = "Hello (Seed 0x01)", 
		Expected = 0xbb4abcad, 
		Seed = 0x01 
	},
	["hello, world"] = { 
		Description = "Hello, world (Seed 0x01)", 
		Expected = 0x6f5cb2e9, 
		Seed = 0x01 
	},
	["19 Jan 2038 at 3:14:07 AM"] = { 
		Description = "Date String (Seed 0x01)", 
		Expected = 0xf50e1f30, 
		Seed = 0x01 
	},
	["The quick brown fox jumps over the lazy dog."] = { 
		Description = "Quick Brown Fox (Seed 0x01)", 
		Expected = 0x846f6a36, 
		Seed = 0x01 
	},
}

local SeededTestVectors2A: TestVectors = {
	[""] = { 
		Description = "Empty String (Seed 0x2a)", 
		Expected = 0x087fcd5c, 
		Seed = 0x2a 
	},
	["hello"] = { 
		Description = "Hello (Seed 0x2a)", 
		Expected = 0xe2dbd2e1, 
		Seed = 0x2a 
	},
	["hello, world"] = { 
		Description = "Hello, world (Seed 0x2a)", 
		Expected = 0x7ec7c6c2, 
		Seed = 0x2a 
	},
	["19 Jan 2038 at 3:14:07 AM"] = { 
		Description = "Date String (Seed 0x2a)", 
		Expected = 0x58f745f6, 
		Seed = 0x2a 
	},
	["The quick brown fox jumps over the lazy dog."] = { 
		Description = "Quick Brown Fox (Seed 0x2a)", 
		Expected = 0xc02d1434, 
		Seed = 0x2a 
	},
}

Testing.Describe("MurmurHash3-32 Algorithm Tests (Seed 0x00)", function()
	for TestString, Info in TestVectors do
		Testing.Test(Info.Description, function()
			local Result = Algorithm(buffer.fromstring(TestString), Info.Seed)
			Testing.Expect(Result).ToBe(Info.Expected)
		end)
	end
end)

Testing.Describe("MurmurHash3-32 Algorithm Tests (Seed 0x01)", function()
	for TestString, Info in SeededTestVectors1 do
		Testing.Test(Info.Description, function()
			local Result = Algorithm(buffer.fromstring(TestString), Info.Seed)
			Testing.Expect(Result).ToBe(Info.Expected)
		end)
	end
end)

Testing.Describe("MurmurHash3-32 Algorithm Tests (Seed 0x2a)", function()
	for TestString, Info in SeededTestVectors2A do
		Testing.Test(Info.Description, function()
			local Result = Algorithm(buffer.fromstring(TestString), Info.Seed)
			Testing.Expect(Result).ToBe(Info.Expected)
		end)
	end
end)

Testing.Complete()

return 0
