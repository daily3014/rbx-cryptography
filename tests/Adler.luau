--!strict
local Testing = require("./")
type TestVector = {
	Description: string,
	Expected: number
}

type TestVectors = {[string]: TestVector}

local Algorithm = require("../Checksums/Adler")

local TestVectors: TestVectors = {
	[""] = { Description = "Empty String", Expected = 0x1 },
	["a"] = { Description = "Single Character", Expected = 0x00620062 },
	["\0"] = { Description = "Null Terminator", Expected = 0x00010001 },
	["Wikipedia"] = { Description = "Wikipedia Example", Expected = 0x11e60398 },
	[string.rep("a", 55)] = { Description = "Block of Characters", Expected = 0x47d914d8 },
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = { Description = "448 Bit", Expected = 0x807416f9 },
	[string.rep("a", 111)] = { Description = "111 Characters", Expected = 0x343e2a10 },
	[string.rep("a", 119)] = { Description = "119 Characters", Expected = 0x92712d18 },
	[string.rep("a", 239)] = { Description = "239 Characters", Expected = 0x766d5a90 },
	[string.rep("a", 1024)] = { Description = "Long String", Expected = 0xf3788410 },
	[string.rep("a", 199999)] = { Description = "Really Long String", Expected = 0xb6551638 },
	[string.rep("a", 1e6)] = { Description = "Million", Expected = 0x15d870f9 },
}
Testing.Describe("Adler Checksum Algorithm Tests", function()
	for TestString, Info in TestVectors do
		Testing.Test(Info.Description, function()
			local Result = Algorithm(buffer.fromstring(TestString))
			Testing.Expect(Result).ToBe(Info.Expected)
		end)
	end
end)

Testing.Complete()

return 0