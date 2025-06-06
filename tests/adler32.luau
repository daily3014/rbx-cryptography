--!strict

type TestVector = {
	Description: string,
	Expected: number
}

type TestVectors = {[string]: TestVector}

local AlgorithmName = script.Parent.Name
local Algorithm = require(script.Parent)

local TestVectors: TestVectors = {
	[""] = { Description = "Empty String", Expected = 0x1 },
	["a"] = { Description = "Single Character", Expected = 0x00620062 },
	--["Привет, мир!"] = { Description = "UTF-8 Example", Expected = 0xa0800d97 },
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

for TestString, Info in TestVectors do
	local Result = Algorithm(buffer.fromstring(TestString))

	local ErrorMessage = string.format(
		"%s: Test String '%s' (%s) produced incorrect checksum. Expected '%i', got '%i'",
		AlgorithmName,
		TestString,
		Info.Description,
		Info.Expected,
		Result
	)

	assert(Result == Info.Expected, ErrorMessage)
	warn(`{AlgorithmName}: Test '{Info.Description}' passed`)
end

print(`[{AlgorithmName}] All test cases passed`)

return 0