--!strict

type TestVector = {
	Description: string,
	Expected: number,
}

type TestVectors = { [string]: TestVector }

local AlgorithmName = script.Parent.Name
local Algorithm = require(script.Parent)

local TestVectors: TestVectors = {
	[""] = { Description = "Empty String", Expected = 0x00000000 },
	["The quick brown fox jumps over the lazy dog."] = { Description = "Pangramm Example", Expected = 0x519025E9 },
	["Привет, мир!"] = { Description = "UTF-8 Example", Expected = 0x391651BC },
	["\0"] = { Description = "Null Terminator", Expected = 0xD202EF8D },
	[string.rep("a", 55)] = { Description = "Block of Characters", Expected = 0xAADFE34E },
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = { Description = "448 Bit", Expected = 0x171A3F5F },
	[string.rep("a", 111)] = { Description = "111 Characters", Expected = 0xD7EE9B8C },
	["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] = {
		Description = "896 Bits",
		Expected = 0x191F3349,
	},
	[string.rep("a", 119)] = { Description = "119 Characters", Expected = 0x4144EBAE },
	[string.rep("a", 239)] = { Description = "239 Characters", Expected = 0x5B34791C },
	[string.rep("a", 1024)] = { Description = "Long String", Expected = 0x7C5597B9 },
	[string.rep("a", 199999)] = { Description = "Really Long String", Expected = 0xB3D0F54D },
	[string.rep("a", 1e6)] = { Description = "Million", Expected = 0xDC25BFBC },
}

for TestString, Info in TestVectors do
	local Result = Algorithm(buffer.fromstring(TestString), "Iso", false) :: number

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
