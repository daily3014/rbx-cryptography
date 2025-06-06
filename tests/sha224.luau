--!strict

type TestVector = {
	Description: string,
	Expected: string
}

type TestVectors = {[string]: TestVector}

local AlgorithmName = script.Parent.Name
local Algorithm = require(script.Parent)

local TestVectors: TestVectors = {
	[""] = { Description = "Empty String", Expected = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" },
	["The quick brown fox jumps over the lazy dog."] = { Description = "Pangramm Example", Expected = "619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c" },
	["Привет, мир!"] = { Description = "UTF-8 Example", Expected = "941fd4cfe921e7a8ea1e1c6dd255b3c06d948fe7546bcd1d8deda161" },
	["\0"] = { Description = "Null Terminator", Expected = "fff9292b4201617bdc4d3053fce02734166a683d7d858a7f5f59b073" },
	[string.rep("a", 55)] = { Description = "Block of Characters", Expected = "fb0bd626a70c28541dfa781bb5cc4d7d7f56622a58f01a0b1ddd646f" },
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = { Description = "448 Bit", Expected = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" },
	[string.rep("a", 111)] = { Description = "111 Characters", Expected = "4aeec1a49b2c1bc663abf2809b36faaa64359523d4f26d02dbc2cba3" },
	["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] = { Description = "896 Bits", Expected = "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3" },
	[string.rep("a", 119)] = { Description = "119 Characters", Expected = "e000e6709d26667b631faa7fc1bd404eb4774003c5fb4f51a0184875" },
	[string.rep("a", 239)] = { Description = "239 Characters", Expected = "9da4e535cdffdbb7ee783ef7c6b61cbda7bcd4b15ce59d6ce5c2f099" },
	[string.rep("a", 1024)] = { Description = "Long String", Expected = "dcbd9ce406352c2e127ce1cad5042c22dd28a0246dadefc12f384c2e" },
	[string.rep("a", 199999)] = { Description = "Really Long String", Expected = "4fa3ff00143a30c4530a986cecb42ee2c2ae41b52faff36bfbee5152" },
	[string.rep("a", 1e6)] = { Description = "Million", Expected = "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67" },
}

for TestString, Info in TestVectors do
	local Result = Algorithm(buffer.fromstring(TestString))
	
	local ErrorMessage = string.format(
		"%s: Test String '%s' (%s) produced incorrect hash. Expected '%s', got '%s'",
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