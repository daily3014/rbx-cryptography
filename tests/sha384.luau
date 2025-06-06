--!strict

type TestVector = {
	Description: string,
	Expected: string
}

type TestVectors = {[string]: TestVector}

local AlgorithmName = script.Parent.Name
local Algorithm = require(script.Parent)

local TestVectors: TestVectors = {
	[""] = { Description = "Empty String", Expected = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" },
	["The quick brown fox jumps over the lazy dog."] = { Description = "Pangramm Example", Expected = "ed892481d8272ca6df370bf706e4d7bc1b5739fa2177aae6c50e946678718fc67a7af2819a021c2fc34e91bdb63409d7" },
	["Привет, мир!"] = { Description = "UTF-8 Example", Expected = "6a69c1a6d1d16f369dd6883690561e0bd508d6766a512c33d7c46a2c73cfbdbbc1fcf55cd5d657830713cffc343b7bac" },
	["\0"] = { Description = "Null Terminator", Expected = "bec021b4f368e3069134e012c2b4307083d3a9bdd206e24e5f0d86e13d6636655933ec2b413465966817a9c208a11717" },
	[string.rep("a", 55)] = { Description = "Block of Characters", Expected = "5d91ac7e74e62b5c728904b40f10784d66b7af9cb6302123e48c92f0432ceb8d2a92c02de77dcb29ed75c4b42bde46f4" },
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = { Description = "448 Bit", Expected = "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b" },
	[string.rep("a", 111)] = { Description = "111 Characters", Expected = "3c37955051cb5c3026f94d551d5b5e2ac38d572ae4e07172085fed81f8466b8f90dc23a8ffcdea0b8d8e58e8fdacc80a" },
	["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] = { Description = "896 Bits", Expected = "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039" },
	[string.rep("a", 119)] = { Description = "119 Characters", Expected = "c2fbb1911d6889e3db556b482236ab82f3c736f00a22c088641a09fdbbca27e3f1e3b6235bad20aee1ca083c76ac590c" },
	[string.rep("a", 239)] = { Description = "239 Characters", Expected = "e247c35f4bc1aa38026f8880c8c97305545d00d3f859e00c57d1c1f0a176b3c6b749c4eb081f08bd0fba500969cd056a" },
	[string.rep("a", 1024)] = { Description = "Long String", Expected = "a31bea5896ef0e418f18014ef9fde89f6f33a177dc97190bc39dedd94e5476342a0d277c92bc19ca0542fca227d12c4c" },
	[string.rep("a", 199999)] = { Description = "Really Long String", Expected = "a698a19c13a234f4cff4f80bdc8e4b69f729580ff9b3ff55526fbcdf1f1700ea0186c1d5c412d75aff1db8884d697534" },
	[string.rep("a", 1e6)] = { Description = "Million", Expected = "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985" },
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