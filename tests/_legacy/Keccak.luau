--!strict

type TestVector = {
	Description: string,
	Expected: string,
}

type TestVectors = { [string]: TestVector }

local AlgorithmName = script.Parent.Name
local Algorithm = require(script.Parent)
local SHA3_224_TestVectors: TestVectors = {
	[""] = { Description = "Empty String", Expected = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" },
	["abc"] = { Description = "Short String", Expected = "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf" },
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = {
		Description = "448 Bit",
		Expected = "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33",
	},
	["The quick brown fox jumps over the lazy dog"] = {
		Description = "Pangram",
		Expected = "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795",
	},
	[string.rep("a", 1000000)] = {
		Description = "Million a's",
		Expected = "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c",
	},
}

local SHA3_256_TestVectors: TestVectors = {
	[""] = {
		Description = "Empty String",
		Expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
	},
	["abc"] = {
		Description = "Short String",
		Expected = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
	},
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = {
		Description = "448 Bit",
		Expected = "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
	},
	["The quick brown fox jumps over the lazy dog"] = {
		Description = "Pangram",
		Expected = "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
	},
	["The quick brown fox jumps over the lazy dog."] = {
		Description = "Pangram with Period",
		Expected = "a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d",
	},
	[string.rep("a", 1000000)] = {
		Description = "Million a's",
		Expected = "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1",
	},
}

local SHA3_384_TestVectors: TestVectors = {
	[""] = {
		Description = "Empty String",
		Expected = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
	},
	["abc"] = {
		Description = "Short String",
		Expected = "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
	},
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = {
		Description = "448 Bit",
		Expected = "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22",
	},
	["The quick brown fox jumps over the lazy dog"] = {
		Description = "Pangram",
		Expected = "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41",
	},
	[string.rep("a", 1000000)] = {
		Description = "Million a's",
		Expected = "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340",
	},
}

local SHA3_512_TestVectors: TestVectors = {
	[""] = {
		Description = "Empty String",
		Expected = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
	},
	["abc"] = {
		Description = "Short String",
		Expected = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
	},
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = {
		Description = "448 Bit",
		Expected = "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e",
	},
	["The quick brown fox jumps over the lazy dog"] = {
		Description = "Pangram",
		Expected = "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450",
	},
	[string.rep("a", 1000000)] = {
		Description = "Million a's",
		Expected = "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87",
	},
}

local SHAKE128_TestVectors: TestVectors = {
	[""] = {
		Description = "Empty String (32 bytes)",
		Expected = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
	},
	["abc"] = {
		Description = "Short String (32 bytes)",
		Expected = "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
	},
	["The quick brown fox jumps over the lazy dog"] = {
		Description = "Pangram (32 bytes)",
		Expected = "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e",
	},
	[string.rep("a", 1000000)] = {
		Description = "Million a's (32 bytes)",
		Expected = "9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef58",
	},
}

local SHAKE256_TestVectors: TestVectors = {
	[""] = {
		Description = "Empty String (64 bytes)",
		Expected = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
	},
	["abc"] = {
		Description = "Short String (64 bytes)",
		Expected = "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
	},
	["The quick brown fox jumps over the lazy dog"] = {
		Description = "Pangram (64 bytes)",
		Expected = "2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca1d01d1369a23539cd80f7c054b6e5daf9c962cad5b8ed5bd11998b40d5734442",
	},
	[string.rep("a", 1000000)] = {
		Description = "Million a's (64 bytes)",
		Expected = "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a3fd124d4df76c0a539ee7dd2f6e1ec346124c815d9410e145eb561bcd97b18ab",
	},
}

local function TestSHA3_224()
	for TestString, Info in SHA3_224_TestVectors do
		local a = Algorithm.SHA3_224
		local Result = a(buffer.fromstring(TestString))

		local ErrorMessage = string.format(
			"SHA3-224: Test String '%s' (%s) produced incorrect hash. Expected '%s', got '%s'",
			TestString:sub(1, 50) .. (TestString:len() > 50 and "..." or ""),
			Info.Description,
			Info.Expected,
			Result
		)

		assert(Result == Info.Expected, ErrorMessage)
		warn(`SHA3-224: Test '{Info.Description}' passed`)
	end
end

local function TestSHA3_256()
	for TestString, Info in SHA3_256_TestVectors do
		local Result = Algorithm.SHA3_256(buffer.fromstring(TestString))

		local ErrorMessage = string.format(
			"SHA3-256: Test String '%s' (%s) produced incorrect hash. Expected '%s', got '%s'",
			TestString:sub(1, 50) .. (TestString:len() > 50 and "..." or ""),
			Info.Description,
			Info.Expected,
			Result
		)

		assert(Result == Info.Expected, ErrorMessage)
		warn(`SHA3-256: Test '{Info.Description}' passed`)
	end
end

local function TestSHA3_384()
	for TestString, Info in SHA3_384_TestVectors do
		local Result = Algorithm.SHA3_384(buffer.fromstring(TestString))

		local ErrorMessage = string.format(
			"SHA3-384: Test String '%s' (%s) produced incorrect hash. Expected '%s', got '%s'",
			TestString:sub(1, 50) .. (TestString:len() > 50 and "..." or ""),
			Info.Description,
			Info.Expected,
			Result
		)

		assert(Result == Info.Expected, ErrorMessage)
		warn(`SHA3-384: Test '{Info.Description}' passed`)
	end
end

local function TestSHA3_512()
	for TestString, Info in SHA3_512_TestVectors do
		local Result = Algorithm.SHA3_512(buffer.fromstring(TestString))

		local ErrorMessage = string.format(
			"SHA3-512: Test String '%s' (%s) produced incorrect hash. Expected '%s', got '%s'",
			TestString:sub(1, 50) .. (TestString:len() > 50 and "..." or ""),
			Info.Description,
			Info.Expected,
			Result
		)

		assert(Result == Info.Expected, ErrorMessage)
		warn(`SHA3-512: Test '{Info.Description}' passed`)
	end
end

local function TestSHAKE128()
	for TestString, Info in SHAKE128_TestVectors do
		local Result = Algorithm.SHAKE128(buffer.fromstring(TestString), 32)

		local ErrorMessage = string.format(
			"SHAKE128: Test String '%s' (%s) produced incorrect hash. Expected '%s', got '%s'",
			TestString:sub(1, 50) .. (TestString:len() > 50 and "..." or ""),
			Info.Description,
			Info.Expected,
			Result
		)

		assert(Result == Info.Expected, ErrorMessage)
		warn(`SHAKE128: Test '{Info.Description}' passed`)
	end
end

local function TestSHAKE256()
	for TestString, Info in SHAKE256_TestVectors do
		local Result = Algorithm.SHAKE256(buffer.fromstring(TestString), 64)

		local ErrorMessage = string.format(
			"SHAKE256: Test String '%s' (%s) produced incorrect hash. Expected '%s', got '%s'",
			TestString:sub(1, 50) .. (TestString:len() > 50 and "..." or ""),
			Info.Description,
			Info.Expected,
			Result
		)

		assert(Result == Info.Expected, ErrorMessage)
		warn(`SHAKE256: Test '{Info.Description}' passed`)
	end
end

-- Run all tests
print(`[{AlgorithmName}] Running SHA-3 test suite...`)

TestSHA3_224()
print(`[{AlgorithmName}] SHA3-224 tests passed`)

TestSHA3_256()
print(`[{AlgorithmName}] SHA3-256 tests passed`)

TestSHA3_384()
print(`[{AlgorithmName}] SHA3-384 tests passed`)

TestSHA3_512()
print(`[{AlgorithmName}] SHA3-512 tests passed`)

TestSHAKE128()
print(`[{AlgorithmName}] SHAKE128 tests passed`)

TestSHAKE256()
print(`[{AlgorithmName}] SHAKE256 tests passed`)

print(`[{AlgorithmName}] All SHA-3 test cases passed successfully!`)

return 0
