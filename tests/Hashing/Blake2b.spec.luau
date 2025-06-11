--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)
local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local Blake2b = Cryptography.Hashing.Blake2b

local basicTestCases = {
	{
		input = "abc",
		description = "Basic ABC Test",
		expected = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
		outLen = 64,
	},
	{
		input = "",
		description = "Empty String",
		expected = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
		outLen = 64,
	},
	{
		input = "foo",
		description = "Foo Test",
		expected = "ca002330e69d3e6b84a46a56a6533fd79d51d97a3bb7cad6c2ff43b354185d6dc1e723fb3db4ae0737e120378424c714bb982d9dc5bbd7a0ab318240ddd18f8d",
		outLen = 64,
	},
	{
		input = "bar",
		description = "Bar Test",
		expected = "76aafe37ce69887569c3c1a51f14b639191fb2180cb0c87b566529496636712868556a9adf069d59769bf7e2393d215f195d8e7694f26fc7e20d92195973add8",
		outLen = 64,
	},
	{
		input = "baz",
		description = "Baz Test",
		expected = "2305476f21a28dd31ba7aaa4bcbd92780ff6c3ee77d45ea025dfec737e6bc725ce391585326dc22208f77c2643ca4afa34334042858a6f250e9094c8f77c82f6",
		outLen = 64,
	},
	{
		input = "The Fitness-Gram Pacer Test is a multi-stage aerobic capacity test",
		description = "Fitness-Gram Test",
		expected = "7a17312276da3e41be9ef397aa035eadffe426afa70856d11155395f5af77932021e7db7995c536a86fbf9e840763f177d7bb2287c726a70b75494b018b6700c",
		outLen = 64,
	},
}

local variableLengthTestCases = {
	{
		input = "abc",
		description = "ABC 60 Bytes",
		expected = "bdc0b8b38bd714f166d1cf227148c8de5a5ed75da184589212d8a584cccd73a02422f43c4dd1a427b8fbad742d348eb81d8cb7492efe626fce490618",
		outLen = 60,
	},
	{
		input = "abc",
		description = "ABC 56 Bytes",
		expected = "13ee23af59cf24b95795d6417d2592f96d772eb6c4866e51698ecf6d4848539251ae2ee731a28758ecbcd5cb5f3f005c202f509cc32975b1",
		outLen = 56,
	},
	{
		input = "abc",
		description = "ABC 52 Bytes",
		expected = "9a5803f1993120dfbf7af41936779ae2192dee216146b264e8080aae7dc602926e8d533565d775b43be548cb67c49aa7cde9e063",
		outLen = 52,
	},
	{
		input = "abc",
		description = "ABC 48 Bytes",
		expected = "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4",
		outLen = 48,
	},
	{
		input = "abc",
		description = "ABC 44 Bytes",
		expected = "db1ccc0bf65b615c7269cf24b45ba65c665cb228ef77057ce4f9bec0b2821af9f9ffdd5441bd260ea1158084",
		outLen = 44,
	},
	{
		input = "abc",
		description = "ABC 40 Bytes",
		expected = "8ad6d6166cdc8c2ffd5f25c5e7f957513b4a0e6661e998c3744a101363ac6e352858b0d412d5c322",
		outLen = 40,
	},
	{
		input = "abc",
		description = "ABC 36 Bytes",
		expected = "b2b77f50103450a6aaed6b3b080dbe5bacde149c9587a0096149418264d1fee0b98dac2b",
		outLen = 36,
	},
	{
		input = "abc",
		description = "ABC 32 Bytes",
		expected = "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
		outLen = 32,
	},
	{
		input = "abc",
		description = "ABC 28 Bytes",
		expected = "9bd237b02a29e43bdd6738afa5b53ff0eee178d6210b618e4511aec8",
		outLen = 28,
	},
	{
		input = "abc",
		description = "ABC 24 Bytes",
		expected = "56a17e38cc371a46b12c32f18e0c61de2a84e9c2555b114e",
		outLen = 24,
	},
	{
		input = "abc",
		description = "ABC 16 Bytes",
		expected = "cf4ab791c62b8d2b2109c90275287816",
		outLen = 16,
	},
	{
		input = "abc",
		description = "ABC 8 Bytes",
		expected = "d8bb14d833d59559",
		outLen = 8,
	},
	{
		input = "abc",
		description = "ABC 4 Bytes",
		expected = "63906248",
		outLen = 4,
	},
	{
		input = "abc",
		description = "ABC 2 Bytes",
		expected = "ae1e",
		outLen = 2,
	},
	{
		input = "abc",
		description = "ABC 1 Byte",
		expected = "6b",
		outLen = 1,
	},
}

local keyedTestCases = {
	{
		input = "abc",
		description = "ABC with 64 Byte Key",
		expected = "c2f2d6db0908b89406dfd636c55abd50f31be6b13767a6258f61e476aca87416f876ce17bd336c3d3f6b6a2652f42b8480c3edd1ae66657f587f925b87ab8416",
		outLen = 64,
		key = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1",
	},
	{
		input = "abc",
		description = "ABC with 32 Byte Key",
		expected = "a9ac1196ebf670f73f4764fd2d820c5c40818423a6f333fff98a6bb159aa24b20da24f44929c66c401c8a1d06d5d0f4af97633f276fabeddde3ed810c2385039",
		outLen = 64,
		key = "bddd813c634239723171ef3fee98579b",
	},
	{
		input = "abc",
		description = "ABC with 16 Byte Key",
		expected = "e1ca64e8abc97d6b08fade1e242f7c39340d74d4a9b0d3317ef9d2fbbf28a25a05fe83f4a7470e0220db8d1818f62029f57281d2aa608ebad9154a865ac2da70",
		outLen = 64,
		key = "cf4ab791c62b8d2b",
	},
	{
		input = "",
		description = "Empty String with Key",
		expected = "0532e878558d08b3586bb2771609976c0d7d521e23447086aff388ff65b2d643b11b180f894ded8fad97a1bf2c4ac48caf2234d85699e44a5c40187dea2c21f5",
		outLen = 64,
		key = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419",
	},
}

local alphabetTestCases = {
	{
		input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		description = "448 Bit Alphabet",
		expected = "7285ff3e8bd768d69be62b3bf18765a325917fa9744ac2f582a20850bc2b1141ed1b3e4528595acc90772bdf2d37dc8a47130b44f33a02e8730e5ad8e166e888",
		outLen = 64,
	},
	{
		input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		description = "896 Bit Alphabet",
		expected = "ce741ac5930fe346811175c5227bb7bfcd47f42612fae46c0809514f9e0e3a11ee1773287147cdeaeedff50709aa716341fe65240f4ad6777d6bfaf9726e5e52",
		outLen = 64,
	},
}

local largeInputTestCases = {
	{
		input = string.rep("!", 128),
		description = "Block Size Test",
		expected = "cc28dceb6925b2e02a177a961a0f819f464e3fa78c34be6117ea8ac6fbe02b58e6c91a1faf5605d3be43b23414a99c0322ada77a088f3454f980be1d3df68813",
		outLen = 64,
	},
	{
		input = string.rep("e", 199999),
		description = "199999 E Characters",
		expected = "720d7925523d2ca4e39e11e91231890446abaffd09f5e69628b326e5ad0295a4c0335726da08fc56120e52f378042a8146e2e56f38187f33bd23e8ec42b88f35",
		outLen = 64,
	},
	{
		input = string.rep("a", 1e6),
		description = "Million A Characters",
		expected = "98fb3efb7206fd19ebf69b6f312cf7b64e3b94dbe1a17107913975a793f177e1d077609d7fba363cbba00d05f7aa4e4fa8715d6428104c0a75643b0ff3fd3eaf",
		outLen = 64,
	},
}

describe("Blake2b", function()
	describe("Basic Hash", function()
		it.each(basicTestCases)("should hash $description correctly", function(testCase)
			local messageBuffer = buffer.fromstring(testCase.input)
			local result = Blake2b(messageBuffer, testCase.outLen)
			
			expect(result).toBe(testCase.expected)
		end)
	end)
	
	describe("Variable Length Output", function()
		it.each(variableLengthTestCases)("should hash $description correctly", function(testCase)
			local messageBuffer = buffer.fromstring(testCase.input)
			local result = Blake2b(messageBuffer, testCase.outLen)
			
			expect(result).toBe(testCase.expected)
		end)
	end)
	
	describe("Keyed Hash", function()
		it.each(keyedTestCases)("should hash $description correctly", function(testCase)
			local messageBuffer = buffer.fromstring(testCase.input)
			local keyBuffer = buffer.fromstring(testCase.key)
			local result = Blake2b(messageBuffer, testCase.outLen, keyBuffer)
			
			expect(result).toBe(testCase.expected)
		end)
	end)
	
	describe("Alphabet Tests", function()
		it.each(alphabetTestCases)("should hash $description correctly", function(testCase)
			local messageBuffer = buffer.fromstring(testCase.input)
			local result = Blake2b(messageBuffer, testCase.outLen)
			
			expect(result).toBe(testCase.expected)
		end)
	end)
	
	describe("Large Input Tests", function()
		it.each(largeInputTestCases)("should hash $description correctly", function(testCase)
			local messageBuffer = buffer.fromstring(testCase.input)
			local result = Blake2b(messageBuffer, testCase.outLen)
			
			expect(result).toBe(testCase.expected)
		end)
	end)
end)