--!strict

type TestVector = {
	Description: string,
	Expected: string,
}

type TestVectors = { [string]: TestVector }

local AlgorithmName = script.Parent.Name
local Algorithm = require(script.Parent)

local TestVectors: TestVectors = {
	[""] = {
		Description = "Empty String",
		Expected = "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
	},
	["The quick brown fox jumps over the lazy dog."] = {
		Description = "Pangramm Example",
		Expected = "1546741840f8a492b959d9b8b2344b9b0eb51b004bba35c0aebaac86d45264c3",
	},
	["Привет, мир!"] = {
		Description = "UTF-8 Example",
		Expected = "2ecef582e43e1cf108c03f7f78da7f1c9908bce487738ee3e90bf0d548af6f29",
	},
	["\0"] = {
		Description = "Null Terminator",
		Expected = "10baad1713566ac2333467bddb0597dec9066120dd72ac2dcb8394221dcbe43d",
	},
	[string.rep("a", 55)] = {
		Description = "Block of Characters",
		Expected = "f6513468f05e7cec7d52fc337ef79dfa7c82520268d3aeba4002ead9a5642916",
	},
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = {
		Description = "448 Bit",
		Expected = "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461",
	},
	[string.rep("a", 111)] = {
		Description = "111 Characters",
		Expected = "0239e429f98d0ed61ee8e2a7c30afe98c1c3a80ce5dff62a107e9c538f7632ce",
	},
	["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] = {
		Description = "896 Bits",
		Expected = "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
	},
	[string.rep("a", 119)] = {
		Description = "119 Characters",
		Expected = "6cb452f832033489de69b49d6a8e8a1e0018092f1986c132287f4ca4ab3ee545",
	},
	[string.rep("a", 239)] = {
		Description = "239 Characters",
		Expected = "78d0a1b37aaad84c89fff13cbe3cd3d1025bcdb648268f9102b7e7032bea7d2a",
	},
	[string.rep("a", 1024)] = {
		Description = "Long String",
		Expected = "fe25c1c9bbdd2fad014a4d33105227865256abab8cf01d4b6675a3f8b468626e",
	},
	[string.rep("a", 199999)] = {
		Description = "Really Long String",
		Expected = "02f7539fbbb32c2dbe4e217f8a37bdbc39e1950700daaf73884ee1e79f2b13c9",
	},
	[string.rep("a", 1e6)] = {
		Description = "Million",
		Expected = "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21",
	},
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
