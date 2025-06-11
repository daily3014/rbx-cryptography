--!strict
type TestVector = {
	Description: string,
	Expected: string,
	OutLen: number?,
	Key: string?,
}
type TestVectors = { [string]: TestVector }

local AlgorithmName = script.Parent.Name
local Algorithm = require(script.Parent)

local TestVectors: TestVectors = {
	["abc"] = {
		Description = "Basic ABC Test",
		Expected = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
		OutLen = 64,
	},
	["abc_60"] = {
		Description = "ABC 60 Bytes",
		Expected = "bdc0b8b38bd714f166d1cf227148c8de5a5ed75da184589212d8a584cccd73a02422f43c4dd1a427b8fbad742d348eb81d8cb7492efe626fce490618",
		OutLen = 60,
	},
	["abc_56"] = {
		Description = "ABC 56 Bytes",
		Expected = "13ee23af59cf24b95795d6417d2592f96d772eb6c4866e51698ecf6d4848539251ae2ee731a28758ecbcd5cb5f3f005c202f509cc32975b1",
		OutLen = 56,
	},
	["abc_52"] = {
		Description = "ABC 52 Bytes",
		Expected = "9a5803f1993120dfbf7af41936779ae2192dee216146b264e8080aae7dc602926e8d533565d775b43be548cb67c49aa7cde9e063",
		OutLen = 52,
	},
	["abc_48"] = {
		Description = "ABC 48 Bytes",
		Expected = "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4",
		OutLen = 48,
	},
	["abc_44"] = {
		Description = "ABC 44 Bytes",
		Expected = "db1ccc0bf65b615c7269cf24b45ba65c665cb228ef77057ce4f9bec0b2821af9f9ffdd5441bd260ea1158084",
		OutLen = 44,
	},
	["abc_40"] = {
		Description = "ABC 40 Bytes",
		Expected = "8ad6d6166cdc8c2ffd5f25c5e7f957513b4a0e6661e998c3744a101363ac6e352858b0d412d5c322",
		OutLen = 40,
	},
	["abc_36"] = {
		Description = "ABC 36 Bytes",
		Expected = "b2b77f50103450a6aaed6b3b080dbe5bacde149c9587a0096149418264d1fee0b98dac2b",
		OutLen = 36,
	},
	["abc_32"] = {
		Description = "ABC 32 Bytes",
		Expected = "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
		OutLen = 32,
	},
	["abc_28"] = {
		Description = "ABC 28 Bytes",
		Expected = "9bd237b02a29e43bdd6738afa5b53ff0eee178d6210b618e4511aec8",
		OutLen = 28,
	},
	["abc_24"] = {
		Description = "ABC 24 Bytes",
		Expected = "56a17e38cc371a46b12c32f18e0c61de2a84e9c2555b114e",
		OutLen = 24,
	},
	["abc_16"] = {
		Description = "ABC 16 Bytes",
		Expected = "cf4ab791c62b8d2b2109c90275287816",
		OutLen = 16,
	},
	["abc_8"] = {
		Description = "ABC 8 Bytes",
		Expected = "d8bb14d833d59559",
		OutLen = 8,
	},
	["abc_4"] = {
		Description = "ABC 4 Bytes",
		Expected = "63906248",
		OutLen = 4,
	},
	["abc_2"] = {
		Description = "ABC 2 Bytes",
		Expected = "ae1e",
		OutLen = 2,
	},
	["abc_1"] = {
		Description = "ABC 1 Byte",
		Expected = "6b",
		OutLen = 1,
	},

	-- ABC tests with keys
	["abc_key_64"] = {
		Description = "ABC with 64 Byte Key",
		Expected = "c2f2d6db0908b89406dfd636c55abd50f31be6b13767a6258f61e476aca87416f876ce17bd336c3d3f6b6a2652f42b8480c3edd1ae66657f587f925b87ab8416",
		OutLen = 64,
		Key = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1",
	},
	["abc_key_60"] = {
		Description = "ABC with 60 Byte Key",
		Expected = "0a1af64a08b611489317551c2fab679ee167f522063f185dd9401abb9a98168fa28020d7a630d8f95890a9cde3d3caaee40e925b6ef4fbc6bef19b982b7afb07",
		OutLen = 64,
		Key = "bdc0b8b38bd714f166d1cf227148c8de5a5ed75da184589212d8a584cccd",
	},
	["abc_key_56"] = {
		Description = "ABC with 56 Byte Key",
		Expected = "5898daa9ef3e553095d750fb92c53d531350abdae57b590cd319ecc6dc8d0a41370e063344505f0016bf59b09ba5b5282f68830f5bbb40f117c74bfb678d6a5d",
		OutLen = 64,
		Key = "13ee23af59cf24b95795d6417d2592f96d772eb6c4866e51698ecf6d",
	},
	["abc_key_48"] = {
		Description = "ABC with 48 Byte Key",
		Expected = "be0a08a35fa7bac9f2441b52d41abc0b19981a14f1161575e70c28c18a7154edd2fb764cb45f17e87bec23a22a3454266b03777fb770be817c59ff80e349cd86",
		OutLen = 64,
		Key = "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbd",
	},
	["abc_key_44"] = {
		Description = "ABC with 44 Byte Key",
		Expected = "6dda971e92cd392f866c7442b585ca16a3b8e7e052b0cff9ce2cb63db3cd0e9bf88b3f9379d83d0e00e800d791db9b95cc375a4958effc68135e7d84d4fb98e3",
		OutLen = 64,
		Key = "db1ccc0bf65b615c7269cf24b45ba65c665cb228ef77",
	},
	["abc_key_40"] = {
		Description = "ABC with 40 Byte Key",
		Expected = "4bfd84ddcc52b007d929ce27feed940295fe37b8f6d28bd6ce101fd53a95bed870df7e2d88a4ac50bd7772d1b245af3d663cb6bdb6a8b1fa5eda24a859dc433d",
		OutLen = 64,
		Key = "8ad6d6166cdc8c2ffd5f25c5e7f957513b4a0e66",
	},
	["abc_key_36"] = {
		Description = "ABC with 36 Byte Key",
		Expected = "4d396810a9f4f1448f35f9de94610fc5067b44a3544fa746af327ccae319e7ea05b9f6d4705e1d668639db9ba636541ee582484528b6eb5310f8beff797a9e8a",
		OutLen = 64,
		Key = "b2b77f50103450a6aaed6b3b080dbe5bacde",
	},
	["abc_key_32"] = {
		Description = "ABC with 32 Byte Key",
		Expected = "a9ac1196ebf670f73f4764fd2d820c5c40818423a6f333fff98a6bb159aa24b20da24f44929c66c401c8a1d06d5d0f4af97633f276fabeddde3ed810c2385039",
		OutLen = 64,
		Key = "bddd813c634239723171ef3fee98579b",
	},
	["abc_key_16"] = {
		Description = "ABC with 16 Byte Key",
		Expected = "e1ca64e8abc97d6b08fade1e242f7c39340d74d4a9b0d3317ef9d2fbbf28a25a05fe83f4a7470e0220db8d1818f62029f57281d2aa608ebad9154a865ac2da70",
		OutLen = 64,
		Key = "cf4ab791c62b8d2b",
	},
	["abc_key_8"] = {
		Description = "ABC with 8 Byte Key",
		Expected = "bde1a9f80f3c88258053723754fff9d5155a5694a34669f7892c6469c0b9db6019b56b97ec25fa6b82173318fc27b67caee576cacd21e61f312bb6ea3c49c414",
		OutLen = 64,
		Key = "d8bb14d8",
	},
	["abc_key_4"] = {
		Description = "ABC with 4 Byte Key",
		Expected = "bef63af934a11a46a647ca0496bd03844cd52206bcf6eb95e8d1e815f7ca30415461cbeb269bfd09b8652518253fe00bb614e854a3f55900486799b474807736",
		OutLen = 64,
		Key = "6390",
	},
	["abc_key_2"] = {
		Description = "ABC with 2 Byte Key",
		Expected = "15cf17d6b18fcc83f2b4235492df9b98176ae9dba2de5b7ce29c8eb47b921fbbca7bd60ef779c437361a404090d30589626bf9d6edddf84027a7eef217c30bc5",
		OutLen = 64,
		Key = "ae",
	},
	["abc_key_1"] = {
		Description = "ABC with 1 Byte Key",
		Expected = "968ff3c3b73ad7825542c57d18f755ea5879894cf4ebd7a0720972ec627e563334f05c132cd62f3373b003564d7b87831f9fa306ae86b37ae9e8fe5977cc4836",
		OutLen = 64,
		Key = "6",
	},

	[""] = {
		Description = "Empty String",
		Expected = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
		OutLen = 64,
	},
	["empty_key"] = {
		Description = "Empty String with Key",
		Expected = "0532e878558d08b3586bb2771609976c0d7d521e23447086aff388ff65b2d643b11b180f894ded8fad97a1bf2c4ac48caf2234d85699e44a5c40187dea2c21f5",
		OutLen = 64,
		Key = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419",
	},

	["alphabet_448"] = {
		Description = "448 Bit Alphabet",
		Expected = "7285ff3e8bd768d69be62b3bf18765a325917fa9744ac2f582a20850bc2b1141ed1b3e4528595acc90772bdf2d37dc8a47130b44f33a02e8730e5ad8e166e888",
		OutLen = 64,
	},
	["alphabet_448_key"] = {
		Description = "448 Bit Alphabet with Key",
		Expected = "e1988e2c9f4888f90e0d299a1f1ea651802c441edda1444931bad0e3f5cd0ad6840259504c54bf4bee74400ded9f7b9d824cdbbb354722b609cd8423c4e004de",
		OutLen = 64,
		Key = "7285ff3e8bd768d69be62b3bf18765a325917fa9744ac2f582a20850bc2b1141",
	},
	["alphabet_896"] = {
		Description = "896 Bit Alphabet",
		Expected = "ce741ac5930fe346811175c5227bb7bfcd47f42612fae46c0809514f9e0e3a11ee1773287147cdeaeedff50709aa716341fe65240f4ad6777d6bfaf9726e5e52",
		OutLen = 64,
	},
	["alphabet_896_key"] = {
		Description = "896 Bit Alphabet with Key",
		Expected = "d64e6645fc551fcb490f6cdb97fc70679c02f38ede8ef9be5a65d2ea5fbd0e61581aada01a1af6986070659e3a4c7343f069d510aaf8246b30dd3290c8e03831",
		OutLen = 64,
		Key = "ce741ac5930fe346811175c5227bb7bfcd47f42612fae46c0809514f9e0e3a11",
	},

	["foo"] = {
		Description = "Foo Test",
		Expected = "ca002330e69d3e6b84a46a56a6533fd79d51d97a3bb7cad6c2ff43b354185d6dc1e723fb3db4ae0737e120378424c714bb982d9dc5bbd7a0ab318240ddd18f8d",
		OutLen = 64,
	},
	["foo_key"] = {
		Description = "Foo with Key",
		Expected = "1863442c12970f0f698383d9c8b3864e852c01cb49dff1a4e4a7f0aea90ed73177caf460b7396aee9739c2d991e8666b232965633c2a78b548f3f7535de8d3b0",
		OutLen = 64,
		Key = "ca002330e69d3e6b84a46a56a6533fd79d51d97a3bb7cad6c2ff43b354185d6d",
	},
	["bar"] = {
		Description = "Bar Test",
		Expected = "76aafe37ce69887569c3c1a51f14b639191fb2180cb0c87b566529496636712868556a9adf069d59769bf7e2393d215f195d8e7694f26fc7e20d92195973add8",
		OutLen = 64,
	},
	["bar_key"] = {
		Description = "Bar with Key",
		Expected = "aee2742827f9eeb2270fa21a8b630c59633855886791b43021d70c6fd5c8d9c590a339c629c2653c6eb8959de89a4bdac2fbde208434a1d0b6c0f363c856927e",
		OutLen = 64,
		Key = "76aafe37ce69887569c3c1a51f14b639191fb2180cb0c87b5665294966367128",
	},
	["baz"] = {
		Description = "Baz Test",
		Expected = "2305476f21a28dd31ba7aaa4bcbd92780ff6c3ee77d45ea025dfec737e6bc725ce391585326dc22208f77c2643ca4afa34334042858a6f250e9094c8f77c82f6",
		OutLen = 64,
	},
	["baz_key"] = {
		Description = "Baz with Key",
		Expected = "cf757dd4a0cfec70bf13dcd160852845560b9b3e8ce8020348825dd0f0e29716a081d5703983646957008ac2f1f6fd043a9c47bfbb9480176eeddc6cb6ee1e4f",
		OutLen = 64,
		Key = "2305476f21a28dd31ba7aaa4bcbd92780ff6c3ee77d45ea025dfec737e6bc725",
	},

	["fitness_gram"] = {
		Description = "Fitness-Gram Test",
		Expected = "7a17312276da3e41be9ef397aa035eadffe426afa70856d11155395f5af77932021e7db7995c536a86fbf9e840763f177d7bb2287c726a70b75494b018b6700c",
		OutLen = 64,
	},
	["fitness_gram_key"] = {
		Description = "Fitness-Gram with Key",
		Expected = "d4ad49ad88892b37a5067739e07d3af18fece632f023dd266a2027668b6628424d21cca8daa6fbffca724bb3e623526995a3a808e2e01553eda36e3ae2f74a8f",
		OutLen = 64,
		Key = "7a17312276da3e41be9ef397aa035eadffe426afa70856d11155395f5af77932",
	},

	["block_size"] = {
		Description = "Block Size Test",
		Expected = "cc28dceb6925b2e02a177a961a0f819f464e3fa78c34be6117ea8ac6fbe02b58e6c91a1faf5605d3be43b23414a99c0322ada77a088f3454f980be1d3df68813",
		OutLen = 64,
	},
	["block_size_key"] = {
		Description = "Block Size with Key",
		Expected = "a58b0e2f33b9fac979f77a58e30031a0ae5ec6c8946180bb1e03aaacbed8e94585f26c62925d1877e341076cbd5ae0ece4ac114009af2b6cf0f9e3671626eae4",
		OutLen = 64,
		Key = "cc28dceb6925b2e02a177a961a0f819f464e3fa78c34be6117ea8ac6fbe02b58",
	},

	["199999_e"] = {
		Description = "199999 E Characters",
		Expected = "720d7925523d2ca4e39e11e91231890446abaffd09f5e69628b326e5ad0295a4c0335726da08fc56120e52f378042a8146e2e56f38187f33bd23e8ec42b88f35",
		OutLen = 64,
	},
	["199999_e_key"] = {
		Description = "199999 E Characters with Key",
		Expected = "9ac0a89038f6d3a82b681a8ad902e9c4e520b2597c7478184639084ce4ba5ab05c16f40859269a185837b208888cf870b4e2aa0d60e8a6cb0b1e2643b69d5526",
		OutLen = 64,
		Key = "720d7925523d2ca4e39e11e91231890446abaffd09f5e69628b326e5ad0295a4",
	},
	["million_a"] = {
		Description = "Million A Characters",
		Expected = "98fb3efb7206fd19ebf69b6f312cf7b64e3b94dbe1a17107913975a793f177e1d077609d7fba363cbba00d05f7aa4e4fa8715d6428104c0a75643b0ff3fd3eaf",
		OutLen = 64,
	},
	["million_a_key"] = {
		Description = "Million A Characters with Key",
		Expected = "a01e874c2a19010ac02b16ea0eba0c03c434c00aeccb45fbe05b658111eff7dd254800b26c65819e420e4173e8731b4274a6561e3c7888db2d34cc488e315480",
		OutLen = 64,
		Key = "98fb3efb7206fd19ebf69b6f312cf7b64e3b94dbe1a17107913975a793f177e1",
	},
}

local TestData = {
	["abc"] = "abc",
	["abc_60"] = "abc",
	["abc_56"] = "abc",
	["abc_52"] = "abc",
	["abc_48"] = "abc",
	["abc_44"] = "abc",
	["abc_40"] = "abc",
	["abc_36"] = "abc",
	["abc_32"] = "abc",
	["abc_28"] = "abc",
	["abc_24"] = "abc",
	["abc_16"] = "abc",
	["abc_8"] = "abc",
	["abc_4"] = "abc",
	["abc_2"] = "abc",
	["abc_1"] = "abc",
	["abc_key_64"] = "abc",
	["abc_key_60"] = "abc",
	["abc_key_56"] = "abc",
	["abc_key_48"] = "abc",
	["abc_key_44"] = "abc",
	["abc_key_40"] = "abc",
	["abc_key_36"] = "abc",
	["abc_key_32"] = "abc",
	["abc_key_16"] = "abc",
	["abc_key_8"] = "abc",
	["abc_key_4"] = "abc",
	["abc_key_2"] = "abc",
	["abc_key_1"] = "abc",
	[""] = "",
	["empty_key"] = "",
	["alphabet_448"] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	["alphabet_448_key"] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	["alphabet_896"] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
	["alphabet_896_key"] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
	["foo"] = "foo",
	["foo_key"] = "foo",
	["bar"] = "bar",
	["bar_key"] = "bar",
	["baz"] = "baz",
	["baz_key"] = "baz",
	["fitness_gram"] = "The Fitness-Gram Pacer Test is a multi-stage aerobic capacity test",
	["fitness_gram_key"] = "The Fitness-Gram Pacer Test is a multi-stage aerobic capacity test",
	["block_size"] = string.rep("!", 128),
	["block_size_key"] = string.rep("!", 128),
	["199999_e"] = string.rep("e", 199999),
	["199999_e_key"] = string.rep("e", 199999),
	["million_a"] = string.rep("a", 1e6),
	["million_a_key"] = string.rep("a", 1e6),
}

for TestKey, Info in TestVectors do
	local TestString = TestData[TestKey]
	local MessageBuffer = buffer.fromstring(TestString)
	local KeyBuffer = if Info.Key then buffer.fromstring(Info.Key) else nil

	local Result = Algorithm(MessageBuffer, Info.OutLen, KeyBuffer)

	local ErrorMessage = string.format(
		"%s: Test '%s' (%s) produced incorrect hash. Expected '%s', got '%s'",
		AlgorithmName,
		TestKey,
		Info.Description,
		Info.Expected,
		Result
	)

	assert(Result == Info.Expected, ErrorMessage)
	warn(`{AlgorithmName}: Test '{Info.Description}' passed`)
end

print(`[{AlgorithmName}] All test cases passed`)
return 0
