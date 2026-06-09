--!strict
-- Auto-generated from Tadashi/testvectors/hkdf_sha256_test.json
-- Do not edit by hand.

return {
	algorithm = [[HKDF-SHA256]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_kdf_v1.json]],
	header = {
		[[HKDF with SHA-256 per RFC 5869, with bug-catching cases targeting the extract/expand split, expand-counter advance, output-length boundaries, and empty-salt/info handling.]],
		[[Each non-KAT test's targets[] lists the implementation bugs it is designed to catch.]]
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test from RFC 5869.]]
		},
		EmptySalt = {
			bugType = [[EDGE_CASE]],
			description = [[Salt is empty; HKDF defaults it to HashLen zero bytes.]]
		},
		EmptyInfo = {
			bugType = [[EDGE_CASE]],
			description = [[Info is empty; expand inputs become just T(i-1) || counter.]]
		},
		EmptyIKM = {
			bugType = [[EDGE_CASE]],
			description = [[IKM is empty; extract step is HMAC over an empty message.]]
		},
		ShortOutput = {
			bugType = [[EDGE_CASE]],
			description = [[Output length 1 byte.]]
		},
		OutputBoundary = {
			bugType = [[EDGE_CASE]],
			description = [[Output length is an exact multiple of HashLen.]]
		},
		ExpandCounter = {
			bugType = [[MISSING_STEP]],
			description = [[Expand step appends a 1-byte (not 4-byte) counter that advances from 0x01.]],
			effect = [[Bug if counter byte width is wrong or counter does not advance.]]
		},
		MaxOutput = {
			bugType = [[EDGE_CASE]],
			description = [[Output length equals 255 * HashLen, the RFC 5869 maximum.]]
		},
		LongInputs = {
			bugType = [[BASIC]],
			description = [[All inputs span multiple hash blocks.]]
		},
		HexByteOrder = {
			bugType = [[ENCODING]],
			description = [[Bytes are asymmetric; reversed byte order would produce a different result.]]
		},
		HexNibbleOrder = {
			bugType = [[ENCODING]],
			description = [[Each byte has distinct high and low nibbles.]]
		},
		Pseudorandom = {
			bugType = [[BASIC]],
			description = [[Standard correctness check on output value.]]
		},
		OverMaxOutput = {
			bugType = [[MISSING_STEP]],
			description = [[Requested output length exceeds 255 * HashLen, the RFC 5869 maximum (the expand counter is a single byte).]],
			effect = [[Implementations that let the counter wrap emit repeating or undefined output instead of rejecting.]]
		},
		OutputCollision = {
			bugType = [[FUNCTIONALITY]],
			description = [[Distinct salts producing identical OKM: a salt longer than the HMAC block size is hashed first, so HKDF(salt=long) equals HKDF(salt=Hash(long)). Documents an inherent hazard of salt handling, both outputs are correct.]]
		},
		SaltHashEquivalence = {
			bugType = [[FUNCTIONALITY]],
			description = [[A salt longer than the block size of the hash is equivalent to the hash of the salt.]]
		}
	},
	numberOfTests = 13,
	testGroups = {
		{
			type = [[HkdfSha256]],
			hashLen = 256,
			blockSize = 512,
			tests = {
				{
					tcId = 1,
					comment = [[RFC 5869 TC1: SHA-256, 22-byte IKM, 13-byte salt, 10-byte info, L=42.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc5869]],
						version = [[A.1]]
					},
					ikm = [[0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b]],
					salt = [[000102030405060708090a0b0c]],
					info = [[f0f1f2f3f4f5f6f7f8f9]],
					outputLen = 42,
					okm = [[3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865]],
					result = [[valid]]
				},
				{
					tcId = 2,
					comment = [[RFC 5869 TC2: SHA-256, 80-byte IKM, 80-byte salt, 80-byte info, L=82. Long inputs combine multi-block IKM, salt, and info paths.]],
					targets = {
						[[LongInputs]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc5869]],
						version = [[A.2]]
					},
					ikm = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f]],
					salt = [[606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf]],
					info = [[b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff]],
					outputLen = 82,
					okm = [[b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87]],
					result = [[valid]]
				},
				{
					tcId = 3,
					comment = [[RFC 5869 TC3: SHA-256, 22-byte IKM, empty salt, empty info, L=42. Empty salt defaults to HashLen zero bytes; empty info means expand inputs are just T(i-1) || 0x01..]],
					targets = {
						[[EmptySalt]],
						[[EmptyInfo]]
					},
					flags = {
						[[Ktv]],
						[[EmptySalt]],
						[[EmptyInfo]]
					},
					source = {
						name = [[rfc5869]],
						version = [[A.3]]
					},
					ikm = [[0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b]],
					salt = [[]],
					info = [[]],
					outputLen = 42,
					okm = [[8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8]],
					result = [[valid]]
				},
				{
					tcId = 4,
					comment = [[Output length 1 byte. Smallest valid output; single expand iteration, take only the first byte.]],
					targets = {
						[[ShortOutput]]
					},
					flags = {
						[[ShortOutput]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					ikm = [[70617373776f7264]],
					salt = [[73616c74]],
					info = [[696e666f]],
					outputLen = 1,
					okm = [[38]],
					result = [[valid]]
				},
				{
					tcId = 5,
					comment = [[Output length exactly HashLen (32 bytes). Exactly 1 expand iteration; T(1) becomes the OKM verbatim with no truncation.]],
					targets = {
						[[OutputBoundary]]
					},
					flags = {
						[[OutputBoundary]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					ikm = [[70617373776f7264]],
					salt = [[73616c74]],
					info = [[696e666f]],
					outputLen = 32,
					okm = [[38cfafc6eba0b5e2ae3b8e179ec92af63213abc9729f1c26c76ac5e8fb863758]],
					result = [[valid]]
				},
				{
					tcId = 6,
					comment = [[Output length HashLen+1 (33 bytes). Triggers second expand iteration with counter byte 0x02; bug if counter never advances past 0x01.]],
					targets = {
						[[ExpandCounter]]
					},
					flags = {
						[[ExpandCounter]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					ikm = [[70617373776f7264]],
					salt = [[73616c74]],
					info = [[696e666f]],
					outputLen = 33,
					okm = [[38cfafc6eba0b5e2ae3b8e179ec92af63213abc9729f1c26c76ac5e8fb8637586c]],
					result = [[valid]]
				},
				{
					tcId = 7,
					comment = [[Output length 255 * HashLen (8160 bytes), the maximum allowed. Exercises the expand loop through all 255 iterations; bug if counter wraps or terminates early.]],
					targets = {
						[[ExpandCounter]],
						[[MaxOutput]]
					},
					flags = {
						[[MaxOutput]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					ikm = [[70617373776f7264]],
					salt = [[73616c74]],
					info = [[696e666f]],
					outputLen = 8160,
					okm = [[38cfafc6eba0b5e2ae3b8e179ec92af63213abc9729f1c26c76ac5e8fb8637586c416f57b3fe81c03dc98b6f82021887b1259f5b78dbeb9c41b7c81c793d710c3040cb3ed20da58ae7530fad8e5c759318dee2e9f98b950ea58e01d9058f869066524b809a45467abfb385a1a16f45992e7ff99311b7c8741d9f86dcf5725fff80625f24dc0f453b42c76a20b87d0bf619143a09fc0291b6d595099f4ec6d45fb0e32f42bb1d41774a5557aceaa37350f7fd2819781233d8c58226957f9ed71c38c0e04743b5eb83aaa6dc271e8bf5571ea5a3ae7f3fade8862d08bc1d58cb6886d5bdb23a52f52a21df799a9f5fa9b9b121bf397db39c2a5e2192d1f602b3f3a9925fb7bb744dd454c1029843ad65501d512b2e740c1703ebf87b3ace978ba8eb097dce15fec7f9b648232e1ef2d78ddf17ba21d744f04f7a9d8f5a7faa7103446efec2e27f37251499cafcb2bd622d852fc0f3345995f2ef651380a26071ec99a5d8263d017cff2c70ccfdfe589073c3be7a5d0c67c0d91913c49e580ddd3448b50e0449d50f427c25adb9291364b83e384896af3bc2e7765a6136f2a45274a32662b954d80da9015aced8b9f011137ce202fd654e9febe1c225994e08ac121da4ea311ee7cb7a948ff8c6751a08530949319d356b8174d7ce2c87e64e3d5271d84675bb0d564656d034ba250954f206a247f40579e29b161a28d475ca9cb9e4f0899d0fbe15131986d340a4d8f9aef91a080cb2319d485232a11f4d878c0614cb1a6ad92a96bc6d52377b313eec1b273e097b6b8405e152c1365cc5f1cb1339e1481b6c9c48ea9393dcd6346472872821b36d112ef945757cfd5cb35cc6cf9d969cebfb01dc35d53244a8abb48c5fcde9d788d8ab5bbacf5bb2b82adeb520fad91b1c4cda7b7dca4ff29c185b34234d312645133c368fde578d7ce41f0bbe03099b89f49c4ab1099fe9ca6a5dac10cbc66dc9c10c3822f0a272c1c0e8e4bd6bd298d0b76f09e4624e653816c1962d08722d0aa0afdf351f0ffeb9d1fecded07fd5a8790f1d0ac5f9233e98153ccc92f4edc9dd27ff3518a844267e00a4f12f0556921b2a114d558237a57f637f98fc1a409fe0afcf2755f176cfbabee82aaed191e4bba5c805ddb190a187055d87a208b5b13005b86265a23f296649c78017e0f546cd7c7de34c4ca0d5844de76f315464a83915455a87e149b550806c80f738684593a789f877dc86219fbdc104a7d4a78c41ce3a2772416663d75d26d7e5097b2223bc373c4c6dbc911a9b37dc8fe2742a8a9501865e2e571c85014870548569a6569d4171bec14ae6048717baad082e07e8f7aade819ee7cc487a48bebb382a0d4f3f80ff39e1cc227f8c7fd63b21414285860c2f2b69bc15024d680bdee65e484c483043fb5398a33129a779525c48fbb3ffb1b9549ada8df42306a330fd04a631f65d57f9d035af2ba46ec7c33f21196a5eb655652ca22de0b3e3370c738debcdc4db6ffcc22768fe9a52cbf2950ac8719926923b737530338a08fbce4fc86d774b2e19f71c835c16d0cb8b0c879bb73f8e40b8e67be36c8dbbc5e369620b5de517a391508f55d1cf713690563792f255645084e5845b5c5b23aea6bcb672412e53a4bac563f0f8c09d0c26ea620160cdfdc1a68201dcb3d07b8fa8f1389c7365bcc43ab94743ebb09756de0f7b51a6d52d819309fb40c2fb644f26cd2ef3cbf5095d961c03cdf2ba71e7ce6d9c2f9a5bad8fdb793defae95d10b74ef2da6352554dc1ea2480478ae0cea9c293f0b3e9c2100cc7797a11fffc74f781889936c885e50bc46a90bc615d3a17c558d263962a7880dc5efbe8f70d224c7962db7cfb06172f604b394148d8eb00e3e9cc7f0f0a2356540058caeee6aa4f97f2941992c36695c3f311a01248053083c96e9ed3f74a215e02683331f1f34fee3ce409e6e2063a7afd3d94c6e94499ba5c78eb46c43996fe77f6380644d22d72ce26fdfbb1e71b6ac69aab25c3acec078d65e8401b2d2ef6fe9be0e8384d3487b5a5a06a03359b5e9ef660c8f2d89d37619b9b9011b026ee889dd03732720a5a06a43f6b95bd19a87d26ace04036027a7f23c68ca898cbf226e519e25ed4d6e6975edbfa8d07c5b01c61cfa29fb819370507f672f97ff7db6eb0c2d1583d42eeba6bc84fb9c11fcdae47530c87e306ae6547c701a8123c93436c00083af6688f1bf55b975b5d4069424f8e63dea1504a22511d4065de0d46e5b810ecf0c7eab405f30147083544c839d3fb955c9f9dc0051b65234856490a8cefbb3b8c2bf1c48775ee88324f21a327ef91c756fc7b8ffdc4f581ac4df720af28851186ed049a3f60c220b22a1595b899632f90d6f0554c2efd67cec07e574e00cd3ef5133e3ceed4b7b4749ad192b8a6c9e6fbe658f1a0720883f1b6c8f81ed3c8ee3ea273a72d0905aa3aa1b9d2bece90eeb7043b9b669366d6ff957a09ef27eee14a171224a01fe2ba555c26515aec72d204d6f461b4330d6ba118b40d4339939093f9cd4bdf9da9852a64730a586b6412a70c411568e3c4ef84b5fee6c2560a1011247843c059fa0e8e0d82098e5e51de29d254f6c85f2276a13ba46625590bf1f8c92593c8db520171472e6b98f3cb88d77c84ffacb90a4c489f5000ba9abea94833b2e4dd5d431788a758bc45e82740e6f06b1cd3afa50fc992fa527463e0ad09af477439190e1be8a9ef4f760d377c160fef8cec84681c919fa811755a6c8a3c2c0169dadd5f6b5d51f25b7ac1f1c20aa73b32aac8206dc306be70b11e79bde2bd20032537eb519ed6607ad4b693fb38446f2a44aff96a9672fced9be24641bccdcc350f22ed83bc1a2656d7fc79108920a6a89e6ac136f151d5b034c4c8b0d61dfbd821367209f45d221f0c388d0b1f303d261472e9d6022ba4dd6b3139bc0abd4c1214a77aab370caf093b407a676f5414635c01e6cc160f34e3d8ec0cae5dc0393df4875158dcf1d6ed243ec6b2d683bb10c5cc01a5b2e4c9776e5c5de20a9f7282f93a7d637a32c925d6e2caf73e61868b58f6bd082a100becc8bc4fb198594e16548976b6aef6193a79d06e5ac603022796591b2804978ba5ddee2271f38b2abffa2d569a892350c854038baea8fdbba5bc9d9fb1c8f24e5cdbcf0074cce39671ab4992a0a9a82f3e9118ac34661f7b64bd8172d2cddb219c82519809ccbb5f7ecb968a9864b9eef88d076135a1e8b7dd5cfd6ab24154eb96f5d8b6447d68b8c747977ba1ffa95dba0b6fe45446e869556d200098b344725e729ab75f5ca2ce59373528b0c992213360e702312df6e04c21ba94890787aa26ed9b835256246107fd44d539128bbc6f9b37f4b514721eedcd1e3ecb2a2d89baed3cc3db2bcbd72c41718d2da7f95459596c784d1485e260eb69c2d9c66f03f4958aba8eb98cb49288774ed30bed08a3537303e8fcd2d2d0e7d56eb27a77e0949d6ca070aaf4a80fdc0f6580747c24976bbb6c70b6ea88f490cb1ee721abd40fbaca6f6fb206bb8ef52c42c29052d7f56a87d5942949561cb5d9e194135f636d2d4bc158a7002890ff04151418aef29242990c67496013dd953ccbb51d800f0a2f81278efb9dc60d219d91eeca1f75c3266bac0b84329d1be92f3f5c9fb1290ed067ceda240813a51a4c0b1e892b6e642c2d26178e2c9b596bbf4bec1c0c42ac5066e8c384afb673dccffc3977ac0dcdaa72b70f4f79316e2545acad6aef220aefee5d88bbbb05cfadb8c052fa29f350b2fbf8effdf540f8c898bb39ad2bdd02c30eadbffdc2c8c9ebaa291a24c80b28471811c0ee601d93d528d924cdf3f93400311f7a92d5bd011c99d35f6fc7c970c0a4f3b63b038d96a91e7b804d52ee09a4e048dfbad1d75502c009d2e5d5ef4900cbc16ac34cca13d8f98e2b80532770353ae494227c0c25d1ae323b4cc00fd5a0eff9a042a541aee9865708b3c3394f4dadb5dbc2abf9629f9ad67b2ae96dc2f5b77503d1f4978c29fd84dce55b965dbd694756d22dabcb20345c8f604d600d326ef5ae511f270d571ee0552b60932fcfd1d3a30e301d0dcfc1bd64d962e747338ca511f06ad4ebb496b12dc2a4dc6d9905e61a2539af57f3c47814a68e09ddc743030ca9f1a3340bc4f478bfac151ed8b3cddc1d2cce88fd6c09d610e82a047d0e9692b52d9e980ddb98e8a3dc0fede7fa9e27162dd6742b1d5aa7227c924204f7de8991d682a34324108f71df1ee309d9fee437a4564b4d9e9e5c338a46e2618af5b34b7a9c9f79b92a31570924486766e14777249ea9f03b13412b8e20f343f97f94807d7275b559753bf1617eb18117bbf06c2a5974f8cd536bfab1d2c30ddf4ed469b2baa550a4c2aea3e78f1b368b606c11a1493ce15ae69cc7afd3c0f73c5ba35170d51c7900f2c5c51e2a76bd087633ec846b8070d205f1e497144007134ba2382f603e283e7d93050dae9bc77f88f6e9629d36c72a80340f362254543f34021482099b13c8d0741a6918d93dd68b072966c884660ae056433f7784843158fd513d664886a6d1dd4062d418ee76993ddfac53fbb0514754bf609b6a8b68abb650888ff2b6a93166e62278637c686467db523e7ea2b711d6b9296a12c29e5f6aee812fb437b8e3700bd0ef3e37549087a8fd4f8ab699b25fec1ceb8eb32e6794673896778897fc744be88ecd1a129661cce4e3bb8641ec2d26ad7d901140881910eb4e197fd4f9b37642e10434b66410266b79e8a34cffae5f59e5f4534a24e61f84c592d46d18225e756a1aa44e3b656acd62f10460279b395f3ccaf74555197994b643780d17d3c961d77303ce29170f681f3e73699f52438c969874588c1ed9ae9e402934af929d6ebd9ca3386bb64504e39b8fa952526cc7bbe024c7659cafafc99c14581188ab35feb22278215c57d5fc0ac3df720598f60c74ff60f05287871f8d10b9e8788f205e325fee0c57e63896d8ef53a96eb42e28dde3db7f52628d5f94189d231eb6460162f5708b5638551f450faba6a4ef26fce231477f5d25913d422053c1e44e2c66d4fd056c7557050431714f75fdeeb26920c6f8098f1af983cf65d3d3622c4cc12932844a9b9c0cc815d172147630b595dfeb71741cd2207261e189339744bef969668a9afea608900cca9270bbc3470f66153f9bd3c444622ac08a482ac9326a612e42b43b7d8f1d5a627d30a119c4931caffd7fab8f55f5411cfa96c681a327d4b1d5b7ac28bf64e6b8dcc723be5c88331e70376cb35c7c44da7945dc0dff787af734464604e3b1a16aeae3b9ec9aeaf5520b1f4858ea22b132c477bf49329061dbccd4cbb50fb6db7a12314fbd7ec4d57b3dcc274d551cdfadafb688313f6a1854fd09a8ad48802adcfe7aa896d2cb30bc7940812d680ee936677ddb3342e13543143b8c12f9320a8e1080d0b0ee4edd16cac3ef4b114ea110f5cc48aba2adcd4cca72a1eb52bff8f453110e2636adb57719b15ba4062755e57f20dd67dcb555e46f4a37ab315d2851cf40c6c050ed849c3ec75e0c9488a25a74f8c4e395c551c5fbc727a055e027744d4d6ba463625fe78dedc5ab26d07da65ebab5eea365a785ea54045501e526342d92fa8d121263b256233a71e04e407176177598e972a41b05ad76ddcd3d353e393c6cbb7f85414286a36b3505877cc6ccf43f8c50c791961177074cbb82fdbc58197b8616404edc1f62057fb9ae3aa30518da6af6e8c1f264544fe7bc0f07803f868683f17b341a8cfc25c2936460a28a9338e8ddad651db3e6b514b7ec0e3e6aa14b2cc15b0935376d3d7b31589474031cec76031ec8c6d9cf542f64a02869d7ff2f2c94e8e08a0c3c50a7435be4f98bf386c2ad3a3cf8ad1d4fd89e6a8955076e62fde571b921bb56fbe6269e60c2f30b448d2fa01bc843ed04cbd171b03b9e79a31bd2f3ad36d0ed92dabfc33c229aa2856c92345973f4796ec92fb497f31a935d89f03eb93523a0fccf5915abb280de29af3a23d62246b3488e42c6f84c21d1f1fb229a6f7aad79178cf6f34b1ca162b87f906650626a639f2689b355b70cb8a04d3cfc7763f96020bcbc946e11885abfa797fb77a086c67c19bdd5a00baafbe13f1dcd6d523847913c5fb4ed27674ecdeaeff098b7238f96712be6176ac984c847b5a768210c40834871a6c759042da04cba9050e2c05bf9780a42c2f6d87d2f3446b47f402a0e449ec886f2772e3e01043ca12aa4e93a886b7f788d7844b78d228b05a5e58d27a6641453d5a704ee316c6679dd0410f3b1cc78d11557074f40af5daaaf20fb9858bde7b16ba776be56efae572fa5918a736082925be3fcc864d8c7cb91cc6aab87176eba4272e06d5b749b896956b679a8cfef1e6c8a2b3ec638cf9b5f12aa907b9b8e5ba05e4a70ae5c6272de745e02ebe04248507e7307fb5db01c2292b0ddd820854d71fde2b21ad9d83febd9ff548c017b0d80f20222540678cb6624dfaabdc4523647574e0ddfa0277411d835580dca4d141a44ebc50f7ea4141e2d8ee8f0f8f2af153926da1e347df6f684e3ccb1ee764c0c89adbd68777a1021d0116ed8c2f8bc8912c44c87ccc9464f5bd2439bf064d34c3181768fa6e7f3f05df0fb3d6490c40013b4b5e3fb27c09611edff52adf8d6fb460cfa0aff56260c83133b6c650ac9bc3b7333ea8c40eb1ee793ea3078c77f28cb603a3efec8cb821bac461d617590cbd2c8d57d495d107361c24f34f39ca2488be94bec931441232d472d9966c9064c4d05036d976628ce347a4e7c2f8cd295b8329578f46f1bd751e617a04f9432597404cbe1c8eb9635b726b0042d8d82acc1e023eaa733983f301b1695428d288a5aa9dd06e05903015dc87d998b934682d95b4bdf41075fe4241dd43e8f7dcd5bf576b1ad56c26ed0e31367b3a8a40feec1403b88e2482c4e9f05ffd10ac387fab03780e571db0b43fdfb498a7bde0993b5bc9693cd335dbddea11741457851456da48e20ff962a6b9aed39f8589b42250cb2308b411b59713c8fe60e11c2222ab76afbebb5410c72491d809412b62bf5116582d9b700e042267aff80a6c9b36025e93e1a592df00e224e73ccaa8355974e84d10c7ff589b340ae3787feef6e3b7b6bf0389870a46794c0beb71d830375e2df4f4795e09bd9f5b8b7d41bf2e124db12d03e2146c5c86a99eb5149c2c91662e65b2c7d50f062d76f3e436cb5fc6d9b7d68c124fba0e666579b97acaedc67d547e3b2bdc1ecf0578a10a5b8f539b74de3cf8db106bbb47dd20c8cfba054d0d2520385e9e8b34b4975b32b1174b4ca6d54877cc8ef70849883f427f89a6ac82c622a41a68d3d44aa1482ed7eaad1441a99d85722e3dd289eaa183a13678abd8036f26459dda3ae325257e4fdaa73adccb1e388dfe07d0e990ce0640b07540d33bd9f80dc7f56272f68120c67d626c039d8986db2a5b564c635411deef863b8ce81f89cbb56ac4e835e5962165bd2b2be01fe2f7ab5d2d370d7fe1fad8f519421bda119f29e777147f1767c7979e97c4f95da187223d4bf9df4acc57ead1546a328f1c85c8ff5726fc9a5f3503048d543970c03e06ed390e56e7c2d4a5c91aab32ab7b149167f3b83fc4ac212aac0da39933e4390b7a1b777d753f2ae75da9413b211ac66fc762fd63cc2a0245113fb4920a9316dce6a77e07c6e7209d7b1e5bc9a0c8bfea6956ce164098c583a40d21aff9a4f7bab9f5325764a19bb7a83c22d7f79f4bba1b135fbe6cc649da2c044c3273daabe751640c569a0e542df776373e74da42a3ec9298242ebfc10b0a81da3d362a9995cc7d7498eac74e6cc5db21aa9464754da986ad7e46f058431af49eecd85dca39a9d87905717c3cf498a705c7675855bc275b48285462d0a32ff21d070503c95fbf9eb4f5a95e1e20c3d17c3a8341e1abd90ac2c1ecd6c2fbf1621dbe1cd316f4118de5485fadc0b219473eb44e51f06e7427b49c9a15e1c3eda3f36d22514c765fff3e46a7afe9ca50497c9a581bd62489d11e5635ace4835fad38beffa31115119a1a9e24964d2d4de377949be6a8e5ec8d29ab4747a21240438a5f9917919ef2d3b2f9602086c15b99607ad2c0450b482b335daa85f1dd0bed9cc1a52b10d7dd2c6849b97adefebf7f2062d8e52416bacfe8d30c0c67a3916b257b91b8e2012c394e6af8b84830ba76d878c3e794f234f847e7d60fc5a10ae39eed2ba7a02b55dc1582dd795c18638e6d16d46e0f3e4b04a247311c981b6cb03bf3cea1e77367a0935aa37bb716754229bbe15e49fef07ca5863e73f0edf6ce9355138a88b62110e2c3a7c5313fea0a13dcaf19b6c3655087f8b90479617628b05052dc31173a3e855f0358cb930733750b91bf4d1e46cb511605158d5acd4ec33bfed619fa173cfe4d2920867b582981be70fc762c193f7b4bbd1d305e4e0a0bee6bceac148fde8f209262c5df666899099af3c056d1bf7244e8942a6b99ca4f96591a47b2a6be51145277a73e70d7040f1ab63510505ad5be4ea67059dfd44462bb25585fb8ef8f4f997f88460b6af61bac9d5cd4ff8a911e8a6a2c5c19721f90c58f92f90f870660fa3569a397fe733d3f7c3fbebbb091cfb07e8385bb63ae7fdd0f2fd06fe81fc3d4c3525c13737a9813cb6a9d16d3065cc5e2c267f4439857f18e16b2257eb8a94398efbee1d26e5afa552a145266bb096ba78073d2d59f3ba26d8fcd2360b748e84aca9f463aaf98b930208edb9f7030a5cd5c939f79e2bc65e97cf90eb3c5347ce6c8fe5e979fe7b239d910c8bcfddf37851af44ffac41f39573248b6d3440487e0541bba857a78c51c5f37ddc8435c6d7545bd2d0e9c1d06a5a66d530bbb0c3c2d5cc1f5ff5b26f5b897c5ce8580b86a142385d4257564553330a58e3a8ff3a91e908bc5c9a62dcf1b9f205e10da1dcecc19f881f7cf7e84d4c9c8f1dd8eb171f0b707d2c4bba8336870f7c97bb3d913901b767df1dd54021fd57ecbbcb9f7d722b77df9b8a45103b3cfad3a7ba390f22f1243d15ae636fbe72f5465c11c53719ee9eb3d1ad67ac31203009dca8fd7700f40de0162bae35262be88ecb2e4f981a5abaf3648020e0ef0805169bab5e0d4ead71808b3861ba7485dd1c55ef56521fea58f00e32ad7829333e1e870380700227d202fb67951dc10a258541c78e0e2a22f694f043e6a2fafb6cd0e10ccafa10799b16be853c7100ef25d8af1717780cb70a755b6d696c87d10e76730b5b3f96325f6b1ad600e478e3c52359e94812005e3dc68a0572558696c0e72515212cb59e1abebadff15c05d8c08c22f40d27aeb2dfebb1f6f8ff7d29975620f631810fa180ae14df15ab73b7079a93d1c5137cdad74e69f10033e6e2c8d511c2b7063d3aff33ddba19b2d68507282ec066e13b9f0a184654ab0ace9fd0f3088f328b3f2eb13c328b05a496a215bd8eb74808a84de97ebdec35b213b14f8580cc55c49cac333a9ee369e00e498d66dc2b2f6ad5591cc56cf867586da9b4705339b73a2242c36c36fb75ae397d413658ac8f8ddf9836b236ea11556faa9abc79e4cd610d221324e809f708c599b3d35afd7fa629d8a9491e03e03be88b83bd10d9dbe2c9a29bf12f04e115d32101d1eab0cf8783bd86a6b6592f69dc6a207e134e7d1138a796b63cdf8ee28521f7d7de71c2cac0ed7102e6b58b2c70a849954db690680d68a930d1d686074272197fd954648d6994522907018c5c3cb8c6ea27d8064af8c013c9937f57af54ae180cb2e8cc74d116abbcf0618af1c6e0b82a15139b6cf2e84280c183a8b59537c0ecb518e7b903b8eeb60ef3d2957122215bde42a698cb8bff0b7659fbda3443f4c89bdbf4665278406f8e3d961227d5efd26cdae40cb85423d1b7fe44cdc3d115d6ae5deb8252cc86cf9ef38a423522ed4359ec39d8245f8fd55e4a01a966b656b09eda4b780e5f853c9ac88b6b0a207233d4fadba3049e79c19307170223de56d6eae9717b03eac0fd15dea6066bf82ca64ef80c577a357a21b4c817a4b065a0cdb72a1b23e20f1ff25df70b747ba60a8c7726ad32e244ad642039c0c50075e845023434b8e1691170994e0ee9522411590f043ef6805605eb9f767751bd1bde2fc0561d0d5674a5f9c0ec225c47e4325223a730747826a050b613cc21bd02bf2e69a5f436031890bf6b62e859984933de2e7618a2e0c394e818f3d6de8d84e7632de65ad1951fe3d637c612a2a5c2335614dba89743d79733399e623cf6af1d895ffc8df065277feea0d1c66a7d9f78dec7baa300664ec6cbb655f8882c754dbf3effbd796c0fab3cad635b826ac8543c95bafc2282421fde683987a85208b43f166ee8c50eb098faf7c1151dce2c7f242a4bfd4630faf45b14c5b5b528579bcfb1dc9c6beabab8c24d8fdaf1b9e94d131bbf7f7872990e232c4427d430be8844dbe010b90c652a853ab17d15e44264f9324a43fb4ff00053cf513f8af38702eba3f5fe74f234e307410b0c50cd76c797a3c089570525e638b94771b546ab0b0fcecdbbd4013455478311cc1dc773f45e1bb26375f8f9a0c21f1dbbb1e81390479b1e6fecda79c14bb90698b19eb83d237a060ae597bfa024c1fb8d15987809985355bfaf5c1e36ebf1c75aa9b840b979794336004b65b78ed67bf6384e38b1875e958731375ae173e3b72b558125501dd742f260862fccc57df1418bb55f3e0abd0c89feb2841be465a8bd6a16e20b8cbf52304d601d3552d061b5540eb4a084e03c22e0b42810c3fabfac77cfd0d362227e49610110a98fbcb9f26ff1aed329f77da51da8a0d520eb6c796165f5790d5a0170e3fda2aa96a48afcb66d0e474727c1af7b5fd2c6cc16e43de206c75d068dd97358a0f1e1fc9fa1b8040b6e00609014240c516440a549ab9f2e446ca190d193037f6c9d8b8ecfd561be86c7b33a950691b1933468461baf8246c4728c379af55f59c6f7ad14e9aee841f268fdc71ab507989b014ce10e515b908fd252181a83698c258918d2f0032c446c2e309c686844921f20ee43389cbc549f7610158d75f806b4378d2f87eb485599238667bf29ad54145219c797773336bd90a7886d3e452a15bad729ae3383ff290fcc034e48b1c35cbc77e107f39340c316c8c4da40ec910bd07a0864e59ec47a4c09fa613324364c4aebcd33ffd2fb93d29d15411991418ca2ce89903f0a8cb5b5d1c601ae3008e06bd3b3b924d06361dfd7b349389df6e7b6f630dc684d7679403cdb6551f40254d8a61a2b7930b2bdae7e5f8bee5858591fd08e696e0f36be79f5892df836c0efb43ccc1b360ebbe9720557d38eca4e0d38e964de9687e8c734f17f4eda6f879426409cb96110cd7f141cc33929f8348e73cd257693b3c8ed251afa23d7ebde686f43d044594836618a49688292c215f1a4d662a8f95ea26dde58e9fc8936205280b7766e22e840b2ac56c701d33b1438ebebd982d1a8c3053f3c41d3aa2da0655b45d3e61aa2ec8ecc0197bd69b8f23d0cd4538172ca0fc11f77d697b59c1a8d5999c13177]],
					result = [[valid]]
				},
				{
					tcId = 8,
					comment = [[Empty IKM, non-empty salt, empty info. Extract step computes HMAC(salt, empty) which is just HMAC over the empty message.]],
					targets = {
						[[EmptyIKM]],
						[[EmptyInfo]]
					},
					flags = {
						[[EmptyIKM]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					ikm = [[]],
					salt = [[73616c74]],
					info = [[]],
					outputLen = 32,
					okm = [[3575f53d43a910da7c16d7ec27dce663b83bb193d183b5eb3c3bdab69e35efed]],
					result = [[valid]]
				},
				{
					tcId = 9,
					comment = [[Asymmetric IKM, salt, info bytes; nibbles within each byte differ.]],
					targets = {
						[[HexByteOrder]],
						[[HexNibbleOrder]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					ikm = [[0123456789abcdeffedcba9876543210]],
					salt = [[a1b2c3d4e5f60718]],
					info = [[0102030405060708]],
					outputLen = 32,
					okm = [[5353d77b74859fad5bca35836b4210d44067db63e29df3bd307350ef943f4a6a]],
					result = [[valid]]
				},
				{
					tcId = 10,
					comment = [[Output length 255 * HashLen + 1 (8161 bytes), one past the RFC 5869 maximum. The single-byte expand counter cannot reach block 256; must reject.]],
					targets = {
						[[OverMaxOutput]]
					},
					flags = {
						[[OverMaxOutput]]
					},
					source = {
						name = [[rfc5869]],
						version = [[2.3]],
						crossChecked = {
							[[pyca/cryptography]],
							[[rbx-cryptography]]
						}
					},
					ikm = [[0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b]],
					salt = [[]],
					info = [[]],
					outputLen = 8161,
					okm = [[]],
					result = [[invalid]]
				},
				{
					tcId = 11,
					comment = [[Imported from Wycheproof v1 hkdf_sha256_test.json tcId 76: output collision for different salts.]],
					targets = {
						[[OutputCollision]]
					},
					flags = {
						[[OutputCollision]],
						[[EmptySalt]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					ikm = [[3ee1fc0d8fac49d494c4a1b8cf6bf290a4a2c19a27c3ab1914d0d21c841577e0]],
					salt = [[]],
					info = [[4dc991623624fadef207587e42776cf3e0fdf4e5]],
					outputLen = 32,
					okm = [[f41f703259063d401de67cea9192038ddddc71ede5cdb383aad71894c1a39e8c]],
					result = [[valid]]
				},
				{
					tcId = 12,
					comment = [[Imported from Wycheproof v1 hkdf_sha256_test.json tcId 77: output collision for different salts.]],
					targets = {
						[[OutputCollision]]
					},
					flags = {
						[[OutputCollision]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					ikm = [[3ee1fc0d8fac49d494c4a1b8cf6bf290a4a2c19a27c3ab1914d0d21c841577e0]],
					salt = [[0000000000000000000000000000000000000000000000000000000000000000]],
					info = [[4dc991623624fadef207587e42776cf3e0fdf4e5]],
					outputLen = 32,
					okm = [[f41f703259063d401de67cea9192038ddddc71ede5cdb383aad71894c1a39e8c]],
					result = [[valid]]
				},
				{
					tcId = 13,
					comment = [[Imported from Wycheproof v1 hkdf_sha256_test.json tcId 78: a salt longer than the block size of the hash is equivalent to the hash of the salt.]],
					targets = {
						[[SaltHashEquivalence]],
						[[OutputCollision]]
					},
					flags = {
						[[OutputCollision]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					ikm = [[3ee1fc0d8fac49d494c4a1b8cf6bf290a4a2c19a27c3ab1914d0d21c841577e0]],
					salt = [[888815e19321fa618f0ce9800b7c2f6d289ed32c23d9816cc8bb36966bbe413e24db80612bd48c8fd8e791732aed62288c3bf97d7c881b8d80dd48fa31b6f5d0cb]],
					info = [[4dc991623624fadef207587e42776cf3e0fdf4e5]],
					outputLen = 32,
					okm = [[52a1d834f372578ccc7b57e9149f4c45f98ff754dbdec0bb3a8f931bd14e4bb1]],
					result = [[valid]]
				}
			}
		}
	}
}
