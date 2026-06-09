--!strict
-- Auto-generated from Tadashi/testvectors/chacha20_test.json
-- Do not edit by hand.

return {
	algorithm = [[CHACHA20]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_stream_cipher_v1.json]],
	header = {
		[[ChaCha20 stream-cipher test vectors per RFC 8439, plus bug-catching cases.]],
		[[Each non-KAT test's targets[] lists the implementation bugs it is designed to catch.]]
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test from an RFC or other authoritative source.]]
		},
		BlockBoundary = {
			bugType = [[EDGE_CASE]],
			description = [[Plaintext length is exactly N * 64 bytes.]],
			effect = [[Off-by-one in block-loop termination.]]
		},
		LastBlockHandling = {
			bugType = [[EDGE_CASE]],
			description = [[Plaintext does not end on a 64-byte boundary; last block is partial.]]
		},
		EmptyPlaintext = {
			bugType = [[EDGE_CASE]],
			description = [[Zero-length plaintext.]],
			effect = [[Implementation may panic, or return non-empty output.]]
		},
		HexByteOrder = {
			bugType = [[ENCODING]],
			description = [[Bytes are asymmetric; reversed byte order would produce a different result.]],
			effect = [[Catches hex parser that reverses byte order on parse or emit.]]
		},
		HexNibbleOrder = {
			bugType = [[ENCODING]],
			description = [[Each byte has distinct high and low nibbles.]],
			effect = [[Catches hex parser that swaps nibbles within a byte.]]
		},
		Pseudorandom = {
			bugType = [[BASIC]],
			description = [[Standard correctness check on output value.]]
		},
		CounterOverflow = {
			bugType = [[SPEC_AMBIGUOUS]],
			description = [[Block counter starts at 2^32 - 1 and the message spans the wrap to 0. RFC 8439 leaves multi-block messages past the counter limit undefined.]],
			effect = [[Recorded output is the mod-2^32 wrap (the dominant behavior); clean rejection also conforms. Anything else (64-bit carry into the nonce word, crash) is a bug.]]
		}
	},
	numberOfTests = 18,
	testGroups = {
		{
			type = [[ChaCha20Encrypt]],
			keySize = 256,
			ivSize = 96,
			tests = {
				{
					tcId = 1,
					comment = [[RFC 8439 §2.4.2 canonical test vector.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8439]],
						version = [[2.4.2]]
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000000000000004a00000000]],
					counter = 1,
					msg = [[4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e]],
					ct = [[6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d]],
					result = [[valid]]
				},
				{
					tcId = 2,
					comment = [[RFC 8439 §A.2 vector #2, counter=1, 'Any submission...' text.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8439]],
						version = [[A.2#2]]
					},
					key = [[0000000000000000000000000000000000000000000000000000000000000001]],
					iv = [[000000000000000000000002]],
					counter = 1,
					msg = [[416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f]],
					ct = [[a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221]],
					result = [[valid]]
				},
				{
					tcId = 3,
					comment = [[RFC 8439 §A.2 vector #3, counter=42, 'sunscreen' text again with diff params.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8439]],
						version = [[A.2#3]]
					},
					key = [[1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0]],
					iv = [[000000000000000000000002]],
					counter = 42,
					msg = [[2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e]],
					ct = [[62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1]],
					result = [[valid]]
				},
				{
					tcId = 4,
					comment = [[Plaintext of exactly 64 bytes, single ChaCha20 block, no remainder.]],
					targets = {
						[[BlockBoundary]]
					},
					flags = {
						[[BlockBoundary]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000000090000004a00000000]],
					counter = 1,
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e]],
					result = [[valid]]
				},
				{
					tcId = 5,
					comment = [[Plaintext of 63 bytes, full block computed, last byte of keystream discarded.]],
					targets = {
						[[LastBlockHandling]]
					},
					flags = {
						[[LastBlockHandling]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000000090000004a00000000]],
					counter = 1,
					msg = [[000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c]],
					result = [[valid]]
				},
				{
					tcId = 6,
					comment = [[Plaintext of 65 bytes, exactly one block + 1 byte; tests the partial-block path.]],
					targets = {
						[[LastBlockHandling]],
						[[BlockBoundary]]
					},
					flags = {
						[[LastBlockHandling]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000000090000004a00000000]],
					counter = 1,
					msg = [[0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e0a]],
					result = [[valid]]
				},
				{
					tcId = 7,
					comment = [[Plaintext of exactly 128 bytes, two full blocks, no remainder.]],
					targets = {
						[[BlockBoundary]]
					},
					flags = {
						[[BlockBoundary]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000000090000004a00000000]],
					counter = 1,
					msg = [[0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e0a88837739d7bf4ef8ccacb0ea2bb9d69d56c394aa351dfda5bf459f0a2e9fe8e721f89255f9c486bf21679c683d4f9c5cf2fa27865526005b06ca374c86af3b]],
					result = [[valid]]
				},
				{
					tcId = 8,
					comment = [[Empty plaintext, output must also be empty; tests that the implementation doesn't panic.]],
					targets = {
						[[EmptyPlaintext]]
					},
					flags = {
						[[EmptyPlaintext]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[0000000000000000000000000000000000000000000000000000000000000000]],
					iv = [[000000000000000000000000]],
					counter = 0,
					msg = [[]],
					ct = [[]],
					result = [[valid]]
				},
				{
					tcId = 9,
					comment = [[Single byte plaintext at counter=0, all-zero key/nonce, tests basic single-byte path.]],
					targets = {
						[[ZeroInputs]],
						[[InitialStateConstants]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[0000000000000000000000000000000000000000000000000000000000000000]],
					iv = [[000000000000000000000000]],
					counter = 0,
					msg = [[00]],
					ct = [[76]],
					result = [[valid]]
				},
				{
					tcId = 10,
					comment = [[All-zero key + nonce + plaintext at counter=0, output = first byte of ChaCha20 keystream from canonical state; bug if Sigma constants 'expand 32-byte k' wrong.]],
					targets = {
						[[InitialStateConstants]],
						[[ZeroInputs]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[0000000000000000000000000000000000000000000000000000000000000000]],
					iv = [[000000000000000000000000]],
					counter = 0,
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586]],
					result = [[valid]]
				},
				{
					tcId = 11,
					comment = [[Counter starts at 0xfffffffe (= 2^32 - 2), single-block message; tests counter LE encoding.]],
					targets = {
						[[CounterEndianness]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]],
					iv = [[555555555555555555555555]],
					counter = 4294967294,
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[f4430bf344222befff8d8cb96bfc9dfb07ec64f2818d1ee9f59abe73f6c5158f15cd94302988f38781249e3050659f7cb860cd580f2f0765942c2b027ba669b1]],
					result = [[valid]]
				},
				{
					tcId = 12,
					comment = [[Counter = 0xfffffffe, 128-byte message, second block computed at counter 0xffffffff; tests counter at the wrap boundary.]],
					targets = {
						[[CounterEndianness]],
						[[BlockBoundary]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]],
					iv = [[555555555555555555555555]],
					counter = 4294967294,
					msg = [[0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[f4430bf344222befff8d8cb96bfc9dfb07ec64f2818d1ee9f59abe73f6c5158f15cd94302988f38781249e3050659f7cb860cd580f2f0765942c2b027ba669b1a91f5c28c6708f0c39a61fc8b72815f427a2c89b6d141c992c440dc68d68e9de492a2b39b482e6c3542cde3652e03e0eb35341913f8cbf486343a621b4200dc2]],
					result = [[valid]]
				},
				{
					tcId = 13,
					comment = [[Nonce = 00 00 00 00 00 00 00 00 00 00 00 80, high bit set in last byte; tests nonce LE interpretation.]],
					targets = {
						[[NonceEndianness]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[0000000000000000000000000000000000000000000000000000000000000000]],
					iv = [[000000000000000000000080]],
					counter = 0,
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[213a358a4865b310b0ef6b3fc1b8c2b31be1cffac4a904cfb166884aa00a5e95812ab8efdfe6f9d222f33b25d29e030c3371982e02bd99f742e25492501b36ee]],
					result = [[valid]]
				},
				{
					tcId = 14,
					comment = [[Key with byte 0 set, all others zero, tests key is loaded LE into state words.]],
					targets = {
						[[KeyEndianness]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[0100000000000000000000000000000000000000000000000000000000000000]],
					iv = [[000000000000000000000000]],
					counter = 0,
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[c5d30a7ce1ec119378c84f487d775a8542f13ece238a9455e8229e888de85bbd29eb63d0a17a5b999b52da22be4023eb07620a54f6fa6ad8737b71eb0464dac0]],
					result = [[valid]]
				},
				{
					tcId = 15,
					comment = [[Key with byte 31 set, all others zero, distinguishes byte-0 vs byte-31 endianness bugs from previous test.]],
					targets = {
						[[KeyEndianness]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[0000000000000000000000000000000000000000000000000000000000000001]],
					iv = [[000000000000000000000000]],
					counter = 0,
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963]],
					result = [[valid]]
				},
				{
					tcId = 16,
					comment = [[192-byte plaintext (3 full blocks, no remainder), tests block counter increments correctly across multiple blocks.]],
					targets = {
						[[BlockBoundary]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[4242424242424242424242424242424242424242424242424242424242424242]],
					iv = [[424242424242424242424242]],
					counter = 1,
					msg = [[000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[71125c1c99544d7e0d00bb33246fdbe01bb7d0c6ccf1911d0f8ea157786524c75bbebf4a08fe01bccd91848d15f3af8d74ed229657323e5a0ffb8f85a58096c4db4be8ab266bbb73f25c68ca15d647e253afb18d100fa8d0b75437dc4321d682a9607a921fc5094c9db1be379d6ede42dc07817473f50ac4208e2171b5e22d834bea990de1dfb071838cb1573b6b1d5901fa384d692f465843f1360dbf38675186590dc6cd847f84e601e9cef968867949bad623386e616d5df9890c71aa212f]],
					result = [[valid]]
				},
				{
					tcId = 17,
					comment = [[Asymmetric key/iv/counter/msg bytes; nibbles within each byte differ; bytes do not form a palindrome. Catches hex parser nibble-swap or byte-reverse bugs.]],
					targets = {
						[[HexByteOrder]],
						[[HexNibbleOrder]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[0123456789abcdeffedcba98765432100f1e2d3c4b5a6978a1b2c3d4e5f60718]],
					iv = [[0123456789abcdef01234567]],
					counter = 305419896,
					msg = [[0fedcba98765432100112233445566778899aabbccddeeff1eef00ddcc11bbaa]],
					ct = [[d629644d034a955bcaef93652461e699db7a2160e63dd93a228b85ba766756f6]],
					result = [[valid]]
				},
				{
					tcId = 18,
					comment = [[Counter = 0xffffffff with a 128-byte message: block 2 wraps the counter to 0. Acceptable: mod-2^32 wrap (recorded, computed independently by a reference implementation) or clean rejection. A 64-bit counter carry into the first nonce word is the classic bug here.]],
					targets = {
						[[CounterOverflow]],
						[[CounterEndianness]]
					},
					flags = {
						[[CounterOverflow]],
						[[Acceptable]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[pure-python RFC 8439 reference]],
							[[rbx-cryptography]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000000000000004a00000000]],
					counter = 4294967295,
					msg = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f]],
					ct = [[6d28d858d56f412e18e1cab6b873d1c7598d2031d8039b20396d65d9ae0f78c6d17da11ad52a136a3ee5b1a53da39fad8fb4bed645ba92d05bb0d0758937aa4aef445c03ffe5730ec97bd0cb265940e08209f079399e1deeae0fc6e8b3bf80f0e31aba1fc66e3dc648e8c96dc363dd3331d34ba1798902bf6f082c76e0e16034]],
					result = [[acceptable]]
				}
			}
		}
	}
}
