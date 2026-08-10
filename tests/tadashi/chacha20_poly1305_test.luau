--!strict
-- Auto-generated from Tadashi/testvectors/chacha20_poly1305_test.json
-- Do not edit by hand.

return {
	algorithm = [[CHACHA20-POLY1305]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_aead_v1.json]],
	header = {
		[[ChaCha20-Poly1305 AEAD per RFC 8439, with bug-catching cases targeting padding boundaries, length encoding, counter-start, and tag-verification rejection.]],
		[[Each non-KAT test's targets[] lists the implementation bugs it is designed to catch.]]
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test from an RFC or authoritative source.]]
		},
		BothEmpty = {
			bugType = [[EDGE_CASE]],
			description = [[Both AAD and plaintext are empty.]],
			effect = [[MAC input collapses to just the 16-byte length block.]]
		},
		AadOnly = {
			bugType = [[EDGE_CASE]],
			description = [[MAC input is dominated by the AAD section.]]
		},
		AadPaddingZero = {
			bugType = [[EDGE_CASE]],
			description = [[AAD length is exactly a multiple of 16.]],
			effect = [[Bug if implementation always adds a zero-pad block.]]
		},
		CtPaddingZero = {
			bugType = [[EDGE_CASE]],
			description = [[Ciphertext length is exactly a multiple of 16.]],
			effect = [[Bug if implementation always adds a zero-pad block.]]
		},
		LengthEncoding = {
			bugType = [[EDGE_CASE]],
			description = [[AAD and ciphertext lengths chosen to expose BE-vs-LE confusion in the 8-byte length fields.]],
			effect = [[Tag changes if length fields are encoded big-endian or with wrong width.]]
		},
		CounterStart = {
			bugType = [[MISSING_STEP]],
			description = [[Encryptor must start ChaCha20 at counter=1; block 0 is reserved for the Poly1305 one-time key.]],
			effect = [[If counter starts at 0, first plaintext block XORs against MAC key bytes.]]
		},
		WrongMacKey = {
			bugType = [[MISSING_STEP]],
			description = [[The Poly1305 key is derived from ChaCha20 block 0 with counter=0, key, nonce.]],
			effect = [[Wrong block or counter yields wrong MAC key and wrong tag.]]
		},
		TagForgery = {
			bugType = [[AUTH_BYPASS]],
			description = [[Modified tag, ciphertext, or AAD with otherwise valid encryption.]],
			effect = [[Decrypt must reject; bug if implementation returns plaintext without verifying tag.]]
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
		Poly1305AccumulatorEdge = {
			bugType = [[EDGE_CASE]],
			description = [[Ciphertext constructed so the Poly1305 accumulator passes through an edge value (0, 1, small constants, 2^32 boundaries, or values near 2^130 - 5) during tag computation over the AEAD transcript.]],
			effect = [[Limb-arithmetic or final-reduction bugs in the MAC produce a wrong tag only for these constructed transcripts.]]
		},
		Poly1305DerivedKeyEdge = {
			bugType = [[EDGE_CASE]],
			description = [[Nonce searched so the Poly1305 key derived from block 0 of the keystream has an edge-case value after clamping.]],
			effect = [[Bugs that only manifest for degenerate r or s halves of the one-time key.]]
		},
		TagArithmeticEdge = {
			bugType = [[EDGE_CASE]],
			description = [[Inputs chosen so the final tag is an edge value; catches errors in the final modular addition of s.]]
		},
		CiphertextEdge = {
			bugType = [[EDGE_CASE]],
			description = [[Ciphertext is a special-case bit pattern feeding the MAC.]]
		},
		InvalidNonceSize = {
			bugType = [[MISSING_STEP]],
			description = [[Nonce length differs from the specification (12 bytes for ChaCha20-Poly1305, 24 for XChaCha20-Poly1305); must reject.]],
			effect = [[Accepting foreign nonce sizes silently truncates or pads, destroying nonce-uniqueness guarantees.]]
		}
	},
	numberOfTests = 35,
	testGroups = {
		{
			type = [[ChaCha20Poly1305AeadEncrypt]],
			keySize = 256,
			ivSize = 96,
			tagSize = 128,
			tests = {
				{
					tcId = 1,
					comment = [[RFC 8439 §2.8.2 canonical ChaCha20-Poly1305 AEAD vector.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8439]],
						version = [[2.8.2]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[070000004041424344454647]],
					aad = [[50515253c0c1c2c3c4c5c6c7]],
					msg = [[4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e]],
					ct = [[d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116]],
					tag = [[1ae10b594f09e26a7e902ecbd0600691]],
					result = [[valid]]
				},
				{
					tcId = 2,
					comment = [[Empty AAD and empty plaintext. MAC input is just the 16-byte zero-length block; tests the degenerate case end-to-end.]],
					targets = {
						[[BothEmpty]]
					},
					flags = {
						[[BothEmpty]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[070000004041424344454647]],
					aad = [[]],
					msg = [[]],
					ct = [[]],
					tag = [[a0784d7a4716f3feb4f64e7f4b39bf04]],
					result = [[valid]]
				},
				{
					tcId = 3,
					comment = [[Non-trivial AAD, empty plaintext. Tag covers AAD + pad16(AAD) + empty CT + lengths(AAD=15, CT=0).]],
					targets = {
						[[AadOnly]]
					},
					flags = {
						[[AadOnly]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[070000004041424344454647]],
					aad = [[0102030405060708090a0b0c0d0e0f]],
					msg = [[]],
					ct = [[]],
					tag = [[0169370a3e1dd45d7e81c73028d84a03]],
					result = [[valid]]
				},
				{
					tcId = 4,
					comment = [[AAD is exactly 16 bytes (one full Poly1305 block, no padding). Bug if implementation adds an extra 16-byte zero pad block.]],
					targets = {
						[[AadPaddingZero]]
					},
					flags = {
						[[AadPaddingZero]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[070000004041424344454647]],
					aad = [[000102030405060708090a0b0c0d0e0f]],
					msg = [[ff]],
					ct = [[60]],
					tag = [[f7bf1248642ede395bfe4ca5338822b2]],
					result = [[valid]]
				},
				{
					tcId = 5,
					comment = [[Plaintext (and thus ciphertext) is exactly 16 bytes; pad16(ct) is empty. Bug if implementation adds an extra 16-byte zero pad block.]],
					targets = {
						[[CtPaddingZero]]
					},
					flags = {
						[[CtPaddingZero]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[070000004041424344454647]],
					aad = [[aa]],
					msg = [[000102030405060708090a0b0c0d0e0f]],
					ct = [[9f7aeb5e05f846bd1deb85f03a8c04a1]],
					tag = [[1aa6b812c5e7b6d8389c3b7a36587017]],
					result = [[valid]]
				},
				{
					tcId = 6,
					comment = [[Both AAD and plaintext are 15 bytes; each gets 1 byte of zero padding. Probes both pad16 sites with the most boundary-sensitive value.]],
					targets = {
						[[AadPaddingZero]],
						[[CtPaddingZero]]
					},
					flags = {
						[[AadPaddingZero]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[070000004041424344454647]],
					aad = [[000102030405060708090a0b0c0d0e]],
					msg = [[ff0102030405060708090a0b0c0d0e]],
					ct = [[607aeb5e05f846bd1deb85f03a8c04]],
					tag = [[0affefed36a8cacb399afb021867a63f]],
					result = [[valid]]
				},
				{
					tcId = 7,
					comment = [[AAD and plaintext both 17 bytes (one full block + 1 byte each); 15 bytes of padding each. Bug if partial padding length is wrong.]],
					targets = {
						[[AadPaddingZero]],
						[[CtPaddingZero]]
					},
					flags = {
						[[AadPaddingZero]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[070000004041424344454647]],
					aad = [[000102030405060708090a0b0c0d0e0fff]],
					msg = [[ff0102030405060708090a0b0c0d0e0f00]],
					ct = [[607aeb5e05f846bd1deb85f03a8c04a1c1]],
					tag = [[47141df94b7a7158ee5e1f40e9d92770]],
					result = [[valid]]
				},
				{
					tcId = 8,
					comment = [[AAD spans 5 Poly1305 blocks (80 bytes), 1-byte plaintext. Exercises the AAD loop for multi-block handling.]],
					targets = {
						[[AadOnly]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[070000004041424344454647]],
					aad = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f]],
					msg = [[ff]],
					ct = [[60]],
					tag = [[b90f6b9b4717101314d6de89259d2192]],
					result = [[valid]]
				},
				{
					tcId = 9,
					comment = [[AAD length 12 and ciphertext length 24, distinct non-trivial values chosen to expose BE-vs-LE confusion in the 8-byte length fields appended to the MAC input.]],
					targets = {
						[[LengthEncoding]]
					},
					flags = {
						[[LengthEncoding]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[070000004041424344454647]],
					aad = [[000102030405060708090a0b]],
					msg = [[0102030405060708090a0b0c0d0e0f101112131415161718]],
					ct = [[9e79ea5904fb47b21ce884f73b8f05bed0d29b2b1c1779c6]],
					tag = [[c0fd4ce964266ad46b54e7f5e9a55e8d]],
					result = [[valid]]
				},
				{
					tcId = 10,
					comment = [[Single block plaintext. Encryptor must start ChaCha20 at counter=1; if it starts at counter=0 the first plaintext block is XORed with the bytes used as the Poly1305 key (block 0), producing a different ciphertext.]],
					targets = {
						[[CounterStart]],
						[[WrongMacKey]]
					},
					flags = {
						[[CounterStart]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[070000004041424344454647]],
					aad = [[]],
					msg = [[55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555]],
					ct = [[ca2ebc0854a815ef40b7daae63d45ffb9495dd6a5c543b8b88df85d200d756f01bcb9e6df9db0b7eed8fe75aaf8e07bd2051e73beb3c381a35f1d09a44ed4e0c]],
					tag = [[848224985df4f54a6b15ca02ccf1d193]],
					result = [[valid]]
				},
				{
					tcId = 11,
					comment = [[RFC 8439 §2.8.2 vector with bit 0 of tag byte 0 flipped. Decrypt must reject.]],
					targets = {
						[[TagForgery]]
					},
					flags = {
						[[TagForgery]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[070000004041424344454647]],
					aad = [[50515253c0c1c2c3c4c5c6c7]],
					msg = [[4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e]],
					ct = [[d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116]],
					tag = [[1be10b594f09e26a7e902ecbd0600691]],
					result = [[invalid]]
				},
				{
					tcId = 12,
					comment = [[RFC 8439 §2.8.2 vector with bit 127 of the tag (the last bit) flipped. Decrypt must reject; catches comparators that bail after a prefix match.]],
					targets = {
						[[TagForgery]]
					},
					flags = {
						[[TagForgery]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[070000004041424344454647]],
					aad = [[50515253c0c1c2c3c4c5c6c7]],
					msg = [[4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e]],
					ct = [[d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116]],
					tag = [[1ae10b594f09e26a7e902ecbd0600611]],
					result = [[invalid]]
				},
				{
					tcId = 13,
					comment = [[RFC 8439 §2.8.2 vector with bit 0 of ciphertext byte 0 flipped, tag unchanged. Decrypt must reject.]],
					targets = {
						[[TagForgery]]
					},
					flags = {
						[[TagForgery]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[070000004041424344454647]],
					aad = [[50515253c0c1c2c3c4c5c6c7]],
					msg = [[4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e]],
					ct = [[d21a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116]],
					tag = [[1ae10b594f09e26a7e902ecbd0600691]],
					result = [[invalid]]
				},
				{
					tcId = 14,
					comment = [[RFC 8439 §2.8.2 vector with bit 0 of AAD byte 0 flipped, ct and tag unchanged. Decrypt must reject.]],
					targets = {
						[[TagForgery]]
					},
					flags = {
						[[TagForgery]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[070000004041424344454647]],
					aad = [[51515253c0c1c2c3c4c5c6c7]],
					msg = [[4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e]],
					ct = [[d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116]],
					tag = [[1ae10b594f09e26a7e902ecbd0600691]],
					result = [[invalid]]
				},
				{
					tcId = 15,
					comment = [[Asymmetric key, iv, aad, msg bytes; nibbles within each byte differ. Catches hex parser nibble-swap or byte-reverse bugs anywhere in the runner.]],
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
					aad = [[a1b2c3d4e5f60718]],
					msg = [[0fedcba98765432100112233445566778899aabbccddeeff1eef00ddcc11bbaa]],
					ct = [[f1cea623ed3d697a824a76d1f176b26864ce643741839f29b7fa417f73dce2f7]],
					tag = [[ef564d6ef856531cbb40c0015672f2dc]],
					result = [[valid]]
				},
				{
					tcId = 16,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 206: edge case for poly1305 key:ffffffefeb344f6bc37ba77ea2ee06dfe8c7f4ae10810422124fc5e1bd7fe301.]],
					targets = {
						[[Poly1305DerivedKeyEdge]],
						[[WrongMacKey]]
					},
					flags = {
						[[EdgeCasePolyKey]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000102030405060710abb165]],
					aad = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					msg = [[dc8ce708bf26aab862d97e1b42f31ef38c382cf07174142ea564920612997b1c2e38aca2438b588d5459493e97e7fa330ff9bc3b9458297ba0967d86ed090b435103478f2869b93ee29c837e95fb6b9903f3b735b7345428eb93b3db1d9b5187cebb889aa177d83e4f63fc9a5c0596eed939883d06aacdfdea44fdecdf5cb7fc]],
					ct = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					tag = [[c296436246c3a7c4b3ba09ab2a6a0889]],
					result = [[valid]]
				},
				{
					tcId = 17,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 216: edge case for poly1305 key:feffff1ff6b87403fd6435b09775bc92491a0ae62c5842a30e3b82710cc2dad1.]],
					targets = {
						[[Poly1305DerivedKeyEdge]],
						[[WrongMacKey]]
					},
					flags = {
						[[EdgeCasePolyKey]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[9de836aa579585081f330a7c4036e20e38ef15eff3945184d231867f505fffdf]],
					iv = [[00000000101112130bc672c3]],
					aad = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					msg = [[3619cb470af86dceceb6940f2d9abb34c9a9131476053387445ffebbe240d4f9818377855652f46a8219c7f71c3554f8acef8258de4b7d17c0f3d353ac981cc6a13287be1e6b41dc6d133df4ababebdf43d665ce7a4a5c982a0b139cb8202eebc74173e3224a440e4c37d2b595f384290e939ba016df0d49b36cdb4bd91c39]],
					ct = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					tag = [[133fe62391744d11ce44594b96c53baf]],
					result = [[valid]]
				},
				{
					tcId = 18,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 225: edge case for poly1305 key:bc90156087e0125006d90c30babd0590427bff19de1f2e7d0757a79528731138.]],
					targets = {
						[[Poly1305DerivedKeyEdge]],
						[[WrongMacKey]]
					},
					flags = {
						[[EdgeCasePolyKey]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[9de836aa579585081f330a7c4036e20e38ef15eff3945184d231867f505fffdf]],
					iv = [[00000000101112130d8fcf4e]],
					aad = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					msg = [[cfc3db8631c81c69023a3c8a9ad66c35053685144c4fa2a9510add72e211dad9ca5b982e4c194591fdb74116280311d1299ad81227258cb52f079bbcb12aff161d278dec33a326d71276b3de01a8327ee7f45f94179dff18a3fe643e56c30cfd03871c8110ab00f6612b9e17a4647360d7847bb63a3122613c2e7cdddd08ae]],
					ct = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					tag = [[1ae2ed84ea9774d78d782bf8d972a8b8]],
					result = [[valid]]
				},
				{
					tcId = 19,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 226: edge case for tag.]],
					targets = {
						[[TagArithmeticEdge]]
					},
					flags = {
						[[EdgeCaseTag]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f]],
					iv = [[000102030405060708090a0b]],
					aad = [[ffffffffffffffffffffffffffffffff415771fda4fbcc55c377f73203e60226]],
					msg = [[e48caf8a76183327c9561a4651c07c822ccd1642c06607d0d4bc0afb4de15915dbfa3b0b422e77e15c64bf6247031f15fdb643117809821870000adf83834da5]],
					ct = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					tag = [[000102030405060708090a0b0c0d0e0f]],
					result = [[valid]]
				},
				{
					tcId = 20,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 229: edge case for tag.]],
					targets = {
						[[TagArithmeticEdge]]
					},
					flags = {
						[[EdgeCaseTag]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f]],
					iv = [[000102030405060708090a0b]],
					aad = [[fdffffffffffffffffffffffffffffff2bdbf16d8ea4d39dab8dcb3d4bc4e104]],
					msg = [[e48caf8a76183327c9561a4651c07c822ccd1642c06607d0d4bc0afb4de15915dbfa3b0b422e77e15c64bf6247031f15fdb643117809821870000adf83834da5]],
					ct = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					tag = [[00000080000000800000008000000080]],
					result = [[valid]]
				},
				{
					tcId = 21,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 233: Intermediate sum of poly1305 after processing112 bytes is 0x0.]],
					targets = {
						[[Poly1305AccumulatorEdge]]
					},
					flags = {
						[[EdgeCasePoly1305]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000102030405060710abb165]],
					aad = [[ffffffff]],
					msg = [[c68ce708bf26aab862d97e1b42f31ef37bb66f8090c149e452ec7f20327eb2ea2e38aca2438b588d5459493e97e7fa330ff9bc23c897df6b00af86931d6c81555103478f2869b93ee29c837e95fb6b9903f3b72debfba2384baa48ceedfedb91]],
					ct = [[e5ffffffffffffffffffffffffffffff0871bc8f1e4aa235087712d9df183609ffffffffffffffffffffffffffffffffffffffe7a33009ef5fc604ea0f9a75e9ffffffffffffffffffffffffffffffffffffffe7a33009ef5fc604ea0f9a75e9]],
					tag = [[3572162777262c518eef573b720e8e64]],
					result = [[valid]]
				},
				{
					tcId = 22,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 236: Intermediate sum of poly1305 after processing112 bytes is 0x1.]],
					targets = {
						[[Poly1305AccumulatorEdge]]
					},
					flags = {
						[[EdgeCasePoly1305]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000102030405060710abb165]],
					aad = [[ffffffff]],
					msg = [[c78ce708bf26aab862d97e1b42f31ef376209eef141691fba5d10eaf581affe62e38aca2438b588d5459493e97e7fa330e73d2dc3bbd954989cb8433b7d6597b5103478f2869b93ee29c837e95fb6b990279d9d218d1e81ac2ce4a6e474403bf]],
					ct = [[e4ffffffffffffffffffffffffffffff05e74de09a9d7a2aff4a6356b57c7b05fffffffffffffffffffffffffffffffffe759118501a43cdd6a2064aa520adc7fffffffffffffffffffffffffffffffffe759118501a43cdd6a2064aa520adc7]],
					tag = [[347216375f5b7b5c4e6bff4912fd9473]],
					result = [[valid]]
				},
				{
					tcId = 23,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 245: Intermediate sum of poly1305 after processing64 bytes is 0x100000000.]],
					targets = {
						[[Poly1305AccumulatorEdge]]
					},
					flags = {
						[[EdgeCasePoly1305]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000102030405060710abb165]],
					aad = [[ffffffff]],
					msg = [[f717f8d5b28032d5c8e8061cd44d71e4f2d55de772fe7a91ce85e410db3e2d8d50d5ddb5400136323fb83f285e40aca2]],
					ct = [[d464e022f259679255ce87f8694190e881128ee8fc759140941e89e93658a96e81128ee8fc759140941e89e93658a96e]],
					tag = [[821312db9826b5e7fe0a9d30c5e28d4f]],
					result = [[valid]]
				},
				{
					tcId = 24,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 242: Intermediate sum of poly1305 after processing112 bytes is 0x13.]],
					targets = {
						[[Poly1305AccumulatorEdge]]
					},
					flags = {
						[[EdgeCasePoly1305]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000102030405060710abb165]],
					aad = [[ffffffff]],
					msg = [[ee8ce708bf26aab862d97e1b42f31ef3b9f55bd56e0fd74b46063a96354cfbee3238aca2438b588d5459493e97e7fa3320c78886a6f6292d6cc5fbddb546a2b04d03478f2869b93ee29c837e95fb6b992ccd8388859a547e27c0358045d4f874]],
					ct = [[cdffffffffffffffffffffffffffffffca3288dae0843c9a1c9d576fd82a7f0de3ffffffffffffffffffffffffffffffd0c1cb42cd51ffa933ac79a4a7b0560ce3ffffffffffffffffffffffffffffffd0c1cb42cd51ffa933ac79a4a7b0560c]],
					tag = [[22721657b0130d28cf1ec65153c41182]],
					result = [[valid]]
				},
				{
					tcId = 25,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 243: Intermediate sum of poly1305 after processing112 bytes is 0x14.]],
					targets = {
						[[Poly1305AccumulatorEdge]]
					},
					flags = {
						[[EdgeCasePoly1305]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000102030405060710abb165]],
					aad = [[ffffffff]],
					msg = [[ef8ce708bf26aab862d97e1b42f31ef3b46fca24d353ff5e49eac51540e840ea3038aca2438b588d5459493e97e7fa333d311e572202011a75e948586fe268b44f03478f2869b93ee29c837e95fb6b99313b1559016e7c493eec86059f703270]],
					ct = [[ccffffffffffffffffffffffffffffffc7a8192b5dd8148f1371a8ecad8ec409e1ffffffffffffffffffffffffffffffcd375d9349a5d79e2a80ca217d149c08e1ffffffffffffffffffffffffffffffcd375d9349a5d79e2a80ca217d149c08]],
					tag = [[2172166798485c338f9a6d60f3b21891]],
					result = [[valid]]
				},
				{
					tcId = 26,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 239: Intermediate sum of poly1305 after processing112 bytes is 0x5.]],
					targets = {
						[[Poly1305AccumulatorEdge]]
					},
					flags = {
						[[EdgeCasePoly1305]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000102030405060710abb165]],
					aad = [[ffffffff]],
					msg = [[fc8ce708bf26aab862d97e1b42f31ef38b79403dfaabc0d8c18d23a3469c13e62e38aca2438b588d5459493e97e7fa330a4b941e6b66fcc2ed7d8cb3e8cc7ffc5103478f2869b93ee29c837e95fb6b9906419f10480a8191a67842ee185e2538]],
					ct = [[dffffffffffffffffffffffffffffffff8be933274202b099b164e5aabfa9705fffffffffffffffffffffffffffffffffa4dd7da00c12a46b2140ecafa3a8b40fffffffffffffffffffffffffffffffffa4dd7da00c12a46b2140ecafa3a8b40]],
					tag = [[30721677ff2eb8894e5a9d8492b7b0af]],
					result = [[valid]]
				},
				{
					tcId = 27,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 240: Intermediate sum of poly1305 after processing112 bytes is 0xa.]],
					targets = {
						[[Poly1305AccumulatorEdge]]
					},
					flags = {
						[[EdgeCasePoly1305]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000102030405060710abb165]],
					aad = [[ffffffff]],
					msg = [[fa8ce708bf26aab862d97e1b42f31ef39bcbb8da477d580d772de4229bba7de22938aca2438b588d5459493e97e7fa331e9dedf9dd64a0681bac2969549425bc5603478f2869b93ee29c837e95fb6b991297e6f7fe08dd3b50a9e734a4067f78]],
					ct = [[d9ffffffffffffffffffffffffffffffe80c6bd5c9f6b3dc2db689db76dcf901f8ffffffffffffffffffffffffffffffee9bae3db6c376ec44c5ab104662d100f8ffffffffffffffffffffffffffffffee9bae3db6c376ec44c5ab104662d100]],
					tag = [[2b7216c7873744c20ec5e2cdb260d3fa]],
					result = [[valid]]
				},
				{
					tcId = 28,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 244: Intermediate sum of poly1305 after processing64 bytes is 0xffffffff.]],
					targets = {
						[[Poly1305AccumulatorEdge]]
					},
					flags = {
						[[EdgeCasePoly1305]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000102030405060710abb165]],
					aad = [[ffffffff]],
					msg = [[f59d56151de28bef83505f6d89c0b0f7f75b2fa8e6dce386075db283ec85ee62555baffad423af25f66069bb69fb6f4d]],
					ct = [[d6ee4ee25d3bdea81e76de8934cc51fb849cfca7685708575dc6df7a01e36a81849cfca7685708575dc6df7a01e36a81]],
					tag = [[831312cbb0f165dc3e8ff52125f48640]],
					result = [[valid]]
				},
				{
					tcId = 29,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 246: Intermediate sum of poly1305 after processing112 bytes is 0x7ffffffffffff.]],
					targets = {
						[[Poly1305AccumulatorEdge]]
					},
					flags = {
						[[EdgeCasePoly1305]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000102030405060710abb165]],
					aad = [[ffffffff]],
					msg = [[f28ce708bf26aab862d97e1b42f31ef3e68a922c9219d30f07554d7d99f2bde92c38aca2438b588d5459493e97e7fa33e24c07dd98f9b253ab0c318d9b14f6b15303478f2869b93ee29c837e95fb6b99ee460cd3bb95cf00e009ffd06b86ac75]],
					ct = [[d1ffffffffffffffffffffffffffffff954d41231c9238de5dce20847494390afdffffffffffffffffffffffffffffff124a4419f35e64d7f465b3f489e2020dfdffffffffffffffffffffffffffffff124a4419f35e64d7f465b3f489e2020d]],
					tag = [[c1045769d487d545cef3f0d34b7a8733]],
					result = [[valid]]
				},
				{
					tcId = 30,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 276: Intermediate sum of poly1305 after processing112 bytes is 0x2fffffffffffffffffffffffffffffffb.]],
					targets = {
						[[Poly1305AccumulatorEdge]]
					},
					flags = {
						[[EdgeCasePoly1305]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[00010203040506072dd4cd40]],
					aad = [[ffffffff]],
					msg = [[4d115e67ecd3d4178c4c60e713ab4e5e6ee628fc4b5830184cd293364a213e84fe47139a5f4e3f8e92d7a3b71eb4ff0e29db953ad5458fea61f013ea1854fe7572a0085c32ddfcbeb01a8be4c34d5331e1ee75783911c4dd46015783d553f2b5]],
					ct = [[d4fffffffffffffffffffffffffffffff7e106fac57dd8a4c90632cd4e14d70ae9ffffffffffffffffffffffffffffff861126c93f3adf23fcda1400f9947f08e9ffffffffffffffffffffffffffffff861126c93f3adf23fcda1400f9947f08]],
					tag = [[e00d2e8bae5d09c28e9bf59409545d09]],
					result = [[valid]]
				},
				{
					tcId = 34,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 122: no comment in source.]],
					targets = {
						[[CiphertextEdge]],
						[[Poly1305AccumulatorEdge]]
					},
					flags = {
						[[EdgeCaseCiphertext]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[000102030405060708090a0b]],
					aad = [[00000000000000000000000000000000]],
					msg = [[65b63bf074b7283992e24b1ac0df0d22b555dbe2254d94a43f1de748d3cc6f0d]],
					ct = [[0000000000000000000000000000000000000000000000000000000000000000]],
					tag = [[39f4fce3026d83789ffd1ee6f2cd7c4f]],
					result = [[valid]]
				},
				{
					tcId = 35,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 134: no comment in source.]],
					targets = {
						[[CiphertextEdge]],
						[[Poly1305AccumulatorEdge]]
					},
					flags = {
						[[EdgeCaseCiphertext]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[000102030405060708090a0b]],
					aad = [[ffffff7fffffff7fffffff7fffffff7f]],
					msg = [[9a49c48f8b48d7466d1db4653f20f25d4aaa249ddab26bdbc0e218372c339072]],
					ct = [[ffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7f]],
					tag = [[af8492c792bf8d8062be74ff6efb3869]],
					result = [[valid]]
				}
			}
		},
		{
			type = [[ChaCha20Poly1305AeadEncrypt]],
			keySize = 256,
			ivSize = 0,
			tagSize = 128,
			tests = {
				{
					tcId = 31,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 317: nonce has size 0.]],
					targets = {
						[[InvalidNonceSize]]
					},
					flags = {
						[[InvalidNonceSize]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					iv = [[]],
					aad = [[]],
					msg = [[]],
					ct = [[]],
					tag = [[]],
					result = [[invalid]]
				}
			}
		},
		{
			type = [[ChaCha20Poly1305AeadEncrypt]],
			keySize = 256,
			ivSize = 112,
			tagSize = 128,
			tests = {
				{
					tcId = 32,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 321: nonce has size 14.]],
					targets = {
						[[InvalidNonceSize]]
					},
					flags = {
						[[InvalidNonceSize]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					iv = [[000102030405060708090a0b0c0d]],
					aad = [[]],
					msg = [[]],
					ct = [[]],
					tag = [[]],
					result = [[invalid]]
				}
			}
		},
		{
			type = [[ChaCha20Poly1305AeadEncrypt]],
			keySize = 256,
			ivSize = 256,
			tagSize = 128,
			tests = {
				{
					tcId = 33,
					comment = [[Imported from Wycheproof v1 chacha20_poly1305_test.json tcId 325: nonce has size 32.]],
					targets = {
						[[InvalidNonceSize]]
					},
					flags = {
						[[InvalidNonceSize]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					iv = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					aad = [[]],
					msg = [[]],
					ct = [[]],
					tag = [[]],
					result = [[invalid]]
				}
			}
		}
	}
}
