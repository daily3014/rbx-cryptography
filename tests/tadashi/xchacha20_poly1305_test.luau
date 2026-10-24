--!strict
-- Auto-generated from Tadashi/testvectors/xchacha20_poly1305_test.json
-- Do not edit by hand.

return {
	algorithm = [[XCHACHA20-POLY1305]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_aead_v1.json]],
	header = {
		[[XChaCha20-Poly1305 AEAD per draft-irtf-cfrg-xchacha-03, with bug-catching cases targeting padding, length encoding, nonce split, HChaCha20 subkey derivation, counter-start, and tag rejection.]],
		[[Each non-KAT test's targets[] lists the implementation bugs it is designed to catch.]]
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test from an authoritative draft.]]
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
			description = [[AAD and ciphertext lengths chosen to expose BE-vs-LE confusion in the 8-byte length fields.]]
		},
		CounterStart = {
			bugType = [[MISSING_STEP]],
			description = [[Downstream ChaCha20 (post HChaCha20) must start at counter=1; block 0 is for the Poly1305 one-time key.]]
		},
		WrongMacKey = {
			bugType = [[MISSING_STEP]],
			description = [[Poly1305 otk is the first 32 bytes of downstream ChaCha20 block 0 keystream.]]
		},
		NonceSplit = {
			bugType = [[MISSING_STEP]],
			description = [[First 16 bytes of the 24-byte nonce go to HChaCha20; last 8 bytes prefixed with 4 zero bytes form the downstream ChaCha20 nonce.]]
		},
		HChaCha20InitialStateAdd = {
			bugType = [[MISSING_STEP]],
			description = [[HChaCha20 must NOT add the initial state at the end of its rounds (unlike regular ChaCha20). Output = state[0..4] || state[12..16] post-rounds, no add.]]
		},
		TagForgery = {
			bugType = [[AUTH_BYPASS]],
			description = [[Modified tag, ciphertext, AAD, or nonce with otherwise valid encryption.]],
			effect = [[Decrypt must reject.]]
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
	numberOfTests = 22,
	testGroups = {
		{
			type = [[XChaCha20Poly1305AeadEncrypt]],
			keySize = 256,
			ivSize = 192,
			tagSize = 128,
			tests = {
				{
					tcId = 1,
					comment = [[draft-irtf-cfrg-xchacha-03 §A.3.2 canonical XChaCha20-Poly1305 AEAD vector.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[draft-irtf-cfrg-xchacha]],
						version = [[03 §A.3.2]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					aad = [[50515253c0c1c2c3c4c5c6c7]],
					msg = [[4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e]],
					ct = [[bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e]],
					tag = [[c0875924c1c7987947deafd8780acf49]],
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
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					aad = [[]],
					msg = [[]],
					ct = [[]],
					tag = [[1dac8f73146d1e9da796cb7f7221a5df]],
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
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					aad = [[0102030405060708090a0b0c0d0e0f]],
					msg = [[]],
					ct = [[]],
					tag = [[0a24888b7c62d7f0d29099be29ab3753]],
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
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					aad = [[000102030405060708090a0b0c0d0e0f]],
					msg = [[ff]],
					ct = [[0e]],
					tag = [[5c3253be176d57b3a8851e807caf4a9c]],
					result = [[valid]]
				},
				{
					tcId = 5,
					comment = [[Plaintext (and ciphertext) exactly 16 bytes; pad16(ct) is empty. Bug if implementation adds an extra 16-byte zero pad block.]],
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
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					aad = [[aa]],
					msg = [[000102030405060708090a0b0c0d0e0f]],
					ct = [[f10d71f75ff5f25df31b7dd8faa3935a]],
					tag = [[1e9bfd677e55dc13aec2778e5e723b4f]],
					result = [[valid]]
				},
				{
					tcId = 6,
					comment = [[AAD spans 5 Poly1305 blocks (80 bytes), 1-byte plaintext. Exercises the AAD loop downstream of HChaCha20.]],
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
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					aad = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f]],
					msg = [[ff]],
					ct = [[0e]],
					tag = [[a0ff45f9dfeb42519310111b0c8680c5]],
					result = [[valid]]
				},
				{
					tcId = 7,
					comment = [[AAD length 12 and ciphertext length 24, chosen to expose BE-vs-LE confusion in the 8-byte length fields appended to the MAC input.]],
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
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					aad = [[000102030405060708090a0b]],
					msg = [[0102030405060708090a0b0c0d0e0f101112131415161718]],
					ct = [[f00e70f05ef6f352f2187cdffba092452355617a10528bf4]],
					tag = [[93a760b2f61a4729e3a2edfd09c177b8]],
					result = [[valid]]
				},
				{
					tcId = 8,
					comment = [[64-byte plaintext. Downstream ChaCha20 (post HChaCha20) must start at counter=1; using counter=0 would reuse Poly1305 key bytes as keystream.]],
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
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					aad = [[]],
					msg = [[55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555]],
					ct = [[a45926a10ea5a10fae472286a3fbc8006712273b5011c9b99fefa0591700589d556945287e38ca286486b41c3bc60b0f9444ff41f96ef125fbb1c2022833c168]],
					tag = [[34a554fe51049add241d39f26cd6ccb4]],
					result = [[valid]]
				},
				{
					tcId = 9,
					comment = [[Nonce halves are distinct constants (0x11 in bytes 0..15, 0x22 in bytes 16..23). Catches impls that mis-split the 24-byte nonce between HChaCha20 input and downstream-ChaCha20 nonce.]],
					targets = {
						[[NonceSplit]]
					},
					flags = {
						[[NonceSplit]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[111111111111111111111111111111112222222222222222]],
					aad = [[a1a2a3a4a5a6a7a8]],
					msg = [[0102030405060708090a0b0c0d0e0f10]],
					ct = [[9a35fcf65b8db92c63283da6efd53f18]],
					tag = [[fadbad003f3b3d8a80b9fa06ffd0dd4f]],
					result = [[valid]]
				},
				{
					tcId = 10,
					comment = [[Tests that HChaCha20 does NOT add the initial state at the end of its rounds (unlike regular ChaCha20). Mis-adding initial state would produce a different subkey and therefore different (ct, tag).]],
					targets = {
						[[HChaCha20InitialStateAdd]]
					},
					flags = {
						[[HChaCha20InitialStateAdd]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[000000090000004a0000000031415927aaaaaaaaaaaaaaaa]],
					aad = [[]],
					msg = [[0001020304050607]],
					ct = [[44bf3ccf5af9da8a]],
					tag = [[552a633c3e1f3c0fad68a3c9f76fbe6d]],
					result = [[valid]]
				},
				{
					tcId = 11,
					comment = [[Draft §A.3.2 vector with bit 0 of tag byte 0 flipped. Decrypt must reject.]],
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
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					aad = [[50515253c0c1c2c3c4c5c6c7]],
					msg = [[4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e]],
					ct = [[bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e]],
					tag = [[c1875924c1c7987947deafd8780acf49]],
					result = [[invalid]]
				},
				{
					tcId = 12,
					comment = [[Draft §A.3.2 vector with bit 127 (last bit) of the tag flipped. Catches comparators that bail after a prefix match.]],
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
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					aad = [[50515253c0c1c2c3c4c5c6c7]],
					msg = [[4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e]],
					ct = [[bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e]],
					tag = [[c0875924c1c7987947deafd8780acfc9]],
					result = [[invalid]]
				},
				{
					tcId = 13,
					comment = [[Draft §A.3.2 vector with bit 0 of ciphertext byte 0 flipped, tag unchanged. Decrypt must reject.]],
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
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					aad = [[50515253c0c1c2c3c4c5c6c7]],
					msg = [[4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e]],
					ct = [[bc6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e]],
					tag = [[c0875924c1c7987947deafd8780acf49]],
					result = [[invalid]]
				},
				{
					tcId = 14,
					comment = [[Draft §A.3.2 vector with bit 0 of AAD byte 0 flipped, ct and tag unchanged. Decrypt must reject.]],
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
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					aad = [[51515253c0c1c2c3c4c5c6c7]],
					msg = [[4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e]],
					ct = [[bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e]],
					tag = [[c0875924c1c7987947deafd8780acf49]],
					result = [[invalid]]
				},
				{
					tcId = 15,
					comment = [[Draft §A.3.2 vector with bit 0 of nonce byte 0 flipped (within the HChaCha20 input half). Decrypt must reject because the subkey changes.]],
					targets = {
						[[TagForgery]],
						[[NonceSplit]]
					},
					flags = {
						[[TagForgery]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[414142434445464748494a4b4c4d4e4f5051525354555657]],
					aad = [[50515253c0c1c2c3c4c5c6c7]],
					msg = [[4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e]],
					ct = [[bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e]],
					tag = [[c0875924c1c7987947deafd8780acf49]],
					result = [[invalid]]
				},
				{
					tcId = 16,
					comment = [[Draft §A.3.2 vector with bit 0 of nonce byte 16 flipped (within the downstream-ChaCha20 nonce half). Decrypt must reject.]],
					targets = {
						[[TagForgery]],
						[[NonceSplit]]
					},
					flags = {
						[[TagForgery]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[404142434445464748494a4b4c4d4e4f5151525354555657]],
					aad = [[50515253c0c1c2c3c4c5c6c7]],
					msg = [[4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e]],
					ct = [[bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e]],
					tag = [[c0875924c1c7987947deafd8780acf49]],
					result = [[invalid]]
				},
				{
					tcId = 17,
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
					iv = [[a1b2c3d4e5f6071801234567fedcba98765432100f1e2d3c]],
					aad = [[a1b2c3d4e5f60718]],
					msg = [[0fedcba98765432100112233445566778899aabbccddeeff1eef00ddcc11bbaa]],
					ct = [[ae8c362ead2c229798297453c8df3a9388e10ee893d382d20cad448f55d7b41f]],
					tag = [[914d1076b44351e3ffb0e3ce714c3bf0]],
					result = [[valid]]
				},
				{
					tcId = 18,
					comment = [[Imported from Wycheproof v1 xchacha20_poly1305_test.json tcId 206: edge case for poly1305 key:ffffff3f24ac6f2f6436cec230be9ab31d8434bf94e1042d20952749a99cf641.]],
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
					key = [[606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f]],
					iv = [[000102030405060708090a0b0c0d0e0f101112133e8775b2]],
					aad = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					msg = [[7ee395bd21ada42ed12310d34918a28e596a49ee7a22f623d756b896663f68733e6c71a344f4726ac24e330679f25e492be08603aaa23f1e88c10299047c8e585983332a8b6eadcd9b6061b63fe3b58a2021b38c7cf379fe9a9f6d114f3cfe422f91af78c6fd87d4269af0e3e471abed457ae75c027e134c96cf4d9a4a646288]],
					ct = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					tag = [[4921f7c24a2d42f4da7ad9d45e8ec26c]],
					result = [[valid]]
				},
				{
					tcId = 19,
					comment = [[Imported from Wycheproof v1 xchacha20_poly1305_test.json tcId 211: edge case for poly1305 key:00000090e6e328c242cde5c83e3d8262d467f2bcd53d3755c781f3c6a2cb0648.]],
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
					key = [[606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f]],
					iv = [[000102030405060708090a0b0c0d0e0f101112130552a411]],
					aad = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					msg = [[eaccaa778935ef249e0900149dd889462d2a061486ba102b8caebe465f3959fb3119ebb5689676ffdd6d851a26739e772b54a2f5f473ea9c7e58ccbc4cfc953e8c420b2175d9dd519265630bb79bd87a601b113231a8b16ce54c331347ec04c2b1c9160f38207aa46e96feb06dee883eb422fa14908df300bb1a1ef758c408f5]],
					ct = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					tag = [[f00ee0097d7dffbd3e4b216c45da89ef]],
					result = [[valid]]
				},
				{
					tcId = 20,
					comment = [[Imported from Wycheproof v1 xchacha20_poly1305_test.json tcId 215: edge case for poly1305 key:e73c0100fbd50c408e3c06701c3908209a66d9388dd8e29458376300cb04f56a.]],
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
					key = [[606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f]],
					iv = [[000102030405060708090a0b0c0d0e0f10111213d580ecf3]],
					aad = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					msg = [[56d20c8500203274099502f38d547f3008588f396cb521a2bae1800514f1f797c00386d52c09fd64a28b393431848e13dda47f65536bfc681ca73b55a7fc019a4c8358186e009ad3e22a5f08a59b19ca4b3bf11269fecaa49a9e9aff53a02ce2f235fba061ee95eae6177f1153502a50428122a73c83695f17dff5cfde23fdf9]],
					ct = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					tag = [[ca3de68e124484e8bb825b069afaa53d]],
					result = [[valid]]
				}
			}
		},
		{
			type = [[XChaCha20Poly1305AeadEncrypt]],
			keySize = 256,
			ivSize = 0,
			tagSize = 128,
			tests = {
				{
					tcId = 21,
					comment = [[Imported from Wycheproof v1 xchacha20_poly1305_test.json tcId 307: nonce has size 0.]],
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
			type = [[XChaCha20Poly1305AeadEncrypt]],
			keySize = 256,
			ivSize = 104,
			tagSize = 128,
			tests = {
				{
					tcId = 22,
					comment = [[Imported from Wycheproof v1 xchacha20_poly1305_test.json tcId 311: nonce has size 13.]],
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
					iv = [[000102030405060708090a0b0c]],
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
