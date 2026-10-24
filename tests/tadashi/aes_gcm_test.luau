--!strict
-- Auto-generated from Tadashi/testvectors/aes_gcm_test.json
-- Do not edit by hand.

return {
	algorithm = [[AES-GCM]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_aead_v1.json]],
	header = {
		[[AES-GCM AEAD per NIST SP 800-38D, with bug-catching cases targeting GHASH reduction, J0 derivation for non-96-bit IVs, padding boundaries, length encoding, counter start, and tag rejection.]],
		[[Each non-KAT test's targets[] lists the implementation bugs it is designed to catch.]]
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test from NIST SP 800-38D.]]
		},
		BothEmpty = {
			bugType = [[EDGE_CASE]],
			description = [[Both AAD and plaintext are empty.]],
			effect = [[GHASH input collapses to just the 16-byte length block.]]
		},
		AadOnly = {
			bugType = [[EDGE_CASE]],
			description = [[GHASH input is dominated by the AAD section.]]
		},
		AadPaddingZero = {
			bugType = [[EDGE_CASE]],
			description = [[AAD length is exactly a multiple of 16.]],
			effect = [[Bug if implementation always emits a zero-pad block.]]
		},
		CtPaddingZero = {
			bugType = [[EDGE_CASE]],
			description = [[Ciphertext length is exactly a multiple of 16.]],
			effect = [[Bug if implementation always emits a zero-pad block.]]
		},
		BlockBoundary = {
			bugType = [[EDGE_CASE]],
			description = [[Length is exactly N times 16 bytes.]]
		},
		LastBlockHandling = {
			bugType = [[EDGE_CASE]],
			description = [[Last block is partial; tests CTR pad16 and partial XOR.]]
		},
		LengthEncoding = {
			bugType = [[EDGE_CASE]],
			description = [[AAD and CT lengths chosen to expose BE-vs-LE confusion in the 8-byte length fields.]]
		},
		CounterStart = {
			bugType = [[MISSING_STEP]],
			description = [[GCTR must begin at J0+1; J0 itself is reserved for tag encryption.]]
		},
		J0NonStandardIv = {
			bugType = [[MISSING_STEP]],
			description = [[IV is not 96 bits, so J0 = GHASH(IV with bit-padding and length block) instead of IV || 0x00000001.]],
			effect = [[Bug if implementation always uses the 96-bit fast path.]]
		},
		EmptyIv = {
			bugType = [[MISSING_STEP]],
			description = [[Zero-length IV. NIST SP 800-38D Section 5.2.1.1 requires 1 <= len(IV) <= 2^64 - 1. With an empty IV, J0 = GHASH(padding || length block) depends only on H = E_K(0^128), i.e. only on the key.]],
			effect = [[Implementations that accept an empty IV produce a fixed J0 per key, destroying nonce uniqueness for every message encrypted under that key.]]
		},
		GhashReduction = {
			bugType = [[BASIC]],
			description = [[Pseudorandom inputs that exercise GF(2^128) polynomial reduction with the 0xe1 reduction constant.]]
		},
		TagForgery = {
			bugType = [[AUTH_BYPASS]],
			description = [[Modified tag, ciphertext, AAD, or IV with otherwise valid encryption.]],
			effect = [[Decrypt must reject.]]
		},
		TagTruncation = {
			bugType = [[INPUT_VALIDATION]],
			description = [[Tag length less than the 16-byte (128-bit) full-tag; CVE-2025-54887 class. Strict impls reject any tag length != 16.]],
			effect = [[Bug if impl silently accepts shorter tags.]]
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
		TagTruncationSupport = {
			bugType = [[SPEC_AMBIGUOUS]],
			description = [[Tag truncated to a SP 800-38D-permitted shorter length (MSBs of the full tag).]],
			effect = [[Truncation-supporting implementations must authenticate and decrypt; 128-bit-only implementations must cleanly reject. Accepting a truncated tag as if full-length, or comparing only the truncated prefix against a full-length computation buffer, is the bug.]]
		},
		AbsentParameter = {
			bugType = [[API_SURFACE]],
			description = [[Optional AAD argument omitted at the API level (field absent, not empty). Must behave identically to zero-length AAD.]],
			effect = [[Default-argument paths that skip the AAD length block or substitute a placeholder diverge from the spec.]]
		},
		GcmCounterWrap = {
			bugType = [[AUTH_BYPASS]],
			description = [[IV chosen so the 32-bit CTR portion of the counter block wraps modulo 2^32 during encryption (SP 800-38D inc32). The full J0 must not carry into the IV portion.]],
			effect = [[A 64-bit counter increment carries into the fixed IV field, producing wrong keystream blocks after the wrap and, on decrypt-then-MAC designs, potential auth bypass.]]
		}
	},
	numberOfTests = 45,
	testGroups = {
		{
			type = [[AesGcmEncrypt]],
			keySize = 128,
			ivSize = 96,
			tagSize = 128,
			tests = {
				{
					tcId = 1,
					comment = [[NIST GCM spec Test Case 1, AES-128 with zero key and zero IV; empty plaintext and AAD. Tag is E(K, J0).]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[nist-sp-800-38d]],
						version = [[TC1]]
					},
					key = [[00000000000000000000000000000000]],
					iv = [[000000000000000000000000]],
					aad = [[]],
					msg = [[]],
					ct = [[]],
					tag = [[58e2fccefa7e3061367f1d57a4e7455a]],
					result = [[valid]]
				},
				{
					tcId = 2,
					comment = [[NIST GCM spec Test Case 2, AES-128 with zero key and zero IV; one 16-byte zero plaintext block.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[nist-sp-800-38d]],
						version = [[TC2]]
					},
					key = [[00000000000000000000000000000000]],
					iv = [[000000000000000000000000]],
					aad = [[]],
					msg = [[00000000000000000000000000000000]],
					ct = [[0388dace60b6a392f328c2b971b2fe78]],
					tag = [[ab6e47d42cec13bdf53a67b21257bddf]],
					result = [[valid]]
				},
				{
					tcId = 3,
					comment = [[NIST GCM spec Test Case 3, AES-128 with 64-byte plaintext (4 full blocks) and no AAD.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[nist-sp-800-38d]],
						version = [[TC3]]
					},
					key = [[feffe9928665731c6d6a8f9467308308]],
					iv = [[cafebabefacedbaddecaf888]],
					aad = [[]],
					msg = [[d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255]],
					ct = [[42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985]],
					tag = [[4d5c2af327cd64a62cf35abd2ba6fab4]],
					result = [[valid]]
				},
				{
					tcId = 4,
					comment = [[NIST GCM spec Test Case 4, AES-128 with 60-byte plaintext (3 full + 4-byte partial) and 20-byte AAD (1 full + 4-byte partial). Exercises both AAD and CT padding paths.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[nist-sp-800-38d]],
						version = [[TC4]]
					},
					key = [[feffe9928665731c6d6a8f9467308308]],
					iv = [[cafebabefacedbaddecaf888]],
					aad = [[feedfacedeadbeeffeedfacedeadbeefabaddad2]],
					msg = [[d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39]],
					ct = [[42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091]],
					tag = [[5bc94fbc3221a5db94fae95ae7121a47]],
					result = [[valid]]
				},
				{
					tcId = 11,
					comment = [[Empty AAD and empty plaintext. GHASH input is just the 16-byte zero-length block; tag = E(K, J0) XOR GHASH(len(A)=0, len(C)=0).]],
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
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[]],
					msg = [[]],
					ct = [[]],
					tag = [[05950db7e4a3d87b8ca747177e7c3682]],
					result = [[valid]]
				},
				{
					tcId = 12,
					comment = [[15-byte AAD with empty plaintext. GHASH covers one partial AAD block plus the length block.]],
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
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[0102030405060708090a0b0c0d0e0f]],
					msg = [[]],
					ct = [[]],
					tag = [[712d6c33ee884c5ae75b6eb74281242f]],
					result = [[valid]]
				},
				{
					tcId = 13,
					comment = [[AAD is exactly one GHASH block (16 bytes, no padding). Bug if implementation always emits an extra zero-pad block.]],
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
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[000102030405060708090a0b0c0d0e0f]],
					msg = [[ff]],
					ct = [[49]],
					tag = [[fa1d5f2b757b57f45691239484f71bb3]],
					result = [[valid]]
				},
				{
					tcId = 14,
					comment = [[Plaintext is exactly one GHASH block (16 bytes); pad16(C) is empty. Bug if implementation always emits an extra zero-pad block.]],
					targets = {
						[[CtPaddingZero]],
						[[BlockBoundary]]
					},
					flags = {
						[[BlockBoundary]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[aa]],
					msg = [[000102030405060708090a0b0c0d0e0f]],
					ct = [[b6f388c7f832bb4deffea75b87ba0ba1]],
					tag = [[f6b10af52f5aa32b8d53d74fe60b76d0]],
					result = [[valid]]
				},
				{
					tcId = 15,
					comment = [[17-byte plaintext (1 full + 1-byte partial). Tests CTR pad16 and partial-block XOR.]],
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
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[]],
					msg = [[000102030405060708090a0b0c0d0e0fff]],
					ct = [[b6f388c7f832bb4deffea75b87ba0ba1ba]],
					tag = [[13b6e18e5168f83b7970bb92109372a3]],
					result = [[valid]]
				},
				{
					tcId = 16,
					comment = [[AAD length 12 and ciphertext length 24, chosen to expose BE-vs-LE confusion in the 8-byte length fields of the final GHASH block.]],
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
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[000102030405060708090a0b]],
					msg = [[0102030405060708090a0b0c0d0e0f101112131415161718]],
					ct = [[b7f089c0f931ba42eefda65c86b90abe54fe306e6e425bd7]],
					tag = [[3443985effdf2089592e980cd97c003b]],
					result = [[valid]]
				},
				{
					tcId = 17,
					comment = [[AAD spans 5 GHASH blocks (80 bytes), 1-byte plaintext. Exercises the AAD GHASH loop independently of the CT loop.]],
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
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f]],
					msg = [[ff]],
					ct = [[49]],
					tag = [[2133b9a9c1096ea4247bb594d3a5d6a0]],
					result = [[valid]]
				},
				{
					tcId = 18,
					comment = [[64-byte plaintext (4 CTR blocks). GCTR must use counter J0+1, J0+2, J0+3, J0+4; J0 itself is reserved for the final tag encryption.]],
					targets = {
						[[CounterStart]]
					},
					flags = {
						[[CounterStart]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[]],
					msg = [[55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555]],
					ct = [[e3a7df91a962e81fb2a2f805dee250fb10b9762f2e01199aaa0b73f420ae1aea689a1ec3606f0de544ab29b91632a04e620d8333c731513417d60bcd3b89632c]],
					tag = [[9802a8e632910fc159529e77a213fe50]],
					result = [[valid]]
				},
				{
					tcId = 19,
					comment = [[Plaintext is 32 bytes with a 96-bit IV; standard counter start. Adds a second block to make sure the counter increments correctly from J0+1 to J0+2.]],
					targets = {
						[[CounterStart]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[]],
					msg = [[00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100]],
					ct = [[b6e3a8f7b862db3d6f6e07eb476aeb51ba02feb6c0fed547883873e546d95ebf]],
					tag = [[678572b6c72512bd5475196d563b3764]],
					result = [[valid]]
				},
				{
					tcId = 20,
					comment = [[Pseudorandom key, IV, AAD, and plaintext exercising 2 AAD blocks + 2 CT blocks. General-purpose GHASH carry/reduction check.]],
					targets = {
						[[GhashReduction]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[2b7e151628aed2a6abf7158809cf4f3c]],
					iv = [[000102030405060708090a0b]],
					aad = [[48656c6c6f2c20576f726c640d0a41410102030405060708090a0b0c0d0e0f10]],
					msg = [[6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51]],
					ct = [[300e85b4962811d409e56a97d11aa3bda5178ba153daf84e9bbdfa0b7999db66]],
					tag = [[c4b15cc687ddd529d8ba0acdc996fa5d]],
					result = [[valid]]
				},
				{
					tcId = 21,
					comment = [[NIST TC4 with bit 0 of tag byte 0 flipped. Decrypt must reject.]],
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
					key = [[feffe9928665731c6d6a8f9467308308]],
					iv = [[cafebabefacedbaddecaf888]],
					aad = [[feedfacedeadbeeffeedfacedeadbeefabaddad2]],
					msg = [[d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39]],
					ct = [[42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091]],
					tag = [[5ac94fbc3221a5db94fae95ae7121a47]],
					result = [[invalid]]
				},
				{
					tcId = 22,
					comment = [[NIST TC4 with bit 127 of tag flipped. Catches comparators that bail after a prefix match.]],
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
					key = [[feffe9928665731c6d6a8f9467308308]],
					iv = [[cafebabefacedbaddecaf888]],
					aad = [[feedfacedeadbeeffeedfacedeadbeefabaddad2]],
					msg = [[d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39]],
					ct = [[42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091]],
					tag = [[5bc94fbc3221a5db94fae95ae7121ac7]],
					result = [[invalid]]
				},
				{
					tcId = 23,
					comment = [[NIST TC4 with bit 0 of ciphertext byte 0 flipped, tag unchanged. Decrypt must reject.]],
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
					key = [[feffe9928665731c6d6a8f9467308308]],
					iv = [[cafebabefacedbaddecaf888]],
					aad = [[feedfacedeadbeeffeedfacedeadbeefabaddad2]],
					msg = [[d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39]],
					ct = [[43831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091]],
					tag = [[5bc94fbc3221a5db94fae95ae7121a47]],
					result = [[invalid]]
				},
				{
					tcId = 24,
					comment = [[NIST TC4 with bit 0 of AAD byte 0 flipped, ct and tag unchanged. Decrypt must reject.]],
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
					key = [[feffe9928665731c6d6a8f9467308308]],
					iv = [[cafebabefacedbaddecaf888]],
					aad = [[ffedfacedeadbeeffeedfacedeadbeefabaddad2]],
					msg = [[d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39]],
					ct = [[42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091]],
					tag = [[5bc94fbc3221a5db94fae95ae7121a47]],
					result = [[invalid]]
				},
				{
					tcId = 25,
					comment = [[NIST TC4 with bit 0 of IV byte 0 flipped, ct/tag/aad unchanged. Decrypt must reject because J0 changes.]],
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
					key = [[feffe9928665731c6d6a8f9467308308]],
					iv = [[cbfebabefacedbaddecaf888]],
					aad = [[feedfacedeadbeeffeedfacedeadbeefabaddad2]],
					msg = [[d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39]],
					ct = [[42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091]],
					tag = [[5bc94fbc3221a5db94fae95ae7121a47]],
					result = [[invalid]]
				},
				{
					tcId = 26,
					comment = [[15-byte plaintext (sub-block, single partial). Exercises GCTR partial-only path and GHASH pad16(C) for a less-than-full final block.]],
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
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[]],
					msg = [[0102030405060708090a0b0c0d0e0f]],
					ct = [[b7f089c0f931ba42eefda65c86b90a]],
					tag = [[cf0b1b53cae365ca63c8a743cd6fc0a2]],
					result = [[valid]]
				},
				{
					tcId = 27,
					comment = [[17-byte AAD (1 full + 1-byte partial). Tightest AAD partial-block boundary; verifies AAD padding writes the data byte before the zeros, not after.]],
					targets = {
						[[LastBlockHandling]],
						[[AadOnly]]
					},
					flags = {
						[[LastBlockHandling]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[000102030405060708090a0b0c0d0e0fff]],
					msg = [[11]],
					ct = [[a7]],
					tag = [[b1804064c344b448ef5ddc62fb76f0fb]],
					result = [[valid]]
				},
				{
					tcId = 28,
					comment = [[AAD and ciphertext both exactly block-aligned (32 bytes each, 2 full blocks, no padding on either side). Bug if impl always emits a zero-pad block.]],
					targets = {
						[[AadPaddingZero]],
						[[CtPaddingZero]],
						[[BlockBoundary]]
					},
					flags = {
						[[BlockBoundary]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					msg = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					ct = [[96d3a8e7d8129b6dcfde877ba79a2b8175dd11494f617af8c7671c9a49c67180]],
					tag = [[62281de4cd01ba11399953c1189d49d9]],
					result = [[valid]]
				},
				{
					tcId = 31,
					comment = [[80-byte AAD with the last bit (bit 639) flipped, ct and tag unchanged. Catches AAD comparators that short-circuit on a running GHASH prefix.]],
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
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4ecf]],
					msg = [[77777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777]],
					ct = [[c185fdb38b40ca3d9080da27fcc072d9329b540d0c233bb8882951d6028c38c84ab83ce1424d2fc766890b9b3410826c402fa111e513731635f429ef19ab410e]],
					tag = [[0f82a560e7519ade859230f967ba94e9]],
					result = [[invalid]]
				},
				{
					tcId = 32,
					comment = [[64-byte ciphertext with the last bit (bit 511) flipped, AAD and tag unchanged. Catches CT comparators that short-circuit on a running GHASH prefix.]],
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
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f]],
					msg = [[77777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777]],
					ct = [[c185fdb38b40ca3d9080da27fcc072d9329b540d0c233bb8882951d6028c38c84ab83ce1424d2fc766890b9b3410826c402fa111e513731635f429ef19ab418e]],
					tag = [[0f82a560e7519ade859230f967ba94e9]],
					result = [[invalid]]
				},
				{
					tcId = 33,
					comment = [[Tag truncated to 8 bytes (the first 8 of the real 16-byte tag). rbx-crypto's ConstantTimeCompare requires equal lengths, so this is rejected via length-mismatch. CVE-2025-54887 class: impls that accept short tags trade auth strength for forgery surface (2^64 instead of 2^128).]],
					targets = {
						[[TagTruncation]],
						[[TagForgery]]
					},
					flags = {
						[[TagTruncation]],
						[[InputValidation]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[]],
					msg = [[00112233445566778899aabbccddeeff]],
					ct = [[b6e3a8f7b862db3d6f6e07eb476aeb51]],
					tag = [[7a8d236bd11a99c8]],
					result = [[invalid]]
				},
				{
					tcId = 34,
					comment = [[Tag truncated to 12 bytes (96 bits, the minimum recommended truncation per NIST SP 800-38D). rbx-crypto requires the full 16-byte tag; rejects.]],
					targets = {
						[[TagTruncation]],
						[[TagForgery]]
					},
					flags = {
						[[TagTruncation]],
						[[InputValidation]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c]],
					aad = [[]],
					msg = [[00112233445566778899aabbccddeeff]],
					ct = [[b6e3a8f7b862db3d6f6e07eb476aeb51]],
					tag = [[7a8d236bd11a99c832014088]],
					result = [[invalid]]
				},
				{
					tcId = 35,
					comment = [[Asymmetric key, IV, AAD, and plaintext bytes; nibbles within each byte differ. Catches hex parser nibble-swap or byte-reverse bugs anywhere in the runner.]],
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
					key = [[0123456789abcdeffedcba9876543210]],
					iv = [[a1b2c3d4e5f6071801234567]],
					aad = [[a1b2c3d4e5f60718]],
					msg = [[0fedcba98765432100112233445566778899aabbccddeeff1eef00ddcc11bbaa]],
					ct = [[8bdd358a861e1cdd27ee51c3a7f005d3c3dd471c250e9c0ca7376812a8fc2373]],
					tag = [[131f0a2e2aef482177bbb1c0584ef83e]],
					result = [[valid]]
				},
				{
					tcId = 39,
					comment = [[AAD parameter entirely absent (no 'aad' field): the consumer must invoke its API without an AAD argument. Identical inputs to tcId 3 otherwise; ct and tag must equal tcId 3 exactly.]],
					targets = {
						[[AbsentParameter]]
					},
					flags = {
						[[AbsentParameter]]
					},
					source = {
						name = [[nist-gcm-spec]],
						version = [[TC3]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[feffe9928665731c6d6a8f9467308308]],
					iv = [[cafebabefacedbaddecaf888]],
					msg = [[d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255]],
					ct = [[42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985]],
					tag = [[4d5c2af327cd64a62cf35abd2ba6fab4]],
					result = [[valid]]
				},
				{
					tcId = 40,
					comment = [[Imported from Wycheproof v1 aes_gcm_test.json tcId 77: J0:000102030405060708090a0b0c0d0e0f.]],
					targets = {
						[[GcmCounterWrap]],
						[[CounterStart]]
					},
					flags = {
						[[CounterWrap]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[00112233445566778899aabbccddeeff]],
					iv = [[f95fde4a751913202aeeee32a0b55753]],
					aad = [[]],
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[00078d109d92143fcd5df56721b884fac64ac7762cc09eea2a3c68e92a17bdb575f87bda18be564e]],
					tag = [[152a65045fe674f97627427af5be22da]],
					result = [[valid]]
				},
				{
					tcId = 41,
					comment = [[Imported from Wycheproof v1 aes_gcm_test.json tcId 88: J0:000102030405060708090a0bffff7ffe.]],
					targets = {
						[[GcmCounterWrap]],
						[[CounterStart]]
					},
					flags = {
						[[CounterWrap]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[00112233445566778899aabbccddeeff]],
					iv = [[c4dcd9fcce24d3522b66f1469a1e8bb9]],
					aad = [[]],
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[149fde9abbd3a43c2548575e0db9fb84a197a37a5d79697078536bc27fe46cd8d475526d9044aa94]],
					tag = [[62a4b6875c288345d6a454399eac1afa]],
					result = [[valid]]
				}
			}
		},
		{
			type = [[AesGcmEncrypt]],
			keySize = 192,
			ivSize = 96,
			tagSize = 128,
			tests = {
				{
					tcId = 7,
					comment = [[NIST GCM spec Test Case 7, AES-192 with zero key and zero IV; empty plaintext and AAD.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[nist-sp-800-38d]],
						version = [[TC7]]
					},
					key = [[000000000000000000000000000000000000000000000000]],
					iv = [[000000000000000000000000]],
					aad = [[]],
					msg = [[]],
					ct = [[]],
					tag = [[cd33b28ac773f74ba00ed1f312572435]],
					result = [[valid]]
				},
				{
					tcId = 42,
					comment = [[Imported from Wycheproof v1 aes_gcm_test.json tcId 157: J0:000102030405060708090a0b0c0d0e0f.]],
					targets = {
						[[GcmCounterWrap]],
						[[CounterStart]]
					},
					flags = {
						[[CounterWrap]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[00112233445566778899aabbccddeeff1021324354657687]],
					iv = [[029e0e777db092b12535d043012f09ba]],
					aad = [[]],
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[f83cee467336e1a09b75f24e9b4385c99c13e6af722256a66129ece961fe803b167bad206f5017fb]],
					tag = [[09338a42f0acc14f97c064f52f5f1688]],
					result = [[valid]]
				},
				{
					tcId = 43,
					comment = [[Imported from Wycheproof v1 aes_gcm_test.json tcId 168: J0:000102030405060708090a0bffff7ffe.]],
					targets = {
						[[GcmCounterWrap]],
						[[CounterStart]]
					},
					flags = {
						[[CounterWrap]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[00112233445566778899aabbccddeeff1021324354657687]],
					iv = [[a13434d1cd8301d8b12212051fabaabe]],
					aad = [[]],
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[d2cae1684aa407a13a2e2da5357e29f55deccf838b2cf5f869c90d2a611160b1e578ab8121b93735]],
					tag = [[ea2d018099cd7925c507cef0ceddb0ae]],
					result = [[valid]]
				}
			}
		},
		{
			type = [[AesGcmEncrypt]],
			keySize = 256,
			ivSize = 96,
			tagSize = 128,
			tests = {
				{
					tcId = 8,
					comment = [[NIST GCM spec Test Case 13, AES-256 with zero key and zero IV; empty plaintext and AAD.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[nist-sp-800-38d]],
						version = [[TC13]]
					},
					key = [[0000000000000000000000000000000000000000000000000000000000000000]],
					iv = [[000000000000000000000000]],
					aad = [[]],
					msg = [[]],
					ct = [[]],
					tag = [[530f8afbc74536b9a963b4f1c4cb738b]],
					result = [[valid]]
				},
				{
					tcId = 9,
					comment = [[NIST GCM spec Test Case 14, AES-256 with zero key and zero IV; one zero plaintext block.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[nist-sp-800-38d]],
						version = [[TC14]]
					},
					key = [[0000000000000000000000000000000000000000000000000000000000000000]],
					iv = [[000000000000000000000000]],
					aad = [[]],
					msg = [[00000000000000000000000000000000]],
					ct = [[cea7403d4d606b6e074ec5d3baf39d18]],
					tag = [[d0d1c8a799996bf0265b98b5d48ab919]],
					result = [[valid]]
				},
				{
					tcId = 10,
					comment = [[NIST GCM spec Test Case 16, AES-256 with 60-byte plaintext and 20-byte AAD; both partial.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[nist-sp-800-38d]],
						version = [[TC16]]
					},
					key = [[feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308]],
					iv = [[cafebabefacedbaddecaf888]],
					aad = [[feedfacedeadbeeffeedfacedeadbeefabaddad2]],
					msg = [[d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39]],
					ct = [[522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662]],
					tag = [[76fc6ece0f4e1768cddf8853bb2d551b]],
					result = [[valid]]
				},
				{
					tcId = 44,
					comment = [[Imported from Wycheproof v1 aes_gcm_test.json tcId 240: J0:000102030405060708090a0b0c0d0e0f.]],
					targets = {
						[[GcmCounterWrap]],
						[[CounterStart]]
					},
					flags = {
						[[CounterWrap]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f]],
					iv = [[5c2ea9b695fcf6e264b96074d6bfa572]],
					aad = [[]],
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[28e1c5232f4ee8161dbe4c036309e0b3254e9212bef0a93431ce5e5604c8f6a73c18a3183018b770]],
					tag = [[d5808a1bd11a01129bf3c6919aff2339]],
					result = [[valid]]
				},
				{
					tcId = 45,
					comment = [[Imported from Wycheproof v1 aes_gcm_test.json tcId 251: J0:000102030405060708090a0bffff7ffe.]],
					targets = {
						[[GcmCounterWrap]],
						[[CounterStart]]
					},
					flags = {
						[[CounterWrap]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f]],
					iv = [[24836f0a46ab6601a760221b074cbd6d]],
					aad = [[]],
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[5e3434b45edbf0d1f6e02d1144dbf867a1a0120660ff52e6b1700b12c54d2d33b94b00cd7882d885]],
					tag = [[ee74ccb30d649ebf6916d05a7dbe5696]],
					result = [[valid]]
				}
			}
		},
		{
			type = [[AesGcmEncrypt]],
			keySize = 128,
			ivSize = 64,
			tagSize = 128,
			tests = {
				{
					tcId = 5,
					comment = [[NIST GCM spec Test Case 5, AES-128 with 64-bit IV. Non-96-bit IV triggers the J0 = GHASH(IV || 0^pad || len(IV)) derivation rather than the 96-bit fast path.]],
					targets = {
						[[J0NonStandardIv]]
					},
					flags = {
						[[Ktv]],
						[[J0NonStandardIv]]
					},
					source = {
						name = [[nist-sp-800-38d]],
						version = [[TC5]]
					},
					key = [[feffe9928665731c6d6a8f9467308308]],
					iv = [[cafebabefacedbad]],
					aad = [[feedfacedeadbeeffeedfacedeadbeefabaddad2]],
					msg = [[d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39]],
					ct = [[61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598]],
					tag = [[3612d2e79e3b0785561be14aaca2fccb]],
					result = [[valid]]
				}
			}
		},
		{
			type = [[AesGcmEncrypt]],
			keySize = 128,
			ivSize = 480,
			tagSize = 128,
			tests = {
				{
					tcId = 6,
					comment = [[NIST GCM spec Test Case 6, AES-128 with 480-bit (60-byte) IV; J0 derivation runs GHASH over 4 blocks of IV plus a length block.]],
					targets = {
						[[J0NonStandardIv]]
					},
					flags = {
						[[Ktv]],
						[[J0NonStandardIv]]
					},
					source = {
						name = [[nist-sp-800-38d]],
						version = [[TC6]]
					},
					key = [[feffe9928665731c6d6a8f9467308308]],
					iv = [[9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b]],
					aad = [[feedfacedeadbeeffeedfacedeadbeefabaddad2]],
					msg = [[d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39]],
					ct = [[8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5]],
					tag = [[619cc5aefffe0bfa462af43c1699d050]],
					result = [[valid]]
				}
			}
		},
		{
			type = [[AesGcmEncrypt]],
			keySize = 128,
			ivSize = 128,
			tagSize = 128,
			tests = {
				{
					tcId = 29,
					comment = [[128-bit IV (exactly one full GHASH block, no partial). Non-96-bit J0 derivation with no padding inside the IV; only the IV block + the 16-byte length block go through GHASH.]],
					targets = {
						[[J0NonStandardIv]],
						[[BlockBoundary]]
					},
					flags = {
						[[J0NonStandardIv]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[0001020304050607080a0b0c0d0e0f10]],
					aad = [[aabbccdd]],
					msg = [[00112233445566778899aabbccddeeff]],
					ct = [[30e2a2bb8452fed274f9314d4c94be57]],
					tag = [[9b3d8b82630cf14a36116fee5116393d]],
					result = [[valid]]
				}
			}
		},
		{
			type = [[AesGcmEncrypt]],
			keySize = 256,
			ivSize = 64,
			tagSize = 128,
			tests = {
				{
					tcId = 30,
					comment = [[AES-256 with 64-bit IV. Combines the 14-round key schedule and the J0 = GHASH(IV, pad, len) derivation; bug if impl branches on key size and skips the GHASH-of-IV path only for one variant.]],
					targets = {
						[[J0NonStandardIv]]
					},
					flags = {
						[[J0NonStandardIv]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[0001020304050607]],
					aad = [[a1a2a3a4]],
					msg = [[00112233445566778899aabbccddeeff]],
					ct = [[4947d15f001a373760da6e9d66f264c6]],
					tag = [[ae5ff9edf0a878a6e084cd6e6b376b1e]],
					result = [[valid]]
				}
			}
		},
		{
			type = [[AesGcmEncrypt]],
			keySize = 128,
			ivSize = 0,
			tagSize = 128,
			tests = {
				{
					tcId = 36,
					comment = [[Empty (zero-length) IV. SP 800-38D requires 1 <= len(IV) <= 2^64 - 1; both encryption and decryption must refuse to operate. The recorded ct and tag are what a NON-REJECTING implementation computes (with an empty IV, J0 = GHASH(len block) = 0^128, fixed per key): an implementation that accepts the empty IV will successfully authenticate and decrypt, and therefore FAIL this test; refusing (error or auth-failure result) passes.]],
					targets = {
						[[EmptyIv]]
					},
					flags = {
						[[EmptyIv]]
					},
					source = {
						name = [[nist-sp-800-38d]],
						version = [[5.2.1.1]],
						crossChecked = {
							[[pyca/cryptography (AES-ECB primitive, GCM composed per SP 800-38D)]]
						}
					},
					key = [[000102030405060708090a0b0c0d0e0f]],
					iv = [[]],
					aad = [[]],
					msg = [[00112233445566778899aabbccddeeff]],
					ct = [[735731a6d195d269c1e21758a929c3f5]],
					tag = [[5a8120883d0836fb361154cc6d68843b]],
					result = [[invalid]]
				}
			}
		},
		{
			type = [[AesGcmEncrypt]],
			keySize = 128,
			ivSize = 96,
			tagSize = 96,
			tests = {
				{
					tcId = 37,
					comment = [[NIST TC4 with the tag truncated to 96 bits (the minimum recommended SP 800-38D truncation). Acceptable: truncation-supporting implementations authenticate and decrypt (cross-checked with pyca/cryptography); 128-bit-only implementations cleanly reject.]],
					targets = {
						[[TagTruncationSupport]]
					},
					flags = {
						[[TagTruncationSupport]],
						[[Acceptable]]
					},
					source = {
						name = [[nist-gcm-spec]],
						version = [[TC4]],
						crossChecked = {
							[[pyca/cryptography]]
						}
					},
					key = [[feffe9928665731c6d6a8f9467308308]],
					iv = [[cafebabefacedbaddecaf888]],
					aad = [[feedfacedeadbeeffeedfacedeadbeefabaddad2]],
					msg = [[d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39]],
					ct = [[42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091]],
					tag = [[5bc94fbc3221a5db94fae95a]],
					result = [[acceptable]]
				}
			}
		},
		{
			type = [[AesGcmEncrypt]],
			keySize = 128,
			ivSize = 96,
			tagSize = 120,
			tests = {
				{
					tcId = 38,
					comment = [[NIST TC4 with the tag truncated to 120 bits (the longest non-full SP 800-38D truncation). Acceptable: truncation-supporting implementations authenticate and decrypt (cross-checked with pyca/cryptography); 128-bit-only implementations cleanly reject.]],
					targets = {
						[[TagTruncationSupport]]
					},
					flags = {
						[[TagTruncationSupport]],
						[[Acceptable]]
					},
					source = {
						name = [[nist-gcm-spec]],
						version = [[TC4]],
						crossChecked = {
							[[pyca/cryptography]]
						}
					},
					key = [[feffe9928665731c6d6a8f9467308308]],
					iv = [[cafebabefacedbaddecaf888]],
					aad = [[feedfacedeadbeeffeedfacedeadbeefabaddad2]],
					msg = [[d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39]],
					ct = [[42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091]],
					tag = [[5bc94fbc3221a5db94fae95ae7121a]],
					result = [[acceptable]]
				}
			}
		}
	}
}
