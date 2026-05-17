--!strict
-- Auto-generated from Tadashi/testvectors/kmac128_test.json
-- Do not edit by hand.

return {
	algorithm = [[KMAC128]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_keyed_xof_v1.json]],
	header = {
		[[KMAC128 per NIST SP 800-185, with bug-catching cases targeting key bytepad, customization-prefix domain separation, output-length binding, and squeeze boundaries.]],
		[[Each non-KAT test's targets[] lists the implementation bugs it is designed to catch.]]
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test from NIST SP 800-185 §A.4.]]
		},
		EmptyMessage = {
			bugType = [[EDGE_CASE]],
			description = [[Zero-length data input.]]
		},
		EmptyKey = {
			bugType = [[EDGE_CASE]],
			description = [[Zero-length key; encoded as left_encode(0).]]
		},
		EmptyCustom = {
			bugType = [[EDGE_CASE]],
			description = [[Empty customization string; the N="KMAC" prefix is still present so domain stays cSHAKE.]]
		},
		CustomString = {
			bugType = [[MISSING_STEP]],
			description = [[Non-empty customization string is bytepadded into the cSHAKE prefix as encode_string("KMAC") || encode_string(S).]]
		},
		BytepadCustom = {
			bugType = [[MISSING_STEP]],
			description = [[Long customization string makes the cSHAKE customization prefix span multiple absorption blocks; bytepad is applied to the full prefix, not per block.]]
		},
		DomainSeparator = {
			bugType = [[MISSING_STEP]],
			description = [[KMAC always uses the cSHAKE 0x04 domain separator (not the plain SHAKE 0x1F).]]
		},
		BytepadKey = {
			bugType = [[MISSING_STEP]],
			description = [[Encoded key is bytepadded to the rate before being absorbed.]]
		},
		OutputLengthBinding = {
			bugType = [[MISSING_STEP]],
			description = [[Output length in bits is right_encoded and appended to the data input before squeezing.]],
			effect = [[Different output lengths produce unrelated outputs.]]
		},
		ShakeSqueezeBoundary = {
			bugType = [[EDGE_CASE]],
			description = [[Output length at or just over a rate boundary.]]
		},
		LongInput = {
			bugType = [[BASIC]],
			description = [[Data input spans multiple rate-blocks.]]
		},
		LongKey = {
			bugType = [[BASIC]],
			description = [[Encoded+bytepadded key spans multiple rate-blocks.]]
		},
		ShortOutput = {
			bugType = [[EDGE_CASE]],
			description = [[Output length 1 byte.]]
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
		}
	},
	numberOfTests = 12,
	testGroups = {
		{
			type = [[Kmac128]],
			rate = 1344,
			tests = {
				{
					tcId = 1,
					comment = [[NIST SP 800-185 §A.4 Sample 1: KMAC128 with incremental 32-byte key, 4-byte msg, no customization, 32-byte output.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[nist-sp-800-185]],
						version = [[A.4 Sample 1]]
					},
					key = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f]],
					msg = [[00010203]],
					custom = [[]],
					outputLen = 32,
					tag = [[e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e]],
					result = [[valid]]
				},
				{
					tcId = 2,
					comment = [[NIST SP 800-185 §A.4 Sample 2: Same as Sample 1 but with custom string 'My Tagged Application'. Tests cSHAKE customization-prefix path.]],
					targets = {
						[[CustomString]],
						[[DomainSeparator]]
					},
					flags = {
						[[Ktv]],
						[[CustomString]]
					},
					source = {
						name = [[nist-sp-800-185]],
						version = [[A.4 Sample 2]]
					},
					key = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f]],
					msg = [[00010203]],
					custom = [[4d7920546167676564204170706c69636174696f6e]],
					outputLen = 32,
					tag = [[3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5]],
					result = [[valid]]
				},
				{
					tcId = 3,
					comment = [[NIST SP 800-185 §A.4 Sample 3: 200-byte incremental msg with customization. Multi-block data path + custom prefix.]],
					targets = {
						[[CustomString]],
						[[LongInput]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[nist-sp-800-185]],
						version = [[A.4 Sample 3]]
					},
					key = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f]],
					msg = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7]],
					custom = [[4d7920546167676564204170706c69636174696f6e]],
					outputLen = 32,
					tag = [[1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230]],
					result = [[valid]]
				},
				{
					tcId = 4,
					comment = [[Empty msg, no customization, 32-byte output. Tests pure key+bytepad+right_encode flow with no data block.]],
					targets = {
						[[EmptyMessage]]
					},
					flags = {
						[[EmptyMessage]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					key = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f]],
					msg = [[]],
					custom = [[]],
					outputLen = 32,
					tag = [[58e8a99428d57617aa5caeae1de3db108af411286e64a00a6e1f308c3fe9557c]],
					result = [[valid]]
				},
				{
					tcId = 5,
					comment = [[Empty key (zero-length). Encoded key prefix is just left_encode(0); bytepadded to rate; bug if impl special-cases empty key.]],
					targets = {
						[[EmptyKey]]
					},
					flags = {
						[[EmptyKey]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					key = [[]],
					msg = [[aa]],
					custom = [[]],
					outputLen = 32,
					tag = [[2e1292b219feb7747e3cd6108559c4a0a4715edef3bda5b812e238e5cc0c74c5]],
					result = [[valid]]
				},
				{
					tcId = 6,
					comment = [[Output length 1 byte. Smallest valid output. Note KMAC binds output length into the input (via right_encode), so changing outputLen produces an unrelated output.]],
					targets = {
						[[OutputLengthBinding]]
					},
					flags = {
						[[ShortOutput]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					key = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f]],
					msg = [[aa]],
					custom = [[]],
					outputLen = 1,
					tag = [[65]],
					result = [[valid]]
				},
				{
					tcId = 7,
					comment = [[Output length equals rate (168 bytes). Output fits exactly in one squeeze; bug if impl truncates at rate or over-extends.]],
					targets = {
						[[OutputLengthBinding]],
						[[ShakeSqueezeBoundary]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					key = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f]],
					msg = [[aa]],
					custom = [[]],
					outputLen = 168,
					tag = [[3f2487b358dd3490e2b653d68a18c435820818ca04b18bb54e88e3a774f8d5d1b35476b9187c0aa9716983578b0f1c5908b6cdaa37960f2679aec752409978e905e2664a8c9790e72772e4c7d94610191fc8fe91f6a1a8409c8e596a4adf0a98d71d7a50b5a95d0c7844468644872ae62e28c7df637d5ad16693b7e9f86eeec5dd60ab9a554b01b67d6c0fea64674529080c4c933c7edb4e3058bc859b4f04f97fe8a9e202abe66d]],
					result = [[valid]]
				},
				{
					tcId = 8,
					comment = [[Output length rate+1 (169 bytes). Forces second squeeze permutation.]],
					targets = {
						[[OutputLengthBinding]],
						[[ShakeSqueezeBoundary]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					key = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f]],
					msg = [[aa]],
					custom = [[]],
					outputLen = 169,
					tag = [[b3ab75e3f2a5da0a02fa6de6a5cc1f3ec6abcb88958f84a870a3958d8ed6c0eb962b980f2771bca7ec61196493cd26c17c2cc0bc0211c8451873c1248b3f260752af8896871f1383efef595725e6eb269bd86e6625d5c129231339bf0a2d0f5ff6cd6dc9725b5a8a597f0b4e908a421df7667c8d50d0089a17ffd19b19793be98527b1ba1a223dbd90e40d838765e862b3dfb00c77614a5c3e765a9248fd5f48e97406323a5a0815ea]],
					result = [[valid]]
				},
				{
					tcId = 9,
					comment = [[Key longer than rate (200 bytes). Key encoding (left_encode || key) bytepadded to rate; long keys span multiple rate-blocks of the prefix.]],
					targets = {
						[[BytepadKey]],
						[[LongKey]]
					},
					flags = {
						[[LongKey]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					key = [[4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444]],
					msg = [[aa]],
					custom = [[]],
					outputLen = 32,
					tag = [[ef8722befe96e0689b2bf134a0f4e4a4cd1697a9dff6cc48dac08a69307c8d76]],
					result = [[valid]]
				},
				{
					tcId = 10,
					comment = [[Empty customization string. Bug if impl conflates empty custom with non-KMAC mode (cSHAKE with empty N and S falls back to plain SHAKE).]],
					targets = {
						[[DomainSeparator]],
						[[CustomString]]
					},
					flags = {
						[[EmptyCustom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					key = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f]],
					msg = [[aa]],
					custom = [[]],
					outputLen = 32,
					tag = [[0de0beaf2e15a31e6c87a85d036bf1354029342a63fc6dbc4285c4951759f05d]],
					result = [[valid]]
				},
				{
					tcId = 11,
					comment = [[Long customization string (200 bytes). The cSHAKE customization prefix (encode_string("KMAC") || encode_string(S) bytepadded to rate 168) itself spans multiple absorption blocks; catches impls that only bytepad the last partial block or absorb the prefix in one shot.]],
					targets = {
						[[CustomString]],
						[[BytepadCustom]]
					},
					flags = {
						[[CustomString]],
						[[LongCustom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					key = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f]],
					msg = [[aa]],
					custom = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0001020304050607]],
					outputLen = 32,
					tag = [[d31a681e7808bb592d5c5b011fa2badb4396b2ffc7ce7b412f84768afb1b2d37]],
					result = [[valid]]
				},
				{
					tcId = 12,
					comment = [[Asymmetric key, msg, custom bytes; nibbles within each byte differ.]],
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
							[[@noble/hashes]]
						}
					},
					key = [[0123456789abcdeffedcba9876543210]],
					msg = [[0fedcba98765432100112233445566778899aabbccddeeff]],
					custom = [[a1b2c3d4e5f60718]],
					outputLen = 32,
					tag = [[0d1a393d4f9a27cf9b2379a8e6af1501adcf6d155cdb79577b41c34e1c3ec335]],
					result = [[valid]]
				}
			}
		}
	}
}
