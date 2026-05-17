--!strict
-- Auto-generated from Tadashi/testvectors/kmac256_test.json
-- Do not edit by hand.

return {
	algorithm = [[KMAC256]],
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
			type = [[Kmac256]],
			rate = 1088,
			tests = {
				{
					tcId = 1,
					comment = [[NIST SP 800-185 §A.5 Sample 4: KMAC256 with incremental 32-byte key, 4-byte msg, customization 'My Tagged Application', 64-byte output.]],
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
						version = [[A.5 Sample 4]]
					},
					key = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f]],
					msg = [[00010203]],
					custom = [[4d7920546167676564204170706c69636174696f6e]],
					outputLen = 64,
					tag = [[20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd]],
					result = [[valid]]
				},
				{
					tcId = 2,
					comment = [[NIST SP 800-185 §A.5 Sample 5: KMAC256, same key+msg as Sample 4 but no customization, 64-byte output.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[nist-sp-800-185]],
						version = [[A.5 Sample 5]]
					},
					key = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f]],
					msg = [[00010203]],
					custom = [[]],
					outputLen = 64,
					tag = [[2ebd1622de2de44174e3477206060d7f64489a639b7545649132317609fa214f4c8ac90630fb4c757fba074b15186fe452ae71b6a1e443bf54059e090c11ae20]],
					result = [[valid]]
				},
				{
					tcId = 3,
					comment = [[NIST SP 800-185 §A.5 Sample 6: KMAC256 with 200-byte incremental msg, customization 'My Tagged Application', 64-byte output. Multi-block data path + custom prefix.]],
					targets = {
						[[CustomString]],
						[[LongInput]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[nist-sp-800-185]],
						version = [[A.5 Sample 6]]
					},
					key = [[404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f]],
					msg = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7]],
					custom = [[4d7920546167676564204170706c69636174696f6e]],
					outputLen = 64,
					tag = [[b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965]],
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
					tag = [[b0bd4891139d7a354fe4d068bf4b95ee0893f91f5788fc04df8e846446fa1de8]],
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
					tag = [[40a02b4674876170fdea69d24422475791973aa418e3420bcef9df730fc812a8]],
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
					tag = [[c7]],
					result = [[valid]]
				},
				{
					tcId = 7,
					comment = [[Output length equals rate (136 bytes). Output fits exactly in one squeeze; bug if impl truncates at rate or over-extends.]],
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
					outputLen = 136,
					tag = [[1461e6b02982565cd7635103975acf38d242c66a075ea83fc153c76303512e24624b97a77dc537fe1767adc9c17e8f3dc0c924ab977bfa0d233938334b54334c5e7fbc822020964ca7186fa91ee7b083ca1807f93e6d56626e7cdd12ed72f466ff2c5352f022c2e92d77707441c9725c7f682d76603801828bef12a795d0b3b2c622c599ef2d6743]],
					result = [[valid]]
				},
				{
					tcId = 8,
					comment = [[Output length rate+1 (137 bytes). Forces second squeeze permutation.]],
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
					outputLen = 137,
					tag = [[ccc3d58d78a9d9174a97335ba10369a4e999be06a816e1fb53d03ebecb1d60b37ec92533527652395c3c4f6a36ddc12948c6875f8b83a814639396f439ecafaf6e0264447625ae2d683b2f070ae979da840548e82cedfca7921c117098f874360f76a4b39e2be56560897f129dc8d7c79f8cc53d90106c5809ae8d80571f92f1071589306dc4a35c3f]],
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
					tag = [[c0d5796f8c4075232501b9f1e52e137daf764be39c5afabb1fa73e2c047eb3d1]],
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
					tag = [[82737aeb1e0c53b17d6db5cc8367cb1c18305af1f6c46c276ffc11e97f5b1144]],
					result = [[valid]]
				},
				{
					tcId = 11,
					comment = [[Long customization string (200 bytes). The cSHAKE customization prefix (encode_string("KMAC") || encode_string(S) bytepadded to rate 136) itself spans multiple absorption blocks; catches impls that only bytepad the last partial block or absorb the prefix in one shot.]],
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
					outputLen = 64,
					tag = [[f8a0c3187870900e248a4fce66284d574d015791baed8832223df58d58daf929d691d92df3c052430154c9bd95828eaa717683a8a69e70d55d9a0a5afc7f0089]],
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
					tag = [[59397527e7fb2fced32f5a7bd67d4ca5e6ef1d390e942b68a38c965d972d16ef]],
					result = [[valid]]
				}
			}
		}
	}
}
