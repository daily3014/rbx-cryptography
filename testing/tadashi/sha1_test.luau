--!strict
-- Auto-generated from Tadashi/testvectors/sha1_test.json
-- Do not edit by hand.

return {
	algorithm = [[SHA-1]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_hash_v1.json]],
	header = {
		[[SHA-1 per FIPS 180-4. DEPRECATED for new security uses (broken collision resistance since 2017 SHAttered); covered here for legacy compatibility only.]],
		[[Tests cover the FIPS 180-4 KATs plus padding boundaries and length-encoding edges (shared with SHA-256 since both use a 64-byte block and 8-byte BE length field).]]
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test from FIPS 180-4.]]
		},
		Deprecated = {
			bugType = [[BASIC]],
			description = [[Algorithm is broken for collision resistance; use only for legacy compatibility (Git, TLS-pre-1.3 legacy, HMAC where MAC keys are pre-shared).]]
		},
		EmptyMessage = {
			bugType = [[EDGE_CASE]],
			description = [[Zero-length input.]]
		},
		BlockBoundary = {
			bugType = [[EDGE_CASE]],
			description = [[Message length is exactly N * 64 bytes.]]
		},
		PaddingFitsLastBlock = {
			bugType = [[EDGE_CASE]],
			description = [[0x80 + 8-byte length fit in the same block as the last data byte.]]
		},
		PaddingNewBlock = {
			bugType = [[EDGE_CASE]],
			description = [[Padding spills into a second block.]]
		},
		BlockLoop = {
			bugType = [[BASIC]],
			description = [[Long input forces many block iterations.]]
		},
		LengthEncodingBitsVsBytes = {
			bugType = [[EDGE_CASE]],
			description = [[Bit count vs byte count differ; catches bytes-instead-of-bits encoding.]]
		},
		LengthEncodingEndian = {
			bugType = [[EDGE_CASE]],
			description = [[Bit length occupies non-low byte of the 8-byte BE length field.]]
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
	numberOfTests = 10,
	testGroups = {
		{
			type = [[Sha1Digest]],
			digestSize = 160,
			blockSize = 512,
			tests = {
				{
					tcId = 1,
					comment = [[FIPS 180-4 §A.1 empty message. Tests IV constants and pure-padding compression.]],
					targets = {
						[[EmptyMessage]]
					},
					flags = {
						[[Ktv]],
						[[EmptyMessage]],
						[[Deprecated]]
					},
					source = {
						name = [[fips-180-4]],
						version = [[A.1]]
					},
					msg = [[]],
					digest = [[da39a3ee5e6b4b0d3255bfef95601890afd80709]],
					result = [[valid]]
				},
				{
					tcId = 2,
					comment = [[FIPS 180-4 §A.1 'abc'. Standard short single-block KAT.]],
					targets = {},
					flags = {
						[[Ktv]],
						[[Deprecated]]
					},
					source = {
						name = [[fips-180-4]],
						version = [[A.1]]
					},
					msg = [[616263]],
					digest = [[a9993e364706816aba3e25717850c26c9cd0d89d]],
					result = [[valid]]
				},
				{
					tcId = 3,
					comment = [[FIPS 180-4 §A.2 56-byte two-block KAT. Padding spills because 56 + 1 + 8 = 65 > 64.]],
					targets = {
						[[PaddingNewBlock]]
					},
					flags = {
						[[Ktv]],
						[[PaddingNewBlock]],
						[[Deprecated]]
					},
					source = {
						name = [[fips-180-4]],
						version = [[A.2]]
					},
					msg = [[6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071]],
					digest = [[84983e441c3bd26ebaae4aa1f95129e5e54670f1]],
					result = [[valid]]
				},
				{
					tcId = 4,
					comment = [[55-byte message. 0x80 + 8-byte length encoding fit exactly in the same 64-byte block (55 + 1 + 8 = 64).]],
					targets = {
						[[PaddingFitsLastBlock]]
					},
					flags = {
						[[PaddingFitsLastBlock]],
						[[Deprecated]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					msg = [[55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555]],
					digest = [[1e80779d0e0d29a5baacab034f0a31cc291fff5c]],
					result = [[valid]]
				},
				{
					tcId = 5,
					comment = [[63-byte message. Only the 0x80 padding byte fits; everything else spills.]],
					targets = {
						[[PaddingNewBlock]]
					},
					flags = {
						[[PaddingNewBlock]],
						[[Deprecated]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					msg = [[636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363]],
					digest = [[3f85dc2655c3426a4937d49028c01a066c535ce0]],
					result = [[valid]]
				},
				{
					tcId = 6,
					comment = [[64-byte message. Full block; padding entirely in a new block.]],
					targets = {
						[[BlockBoundary]],
						[[PaddingNewBlock]]
					},
					flags = {
						[[BlockBoundary]],
						[[Deprecated]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					msg = [[41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141]],
					digest = [[30b86e44e6001403827a62c58b08893e77cf121f]],
					result = [[valid]]
				},
				{
					tcId = 7,
					comment = [[1024-byte message (16 full blocks). Sustained compression loop.]],
					targets = {
						[[BlockLoop]]
					},
					flags = {
						[[BlockLoop]],
						[[Deprecated]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					msg = [[a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1]],
					digest = [[a1d98481766c6337a1bea1d8394297177c210628]],
					result = [[valid]]
				},
				{
					tcId = 8,
					comment = [[1-byte message. Bit length is 8, byte length is 1; catches impls that encode bytes instead of bits.]],
					targets = {
						[[LengthEncodingBitsVsBytes]]
					},
					flags = {
						[[LengthEncodingBitsVsBytes]],
						[[Deprecated]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					msg = [[aa]],
					digest = [[52538a80094f7b62948fd31e68fd17a315d8dc91]],
					result = [[valid]]
				},
				{
					tcId = 9,
					comment = [[256-byte message. Bit length 2048 (0x800) occupies the second-from-low byte of the 8-byte BE length field.]],
					targets = {
						[[LengthEncodingEndian]]
					},
					flags = {
						[[LengthEncodingEndian]],
						[[Deprecated]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					msg = [[a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5]],
					digest = [[275f4b7e884caa5e506197efabb5ae295f4263b8]],
					result = [[valid]]
				},
				{
					tcId = 10,
					comment = [[Asymmetric message bytes; nibbles within each byte differ.]],
					targets = {
						[[HexByteOrder]],
						[[HexNibbleOrder]]
					},
					flags = {
						[[Pseudorandom]],
						[[Deprecated]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					msg = [[0123456789abcdeffedcba9876543210]],
					digest = [[76bc87baeca7725c948fd1c53766454fda0867af]],
					result = [[valid]]
				}
			}
		}
	}
}
