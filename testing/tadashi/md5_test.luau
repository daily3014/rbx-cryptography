--!strict
-- Auto-generated from Tadashi/testvectors/md5_test.json
-- Do not edit by hand.

return {
	algorithm = [[MD5]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_hash_v1.json]],
	header = {
		[[MD5 per RFC 1321. DEPRECATED for new security uses (cryptographically broken since 2004 (Wang collision attacks)); covered here for legacy compatibility only.]],
		[[Tests cover the RFC 1321 KATs plus padding boundaries and length-encoding edges (shared with SHA-256 since both use a 64-byte block and 8-byte BE length field).]]
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test from RFC 1321.]]
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
			type = [[Md5Digest]],
			digestSize = 128,
			blockSize = 512,
			tests = {
				{
					tcId = 1,
					comment = [[RFC 1321 Appendix A empty message. Tests IV constants and pure-padding compression.]],
					targets = {
						[[EmptyMessage]]
					},
					flags = {
						[[Ktv]],
						[[EmptyMessage]],
						[[Deprecated]]
					},
					source = {
						name = [[rfc1321]],
						version = [[Appendix A]]
					},
					msg = [[]],
					digest = [[d41d8cd98f00b204e9800998ecf8427e]],
					result = [[valid]]
				},
				{
					tcId = 2,
					comment = [[RFC 1321 Appendix A 'abc'. Standard short single-block KAT.]],
					targets = {},
					flags = {
						[[Ktv]],
						[[Deprecated]]
					},
					source = {
						name = [[rfc1321]],
						version = [[Appendix A]]
					},
					msg = [[616263]],
					digest = [[900150983cd24fb0d6963f7d28e17f72]],
					result = [[valid]]
				},
				{
					tcId = 3,
					comment = [[56-byte two-block test. Padding spills because 56 + 1 + 8 = 65 > 64.]],
					targets = {
						[[PaddingNewBlock]]
					},
					flags = {
						[[Ktv]],
						[[PaddingNewBlock]],
						[[Deprecated]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					msg = [[6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071]],
					digest = [[8215ef0796a20bcaaae116d3876c664a]],
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
					digest = [[792cade9332b53fbc239c45f1c4bb697]],
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
					digest = [[bc1cbc032f9b2a1fa2ae54f8576beb7e]],
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
					digest = [[d289a97565bc2d27ac8b8545a5ddba45]],
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
					digest = [[2293e692b02454403038690ad34ebaaa]],
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
					digest = [[9fe0f7244a7da1d3f5b3d21f9b1e1ea8]],
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
					digest = [[5259d466b53d300cd9bb69f9a3c1af36]],
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
					digest = [[054de9cf5f9ea623bbb8dc4781685a58]],
					result = [[valid]]
				}
			}
		}
	}
}
