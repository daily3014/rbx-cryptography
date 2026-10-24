--!strict
-- Auto-generated from Tadashi/testvectors/xchacha20_test.json
-- Do not edit by hand.

return {
	algorithm = [[XCHACHA20]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_stream_cipher_v1.json]],
	header = {
		[[XChaCha20 test vectors per draft-irtf-cfrg-xchacha-03, plus bug-catching cases for both HChaCha20 (the subkey-derivation primitive) and the full XChaCha20 stream cipher.]],
		[[Each non-KAT test's targets[] lists the implementation bugs it is designed to catch.]]
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test from an RFC or authoritative draft.]]
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
		}
	},
	numberOfTests = 13,
	testGroups = {
		{
			type = [[HChaCha20]],
			keySize = 256,
			nonceSize = 128,
			subkeySize = 256,
			tests = {
				{
					tcId = 1,
					comment = [[draft-irtf-cfrg-xchacha-03 §2.2.1 canonical HChaCha20 test vector.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[draft-irtf-cfrg-xchacha]],
						version = [[03 §2.2.1]]
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					nonce = [[000000090000004a0000000031415927]],
					subkey = [[82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc]],
					result = [[valid]]
				},
				{
					tcId = 2,
					comment = [[All-zero key, non-zero nonce, exercises that the nonce ends up in state[12..16] and that the correct output words are selected.]],
					targets = {
						[[WordSelection]],
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
					nonce = [[0123456789abcdeffedcba9876543210]],
					subkey = [[3fa5484fa6aeb3100ee1a6dccea791654b9fc0fb9fa47c4de622f552ab8bd129]],
					result = [[valid]]
				},
				{
					tcId = 3,
					comment = [[Non-zero key, all-zero nonce, exercises that the key ends up in state[4..12] and is mixed correctly.]],
					targets = {
						[[WordSelection]],
						[[InitialStateConstants]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[0123456789abcdeffedcba98765432100f1e2d3c4b5a6978a1b2c3d4e5f60718]],
					nonce = [[00000000000000000000000000000000]],
					subkey = [[08a76bcc8000b6dd1c7df964a83ea32476460ad481a9f554fbc054bc93f7b533]],
					result = [[valid]]
				},
				{
					tcId = 4,
					comment = [[Asymmetric key and nonce bytes; nibbles within each byte differ; bytes do not form a palindrome. Catches hex parser nibble-swap or byte-reverse bugs.]],
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
					nonce = [[a1b2c3d4e5f607180123456789abcdef]],
					subkey = [[3282a1e401120d8948ef1379392d03f5fe7bd4b5342d713a3aa3862b868064fe]],
					result = [[valid]]
				}
			}
		},
		{
			type = [[XChaCha20Encrypt]],
			keySize = 256,
			ivSize = 192,
			tests = {
				{
					tcId = 5,
					comment = [[draft-irtf-cfrg-xchacha-03 §A.2 parameters (key 80..9f, nonce 40..57, counter=1) with the 'dhole' plaintext.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[draft-irtf-cfrg-xchacha]],
						version = [[03 §A.2 (parameters)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					key = [[808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f]],
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					counter = 1,
					msg = [[5468652064686f6c65202870726f6e6f756e6365642022646f682d6c75682229206973206173206c6f206b6e6f776e2061732074686520417369617469632077696c6420646f672c207265642064696f672c20616e642077686f6f746820646f672e2049742069732061626f7574207468652073697a65206f66206120476572666d616e207368657068657264202062757420686f6f6b73206f72652020]],
					ct = [[a56416d43f989b369e325fa384c1f33a4729110b6164be88a5d2d860373d2fe12055635d4a1ebf115ef38a2701e4307aa0628a60c45e8431dd8df6231405b44a288c86a406b4db49e5007cfdc4caa0d12c7be96acb781c8d6cb87b617e86f5e525a523608d6363b5238514b902d78b0ea965ea40df751766f5fd9fd20b1e50e520274943550cb9b6eb51b570316fa2cc28eee98f3a47a96ed8b3dda357f6]],
					result = [[valid]]
				},
				{
					tcId = 6,
					comment = [[Empty plaintext, output must also be empty.]],
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
					iv = [[000000000000000000000000000000000000000000000000]],
					counter = 0,
					msg = [[]],
					ct = [[]],
					result = [[valid]]
				},
				{
					tcId = 7,
					comment = [[Plaintext of exactly 64 bytes, single ChaCha20 block downstream of HChaCha20.]],
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
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					counter = 1,
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[d4390570d0e079168ff487beaf9c659292baadc41359539a6a31fd450904239016f9026e55928410ffb2f44c0adadaf19b6b7de86f85b49cb6fc08f413b24c54]],
					result = [[valid]]
				},
				{
					tcId = 8,
					comment = [[Plaintext of 65 bytes, exactly one block plus 1 byte; tests partial-block path post HChaCha20.]],
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
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					counter = 1,
					msg = [[0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[d4390570d0e079168ff487beaf9c659292baadc41359539a6a31fd450904239016f9026e55928410ffb2f44c0adadaf19b6b7de86f85b49cb6fc08f413b24c545a]],
					result = [[valid]]
				},
				{
					tcId = 9,
					comment = [[Plaintext of 128 bytes, two full blocks; verifies block counter increments inside downstream ChaCha20.]],
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
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					counter = 1,
					msg = [[0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[d4390570d0e079168ff487beaf9c659292baadc41359539a6a31fd450904239016f9026e55928410ffb2f44c0adadaf19b6b7de86f85b49cb6fc08f413b24c545a2bf87214b345c88503b0ffdc799ceff6c7062b283d647750a30794c56533252675b7c9b8e56bb6dda1629a4717c98b9ff313de29ca83e00cbf571222c77b9f]],
					result = [[valid]]
				},
				{
					tcId = 10,
					comment = [[Counter starts at 0xfffffffe, 128-byte message; second block computed at counter 0xffffffff post HChaCha20.]],
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
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[404142434445464748494a4b4c4d4e4f5051525354555657]],
					counter = 4294967294,
					msg = [[0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[77d4d08e99e41ad96bbd8e7ce680ee7fa6c9237ed255261edc53e563e219aea4349e55f1e6d7ff5feed06745d3222de312785b42600bbd0d2c7b261d2843b11abb45dd1458eed4719bbb63397a5ff7a24b3c4c63fc2fa264e9ebbe76e147632002064cfc2aa20a371611a0fe4e4a757074276d955d618f53152de490235b562a]],
					result = [[valid]]
				},
				{
					tcId = 11,
					comment = [[All-zero key and 24-byte nonce at counter=0, exercises Sigma constants through HChaCha20 and ChaCha20.]],
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
					iv = [[000000000000000000000000000000000000000000000000]],
					counter = 0,
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[bcd02a18bf3f01d19292de30a7a8fdaca4b65e50a6002cc72cd6d2f7c91ac3d5728f83e0aad2bfcf9abd2d2db58faedd65015dd83fc09b131e271043019e8e0f]],
					result = [[valid]]
				},
				{
					tcId = 12,
					comment = [[Nonce halves are distinct constants (0x11 for bytes 0..15, 0x22 for bytes 16..23); catches impls that take bytes 0..7 instead of 16..23 for the downstream nonce.]],
					targets = {
						[[NonceSplit]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					iv = [[111111111111111111111111111111112222222222222222]],
					counter = 0,
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[489dfdb5b9193b51fccf0f04e81cd853d6713ede05b576e8bedb575cd90b1d40f60f40f5b8cbe829d31fcdeb6c5f48d2fb3ad6afb955bf61041c13edf5c9bc7e]],
					result = [[valid]]
				},
				{
					tcId = 13,
					comment = [[Asymmetric key, iv, counter, and msg bytes. Catches hex parser nibble-swap or byte-reverse bugs anywhere in the runner.]],
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
					counter = 305419896,
					msg = [[0fedcba98765432100112233445566778899aabbccddeeff1eef00ddcc11bbaa]],
					ct = [[7dc651be5798536429fca712db7e67f6e5b0bb468701d420bcc471d540fccfbd]],
					result = [[valid]]
				}
			}
		}
	}
}
