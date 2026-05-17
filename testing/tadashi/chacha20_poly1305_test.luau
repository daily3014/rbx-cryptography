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
		}
	},
	numberOfTests = 15,
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
				}
			}
		}
	}
}
