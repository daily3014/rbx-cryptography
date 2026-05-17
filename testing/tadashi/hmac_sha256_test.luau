--!strict
-- Auto-generated from Tadashi/testvectors/hmac_sha256_test.json
-- Do not edit by hand.

return {
	algorithm = [[HMAC-SHA256]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_mac_v1.json]],
	header = {
		[[HMAC-SHA256 per RFC 2104 + RFC 4231 with bug-catching cases targeting ipad/opad XOR, key-longer-than-block hashing, and underlying-hash multi-block paths.]],
		[[Each non-KAT test's targets[] lists the implementation bugs it is designed to catch.]]
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test from RFC 4231.]]
		},
		EmptyKey = {
			bugType = [[EDGE_CASE]],
			description = [[Zero-length key; HMAC pads it to block size with zeros.]]
		},
		EmptyMessage = {
			bugType = [[EDGE_CASE]],
			description = [[Zero-length message.]]
		},
		KeyShorterThanBlockZeroPads = {
			bugType = [[EDGE_CASE]],
			description = [[Key length less than block size; zero-padded to block size.]]
		},
		KeyExactlyBlockSize = {
			bugType = [[EDGE_CASE]],
			description = [[Key length exactly equal to block size; no padding or hashing required.]]
		},
		KeyLongerThanBlockHashesFirst = {
			bugType = [[MISSING_STEP]],
			description = [[Key length greater than block size; HMAC hashes the key down first, then zero-pads the digest.]],
			effect = [[Bug if impl uses key directly or truncates instead of hashing.]]
		},
		UnderlyingHashMultiBlock = {
			bugType = [[BASIC]],
			description = [[Long message exercises the underlying hash compression loop inside HMAC.]]
		},
		BlockLoop = {
			bugType = [[BASIC]],
			description = [[Long input forces many hash compression iterations.]]
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
			type = [[HmacSha256]],
			tagSize = 256,
			blockSize = 512,
			tests = {
				{
					tcId = 1,
					comment = [[RFC 4231 §4.2 TC1: 20-byte 0x0b key, 'Hi There'.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc4231]],
						version = [[4.2 TC1]]
					},
					key = [[0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b]],
					msg = [[4869205468657265]],
					tag = [[b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7]],
					result = [[valid]]
				},
				{
					tcId = 2,
					comment = [[RFC 4231 §4.3 TC2: short ASCII key 'Jefe', 'what do ya want for nothing?'. Tests short-key zero-pad path.]],
					targets = {
						[[KeyShorterThanBlockZeroPads]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc4231]],
						version = [[4.3 TC2]]
					},
					key = [[4a656665]],
					msg = [[7768617420646f2079612077616e7420666f72206e6f7468696e673f]],
					tag = [[5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843]],
					result = [[valid]]
				},
				{
					tcId = 3,
					comment = [[RFC 4231 §4.4 TC3: 20-byte 0xaa key, 50-byte 0xdd msg. Single-block message with full-pattern key.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc4231]],
						version = [[4.4 TC3]]
					},
					key = [[aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]],
					msg = [[dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd]],
					tag = [[773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe]],
					result = [[valid]]
				},
				{
					tcId = 4,
					comment = [[RFC 4231 §4.5 TC4: 25-byte incremental key, 50-byte 0xcd msg. Asymmetric key bytes catch ordering bugs.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc4231]],
						version = [[4.5 TC4]]
					},
					key = [[0102030405060708090a0b0c0d0e0f10111213141516171819]],
					msg = [[cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd]],
					tag = [[82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b]],
					result = [[valid]]
				},
				{
					tcId = 5,
					comment = [[RFC 4231 §4.6 TC5: 20-byte 0x0c key, 'Test With Truncation'. Full HMAC output (callers may truncate themselves).]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc4231]],
						version = [[4.6 TC5]]
					},
					key = [[0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c]],
					msg = [[546573742057697468205472756e636174696f6e]],
					tag = [[a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5]],
					result = [[valid]]
				},
				{
					tcId = 6,
					comment = [[RFC 4231 §4.7 TC6: 131-byte 0xaa key (longer than 64-byte block), short msg. Key must be hashed down before use.]],
					targets = {
						[[KeyLongerThanBlockHashesFirst]]
					},
					flags = {
						[[Ktv]],
						[[KeyLongerThanBlockHashesFirst]]
					},
					source = {
						name = [[rfc4231]],
						version = [[4.7 TC6]]
					},
					key = [[aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]],
					msg = [[54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374]],
					tag = [[60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54]],
					result = [[valid]]
				},
				{
					tcId = 7,
					comment = [[RFC 4231 §4.8 TC7: 131-byte 0xaa key, multi-block message. Combines key-too-long and multi-block-msg paths.]],
					targets = {
						[[KeyLongerThanBlockHashesFirst]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc4231]],
						version = [[4.8 TC7]]
					},
					key = [[aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]],
					msg = [[5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e]],
					tag = [[9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2]],
					result = [[valid]]
				},
				{
					tcId = 8,
					comment = [[Empty key, empty message. Zero-length key is zero-padded to block size (= 64 zero bytes), ipad/opad XORed against it.]],
					targets = {
						[[EmptyKey]],
						[[EmptyMessage]]
					},
					flags = {
						[[EmptyKey]],
						[[EmptyMessage]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					key = [[]],
					msg = [[]],
					tag = [[b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad]],
					result = [[valid]]
				},
				{
					tcId = 9,
					comment = [[Key length exactly equal to block size (64 bytes). No hashing of key, no zero-padding.]],
					targets = {
						[[KeyExactlyBlockSize]]
					},
					flags = {
						[[KeyExactlyBlockSize]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					key = [[42424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242]],
					msg = [[626f756e64617279206b6579]],
					tag = [[fa31140dae0cf8033212d76f620d2dd849b7a2f54831fa64dc9758d9d5787f2f]],
					result = [[valid]]
				},
				{
					tcId = 10,
					comment = [[Key length block_size+1 (65 bytes). Bug if impl uses key directly without hashing.]],
					targets = {
						[[KeyLongerThanBlockHashesFirst]]
					},
					flags = {
						[[KeyLongerThanBlockHashesFirst]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					key = [[4343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343]],
					msg = [[6f6e652062797465206f76657220626c6f636b]],
					tag = [[fd36b232914dc1f375953e7c4c0bc1e5c13b3a6d071e2ee3026a6159b6c49cbf]],
					result = [[valid]]
				},
				{
					tcId = 11,
					comment = [[1024-byte message (16 blocks under SHA-256). Sustained underlying-hash compression loop inside HMAC.]],
					targets = {
						[[UnderlyingHashMultiBlock]]
					},
					flags = {
						[[BlockLoop]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[node:crypto]]
						}
					},
					key = [[7374616e646172642d6b6579]],
					msg = [[a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1]],
					tag = [[8a565e2c2a049214e29e6bca656bdc19315b8ec3de0dcfd8f4cbd95873f77e73]],
					result = [[valid]]
				},
				{
					tcId = 12,
					comment = [[Asymmetric key and message bytes; nibbles within each byte differ.]],
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
							[[node:crypto]]
						}
					},
					key = [[0123456789abcdeffedcba9876543210]],
					msg = [[0fedcba98765432100112233445566778899aabbccddeeff]],
					tag = [[fe3e9c6e8259f262ba1755c469c1ab0a1094dcfaadd04e3371bf3e6766d47e60]],
					result = [[valid]]
				}
			}
		}
	}
}
