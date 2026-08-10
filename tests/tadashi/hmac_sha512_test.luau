--!strict
-- Auto-generated from Tadashi/testvectors/hmac_sha512_test.json
-- Do not edit by hand.

return {
	algorithm = [[HMAC-SHA512]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_mac_v1.json]],
	header = {
		[[HMAC-SHA512 per RFC 2104 + RFC 4231 with bug-catching cases targeting ipad/opad XOR, key-longer-than-block hashing, and underlying-hash multi-block paths.]],
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
			type = [[HmacSha512]],
			tagSize = 512,
			blockSize = 1024,
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
					tag = [[87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854]],
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
					tag = [[164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737]],
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
					tag = [[fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb]],
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
					tag = [[b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd]],
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
					tag = [[415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b]],
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
					tag = [[80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598]],
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
					tag = [[e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58]],
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
					tag = [[b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47]],
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
					key = [[4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242]],
					msg = [[626f756e64617279206b6579]],
					tag = [[138e4a31a6db282340b59cb3e5a354bf29a11b897bbc4dbb9d4196caea883f42cf18fbcb76c8b5c0afe8b6a14a592e0dbe49d3d76f0593ffc5655bd1cadbf79e]],
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
					key = [[434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343]],
					msg = [[6f6e652062797465206f76657220626c6f636b]],
					tag = [[6297c4ac475b1dfc4942b4aeb16b978fddee51090326fa878a5fc2a217328efc992d27ce0de8665576f739cbe8867bd5f040da26253585f6df318b211b975cb9]],
					result = [[valid]]
				},
				{
					tcId = 11,
					comment = [[1024-byte message (8 blocks under SHA-512). Sustained underlying-hash compression loop inside HMAC.]],
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
					tag = [[b5f4dd709d6c49b84aeaf58e170cf01274c04172c38d0605dd3d4ea9dcc35cccb5115b7dd3157b5c523c9f80dcbb1b68fc4662b3bebf28afb0336557cedbef5d]],
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
					tag = [[fd77d0815ddc43ffcccae2ee0bd6ab09e067b876bf284461e21fe72c2eaa8896f54d11807a757f93d04a5dfa7e30345923261fe906af35ebb39a1d101865e8c2]],
					result = [[valid]]
				}
			}
		}
	}
}
