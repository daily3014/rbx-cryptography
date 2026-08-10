--!strict
-- Auto-generated from Tadashi/testvectors/ed25519_test.json
-- Do not edit by hand.

return {
	algorithm = [[ED25519]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_eddsa_v1.json]],
	header = {
		[[Ed25519 per RFC 8032 with bug-catching cases beyond Wycheproof: public-key-derivation KATs, S-range boundary tests, the strict-form top-3-bits-of-S check, non-canonical y encodings, small-order public-key rejection, and deterministic-signing assertions.]],
		[[Each non-KAT test's targets[] lists the implementation bugs it is designed to catch.]],
		[[Tests with non-empty sk also assert: PublicKey(sk) == pk AND Sign(sk, msg) == sig. Verify-only tests have empty sk.]]
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test from RFC 8032 §7.1.]]
		},
		KeyDerivation = {
			bugType = [[MISSING_STEP]],
			description = [[PublicKey(SK) = encode(MulG(clamp(SHA-512(SK)[0..32]))); tests the full derivation chain.]]
		},
		ScalarClamping = {
			bugType = [[MISSING_STEP]],
			description = [[Scalar clamping clears bits 0-2 of byte 0 and clears bit 7 / sets bit 6 of byte 31.]]
		},
		SignDeterministic = {
			bugType = [[BASIC]],
			description = [[Ed25519 signing is deterministic; the same (sk, msg) must produce the same sig.]]
		},
		LongMessage = {
			bugType = [[EDGE_CASE]],
			description = [[Message spans many SHA-512 blocks; exercises multi-block paths in both the nonce hash and the challenge hash.]]
		},
		MessageBlockBoundary = {
			bugType = [[EDGE_CASE]],
			description = [[Message length chosen so that the nonce-hash or challenge-hash input lands at a SHA-512 block boundary.]]
		},
		ZeroInput = {
			bugType = [[EDGE_CASE]],
			description = [[All-zero secret key; catches impls that special-case zero inputs.]]
		},
		ScalarSRange = {
			bugType = [[AUTH_BYPASS]],
			description = [[S must be in [0, L) per RFC 8032 §5.1.7 step 1.]],
			effect = [[Bug if impl skips range check or uses S mod L.]]
		},
		SHighBits = {
			bugType = [[AUTH_BYPASS]],
			description = [[Top 3 bits of S byte 31 must be zero since S < L < 2^253.]],
			effect = [[Some impls fast-fail on the 0xE0 mask before computing the full range check.]]
		},
		NonCanonicalY = {
			bugType = [[AUTH_BYPASS]],
			description = [[Point encoding with y >= p (= 2^255 - 19) is non-canonical and must be rejected.]]
		},
		SmallOrderPK = {
			bugType = [[AUTH_BYPASS]],
			description = [[Public key encodes a small-order point (order 1, 2, 4, or 8); strict impls reject these.]]
		},
		SmallOrderR = {
			bugType = [[AUTH_BYPASS]],
			description = [[Signature R component is a small-order point.]]
		},
		MessageBitFlip = {
			bugType = [[AUTH_BYPASS]],
			description = [[Message bit modified; sig must not verify.]]
		},
		PKBitFlip = {
			bugType = [[AUTH_BYPASS]],
			description = [[Public key bit modified; sig must not verify.]]
		},
		SBitFlip = {
			bugType = [[AUTH_BYPASS]],
			description = [[S bit modified; sig must not verify.]]
		},
		RBitFlip = {
			bugType = [[AUTH_BYPASS]],
			description = [[R bit modified; sig must not verify.]]
		},
		BitFlip = {
			bugType = [[AUTH_BYPASS]],
			description = [[A single bit was modified somewhere in the (pk, msg, sig) triple.]]
		},
		PKMismatch = {
			bugType = [[AUTH_BYPASS]],
			description = [[Signature was produced under a different secret key than the public key being checked against.]]
		},
		WrongMessage = {
			bugType = [[AUTH_BYPASS]],
			description = [[Signature is well-formed and matches the public key, but is bound to a different message.]]
		},
		CrossKey = {
			bugType = [[AUTH_BYPASS]],
			description = [[Cross-key forgery attempt.]]
		},
		PointNotOnCurve = {
			bugType = [[AUTH_BYPASS]],
			description = [[Encoded y-coordinate yields a non-square x^2 = (y^2 - 1) / (d*y^2 + 1); the encoded point does not exist on Edwards25519.]]
		},
		PKSignBitFlip = {
			bugType = [[AUTH_BYPASS]],
			description = [[Public-key sign-of-x bit (bit 255) flipped from canonical; encodes the negation of the original point.]]
		},
		RSignBitFlip = {
			bugType = [[AUTH_BYPASS]],
			description = [[R sign-of-x bit (bit 255) flipped from canonical.]]
		},
		RSSwapped = {
			bugType = [[AUTH_BYPASS]],
			description = [[Signature halves R and S swapped.]]
		},
		Structural = {
			bugType = [[AUTH_BYPASS]],
			description = [[Sig is malformed at the structural level rather than at a per-byte level.]]
		},
		CofactorVerification = {
			bugType = [[SPEC_AMBIGUOUS]],
			description = [[Tests whether the verifier multiplies by the cofactor (8) before the zero-check, exposing the ZIP-215 / LIBSODIUM / strict flavor distinction.]],
			effect = [[Different Ed25519 flavors (LIBSODIUM-strict, ed25519-dalek, ZIP-215) give different verdicts. rbx-crypto matches ZIP-215.]]
		},
		SpecCheck = {
			bugType = [[SPEC_AMBIGUOUS]],
			description = [[Test vector from the Chalkias-Garillot-Kondi speccheck suite (github.com/novifinancial/ed25519-speccheck), designed to expose disagreements between Ed25519 implementations.]]
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
		VerifierArithmeticOverflow = {
			bugType = [[KNOWN_BUG]],
			description = [[Valid signature whose R/S values triggered an arithmetic overflow in a production verifier (Tink). Regression vectors for verifier limb arithmetic.]],
			effect = [[A verifier with the same overflow rejects a valid signature.]]
		},
		RSEdgeValues = {
			bugType = [[EDGE_CASE]],
			description = [[r or s set to an algebraic edge value (0, 1, L-1, L, p, ...); the verification equation degenerates and must be rejected by the range/decode checks.]]
		},
		SignatureLength = {
			bugType = [[MISSING_STEP]],
			description = [[Signature with a malformed length (empty, truncated, extended, garbage appended); must be rejected before any algebra.]],
			effect = [[Length-tolerant parsers admit malleable or forged encodings.]]
		}
	},
	numberOfTests = 62,
	testGroups = {
		{
			type = [[Ed25519]],
			keySize = 256,
			tests = {
				{
					tcId = 1,
					comment = [[RFC 8032 §7.1 Test 1: empty message. Smallest possible signing input; tests PK derivation, deterministic nonce derivation, and signing on zero-length data.]],
					targets = {
						[[KeyDerivation]],
						[[SignDeterministic]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8032]],
						version = [[7.1 Test 1]]
					},
					sk = [[9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[valid]]
				},
				{
					tcId = 2,
					comment = [[RFC 8032 §7.1 Test 2: 1-byte message 0x72.]],
					targets = {
						[[KeyDerivation]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8032]],
						version = [[7.1 Test 2]]
					},
					sk = [[4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb]],
					pk = [[3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c]],
					msg = [[72]],
					sig = [[92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00]],
					result = [[valid]]
				},
				{
					tcId = 3,
					comment = [[RFC 8032 §7.1 Test 3: 2-byte message.]],
					targets = {
						[[KeyDerivation]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8032]],
						version = [[7.1 Test 3]]
					},
					sk = [[c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7]],
					pk = [[fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025]],
					msg = [[af82]],
					sig = [[6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a]],
					result = [[valid]]
				},
				{
					tcId = 4,
					comment = [[RFC 8032 §7.1 Test 1024: 1023-byte message. Long-message KAT exercises multi-block SHA-512 inside both nonce and challenge hashes.]],
					targets = {
						[[KeyDerivation]],
						[[LongMessage]]
					},
					flags = {
						[[Ktv]],
						[[LongMessage]]
					},
					source = {
						name = [[rfc8032]],
						version = [[7.1 Test 1024]]
					},
					sk = [[f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5]],
					pk = [[278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e]],
					msg = [[08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0]],
					sig = [[0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03]],
					result = [[valid]]
				},
				{
					tcId = 5,
					comment = [[RFC 8032 §7.1 TEST SHA(abc): 64-byte message = SHA-512('abc'). Bonus: challenge-hash input is 32+32+64 = 128 bytes (exactly one SHA-512 block boundary).]],
					targets = {
						[[KeyDerivation]],
						[[MessageBlockBoundary]]
					},
					flags = {
						[[Ktv]],
						[[MessageBlockBoundary]]
					},
					source = {
						name = [[rfc8032]],
						version = [[7.1 TEST SHA(abc)]]
					},
					sk = [[833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42]],
					pk = [[ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf]],
					msg = [[ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f]],
					sig = [[dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704]],
					result = [[valid]]
				},
				{
					tcId = 6,
					comment = [[32-byte message. Nonce-hash input = 32-byte secondHalf(SHA-512(sk)) || 32-byte msg = 64 bytes (exactly one SHA-512 block); catches SHA-512 padding bugs at block boundaries inside Ed25519's nonce-derivation step.]],
					targets = {
						[[MessageBlockBoundary]]
					},
					flags = {
						[[MessageBlockBoundary]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[4444444444444444444444444444444444444444444444444444444444444444]],
					sig = [[de4d83a97fcf621290fecbe69858efc3801986c245adfbb2c9bcc58c647e7d8278079ab70e83b5d4e5d8a85a975db7c200704c8afee1e4810165c55008ca580c]],
					result = [[valid]]
				},
				{
					tcId = 7,
					comment = [[Key derivation with all-zero SK. SHA-512 of zero produces a specific clamped scalar; tests the full KeyDerivation chain on a corner-case input.]],
					targets = {
						[[KeyDerivation]],
						[[ZeroInput]]
					},
					flags = {
						[[KeyDerivation]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[0000000000000000000000000000000000000000000000000000000000000000]],
					pk = [[3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29]],
					msg = [[00]],
					sig = [[1b9da904f12708363c88d4b96b33b474b2a5a863e290be2be5d4cacef8a5cbac1c0132c3e20e477d7affd1491be6577e8b83af012773beaf51c6df3f4af95b0e]],
					result = [[valid]]
				},
				{
					tcId = 8,
					comment = [[Key derivation with all-0xff SK. SHA-512 then clamping; the clamping must clear bits 0-2 of byte 0 and clear bit 7 and set bit 6 of byte 31.]],
					targets = {
						[[KeyDerivation]],
						[[ScalarClamping]]
					},
					flags = {
						[[KeyDerivation]],
						[[ScalarClamping]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					pk = [[76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5]],
					msg = [[ff]],
					sig = [[00cbd1e6c44d44e79263ba18f5c61a3d35a445a0a9fc1fddd82ed4aa51b774b23db7a144f75a6034eb8c48f1f0162e4c9862b14efc3dd22d68375849247f9108]],
					result = [[valid]]
				},
				{
					tcId = 9,
					comment = [[128-byte message (2 SHA-512 blocks for the nonce and challenge hashes).]],
					targets = {
						[[MessageBlockBoundary]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5]],
					sig = [[b371bb791ad0c96835f8a93555df82f112546269d7d042c8bac9639a26404792f9377ecd376d870f87fcd83b8ea30a22c9361802548e4811dcdcc4c90ea8a90d]],
					result = [[valid]]
				},
				{
					tcId = 10,
					comment = [[S = L (group order). Per RFC 8032 §5.1.7, S must be strictly less than L; this signature must be rejected.]],
					targets = {
						[[ScalarSRange]]
					},
					flags = {
						[[ScalarSRange]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010]],
					result = [[invalid]]
				},
				{
					tcId = 11,
					comment = [[S = L + 1. Just past the boundary; must be rejected.]],
					targets = {
						[[ScalarSRange]]
					},
					flags = {
						[[ScalarSRange]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010]],
					result = [[invalid]]
				},
				{
					tcId = 12,
					comment = [[S replaced with L-1 (largest representable value still < L). The signature is no longer valid for this (msg, R) pair, but the value is in-range; rejection is on cryptographic verification, not on the range check.]],
					targets = {
						[[ScalarSRange]]
					},
					flags = {
						[[ScalarSRange]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010]],
					result = [[invalid]]
				},
				{
					tcId = 13,
					comment = [[S = 0 with the original R. In-range (0 < L) but breaks the verification equation; must be rejected on cryptographic grounds.]],
					targets = {
						[[ScalarSRange]]
					},
					flags = {
						[[ScalarSRange]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901550000000000000000000000000000000000000000000000000000000000000000]],
					result = [[invalid]]
				},
				{
					tcId = 14,
					comment = [[Bit 5 of S byte 31 set (= 0x20 mask). Top 3 bits of S must be zero since S < L < 2^253; this catches the bit-5 case of the strict-form check.]],
					targets = {
						[[SHighBits]]
					},
					flags = {
						[[SHighBits]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a102b]],
					result = [[invalid]]
				},
				{
					tcId = 15,
					comment = [[Bit 6 of S byte 31 set (= 0x40 mask). Top 3 bits must be zero.]],
					targets = {
						[[SHighBits]]
					},
					flags = {
						[[SHighBits]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a104b]],
					result = [[invalid]]
				},
				{
					tcId = 16,
					comment = [[Bit 7 of S byte 31 set (= 0x80 mask). Top 3 bits must be zero.]],
					targets = {
						[[SHighBits]]
					},
					flags = {
						[[SHighBits]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a108b]],
					result = [[invalid]]
				},
				{
					tcId = 17,
					comment = [[Public key y >= p (non-canonical). PK encodes y = p (2^255 - 19); some impls reject, some reduce mod p. rbx-crypto rejects.]],
					targets = {
						[[NonCanonicalY]]
					},
					flags = {
						[[NonCanonicalY]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 18,
					comment = [[Public key all zero (encodes y=0, x=±sqrt(-1), a small-order point of order 4). Strict impls reject small-order public keys.]],
					targets = {
						[[SmallOrderPK]]
					},
					flags = {
						[[SmallOrderPK]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[0000000000000000000000000000000000000000000000000000000000000000]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 19,
					comment = [[Public key encodes the identity element (y=1, x=0): byte 0 = 0x01, rest zero. Identity point cannot verify any real signature.]],
					targets = {
						[[SmallOrderPK]]
					},
					flags = {
						[[SmallOrderPK]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[0100000000000000000000000000000000000000000000000000000000000000]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 20,
					comment = [[R encodes y >= p (non-canonical). Must be rejected.]],
					targets = {
						[[NonCanonicalY]]
					},
					flags = {
						[[NonCanonicalY]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 21,
					comment = [[Original Test 1 signature with bit 0 of message flipped. msg changes from empty to 1-byte 0x01.]],
					targets = {
						[[MessageBitFlip]]
					},
					flags = {
						[[BitFlip]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[01]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 22,
					comment = [[Bit 0 of public key flipped, signature and msg unchanged. Different PK does not verify the original sig.]],
					targets = {
						[[PKBitFlip]]
					},
					flags = {
						[[BitFlip]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d65a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 23,
					comment = [[Bit 0 of S flipped (LSB), R and PK unchanged.]],
					targets = {
						[[SBitFlip]]
					},
					flags = {
						[[BitFlip]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555eb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 24,
					comment = [[Bit 0 of R flipped (LSB), S and PK unchanged.]],
					targets = {
						[[RBitFlip]]
					},
					flags = {
						[[BitFlip]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[e4564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 25,
					comment = [[Bit 120 of R flipped (middle of R). Catches comparators or hash inputs that only look at the low or high bytes of R.]],
					targets = {
						[[RBitFlip]]
					},
					flags = {
						[[BitFlip]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828b84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 26,
					comment = [[Bit 120 of S flipped (middle byte of S, sig offset 47, bit 0 of byte 47).]],
					targets = {
						[[SBitFlip]]
					},
					flags = {
						[[BitFlip]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46ad25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 27,
					comment = [[Sig from RFC Test 2 (sk2, msg=0x72), verified against pk1 from RFC Test 1. PK and signing key mismatch; must reject.]],
					targets = {
						[[PKMismatch]]
					},
					flags = {
						[[CrossKey]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[72]],
					sig = [[92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00]],
					result = [[invalid]]
				},
				{
					tcId = 28,
					comment = [[Test 1 sig (over empty msg) verified against a different message. Sig is well-formed and PK matches, but msg differs from what was signed.]],
					targets = {
						[[WrongMessage]]
					},
					flags = {
						[[WrongMessage]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[0102030405]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 29,
					comment = [[Public key = order-2 point on Edwards25519: y = p-1 (= -1 mod p), x = 0. Encoded with sign-of-x bit = 0. Strict impls reject small-order public keys.]],
					targets = {
						[[SmallOrderPK]]
					},
					flags = {
						[[SmallOrderPK]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 30,
					comment = [[R = identity point (encoded 0x01 || zeros). With most S values the verification equation fails; here using original S so the test asserts rejection.]],
					targets = {
						[[SmallOrderR]]
					},
					flags = {
						[[SmallOrderR]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[01000000000000000000000000000000000000000000000000000000000000005fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 31,
					comment = [[R = order-2 point (y = p-1, x = 0; encoded with sign-of-x bit = 0). The signature must be rejected because R is small-order and the verification equation does not hold for the original S.]],
					targets = {
						[[SmallOrderR]]
					},
					flags = {
						[[SmallOrderR]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 32,
					comment = [[Public key encodes y = 2, which is famously not on Edwards25519 (the equation x^2 = (y^2 - 1) / (d*y^2 + 1) yields a non-square at y=2). Decode must return failure.]],
					targets = {
						[[PointNotOnCurve]]
					},
					flags = {
						[[PointNotOnCurve]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[0200000000000000000000000000000000000000000000000000000000000000]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 33,
					comment = [[R encodes y = 2, not on the curve. Decode of R must fail.]],
					targets = {
						[[PointNotOnCurve]]
					},
					flags = {
						[[PointNotOnCurve]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[02000000000000000000000000000000000000000000000000000000000000005fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 34,
					comment = [[Public key with bit 255 (sign-of-x bit) flipped relative to the canonical pk1. The encoded point becomes the negation; verifies only as a different public key.]],
					targets = {
						[[PKSignBitFlip]]
					},
					flags = {
						[[BitFlip]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707519a]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 35,
					comment = [[R with bit 255 (sign-of-x bit) flipped. R now encodes the negation of the original commitment point.]],
					targets = {
						[[RSignBitFlip]]
					},
					flags = {
						[[BitFlip]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901d55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b]],
					result = [[invalid]]
				},
				{
					tcId = 36,
					comment = [[Signature with R and S halves swapped (sig = S || R instead of R || S). Catches impls that read the halves in the wrong order or that don't enforce positional semantics.]],
					targets = {
						[[RSSwapped]]
					},
					flags = {
						[[Structural]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					sk = [[]],
					pk = [[d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a]],
					msg = [[]],
					sig = [[5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100be5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155]],
					result = [[invalid]]
				},
				{
					tcId = 37,
					comment = [[Deterministic signing: re-signing the same message with the same SK must produce the identical sig. The generator runs Sign once and locks the output; downstream impls should match exactly.]],
					targets = {
						[[SignDeterministic]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20]],
					pk = [[79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664]],
					msg = [[54616461736869]],
					sig = [[14ef763f0948b51af3dcccee243eb1ad137ddfbf9ce79751b7bbed58fa4f9e00b89e76a03eb34ecc68f1fbfc96d49268afa503b0935b790b91bf390352c37e0e]],
					result = [[valid]]
				},
				{
					tcId = 38,
					comment = [[Speccheck vector 0 (Chalkias et al. "Taming the many EdDSAs"). rbx-crypto verdict: valid. This case exposes spec ambiguity; LIBSODIUM-strict or other flavors may give a different verdict.]],
					targets = {
						[[CofactorVerification]],
						[[SmallOrderPK]],
						[[SmallOrderR]]
					},
					flags = {
						[[SpecCheck]]
					},
					source = {
						name = [[ed25519-speccheck]],
						version = [[vector 0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[]],
					pk = [[c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa]],
					msg = [[8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6]],
					sig = [[c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000]],
					result = [[valid]]
				},
				{
					tcId = 39,
					comment = [[Speccheck vector 1 (Chalkias et al. "Taming the many EdDSAs"). rbx-crypto verdict: valid. This case exposes spec ambiguity; LIBSODIUM-strict or other flavors may give a different verdict.]],
					targets = {
						[[CofactorVerification]],
						[[SmallOrderPK]]
					},
					flags = {
						[[SpecCheck]]
					},
					source = {
						name = [[ed25519-speccheck]],
						version = [[vector 1]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[]],
					pk = [[c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa]],
					msg = [[9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79]],
					sig = [[f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04]],
					result = [[valid]]
				},
				{
					tcId = 40,
					comment = [[Speccheck vector 2 (Chalkias et al. "Taming the many EdDSAs"). rbx-crypto verdict: valid. This case exposes spec ambiguity; LIBSODIUM-strict or other flavors may give a different verdict.]],
					targets = {
						[[CofactorVerification]],
						[[SmallOrderR]]
					},
					flags = {
						[[SpecCheck]]
					},
					source = {
						name = [[ed25519-speccheck]],
						version = [[vector 2]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[]],
					pk = [[f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43]],
					msg = [[aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab]],
					sig = [[c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e]],
					result = [[valid]]
				},
				{
					tcId = 41,
					comment = [[Speccheck vector 3 (Chalkias et al. "Taming the many EdDSAs"). rbx-crypto verdict: valid. This case exposes spec ambiguity; LIBSODIUM-strict or other flavors may give a different verdict.]],
					targets = {
						[[CofactorVerification]]
					},
					flags = {
						[[SpecCheck]]
					},
					source = {
						name = [[ed25519-speccheck]],
						version = [[vector 3]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[]],
					pk = [[cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d]],
					msg = [[9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79]],
					sig = [[9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009]],
					result = [[valid]]
				},
				{
					tcId = 42,
					comment = [[Speccheck vector 4 (Chalkias et al. "Taming the many EdDSAs"). rbx-crypto verdict: valid. This case exposes spec ambiguity; LIBSODIUM-strict or other flavors may give a different verdict.]],
					targets = {
						[[CofactorVerification]]
					},
					flags = {
						[[SpecCheck]]
					},
					source = {
						name = [[ed25519-speccheck]],
						version = [[vector 4]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[]],
					pk = [[cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d]],
					msg = [[e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c]],
					sig = [[160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09]],
					result = [[valid]]
				},
				{
					tcId = 43,
					comment = [[Speccheck vector 5 (Chalkias et al. "Taming the many EdDSAs"). rbx-crypto verdict: valid. This case exposes spec ambiguity; LIBSODIUM-strict or other flavors may give a different verdict.]],
					targets = {
						[[CofactorVerification]]
					},
					flags = {
						[[SpecCheck]]
					},
					source = {
						name = [[ed25519-speccheck]],
						version = [[vector 5]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[]],
					pk = [[cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d]],
					msg = [[e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c]],
					sig = [[21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405]],
					result = [[valid]]
				},
				{
					tcId = 44,
					comment = [[Speccheck vector 6 (Chalkias et al. "Taming the many EdDSAs"). rbx-crypto verdict: invalid. This case exposes spec ambiguity; LIBSODIUM-strict or other flavors may give a different verdict.]],
					targets = {
						[[CofactorVerification]]
					},
					flags = {
						[[SpecCheck]]
					},
					source = {
						name = [[ed25519-speccheck]],
						version = [[vector 6]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[]],
					pk = [[442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623]],
					msg = [[85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40]],
					sig = [[e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514]],
					result = [[invalid]]
				},
				{
					tcId = 45,
					comment = [[Speccheck vector 7 (Chalkias et al. "Taming the many EdDSAs"). rbx-crypto verdict: invalid. This case exposes spec ambiguity; LIBSODIUM-strict or other flavors may give a different verdict.]],
					targets = {
						[[CofactorVerification]]
					},
					flags = {
						[[SpecCheck]]
					},
					source = {
						name = [[ed25519-speccheck]],
						version = [[vector 7]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[]],
					pk = [[442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623]],
					msg = [[85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40]],
					sig = [[8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22]],
					result = [[invalid]]
				},
				{
					tcId = 46,
					comment = [[Speccheck vector 8 (Chalkias et al. "Taming the many EdDSAs"). rbx-crypto verdict: invalid. This case exposes spec ambiguity; LIBSODIUM-strict or other flavors may give a different verdict.]],
					targets = {
						[[NonCanonicalY]],
						[[CofactorVerification]]
					},
					flags = {
						[[SpecCheck]]
					},
					source = {
						name = [[ed25519-speccheck]],
						version = [[vector 8]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[]],
					pk = [[f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43]],
					msg = [[9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41]],
					sig = [[ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f]],
					result = [[invalid]]
				},
				{
					tcId = 47,
					comment = [[Speccheck vector 9 (Chalkias et al. "Taming the many EdDSAs"). rbx-crypto verdict: valid. This case exposes spec ambiguity; LIBSODIUM-strict or other flavors may give a different verdict.]],
					targets = {
						[[NonCanonicalY]],
						[[CofactorVerification]]
					},
					flags = {
						[[SpecCheck]]
					},
					source = {
						name = [[ed25519-speccheck]],
						version = [[vector 9]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[]],
					pk = [[f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43]],
					msg = [[9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41]],
					sig = [[ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908]],
					result = [[valid]]
				},
				{
					tcId = 48,
					comment = [[Speccheck vector 10 (Chalkias et al. "Taming the many EdDSAs"). rbx-crypto verdict: valid. This case exposes spec ambiguity; LIBSODIUM-strict or other flavors may give a different verdict.]],
					targets = {
						[[NonCanonicalY]],
						[[CofactorVerification]]
					},
					flags = {
						[[SpecCheck]]
					},
					source = {
						name = [[ed25519-speccheck]],
						version = [[vector 10]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[]],
					pk = [[ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					msg = [[e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b]],
					sig = [[a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04]],
					result = [[valid]]
				},
				{
					tcId = 49,
					comment = [[Speccheck vector 11 (Chalkias et al. "Taming the many EdDSAs"). rbx-crypto verdict: valid. This case exposes spec ambiguity; LIBSODIUM-strict or other flavors may give a different verdict.]],
					targets = {
						[[NonCanonicalY]],
						[[CofactorVerification]]
					},
					flags = {
						[[SpecCheck]]
					},
					source = {
						name = [[ed25519-speccheck]],
						version = [[vector 11]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[]],
					pk = [[ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					msg = [[39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f]],
					sig = [[a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04]],
					result = [[valid]]
				},
				{
					tcId = 50,
					comment = [[Asymmetric SK, msg bytes; nibbles within each byte differ. Catches hex parser nibble-swap or byte-reverse bugs.]],
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
							[[@noble/curves]]
						}
					},
					sk = [[0123456789abcdeffedcba98765432100f1e2d3c4b5a6978a1b2c3d4e5f60718]],
					pk = [[274457faaf07e7beef122995f7a6853692c1965b8e7555448b3b0b6f16c31206]],
					msg = [[0fedcba98765432100112233445566778899aabbccddeeff1eef00ddcc11bbaa]],
					sig = [[4217315e85df602c99b801b322c764e75f28bd91b402ecf91464dd6aa9605b756cbfecb1b6a715cbd26e2fcebab6a8bfe196419a448cefda766ce3afda5ac90c]],
					result = [[valid]]
				},
				{
					tcId = 51,
					comment = [[Imported from Wycheproof v1 eddsa: ed25519_test.json tcId 37: appending 0 byte to signature.]],
					targets = {
						[[SignatureLength]]
					},
					flags = {
						[[SignatureWithGarbage]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					pk = [[7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa]],
					msg = [[54657374]],
					sig = [[7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b30d00]],
					result = [[invalid]]
				},
				{
					tcId = 52,
					comment = [[Imported from Wycheproof v1 eddsa: ed25519_test.json tcId 63: checking malleability .]],
					targets = {
						[[ScalarSRange]]
					},
					flags = {
						[[SignatureMalleability]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					pk = [[7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa]],
					msg = [[54657374]],
					sig = [[7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab067654bce3832c2d76f8f6f5dafc08d9339d4eef676573336a5c51eb6f946b31d]],
					result = [[invalid]]
				},
				{
					tcId = 53,
					comment = [[Imported from Wycheproof v1 eddsa: ed25519_test.json tcId 67: checking malleability .]],
					targets = {
						[[ScalarSRange]]
					},
					flags = {
						[[SignatureMalleability]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					pk = [[7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa]],
					msg = [[54657374]],
					sig = [[7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b32d]],
					result = [[invalid]]
				},
				{
					tcId = 54,
					comment = [[Imported from Wycheproof v1 eddsa: ed25519_test.json tcId 30: empty signature.]],
					targets = {
						[[SignatureLength]]
					},
					flags = {
						[[TruncatedSignature]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					pk = [[7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa]],
					msg = [[54657374]],
					sig = [[]],
					result = [[invalid]]
				},
				{
					tcId = 55,
					comment = [[Imported from Wycheproof v1 eddsa: ed25519_test.json tcId 119: regression test for arithmetic error.]],
					targets = {
						[[VerifierArithmeticOverflow]]
					},
					flags = {
						[[TinkOverflow]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					pk = [[4abfb535313705a6570018440cdec1a3ae33e51f352112fa6acbd0c6bc3ea859]],
					msg = [[321b5f663c19e30ee7bbb85e48ecf44db9d3f512]],
					sig = [[f296715e855d8aecccba782b670163dedc4458fe4eb509a856bcac450920fd2e95a3a3eb212d2d9ccaf948c39ae46a2548af125f8e2ad9b77bd18f92d59f9200]],
					result = [[valid]]
				},
				{
					tcId = 56,
					comment = [[Imported from Wycheproof v1 eddsa: ed25519_test.json tcId 135: regression test for arithmetic error.]],
					targets = {
						[[VerifierArithmeticOverflow]]
					},
					flags = {
						[[TinkOverflow]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					pk = [[e1e7316d231f7f275bdf403360304da1509fdf1af1fd25ca214eaac0a289398f]],
					msg = [[3c87b3453277b353941591fc7eaa7dd37604b42a]],
					sig = [[1c8fbda3d39e2b441f06da6071c13115cb4115c7c3341704cf6513324d4cf1ef4a1dd7678a048b0dde84e48994d080befcd70854079d44b6a0b0f9fa002d130c]],
					result = [[valid]]
				},
				{
					tcId = 57,
					comment = [[Imported from Wycheproof v1 eddsa: ed25519_test.json tcId 150: regression test for arithmetic error.]],
					targets = {
						[[VerifierArithmeticOverflow]]
					},
					flags = {
						[[TinkOverflow]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					pk = [[ccbe7cb2e4bc215cee2f885e1d22f7e0d582b2bbbd782c104e548b152d26fc69]],
					msg = [[44530b0b34f598767a7b875b0caee3c7b9c502d1]],
					sig = [[cfbd450a2c83cb8436c348822fe3ee347d4ee937b7f2ea11ed755cc52852407c9eec2c1fa30d2f9aef90e89b2cc3bcef2b1b9ca59f712110d19894a9cf6a2802]],
					result = [[valid]]
				},
				{
					tcId = 58,
					comment = [[Imported from Wycheproof v1 eddsa: ed25519_test.json tcId 33: signature too long.]],
					targets = {
						[[SignatureLength]]
					},
					flags = {
						[[SignatureWithGarbage]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					pk = [[7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa]],
					msg = [[54657374]],
					sig = [[7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b30d2020]],
					result = [[invalid]]
				},
				{
					tcId = 59,
					comment = [[Imported from Wycheproof v1 eddsa: ed25519_test.json tcId 32: signature too short.]],
					targets = {
						[[SignatureLength]]
					},
					flags = {
						[[TruncatedSignature]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					pk = [[7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa]],
					msg = [[54657374]],
					sig = [[7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946]],
					result = [[invalid]]
				},
				{
					tcId = 60,
					comment = [[Imported from Wycheproof v1 eddsa: ed25519_test.json tcId 10: special values for r and s.]],
					targets = {
						[[RSEdgeValues]],
						[[ScalarSRange]]
					},
					flags = {
						[[InvalidSignature]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					pk = [[7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa]],
					msg = [[3f]],
					sig = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					result = [[invalid]]
				},
				{
					tcId = 61,
					comment = [[Imported from Wycheproof v1 eddsa: ed25519_test.json tcId 20: special values for r and s.]],
					targets = {
						[[RSEdgeValues]],
						[[ScalarSRange]]
					},
					flags = {
						[[InvalidSignature]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					pk = [[7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa]],
					msg = [[3f]],
					sig = [[edd3f55c1a631258d69cf7a2def9de14000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000]],
					result = [[invalid]]
				},
				{
					tcId = 62,
					comment = [[Imported from Wycheproof v1 eddsa: ed25519_test.json tcId 29: special values for r and s.]],
					targets = {
						[[RSEdgeValues]],
						[[ScalarSRange]]
					},
					flags = {
						[[InvalidSignature]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					pk = [[7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa]],
					msg = [[3f]],
					sig = [[edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fedffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f]],
					result = [[invalid]]
				}
			}
		}
	}
}
