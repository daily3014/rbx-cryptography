--!strict
-- Auto-generated from Tadashi/testvectors/x25519_test.json
-- Do not edit by hand.

return {
	algorithm = [[X25519]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_kex_v1.json]],
	header = {
		[[X25519 ECDH per RFC 7748, with bug-catching cases beyond Wycheproof: dedicated public-key-derivation tests, scalar-clamping demonstrations (low bits, bit 7, bit 6), bit-255 u-coordinate mask check, non-canonical u reduction (u=p, u=p+1), small-order-PK zero-output tests, and full Alice/Bob DH round-trip from §6.1.]],
		[[Each non-KAT test's targets[] lists the implementation bugs it is designed to catch.]],
		[[Tests with pk = base (= 0x09 || 0^31) are public-key-derivation tests; their shared is the derived public key.]]
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test from RFC 7748.]]
		},
		KeyDerivation = {
			bugType = [[BASIC]],
			description = [[PublicKey(sk) = Exchange(sk, base); tests the full derivation chain.]]
		},
		DHFlow = {
			bugType = [[BASIC]],
			description = [[Computing the shared secret across one half of the DH exchange.]]
		},
		DHSymmetry = {
			bugType = [[BASIC]],
			description = [[Both parties of an X25519 exchange compute the same shared secret.]]
		},
		SelfExchange = {
			bugType = [[BASIC]],
			description = [[Recursive X25519 with K = u; well-known in RFC 7748 §5.2 as a one-iteration KAT.]]
		},
		SmallOrderPK = {
			bugType = [[EDGE_CASE]],
			description = [[Their public key is a small-order point on the curve.]],
			effect = [[Output is the all-zero byte string; implementations MAY abort per RFC 7748 §6.1 but rbx-crypto follows the original Curve25519 contract of returning zero.]]
		},
		ZeroOutput = {
			bugType = [[EDGE_CASE]],
			description = [[Shared output is the all-zero byte string.]]
		},
		NonCanonicalU = {
			bugType = [[MISSING_STEP]],
			description = [[Their public-key u-coordinate is >= p; RFC 7748 §5 requires reduction mod p.]],
			effect = [[Bug if impl uses u directly without reducing.]]
		},
		Bit255Mask = {
			bugType = [[MISSING_STEP]],
			description = [[u-coordinate bit 255 (high bit of byte 31) must be cleared per RFC 7748 §5.]],
			effect = [[Bug if impl uses u with bit 255 intact.]]
		},
		ScalarClamping = {
			bugType = [[MISSING_STEP]],
			description = [[Secret key is clamped: clear bits 0, 1, 2 of byte 0; clear bit 7 / set bit 6 of byte 31.]],
			effect = [[Bug if any clamping step is skipped.]]
		},
		ClampLowBits = {
			bugType = [[MISSING_STEP]],
			description = [[Low 3 bits of byte 0 of SK must be cleared.]]
		},
		ClampHighBit = {
			bugType = [[MISSING_STEP]],
			description = [[Bit 7 of byte 31 of SK must be cleared.]]
		},
		ClampBit6Set = {
			bugType = [[MISSING_STEP]],
			description = [[Bit 6 of byte 31 of SK must be SET (forces scalar into [2^254, 2^255)).]]
		},
		ClampingBoundary = {
			bugType = [[EDGE_CASE]],
			description = [[SK chosen so that the clamped scalar is at the minimum (2^254) or maximum (2^255 - 8) of the clamped range.]]
		},
		TwistPoint = {
			bugType = [[EDGE_CASE]],
			description = [[u-coordinate is a point on the quadratic twist of Curve25519. The Montgomery ladder produces a defined output; RFC 7748 does not require rejection.]]
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
	numberOfTests = 27,
	testGroups = {
		{
			type = [[X25519Exchange]],
			keySize = 256,
			tests = {
				{
					tcId = 1,
					comment = [[RFC 7748 §5.2 Test Vector 1.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc7748]],
						version = [[5.2 #1]]
					},
					sk = [[a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4]],
					pk = [[e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c]],
					shared = [[c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552]],
					result = [[valid]]
				},
				{
					tcId = 2,
					comment = [[RFC 7748 §5.2 Test Vector 2.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc7748]],
						version = [[5.2 #2]]
					},
					sk = [[4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d]],
					pk = [[e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493]],
					shared = [[95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957]],
					result = [[valid]]
				},
				{
					tcId = 3,
					comment = [[RFC 7748 §5.2 one-iteration self-X25519 (K = u = base). Tests one round of the X25519(K, u) function defined recursively at the end of §5.2.]],
					targets = {
						[[SelfExchange]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc7748]],
						version = [[5.2 one-iter]]
					},
					sk = [[0900000000000000000000000000000000000000000000000000000000000000]],
					pk = [[0900000000000000000000000000000000000000000000000000000000000000]],
					shared = [[422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079]],
					result = [[valid]]
				},
				{
					tcId = 4,
					comment = [[RFC 7748 §6.1 Alice public-key derivation (alice_sk * base = alice_pk).]],
					targets = {
						[[KeyDerivation]]
					},
					flags = {
						[[Ktv]],
						[[KeyDerivation]]
					},
					source = {
						name = [[rfc7748]],
						version = [[6.1 Alice PK]]
					},
					sk = [[77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a]],
					pk = [[0900000000000000000000000000000000000000000000000000000000000000]],
					shared = [[8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a]],
					result = [[valid]]
				},
				{
					tcId = 5,
					comment = [[RFC 7748 §6.1 Bob public-key derivation.]],
					targets = {
						[[KeyDerivation]]
					},
					flags = {
						[[Ktv]],
						[[KeyDerivation]]
					},
					source = {
						name = [[rfc7748]],
						version = [[6.1 Bob PK]]
					},
					sk = [[5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb]],
					pk = [[0900000000000000000000000000000000000000000000000000000000000000]],
					shared = [[de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f]],
					result = [[valid]]
				},
				{
					tcId = 6,
					comment = [[RFC 7748 §6.1 Alice computes shared = alice_sk * bob_pk.]],
					targets = {
						[[DHFlow]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc7748]],
						version = [[6.1 A->B]]
					},
					sk = [[77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a]],
					pk = [[de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f]],
					shared = [[4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742]],
					result = [[valid]]
				},
				{
					tcId = 7,
					comment = [[RFC 7748 §6.1 Bob computes shared = bob_sk * alice_pk. Must equal Alice's result (DH symmetry).]],
					targets = {
						[[DHFlow]]
					},
					flags = {
						[[Ktv]],
						[[DHSymmetry]]
					},
					source = {
						name = [[rfc7748]],
						version = [[6.1 B->A]]
					},
					sk = [[5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb]],
					pk = [[8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a]],
					shared = [[4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742]],
					result = [[valid]]
				},
				{
					tcId = 8,
					comment = [[Their public key u = 0 (the identity of the additive Montgomery group). rbx-crypto returns the all-zero shared secret per the original Curve25519 contract; libsodium-strict and noble REJECT small-order public keys.]],
					targets = {
						[[SmallOrderPK]]
					},
					flags = {
						[[SmallOrderPK]],
						[[ZeroOutput]],
						[[Acceptable]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4]],
					pk = [[0000000000000000000000000000000000000000000000000000000000000000]],
					shared = [[0000000000000000000000000000000000000000000000000000000000000000]],
					result = [[acceptable]]
				},
				{
					tcId = 9,
					comment = [[Their public key u = 1 (order-1 point). rbx-crypto returns zero; strict impls reject.]],
					targets = {
						[[SmallOrderPK]]
					},
					flags = {
						[[SmallOrderPK]],
						[[ZeroOutput]],
						[[Acceptable]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4]],
					pk = [[0100000000000000000000000000000000000000000000000000000000000000]],
					shared = [[0000000000000000000000000000000000000000000000000000000000000000]],
					result = [[acceptable]]
				},
				{
					tcId = 10,
					comment = [[Their public key u = p - 1 (order-2 point on the curve). rbx-crypto returns zero; strict impls reject.]],
					targets = {
						[[SmallOrderPK]]
					},
					flags = {
						[[SmallOrderPK]],
						[[ZeroOutput]],
						[[Acceptable]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4]],
					pk = [[ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f]],
					shared = [[0000000000000000000000000000000000000000000000000000000000000000]],
					result = [[acceptable]]
				},
				{
					tcId = 11,
					comment = [[Their public key u = p (non-canonical, reduces to 0 mod p). RFC 7748 §5 says implementations may reduce; rbx-crypto reduces and returns zero, libsodium/noble reject as invalid encoding.]],
					targets = {
						[[NonCanonicalU]],
						[[SmallOrderPK]]
					},
					flags = {
						[[NonCanonicalU]],
						[[Acceptable]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4]],
					pk = [[edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f]],
					shared = [[0000000000000000000000000000000000000000000000000000000000000000]],
					result = [[acceptable]]
				},
				{
					tcId = 12,
					comment = [[Their public key u = p + 1 (non-canonical, reduces to 1 mod p). rbx-crypto reduces and returns zero (order-1 point); strict impls reject.]],
					targets = {
						[[NonCanonicalU]],
						[[SmallOrderPK]]
					},
					flags = {
						[[NonCanonicalU]],
						[[Acceptable]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4]],
					pk = [[eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f]],
					shared = [[0000000000000000000000000000000000000000000000000000000000000000]],
					result = [[acceptable]]
				},
				{
					tcId = 13,
					comment = [[Known small-order point on the curve. rbx-crypto returns zero; strict impls reject.]],
					targets = {
						[[SmallOrderPK]]
					},
					flags = {
						[[SmallOrderPK]],
						[[ZeroOutput]],
						[[Acceptable]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4]],
					pk = [[e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800]],
					shared = [[0000000000000000000000000000000000000000000000000000000000000000]],
					result = [[acceptable]]
				},
				{
					tcId = 14,
					comment = [[Second known small-order point. rbx-crypto returns zero; strict impls reject.]],
					targets = {
						[[SmallOrderPK]]
					},
					flags = {
						[[SmallOrderPK]],
						[[ZeroOutput]],
						[[Acceptable]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4]],
					pk = [[5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157]],
					shared = [[0000000000000000000000000000000000000000000000000000000000000000]],
					result = [[acceptable]]
				},
				{
					tcId = 15,
					comment = [[Same u as RFC §5.2 Test Vector 1, but with bit 255 (high bit of byte 31) set. RFC 7748 mandates masking this bit before decoding u; the resulting shared must equal that of Test Vector 1.]],
					targets = {
						[[Bit255Mask]]
					},
					flags = {
						[[Bit255Mask]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4]],
					pk = [[e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1ccc]],
					shared = [[c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552]],
					result = [[valid]]
				},
				{
					tcId = 16,
					comment = [[Clamping baseline: low 3 bits clear, bit 6 of byte 31 set, bit 7 cleared. Subsequent clamping-variant tests must produce this same PK.]],
					targets = {
						[[ScalarClamping]]
					},
					flags = {
						[[ScalarClamping]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[48a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba4940]],
					pk = [[0900000000000000000000000000000000000000000000000000000000000000]],
					shared = [[cb0206722f7aa5e5236304b76c6397bffbe055bcfbfe751ee540d4d7000c3a0a]],
					result = [[valid]]
				},
				{
					tcId = 17,
					comment = [[Clamping: low 3 bits dirty in SK. Bits 0-2 of byte 0 must be cleared by clamping; PK must equal the baseline PK.]],
					targets = {
						[[ScalarClamping]],
						[[ClampLowBits]]
					},
					flags = {
						[[ScalarClamping]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[4fa546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba4940]],
					pk = [[0900000000000000000000000000000000000000000000000000000000000000]],
					shared = [[cb0206722f7aa5e5236304b76c6397bffbe055bcfbfe751ee540d4d7000c3a0a]],
					result = [[valid]]
				},
				{
					tcId = 18,
					comment = [[Clamping: bit 7 of byte 31 set in SK. Must be cleared by clamping; PK equals baseline.]],
					targets = {
						[[ScalarClamping]],
						[[ClampHighBit]]
					},
					flags = {
						[[ScalarClamping]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[48a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba49c0]],
					pk = [[0900000000000000000000000000000000000000000000000000000000000000]],
					shared = [[cb0206722f7aa5e5236304b76c6397bffbe055bcfbfe751ee540d4d7000c3a0a]],
					result = [[valid]]
				},
				{
					tcId = 19,
					comment = [[Clamping: bit 6 of byte 31 cleared in SK. Must be SET by clamping; PK equals baseline.]],
					targets = {
						[[ScalarClamping]],
						[[ClampBit6Set]]
					},
					flags = {
						[[ScalarClamping]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[48a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba4900]],
					pk = [[0900000000000000000000000000000000000000000000000000000000000000]],
					shared = [[cb0206722f7aa5e5236304b76c6397bffbe055bcfbfe751ee540d4d7000c3a0a]],
					result = [[valid]]
				},
				{
					tcId = 20,
					comment = [[Their public key u = base + p (= 2^255 - 10), a non-canonical encoding of the base point. Both rbx-crypto and noble reduce mod p and produce the same shared as the canonical base; bug if impl uses u directly without reducing.]],
					targets = {
						[[NonCanonicalU]],
						[[KeyDerivation]]
					},
					flags = {
						[[NonCanonicalU]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4]],
					pk = [[f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f]],
					shared = [[1c9fd88f45606d932a80c71824ae151d15d73e77de38e8e000852e614fae7019]],
					result = [[valid]]
				},
				{
					tcId = 21,
					comment = [[Their public key u = 2^256 - 1 (all-0xff). After bit-255 mask + mod p, this reduces to u = 18; output is non-trivial. Stress-tests the mask + reduce composition.]],
					targets = {
						[[Bit255Mask]],
						[[NonCanonicalU]]
					},
					flags = {
						[[Bit255Mask]],
						[[NonCanonicalU]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4]],
					pk = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					shared = [[76b00406ce7e87774c0038dd8d89b188047977f8828ca1dcb8f98bb5d5d0cf48]],
					result = [[valid]]
				},
				{
					tcId = 22,
					comment = [[Same u as RFC §5.2 Test Vector 2 but with bit 255 cleared (Vector 2's PK has byte 31 = 0x93, bit 7 set; clearing it gives 0x13). Output must equal Test Vector 2's shared because the RFC-mandated mask clears bit 255 before parsing.]],
					targets = {
						[[Bit255Mask]]
					},
					flags = {
						[[Bit255Mask]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d]],
					pk = [[e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413]],
					shared = [[95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957]],
					result = [[valid]]
				},
				{
					tcId = 23,
					comment = [[Smallest clamped scalar: SK = 31 zero bytes || 0x40 clamps to scalar = 2^254. Tests the boundary where only the forced bit 254 contributes to the ladder.]],
					targets = {
						[[ScalarClamping]],
						[[ClampingBoundary]]
					},
					flags = {
						[[ClampingBoundary]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[0000000000000000000000000000000000000000000000000000000000000040]],
					pk = [[0900000000000000000000000000000000000000000000000000000000000000]],
					shared = [[2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74]],
					result = [[valid]]
				},
				{
					tcId = 24,
					comment = [[SK = all 0xff. After clamping: byte 0 = 0xf8 (low 3 bits cleared), byte 31 = 0x7f (bit 7 cleared). Scalar = 2^255 - 8, the largest clamped value.]],
					targets = {
						[[ScalarClamping]],
						[[ClampingBoundary]]
					},
					flags = {
						[[ClampingBoundary]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					pk = [[0900000000000000000000000000000000000000000000000000000000000000]],
					shared = [[847c0d2c375234f365e660955187a3735a0f7613d1609d3a6a4d8c53aeaa5a22]],
					result = [[valid]]
				},
				{
					tcId = 25,
					comment = [[Their public key u = 9 (the base point). Result equals sk's own public key.]],
					targets = {
						[[KeyDerivation]]
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
					sk = [[a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4]],
					pk = [[0900000000000000000000000000000000000000000000000000000000000000]],
					shared = [[1c9fd88f45606d932a80c71824ae151d15d73e77de38e8e000852e614fae7019]],
					result = [[valid]]
				},
				{
					tcId = 26,
					comment = [[Their public key u = 2 (a twist point with small order on the quadratic twist of Curve25519). The Montgomery ladder works on the twist too, producing a non-trivial output even though the input is off-curve in the strict sense.]],
					targets = {
						[[TwistPoint]]
					},
					flags = {
						[[TwistPoint]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/curves]]
						}
					},
					sk = [[a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4]],
					pk = [[0200000000000000000000000000000000000000000000000000000000000000]],
					shared = [[71cacba0b65daf53ddf9c21fb434bc58ee5cfa3954d1b642fc5155048f03466f]],
					result = [[valid]]
				},
				{
					tcId = 27,
					comment = [[Asymmetric SK and PK bytes; nibbles within each byte differ. Catches hex parser nibble-swap or byte-reverse bugs.]],
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
					pk = [[a1b2c3d4e5f6071801234567fedcba98765432100f1e2d3c4b5a6978fedcba90]],
					shared = [[3dffd2a74d0c8236c39f7f4ca9ca2debeec7809f58f9958566cd0982d4e23d1b]],
					result = [[valid]]
				}
			}
		}
	}
}
