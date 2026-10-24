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
		},
		IteratedScalarMult = {
			bugType = [[EDGE_CASE]],
			description = [[RFC 7748 Section 5.2 iterated feedback loop: k_(i+1) = X25519(k_i, u_i), u_(i+1) = k_i, starting from k = u = the base point encoding.]],
			effect = [[Carry-propagation bugs in limb arithmetic that pass every one-shot KAT surface only after hundreds of feedback iterations driving the limbs through rare states.]]
		},
		LadderIntermediateEdge = {
			bugType = [[EDGE_CASE]],
			description = [[Public key constructed so a specific Montgomery-ladder intermediate (x_2, z_2, A, AA, B, BB, C, CB, D, DA, E, DA+CB or DA-CB) hits a boundary value such as 0, 1, p-1 or an all-ones limb pattern.]],
			effect = [[Carry or reduction bugs in limb arithmetic produce a wrong shared secret only for these constructed inputs; random KATs never reach them.]]
		},
		SharedSecretEdge = {
			bugType = [[EDGE_CASE]],
			description = [[Inputs constructed so the shared-secret OUTPUT is an edge value; catches final-reduction and encode bugs.]]
		},
		PrivateKeyEdge = {
			bugType = [[EDGE_CASE]],
			description = [[Private key is a special-case value (interacting with clamping or the group order).]]
		},
		SpecialPublicKey = {
			bugType = [[EDGE_CASE]],
			description = [[Public key has a special algebraic form chosen to stress the ladder.]]
		}
	},
	numberOfTests = 58,
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
				},
				{
					tcId = 28,
					comment = [[RFC 7748 Section 5.2 iterated scalarmult, 1000 iterations. The published 1000-iteration result; the definitive limb-arithmetic carry-bug catcher. Runners without iterations support must skip.]],
					targets = {
						[[IteratedScalarMult]]
					},
					flags = {
						[[IteratedScalarMult]]
					},
					source = {
						name = [[rfc7748]],
						version = [[5.2]],
						crossChecked = {
							[[pyca/cryptography]],
							[[rbx-cryptography]]
						}
					},
					sk = [[0900000000000000000000000000000000000000000000000000000000000000]],
					pk = [[0900000000000000000000000000000000000000000000000000000000000000]],
					iterations = 1000,
					shared = [[684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51]],
					result = [[valid]]
				},
				{
					tcId = 29,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 165: D = 0 in multiplication by 2.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[EdgeCaseMultiplication]],
						[[LowOrderPublic]],
						[[ZeroSharedSecret]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[5891c9272cf9a197735b701e5715268d36d7436b7e351a3e997a0862e4807d4d]],
					pk = [[e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800]],
					shared = [[0000000000000000000000000000000000000000000000000000000000000000]],
					result = [[acceptable]]
				},
				{
					tcId = 30,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 101: RFC 7748.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[Ktv]],
						[[Twist]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[4866e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba4d]],
					pk = [[e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413]],
					shared = [[95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957]],
					result = [[acceptable]]
				},
				{
					tcId = 31,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 103: edge case for shared secret.]],
					targets = {
						[[SharedSecretEdge]]
					},
					flags = {
						[[EdgeCaseShared]],
						[[Twist]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[60a3a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a9767f]],
					pk = [[b7b6d39c765cb60c0c8542f4f3952ffb51d3002d4aeb9f8ff988b192043e6d0a]],
					shared = [[0200000000000000000000000000000000000000000000000000000000000000]],
					result = [[acceptable]]
				},
				{
					tcId = 32,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 110: edge case for shared secret.]],
					targets = {
						[[SharedSecretEdge]]
					},
					flags = {
						[[EdgeCaseShared]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[60a3a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a9767f]],
					pk = [[7e26f8f24cb590027f9d1bc49b0e1a242c7d8f43624d3e8fab28ee08e02cb45e]],
					shared = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03]],
					result = [[valid]]
				},
				{
					tcId = 33,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 116: edge case for shared secret.]],
					targets = {
						[[SharedSecretEdge]]
					},
					flags = {
						[[EdgeCaseShared]],
						[[Twist]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[60a3a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a9767f]],
					pk = [[8e41f05ea3c76572be104ad8788e970863c6e2ca3daae64d1c2f46decfffa571]],
					shared = [[0000000000000000000000000000000000000000000000000000000000008000]],
					result = [[acceptable]]
				},
				{
					tcId = 34,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 87: non-canonical public key.]],
					targets = {
						[[NonCanonicalU]]
					},
					flags = {
						[[NonCanonicalPublic]],
						[[Twist]],
						[[SpecialPublicKey]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[0016b62af5cabde8c40938ebf2108e05d27fa0533ed85d70015ad4ad39762d54]],
					pk = [[efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f]],
					shared = [[b4d10e832714972f96bd3382e4d082a21a8333a16315b3ffb536061d2482360d]],
					result = [[acceptable]]
				},
				{
					tcId = 35,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 511: private key == -1 (mod order).]],
					targets = {
						[[PrivateKeyEdge]],
						[[ScalarClamping]]
					},
					flags = {
						[[EdgeCasePrivateKey]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[a023cdd083ef5bb82f10d62e59e15a6800000000000000000000000000000050]],
					pk = [[6c05871352a451dbe182ed5e6ba554f2034456ffe041a054ff9cc56b8e946376]],
					shared = [[6c05871352a451dbe182ed5e6ba554f2034456ffe041a054ff9cc56b8e946376]],
					result = [[valid]]
				},
				{
					tcId = 36,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 512: private key == 1 (mod order) on twist.]],
					targets = {
						[[PrivateKeyEdge]],
						[[TwistPoint]]
					},
					flags = {
						[[Twist]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[58083dd261ad91eff952322ec824c682ffffffffffffffffffffffffffffff5f]],
					pk = [[2eae5ec3dd494e9f2d37d258f873a8e6e9d0dbd1e383ef64d98bb91b3e0be035]],
					shared = [[2eae5ec3dd494e9f2d37d258f873a8e6e9d0dbd1e383ef64d98bb91b3e0be035]],
					result = [[acceptable]]
				},
				{
					tcId = 37,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 2: public key on twist.]],
					targets = {
						[[TwistPoint]],
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[Twist]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[d85d8c061a50804ac488ad774ac716c3f5ba714b2712e048491379a500211958]],
					pk = [[63aa40c6e38346c5caf23a6df0a5e6c80889a08647e551b3563449befcfc9733]],
					shared = [[279df67a7c4611db4708a0e8282b195e5ac0ed6f4b2f292c6fbd0acac30d1332]],
					result = [[acceptable]]
				},
				{
					tcId = 38,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 17: public key on twist.]],
					targets = {
						[[TwistPoint]],
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[Twist]],
						[[SpecialPublicKey]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[a8e56bb13a9f2b33b8e6750b4a6e6621dc26ae8c5c624a0992c8f0d5b910f170]],
					pk = [[0000000000000000000000000000000000000000000000000100000000000000]],
					shared = [[f294e7922c6cea587aefe72911630d50f2456a2ba7f21207d57f1ecce04f6213]],
					result = [[acceptable]]
				},
				{
					tcId = 39,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 31: public key on twist.]],
					targets = {
						[[TwistPoint]],
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[Twist]],
						[[SpecialPublicKey]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[d02456e456911d3c6cd054933199807732dfdc958642ad1aebe900c793bef24a]],
					pk = [[eaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f]],
					shared = [[07ba5fcbda21a9a17845c401492b10e6de0a168d5c94b606694c11bac39bea41]],
					result = [[acceptable]]
				},
				{
					tcId = 40,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 65: public key with low order.]],
					targets = {
						[[SmallOrderPK]]
					},
					flags = {
						[[LowOrderPublic]],
						[[Twist]],
						[[SpecialPublicKey]],
						[[ZeroSharedSecret]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[c8fe0df92ae68a03023fc0c9adb9557d31be7feed0d3ab36c558143daf4dbb40]],
					pk = [[ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f]],
					shared = [[0000000000000000000000000000000000000000000000000000000000000000]],
					result = [[acceptable]]
				},
				{
					tcId = 41,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 210: special case for A in multiplication by 2.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[EdgeCaseMultiplication]],
						[[Twist]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[d86c18f2be396b3bb72f22e6ece22e273af6e1506a1c09ad4d01bdd2f439f843]],
					pk = [[8c9885a26cb334054700a270f7a5f4aac06bad8263b651ebf0712eca1ebb6416]],
					shared = [[a5952588613eb7a5cd49dd526f1f20a4f0ffe9423e82cea302c2dd90ce559955]],
					result = [[acceptable]]
				},
				{
					tcId = 42,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 181: special case for AA in multiplication by 2.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[EdgeCaseMultiplication]],
						[[Twist]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[e82c480631fb153ba2211fe603032b3e71b162dbd3c11bec03208ffcd510655f]],
					pk = [[cb3d4a90f86b3011da3369d9988597c7fff1499273b4a04f84d0e26ed1683c0d]],
					shared = [[dbf6203516635840cf69a02db87cf0d95dae315da7fc1ec7ce2b29e1f2db6666]],
					result = [[acceptable]]
				},
				{
					tcId = 43,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 216: special case for B in multiplication by 2.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[EdgeCaseMultiplication]],
						[[Twist]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[9036ed7d68f7448ac440dc51216b49840dcabd3d5e32e3b4ffc32a5fe9e96742]],
					pk = [[8d9885a26cb334054700a270f7a5f4aac06bad8263b651ebf0712eca1ebb6416]],
					shared = [[ec9070ad3491a5ff50d7d0db6c9c844783dde1c6fbd4fe163e9ade1ce9cd041d]],
					result = [[acceptable]]
				},
				{
					tcId = 44,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 185: special case for BB in multiplication by 2.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[EdgeCaseMultiplication]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[58cd4ca1e4331188de2b2889419ce20ec5ef88a0e93af092099065551b904e41]],
					pk = [[cc3d4a90f86b3011da3369d9988597c7fff1499273b4a04f84d0e26ed1683c0d]],
					shared = [[0d74214da1344b111d59dfad3713eb56effe7c560c59cbbb99ec313962dbba58]],
					result = [[valid]]
				},
				{
					tcId = 45,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 222: special case for C in multiplication by 2.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[EdgeCaseMultiplication]],
						[[Twist]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[709098feb2e25c67b4bfd3be0a01af409adb6da52b3fbe3d970642dd2c983856]],
					pk = [[c8239b710136fe431fb4d98436157e47c9e78a10f09ff92e98baff159926061c]],
					shared = [[f1bd12d9d32c6f4c5b2dcb3a5c52d9fd454d52ca704c2c137956ec8ad9aef107]],
					result = [[acceptable]]
				},
				{
					tcId = 46,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 226: special case for CB in multiplication by 2.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[EdgeCaseMultiplication]],
						[[Twist]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[c887886fd07107c7221f6d9dd36c305ec779ceca132ac933ff77dab2beac6345]],
					pk = [[737d45477e2beb77a6c38b98e2a19b05c395df7da998cb91f6dfab5819614f27]],
					shared = [[8cf4538ae5f445cc6d273df4ad300a45d7bb2f6e373a562440f1b37773904e32]],
					result = [[acceptable]]
				},
				{
					tcId = 47,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 189: special case for D in multiplication by 2.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[EdgeCaseMultiplication]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[e0328c7d188d98faf2ac72d728b7d14f2bbbd7a94d0fbd8e8f79abe0b1fe1055]],
					pk = [[e58baccede32bcf33b3b6e3d69c02af8284a9631de74b6af3f046a9369df040f]],
					shared = [[97bd42093e0d48f973f059dd7ab9f97d13d5b0d5eedffdf6da3c3c432872c549]],
					result = [[valid]]
				},
				{
					tcId = 48,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 195: special case for DA + CB in multiplication by 2.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[EdgeCaseMultiplication]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[08ece580bb6ddf96559b81d7a97dd4531def6cc78d448a70cebabdd26caab146]],
					pk = [[f5c6311a1dd1b9e0f8cfd034ac6d01bf28d9d0f962a1934ae2cb97cb173dd810]],
					shared = [[2bfd8e5308c34498eb2b4daf9ed51cf623da3beaeb0efd3d687f2b8becbf3101]],
					result = [[valid]]
				},
				{
					tcId = 49,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 167: special case for DA - CB in multiplication by 2.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[EdgeCaseMultiplication]],
						[[Twist]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[0066dd7674fe51f9326c1e239b875f8ac0701aae69a804c25fe43595e8660b45]],
					pk = [[b0224e7134cf92d40a31515f2f0e89c2a2777e8ac2fe741db0dc39399fdf2702]],
					shared = [[8dacfe7beaaa62b94bf6e50ee5214d99ad7cda5a431ea0c62f2b20a89d73c62e]],
					result = [[acceptable]]
				},
				{
					tcId = 50,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 171: special case for DA in multiplication by 2.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[EdgeCaseMultiplication]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[88281cc51d5512d8814ea5249b879dcbad0323d38512dafbdc7ba85bba8c8d5d]],
					pk = [[4fce3bb6c8aaf022dbd100e3cde3941b37d543f00401dba7da9bc143dfc55709]],
					shared = [[42184e22c535530c457bd3b4f1084cbf5e297f502fe136b8d1daecf5334cc96c]],
					result = [[valid]]
				},
				{
					tcId = 51,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 155: special case for E in multiplication by 2.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[EdgeCaseMultiplication]],
						[[Twist]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[581ecbda5a4a228044fefd6e03df234558c3c79152c6e2c5e60b142c4f26a851]],
					pk = [[0000000000000000000008000000000000000000000000000000000000000000]],
					shared = [[59e7b1e6f47065a48bd34913d910176b6792a1372aad22e73cd7df45fcf91a0e]],
					result = [[acceptable]]
				},
				{
					tcId = 52,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 175: special case for x_2 in multiplication by 2.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[EdgeCaseMultiplication]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[c0b386f4ef0d4698686404977e7b60cb6c1f8b6012a22e29d6224c5947439041]],
					pk = [[f12f18bd59c126348f6a7a9f4a5fdd9fcaf581345073a851fba098e5d64b4a0c]],
					shared = [[6600cbe900616a770a126b8b19156d5e27e1174bd538d0944eb3c0be4899c758]],
					result = [[valid]]
				},
				{
					tcId = 53,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 202: special case for z_2 in multiplication by 2.]],
					targets = {
						[[LadderIntermediateEdge]]
					},
					flags = {
						[[EdgeCaseMultiplication]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[a84f488e193139f986b0e5b249635b137d385e420342aef1f194fcde1fe5e850]],
					pk = [[4ef367901aac8ba90a50e0cf86ca4e4a3ff164fb121605be346e2e48d04ac912]],
					shared = [[7eb48a60b14fb9ea5728f6410aef627d1522fad481b934af64e2c483b64d585f]],
					result = [[valid]]
				},
				{
					tcId = 54,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 513: special case private key.]],
					targets = {
						[[PrivateKeyEdge]],
						[[ScalarClamping]]
					},
					flags = {
						[[EdgeCasePrivateKey]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[4855555555555555555555555555555555555555555555555555555555555555]],
					pk = [[3e3e7708ef72a6dd78d858025089765b1c30a19715ac19e8d917067d208e0666]],
					shared = [[63ef7d1c586476ec78bb7f747e321e01102166bf967a9ea9ba9741f49d439510]],
					result = [[valid]]
				},
				{
					tcId = 55,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 516: special case private key.]],
					targets = {
						[[PrivateKeyEdge]],
						[[ScalarClamping]]
					},
					flags = {
						[[EdgeCasePrivateKey]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6a]],
					pk = [[3e3e7708ef72a6dd78d858025089765b1c30a19715ac19e8d917067d208e0666]],
					shared = [[4782036d6b136ca44a2fd7674d8afb0169943230ac8eab5160a212376c06d778]],
					result = [[valid]]
				},
				{
					tcId = 56,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 518: special case private key.]],
					targets = {
						[[PrivateKeyEdge]],
						[[ScalarClamping]]
					},
					flags = {
						[[EdgeCasePrivateKey]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6a]],
					pk = [[be3b3edeffaf83c54ae526379b23dd79f1cb41446e3687fef347eb9b5f0dc308]],
					shared = [[e3c649beae7cc4a0698d519a0a61932ee5493cbb590dbe14db0274cc8611f914]],
					result = [[valid]]
				},
				{
					tcId = 57,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 117: special case public key.]],
					targets = {
						[[SpecialPublicKey]]
					},
					flags = {
						[[EdgeCaseMultiplication]],
						[[SmallPublicKey]],
						[[LowOrderPublic]],
						[[ZeroSharedSecret]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[c8d07c46bbfb827753b92c70e49583ce8bfa44641a7382258ea903d6a832c96b]],
					pk = [[0000000000000000000000000000000000000000000000000000000000000000]],
					shared = [[0000000000000000000000000000000000000000000000000000000000000000]],
					result = [[acceptable]]
				},
				{
					tcId = 58,
					comment = [[Imported from Wycheproof v1 x25519_test.json tcId 136: special case public key.]],
					targets = {
						[[SpecialPublicKey]]
					},
					flags = {
						[[EdgeCaseMultiplication]],
						[[Twist]]
					},
					source = {
						name = [[wycheproof]],
						version = [[v1 (C2SP)]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					sk = [[b876b05daff0530b139d9e11250563418077178246c5fa7005ba00e9b6647763]],
					pk = [[fbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2f]],
					shared = [[686eb910a937211b9147c8a051a1197906818fdc626668eb5f5d394afd86d41b]],
					result = [[acceptable]]
				}
			}
		}
	}
}
