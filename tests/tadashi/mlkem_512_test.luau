--!strict
-- Auto-generated from Tadashi/testvectors/mlkem_512_test.json
-- Do not edit by hand.

return {
	algorithm = [[ML-KEM-512]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_kem_v1.json]],
	header = {
		[[ML-KEM-512 per FIPS 203 with KeyGen / Encapsulate / Decapsulate KATs and implicit-rejection tests. Wycheproof skips this parameter set; Tadashi covers it specifically.]],
		[[Tests store seeds (D, Z) and message rather than the full encapsulation key (~800 bytes) so runners regenerate keys from seeds. Each test exercises one operation; KeyGen tests publish SHA3-256(ek) and SHA3-256(dk) for cross-impl verification.]]
	},
	params = {
		k = 2,
		eta1 = 3,
		eta2 = 2,
		du = 10,
		dv = 4,
		ekLen = 800,
		dkLen = 1632,
		ctLen = 768
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test cross-checked against @noble/post-quantum.]]
		},
		KeyGen = {
			bugType = [[BASIC]],
			description = [[KeyGen(D, Z) produces canonical (ek, dk).]]
		},
		Encapsulate = {
			bugType = [[BASIC]],
			description = [[Encapsulate(msg, ek) produces canonical (ct, shared).]]
		},
		Decapsulate = {
			bugType = [[BASIC]],
			description = [[Decapsulate(dk, ct) recovers the shared secret.]]
		},
		RoundTrip = {
			bugType = [[BASIC]],
			description = [[Decapsulate of Encapsulate output recovers the same shared.]]
		},
		ImplicitRejection = {
			bugType = [[AUTH_BYPASS]],
			description = [[Tampered or random ct: FO re-encryption check fails; spec mandates returning SHAKE256(Z || ct) instead of an error or zero output.]],
			effect = [[Bug if impl returns zero, errors out, or returns the raw KPrime on FO mismatch.]]
		},
		FOReencryption = {
			bugType = [[MISSING_STEP]],
			description = [[Decapsulate re-encrypts mPrime under the embedded public key and constant-time-compares against the input ct.]]
		},
		RandomCiphertext = {
			bugType = [[EDGE_CASE]],
			description = [[Ciphertext is not derived from any Encapsulate; FO check rejects.]]
		},
		CrossKey = {
			bugType = [[AUTH_BYPASS]],
			description = [[Ciphertext was produced for a different key pair.]]
		},
		BitFlip = {
			bugType = [[AUTH_BYPASS]],
			description = [[A single bit of the ciphertext was modified.]]
		},
		ZeroInput = {
			bugType = [[EDGE_CASE]],
			description = [[All-zero seeds or message.]]
		},
		MessageAllOnes = {
			bugType = [[EDGE_CASE]],
			description = [[Message is all 0xff bytes.]]
		},
		DZSeparation = {
			bugType = [[MISSING_STEP]],
			description = [[D and Z are distinct; catches impls that conflate the two 32-byte seeds.]]
		},
		NonCanonicalEk = {
			bugType = [[INPUT_VALIDATION]],
			description = [[Public key has a 12-bit coefficient >= q (= 3329). FIPS 203 Algorithm 17 step 1 requires rejection.]]
		},
		InputValidation = {
			bugType = [[INPUT_VALIDATION]],
			description = [[Input fails a structural or canonical-encoding check that the spec mandates.]]
		},
		DegenerateKey = {
			bugType = [[EDGE_CASE]],
			description = [[Public key is mathematically valid (canonical encoding) but degenerate (e.g. all-zero coefficients); accepting is correct per spec but offers no security in practice.]]
		},
		DkValidation = {
			bugType = [[SPEC_AMBIGUOUS]],
			description = [[FIPS 203 Algorithm 24 (dkCheck) defines an optional integrity check on dk. Implementations may choose to recompute H(ek) on Decaps (strict) or trust the stored H (permissive). Both are spec-compliant.]],
			effect = [[Strict impls reject; permissive impls produce a garbage shared.]]
		},
		HFieldTamper = {
			bugType = [[SPEC_AMBIGUOUS]],
			description = [[The H(ek) field embedded in dk has been modified.]]
		},
		NonCanonicalDk = {
			bugType = [[SPEC_AMBIGUOUS]],
			description = [[A 12-bit coefficient in dk (the s-hat region or the embedded ek t-hat region) is >= q. FIPS 203 Decaps (Algorithm 19) never range-checks dk; every non-rejecting behavior (silent mod-q reduction, use-as-is, internal detection) makes the FO re-encryption check fail and converges on the implicit-rejection value SHAKE256(z || ct), which depends only on the untouched z field.]],
			effect = [[Crashing, or returning anything other than SHAKE256(z || ct) or a clean rejection, indicates unsafe handling of malformed secret keys.]]
		},
		Acceptable = {
			bugType = [[SPEC_AMBIGUOUS]],
			description = [[Either matching the recorded output or rejecting cleanly is a spec-conformant choice.]]
		},
		UnluckySample = {
			bugType = [[EDGE_CASE]],
			description = [[Seed bruteforced so that SampleNTT must consume an unusually large number of XOF bytes (probability ~2^-38 per matrix entry).]],
			effect = [[Catches impls with fixed-size XOF buffers that overflow on the unlucky path (DJB calls the worst-case form KyberBleed).]]
		},
		XofBufferOverflow = {
			bugType = [[AUTH_BYPASS]],
			description = [[Fixed-size XOF read buffer too small for the unlucky tail of SampleNTT; can leak adjacent state.]]
		},
		StrcmpVsMemcmp = {
			bugType = [[AUTH_BYPASS]],
			description = [[Ciphertext crafted so that the FO re-encryption check has matching null-byte prefixes; an impl using strcmp short-circuits and skips implicit rejection.]],
			effect = [[Yields wrong K on the strcmp path; correct K on memcmp.]]
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
		ZBinding = {
			bugType = [[MISSING_STEP]],
			description = [[The implicit-rejection secret must be derived from the z field of THIS dk: same d seed and same tampered ciphertext as the bit-flip rejection test, but a different z, must yield a different shared secret.]],
			effect = [[Implementations returning a constant, zeros, or anything not keyed on z pass single-vector rejection tests but fail this pair.]]
		}
	},
	numberOfTests = 24,
	testGroups = {
		{
			type = [[MlKemKeyGen]],
			tests = {
				{
					tcId = 1,
					comment = [[ML-KEM-512 KeyGen with all-zero seeds (D = Z = 0^32). Tests the full KeyGen path on the zero-input edge.]],
					targets = {
						[[KeyGen]],
						[[ZeroInput]]
					},
					flags = {
						[[Ktv]],
						[[ZeroInput]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[0000000000000000000000000000000000000000000000000000000000000000]],
					z = [[0000000000000000000000000000000000000000000000000000000000000000]],
					ekSha3_256 = [[e5bd1b37a75e0f092974e846e8c37c45487d60739f99351719a5394723262b3b]],
					dkSha3_256 = [[c4d6b5ebc673f958555366a0e7f6f4849fac965157fd4e334d107460b3f3ef5d]]
				},
				{
					tcId = 2,
					comment = [[ML-KEM-512 KeyGen with incremental seeds (D = 0..31, Z = 32..63). Matches @noble/post-quantum seed convention where the 64-byte input is D || Z.]],
					targets = {
						[[KeyGen]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					ekSha3_256 = [[82f101ff648063b376e2bb6c5b7455f655a50c2feadade150efa0e0e6f365aea]],
					dkSha3_256 = [[0bd3f5df01098ac9c29d687c7f1bd0588a5573feeef8f1e3b4573fa7f6ab57c8]]
				},
				{
					tcId = 3,
					comment = [[ML-KEM-512 KeyGen with all-0xff seeds. Stresses the SHAKE expansion of rho with the maximum-byte input.]],
					targets = {
						[[KeyGen]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					z = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					ekSha3_256 = [[724f96152c301f9c2167327e0baccb68363fd8ed452557f1edd8c166a5058792]],
					dkSha3_256 = [[e6a44d4022f7751217d2b8aa907265bb51f4ac8e16fb6b1ea215a72c00767cf9]]
				},
				{
					tcId = 4,
					comment = [[ML-KEM-512 KeyGen with asymmetric D and Z (different patterns). Catches D/Z mix-up bugs.]],
					targets = {
						[[KeyGen]],
						[[DZSeparation]]
					},
					flags = {
						[[DZSeparation]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef]],
					z = [[fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210]],
					ekSha3_256 = [[a2ee530c45a3e02796a76e3bf9e3f613efa9670d6721051ed8af899974fe4466]],
					dkSha3_256 = [[bc2b904be74039ee6fd94e25cd6b674205312cdd1bd3d08962c671f62ed62cdc]]
				},
				{
					tcId = 19,
					comment = [[C2SP/CCTV unluckysample for ML-KEM-512: seed forces SampleNTT to read >575 bytes from SHAKE-128 (probability ~2^-38). Catches fixed-size XOF buffer overflow; DJB calls the worst-case 'KyberBleed'.]],
					targets = {
						[[UnluckySample]],
						[[XofBufferOverflow]]
					},
					flags = {
						[[UnluckySample]]
					},
					source = {
						name = [[c2sp-cctv]],
						version = [[unluckysample/ML-KEM-512]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[8c7238e1965ddd73b1114b897e1bf4b308c0d9cc710d0482ab8b9e737405354a]],
					z = [[8476013560151d986dc7834dcb57c75f845f8d7ee71558d0955f3f4feb723cf2]],
					ekSha3_256 = [[6ccefbd4f875d1a93a740ad1832a2d8469cb12c403de86a4840e937f3d18a36b]],
					dkSha3_256 = [[a70bbf31ff2c2259f0429468e5e32f73dd8bcafd6d037d093b21d6c6c49073be]]
				}
			}
		},
		{
			type = [[MlKemEncapsulate]],
			tests = {
				{
					tcId = 5,
					comment = [[ML-KEM-512 Encapsulate with zero seeds and zero message. Tests the full Encapsulate path on the all-zero input edge.]],
					targets = {
						[[Encapsulate]],
						[[ZeroInput]]
					},
					flags = {
						[[Ktv]],
						[[ZeroInput]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[0000000000000000000000000000000000000000000000000000000000000000]],
					z = [[0000000000000000000000000000000000000000000000000000000000000000]],
					ekOverride = [[]],
					msg = [[0000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[6bc50400277abb7e6bf9fb56820175ebb7b9f4f2822c6d0ae080a349920f6d008eba35b542b9d7ed89cbfd38d79f553bf08e638095cf0d4f5040ac1d1bdc24843b18c2779f241181a6ccd8f4e800dc266136d1b65d9c126df5e793c86dacaf3c783fa9c1006f08294f1a4d3bb44b6fc209004bc1f0e67f48480940f20a8618bfc64eb2b0abfe1bea91588c186e30e833872926efe90c3b8b0c994053b930ba17b38a74595d4c761ad33fe4f7a30f3a2c85c146f0a491a312b2a44b888d1c85b1e4411f9db7912f6098fdfc2989117d16099e76f19cb350b9d002d2a20dddee90470db94a5311a24f135a40dcc6fed72836eca05eabc17d193359e2e4ea26672fe505d8346e3cab638b2416c71b2a9be50478986c6c1e94e37f8652c017568d017a2881073d612acdc8b67e5bada890bd0c95b5099d7c348c748f8e7c286ce22fa2877f8043461cb21c5ad2ecadf955e36b195408841a3482f49cec3d65f9787f3747cff1cb15f2acff3b8fa08c25885c38239a27166adfa3981d16334b4ffb8385667603b9b54621b9f3f4f13a85ec9e566ab61dcccafb11ae477d93a5bc9032dea1a51e5d5217980a8bc41a287c9c223e33064077e5224986f93cc5c1b9772553665a18835a2bbfac047026e82bb60ce80095bb0875f337312eef288d5892d4fdd702ce8f118317531944d7d56d44043a0a0146f2d2a50588a0d90de1a07af2202e5b05e42b113db382643befc153ba9f7f2959873952da7bffd7dda1a99fa1e23874b094dcc5b5f361df9262e196876db42cc7f038e95efcff4c01c75939e59bfbf52b1be5f8250607c782462a99d0a96781d7a229961a948e7d517699ad61ecb6c0588ed09dff58571b2ead65d8dea5fa814b2c061bfe49204d5e1bb74096aa8125eb84dbea5d0baff98e41a6dd913a6854b72eb174fff50da73cc7305b55c62dc84cb4adccd0a11b41c723e8daffb73a12c2dc397cf4b950005388c87749fd703de0aa0c28d4a2ec825ddae8052fe89c21393a222f0a5c6d01dfc89f46f71502ad1935635558f57a46c97ae63384482bf0e7c57298436a99ba00574faa0a]],
					shared = [[4ad53a06b29f12568421a552c08195b58673c82f870cc1ccd65a08e4325feb27]],
					result = [[valid]]
				},
				{
					tcId = 6,
					comment = [[ML-KEM-512 Encapsulate: incremental seeds + zero message.]],
					targets = {
						[[Encapsulate]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					ekOverride = [[]],
					msg = [[0000000000000000000000000000000000000000000000000000000000000000]],
					ct = [[630d9d9fbf675e2888509de2e6bbce045848dc41fb02f375f9f97c8e57b984a4becfdbc76dfabf5f6d990fa7b110f432324b08b333f6da81edf59ce9a7eb8b2583f03938b18066d15ebf6c2d663311e867753239833cd7177f4cec74eecf36e95450b7cace59517460efc3c102292d3f5c9a0aa5b4136558f095568cfe876d66a1a67e2148213f130c1ccd9a8ea162c2fda0197015745f7b5ca00bdff28153b19cbad06f6462f38c2e79da2da0a3805d643749abf82571149f8c58cd3e97b5adf05e43296989860f7b0d55913899f88f040b70f909a07acab8c1bee1791bc03bdaa078d66446bc7c9984b710d550652020206965709956ad4c859acc9eb55be431552a6cb45a9e175f1ddcf7992d1513c26cbff04a407d1f5f4b3cf12df7fe3c38eeac4602c39682d46e441428c46d041d7c1dc16793ea685f2da48cf5702ef81a9c361a9e410e1cf01c279cf4c6849938aac4cb064fe8b2dd62b267fbf4af8c2bd4bad902be979f9666b82ee1b2ed3b3541dcd480615690ddd74126e9acb266440b255542832f283d27b8aef5557b2993e29a34dc6ae034e9455adf1bf8bda60bf00f773350f78f9fd6415102124db59c8e16dc50bffde418ae0af42101db14c0841faee6612ac3b4ff186c6d626d5943fdb85e607aeb6a4b195a56dbc7631951083669e9f273ab2695074ccd6e7a1f2b11cbac033b1087e2b8adacd4c221a575eb85407da61a6aaa73e908143d2169fb18f0dc39b209eb49352875f5383346425bacddfdb8a0fc42b44b0614e284ffb164a3e4b433834d580e6d7f2d5578416c43bcfe8f219d73346a71c5771fcfc78689d3e87d8d68a0b773d8861d4fad85755a79a5d62cdc7ff5c8a6ff4439101efb808f609509adf8875f854b5adecde235eb8815755065c3776452b27a3cde72d69883089e73d35cb5b3cdc11898dbb24a4d2fc697f79dd0504d7a957dd523d81046a7a291f0083a54c6fc2b2b317271b219ffd073efc3f714c430f95e17e5c82954bafd7db7dadf8ba4bfe84c77f7287f9b70da6575367e88d0f136cdf23164a78cb9e4c887f38a22b7ec4871c52b10]],
					shared = [[17be7a281ee21f0e23cf56c76249028765a1a2e6e70517ce027f3942fea3514b]],
					result = [[valid]]
				},
				{
					tcId = 7,
					comment = [[ML-KEM-512 Encapsulate: incremental seeds + incremental message.]],
					targets = {
						[[Encapsulate]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					ekOverride = [[]],
					msg = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					ct = [[9a4ddbd3e08a1c9a45eec13d3ad97626b67af42128b34d5a37de399b2d8e97ec2e174f6de1318560a51381a31dd3dba79d902e10d14057f6ce3fbc30de25363541934e76cb2446dbd2cb8fea570baacb222c769a8e7ebfe49ce6a3d9f2add1cc0f21a1cb6395ba8634fbd02199549db4a349b2ae3619168a7fe66c62d808006e6608aa66cbb8167146b40c81a37152eeb47169a9c5b5d1064558cf1a59d0d15ace1893914f282406f51b9044992189b6664b8e2700c4485f1ee76af83c955d090ab8c0c49c128f9b6b5f89f372dba4bfd9d63fe521b309163b259791c5791cf834b9c22d06b3811c5268deee7de7f940e6248b963ef6335c18ea6150ef009a75eec0c2bf9702498e54e4cc33c8d969c1d8c8e1afbd5af1c955e746719dd8cfc138e17ce3cb04675a9bf2a5bc1e0444904f62228722b13e7c64fd79be91c2e346a9cfbda57ddcf805f6f9dda5bad3f15eb2dab119e5e7cffd8ef3fefe59ef1e49f56d6dab30528273cb3b824a836c593e4d44e9b9fb48610a280008a4110638917a49bd7ef5baaed79cff763fa555a95ac73b4694fd42220a96d56c080f5097c9bcea62aedf3804bd87a7d42e0b6f694fc3752d9a23d4009a6bc4738a3314e655dc8fb7cfeb1c4f830af0ab829fa315b39605ab42d23a142dbd0d9df7f20ca1f74365a3dd1eb19c32806bcd2540024e2589e5977f4fbf0b33014c19a1b67c0628f814f3071eadde644adba93a02590908444354587eafe94f138b270623086e381c027ae1d3a6fc62d1047213cccda3c916e814f2fd1a672d4466e57492febc51edce627a700ee707db38952c7ad9a81d44f4178a1aa11d41e16491aff6e5169fd5c7a623290cf509ee4cf7c51c86a8682700cf73ec9aec335a6844a7de7dcee9a93fcbf6eaad6911909f8fb036e731f1118fce5cc77cc4e5d4cf669354292a544378d77dbb0603dd41c733661dddf9651f20b30a311bcfeaeac82dcc94e918ef41e1cd64fb49fdd3f4a77c9f681a0f4a0a9abc43c3679fbaf7369b2afe66d80549fb2e489b815701d23275a4db0eb1234997c9d868aa431adca4aa513c600f4d]],
					shared = [[40a832e418f10e1000bda5faef8f682e85039dc6572dad28e436b65021031b6f]],
					result = [[valid]]
				},
				{
					tcId = 8,
					comment = [[ML-KEM-512 Encapsulate: incremental seeds + all-0xff message. Bug-catching for messages with all bits set.]],
					targets = {
						[[Encapsulate]],
						[[MessageAllOnes]]
					},
					flags = {
						[[MessageAllOnes]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					ekOverride = [[]],
					msg = [[ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]],
					ct = [[2e47031e1b059799f6a57a6d396fb1f504b0198aac5e9ec85173b77a35838bb4aaa1fdb332f187f2b4395133495e7071beb7d39edcf62b668841bd3a419b57024cf902cab317460bc70b2a024f56d48b732d4de1fcc68b742551730f87068b435790bc890de51fbdf6afaeabc1dc5967a218616496399bc21ee82a6d9559e277b798fa710b1d20ceaef2ec97b57f81b656510136c97d224cd5e75e81d1e7a351712376958e0ef603831874c2dc814949bdf3868b0527df793234430814704b90e02dcec7f5a5f55fa361f7b632408832cbb75067b1c5926259e840db37549d6835ce88195bae6feba201cf0e76f3da03fb6a1ff942e27761446b913c66ae19c3133b89d6de703b47286901634cafa45c4d1b46d18df22291e1d454c732cd686a8e86bbf6bdee15f6c89a24418bb2929002ffa2a6c78d397532bf06977cd3f01a0bb30b8952a48120d49dfb26b2122a03441fbaae03b9735c9ea49594e55dec4922dabd4124ee7d1ef405cde05358a14b516f338d7787cde62e261a91a164199c203986886034d823168abc2cc2ea0907897a772e00a46a00720abf431c764dcdd44f69320310eccdbf100eeafe3d44a9c4eb72bd3206dca5998aa8fc2cb07d34742772e2499c6a966a001d22834e32c40dad8e3e7d4b6e9d6d617dee0e8c6758d7278b10d4395548e0e85d93b2471614a0e9f79cc3cdcd25a74f7dc3fb3c17d73257ba40ec621513b6903eee31bb64e8c16d6bf4ee317cb695eb859d845cb345e07f18844124efcba23d2d49b9daf2bf04e28620090124bfe9728a1fe057f17de0098ba463f8d8ba6b928bb62f72abc5f5a96a0cecd80ba463d504e7cc498e3d8647aa12361041c1ed80a16314786ef482da7b6daf946fcaad7bcb6197e39f3d7a91eabe4db55514550f2f04c5e8d3b74a073c21a7b84d41a7cb32c751034203d5fd071ff3955d2ba825effd637215e7ca85fff7cf47c77ea72f85e7cc4e9d0e40f7bd9522e2e78403e1208d9e38177fab888a8d52d9d37828154e79e3dd6ce48a1dfd910ba77ee3c3183ccf68c8a1f211a5fd85a077a0c85b615da3e0c1e443]],
					shared = [[604d9f96971fea3ad58ca0723e909fe92233290b341841197f6c2f2c8738d253]],
					result = [[valid]]
				},
				{
					tcId = 9,
					comment = [[ML-KEM-512 Encapsulate with asymmetric message bytes; nibbles within each byte differ.]],
					targets = {
						[[Encapsulate]],
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
							[[@noble/post-quantum]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					ekOverride = [[]],
					msg = [[0123456789abcdeffedcba98765432100f1e2d3c4b5a6978a1b2c3d4e5f60718]],
					ct = [[14d7837f27bebb99cdbce0ffe08e7c69dfd517c6f23f234322140605c64dcd3e5d895e85e6545b54c9463096ee3daee5d34108c4e241494bef506b43e95e636a69e556c5f1cae5497d2864cf7585d8a9ac163540ccd333c7642d5620b7c746ca31d14872943a716f52ba3cc9e67f10ea3fe2265ac48373db22121d727710ebd57a0d63edeb7f002ac4b3971b3878c82dbdfe07b4189d0a88944c8e81ac5f70a19a3f117e293f3674c604ef189bd3cb0852867bff5c56187f17ec3424006ccf40889fa7866a04944905a9ae8e23c8b1fd36188d24059fb6e6c73ddfa0f0365b76a844ff4b94fe440d3bb6e624b484a47a17203ea6e1372d83602632176acdb7ee564406979070f3adb7935050219e2bfa57f6bb347f918819817f4218a6af1b8a60817c62e70385fe33ff9e88cb54ddaaf62949b8c5c64728bd826982e84e5c410b141900c581006ea33cdb90e54e73dae4047fcf804a51820e36f22135041511a286a6c9b703aa7f6d13fb7bdbce96f4692c96e3559fa3f7e83c0d2793c3b65797dad6195fbe40fb55dc26623cbadb5e19a2eb01342aaddbb46c788d84762924128aaaa44e5610350e238194482e852b069dd9f5bf88648783adc918c04583f6cabc02ed7569d233721017d223e421528d1226ddc6a45df61b369bced6794e7231ae1bd1a1b2d298f94ff0aabc28881aadaac5ed72409de638d956c39a5633a3b77728fa330b1348aa3bde81d655455544284c0521020c5fd224484d355955b2186126b28a67e687ea740142cfedc9d3385604ab0af684540a5e93653e79ad5be81087b96952f3c213d7aadba1ce0b625e5d2745375308ad6406c40465bb92964b2a5e153fc0d8df239af0134282372b718525ca316b313f788e1d61efb4e583ccd8b91d2cb80d61242f3e1d2985c996af945aa35e2751eddd3068b063691b36ca9725ae57740b33b49dc0fb4ad698a7d8569734a59a3192db423447e4ee1034e4f940453908f2d8d5c9528632b9ece12291b9f0be8459fa36f5947a35a05b57ab090cb07d62dfd8516a009859d7543c70b5e64fe74ad184ace15874b0ade823]],
					shared = [[5b27caf94656a873bbff544061f5677b8d0ca40c6b4b3f558308c3be07477b9d]],
					result = [[valid]]
				},
				{
					tcId = 16,
					comment = [[Encapsulate with a non-canonical public key: first 12-bit coefficient set to q (= 3329). FIPS 203 Algorithm 17 step 1 requires rejecting ek encodings where any coefficient >= q. Both rbx-crypto and noble reject (via different error messages); impl-bug if impl accepts and processes.]],
					targets = {
						[[NonCanonicalEk]]
					},
					flags = {
						[[NonCanonicalEk]],
						[[InputValidation]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					ekOverride = [[019d815e597d104355cf29aa5333c93251869d5bcdbe487124f602b8b6a66c16c4761648ad765cf5d8006b515e905a7f0ac076b0c62efa328153e7ca5701699f1305f1e6bc6f90b0e49b693512b6ce992a8b8016ddfc1a662c7e3f9619cbd869dd771af30896ccd5918ac6cb77466c5e779996d67ff9aabc97503f2c7b7e2d000d86450fb1807ca4cabda465825a31c789a1b7a491ab3872765d320d0b71920fa213c94093416b83b8124e69f65e62cb5000dcc37aa9a0fff73970c4772f357d24189ca6f5305568c0e2376a3762a68c605e563c5d209572e0fc7532ca294729535567b5fc413c5e8792d2464536cc808f98add74664f141566f9016a90a541829a98a0464ce41a8bb44c2d4fa3c2c209460728ef14a1a7c4c9b98d12203b4cc3529160a9ab2d7838f7ff6b53ae05aa31a7d646b7afa6c45932526a3c3755619be994c211c2a31c05b3447836cb2150be1829dae6b04c5535cff546e392ba797411720f924f490a5ac5495f21356d550b782a64c1688b6b655bcc7842197a434c2f6563b5b7f09a78bcc488232783561d16f4cbab6755400050781570c66604b817ad1252294736e8b01861a4b5a74519b8b6fe51489a5072392e587626c713776575d33806a1c8e2732af97c2680f51666331c4eb8bbc0431c4f96832daf1b3c45528fba153f6c78b1c198702947ccd337727a46fb53ba11de5cb4191346859516cb6ad72400f3cf209b236aef35a580ac87eb3e30fafd66973ca8a7dd2675af41f7a17b61433cd1af80f7708869f665488497980b1ac10a0cdcb636a00ed8681b35e429124ca80350725b85f83a5eac3a4a3cc1600903e65293560b9b336e5af0d529dac1a048119302cb7a9bcc110b94851bf02117f199dc485a852b7473f09b831a6831d5b54c0b790d225cf6bb92d9462a26cdb33dda5123c7aaf0e26a0b83655eea28bf3a8074725018fd6bae4b601cf61baab71a7a3d35197a343e74b4a272c125d540896426d85b7958d3b38a6ba987ec37225c7b44cdb12dde4539b4ab082363683f04bf7a09cc5c41dfe830a1b162e0b324334362f084a14467723344badd000f8d8c537c48f998f05307cebd1ede0b81c3bc59a065a1b6d63b26c]],
					msg = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					ct = [[]],
					shared = [[]],
					result = [[invalid]]
				},
				{
					tcId = 17,
					comment = [[Encapsulate with a non-canonical public key: first 12-bit coefficient set to 4095 (= 2^12 - 1, the maximum value representable in 12 bits, far above q). Must reject.]],
					targets = {
						[[NonCanonicalEk]]
					},
					flags = {
						[[NonCanonicalEk]],
						[[InputValidation]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					ekOverride = [[ff9f815e597d104355cf29aa5333c93251869d5bcdbe487124f602b8b6a66c16c4761648ad765cf5d8006b515e905a7f0ac076b0c62efa328153e7ca5701699f1305f1e6bc6f90b0e49b693512b6ce992a8b8016ddfc1a662c7e3f9619cbd869dd771af30896ccd5918ac6cb77466c5e779996d67ff9aabc97503f2c7b7e2d000d86450fb1807ca4cabda465825a31c789a1b7a491ab3872765d320d0b71920fa213c94093416b83b8124e69f65e62cb5000dcc37aa9a0fff73970c4772f357d24189ca6f5305568c0e2376a3762a68c605e563c5d209572e0fc7532ca294729535567b5fc413c5e8792d2464536cc808f98add74664f141566f9016a90a541829a98a0464ce41a8bb44c2d4fa3c2c209460728ef14a1a7c4c9b98d12203b4cc3529160a9ab2d7838f7ff6b53ae05aa31a7d646b7afa6c45932526a3c3755619be994c211c2a31c05b3447836cb2150be1829dae6b04c5535cff546e392ba797411720f924f490a5ac5495f21356d550b782a64c1688b6b655bcc7842197a434c2f6563b5b7f09a78bcc488232783561d16f4cbab6755400050781570c66604b817ad1252294736e8b01861a4b5a74519b8b6fe51489a5072392e587626c713776575d33806a1c8e2732af97c2680f51666331c4eb8bbc0431c4f96832daf1b3c45528fba153f6c78b1c198702947ccd337727a46fb53ba11de5cb4191346859516cb6ad72400f3cf209b236aef35a580ac87eb3e30fafd66973ca8a7dd2675af41f7a17b61433cd1af80f7708869f665488497980b1ac10a0cdcb636a00ed8681b35e429124ca80350725b85f83a5eac3a4a3cc1600903e65293560b9b336e5af0d529dac1a048119302cb7a9bcc110b94851bf02117f199dc485a852b7473f09b831a6831d5b54c0b790d225cf6bb92d9462a26cdb33dda5123c7aaf0e26a0b83655eea28bf3a8074725018fd6bae4b601cf61baab71a7a3d35197a343e74b4a272c125d540896426d85b7958d3b38a6ba987ec37225c7b44cdb12dde4539b4ab082363683f04bf7a09cc5c41dfe830a1b162e0b324334362f084a14467723344badd000f8d8c537c48f998f05307cebd1ede0b81c3bc59a065a1b6d63b26c]],
					msg = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					ct = [[]],
					shared = [[]],
					result = [[invalid]]
				},
				{
					tcId = 18,
					comment = [[Encapsulate with an all-zero public key (all coefficients = 0, all of rho = 0). Canonical encoding (0 < q) but degenerate; both impls accept. No security in practice — an adversary with the matching all-zero dk-stand-in could decapsulate. Tadashi records the deterministic output for cross-impl agreement.]],
					targets = {
						[[ZeroInput]],
						[[DegenerateKey]]
					},
					flags = {
						[[ZeroInput]],
						[[DegenerateKey]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					ekOverride = [[0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					msg = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					ct = [[54158e6aa3f5cb974e9fb667028f2d1ae1ab23bcd1bdcb82727b922ef886bfea9c9574339c3e943fdd431f82b1de52c7b98cc970d57c8b610884d9b5f8fd506a366ea42a95b08a7cdb3ce6ce2bb413983476dc08ad7e8f8db352234698ae945e460cd09755655890bcdabf7e22f106118883833f8a6a43059c75e4f2559547dc68a9dbdfcff3bc650ef19ae50355a8dec04ce8d25a1c9a843f2b87262809cb0f6224563fe93c840c263eb6bf641e3392ddca1dd7df74c4b9f2416cb07e11c134cc28dd636f6a65acc8bd0d9471d10fcc9e3bc90b372009409fade61a8c7147a3af45b50ba22c0dda03a68d957e7cf2c1a69a98020cbd65d87b94bd645f4eb468755f57e0198d9dfdcf125a4f4c5b1fa2e84338c66b9917f91749cfd0adf84e20a1c82ff9c4ab36acb1c8b06ed39d51851ee236c8e5abe17fe5efe7ea2f7c64e1a00c8730075d2f8f4f7bc3e2672e72e71c8328bc0f6f45a8784feb8d9c161e18191376365a3d60dd4e3cdefe4407572529b2207976d5683f083714f47f63bbacc8d16fdffd722d8d616cfed392588cc8cc8c84b1b7c4ae8d5e8a4005f38e6a8860b5720b8678516fb1028454bbb7ff3c058dd8fc408015a8ff920b48fd8977edfe18b785973c167871a6b9e68082d64008545a3c6933f1ccdc61e155dbea9046d15d4d0aab62a2619755c29a2e6b56ab87905f0b010fc5544b2e2ba53e64a0690d2029a703444e4ab32b31aed8436c4c7d0280c617944c9a0ccaef2f89b0b5b72c990b25b0c077da911fe2dd33838b963eaf7636df3794759bba15455b0e3db975d07c0b19fbc5482a1aa5153b2dc8aa786218f2a4c3cb461ab076f6a92ef5e2d8f0f80c888ce0a661274e10363cc54d419e364cb3e4ff63e458639c194e668e0000000008000000800000008800000000080000080800008008000088080000008000000880000080800000888000000088000008880000808800008888000000000800080008008000080088000800000808000808080080080800880808000080080008800800808008008880080000880800088808008088080088880800]],
					shared = [[79482694b9917372573c3bd2e2714766ec85e49302620747a27d515bf2cab133]],
					result = [[valid]]
				}
			}
		},
		{
			type = [[MlKemDecapsulate]],
			tests = {
				{
					tcId = 10,
					comment = [[ML-KEM-512 Decapsulate: round-trip with the all-zero KeyGen + all-zero Encapsulate. Shared must equal Encapsulate's output.]],
					targets = {
						[[Decapsulate]],
						[[RoundTrip]]
					},
					flags = {
						[[Ktv]],
						[[RoundTrip]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[0000000000000000000000000000000000000000000000000000000000000000]],
					z = [[0000000000000000000000000000000000000000000000000000000000000000]],
					dkOverride = [[]],
					ct = [[6bc50400277abb7e6bf9fb56820175ebb7b9f4f2822c6d0ae080a349920f6d008eba35b542b9d7ed89cbfd38d79f553bf08e638095cf0d4f5040ac1d1bdc24843b18c2779f241181a6ccd8f4e800dc266136d1b65d9c126df5e793c86dacaf3c783fa9c1006f08294f1a4d3bb44b6fc209004bc1f0e67f48480940f20a8618bfc64eb2b0abfe1bea91588c186e30e833872926efe90c3b8b0c994053b930ba17b38a74595d4c761ad33fe4f7a30f3a2c85c146f0a491a312b2a44b888d1c85b1e4411f9db7912f6098fdfc2989117d16099e76f19cb350b9d002d2a20dddee90470db94a5311a24f135a40dcc6fed72836eca05eabc17d193359e2e4ea26672fe505d8346e3cab638b2416c71b2a9be50478986c6c1e94e37f8652c017568d017a2881073d612acdc8b67e5bada890bd0c95b5099d7c348c748f8e7c286ce22fa2877f8043461cb21c5ad2ecadf955e36b195408841a3482f49cec3d65f9787f3747cff1cb15f2acff3b8fa08c25885c38239a27166adfa3981d16334b4ffb8385667603b9b54621b9f3f4f13a85ec9e566ab61dcccafb11ae477d93a5bc9032dea1a51e5d5217980a8bc41a287c9c223e33064077e5224986f93cc5c1b9772553665a18835a2bbfac047026e82bb60ce80095bb0875f337312eef288d5892d4fdd702ce8f118317531944d7d56d44043a0a0146f2d2a50588a0d90de1a07af2202e5b05e42b113db382643befc153ba9f7f2959873952da7bffd7dda1a99fa1e23874b094dcc5b5f361df9262e196876db42cc7f038e95efcff4c01c75939e59bfbf52b1be5f8250607c782462a99d0a96781d7a229961a948e7d517699ad61ecb6c0588ed09dff58571b2ead65d8dea5fa814b2c061bfe49204d5e1bb74096aa8125eb84dbea5d0baff98e41a6dd913a6854b72eb174fff50da73cc7305b55c62dc84cb4adccd0a11b41c723e8daffb73a12c2dc397cf4b950005388c87749fd703de0aa0c28d4a2ec825ddae8052fe89c21393a222f0a5c6d01dfc89f46f71502ad1935635558f57a46c97ae63384482bf0e7c57298436a99ba00574faa0a]],
					shared = [[4ad53a06b29f12568421a552c08195b58673c82f870cc1ccd65a08e4325feb27]],
					result = [[valid]]
				},
				{
					tcId = 11,
					comment = [[ML-KEM-512 Decapsulate: round-trip with incremental KeyGen + incremental message.]],
					targets = {
						[[Decapsulate]],
						[[RoundTrip]]
					},
					flags = {
						[[RoundTrip]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					dkOverride = [[]],
					ct = [[9a4ddbd3e08a1c9a45eec13d3ad97626b67af42128b34d5a37de399b2d8e97ec2e174f6de1318560a51381a31dd3dba79d902e10d14057f6ce3fbc30de25363541934e76cb2446dbd2cb8fea570baacb222c769a8e7ebfe49ce6a3d9f2add1cc0f21a1cb6395ba8634fbd02199549db4a349b2ae3619168a7fe66c62d808006e6608aa66cbb8167146b40c81a37152eeb47169a9c5b5d1064558cf1a59d0d15ace1893914f282406f51b9044992189b6664b8e2700c4485f1ee76af83c955d090ab8c0c49c128f9b6b5f89f372dba4bfd9d63fe521b309163b259791c5791cf834b9c22d06b3811c5268deee7de7f940e6248b963ef6335c18ea6150ef009a75eec0c2bf9702498e54e4cc33c8d969c1d8c8e1afbd5af1c955e746719dd8cfc138e17ce3cb04675a9bf2a5bc1e0444904f62228722b13e7c64fd79be91c2e346a9cfbda57ddcf805f6f9dda5bad3f15eb2dab119e5e7cffd8ef3fefe59ef1e49f56d6dab30528273cb3b824a836c593e4d44e9b9fb48610a280008a4110638917a49bd7ef5baaed79cff763fa555a95ac73b4694fd42220a96d56c080f5097c9bcea62aedf3804bd87a7d42e0b6f694fc3752d9a23d4009a6bc4738a3314e655dc8fb7cfeb1c4f830af0ab829fa315b39605ab42d23a142dbd0d9df7f20ca1f74365a3dd1eb19c32806bcd2540024e2589e5977f4fbf0b33014c19a1b67c0628f814f3071eadde644adba93a02590908444354587eafe94f138b270623086e381c027ae1d3a6fc62d1047213cccda3c916e814f2fd1a672d4466e57492febc51edce627a700ee707db38952c7ad9a81d44f4178a1aa11d41e16491aff6e5169fd5c7a623290cf509ee4cf7c51c86a8682700cf73ec9aec335a6844a7de7dcee9a93fcbf6eaad6911909f8fb036e731f1118fce5cc77cc4e5d4cf669354292a544378d77dbb0603dd41c733661dddf9651f20b30a311bcfeaeac82dcc94e918ef41e1cd64fb49fdd3f4a77c9f681a0f4a0a9abc43c3679fbaf7369b2afe66d80549fb2e489b815701d23275a4db0eb1234997c9d868aa431adca4aa513c600f4d]],
					shared = [[40a832e418f10e1000bda5faef8f682e85039dc6572dad28e436b65021031b6f]],
					result = [[valid]]
				},
				{
					tcId = 12,
					comment = [[ML-KEM-512 Decapsulate: bit 0 of ciphertext flipped, then decapsulated. The FO re-encryption check fails; output is the implicit-rejection value = SHAKE256(Z || ct'). MUST differ from the original shared (catches impls that return zero or the raw KPrime on FO mismatch).]],
					targets = {
						[[Decapsulate]],
						[[ImplicitRejection]],
						[[FOReencryption]]
					},
					flags = {
						[[ImplicitRejection]],
						[[BitFlip]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					dkOverride = [[]],
					ct = [[9b4ddbd3e08a1c9a45eec13d3ad97626b67af42128b34d5a37de399b2d8e97ec2e174f6de1318560a51381a31dd3dba79d902e10d14057f6ce3fbc30de25363541934e76cb2446dbd2cb8fea570baacb222c769a8e7ebfe49ce6a3d9f2add1cc0f21a1cb6395ba8634fbd02199549db4a349b2ae3619168a7fe66c62d808006e6608aa66cbb8167146b40c81a37152eeb47169a9c5b5d1064558cf1a59d0d15ace1893914f282406f51b9044992189b6664b8e2700c4485f1ee76af83c955d090ab8c0c49c128f9b6b5f89f372dba4bfd9d63fe521b309163b259791c5791cf834b9c22d06b3811c5268deee7de7f940e6248b963ef6335c18ea6150ef009a75eec0c2bf9702498e54e4cc33c8d969c1d8c8e1afbd5af1c955e746719dd8cfc138e17ce3cb04675a9bf2a5bc1e0444904f62228722b13e7c64fd79be91c2e346a9cfbda57ddcf805f6f9dda5bad3f15eb2dab119e5e7cffd8ef3fefe59ef1e49f56d6dab30528273cb3b824a836c593e4d44e9b9fb48610a280008a4110638917a49bd7ef5baaed79cff763fa555a95ac73b4694fd42220a96d56c080f5097c9bcea62aedf3804bd87a7d42e0b6f694fc3752d9a23d4009a6bc4738a3314e655dc8fb7cfeb1c4f830af0ab829fa315b39605ab42d23a142dbd0d9df7f20ca1f74365a3dd1eb19c32806bcd2540024e2589e5977f4fbf0b33014c19a1b67c0628f814f3071eadde644adba93a02590908444354587eafe94f138b270623086e381c027ae1d3a6fc62d1047213cccda3c916e814f2fd1a672d4466e57492febc51edce627a700ee707db38952c7ad9a81d44f4178a1aa11d41e16491aff6e5169fd5c7a623290cf509ee4cf7c51c86a8682700cf73ec9aec335a6844a7de7dcee9a93fcbf6eaad6911909f8fb036e731f1118fce5cc77cc4e5d4cf669354292a544378d77dbb0603dd41c733661dddf9651f20b30a311bcfeaeac82dcc94e918ef41e1cd64fb49fdd3f4a77c9f681a0f4a0a9abc43c3679fbaf7369b2afe66d80549fb2e489b815701d23275a4db0eb1234997c9d868aa431adca4aa513c600f4d]],
					shared = [[237613cd21e778aef215c907c6fd1fd6f6333303275e0fb132b6ec78b3f81fa4]],
					result = [[implicitRejection]]
				},
				{
					tcId = 13,
					comment = [[ML-KEM-512 Decapsulate: bit flipped near the middle of ciphertext. Same implicit-rejection path.]],
					targets = {
						[[Decapsulate]],
						[[ImplicitRejection]]
					},
					flags = {
						[[ImplicitRejection]],
						[[BitFlip]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					dkOverride = [[]],
					ct = [[9a4ddbd3e08a1c9a45eec13d3ad97626b67af42128b34d5a37de399b2d8e97ec2e174f6de1318560a51381a31dd3dba79d902e10d14057f6ce3fbc30de25363541934e76cb2446dbd2cb8fea570baacb222c769a8e7ebfe49ce6a3d9f2add1cc0f21a1cb6395ba8634fbd02199549db4a349b2ae3619168a7fe66c62d808006e6608aa66cbb8167146b40c81a37152eeb47169a9c5b5d1064558cf1a59d0d15ace1893914f282406f51b9044992189b6664b8e2700c4485f1ee76af83c955d090ab8c0c49c128f9b6b5f89f372dba4bfd9d63fe521b309163b259791c5791cf834b9c22d06b3811c5268deee7de7f940e6248b963ef6335c18ea6150ef009a75eec0c2bf9702498e54e4cc33c8d969c1d8c8e1afbd5af1c955e746719dd8cfc138e17ce3cb04675a9bf2a5bc1e0444904f62228722b13e7c64fd79be91c2e346a9cfbda57ddcf805f6f9dda5bad3f15eb2dab119e5e7cffd8ef3fefe59ef1e49f56d6dab30528273cb3b824a836c593e4d44e9b9fb48610a280008a4110638917b49bd7ef5baaed79cff763fa555a95ac73b4694fd42220a96d56c080f5097c9bcea62aedf3804bd87a7d42e0b6f694fc3752d9a23d4009a6bc4738a3314e655dc8fb7cfeb1c4f830af0ab829fa315b39605ab42d23a142dbd0d9df7f20ca1f74365a3dd1eb19c32806bcd2540024e2589e5977f4fbf0b33014c19a1b67c0628f814f3071eadde644adba93a02590908444354587eafe94f138b270623086e381c027ae1d3a6fc62d1047213cccda3c916e814f2fd1a672d4466e57492febc51edce627a700ee707db38952c7ad9a81d44f4178a1aa11d41e16491aff6e5169fd5c7a623290cf509ee4cf7c51c86a8682700cf73ec9aec335a6844a7de7dcee9a93fcbf6eaad6911909f8fb036e731f1118fce5cc77cc4e5d4cf669354292a544378d77dbb0603dd41c733661dddf9651f20b30a311bcfeaeac82dcc94e918ef41e1cd64fb49fdd3f4a77c9f681a0f4a0a9abc43c3679fbaf7369b2afe66d80549fb2e489b815701d23275a4db0eb1234997c9d868aa431adca4aa513c600f4d]],
					shared = [[763872c9309ead4784bfd5edbe42e5179c6f5f18f879568c5e062bd70df74ece]],
					result = [[implicitRejection]]
				},
				{
					tcId = 14,
					comment = [[ML-KEM-512 Decapsulate: pseudorandom ciphertext (not derived from any Encapsulate). Implicit rejection path.]],
					targets = {
						[[Decapsulate]],
						[[ImplicitRejection]],
						[[RandomCiphertext]]
					},
					flags = {
						[[ImplicitRejection]],
						[[RandomCiphertext]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					dkOverride = [[]],
					ct = [[55565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051525354]],
					shared = [[532388deb7167bd14e9772774233f5de03246c9a8a9952ce8d628fbfc4eabdae]],
					result = [[implicitRejection]]
				},
				{
					tcId = 15,
					comment = [[ML-KEM-512 Decapsulate: dk from incremental seeds, ct from all-0xff seeds. Cross-key forgery; implicit rejection.]],
					targets = {
						[[Decapsulate]],
						[[ImplicitRejection]],
						[[CrossKey]]
					},
					flags = {
						[[ImplicitRejection]],
						[[CrossKey]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					dkOverride = [[]],
					ct = [[99993eabf4ecd21d0d156932451644d76bf68aa61963547a45ffa69640173d568f2eb032e653999307fc96e2dacebb37ada5ec8d7ec6454e97f9d8c6ae345d6581ff896450d8ba0f24e149f45d8fc1bdd1179a4ace6ef62fc3348ec3eb5db1b4c74680847600e4f0089f523e841e80155d0e790466050582188a187e55a7f411ff55cacc70eb2a727b0f7f790b821f9d7724c23377cf12ad24a90e705f5876ec36704777711f88487531a1f13545727a83fe6c4e872d112f93fe7a4069e0ae2f3c7bbbb2bfbbf7da160b3aa90407c4a68c9da6a970757a5a3f3adbf27280934122ff08f331678ad30b277a9ccc6fd65e955f6a6056498f308b267bf47f2fe4c3b43b83c40ef62f93191d9efa5076d4e2f0953a4f6d8c660bb56d1a6952afbaee5677608c43a049f11d65935ad9ef488fee23e33f278b3bb6933ee3343941ebb4e69c5a0525d3ec5b4db00991ed2816165de75238adebb8d9a8c32a561648e5a65dcc283455df7762e815457748d7ff3fbdc60623c30cdcf53acf4b1b62b43126305b8371bb71806edc919d51b5361b6bcedabdecc269ed3d720b9f41cadc52796003dbfccd3f52675491073335ccbf2415a180db816834396e234617e42b5bddfc6bc54db4288be805531af964a798dccbbf456480a5fc8ff6bdc532c87feab772149bb71612aa900770254deeead07cd201c3310a0fbe1ec3c75905665c2b3788f6699817341168af86cdffc33ebc4031b68941854518bfd9f89ca3ab99e002c8fa0c52249c7107b1617c53d198360112379a04597cb013777118413425e81dfb90a95fd8a329bd347bbf3191e5bcd07c2923e15a407c30e3cbbcdf2fe4f7e690147049ea265658117aa56a5504ccce1fddc90e3e608dfa3af9390964d4a23a5caf471ac399a7207255214704b30483dba7b0bfef74ca27759e3999a79fe63f9e3bcf0115327a34882f215dcb549df183860d5351ba6cfa0582dc51eb1ffa7ad46eff33007280d7d6cdf9556d4a0e55c078097bbfdb7195cb1538e0afc2aa0d7564ed3befc70a675d11be245c4e5cdbef3ab2bd3633fa7c3aa11ce81e5a5e3a]],
					shared = [[305c9956398f815201b2a160c07ed093b5f5ecb7100d6fc795d1c1072f5d7e3c]],
					result = [[implicitRejection]]
				},
				{
					tcId = 20,
					comment = [[C2SP/CCTV strcmp vector for ML-KEM-512: ciphertext crafted so that the FO re-encryption check has matching null-byte prefixes. If Decaps uses strcmp instead of memcmp the comparison short-circuits and the implicit-rejection path is skipped, yielding the wrong K.]],
					targets = {
						[[StrcmpVsMemcmp]],
						[[FOReencryption]]
					},
					flags = {
						[[StrcmpVsMemcmp]]
					},
					source = {
						name = [[c2sp-cctv]],
						version = [[strcmp/ML-KEM-512]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[0000000000000000000000000000000000000000000000000000000000000000]],
					z = [[0000000000000000000000000000000000000000000000000000000000000000]],
					dkOverride = [[5961ad4848355fd421beb06e2557b15909a87fc4c5a662964fc96d81692bd631002f341727359eb02a779be4285932ba25f96ea170a4a11c51f5352d8f6c0d20c02151c567aef2ca08342c7e09b68aea38b11c2989fa1942eb66946240e5cb4d57384567f800fa0102fa0505d891b529124f0f796e3f85cd26b0ac63d865a63476fde55593db3a9c69ce175bb97fc864f333ad074a887428733698ba808a605bc846fb72be53cb8c43b54e2bd8340d197c20dac1cc028ecbb136c126895fca2fd5463f0c021a57b15627c1011b01b180bb3f27124a01f74a0392460bfb896d3bb8b7a9af588874fe8b9205771cc5a079c0a21dcc88b77cba67162646f88b4decf97fd96a226b39a8814ab915c19b50ab22901c3627acb86062155b164e007c411522a571d71455e22778b49c038316fcd6cadf4111753292f7f0276e39737e92272e811298c471afd24d18f2a70e7574c9f7a385c8490669868e3374dd6496030bbec527b400fa5aec089e225776a868594af22ec2f96bf3220374875b39e07184696881077c9e70bde1f052716118b7918ca7b475cb5b4d86669ad35373ee49bbead52f210464ee27ad6b4c1171b1980c974a1a8489b3f3c47a1cb7b5cbc841f960b226bbc7394a056013ee49897c9a4c82b3ab5d4a2068772a22071f15fc428217361e200745ab94cb2c63235a9a746403fb0a72d2d2c36bac110bcc9fc37335266616b86875deb560dc2a19fda2bf17352966d00a07f24bc4b60c24d54c07b0627a3c507ecc48b22a32fcd423d6c3a6014c0ec7a75b3384a5044019e8f211d8623785167b18e5398fb63e22ab6e62ca8c6316110ab4391a13c067060aea5b47788b55a9aa3bbe41acd5599d952c8f1cb4770d267d8c10a98df31be6681e23b01e4b48031565123a5656c13165b46690497c0b25d4467cf839389220c3639f5d57a03090cd261a9a36c59d032674231843986022e0a2190de9657c0a350840b47c06a036c047c8816947da4b1c16a7c6e0c63971208968331cb2b368d98428596b75562076a330bc1cced9978049c15e111967159130756c69cd939a5b904ccb23cf669a01d44a0d329bbd75eb42aef97402a1cd9263909cd678630656f4162b55b881144595f693c114b32aaed662c20787ab48c71a67b7e1d597ed493f3420cb561cac812549c2cba5c135b563e9592ba195d1fb8cb4444fab75191579618dd43fca27515f110641c352df20780ad0089112aa64d34eeb00a6490ad09bb4bbc6c42d0ad804726bc1bf5bcad24746eb1a4b8701acaf2a82f0c0a2d9d84777b395ec4a953c7cc213b3070e7714e82120c92c173c3661862899da6832240955a372737f055b4d88688a5c2c55c4a3b70780119b3653ab7692c3c731ba7c91e55f89637d8fb29262618e32e9cff14abc3648024c64310b47027ee4cf1d5985de9251520bca3d716eb9989123d298587c7029c714202132a6f14d51920cfdf2b89ff58a4bcaaec8bb7b888013c155a0e93558e2ba3ff6e8058f26156fbca16702c599d2cf323bb771945e1fdc918a428a00f69573fa3cd8088b6228480b91cbe27aa3e5da2571363880a235cd664fdff18bb12c68989476ee56386ea0883be2c458864949ab3524a4be228763c27524593b25d8e95af656942f77b820d42055454f07f2085fb11305513ba8511f9a4360caf09bae125ebbb972988acd1b6a16e9537e27713a7fa865cf426d97d266bdda5a99b19066b8b03872c6299591b40a2833c57ad97754b8b88440637fc9b332c039b4c2c2261b548ad384098efb7d100693dd9a30cc779f7a7187e146c9d1d93ab7e96fe13504ec043bd6c465b365786b244b7990195f76c66efcabe0ec92f0b302a749817953836d3070da8a4596545a0afac70dfc989bb0b16fd05e0db948cb1b8995c8c4d73730bccb0beb7336d7f2074270275f1b734f977c9fe641f45770fdec292f28c85ae0488b9c32e90730e373bce63966228a0622e4a17cb04d3c608f3ba3633dfb727bb1ab93fa2543f972e3e45d9d481288cbcbfc9a6fa8d656c7a7563e028e65713ac94023cfd15e244274244c38d57158e7e360426b84191a94c55537c18c4a7d0a880939a0097a798f1534d979ca79dc224f48068552561e11163b6c2a79c5c6dd3ac8203c96672935c131558e1550841be848115fc8aae866ceb49f6ff7cc2bc19cddda6f052930dc583aebb50ec2e2baedda9ee6f8771c312a796dd418ae26fa0f65cace005792076f44f152c8cc97c8b4802a4b5d4550a8eee465eed6b36666e929d5d4095a12ed]],
					ct = [[00f16e1645a08634736c206fbd6f6a5942f609a3449a18d3bb8cdae503f69cd728957ded842f7cb84abc7802b346acfbd1881aad3168d452e5359e002641de5ff04f067e1a68192ad966b2f127a56aab0bfe4789122000e356f71556e5d414075269b128e21168770560b5a4e92fefff74233e6836e1d4fc18f8ef3f93d17dca8fe41c2fcb93a2217fc53c551e7ddf947f43b07e1c60fd8a7aff778a7227aaf00b6349287a44303e7b3e9779744695061e45a26113b568879b8685fbae6d3513983ad39e8604abe448ea5c950c43d6dded934bfae51c8c34ae22f4a3e0e35781bab8a4fbdc888b9057d553b9679185481c2f18caead15704143e7bd3f3497ebc232ea4172767f462c0e14c597d8ef008a776c1134283acf777746f4fc63a56e57217e3ecaf6f4065924ec52f6429b2bef71ff1ad5736c54c07a44bf544dfa60dfd9893f2f8746642dce0e5d463300056c4375efdd299a1211fa1605a46d52e3b3a4f1031db95c88f6772c03eb076c49042fb2d59dcf45c1fc589f773117c3895aa7aec83685049d489ed7173aa1d8aa75badff731acd50ee2e569920f7c7941b47a7dec566d09958a907f0779b7a0b1dcf6409b3078960adfa494004fa201b714d4b46d606ae3cb7e30feacb137a0679c1b0df51ca1f523e8603c76b8a9114945215d883857f7aded8d16df86dae7cf6dc838fe4c3606c9cefbba0d428656a4615063dfb7336c4aba005d7703883a70292e736461ef562737c9b86ab349d9fb852ae69c570e3c353692d8c0fb609c6f8beb862f4e4fca4ce1eb14ceb0cf667e132c086a2ac4acdfb3f7d50abb40f805e533d715c6bc120a14d337a0fa06121ce367c727d61b8e7fcd34f575b4c4549614f1f5a9628d29f3a11491c04d3630cc2753de0e6b2d7be78a0c4a94453c53437131809763c9b82311877399589a34f395ce035e0d462a123723e5684677654ffda40f65474dc2b2175292a4e443773595fb9e9c3ded7eb05e3aea1b90cd2621669fd2046f486259fbd6fd41d2163725ead11a1f0a7e99c31de89d421d3327d3312f29fe34fb5c8645aaeeaf486e04c7a]],
					shared = [[3f238984ba263b21b17267a4fcbc3d6d803d2d4f122f746b44e9a5a1592ea6b7]],
					result = [[valid]]
				},
				{
					tcId = 21,
					comment = [[Decapsulate with dk whose embedded H(ek) field has bit 7 of byte 0 flipped. FIPS 203 Algorithm 24 (dkCheck) defines an optional check that the stored H equals SHA3-256(stored ek); Algorithm 19 (Decaps) itself does not require it. rbx-crypto silently uses the corrupted H field and produces a different (garbage) shared; @noble/post-quantum rejects via 'hash check failed'. Both behaviors are spec-compliant.]],
					targets = {
						[[DkValidation]],
						[[HFieldTamper]]
					},
					flags = {
						[[DkValidation]],
						[[Acceptable]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/post-quantum]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					dkOverride = [[70554fd436344f2785b1b3b1bac184b6679003336c26f15a7de878c4825c6be03f3c4a480f75b7486aad31d3a00518623fd207ab528dd62721495835ae0062c367b74a71baf10aad0e8a2902076be31348beb15ccc0957cdebb4aff226756bbc601b6568ab784acbaeb34702f0f86a26202118b22b23f83558776c79c14dba983379c803e0dcc3160a11757030e69c6919798d81eb698a9a4483a99e5a5cb2c31c9a661799f3cc89c790706ea041629045d42a83aed88860e394c69187e2105d28cc14ec393592d67dd00aa43fe8b4eae4414002866b5c713c6a8d7d16cf78b819d6f12e9e5a74233908f0b15e3c4ba8329c5cdda55c84928e3aa8063e5aa9676403f91735b11010c7f593091364dc86445bc804840a9a21724212469f8a7b0ce0ac698eb86cad39a7f4824d9a5163aac21ee6808b053c8a3facb0b6744b5262bbcb26a43f664c8732b64cfc7acf099605f41c796060976ac433833fe00343fb1828300a424741116e4b45bb276ea81129a0db4c6e60bce611101e8c625474925e0222679308a3e7708d1972a7b423eb232851c36d2ed53d3ed3bb7500637061a5dc2292fa1c466c07354683328bec2c1ed2cb5c99b78eca0969038cf7c34dd118724e31cae086206b34302b520f5d177aded5b3cce02acce808ea26bcc072625fdb93f17458a5fc1d4da394380a1f57e9cc66109438a075f0d2813fcc4a199cc76db3823f270b0061594192940411a37ffbafae2c150165cec5c6bf73c595fb92cd15312607da070778652bd9944bc48bc7d1a534338bad0bad6656c5d502ce7850ab1587244eeb58f439ab5e08574a718c8aac3d77c798bba1542733be73448f23fb70c0e5353a27c88322c5218493afbb38086434d6d60a56ba887dd498c3ab26a0870993815aa6a40975f218adca1582d64ffc8652fbb3a9a6fbc304f91945fa4aaef2878fd715df70113d2379f44886f812c83ff2b719a69e1ec74ae4b15accd3aed5a53ce76a7b0982471633b973cb40a1a0015d0a424fa11a479c023017436d2a2900e993eb5a0a067400c7f4aadf201fc4fa31264a63bae95cc8d65c3995815e597d104355cf29aa5333c93251869d5bcdbe487124f602b8b6a66c16c4761648ad765cf5d8006b515e905a7f0ac076b0c62efa328153e7ca5701699f1305f1e6bc6f90b0e49b693512b6ce992a8b8016ddfc1a662c7e3f9619cbd869dd771af30896ccd5918ac6cb77466c5e779996d67ff9aabc97503f2c7b7e2d000d86450fb1807ca4cabda465825a31c789a1b7a491ab3872765d320d0b71920fa213c94093416b83b8124e69f65e62cb5000dcc37aa9a0fff73970c4772f357d24189ca6f5305568c0e2376a3762a68c605e563c5d209572e0fc7532ca294729535567b5fc413c5e8792d2464536cc808f98add74664f141566f9016a90a541829a98a0464ce41a8bb44c2d4fa3c2c209460728ef14a1a7c4c9b98d12203b4cc3529160a9ab2d7838f7ff6b53ae05aa31a7d646b7afa6c45932526a3c3755619be994c211c2a31c05b3447836cb2150be1829dae6b04c5535cff546e392ba797411720f924f490a5ac5495f21356d550b782a64c1688b6b655bcc7842197a434c2f6563b5b7f09a78bcc488232783561d16f4cbab6755400050781570c66604b817ad1252294736e8b01861a4b5a74519b8b6fe51489a5072392e587626c713776575d33806a1c8e2732af97c2680f51666331c4eb8bbc0431c4f96832daf1b3c45528fba153f6c78b1c198702947ccd337727a46fb53ba11de5cb4191346859516cb6ad72400f3cf209b236aef35a580ac87eb3e30fafd66973ca8a7dd2675af41f7a17b61433cd1af80f7708869f665488497980b1ac10a0cdcb636a00ed8681b35e429124ca80350725b85f83a5eac3a4a3cc1600903e65293560b9b336e5af0d529dac1a048119302cb7a9bcc110b94851bf02117f199dc485a852b7473f09b831a6831d5b54c0b790d225cf6bb92d9462a26cdb33dda5123c7aaf0e26a0b83655eea28bf3a8074725018fd6bae4b601cf61baab71a7a3d35197a343e74b4a272c125d540896426d85b7958d3b38a6ba987ec37225c7b44cdb12dde4539b4ab082363683f04bf7a09cc5c41dfe830a1b162e0b324334362f084a14467723344badd000f8d8c537c48f998f05307cebd1ede0b81c3bc59a065a1b6d63b26c7df101ff648063b376e2bb6c5b7455f655a50c2feadade150efa0e0e6f365aea202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					ct = [[9a4ddbd3e08a1c9a45eec13d3ad97626b67af42128b34d5a37de399b2d8e97ec2e174f6de1318560a51381a31dd3dba79d902e10d14057f6ce3fbc30de25363541934e76cb2446dbd2cb8fea570baacb222c769a8e7ebfe49ce6a3d9f2add1cc0f21a1cb6395ba8634fbd02199549db4a349b2ae3619168a7fe66c62d808006e6608aa66cbb8167146b40c81a37152eeb47169a9c5b5d1064558cf1a59d0d15ace1893914f282406f51b9044992189b6664b8e2700c4485f1ee76af83c955d090ab8c0c49c128f9b6b5f89f372dba4bfd9d63fe521b309163b259791c5791cf834b9c22d06b3811c5268deee7de7f940e6248b963ef6335c18ea6150ef009a75eec0c2bf9702498e54e4cc33c8d969c1d8c8e1afbd5af1c955e746719dd8cfc138e17ce3cb04675a9bf2a5bc1e0444904f62228722b13e7c64fd79be91c2e346a9cfbda57ddcf805f6f9dda5bad3f15eb2dab119e5e7cffd8ef3fefe59ef1e49f56d6dab30528273cb3b824a836c593e4d44e9b9fb48610a280008a4110638917a49bd7ef5baaed79cff763fa555a95ac73b4694fd42220a96d56c080f5097c9bcea62aedf3804bd87a7d42e0b6f694fc3752d9a23d4009a6bc4738a3314e655dc8fb7cfeb1c4f830af0ab829fa315b39605ab42d23a142dbd0d9df7f20ca1f74365a3dd1eb19c32806bcd2540024e2589e5977f4fbf0b33014c19a1b67c0628f814f3071eadde644adba93a02590908444354587eafe94f138b270623086e381c027ae1d3a6fc62d1047213cccda3c916e814f2fd1a672d4466e57492febc51edce627a700ee707db38952c7ad9a81d44f4178a1aa11d41e16491aff6e5169fd5c7a623290cf509ee4cf7c51c86a8682700cf73ec9aec335a6844a7de7dcee9a93fcbf6eaad6911909f8fb036e731f1118fce5cc77cc4e5d4cf669354292a544378d77dbb0603dd41c733661dddf9651f20b30a311bcfeaeac82dcc94e918ef41e1cd64fb49fdd3f4a77c9f681a0f4a0a9abc43c3679fbaf7369b2afe66d80549fb2e489b815701d23275a4db0eb1234997c9d868aa431adca4aa513c600f4d]],
					shared = [[1c859c4aefbe56fc4081c8a96c44b878e877808157bd1ca2d2b2e1e9bca36cc6]],
					result = [[acceptable]]
				},
				{
					tcId = 22,
					comment = [[ML-KEM-512 Decapsulate with dk whose first 12-bit s-hat coefficient is set to 4095 (>= q = 3329). Decaps never validates dk coefficient ranges; any non-rejecting handling corrupts decryption, the FO re-encryption check fails, and the output converges on SHAKE256(z || ct) regardless of how the bad coefficient was decoded. Strict dk validators may instead cleanly reject.]],
					targets = {
						[[NonCanonicalDk]],
						[[ImplicitRejection]],
						[[InputValidation]]
					},
					flags = {
						[[NonCanonicalDk]],
						[[Acceptable]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					dkOverride = [[ffff4fd436344f2785b1b3b1bac184b6679003336c26f15a7de878c4825c6be03f3c4a480f75b7486aad31d3a00518623fd207ab528dd62721495835ae0062c367b74a71baf10aad0e8a2902076be31348beb15ccc0957cdebb4aff226756bbc601b6568ab784acbaeb34702f0f86a26202118b22b23f83558776c79c14dba983379c803e0dcc3160a11757030e69c6919798d81eb698a9a4483a99e5a5cb2c31c9a661799f3cc89c790706ea041629045d42a83aed88860e394c69187e2105d28cc14ec393592d67dd00aa43fe8b4eae4414002866b5c713c6a8d7d16cf78b819d6f12e9e5a74233908f0b15e3c4ba8329c5cdda55c84928e3aa8063e5aa9676403f91735b11010c7f593091364dc86445bc804840a9a21724212469f8a7b0ce0ac698eb86cad39a7f4824d9a5163aac21ee6808b053c8a3facb0b6744b5262bbcb26a43f664c8732b64cfc7acf099605f41c796060976ac433833fe00343fb1828300a424741116e4b45bb276ea81129a0db4c6e60bce611101e8c625474925e0222679308a3e7708d1972a7b423eb232851c36d2ed53d3ed3bb7500637061a5dc2292fa1c466c07354683328bec2c1ed2cb5c99b78eca0969038cf7c34dd118724e31cae086206b34302b520f5d177aded5b3cce02acce808ea26bcc072625fdb93f17458a5fc1d4da394380a1f57e9cc66109438a075f0d2813fcc4a199cc76db3823f270b0061594192940411a37ffbafae2c150165cec5c6bf73c595fb92cd15312607da070778652bd9944bc48bc7d1a534338bad0bad6656c5d502ce7850ab1587244eeb58f439ab5e08574a718c8aac3d77c798bba1542733be73448f23fb70c0e5353a27c88322c5218493afbb38086434d6d60a56ba887dd498c3ab26a0870993815aa6a40975f218adca1582d64ffc8652fbb3a9a6fbc304f91945fa4aaef2878fd715df70113d2379f44886f812c83ff2b719a69e1ec74ae4b15accd3aed5a53ce76a7b0982471633b973cb40a1a0015d0a424fa11a479c023017436d2a2900e993eb5a0a067400c7f4aadf201fc4fa31264a63bae95cc8d65c3995815e597d104355cf29aa5333c93251869d5bcdbe487124f602b8b6a66c16c4761648ad765cf5d8006b515e905a7f0ac076b0c62efa328153e7ca5701699f1305f1e6bc6f90b0e49b693512b6ce992a8b8016ddfc1a662c7e3f9619cbd869dd771af30896ccd5918ac6cb77466c5e779996d67ff9aabc97503f2c7b7e2d000d86450fb1807ca4cabda465825a31c789a1b7a491ab3872765d320d0b71920fa213c94093416b83b8124e69f65e62cb5000dcc37aa9a0fff73970c4772f357d24189ca6f5305568c0e2376a3762a68c605e563c5d209572e0fc7532ca294729535567b5fc413c5e8792d2464536cc808f98add74664f141566f9016a90a541829a98a0464ce41a8bb44c2d4fa3c2c209460728ef14a1a7c4c9b98d12203b4cc3529160a9ab2d7838f7ff6b53ae05aa31a7d646b7afa6c45932526a3c3755619be994c211c2a31c05b3447836cb2150be1829dae6b04c5535cff546e392ba797411720f924f490a5ac5495f21356d550b782a64c1688b6b655bcc7842197a434c2f6563b5b7f09a78bcc488232783561d16f4cbab6755400050781570c66604b817ad1252294736e8b01861a4b5a74519b8b6fe51489a5072392e587626c713776575d33806a1c8e2732af97c2680f51666331c4eb8bbc0431c4f96832daf1b3c45528fba153f6c78b1c198702947ccd337727a46fb53ba11de5cb4191346859516cb6ad72400f3cf209b236aef35a580ac87eb3e30fafd66973ca8a7dd2675af41f7a17b61433cd1af80f7708869f665488497980b1ac10a0cdcb636a00ed8681b35e429124ca80350725b85f83a5eac3a4a3cc1600903e65293560b9b336e5af0d529dac1a048119302cb7a9bcc110b94851bf02117f199dc485a852b7473f09b831a6831d5b54c0b790d225cf6bb92d9462a26cdb33dda5123c7aaf0e26a0b83655eea28bf3a8074725018fd6bae4b601cf61baab71a7a3d35197a343e74b4a272c125d540896426d85b7958d3b38a6ba987ec37225c7b44cdb12dde4539b4ab082363683f04bf7a09cc5c41dfe830a1b162e0b324334362f084a14467723344badd000f8d8c537c48f998f05307cebd1ede0b81c3bc59a065a1b6d63b26c82f101ff648063b376e2bb6c5b7455f655a50c2feadade150efa0e0e6f365aea202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					ct = [[9a4ddbd3e08a1c9a45eec13d3ad97626b67af42128b34d5a37de399b2d8e97ec2e174f6de1318560a51381a31dd3dba79d902e10d14057f6ce3fbc30de25363541934e76cb2446dbd2cb8fea570baacb222c769a8e7ebfe49ce6a3d9f2add1cc0f21a1cb6395ba8634fbd02199549db4a349b2ae3619168a7fe66c62d808006e6608aa66cbb8167146b40c81a37152eeb47169a9c5b5d1064558cf1a59d0d15ace1893914f282406f51b9044992189b6664b8e2700c4485f1ee76af83c955d090ab8c0c49c128f9b6b5f89f372dba4bfd9d63fe521b309163b259791c5791cf834b9c22d06b3811c5268deee7de7f940e6248b963ef6335c18ea6150ef009a75eec0c2bf9702498e54e4cc33c8d969c1d8c8e1afbd5af1c955e746719dd8cfc138e17ce3cb04675a9bf2a5bc1e0444904f62228722b13e7c64fd79be91c2e346a9cfbda57ddcf805f6f9dda5bad3f15eb2dab119e5e7cffd8ef3fefe59ef1e49f56d6dab30528273cb3b824a836c593e4d44e9b9fb48610a280008a4110638917a49bd7ef5baaed79cff763fa555a95ac73b4694fd42220a96d56c080f5097c9bcea62aedf3804bd87a7d42e0b6f694fc3752d9a23d4009a6bc4738a3314e655dc8fb7cfeb1c4f830af0ab829fa315b39605ab42d23a142dbd0d9df7f20ca1f74365a3dd1eb19c32806bcd2540024e2589e5977f4fbf0b33014c19a1b67c0628f814f3071eadde644adba93a02590908444354587eafe94f138b270623086e381c027ae1d3a6fc62d1047213cccda3c916e814f2fd1a672d4466e57492febc51edce627a700ee707db38952c7ad9a81d44f4178a1aa11d41e16491aff6e5169fd5c7a623290cf509ee4cf7c51c86a8682700cf73ec9aec335a6844a7de7dcee9a93fcbf6eaad6911909f8fb036e731f1118fce5cc77cc4e5d4cf669354292a544378d77dbb0603dd41c733661dddf9651f20b30a311bcfeaeac82dcc94e918ef41e1cd64fb49fdd3f4a77c9f681a0f4a0a9abc43c3679fbaf7369b2afe66d80549fb2e489b815701d23275a4db0eb1234997c9d868aa431adca4aa513c600f4d]],
					shared = [[1c859c4aefbe56fc4081c8a96c44b878e877808157bd1ca2d2b2e1e9bca36cc6]],
					result = [[acceptable]]
				},
				{
					tcId = 23,
					comment = [[ML-KEM-512 Decapsulate with dk whose embedded ek has its first 12-bit t-hat coefficient set to 4095 (>= q). The corruption lies past the s-hat region, so decryption itself succeeds and the bad value is first touched during FO re-encryption; the output converges on SHAKE256(z || ct) for every non-rejecting implementation. Strict dk validators may instead cleanly reject.]],
					targets = {
						[[NonCanonicalDk]],
						[[ImplicitRejection]],
						[[FOReencryption]]
					},
					flags = {
						[[NonCanonicalDk]],
						[[Acceptable]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[rbx-cryptography]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					dkOverride = [[70554fd436344f2785b1b3b1bac184b6679003336c26f15a7de878c4825c6be03f3c4a480f75b7486aad31d3a00518623fd207ab528dd62721495835ae0062c367b74a71baf10aad0e8a2902076be31348beb15ccc0957cdebb4aff226756bbc601b6568ab784acbaeb34702f0f86a26202118b22b23f83558776c79c14dba983379c803e0dcc3160a11757030e69c6919798d81eb698a9a4483a99e5a5cb2c31c9a661799f3cc89c790706ea041629045d42a83aed88860e394c69187e2105d28cc14ec393592d67dd00aa43fe8b4eae4414002866b5c713c6a8d7d16cf78b819d6f12e9e5a74233908f0b15e3c4ba8329c5cdda55c84928e3aa8063e5aa9676403f91735b11010c7f593091364dc86445bc804840a9a21724212469f8a7b0ce0ac698eb86cad39a7f4824d9a5163aac21ee6808b053c8a3facb0b6744b5262bbcb26a43f664c8732b64cfc7acf099605f41c796060976ac433833fe00343fb1828300a424741116e4b45bb276ea81129a0db4c6e60bce611101e8c625474925e0222679308a3e7708d1972a7b423eb232851c36d2ed53d3ed3bb7500637061a5dc2292fa1c466c07354683328bec2c1ed2cb5c99b78eca0969038cf7c34dd118724e31cae086206b34302b520f5d177aded5b3cce02acce808ea26bcc072625fdb93f17458a5fc1d4da394380a1f57e9cc66109438a075f0d2813fcc4a199cc76db3823f270b0061594192940411a37ffbafae2c150165cec5c6bf73c595fb92cd15312607da070778652bd9944bc48bc7d1a534338bad0bad6656c5d502ce7850ab1587244eeb58f439ab5e08574a718c8aac3d77c798bba1542733be73448f23fb70c0e5353a27c88322c5218493afbb38086434d6d60a56ba887dd498c3ab26a0870993815aa6a40975f218adca1582d64ffc8652fbb3a9a6fbc304f91945fa4aaef2878fd715df70113d2379f44886f812c83ff2b719a69e1ec74ae4b15accd3aed5a53ce76a7b0982471633b973cb40a1a0015d0a424fa11a479c023017436d2a2900e993eb5a0a067400c7f4aadf201fc4fa31264a63bae95cc8d65cffff815e597d104355cf29aa5333c93251869d5bcdbe487124f602b8b6a66c16c4761648ad765cf5d8006b515e905a7f0ac076b0c62efa328153e7ca5701699f1305f1e6bc6f90b0e49b693512b6ce992a8b8016ddfc1a662c7e3f9619cbd869dd771af30896ccd5918ac6cb77466c5e779996d67ff9aabc97503f2c7b7e2d000d86450fb1807ca4cabda465825a31c789a1b7a491ab3872765d320d0b71920fa213c94093416b83b8124e69f65e62cb5000dcc37aa9a0fff73970c4772f357d24189ca6f5305568c0e2376a3762a68c605e563c5d209572e0fc7532ca294729535567b5fc413c5e8792d2464536cc808f98add74664f141566f9016a90a541829a98a0464ce41a8bb44c2d4fa3c2c209460728ef14a1a7c4c9b98d12203b4cc3529160a9ab2d7838f7ff6b53ae05aa31a7d646b7afa6c45932526a3c3755619be994c211c2a31c05b3447836cb2150be1829dae6b04c5535cff546e392ba797411720f924f490a5ac5495f21356d550b782a64c1688b6b655bcc7842197a434c2f6563b5b7f09a78bcc488232783561d16f4cbab6755400050781570c66604b817ad1252294736e8b01861a4b5a74519b8b6fe51489a5072392e587626c713776575d33806a1c8e2732af97c2680f51666331c4eb8bbc0431c4f96832daf1b3c45528fba153f6c78b1c198702947ccd337727a46fb53ba11de5cb4191346859516cb6ad72400f3cf209b236aef35a580ac87eb3e30fafd66973ca8a7dd2675af41f7a17b61433cd1af80f7708869f665488497980b1ac10a0cdcb636a00ed8681b35e429124ca80350725b85f83a5eac3a4a3cc1600903e65293560b9b336e5af0d529dac1a048119302cb7a9bcc110b94851bf02117f199dc485a852b7473f09b831a6831d5b54c0b790d225cf6bb92d9462a26cdb33dda5123c7aaf0e26a0b83655eea28bf3a8074725018fd6bae4b601cf61baab71a7a3d35197a343e74b4a272c125d540896426d85b7958d3b38a6ba987ec37225c7b44cdb12dde4539b4ab082363683f04bf7a09cc5c41dfe830a1b162e0b324334362f084a14467723344badd000f8d8c537c48f998f05307cebd1ede0b81c3bc59a065a1b6d63b26c82f101ff648063b376e2bb6c5b7455f655a50c2feadade150efa0e0e6f365aea202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f]],
					ct = [[9a4ddbd3e08a1c9a45eec13d3ad97626b67af42128b34d5a37de399b2d8e97ec2e174f6de1318560a51381a31dd3dba79d902e10d14057f6ce3fbc30de25363541934e76cb2446dbd2cb8fea570baacb222c769a8e7ebfe49ce6a3d9f2add1cc0f21a1cb6395ba8634fbd02199549db4a349b2ae3619168a7fe66c62d808006e6608aa66cbb8167146b40c81a37152eeb47169a9c5b5d1064558cf1a59d0d15ace1893914f282406f51b9044992189b6664b8e2700c4485f1ee76af83c955d090ab8c0c49c128f9b6b5f89f372dba4bfd9d63fe521b309163b259791c5791cf834b9c22d06b3811c5268deee7de7f940e6248b963ef6335c18ea6150ef009a75eec0c2bf9702498e54e4cc33c8d969c1d8c8e1afbd5af1c955e746719dd8cfc138e17ce3cb04675a9bf2a5bc1e0444904f62228722b13e7c64fd79be91c2e346a9cfbda57ddcf805f6f9dda5bad3f15eb2dab119e5e7cffd8ef3fefe59ef1e49f56d6dab30528273cb3b824a836c593e4d44e9b9fb48610a280008a4110638917a49bd7ef5baaed79cff763fa555a95ac73b4694fd42220a96d56c080f5097c9bcea62aedf3804bd87a7d42e0b6f694fc3752d9a23d4009a6bc4738a3314e655dc8fb7cfeb1c4f830af0ab829fa315b39605ab42d23a142dbd0d9df7f20ca1f74365a3dd1eb19c32806bcd2540024e2589e5977f4fbf0b33014c19a1b67c0628f814f3071eadde644adba93a02590908444354587eafe94f138b270623086e381c027ae1d3a6fc62d1047213cccda3c916e814f2fd1a672d4466e57492febc51edce627a700ee707db38952c7ad9a81d44f4178a1aa11d41e16491aff6e5169fd5c7a623290cf509ee4cf7c51c86a8682700cf73ec9aec335a6844a7de7dcee9a93fcbf6eaad6911909f8fb036e731f1118fce5cc77cc4e5d4cf669354292a544378d77dbb0603dd41c733661dddf9651f20b30a311bcfeaeac82dcc94e918ef41e1cd64fb49fdd3f4a77c9f681a0f4a0a9abc43c3679fbaf7369b2afe66d80549fb2e489b815701d23275a4db0eb1234997c9d868aa431adca4aa513c600f4d]],
					shared = [[1c859c4aefbe56fc4081c8a96c44b878e877808157bd1ca2d2b2e1e9bca36cc6]],
					result = [[acceptable]]
				},
				{
					tcId = 24,
					comment = [[ML-KEM-512 ZBinding: identical d seed and identical tampered ciphertext to tcId 12, but z = 0xaa repeated. The rejection secret SHAKE256(z || ct) must differ from tcId 12, proving the output is keyed on this dk's z (cross-checked with CPython hashlib.shake_256).]],
					targets = {
						[[ZBinding]],
						[[ImplicitRejection]]
					},
					flags = {
						[[ZBinding]],
						[[ImplicitRejection]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[hashlib (CPython)]],
							[[rbx-cryptography]]
						}
					},
					d = [[000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f]],
					z = [[aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]],
					dkOverride = [[]],
					ct = [[9b4ddbd3e08a1c9a45eec13d3ad97626b67af42128b34d5a37de399b2d8e97ec2e174f6de1318560a51381a31dd3dba79d902e10d14057f6ce3fbc30de25363541934e76cb2446dbd2cb8fea570baacb222c769a8e7ebfe49ce6a3d9f2add1cc0f21a1cb6395ba8634fbd02199549db4a349b2ae3619168a7fe66c62d808006e6608aa66cbb8167146b40c81a37152eeb47169a9c5b5d1064558cf1a59d0d15ace1893914f282406f51b9044992189b6664b8e2700c4485f1ee76af83c955d090ab8c0c49c128f9b6b5f89f372dba4bfd9d63fe521b309163b259791c5791cf834b9c22d06b3811c5268deee7de7f940e6248b963ef6335c18ea6150ef009a75eec0c2bf9702498e54e4cc33c8d969c1d8c8e1afbd5af1c955e746719dd8cfc138e17ce3cb04675a9bf2a5bc1e0444904f62228722b13e7c64fd79be91c2e346a9cfbda57ddcf805f6f9dda5bad3f15eb2dab119e5e7cffd8ef3fefe59ef1e49f56d6dab30528273cb3b824a836c593e4d44e9b9fb48610a280008a4110638917a49bd7ef5baaed79cff763fa555a95ac73b4694fd42220a96d56c080f5097c9bcea62aedf3804bd87a7d42e0b6f694fc3752d9a23d4009a6bc4738a3314e655dc8fb7cfeb1c4f830af0ab829fa315b39605ab42d23a142dbd0d9df7f20ca1f74365a3dd1eb19c32806bcd2540024e2589e5977f4fbf0b33014c19a1b67c0628f814f3071eadde644adba93a02590908444354587eafe94f138b270623086e381c027ae1d3a6fc62d1047213cccda3c916e814f2fd1a672d4466e57492febc51edce627a700ee707db38952c7ad9a81d44f4178a1aa11d41e16491aff6e5169fd5c7a623290cf509ee4cf7c51c86a8682700cf73ec9aec335a6844a7de7dcee9a93fcbf6eaad6911909f8fb036e731f1118fce5cc77cc4e5d4cf669354292a544378d77dbb0603dd41c733661dddf9651f20b30a311bcfeaeac82dcc94e918ef41e1cd64fb49fdd3f4a77c9f681a0f4a0a9abc43c3679fbaf7369b2afe66d80549fb2e489b815701d23275a4db0eb1234997c9d868aa431adca4aa513c600f4d]],
					shared = [[146a2aaea368d9681b9c4c299576a5909998e27ab3291e436de284ed34cb1084]],
					result = [[implicitRejection]]
				}
			}
		}
	}
}
