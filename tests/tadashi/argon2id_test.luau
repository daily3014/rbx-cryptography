--!strict
-- Auto-generated from Tadashi/testvectors/argon2id_test.json
-- Do not edit by hand.

return {
	algorithm = [[ARGON2ID]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_kdf_v1.json]],
	header = {
		[[Argon2id per RFC 9106, version 0x13. Includes the §5.3 canonical KAT with all six input fields plus parameter sweeps (t, m, p), output-length variations, and the empty/min-bound edge cases.]],
		[[Wycheproof and NIST CAVP do not publish Argon2 vectors; Tadashi fills this gap.]]
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test from RFC 9106.]]
		},
		MinimumCost = {
			bugType = [[EDGE_CASE]],
			description = [[Smallest legal t/m/p; smoke test of the core path.]]
		},
		IterationCost = {
			bugType = [[BASIC]],
			description = [[Time-cost (t) feeds into H0 and the number of memory passes.]]
		},
		MemoryCost = {
			bugType = [[BASIC]],
			description = [[Memory-cost (m, KiB) determines the total block count.]]
		},
		Parallelism = {
			bugType = [[BASIC]],
			description = [[Parallelism (p) splits memory into lanes; tests cross-lane reference reads.]]
		},
		OutputLength = {
			bugType = [[EDGE_CASE]],
			description = [[Output length other than the default 32.]]
		},
		VariableHashIteration = {
			bugType = [[MISSING_STEP]],
			description = [[RFC 9106 §3.2 specifies a chained Blake2b construction for output lengths > 64 bytes; catches impls that only support the single-call path.]]
		},
		EmptyPassword = {
			bugType = [[EDGE_CASE]],
			description = [[Zero-length password; tests the H0 length-prefix path.]]
		},
		MinimumSalt = {
			bugType = [[EDGE_CASE]],
			description = [[Salt at the RFC 9106 minimum length (8 bytes).]]
		},
		LongSalt = {
			bugType = [[EDGE_CASE]],
			description = [[Salt longer than the recommended 16 bytes.]]
		},
		SecretOnly = {
			bugType = [[EDGE_CASE]],
			description = [[Optional Secret (K) present, Associated Data (X) empty.]]
		},
		AdOnly = {
			bugType = [[EDGE_CASE]],
			description = [[Associated Data (X) present, Secret (K) empty.]]
		},
		SecretAdSeparation = {
			bugType = [[MISSING_STEP]],
			description = [[Secret (K) and Associated Data (X) occupy distinct positions in H0; catches impls that swap them.]]
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
		AbsentParameter = {
			bugType = [[API_SURFACE]],
			description = [[Options omitted entirely at the API level: the consumer must invoke its implementation with only password and salt and obtain the documented defaults (m = 19456 KiB, t = 2, p = 1, 32-byte tag).]],
			effect = [[Default-parameter paths are what most callers actually run and are never pinned by fully-specified vectors.]]
		},
		MinTagLength = {
			bugType = [[EDGE_CASE]],
			description = [[Output length 4 bytes, the RFC 9106 minimum tag length; exercises the short-output path of the H-prime variable-length hash.]]
		},
		ParallelMinMemory = {
			bugType = [[EDGE_CASE]],
			description = [[p = 4 lanes with m = 32 KiB (the 8*p minimum) and a single pass; every lane has the minimum 2 blocks per segment and slice-0 cross-lane references hit the smallest legal reference areas.]]
		}
	},
	numberOfTests = 18,
	testGroups = {
		{
			type = [[Argon2id]],
			version = 19,
			tests = {
				{
					tcId = 1,
					comment = [[RFC 9106 §5.3 canonical Argon2id KAT: t=3, m=32 KiB, p=4, dkLen=32, password=32*0x01, salt=16*0x02, secret=8*0x03, AD=12*0x04. The full-feature reference test.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc9106]],
						version = [[5.3]]
					},
					password = [[0101010101010101010101010101010101010101010101010101010101010101]],
					salt = [[02020202020202020202020202020202]],
					secret = [[0303030303030303]],
					ad = [[040404040404040404040404]],
					t = 3,
					m = 32,
					p = 4,
					outputLen = 32,
					tag = [[0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659]],
					result = [[valid]]
				},
				{
					tcId = 2,
					comment = [[Minimum-cost parameters: t=1, m=8 KiB, p=1, dkLen=32, no secret, no AD. Smoke test of the core memory-filling loop with the smallest legal memory.]],
					targets = {
						[[MinimumCost]]
					},
					flags = {
						[[MinimumCost]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[73616c7473616c74]],
					secret = [[]],
					ad = [[]],
					t = 1,
					m = 8,
					p = 1,
					outputLen = 32,
					tag = [[78f1d7ead7a95d6bac7fa6fa307f5327e4951ad79ddd1fc5b42931abf5f9515a]],
					result = [[valid]]
				},
				{
					tcId = 3,
					comment = [[Iteration parameter: t=2 (vs the minimum 1). Same password/salt as the previous test; output must differ because t feeds into H0.]],
					targets = {
						[[IterationCost]]
					},
					flags = {
						[[IterationCost]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[73616c7473616c74]],
					secret = [[]],
					ad = [[]],
					t = 2,
					m = 8,
					p = 1,
					outputLen = 32,
					tag = [[2c47680f2453aa94ee23bf23dd983e90c41164b4e59293233035af8bdcd64067]],
					result = [[valid]]
				},
				{
					tcId = 4,
					comment = [[Memory parameter: m=64 KiB (vs minimum 8). Catches bugs in memory-block allocation and indexing across larger lanes.]],
					targets = {
						[[MemoryCost]]
					},
					flags = {
						[[MemoryCost]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[73616c7473616c74]],
					secret = [[]],
					ad = [[]],
					t = 1,
					m = 64,
					p = 1,
					outputLen = 32,
					tag = [[ef041d9b15f31a1d77d4edb2a1f24e8ae7931c7d6ceaa52ee36d83fd52f96aa7]],
					result = [[valid]]
				},
				{
					tcId = 5,
					comment = [[Parallelism parameter: p=2 (vs 1). Tests segment-based memory partitioning and cross-lane reference reading.]],
					targets = {
						[[Parallelism]]
					},
					flags = {
						[[Parallelism]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[73616c7473616c74]],
					secret = [[]],
					ad = [[]],
					t = 1,
					m = 16,
					p = 2,
					outputLen = 32,
					tag = [[2e3f6b46bd94ae5c1b4f5663d55cae4e92e89c24302ad2e1464e60a224a5d899]],
					result = [[valid]]
				},
				{
					tcId = 6,
					comment = [[Parallelism p=4 with t=2 and m=32 (rbx-crypto requires m >= 8*p). Exercises both multi-lane and multi-iteration.]],
					targets = {
						[[Parallelism]],
						[[IterationCost]]
					},
					flags = {
						[[Parallelism]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[73616c7473616c74]],
					secret = [[]],
					ad = [[]],
					t = 2,
					m = 32,
					p = 4,
					outputLen = 32,
					tag = [[bad2885bf29d8c47aa8f969c8b99173355207429c4a29f039739efc1be09fbfb]],
					result = [[valid]]
				},
				{
					tcId = 7,
					comment = [[Output length 16 bytes (shorter than default 32). Tests the variable-length VariableHash output construction with a length below 64 (single Blake2b call path).]],
					targets = {
						[[OutputLength]]
					},
					flags = {
						[[OutputLength]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[73616c7473616c74]],
					secret = [[]],
					ad = [[]],
					t = 1,
					m = 8,
					p = 1,
					outputLen = 16,
					tag = [[fa830f1085352b133cb1b059bb3e15b0]],
					result = [[valid]]
				},
				{
					tcId = 8,
					comment = [[Output length 64 bytes (Blake2b max, single-call boundary).]],
					targets = {
						[[OutputLength]]
					},
					flags = {
						[[OutputLength]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[73616c7473616c74]],
					secret = [[]],
					ad = [[]],
					t = 1,
					m = 8,
					p = 1,
					outputLen = 64,
					tag = [[86d26cf1e488dcd83e22c39e7df0d306eeb36b7277c5999d0198b0e29bb15e7a33ee9f3df2a20375cab742a63230700618512a51b5bb8dbb85c0292320e10fda]],
					result = [[valid]]
				},
				{
					tcId = 9,
					comment = [[Output length 100 bytes (forces the iterated VariableHash path past the single-Blake2b cutoff). Per RFC 9106 §3.2, longer outputs are produced by chained Blake2b calls.]],
					targets = {
						[[OutputLength]],
						[[VariableHashIteration]]
					},
					flags = {
						[[VariableHashIteration]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[73616c7473616c74]],
					secret = [[]],
					ad = [[]],
					t = 1,
					m = 8,
					p = 1,
					outputLen = 100,
					tag = [[3962432f4acc8891038162666267496e0a827e2a1b042b2c2a8b877e083d818167946f36b4962e1215891a9d3f2c9bef626253691815dba815c9a2f256f6554d2d9f5340eafa40454cab06996929ee34681ec33164ada581ddb923e5dd13dd12cd42d606]],
					result = [[valid]]
				},
				{
					tcId = 10,
					comment = [[Empty password. Length 0 password gets encoded as 4-byte length 0 in H0, with no password bytes following.]],
					targets = {
						[[EmptyPassword]]
					},
					flags = {
						[[EmptyPassword]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					password = [[]],
					salt = [[73616c7473616c74]],
					secret = [[]],
					ad = [[]],
					t = 1,
					m = 8,
					p = 1,
					outputLen = 32,
					tag = [[3701b5ccd9211d3d025397f7a17fc780a7a25138d0125853fafc74d4d0c6063a]],
					result = [[valid]]
				},
				{
					tcId = 11,
					comment = [[8-byte salt (the RFC 9106 minimum).]],
					targets = {
						[[MinimumSalt]]
					},
					flags = {
						[[MinimumSalt]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[4242424242424242]],
					secret = [[]],
					ad = [[]],
					t = 1,
					m = 8,
					p = 1,
					outputLen = 32,
					tag = [[6f83e107c2df9307fe5797c58e7900449c4763ccb1a219961c43487c36bfd676]],
					result = [[valid]]
				},
				{
					tcId = 12,
					comment = [[32-byte salt. Tests that the longer salt is correctly absorbed (length-prefixed by 4 bytes in H0).]],
					targets = {
						[[LongSalt]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[4242424242424242424242424242424242424242424242424242424242424242]],
					secret = [[]],
					ad = [[]],
					t = 1,
					m = 8,
					p = 1,
					outputLen = 32,
					tag = [[c15b1b48bde1b8edcadd9ca674713a143a4669ccd7a10237b70ecfa4c2918574]],
					result = [[valid]]
				},
				{
					tcId = 13,
					comment = [[With secret only (no AD). Catches impls that swap K and X positions in H0.]],
					targets = {
						[[SecretOnly]],
						[[SecretAdSeparation]]
					},
					flags = {
						[[SecretOnly]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[73616c7473616c74]],
					secret = [[33333333333333333333333333333333]],
					ad = [[]],
					t = 1,
					m = 8,
					p = 1,
					outputLen = 32,
					tag = [[00f0a08fbd126ca1ac15948c6a55b1a5f7a8dfae76ef811c59b5d12842ff3ead]],
					result = [[valid]]
				},
				{
					tcId = 14,
					comment = [[With AD only (no secret). Mirror of the secret-only test.]],
					targets = {
						[[AdOnly]],
						[[SecretAdSeparation]]
					},
					flags = {
						[[AdOnly]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[@noble/hashes]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[73616c7473616c74]],
					secret = [[]],
					ad = [[44444444444444444444444444444444]],
					t = 1,
					m = 8,
					p = 1,
					outputLen = 32,
					tag = [[e4bbc51c762245e32f864ee0f7db346599a8deacde9db6aab96ebb571fcb44e2]],
					result = [[valid]]
				},
				{
					tcId = 15,
					comment = [[Asymmetric password and salt bytes; nibbles within each byte differ. Catches hex parser nibble-swap or byte-reverse bugs.]],
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
							[[@noble/hashes]]
						}
					},
					password = [[0123456789abcdeffedcba98765432100f1e2d3c4b5a6978]],
					salt = [[a1b2c3d4e5f60718]],
					secret = [[]],
					ad = [[]],
					t = 1,
					m = 8,
					p = 1,
					outputLen = 32,
					tag = [[4022455d900e347d959347148d2b72a589adbf0d84e7eb639d101fdf5cf48c7d]],
					result = [[valid]]
				},
				{
					tcId = 16,
					comment = [[All options absent: the consumer must call with password and salt only. Pins the documented default parameters (m = 19456, t = 2, p = 1, dkLen = 32), which are what most real callers run (cross-checked with argon2-cffi).]],
					targets = {
						[[AbsentParameter]]
					},
					flags = {
						[[AbsentParameter]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[argon2-cffi (phc-winner-argon2)]],
							[[rbx-cryptography]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[000102030405060708090a0b0c0d0e0f]],
					tag = [[39903a34cd393876436e671cd690dfe8ab9ce7b13459a7e04ec0e4f0694ddb0d]],
					result = [[valid]]
				},
				{
					tcId = 17,
					comment = [[Output length 4 bytes, the RFC 9106 minimum. H-prime takes the direct single-Blake2b path with a 4-byte digest.]],
					targets = {
						[[MinTagLength]],
						[[OutputLength]]
					},
					flags = {
						[[MinTagLength]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[argon2-cffi (phc-winner-argon2)]],
							[[rbx-cryptography]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[000102030405060708090a0b0c0d0e0f]],
					secret = [[]],
					ad = [[]],
					t = 1,
					m = 8,
					p = 1,
					outputLen = 4,
					tag = [[c2238164]],
					result = [[valid]]
				},
				{
					tcId = 18,
					comment = [[p = 4 with m = 32 KiB (exactly 8*p, the minimum) and t = 1: a single pass over four 2-block segments per lane, the smallest legal multi-lane geometry. Stresses slice-0 same-lane-only indexing and minimal reference areas.]],
					targets = {
						[[ParallelMinMemory]],
						[[Parallelism]]
					},
					flags = {
						[[ParallelMinMemory]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]],
						crossChecked = {
							[[argon2-cffi (phc-winner-argon2)]],
							[[rbx-cryptography]]
						}
					},
					password = [[70617373776f7264]],
					salt = [[000102030405060708090a0b0c0d0e0f]],
					secret = [[]],
					ad = [[]],
					t = 1,
					m = 32,
					p = 4,
					outputLen = 32,
					tag = [[747c33ed662de7a2fe76928a145df0bfaf051f5c81be8f22ceb3e681495dab02]],
					result = [[valid]]
				}
			}
		}
	}
}
