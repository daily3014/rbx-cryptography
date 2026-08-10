--!strict
-- Auto-generated from Tadashi/testvectors/poly1305_test.json
-- Do not edit by hand.

return {
	algorithm = [[POLY1305]],
	generatorVersion = [[Tadashi 0.1.0]],
	schema = [[tadashi_mac_v1.json]],
	header = {
		[[Standalone Poly1305 one-time MAC tests per RFC 8439 §2.5 and §A.3, plus bug-catching cases.]],
		[[Each non-KAT test's targets[] lists the implementation bugs it is designed to catch.]]
	},
	notes = {
		Ktv = {
			bugType = [[BASIC]],
			description = [[Known-answer test from an RFC or authoritative source.]]
		},
		EmptyMessage = {
			bugType = [[EDGE_CASE]],
			description = [[Zero-length MAC input.]],
			effect = [[Tag must equal s (the second half of the key) verbatim.]]
		},
		BlockBoundaryMac = {
			bugType = [[EDGE_CASE]],
			description = [[Message length is exactly N * 16 bytes.]],
			effect = [[Bug if partial-block code path runs on a full-block boundary.]]
		},
		LastBlockHandling = {
			bugType = [[EDGE_CASE]],
			description = [[Message length is not a multiple of 16; last block is partial and gets 0x01 padding.]]
		},
		RClamping = {
			bugType = [[MISSING_STEP]],
			description = [[Key r-portion must be clamped before polynomial evaluation.]],
			effect = [[Skipping clamping yields wrong tag.]]
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
			type = [[Poly1305Mac]],
			keySize = 256,
			tagSize = 128,
			tests = {
				{
					tcId = 1,
					comment = [[RFC 8439 §2.5.2 canonical Poly1305 test vector.]],
					targets = {},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8439]],
						version = [[2.5.2]]
					},
					key = [[85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b]],
					msg = [[43727970746f6772617068696320466f72756d2052657365617263682047726f7570]],
					tag = [[a8061dc1305136c6c22b8baf0c0127a9]],
					result = [[valid]]
				},
				{
					tcId = 2,
					comment = [[RFC 8439 §A.3 #1, all-zero key and message, tag should also be all zero.]],
					targets = {
						[[ZeroInputs]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8439]],
						version = [[A.3#1]]
					},
					key = [[0000000000000000000000000000000000000000000000000000000000000000]],
					msg = [[00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]],
					tag = [[00000000000000000000000000000000]],
					result = [[valid]]
				},
				{
					tcId = 3,
					comment = [[RFC 8439 §A.3 #2, r=0 (cleared by clamping) and s non-zero; tag must equal s.]],
					targets = {
						[[RClamping]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8439]],
						version = [[A.3#2]]
					},
					key = [[0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e]],
					msg = [[416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f]],
					tag = [[36e5f6b5c5e06070f0efca96227a863e]],
					result = [[valid]]
				},
				{
					tcId = 4,
					comment = [[RFC 8439 §A.3 #3, r non-zero and s=0; isolates the polynomial-evaluation path.]],
					targets = {
						[[PadAddition]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8439]],
						version = [[A.3#3]]
					},
					key = [[36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000]],
					msg = [[416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f]],
					tag = [[f3477e7cd95417af89a6b8794c310cf0]],
					result = [[valid]]
				},
				{
					tcId = 5,
					comment = [[RFC 8439 §A.3 #5, final partial reduction lands exactly at 2^130 - 5; bug if partial reduction doesn't perform the conditional subtract.]],
					targets = {
						[[FinalReduction]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8439]],
						version = [[A.3#5]]
					},
					key = [[0200000000000000000000000000000000000000000000000000000000000000]],
					msg = [[ffffffffffffffffffffffffffffffff]],
					tag = [[03000000000000000000000000000000]],
					result = [[valid]]
				},
				{
					tcId = 6,
					comment = [[RFC 8439 §A.3 #7, final h needs two subtractions of p (i.e. partial-reduction result > 2p).]],
					targets = {
						[[FinalReduction]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8439]],
						version = [[A.3#7]]
					},
					key = [[0100000000000000000000000000000000000000000000000000000000000000]],
					msg = [[fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000]],
					tag = [[05000000000000000000000000000000]],
					result = [[valid]]
				},
				{
					tcId = 7,
					comment = [[RFC 8439 §A.3 #8, no carry out of the final (h + s) addition; bug if implementation always assumes carry.]],
					targets = {
						[[PadAddition]],
						[[ModTruncation]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8439]],
						version = [[A.3#8]]
					},
					key = [[0100000000000000000000000000000000000000000000000000000000000000]],
					msg = [[fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101]],
					tag = [[00000000000000000000000000000000]],
					result = [[valid]]
				},
				{
					tcId = 8,
					comment = [[RFC 8439 §A.3 #9, single 16-byte block with high bits set; tests partial-block padding when message ends on a 16-byte boundary.]],
					targets = {
						[[LastBlockHandling]]
					},
					flags = {
						[[Ktv]]
					},
					source = {
						name = [[rfc8439]],
						version = [[A.3#9]]
					},
					key = [[0200000000000000000000000000000000000000000000000000000000000000]],
					msg = [[fdffffffffffffffffffffffffffffff]],
					tag = [[faffffffffffffffffffffffffffffff]],
					result = [[valid]]
				},
				{
					tcId = 9,
					comment = [[Empty message, tag must equal the s portion of the key (the last 16 bytes) verbatim.]],
					targets = {
						[[EmptyMessage]]
					},
					flags = {
						[[EmptyMessage]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b]],
					msg = [[]],
					tag = [[0103808afb0db2fd4abff6af4149f51b]],
					result = [[valid]]
				},
				{
					tcId = 10,
					comment = [[Exactly 16 bytes (one full block, no partial); tests block-boundary handling between full-block and partial-block paths.]],
					targets = {
						[[BlockBoundaryMac]]
					},
					flags = {
						[[BlockBoundaryMac]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b]],
					msg = [[0102030405060708090a0b0c0d0e0f10]],
					tag = [[e1166a3cc0d965fce45dc81964436973]],
					result = [[valid]]
				},
				{
					tcId = 11,
					comment = [[17 bytes; one full block plus 1-byte partial. Tests that the partial-block padding places 0x01 at the correct offset.]],
					targets = {
						[[LastBlockHandling]]
					},
					flags = {
						[[LastBlockHandling]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b]],
					msg = [[0102030405060708090a0b0c0d0e0f10ff]],
					tag = [[24c1a8138ad7c60852d5ea6a0ba492e2]],
					result = [[valid]]
				},
				{
					tcId = 12,
					comment = [[32 bytes (two full blocks, no partial); tests block-loop accumulator carry between blocks.]],
					targets = {
						[[BlockBoundaryMac]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b]],
					msg = [[0102030405060708090a0b0c0d0e0f10112233445566778899aabbccddeeff00]],
					tag = [[6ba8bf24f82c62225c0d2daa3dd970b0]],
					result = [[valid]]
				},
				{
					tcId = 13,
					comment = [[r portion = all 0xFF; clamping must clear the top 4 bits of bytes 3, 7, 11, 15 and the bottom 2 bits of bytes 4, 8, 12. Bug if clamping is skipped or uses wrong bit masks.]],
					targets = {
						[[RClamping]]
					},
					flags = {
						[[RClamping]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[ffffffffffffffffffffffffffffffff85d6be7857556d337f4452fe42d506a8]],
					msg = [[0102030405060708090a0b0c0d0e0f10]],
					tag = [[7d1039035595eabd797ec67c2efd650e]],
					result = [[valid]]
				},
				{
					tcId = 14,
					comment = [[Message and key chosen so h is close to 2^128 and s wraps the addition; tests final mod-2^128 truncation.]],
					targets = {
						[[ModTruncation]],
						[[PadAddition]]
					},
					flags = {
						[[Pseudorandom]]
					},
					source = {
						name = [[tadashi]],
						version = [[0.1.0]]
					},
					key = [[0100000000000000000000000000000000ffffffffffffffffffffffffffffff]],
					msg = [[ffffffffffffffffffffffffffffffff00000000000000000000000000000000]],
					tag = [[fffeffffffffffffffffffffffffffff]],
					result = [[valid]]
				},
				{
					tcId = 15,
					comment = [[Asymmetric key and message bytes; nibbles within each byte differ. Catches hex parser nibble-swap or byte-reverse bugs.]],
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
					msg = [[0fedcba98765432100112233445566778899aabbccddeeff1eef00ddcc11bbaa]],
					tag = [[4fdd6f47048b238671a501a3e2e7ab29]],
					result = [[valid]]
				}
			}
		}
	}
}
