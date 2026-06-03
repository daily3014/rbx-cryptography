--[=[
	Cryptography library: Blake3
	
	Sizes:
		Key: 32 bytes
		Output: variable
	
	Return type: string (hex)
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Key = buffer.fromstring(string.rep("k", 32))
		
		--------Standard Hash--------
		local Hash = Blake3.Digest(Message, 32)
		
		--------Keyed Hash--------
		local KeyedHash = Blake3.DigestKeyed(Message, Key, 32)
		
		--------Key Derivation--------
		local Context = buffer.fromstring("my context")
		local KeyDeriver = Blake3.DeriveKey(Context)
		local DerivedKey = KeyDeriver(Message, 32)
--]=]

--!strict
--!optimize 2
--!native

local Conversions = require("../Utilities/Conversions")
local ToHex = Conversions.ToHex

local Blake3 = {}

local MASK = 0xFFFFFFFFi

local BLOCK_SIZE = 64
local CV_SIZE = 32
local EXTENDED_CV_SIZE = 64
local MAX_STACK_DEPTH = 64
local STACK_BUFFER_SIZE = MAX_STACK_DEPTH * CV_SIZE

local BLAKE3_KEY_SIZE = 32
local BLAKE3_MIN_OUTPUT_BYTES = 1
local BLAKE3_MAX_OUTPUT_BYTES = 2^32 - 1

local CHUNK_START = 0x01
local CHUNK_END = 0x02
local PARENT_FLAG = 0x04
local ROOT_FLAG = 0x08
local HASH_FLAG = 0x10
local DERIVE_CONTEXT_FLAG = 0x20
local DERIVE_MATERIAL_FLAG = 0x40

local INITIAL_VECTORS = buffer.create(CV_SIZE) do
	local IV = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	for Index, Value in ipairs(IV) do
		buffer.writeu32(INITIAL_VECTORS, (Index - 1) * 4, Value)
	end
end

local function Compress(Hash: buffer, MessageBlock: buffer, MessageOffset: number, Counter: number, BlockLength: number, Flags: number, IsFull: boolean?, Storage: buffer?): buffer
	local Hash00 = integer.create(buffer.readu32(Hash, 0)) :: integer
	local Hash01 = integer.create(buffer.readu32(Hash, 4)) :: integer
	local Hash02 = integer.create(buffer.readu32(Hash, 8)) :: integer
	local Hash03 = integer.create(buffer.readu32(Hash, 12)) :: integer
	local Hash04 = integer.create(buffer.readu32(Hash, 16)) :: integer
	local Hash05 = integer.create(buffer.readu32(Hash, 20)) :: integer
	local Hash06 = integer.create(buffer.readu32(Hash, 24)) :: integer
	local Hash07 = integer.create(buffer.readu32(Hash, 28)) :: integer

	local V00, V01, V02, V03 = Hash00, Hash01, Hash02, Hash03
	local V04, V05, V06, V07 = Hash04, Hash05, Hash06, Hash07
	local V08, V09, V10, V11 = 0x6a09e667i, 0xbb67ae85i, 0x3c6ef372i, 0xa54ff53ai

	local CounterLow = Counter % 0x100000000
	local V12 = integer.create(CounterLow) :: integer
	local V13 = integer.create((Counter - CounterLow) / 0x100000000) :: integer
	local V14 = integer.create(BlockLength) :: integer
	local V15 = integer.create(Flags) :: integer

	local M00 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 0)) :: integer
	local M01 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 4)) :: integer
	local M02 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 8)) :: integer
	local M03 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 12)) :: integer
	local M04 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 16)) :: integer
	local M05 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 20)) :: integer
	local M06 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 24)) :: integer
	local M07 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 28)) :: integer
	local M08 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 32)) :: integer
	local M09 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 36)) :: integer
	local M10 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 40)) :: integer
	local M11 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 44)) :: integer
	local M12 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 48)) :: integer
	local M13 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 52)) :: integer
	local M14 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 56)) :: integer
	local M15 = integer.create(buffer.readu32(MessageBlock, MessageOffset + 60)) :: integer

		V00 = integer.band(integer.add(integer.add(V00, V04), M00), MASK); V12 = integer.bxor(V12, V00); V12 = integer.band(integer.bor(integer.lshift(V12, 16i), integer.rshift(V12, 16i)), MASK)
		V08 = integer.band(integer.add(V08, V12), MASK); V04 = integer.bxor(V04, V08); V04 = integer.band(integer.bor(integer.lshift(V04, 20i), integer.rshift(V04, 12i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V04), M01), MASK); V12 = integer.bxor(V12, V00); V12 = integer.band(integer.bor(integer.lshift(V12, 24i), integer.rshift(V12, 8i)), MASK)
		V08 = integer.band(integer.add(V08, V12), MASK); V04 = integer.bxor(V04, V08); V04 = integer.band(integer.bor(integer.lshift(V04, 25i), integer.rshift(V04, 7i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V05), M02), MASK); V13 = integer.bxor(V13, V01); V13 = integer.band(integer.bor(integer.lshift(V13, 16i), integer.rshift(V13, 16i)), MASK)
		V09 = integer.band(integer.add(V09, V13), MASK); V05 = integer.bxor(V05, V09); V05 = integer.band(integer.bor(integer.lshift(V05, 20i), integer.rshift(V05, 12i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V05), M03), MASK); V13 = integer.bxor(V13, V01); V13 = integer.band(integer.bor(integer.lshift(V13, 24i), integer.rshift(V13, 8i)), MASK)
		V09 = integer.band(integer.add(V09, V13), MASK); V05 = integer.bxor(V05, V09); V05 = integer.band(integer.bor(integer.lshift(V05, 25i), integer.rshift(V05, 7i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V06), M04), MASK); V14 = integer.bxor(V14, V02); V14 = integer.band(integer.bor(integer.lshift(V14, 16i), integer.rshift(V14, 16i)), MASK)
		V10 = integer.band(integer.add(V10, V14), MASK); V06 = integer.bxor(V06, V10); V06 = integer.band(integer.bor(integer.lshift(V06, 20i), integer.rshift(V06, 12i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V06), M05), MASK); V14 = integer.bxor(V14, V02); V14 = integer.band(integer.bor(integer.lshift(V14, 24i), integer.rshift(V14, 8i)), MASK)
		V10 = integer.band(integer.add(V10, V14), MASK); V06 = integer.bxor(V06, V10); V06 = integer.band(integer.bor(integer.lshift(V06, 25i), integer.rshift(V06, 7i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V07), M06), MASK); V15 = integer.bxor(V15, V03); V15 = integer.band(integer.bor(integer.lshift(V15, 16i), integer.rshift(V15, 16i)), MASK)
		V11 = integer.band(integer.add(V11, V15), MASK); V07 = integer.bxor(V07, V11); V07 = integer.band(integer.bor(integer.lshift(V07, 20i), integer.rshift(V07, 12i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V07), M07), MASK); V15 = integer.bxor(V15, V03); V15 = integer.band(integer.bor(integer.lshift(V15, 24i), integer.rshift(V15, 8i)), MASK)
		V11 = integer.band(integer.add(V11, V15), MASK); V07 = integer.bxor(V07, V11); V07 = integer.band(integer.bor(integer.lshift(V07, 25i), integer.rshift(V07, 7i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V05), M08), MASK); V15 = integer.bxor(V15, V00); V15 = integer.band(integer.bor(integer.lshift(V15, 16i), integer.rshift(V15, 16i)), MASK)
		V10 = integer.band(integer.add(V10, V15), MASK); V05 = integer.bxor(V05, V10); V05 = integer.band(integer.bor(integer.lshift(V05, 20i), integer.rshift(V05, 12i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V05), M09), MASK); V15 = integer.bxor(V15, V00); V15 = integer.band(integer.bor(integer.lshift(V15, 24i), integer.rshift(V15, 8i)), MASK)
		V10 = integer.band(integer.add(V10, V15), MASK); V05 = integer.bxor(V05, V10); V05 = integer.band(integer.bor(integer.lshift(V05, 25i), integer.rshift(V05, 7i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V06), M10), MASK); V12 = integer.bxor(V12, V01); V12 = integer.band(integer.bor(integer.lshift(V12, 16i), integer.rshift(V12, 16i)), MASK)
		V11 = integer.band(integer.add(V11, V12), MASK); V06 = integer.bxor(V06, V11); V06 = integer.band(integer.bor(integer.lshift(V06, 20i), integer.rshift(V06, 12i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V06), M11), MASK); V12 = integer.bxor(V12, V01); V12 = integer.band(integer.bor(integer.lshift(V12, 24i), integer.rshift(V12, 8i)), MASK)
		V11 = integer.band(integer.add(V11, V12), MASK); V06 = integer.bxor(V06, V11); V06 = integer.band(integer.bor(integer.lshift(V06, 25i), integer.rshift(V06, 7i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V07), M12), MASK); V13 = integer.bxor(V13, V02); V13 = integer.band(integer.bor(integer.lshift(V13, 16i), integer.rshift(V13, 16i)), MASK)
		V08 = integer.band(integer.add(V08, V13), MASK); V07 = integer.bxor(V07, V08); V07 = integer.band(integer.bor(integer.lshift(V07, 20i), integer.rshift(V07, 12i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V07), M13), MASK); V13 = integer.bxor(V13, V02); V13 = integer.band(integer.bor(integer.lshift(V13, 24i), integer.rshift(V13, 8i)), MASK)
		V08 = integer.band(integer.add(V08, V13), MASK); V07 = integer.bxor(V07, V08); V07 = integer.band(integer.bor(integer.lshift(V07, 25i), integer.rshift(V07, 7i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V04), M14), MASK); V14 = integer.bxor(V14, V03); V14 = integer.band(integer.bor(integer.lshift(V14, 16i), integer.rshift(V14, 16i)), MASK)
		V09 = integer.band(integer.add(V09, V14), MASK); V04 = integer.bxor(V04, V09); V04 = integer.band(integer.bor(integer.lshift(V04, 20i), integer.rshift(V04, 12i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V04), M15), MASK); V14 = integer.bxor(V14, V03); V14 = integer.band(integer.bor(integer.lshift(V14, 24i), integer.rshift(V14, 8i)), MASK)
		V09 = integer.band(integer.add(V09, V14), MASK); V04 = integer.bxor(V04, V09); V04 = integer.band(integer.bor(integer.lshift(V04, 25i), integer.rshift(V04, 7i)), MASK)

		V00 = integer.band(integer.add(integer.add(V00, V04), M02), MASK); V12 = integer.bxor(V12, V00); V12 = integer.band(integer.bor(integer.lshift(V12, 16i), integer.rshift(V12, 16i)), MASK)
		V08 = integer.band(integer.add(V08, V12), MASK); V04 = integer.bxor(V04, V08); V04 = integer.band(integer.bor(integer.lshift(V04, 20i), integer.rshift(V04, 12i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V04), M06), MASK); V12 = integer.bxor(V12, V00); V12 = integer.band(integer.bor(integer.lshift(V12, 24i), integer.rshift(V12, 8i)), MASK)
		V08 = integer.band(integer.add(V08, V12), MASK); V04 = integer.bxor(V04, V08); V04 = integer.band(integer.bor(integer.lshift(V04, 25i), integer.rshift(V04, 7i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V05), M03), MASK); V13 = integer.bxor(V13, V01); V13 = integer.band(integer.bor(integer.lshift(V13, 16i), integer.rshift(V13, 16i)), MASK)
		V09 = integer.band(integer.add(V09, V13), MASK); V05 = integer.bxor(V05, V09); V05 = integer.band(integer.bor(integer.lshift(V05, 20i), integer.rshift(V05, 12i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V05), M10), MASK); V13 = integer.bxor(V13, V01); V13 = integer.band(integer.bor(integer.lshift(V13, 24i), integer.rshift(V13, 8i)), MASK)
		V09 = integer.band(integer.add(V09, V13), MASK); V05 = integer.bxor(V05, V09); V05 = integer.band(integer.bor(integer.lshift(V05, 25i), integer.rshift(V05, 7i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V06), M07), MASK); V14 = integer.bxor(V14, V02); V14 = integer.band(integer.bor(integer.lshift(V14, 16i), integer.rshift(V14, 16i)), MASK)
		V10 = integer.band(integer.add(V10, V14), MASK); V06 = integer.bxor(V06, V10); V06 = integer.band(integer.bor(integer.lshift(V06, 20i), integer.rshift(V06, 12i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V06), M00), MASK); V14 = integer.bxor(V14, V02); V14 = integer.band(integer.bor(integer.lshift(V14, 24i), integer.rshift(V14, 8i)), MASK)
		V10 = integer.band(integer.add(V10, V14), MASK); V06 = integer.bxor(V06, V10); V06 = integer.band(integer.bor(integer.lshift(V06, 25i), integer.rshift(V06, 7i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V07), M04), MASK); V15 = integer.bxor(V15, V03); V15 = integer.band(integer.bor(integer.lshift(V15, 16i), integer.rshift(V15, 16i)), MASK)
		V11 = integer.band(integer.add(V11, V15), MASK); V07 = integer.bxor(V07, V11); V07 = integer.band(integer.bor(integer.lshift(V07, 20i), integer.rshift(V07, 12i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V07), M13), MASK); V15 = integer.bxor(V15, V03); V15 = integer.band(integer.bor(integer.lshift(V15, 24i), integer.rshift(V15, 8i)), MASK)
		V11 = integer.band(integer.add(V11, V15), MASK); V07 = integer.bxor(V07, V11); V07 = integer.band(integer.bor(integer.lshift(V07, 25i), integer.rshift(V07, 7i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V05), M01), MASK); V15 = integer.bxor(V15, V00); V15 = integer.band(integer.bor(integer.lshift(V15, 16i), integer.rshift(V15, 16i)), MASK)
		V10 = integer.band(integer.add(V10, V15), MASK); V05 = integer.bxor(V05, V10); V05 = integer.band(integer.bor(integer.lshift(V05, 20i), integer.rshift(V05, 12i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V05), M11), MASK); V15 = integer.bxor(V15, V00); V15 = integer.band(integer.bor(integer.lshift(V15, 24i), integer.rshift(V15, 8i)), MASK)
		V10 = integer.band(integer.add(V10, V15), MASK); V05 = integer.bxor(V05, V10); V05 = integer.band(integer.bor(integer.lshift(V05, 25i), integer.rshift(V05, 7i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V06), M12), MASK); V12 = integer.bxor(V12, V01); V12 = integer.band(integer.bor(integer.lshift(V12, 16i), integer.rshift(V12, 16i)), MASK)
		V11 = integer.band(integer.add(V11, V12), MASK); V06 = integer.bxor(V06, V11); V06 = integer.band(integer.bor(integer.lshift(V06, 20i), integer.rshift(V06, 12i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V06), M05), MASK); V12 = integer.bxor(V12, V01); V12 = integer.band(integer.bor(integer.lshift(V12, 24i), integer.rshift(V12, 8i)), MASK)
		V11 = integer.band(integer.add(V11, V12), MASK); V06 = integer.bxor(V06, V11); V06 = integer.band(integer.bor(integer.lshift(V06, 25i), integer.rshift(V06, 7i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V07), M09), MASK); V13 = integer.bxor(V13, V02); V13 = integer.band(integer.bor(integer.lshift(V13, 16i), integer.rshift(V13, 16i)), MASK)
		V08 = integer.band(integer.add(V08, V13), MASK); V07 = integer.bxor(V07, V08); V07 = integer.band(integer.bor(integer.lshift(V07, 20i), integer.rshift(V07, 12i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V07), M14), MASK); V13 = integer.bxor(V13, V02); V13 = integer.band(integer.bor(integer.lshift(V13, 24i), integer.rshift(V13, 8i)), MASK)
		V08 = integer.band(integer.add(V08, V13), MASK); V07 = integer.bxor(V07, V08); V07 = integer.band(integer.bor(integer.lshift(V07, 25i), integer.rshift(V07, 7i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V04), M15), MASK); V14 = integer.bxor(V14, V03); V14 = integer.band(integer.bor(integer.lshift(V14, 16i), integer.rshift(V14, 16i)), MASK)
		V09 = integer.band(integer.add(V09, V14), MASK); V04 = integer.bxor(V04, V09); V04 = integer.band(integer.bor(integer.lshift(V04, 20i), integer.rshift(V04, 12i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V04), M08), MASK); V14 = integer.bxor(V14, V03); V14 = integer.band(integer.bor(integer.lshift(V14, 24i), integer.rshift(V14, 8i)), MASK)
		V09 = integer.band(integer.add(V09, V14), MASK); V04 = integer.bxor(V04, V09); V04 = integer.band(integer.bor(integer.lshift(V04, 25i), integer.rshift(V04, 7i)), MASK)

		V00 = integer.band(integer.add(integer.add(V00, V04), M03), MASK); V12 = integer.bxor(V12, V00); V12 = integer.band(integer.bor(integer.lshift(V12, 16i), integer.rshift(V12, 16i)), MASK)
		V08 = integer.band(integer.add(V08, V12), MASK); V04 = integer.bxor(V04, V08); V04 = integer.band(integer.bor(integer.lshift(V04, 20i), integer.rshift(V04, 12i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V04), M04), MASK); V12 = integer.bxor(V12, V00); V12 = integer.band(integer.bor(integer.lshift(V12, 24i), integer.rshift(V12, 8i)), MASK)
		V08 = integer.band(integer.add(V08, V12), MASK); V04 = integer.bxor(V04, V08); V04 = integer.band(integer.bor(integer.lshift(V04, 25i), integer.rshift(V04, 7i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V05), M10), MASK); V13 = integer.bxor(V13, V01); V13 = integer.band(integer.bor(integer.lshift(V13, 16i), integer.rshift(V13, 16i)), MASK)
		V09 = integer.band(integer.add(V09, V13), MASK); V05 = integer.bxor(V05, V09); V05 = integer.band(integer.bor(integer.lshift(V05, 20i), integer.rshift(V05, 12i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V05), M12), MASK); V13 = integer.bxor(V13, V01); V13 = integer.band(integer.bor(integer.lshift(V13, 24i), integer.rshift(V13, 8i)), MASK)
		V09 = integer.band(integer.add(V09, V13), MASK); V05 = integer.bxor(V05, V09); V05 = integer.band(integer.bor(integer.lshift(V05, 25i), integer.rshift(V05, 7i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V06), M13), MASK); V14 = integer.bxor(V14, V02); V14 = integer.band(integer.bor(integer.lshift(V14, 16i), integer.rshift(V14, 16i)), MASK)
		V10 = integer.band(integer.add(V10, V14), MASK); V06 = integer.bxor(V06, V10); V06 = integer.band(integer.bor(integer.lshift(V06, 20i), integer.rshift(V06, 12i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V06), M02), MASK); V14 = integer.bxor(V14, V02); V14 = integer.band(integer.bor(integer.lshift(V14, 24i), integer.rshift(V14, 8i)), MASK)
		V10 = integer.band(integer.add(V10, V14), MASK); V06 = integer.bxor(V06, V10); V06 = integer.band(integer.bor(integer.lshift(V06, 25i), integer.rshift(V06, 7i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V07), M07), MASK); V15 = integer.bxor(V15, V03); V15 = integer.band(integer.bor(integer.lshift(V15, 16i), integer.rshift(V15, 16i)), MASK)
		V11 = integer.band(integer.add(V11, V15), MASK); V07 = integer.bxor(V07, V11); V07 = integer.band(integer.bor(integer.lshift(V07, 20i), integer.rshift(V07, 12i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V07), M14), MASK); V15 = integer.bxor(V15, V03); V15 = integer.band(integer.bor(integer.lshift(V15, 24i), integer.rshift(V15, 8i)), MASK)
		V11 = integer.band(integer.add(V11, V15), MASK); V07 = integer.bxor(V07, V11); V07 = integer.band(integer.bor(integer.lshift(V07, 25i), integer.rshift(V07, 7i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V05), M06), MASK); V15 = integer.bxor(V15, V00); V15 = integer.band(integer.bor(integer.lshift(V15, 16i), integer.rshift(V15, 16i)), MASK)
		V10 = integer.band(integer.add(V10, V15), MASK); V05 = integer.bxor(V05, V10); V05 = integer.band(integer.bor(integer.lshift(V05, 20i), integer.rshift(V05, 12i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V05), M05), MASK); V15 = integer.bxor(V15, V00); V15 = integer.band(integer.bor(integer.lshift(V15, 24i), integer.rshift(V15, 8i)), MASK)
		V10 = integer.band(integer.add(V10, V15), MASK); V05 = integer.bxor(V05, V10); V05 = integer.band(integer.bor(integer.lshift(V05, 25i), integer.rshift(V05, 7i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V06), M09), MASK); V12 = integer.bxor(V12, V01); V12 = integer.band(integer.bor(integer.lshift(V12, 16i), integer.rshift(V12, 16i)), MASK)
		V11 = integer.band(integer.add(V11, V12), MASK); V06 = integer.bxor(V06, V11); V06 = integer.band(integer.bor(integer.lshift(V06, 20i), integer.rshift(V06, 12i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V06), M00), MASK); V12 = integer.bxor(V12, V01); V12 = integer.band(integer.bor(integer.lshift(V12, 24i), integer.rshift(V12, 8i)), MASK)
		V11 = integer.band(integer.add(V11, V12), MASK); V06 = integer.bxor(V06, V11); V06 = integer.band(integer.bor(integer.lshift(V06, 25i), integer.rshift(V06, 7i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V07), M11), MASK); V13 = integer.bxor(V13, V02); V13 = integer.band(integer.bor(integer.lshift(V13, 16i), integer.rshift(V13, 16i)), MASK)
		V08 = integer.band(integer.add(V08, V13), MASK); V07 = integer.bxor(V07, V08); V07 = integer.band(integer.bor(integer.lshift(V07, 20i), integer.rshift(V07, 12i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V07), M15), MASK); V13 = integer.bxor(V13, V02); V13 = integer.band(integer.bor(integer.lshift(V13, 24i), integer.rshift(V13, 8i)), MASK)
		V08 = integer.band(integer.add(V08, V13), MASK); V07 = integer.bxor(V07, V08); V07 = integer.band(integer.bor(integer.lshift(V07, 25i), integer.rshift(V07, 7i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V04), M08), MASK); V14 = integer.bxor(V14, V03); V14 = integer.band(integer.bor(integer.lshift(V14, 16i), integer.rshift(V14, 16i)), MASK)
		V09 = integer.band(integer.add(V09, V14), MASK); V04 = integer.bxor(V04, V09); V04 = integer.band(integer.bor(integer.lshift(V04, 20i), integer.rshift(V04, 12i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V04), M01), MASK); V14 = integer.bxor(V14, V03); V14 = integer.band(integer.bor(integer.lshift(V14, 24i), integer.rshift(V14, 8i)), MASK)
		V09 = integer.band(integer.add(V09, V14), MASK); V04 = integer.bxor(V04, V09); V04 = integer.band(integer.bor(integer.lshift(V04, 25i), integer.rshift(V04, 7i)), MASK)

		V00 = integer.band(integer.add(integer.add(V00, V04), M10), MASK); V12 = integer.bxor(V12, V00); V12 = integer.band(integer.bor(integer.lshift(V12, 16i), integer.rshift(V12, 16i)), MASK)
		V08 = integer.band(integer.add(V08, V12), MASK); V04 = integer.bxor(V04, V08); V04 = integer.band(integer.bor(integer.lshift(V04, 20i), integer.rshift(V04, 12i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V04), M07), MASK); V12 = integer.bxor(V12, V00); V12 = integer.band(integer.bor(integer.lshift(V12, 24i), integer.rshift(V12, 8i)), MASK)
		V08 = integer.band(integer.add(V08, V12), MASK); V04 = integer.bxor(V04, V08); V04 = integer.band(integer.bor(integer.lshift(V04, 25i), integer.rshift(V04, 7i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V05), M12), MASK); V13 = integer.bxor(V13, V01); V13 = integer.band(integer.bor(integer.lshift(V13, 16i), integer.rshift(V13, 16i)), MASK)
		V09 = integer.band(integer.add(V09, V13), MASK); V05 = integer.bxor(V05, V09); V05 = integer.band(integer.bor(integer.lshift(V05, 20i), integer.rshift(V05, 12i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V05), M09), MASK); V13 = integer.bxor(V13, V01); V13 = integer.band(integer.bor(integer.lshift(V13, 24i), integer.rshift(V13, 8i)), MASK)
		V09 = integer.band(integer.add(V09, V13), MASK); V05 = integer.bxor(V05, V09); V05 = integer.band(integer.bor(integer.lshift(V05, 25i), integer.rshift(V05, 7i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V06), M14), MASK); V14 = integer.bxor(V14, V02); V14 = integer.band(integer.bor(integer.lshift(V14, 16i), integer.rshift(V14, 16i)), MASK)
		V10 = integer.band(integer.add(V10, V14), MASK); V06 = integer.bxor(V06, V10); V06 = integer.band(integer.bor(integer.lshift(V06, 20i), integer.rshift(V06, 12i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V06), M03), MASK); V14 = integer.bxor(V14, V02); V14 = integer.band(integer.bor(integer.lshift(V14, 24i), integer.rshift(V14, 8i)), MASK)
		V10 = integer.band(integer.add(V10, V14), MASK); V06 = integer.bxor(V06, V10); V06 = integer.band(integer.bor(integer.lshift(V06, 25i), integer.rshift(V06, 7i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V07), M13), MASK); V15 = integer.bxor(V15, V03); V15 = integer.band(integer.bor(integer.lshift(V15, 16i), integer.rshift(V15, 16i)), MASK)
		V11 = integer.band(integer.add(V11, V15), MASK); V07 = integer.bxor(V07, V11); V07 = integer.band(integer.bor(integer.lshift(V07, 20i), integer.rshift(V07, 12i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V07), M15), MASK); V15 = integer.bxor(V15, V03); V15 = integer.band(integer.bor(integer.lshift(V15, 24i), integer.rshift(V15, 8i)), MASK)
		V11 = integer.band(integer.add(V11, V15), MASK); V07 = integer.bxor(V07, V11); V07 = integer.band(integer.bor(integer.lshift(V07, 25i), integer.rshift(V07, 7i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V05), M04), MASK); V15 = integer.bxor(V15, V00); V15 = integer.band(integer.bor(integer.lshift(V15, 16i), integer.rshift(V15, 16i)), MASK)
		V10 = integer.band(integer.add(V10, V15), MASK); V05 = integer.bxor(V05, V10); V05 = integer.band(integer.bor(integer.lshift(V05, 20i), integer.rshift(V05, 12i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V05), M00), MASK); V15 = integer.bxor(V15, V00); V15 = integer.band(integer.bor(integer.lshift(V15, 24i), integer.rshift(V15, 8i)), MASK)
		V10 = integer.band(integer.add(V10, V15), MASK); V05 = integer.bxor(V05, V10); V05 = integer.band(integer.bor(integer.lshift(V05, 25i), integer.rshift(V05, 7i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V06), M11), MASK); V12 = integer.bxor(V12, V01); V12 = integer.band(integer.bor(integer.lshift(V12, 16i), integer.rshift(V12, 16i)), MASK)
		V11 = integer.band(integer.add(V11, V12), MASK); V06 = integer.bxor(V06, V11); V06 = integer.band(integer.bor(integer.lshift(V06, 20i), integer.rshift(V06, 12i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V06), M02), MASK); V12 = integer.bxor(V12, V01); V12 = integer.band(integer.bor(integer.lshift(V12, 24i), integer.rshift(V12, 8i)), MASK)
		V11 = integer.band(integer.add(V11, V12), MASK); V06 = integer.bxor(V06, V11); V06 = integer.band(integer.bor(integer.lshift(V06, 25i), integer.rshift(V06, 7i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V07), M05), MASK); V13 = integer.bxor(V13, V02); V13 = integer.band(integer.bor(integer.lshift(V13, 16i), integer.rshift(V13, 16i)), MASK)
		V08 = integer.band(integer.add(V08, V13), MASK); V07 = integer.bxor(V07, V08); V07 = integer.band(integer.bor(integer.lshift(V07, 20i), integer.rshift(V07, 12i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V07), M08), MASK); V13 = integer.bxor(V13, V02); V13 = integer.band(integer.bor(integer.lshift(V13, 24i), integer.rshift(V13, 8i)), MASK)
		V08 = integer.band(integer.add(V08, V13), MASK); V07 = integer.bxor(V07, V08); V07 = integer.band(integer.bor(integer.lshift(V07, 25i), integer.rshift(V07, 7i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V04), M01), MASK); V14 = integer.bxor(V14, V03); V14 = integer.band(integer.bor(integer.lshift(V14, 16i), integer.rshift(V14, 16i)), MASK)
		V09 = integer.band(integer.add(V09, V14), MASK); V04 = integer.bxor(V04, V09); V04 = integer.band(integer.bor(integer.lshift(V04, 20i), integer.rshift(V04, 12i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V04), M06), MASK); V14 = integer.bxor(V14, V03); V14 = integer.band(integer.bor(integer.lshift(V14, 24i), integer.rshift(V14, 8i)), MASK)
		V09 = integer.band(integer.add(V09, V14), MASK); V04 = integer.bxor(V04, V09); V04 = integer.band(integer.bor(integer.lshift(V04, 25i), integer.rshift(V04, 7i)), MASK)

		V00 = integer.band(integer.add(integer.add(V00, V04), M12), MASK); V12 = integer.bxor(V12, V00); V12 = integer.band(integer.bor(integer.lshift(V12, 16i), integer.rshift(V12, 16i)), MASK)
		V08 = integer.band(integer.add(V08, V12), MASK); V04 = integer.bxor(V04, V08); V04 = integer.band(integer.bor(integer.lshift(V04, 20i), integer.rshift(V04, 12i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V04), M13), MASK); V12 = integer.bxor(V12, V00); V12 = integer.band(integer.bor(integer.lshift(V12, 24i), integer.rshift(V12, 8i)), MASK)
		V08 = integer.band(integer.add(V08, V12), MASK); V04 = integer.bxor(V04, V08); V04 = integer.band(integer.bor(integer.lshift(V04, 25i), integer.rshift(V04, 7i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V05), M09), MASK); V13 = integer.bxor(V13, V01); V13 = integer.band(integer.bor(integer.lshift(V13, 16i), integer.rshift(V13, 16i)), MASK)
		V09 = integer.band(integer.add(V09, V13), MASK); V05 = integer.bxor(V05, V09); V05 = integer.band(integer.bor(integer.lshift(V05, 20i), integer.rshift(V05, 12i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V05), M11), MASK); V13 = integer.bxor(V13, V01); V13 = integer.band(integer.bor(integer.lshift(V13, 24i), integer.rshift(V13, 8i)), MASK)
		V09 = integer.band(integer.add(V09, V13), MASK); V05 = integer.bxor(V05, V09); V05 = integer.band(integer.bor(integer.lshift(V05, 25i), integer.rshift(V05, 7i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V06), M15), MASK); V14 = integer.bxor(V14, V02); V14 = integer.band(integer.bor(integer.lshift(V14, 16i), integer.rshift(V14, 16i)), MASK)
		V10 = integer.band(integer.add(V10, V14), MASK); V06 = integer.bxor(V06, V10); V06 = integer.band(integer.bor(integer.lshift(V06, 20i), integer.rshift(V06, 12i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V06), M10), MASK); V14 = integer.bxor(V14, V02); V14 = integer.band(integer.bor(integer.lshift(V14, 24i), integer.rshift(V14, 8i)), MASK)
		V10 = integer.band(integer.add(V10, V14), MASK); V06 = integer.bxor(V06, V10); V06 = integer.band(integer.bor(integer.lshift(V06, 25i), integer.rshift(V06, 7i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V07), M14), MASK); V15 = integer.bxor(V15, V03); V15 = integer.band(integer.bor(integer.lshift(V15, 16i), integer.rshift(V15, 16i)), MASK)
		V11 = integer.band(integer.add(V11, V15), MASK); V07 = integer.bxor(V07, V11); V07 = integer.band(integer.bor(integer.lshift(V07, 20i), integer.rshift(V07, 12i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V07), M08), MASK); V15 = integer.bxor(V15, V03); V15 = integer.band(integer.bor(integer.lshift(V15, 24i), integer.rshift(V15, 8i)), MASK)
		V11 = integer.band(integer.add(V11, V15), MASK); V07 = integer.bxor(V07, V11); V07 = integer.band(integer.bor(integer.lshift(V07, 25i), integer.rshift(V07, 7i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V05), M07), MASK); V15 = integer.bxor(V15, V00); V15 = integer.band(integer.bor(integer.lshift(V15, 16i), integer.rshift(V15, 16i)), MASK)
		V10 = integer.band(integer.add(V10, V15), MASK); V05 = integer.bxor(V05, V10); V05 = integer.band(integer.bor(integer.lshift(V05, 20i), integer.rshift(V05, 12i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V05), M02), MASK); V15 = integer.bxor(V15, V00); V15 = integer.band(integer.bor(integer.lshift(V15, 24i), integer.rshift(V15, 8i)), MASK)
		V10 = integer.band(integer.add(V10, V15), MASK); V05 = integer.bxor(V05, V10); V05 = integer.band(integer.bor(integer.lshift(V05, 25i), integer.rshift(V05, 7i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V06), M05), MASK); V12 = integer.bxor(V12, V01); V12 = integer.band(integer.bor(integer.lshift(V12, 16i), integer.rshift(V12, 16i)), MASK)
		V11 = integer.band(integer.add(V11, V12), MASK); V06 = integer.bxor(V06, V11); V06 = integer.band(integer.bor(integer.lshift(V06, 20i), integer.rshift(V06, 12i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V06), M03), MASK); V12 = integer.bxor(V12, V01); V12 = integer.band(integer.bor(integer.lshift(V12, 24i), integer.rshift(V12, 8i)), MASK)
		V11 = integer.band(integer.add(V11, V12), MASK); V06 = integer.bxor(V06, V11); V06 = integer.band(integer.bor(integer.lshift(V06, 25i), integer.rshift(V06, 7i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V07), M00), MASK); V13 = integer.bxor(V13, V02); V13 = integer.band(integer.bor(integer.lshift(V13, 16i), integer.rshift(V13, 16i)), MASK)
		V08 = integer.band(integer.add(V08, V13), MASK); V07 = integer.bxor(V07, V08); V07 = integer.band(integer.bor(integer.lshift(V07, 20i), integer.rshift(V07, 12i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V07), M01), MASK); V13 = integer.bxor(V13, V02); V13 = integer.band(integer.bor(integer.lshift(V13, 24i), integer.rshift(V13, 8i)), MASK)
		V08 = integer.band(integer.add(V08, V13), MASK); V07 = integer.bxor(V07, V08); V07 = integer.band(integer.bor(integer.lshift(V07, 25i), integer.rshift(V07, 7i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V04), M06), MASK); V14 = integer.bxor(V14, V03); V14 = integer.band(integer.bor(integer.lshift(V14, 16i), integer.rshift(V14, 16i)), MASK)
		V09 = integer.band(integer.add(V09, V14), MASK); V04 = integer.bxor(V04, V09); V04 = integer.band(integer.bor(integer.lshift(V04, 20i), integer.rshift(V04, 12i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V04), M04), MASK); V14 = integer.bxor(V14, V03); V14 = integer.band(integer.bor(integer.lshift(V14, 24i), integer.rshift(V14, 8i)), MASK)
		V09 = integer.band(integer.add(V09, V14), MASK); V04 = integer.bxor(V04, V09); V04 = integer.band(integer.bor(integer.lshift(V04, 25i), integer.rshift(V04, 7i)), MASK)

		V00 = integer.band(integer.add(integer.add(V00, V04), M09), MASK); V12 = integer.bxor(V12, V00); V12 = integer.band(integer.bor(integer.lshift(V12, 16i), integer.rshift(V12, 16i)), MASK)
		V08 = integer.band(integer.add(V08, V12), MASK); V04 = integer.bxor(V04, V08); V04 = integer.band(integer.bor(integer.lshift(V04, 20i), integer.rshift(V04, 12i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V04), M14), MASK); V12 = integer.bxor(V12, V00); V12 = integer.band(integer.bor(integer.lshift(V12, 24i), integer.rshift(V12, 8i)), MASK)
		V08 = integer.band(integer.add(V08, V12), MASK); V04 = integer.bxor(V04, V08); V04 = integer.band(integer.bor(integer.lshift(V04, 25i), integer.rshift(V04, 7i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V05), M11), MASK); V13 = integer.bxor(V13, V01); V13 = integer.band(integer.bor(integer.lshift(V13, 16i), integer.rshift(V13, 16i)), MASK)
		V09 = integer.band(integer.add(V09, V13), MASK); V05 = integer.bxor(V05, V09); V05 = integer.band(integer.bor(integer.lshift(V05, 20i), integer.rshift(V05, 12i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V05), M05), MASK); V13 = integer.bxor(V13, V01); V13 = integer.band(integer.bor(integer.lshift(V13, 24i), integer.rshift(V13, 8i)), MASK)
		V09 = integer.band(integer.add(V09, V13), MASK); V05 = integer.bxor(V05, V09); V05 = integer.band(integer.bor(integer.lshift(V05, 25i), integer.rshift(V05, 7i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V06), M08), MASK); V14 = integer.bxor(V14, V02); V14 = integer.band(integer.bor(integer.lshift(V14, 16i), integer.rshift(V14, 16i)), MASK)
		V10 = integer.band(integer.add(V10, V14), MASK); V06 = integer.bxor(V06, V10); V06 = integer.band(integer.bor(integer.lshift(V06, 20i), integer.rshift(V06, 12i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V06), M12), MASK); V14 = integer.bxor(V14, V02); V14 = integer.band(integer.bor(integer.lshift(V14, 24i), integer.rshift(V14, 8i)), MASK)
		V10 = integer.band(integer.add(V10, V14), MASK); V06 = integer.bxor(V06, V10); V06 = integer.band(integer.bor(integer.lshift(V06, 25i), integer.rshift(V06, 7i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V07), M15), MASK); V15 = integer.bxor(V15, V03); V15 = integer.band(integer.bor(integer.lshift(V15, 16i), integer.rshift(V15, 16i)), MASK)
		V11 = integer.band(integer.add(V11, V15), MASK); V07 = integer.bxor(V07, V11); V07 = integer.band(integer.bor(integer.lshift(V07, 20i), integer.rshift(V07, 12i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V07), M01), MASK); V15 = integer.bxor(V15, V03); V15 = integer.band(integer.bor(integer.lshift(V15, 24i), integer.rshift(V15, 8i)), MASK)
		V11 = integer.band(integer.add(V11, V15), MASK); V07 = integer.bxor(V07, V11); V07 = integer.band(integer.bor(integer.lshift(V07, 25i), integer.rshift(V07, 7i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V05), M13), MASK); V15 = integer.bxor(V15, V00); V15 = integer.band(integer.bor(integer.lshift(V15, 16i), integer.rshift(V15, 16i)), MASK)
		V10 = integer.band(integer.add(V10, V15), MASK); V05 = integer.bxor(V05, V10); V05 = integer.band(integer.bor(integer.lshift(V05, 20i), integer.rshift(V05, 12i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V05), M03), MASK); V15 = integer.bxor(V15, V00); V15 = integer.band(integer.bor(integer.lshift(V15, 24i), integer.rshift(V15, 8i)), MASK)
		V10 = integer.band(integer.add(V10, V15), MASK); V05 = integer.bxor(V05, V10); V05 = integer.band(integer.bor(integer.lshift(V05, 25i), integer.rshift(V05, 7i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V06), M00), MASK); V12 = integer.bxor(V12, V01); V12 = integer.band(integer.bor(integer.lshift(V12, 16i), integer.rshift(V12, 16i)), MASK)
		V11 = integer.band(integer.add(V11, V12), MASK); V06 = integer.bxor(V06, V11); V06 = integer.band(integer.bor(integer.lshift(V06, 20i), integer.rshift(V06, 12i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V06), M10), MASK); V12 = integer.bxor(V12, V01); V12 = integer.band(integer.bor(integer.lshift(V12, 24i), integer.rshift(V12, 8i)), MASK)
		V11 = integer.band(integer.add(V11, V12), MASK); V06 = integer.bxor(V06, V11); V06 = integer.band(integer.bor(integer.lshift(V06, 25i), integer.rshift(V06, 7i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V07), M02), MASK); V13 = integer.bxor(V13, V02); V13 = integer.band(integer.bor(integer.lshift(V13, 16i), integer.rshift(V13, 16i)), MASK)
		V08 = integer.band(integer.add(V08, V13), MASK); V07 = integer.bxor(V07, V08); V07 = integer.band(integer.bor(integer.lshift(V07, 20i), integer.rshift(V07, 12i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V07), M06), MASK); V13 = integer.bxor(V13, V02); V13 = integer.band(integer.bor(integer.lshift(V13, 24i), integer.rshift(V13, 8i)), MASK)
		V08 = integer.band(integer.add(V08, V13), MASK); V07 = integer.bxor(V07, V08); V07 = integer.band(integer.bor(integer.lshift(V07, 25i), integer.rshift(V07, 7i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V04), M04), MASK); V14 = integer.bxor(V14, V03); V14 = integer.band(integer.bor(integer.lshift(V14, 16i), integer.rshift(V14, 16i)), MASK)
		V09 = integer.band(integer.add(V09, V14), MASK); V04 = integer.bxor(V04, V09); V04 = integer.band(integer.bor(integer.lshift(V04, 20i), integer.rshift(V04, 12i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V04), M07), MASK); V14 = integer.bxor(V14, V03); V14 = integer.band(integer.bor(integer.lshift(V14, 24i), integer.rshift(V14, 8i)), MASK)
		V09 = integer.band(integer.add(V09, V14), MASK); V04 = integer.bxor(V04, V09); V04 = integer.band(integer.bor(integer.lshift(V04, 25i), integer.rshift(V04, 7i)), MASK)

		V00 = integer.band(integer.add(integer.add(V00, V04), M11), MASK); V12 = integer.bxor(V12, V00); V12 = integer.band(integer.bor(integer.lshift(V12, 16i), integer.rshift(V12, 16i)), MASK)
		V08 = integer.band(integer.add(V08, V12), MASK); V04 = integer.bxor(V04, V08); V04 = integer.band(integer.bor(integer.lshift(V04, 20i), integer.rshift(V04, 12i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V04), M15), MASK); V12 = integer.bxor(V12, V00); V12 = integer.band(integer.bor(integer.lshift(V12, 24i), integer.rshift(V12, 8i)), MASK)
		V08 = integer.band(integer.add(V08, V12), MASK); V04 = integer.bxor(V04, V08); V04 = integer.band(integer.bor(integer.lshift(V04, 25i), integer.rshift(V04, 7i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V05), M05), MASK); V13 = integer.bxor(V13, V01); V13 = integer.band(integer.bor(integer.lshift(V13, 16i), integer.rshift(V13, 16i)), MASK)
		V09 = integer.band(integer.add(V09, V13), MASK); V05 = integer.bxor(V05, V09); V05 = integer.band(integer.bor(integer.lshift(V05, 20i), integer.rshift(V05, 12i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V05), M00), MASK); V13 = integer.bxor(V13, V01); V13 = integer.band(integer.bor(integer.lshift(V13, 24i), integer.rshift(V13, 8i)), MASK)
		V09 = integer.band(integer.add(V09, V13), MASK); V05 = integer.bxor(V05, V09); V05 = integer.band(integer.bor(integer.lshift(V05, 25i), integer.rshift(V05, 7i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V06), M01), MASK); V14 = integer.bxor(V14, V02); V14 = integer.band(integer.bor(integer.lshift(V14, 16i), integer.rshift(V14, 16i)), MASK)
		V10 = integer.band(integer.add(V10, V14), MASK); V06 = integer.bxor(V06, V10); V06 = integer.band(integer.bor(integer.lshift(V06, 20i), integer.rshift(V06, 12i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V06), M09), MASK); V14 = integer.bxor(V14, V02); V14 = integer.band(integer.bor(integer.lshift(V14, 24i), integer.rshift(V14, 8i)), MASK)
		V10 = integer.band(integer.add(V10, V14), MASK); V06 = integer.bxor(V06, V10); V06 = integer.band(integer.bor(integer.lshift(V06, 25i), integer.rshift(V06, 7i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V07), M08), MASK); V15 = integer.bxor(V15, V03); V15 = integer.band(integer.bor(integer.lshift(V15, 16i), integer.rshift(V15, 16i)), MASK)
		V11 = integer.band(integer.add(V11, V15), MASK); V07 = integer.bxor(V07, V11); V07 = integer.band(integer.bor(integer.lshift(V07, 20i), integer.rshift(V07, 12i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V07), M06), MASK); V15 = integer.bxor(V15, V03); V15 = integer.band(integer.bor(integer.lshift(V15, 24i), integer.rshift(V15, 8i)), MASK)
		V11 = integer.band(integer.add(V11, V15), MASK); V07 = integer.bxor(V07, V11); V07 = integer.band(integer.bor(integer.lshift(V07, 25i), integer.rshift(V07, 7i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V05), M14), MASK); V15 = integer.bxor(V15, V00); V15 = integer.band(integer.bor(integer.lshift(V15, 16i), integer.rshift(V15, 16i)), MASK)
		V10 = integer.band(integer.add(V10, V15), MASK); V05 = integer.bxor(V05, V10); V05 = integer.band(integer.bor(integer.lshift(V05, 20i), integer.rshift(V05, 12i)), MASK)
		V00 = integer.band(integer.add(integer.add(V00, V05), M10), MASK); V15 = integer.bxor(V15, V00); V15 = integer.band(integer.bor(integer.lshift(V15, 24i), integer.rshift(V15, 8i)), MASK)
		V10 = integer.band(integer.add(V10, V15), MASK); V05 = integer.bxor(V05, V10); V05 = integer.band(integer.bor(integer.lshift(V05, 25i), integer.rshift(V05, 7i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V06), M02), MASK); V12 = integer.bxor(V12, V01); V12 = integer.band(integer.bor(integer.lshift(V12, 16i), integer.rshift(V12, 16i)), MASK)
		V11 = integer.band(integer.add(V11, V12), MASK); V06 = integer.bxor(V06, V11); V06 = integer.band(integer.bor(integer.lshift(V06, 20i), integer.rshift(V06, 12i)), MASK)
		V01 = integer.band(integer.add(integer.add(V01, V06), M12), MASK); V12 = integer.bxor(V12, V01); V12 = integer.band(integer.bor(integer.lshift(V12, 24i), integer.rshift(V12, 8i)), MASK)
		V11 = integer.band(integer.add(V11, V12), MASK); V06 = integer.bxor(V06, V11); V06 = integer.band(integer.bor(integer.lshift(V06, 25i), integer.rshift(V06, 7i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V07), M03), MASK); V13 = integer.bxor(V13, V02); V13 = integer.band(integer.bor(integer.lshift(V13, 16i), integer.rshift(V13, 16i)), MASK)
		V08 = integer.band(integer.add(V08, V13), MASK); V07 = integer.bxor(V07, V08); V07 = integer.band(integer.bor(integer.lshift(V07, 20i), integer.rshift(V07, 12i)), MASK)
		V02 = integer.band(integer.add(integer.add(V02, V07), M04), MASK); V13 = integer.bxor(V13, V02); V13 = integer.band(integer.bor(integer.lshift(V13, 24i), integer.rshift(V13, 8i)), MASK)
		V08 = integer.band(integer.add(V08, V13), MASK); V07 = integer.bxor(V07, V08); V07 = integer.band(integer.bor(integer.lshift(V07, 25i), integer.rshift(V07, 7i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V04), M07), MASK); V14 = integer.bxor(V14, V03); V14 = integer.band(integer.bor(integer.lshift(V14, 16i), integer.rshift(V14, 16i)), MASK)
		V09 = integer.band(integer.add(V09, V14), MASK); V04 = integer.bxor(V04, V09); V04 = integer.band(integer.bor(integer.lshift(V04, 20i), integer.rshift(V04, 12i)), MASK)
		V03 = integer.band(integer.add(integer.add(V03, V04), M13), MASK); V14 = integer.bxor(V14, V03); V14 = integer.band(integer.bor(integer.lshift(V14, 24i), integer.rshift(V14, 8i)), MASK)
		V09 = integer.band(integer.add(V09, V14), MASK); V04 = integer.bxor(V04, V09); V04 = integer.band(integer.bor(integer.lshift(V04, 25i), integer.rshift(V04, 7i)), MASK)

	if IsFull then
		local Result = buffer.create(EXTENDED_CV_SIZE)
		buffer.writeu32(Result, 0, integer.tonumber(integer.bxor(V00, V08)))
		buffer.writeu32(Result, 4, integer.tonumber(integer.bxor(V01, V09)))
		buffer.writeu32(Result, 8, integer.tonumber(integer.bxor(V02, V10)))
		buffer.writeu32(Result, 12, integer.tonumber(integer.bxor(V03, V11)))
		buffer.writeu32(Result, 16, integer.tonumber(integer.bxor(V04, V12)))
		buffer.writeu32(Result, 20, integer.tonumber(integer.bxor(V05, V13)))
		buffer.writeu32(Result, 24, integer.tonumber(integer.bxor(V06, V14)))
		buffer.writeu32(Result, 28, integer.tonumber(integer.bxor(V07, V15)))
		buffer.writeu32(Result, 32, integer.tonumber(integer.bxor(V08, Hash00)))
		buffer.writeu32(Result, 36, integer.tonumber(integer.bxor(V09, Hash01)))
		buffer.writeu32(Result, 40, integer.tonumber(integer.bxor(V10, Hash02)))
		buffer.writeu32(Result, 44, integer.tonumber(integer.bxor(V11, Hash03)))
		buffer.writeu32(Result, 48, integer.tonumber(integer.bxor(V12, Hash04)))
		buffer.writeu32(Result, 52, integer.tonumber(integer.bxor(V13, Hash05)))
		buffer.writeu32(Result, 56, integer.tonumber(integer.bxor(V14, Hash06)))
		buffer.writeu32(Result, 60, integer.tonumber(integer.bxor(V15, Hash07)))
		return Result
	else
		local Result = Storage or buffer.create(CV_SIZE)
		buffer.writeu32(Result, 0, integer.tonumber(integer.bxor(V00, V08)))
		buffer.writeu32(Result, 4, integer.tonumber(integer.bxor(V01, V09)))
		buffer.writeu32(Result, 8, integer.tonumber(integer.bxor(V02, V10)))
		buffer.writeu32(Result, 12, integer.tonumber(integer.bxor(V03, V11)))
		buffer.writeu32(Result, 16, integer.tonumber(integer.bxor(V04, V12)))
		buffer.writeu32(Result, 20, integer.tonumber(integer.bxor(V05, V13)))
		buffer.writeu32(Result, 24, integer.tonumber(integer.bxor(V06, V14)))
		buffer.writeu32(Result, 28, integer.tonumber(integer.bxor(V07, V15)))
		return Result
	end
end


local function ProcessMessage(InitialHashVector: buffer, Flags: number, Message: buffer, Length: number): buffer
	local MessageLength = buffer.len(Message)
	local StateCvs = buffer.create(STACK_BUFFER_SIZE)
	local StateCv = buffer.create(CV_SIZE)

	local StackSize = 0
	local StateCounter = 0

	local StateChunkNumber = 0
	local StateEndFlag = 0

	local BlockSize = BLOCK_SIZE
	local CvSize = CV_SIZE
	local ExtendedCvSize = EXTENDED_CV_SIZE

	local StateStartFlag = CHUNK_START
	local ChunkStart = CHUNK_START
	local ChunkEnd = CHUNK_END

	local ParentFlag = PARENT_FLAG
	local RootFlag = ROOT_FLAG
	local FlagsParent = Flags + ParentFlag

	local PopCv = buffer.create(CvSize)
	local MergeBlock = buffer.create(ExtendedCvSize)
	local StackCv = buffer.create(CvSize)
	local Block = buffer.create(ExtendedCvSize)

	buffer.copy(StateCv, 0, InitialHashVector, 0, CvSize)

	for BlockOffset = 0, MessageLength - BlockSize - 1, BlockSize do
		local StateFlags = Flags + StateStartFlag + StateEndFlag
		StateCv = Compress(StateCv, Message, BlockOffset, StateCounter, BlockSize, StateFlags, false, StateCv)
		StateStartFlag = 0
		StateChunkNumber += 1

		if StateChunkNumber == 15 then
			StateEndFlag = ChunkEnd
		elseif StateChunkNumber == 16 then
			local MergeCv = StateCv
			local MergeAmount = StateCounter + 1

			while MergeAmount % 2 == 0 do
				StackSize -= 1
				buffer.copy(PopCv, 0, StateCvs, StackSize * CvSize, CvSize)
				buffer.copy(MergeBlock, 0, PopCv, 0, CvSize)
				buffer.copy(MergeBlock, CvSize, MergeCv, 0, CvSize)
				MergeCv = Compress(InitialHashVector, MergeBlock, 0, 0, BlockSize, FlagsParent)
				MergeAmount /= 2
			end

			buffer.copy(StateCvs, StackSize * CvSize, MergeCv, 0, CvSize)
			StackSize += 1

			buffer.copy(StateCv, 0, InitialHashVector, 0, CvSize)
			StateStartFlag = ChunkStart
			StateCounter += 1
			StateChunkNumber = 0
			StateEndFlag = 0
		end
	end

	local LastLength = MessageLength == 0 and 0 or ((MessageLength - 1) % BlockSize + 1)
	local PaddedMessage = buffer.create(BlockSize)
	if LastLength > 0 then
		buffer.copy(PaddedMessage, 0, Message, MessageLength - LastLength, LastLength)
	end

	local OutputCv: buffer
	local OutputBlock: buffer
	local OutputLength: number
	local OutputFlags: number

	if StateCounter > 0 then
		local StateFlags = Flags + StateStartFlag + ChunkEnd
		local MergeCv = Compress(StateCv, PaddedMessage, 0, StateCounter, LastLength, StateFlags)
		for Index = StackSize, 2, -1 do
			buffer.copy(StackCv, 0, StateCvs, (Index - 1) * CvSize, CvSize)
			buffer.copy(Block, 0, StackCv, 0, CvSize)
			buffer.copy(Block, CvSize, MergeCv, 0, CvSize)
			MergeCv = Compress(InitialHashVector, Block, 0, 0, BlockSize, FlagsParent)
		end

		OutputCv = InitialHashVector
		local FirstStackCv = buffer.create(CvSize)
		buffer.copy(FirstStackCv, 0, StateCvs, 0, CvSize)
		OutputBlock = buffer.create(ExtendedCvSize)

		buffer.copy(OutputBlock, 0, FirstStackCv, 0, CvSize)
		buffer.copy(OutputBlock, CvSize, MergeCv, 0, CvSize)

		OutputLength = BlockSize
		OutputFlags = Flags + RootFlag + ParentFlag
	else
		OutputCv = StateCv
		OutputBlock = PaddedMessage
		OutputLength = LastLength
		OutputFlags = Flags + StateStartFlag + ChunkEnd + RootFlag
	end

	local Output = buffer.create(Length)
	local OutputOffset = 0
	for Index = 0, Length // BlockSize do
		local MessageDigest = Compress(OutputCv, OutputBlock, 0, Index, OutputLength, OutputFlags, true)
		local BytesToCopy = math.min(BlockSize, Length - OutputOffset)
		buffer.copy(Output, OutputOffset, MessageDigest, 0, BytesToCopy)
		OutputOffset += BytesToCopy
		if OutputOffset >= Length then
			break
		end
	end

	return Output
end

function Blake3.Digest(Message: buffer, Length: number?): (string, buffer)
	if Message == nil then
		error("Message cannot be nil", 2)
	end

	if typeof(Message) ~= "buffer" then
		error(`Message must be a buffer, got {typeof(Message)}`, 2)
	end

	if Length then
		if typeof(Length) ~= "number" then
			error(`Length must be a number, got {typeof(Length)}`, 2)
		end

		if Length ~= math.floor(Length) then
			error(`Length must be an integer, got {Length}`, 2)
		end

		if Length < BLAKE3_MIN_OUTPUT_BYTES then
			error(`Length must be at least {BLAKE3_MIN_OUTPUT_BYTES} byte, got {Length} bytes`, 2)
		end

		if Length > BLAKE3_MAX_OUTPUT_BYTES then
			error(`Length must be at most {BLAKE3_MAX_OUTPUT_BYTES} bytes, got {Length} bytes`, 2)
		end
	end

	local Result = ProcessMessage(INITIAL_VECTORS, 0, Message, Length or 32)

	return ToHex(Result), Result
end

function Blake3.DigestKeyed(Message: buffer, Key: buffer, Length: number?): (string, buffer)
	if Key == nil then
		error("Key cannot be nil", 2)
	end

	if typeof(Key) ~= "buffer" then
		error(`Key must be a buffer, got {typeof(Key)}`, 2)
	end

	local KeyLength = buffer.len(Key)
	if KeyLength ~= BLAKE3_KEY_SIZE then
		error(`Key must be exactly {BLAKE3_KEY_SIZE} bytes long, got {KeyLength} bytes`, 2)
	end

	if Message == nil then
		error("Message cannot be nil", 2)
	end
	if typeof(Message) ~= "buffer" then
		error(`Message must be a buffer, got {typeof(Message)}`, 2)
	end

	if Length then
		if typeof(Length) ~= "number" then
			error(`Length must be a number, got {typeof(Length)}`, 2)
		end
		if Length ~= math.floor(Length) then
			error(`Length must be an integer, got {Length}`, 2)
		end
		if Length < BLAKE3_MIN_OUTPUT_BYTES then
			error(`Length must be at least {BLAKE3_MIN_OUTPUT_BYTES} byte, got {Length} bytes`, 2)
		end
		if Length > BLAKE3_MAX_OUTPUT_BYTES then
			error(`Length must be at most {BLAKE3_MAX_OUTPUT_BYTES} bytes, got {Length} bytes`, 2)
		end
	end

	local Result = ProcessMessage(Key, HASH_FLAG, Message, Length or 32)

	return ToHex(Result), Result
end

function Blake3.DeriveKey(Context: buffer): (buffer, number?) -> (string, buffer)
	if Context == nil then
		error("Context cannot be nil", 2)
	end

	if typeof(Context) ~= "buffer" then
		error(`Context must be a buffer, got {typeof(Context)}`, 2)
	end

	local ContextHash = ProcessMessage(INITIAL_VECTORS, DERIVE_CONTEXT_FLAG, Context, 32)

	return function(Material: buffer, Length: number?): (string, buffer)
		if Material == nil then
			error("Material cannot be nil", 2)
		end

		if typeof(Material) ~= "buffer" then
			error(`Material must be a buffer, got {typeof(Material)}`, 2)
		end

		if Length then
			if typeof(Length) ~= "number" then
				error(`Length must be a number, got {typeof(Length)}`, 2)
			end

			if Length ~= math.floor(Length) then
				error(`Length must be an integer, got {Length}`, 2)
			end

			if Length < BLAKE3_MIN_OUTPUT_BYTES then
				error(`Length must be at least {BLAKE3_MIN_OUTPUT_BYTES} byte, got {Length} bytes`, 2)
			end

			if Length > BLAKE3_MAX_OUTPUT_BYTES then
				error(`Length must be at most {BLAKE3_MAX_OUTPUT_BYTES} bytes, got {Length} bytes`, 2)
			end
		end

		local Result = ProcessMessage(ContextHash, DERIVE_MATERIAL_FLAG, Material, Length or 32)

		return ToHex(Result), Result
	end
end

return Blake3
