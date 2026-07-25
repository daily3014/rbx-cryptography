--[=[
	Cryptography library: Blake3
	
	Sizes:
		Key: 32 bytes
		Output: variable
	
	Return type: (string, buffer)
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
local DUP = 0x100000001i

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
	local Hash00 = integer.mul(integer.create(buffer.readu32(Hash, 0)) :: integer, DUP)
	local Hash01 = integer.mul(integer.create(buffer.readu32(Hash, 4)) :: integer, DUP)
	local Hash02 = integer.mul(integer.create(buffer.readu32(Hash, 8)) :: integer, DUP)
	local Hash03 = integer.mul(integer.create(buffer.readu32(Hash, 12)) :: integer, DUP)
	local Hash04 = integer.mul(integer.create(buffer.readu32(Hash, 16)) :: integer, DUP)
	local Hash05 = integer.mul(integer.create(buffer.readu32(Hash, 20)) :: integer, DUP)
	local Hash06 = integer.mul(integer.create(buffer.readu32(Hash, 24)) :: integer, DUP)
	local Hash07 = integer.mul(integer.create(buffer.readu32(Hash, 28)) :: integer, DUP)

	local V00, V01, V02, V03 = Hash00, Hash01, Hash02, Hash03
	local V04, V05, V06, V07 = Hash04, Hash05, Hash06, Hash07
	local V08, V09, V10, V11 = 0x6A09E6676A09E667i, 0xBB67AE85BB67AE85i, 0x3C6EF3723C6EF372i, 0xA54FF53AA54FF53Ai

	local CounterLow = Counter % 0x100000000
	local V12 = integer.mul(integer.create(CounterLow) :: integer, DUP)
	local V13 = integer.mul(integer.create((Counter - CounterLow) / 0x100000000) :: integer, DUP)
	local V14 = integer.mul(integer.create(BlockLength) :: integer, DUP)
	local V15 = integer.mul(integer.create(Flags) :: integer, DUP)

	local M00 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 0)) :: integer, DUP)
	local M01 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 4)) :: integer, DUP)
	local M02 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 8)) :: integer, DUP)
	local M03 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 12)) :: integer, DUP)
	local M04 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 16)) :: integer, DUP)
	local M05 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 20)) :: integer, DUP)
	local M06 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 24)) :: integer, DUP)
	local M07 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 28)) :: integer, DUP)
	local M08 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 32)) :: integer, DUP)
	local M09 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 36)) :: integer, DUP)
	local M10 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 40)) :: integer, DUP)
	local M11 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 44)) :: integer, DUP)
	local M12 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 48)) :: integer, DUP)
	local M13 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 52)) :: integer, DUP)
	local M14 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 56)) :: integer, DUP)
	local M15 = integer.mul(integer.create(buffer.readu32(MessageBlock, MessageOffset + 60)) :: integer, DUP)

		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V04), M00), MASK), integer.lshift(integer.add(integer.add(V00, V04), M00), 32i)); V12 = integer.bxor(V12, V00); V12 = integer.rrotate(V12, 16i)
		V08 = integer.bor(integer.band(integer.add(V08, V12), MASK), integer.lshift(integer.add(V08, V12), 32i)); V04 = integer.bxor(V04, V08); V04 = integer.rrotate(V04, 12i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V04), M01), MASK), integer.lshift(integer.add(integer.add(V00, V04), M01), 32i)); V12 = integer.bxor(V12, V00); V12 = integer.rrotate(V12, 8i)
		V08 = integer.bor(integer.band(integer.add(V08, V12), MASK), integer.lshift(integer.add(V08, V12), 32i)); V04 = integer.bxor(V04, V08); V04 = integer.rrotate(V04, 7i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V05), M02), MASK), integer.lshift(integer.add(integer.add(V01, V05), M02), 32i)); V13 = integer.bxor(V13, V01); V13 = integer.rrotate(V13, 16i)
		V09 = integer.bor(integer.band(integer.add(V09, V13), MASK), integer.lshift(integer.add(V09, V13), 32i)); V05 = integer.bxor(V05, V09); V05 = integer.rrotate(V05, 12i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V05), M03), MASK), integer.lshift(integer.add(integer.add(V01, V05), M03), 32i)); V13 = integer.bxor(V13, V01); V13 = integer.rrotate(V13, 8i)
		V09 = integer.bor(integer.band(integer.add(V09, V13), MASK), integer.lshift(integer.add(V09, V13), 32i)); V05 = integer.bxor(V05, V09); V05 = integer.rrotate(V05, 7i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V06), M04), MASK), integer.lshift(integer.add(integer.add(V02, V06), M04), 32i)); V14 = integer.bxor(V14, V02); V14 = integer.rrotate(V14, 16i)
		V10 = integer.bor(integer.band(integer.add(V10, V14), MASK), integer.lshift(integer.add(V10, V14), 32i)); V06 = integer.bxor(V06, V10); V06 = integer.rrotate(V06, 12i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V06), M05), MASK), integer.lshift(integer.add(integer.add(V02, V06), M05), 32i)); V14 = integer.bxor(V14, V02); V14 = integer.rrotate(V14, 8i)
		V10 = integer.bor(integer.band(integer.add(V10, V14), MASK), integer.lshift(integer.add(V10, V14), 32i)); V06 = integer.bxor(V06, V10); V06 = integer.rrotate(V06, 7i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V07), M06), MASK), integer.lshift(integer.add(integer.add(V03, V07), M06), 32i)); V15 = integer.bxor(V15, V03); V15 = integer.rrotate(V15, 16i)
		V11 = integer.bor(integer.band(integer.add(V11, V15), MASK), integer.lshift(integer.add(V11, V15), 32i)); V07 = integer.bxor(V07, V11); V07 = integer.rrotate(V07, 12i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V07), M07), MASK), integer.lshift(integer.add(integer.add(V03, V07), M07), 32i)); V15 = integer.bxor(V15, V03); V15 = integer.rrotate(V15, 8i)
		V11 = integer.bor(integer.band(integer.add(V11, V15), MASK), integer.lshift(integer.add(V11, V15), 32i)); V07 = integer.bxor(V07, V11); V07 = integer.rrotate(V07, 7i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V05), M08), MASK), integer.lshift(integer.add(integer.add(V00, V05), M08), 32i)); V15 = integer.bxor(V15, V00); V15 = integer.rrotate(V15, 16i)
		V10 = integer.bor(integer.band(integer.add(V10, V15), MASK), integer.lshift(integer.add(V10, V15), 32i)); V05 = integer.bxor(V05, V10); V05 = integer.rrotate(V05, 12i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V05), M09), MASK), integer.lshift(integer.add(integer.add(V00, V05), M09), 32i)); V15 = integer.bxor(V15, V00); V15 = integer.rrotate(V15, 8i)
		V10 = integer.bor(integer.band(integer.add(V10, V15), MASK), integer.lshift(integer.add(V10, V15), 32i)); V05 = integer.bxor(V05, V10); V05 = integer.rrotate(V05, 7i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V06), M10), MASK), integer.lshift(integer.add(integer.add(V01, V06), M10), 32i)); V12 = integer.bxor(V12, V01); V12 = integer.rrotate(V12, 16i)
		V11 = integer.bor(integer.band(integer.add(V11, V12), MASK), integer.lshift(integer.add(V11, V12), 32i)); V06 = integer.bxor(V06, V11); V06 = integer.rrotate(V06, 12i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V06), M11), MASK), integer.lshift(integer.add(integer.add(V01, V06), M11), 32i)); V12 = integer.bxor(V12, V01); V12 = integer.rrotate(V12, 8i)
		V11 = integer.bor(integer.band(integer.add(V11, V12), MASK), integer.lshift(integer.add(V11, V12), 32i)); V06 = integer.bxor(V06, V11); V06 = integer.rrotate(V06, 7i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V07), M12), MASK), integer.lshift(integer.add(integer.add(V02, V07), M12), 32i)); V13 = integer.bxor(V13, V02); V13 = integer.rrotate(V13, 16i)
		V08 = integer.bor(integer.band(integer.add(V08, V13), MASK), integer.lshift(integer.add(V08, V13), 32i)); V07 = integer.bxor(V07, V08); V07 = integer.rrotate(V07, 12i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V07), M13), MASK), integer.lshift(integer.add(integer.add(V02, V07), M13), 32i)); V13 = integer.bxor(V13, V02); V13 = integer.rrotate(V13, 8i)
		V08 = integer.bor(integer.band(integer.add(V08, V13), MASK), integer.lshift(integer.add(V08, V13), 32i)); V07 = integer.bxor(V07, V08); V07 = integer.rrotate(V07, 7i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V04), M14), MASK), integer.lshift(integer.add(integer.add(V03, V04), M14), 32i)); V14 = integer.bxor(V14, V03); V14 = integer.rrotate(V14, 16i)
		V09 = integer.bor(integer.band(integer.add(V09, V14), MASK), integer.lshift(integer.add(V09, V14), 32i)); V04 = integer.bxor(V04, V09); V04 = integer.rrotate(V04, 12i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V04), M15), MASK), integer.lshift(integer.add(integer.add(V03, V04), M15), 32i)); V14 = integer.bxor(V14, V03); V14 = integer.rrotate(V14, 8i)
		V09 = integer.bor(integer.band(integer.add(V09, V14), MASK), integer.lshift(integer.add(V09, V14), 32i)); V04 = integer.bxor(V04, V09); V04 = integer.rrotate(V04, 7i)

		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V04), M02), MASK), integer.lshift(integer.add(integer.add(V00, V04), M02), 32i)); V12 = integer.bxor(V12, V00); V12 = integer.rrotate(V12, 16i)
		V08 = integer.bor(integer.band(integer.add(V08, V12), MASK), integer.lshift(integer.add(V08, V12), 32i)); V04 = integer.bxor(V04, V08); V04 = integer.rrotate(V04, 12i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V04), M06), MASK), integer.lshift(integer.add(integer.add(V00, V04), M06), 32i)); V12 = integer.bxor(V12, V00); V12 = integer.rrotate(V12, 8i)
		V08 = integer.bor(integer.band(integer.add(V08, V12), MASK), integer.lshift(integer.add(V08, V12), 32i)); V04 = integer.bxor(V04, V08); V04 = integer.rrotate(V04, 7i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V05), M03), MASK), integer.lshift(integer.add(integer.add(V01, V05), M03), 32i)); V13 = integer.bxor(V13, V01); V13 = integer.rrotate(V13, 16i)
		V09 = integer.bor(integer.band(integer.add(V09, V13), MASK), integer.lshift(integer.add(V09, V13), 32i)); V05 = integer.bxor(V05, V09); V05 = integer.rrotate(V05, 12i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V05), M10), MASK), integer.lshift(integer.add(integer.add(V01, V05), M10), 32i)); V13 = integer.bxor(V13, V01); V13 = integer.rrotate(V13, 8i)
		V09 = integer.bor(integer.band(integer.add(V09, V13), MASK), integer.lshift(integer.add(V09, V13), 32i)); V05 = integer.bxor(V05, V09); V05 = integer.rrotate(V05, 7i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V06), M07), MASK), integer.lshift(integer.add(integer.add(V02, V06), M07), 32i)); V14 = integer.bxor(V14, V02); V14 = integer.rrotate(V14, 16i)
		V10 = integer.bor(integer.band(integer.add(V10, V14), MASK), integer.lshift(integer.add(V10, V14), 32i)); V06 = integer.bxor(V06, V10); V06 = integer.rrotate(V06, 12i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V06), M00), MASK), integer.lshift(integer.add(integer.add(V02, V06), M00), 32i)); V14 = integer.bxor(V14, V02); V14 = integer.rrotate(V14, 8i)
		V10 = integer.bor(integer.band(integer.add(V10, V14), MASK), integer.lshift(integer.add(V10, V14), 32i)); V06 = integer.bxor(V06, V10); V06 = integer.rrotate(V06, 7i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V07), M04), MASK), integer.lshift(integer.add(integer.add(V03, V07), M04), 32i)); V15 = integer.bxor(V15, V03); V15 = integer.rrotate(V15, 16i)
		V11 = integer.bor(integer.band(integer.add(V11, V15), MASK), integer.lshift(integer.add(V11, V15), 32i)); V07 = integer.bxor(V07, V11); V07 = integer.rrotate(V07, 12i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V07), M13), MASK), integer.lshift(integer.add(integer.add(V03, V07), M13), 32i)); V15 = integer.bxor(V15, V03); V15 = integer.rrotate(V15, 8i)
		V11 = integer.bor(integer.band(integer.add(V11, V15), MASK), integer.lshift(integer.add(V11, V15), 32i)); V07 = integer.bxor(V07, V11); V07 = integer.rrotate(V07, 7i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V05), M01), MASK), integer.lshift(integer.add(integer.add(V00, V05), M01), 32i)); V15 = integer.bxor(V15, V00); V15 = integer.rrotate(V15, 16i)
		V10 = integer.bor(integer.band(integer.add(V10, V15), MASK), integer.lshift(integer.add(V10, V15), 32i)); V05 = integer.bxor(V05, V10); V05 = integer.rrotate(V05, 12i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V05), M11), MASK), integer.lshift(integer.add(integer.add(V00, V05), M11), 32i)); V15 = integer.bxor(V15, V00); V15 = integer.rrotate(V15, 8i)
		V10 = integer.bor(integer.band(integer.add(V10, V15), MASK), integer.lshift(integer.add(V10, V15), 32i)); V05 = integer.bxor(V05, V10); V05 = integer.rrotate(V05, 7i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V06), M12), MASK), integer.lshift(integer.add(integer.add(V01, V06), M12), 32i)); V12 = integer.bxor(V12, V01); V12 = integer.rrotate(V12, 16i)
		V11 = integer.bor(integer.band(integer.add(V11, V12), MASK), integer.lshift(integer.add(V11, V12), 32i)); V06 = integer.bxor(V06, V11); V06 = integer.rrotate(V06, 12i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V06), M05), MASK), integer.lshift(integer.add(integer.add(V01, V06), M05), 32i)); V12 = integer.bxor(V12, V01); V12 = integer.rrotate(V12, 8i)
		V11 = integer.bor(integer.band(integer.add(V11, V12), MASK), integer.lshift(integer.add(V11, V12), 32i)); V06 = integer.bxor(V06, V11); V06 = integer.rrotate(V06, 7i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V07), M09), MASK), integer.lshift(integer.add(integer.add(V02, V07), M09), 32i)); V13 = integer.bxor(V13, V02); V13 = integer.rrotate(V13, 16i)
		V08 = integer.bor(integer.band(integer.add(V08, V13), MASK), integer.lshift(integer.add(V08, V13), 32i)); V07 = integer.bxor(V07, V08); V07 = integer.rrotate(V07, 12i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V07), M14), MASK), integer.lshift(integer.add(integer.add(V02, V07), M14), 32i)); V13 = integer.bxor(V13, V02); V13 = integer.rrotate(V13, 8i)
		V08 = integer.bor(integer.band(integer.add(V08, V13), MASK), integer.lshift(integer.add(V08, V13), 32i)); V07 = integer.bxor(V07, V08); V07 = integer.rrotate(V07, 7i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V04), M15), MASK), integer.lshift(integer.add(integer.add(V03, V04), M15), 32i)); V14 = integer.bxor(V14, V03); V14 = integer.rrotate(V14, 16i)
		V09 = integer.bor(integer.band(integer.add(V09, V14), MASK), integer.lshift(integer.add(V09, V14), 32i)); V04 = integer.bxor(V04, V09); V04 = integer.rrotate(V04, 12i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V04), M08), MASK), integer.lshift(integer.add(integer.add(V03, V04), M08), 32i)); V14 = integer.bxor(V14, V03); V14 = integer.rrotate(V14, 8i)
		V09 = integer.bor(integer.band(integer.add(V09, V14), MASK), integer.lshift(integer.add(V09, V14), 32i)); V04 = integer.bxor(V04, V09); V04 = integer.rrotate(V04, 7i)

		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V04), M03), MASK), integer.lshift(integer.add(integer.add(V00, V04), M03), 32i)); V12 = integer.bxor(V12, V00); V12 = integer.rrotate(V12, 16i)
		V08 = integer.bor(integer.band(integer.add(V08, V12), MASK), integer.lshift(integer.add(V08, V12), 32i)); V04 = integer.bxor(V04, V08); V04 = integer.rrotate(V04, 12i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V04), M04), MASK), integer.lshift(integer.add(integer.add(V00, V04), M04), 32i)); V12 = integer.bxor(V12, V00); V12 = integer.rrotate(V12, 8i)
		V08 = integer.bor(integer.band(integer.add(V08, V12), MASK), integer.lshift(integer.add(V08, V12), 32i)); V04 = integer.bxor(V04, V08); V04 = integer.rrotate(V04, 7i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V05), M10), MASK), integer.lshift(integer.add(integer.add(V01, V05), M10), 32i)); V13 = integer.bxor(V13, V01); V13 = integer.rrotate(V13, 16i)
		V09 = integer.bor(integer.band(integer.add(V09, V13), MASK), integer.lshift(integer.add(V09, V13), 32i)); V05 = integer.bxor(V05, V09); V05 = integer.rrotate(V05, 12i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V05), M12), MASK), integer.lshift(integer.add(integer.add(V01, V05), M12), 32i)); V13 = integer.bxor(V13, V01); V13 = integer.rrotate(V13, 8i)
		V09 = integer.bor(integer.band(integer.add(V09, V13), MASK), integer.lshift(integer.add(V09, V13), 32i)); V05 = integer.bxor(V05, V09); V05 = integer.rrotate(V05, 7i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V06), M13), MASK), integer.lshift(integer.add(integer.add(V02, V06), M13), 32i)); V14 = integer.bxor(V14, V02); V14 = integer.rrotate(V14, 16i)
		V10 = integer.bor(integer.band(integer.add(V10, V14), MASK), integer.lshift(integer.add(V10, V14), 32i)); V06 = integer.bxor(V06, V10); V06 = integer.rrotate(V06, 12i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V06), M02), MASK), integer.lshift(integer.add(integer.add(V02, V06), M02), 32i)); V14 = integer.bxor(V14, V02); V14 = integer.rrotate(V14, 8i)
		V10 = integer.bor(integer.band(integer.add(V10, V14), MASK), integer.lshift(integer.add(V10, V14), 32i)); V06 = integer.bxor(V06, V10); V06 = integer.rrotate(V06, 7i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V07), M07), MASK), integer.lshift(integer.add(integer.add(V03, V07), M07), 32i)); V15 = integer.bxor(V15, V03); V15 = integer.rrotate(V15, 16i)
		V11 = integer.bor(integer.band(integer.add(V11, V15), MASK), integer.lshift(integer.add(V11, V15), 32i)); V07 = integer.bxor(V07, V11); V07 = integer.rrotate(V07, 12i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V07), M14), MASK), integer.lshift(integer.add(integer.add(V03, V07), M14), 32i)); V15 = integer.bxor(V15, V03); V15 = integer.rrotate(V15, 8i)
		V11 = integer.bor(integer.band(integer.add(V11, V15), MASK), integer.lshift(integer.add(V11, V15), 32i)); V07 = integer.bxor(V07, V11); V07 = integer.rrotate(V07, 7i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V05), M06), MASK), integer.lshift(integer.add(integer.add(V00, V05), M06), 32i)); V15 = integer.bxor(V15, V00); V15 = integer.rrotate(V15, 16i)
		V10 = integer.bor(integer.band(integer.add(V10, V15), MASK), integer.lshift(integer.add(V10, V15), 32i)); V05 = integer.bxor(V05, V10); V05 = integer.rrotate(V05, 12i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V05), M05), MASK), integer.lshift(integer.add(integer.add(V00, V05), M05), 32i)); V15 = integer.bxor(V15, V00); V15 = integer.rrotate(V15, 8i)
		V10 = integer.bor(integer.band(integer.add(V10, V15), MASK), integer.lshift(integer.add(V10, V15), 32i)); V05 = integer.bxor(V05, V10); V05 = integer.rrotate(V05, 7i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V06), M09), MASK), integer.lshift(integer.add(integer.add(V01, V06), M09), 32i)); V12 = integer.bxor(V12, V01); V12 = integer.rrotate(V12, 16i)
		V11 = integer.bor(integer.band(integer.add(V11, V12), MASK), integer.lshift(integer.add(V11, V12), 32i)); V06 = integer.bxor(V06, V11); V06 = integer.rrotate(V06, 12i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V06), M00), MASK), integer.lshift(integer.add(integer.add(V01, V06), M00), 32i)); V12 = integer.bxor(V12, V01); V12 = integer.rrotate(V12, 8i)
		V11 = integer.bor(integer.band(integer.add(V11, V12), MASK), integer.lshift(integer.add(V11, V12), 32i)); V06 = integer.bxor(V06, V11); V06 = integer.rrotate(V06, 7i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V07), M11), MASK), integer.lshift(integer.add(integer.add(V02, V07), M11), 32i)); V13 = integer.bxor(V13, V02); V13 = integer.rrotate(V13, 16i)
		V08 = integer.bor(integer.band(integer.add(V08, V13), MASK), integer.lshift(integer.add(V08, V13), 32i)); V07 = integer.bxor(V07, V08); V07 = integer.rrotate(V07, 12i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V07), M15), MASK), integer.lshift(integer.add(integer.add(V02, V07), M15), 32i)); V13 = integer.bxor(V13, V02); V13 = integer.rrotate(V13, 8i)
		V08 = integer.bor(integer.band(integer.add(V08, V13), MASK), integer.lshift(integer.add(V08, V13), 32i)); V07 = integer.bxor(V07, V08); V07 = integer.rrotate(V07, 7i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V04), M08), MASK), integer.lshift(integer.add(integer.add(V03, V04), M08), 32i)); V14 = integer.bxor(V14, V03); V14 = integer.rrotate(V14, 16i)
		V09 = integer.bor(integer.band(integer.add(V09, V14), MASK), integer.lshift(integer.add(V09, V14), 32i)); V04 = integer.bxor(V04, V09); V04 = integer.rrotate(V04, 12i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V04), M01), MASK), integer.lshift(integer.add(integer.add(V03, V04), M01), 32i)); V14 = integer.bxor(V14, V03); V14 = integer.rrotate(V14, 8i)
		V09 = integer.bor(integer.band(integer.add(V09, V14), MASK), integer.lshift(integer.add(V09, V14), 32i)); V04 = integer.bxor(V04, V09); V04 = integer.rrotate(V04, 7i)

		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V04), M10), MASK), integer.lshift(integer.add(integer.add(V00, V04), M10), 32i)); V12 = integer.bxor(V12, V00); V12 = integer.rrotate(V12, 16i)
		V08 = integer.bor(integer.band(integer.add(V08, V12), MASK), integer.lshift(integer.add(V08, V12), 32i)); V04 = integer.bxor(V04, V08); V04 = integer.rrotate(V04, 12i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V04), M07), MASK), integer.lshift(integer.add(integer.add(V00, V04), M07), 32i)); V12 = integer.bxor(V12, V00); V12 = integer.rrotate(V12, 8i)
		V08 = integer.bor(integer.band(integer.add(V08, V12), MASK), integer.lshift(integer.add(V08, V12), 32i)); V04 = integer.bxor(V04, V08); V04 = integer.rrotate(V04, 7i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V05), M12), MASK), integer.lshift(integer.add(integer.add(V01, V05), M12), 32i)); V13 = integer.bxor(V13, V01); V13 = integer.rrotate(V13, 16i)
		V09 = integer.bor(integer.band(integer.add(V09, V13), MASK), integer.lshift(integer.add(V09, V13), 32i)); V05 = integer.bxor(V05, V09); V05 = integer.rrotate(V05, 12i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V05), M09), MASK), integer.lshift(integer.add(integer.add(V01, V05), M09), 32i)); V13 = integer.bxor(V13, V01); V13 = integer.rrotate(V13, 8i)
		V09 = integer.bor(integer.band(integer.add(V09, V13), MASK), integer.lshift(integer.add(V09, V13), 32i)); V05 = integer.bxor(V05, V09); V05 = integer.rrotate(V05, 7i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V06), M14), MASK), integer.lshift(integer.add(integer.add(V02, V06), M14), 32i)); V14 = integer.bxor(V14, V02); V14 = integer.rrotate(V14, 16i)
		V10 = integer.bor(integer.band(integer.add(V10, V14), MASK), integer.lshift(integer.add(V10, V14), 32i)); V06 = integer.bxor(V06, V10); V06 = integer.rrotate(V06, 12i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V06), M03), MASK), integer.lshift(integer.add(integer.add(V02, V06), M03), 32i)); V14 = integer.bxor(V14, V02); V14 = integer.rrotate(V14, 8i)
		V10 = integer.bor(integer.band(integer.add(V10, V14), MASK), integer.lshift(integer.add(V10, V14), 32i)); V06 = integer.bxor(V06, V10); V06 = integer.rrotate(V06, 7i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V07), M13), MASK), integer.lshift(integer.add(integer.add(V03, V07), M13), 32i)); V15 = integer.bxor(V15, V03); V15 = integer.rrotate(V15, 16i)
		V11 = integer.bor(integer.band(integer.add(V11, V15), MASK), integer.lshift(integer.add(V11, V15), 32i)); V07 = integer.bxor(V07, V11); V07 = integer.rrotate(V07, 12i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V07), M15), MASK), integer.lshift(integer.add(integer.add(V03, V07), M15), 32i)); V15 = integer.bxor(V15, V03); V15 = integer.rrotate(V15, 8i)
		V11 = integer.bor(integer.band(integer.add(V11, V15), MASK), integer.lshift(integer.add(V11, V15), 32i)); V07 = integer.bxor(V07, V11); V07 = integer.rrotate(V07, 7i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V05), M04), MASK), integer.lshift(integer.add(integer.add(V00, V05), M04), 32i)); V15 = integer.bxor(V15, V00); V15 = integer.rrotate(V15, 16i)
		V10 = integer.bor(integer.band(integer.add(V10, V15), MASK), integer.lshift(integer.add(V10, V15), 32i)); V05 = integer.bxor(V05, V10); V05 = integer.rrotate(V05, 12i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V05), M00), MASK), integer.lshift(integer.add(integer.add(V00, V05), M00), 32i)); V15 = integer.bxor(V15, V00); V15 = integer.rrotate(V15, 8i)
		V10 = integer.bor(integer.band(integer.add(V10, V15), MASK), integer.lshift(integer.add(V10, V15), 32i)); V05 = integer.bxor(V05, V10); V05 = integer.rrotate(V05, 7i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V06), M11), MASK), integer.lshift(integer.add(integer.add(V01, V06), M11), 32i)); V12 = integer.bxor(V12, V01); V12 = integer.rrotate(V12, 16i)
		V11 = integer.bor(integer.band(integer.add(V11, V12), MASK), integer.lshift(integer.add(V11, V12), 32i)); V06 = integer.bxor(V06, V11); V06 = integer.rrotate(V06, 12i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V06), M02), MASK), integer.lshift(integer.add(integer.add(V01, V06), M02), 32i)); V12 = integer.bxor(V12, V01); V12 = integer.rrotate(V12, 8i)
		V11 = integer.bor(integer.band(integer.add(V11, V12), MASK), integer.lshift(integer.add(V11, V12), 32i)); V06 = integer.bxor(V06, V11); V06 = integer.rrotate(V06, 7i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V07), M05), MASK), integer.lshift(integer.add(integer.add(V02, V07), M05), 32i)); V13 = integer.bxor(V13, V02); V13 = integer.rrotate(V13, 16i)
		V08 = integer.bor(integer.band(integer.add(V08, V13), MASK), integer.lshift(integer.add(V08, V13), 32i)); V07 = integer.bxor(V07, V08); V07 = integer.rrotate(V07, 12i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V07), M08), MASK), integer.lshift(integer.add(integer.add(V02, V07), M08), 32i)); V13 = integer.bxor(V13, V02); V13 = integer.rrotate(V13, 8i)
		V08 = integer.bor(integer.band(integer.add(V08, V13), MASK), integer.lshift(integer.add(V08, V13), 32i)); V07 = integer.bxor(V07, V08); V07 = integer.rrotate(V07, 7i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V04), M01), MASK), integer.lshift(integer.add(integer.add(V03, V04), M01), 32i)); V14 = integer.bxor(V14, V03); V14 = integer.rrotate(V14, 16i)
		V09 = integer.bor(integer.band(integer.add(V09, V14), MASK), integer.lshift(integer.add(V09, V14), 32i)); V04 = integer.bxor(V04, V09); V04 = integer.rrotate(V04, 12i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V04), M06), MASK), integer.lshift(integer.add(integer.add(V03, V04), M06), 32i)); V14 = integer.bxor(V14, V03); V14 = integer.rrotate(V14, 8i)
		V09 = integer.bor(integer.band(integer.add(V09, V14), MASK), integer.lshift(integer.add(V09, V14), 32i)); V04 = integer.bxor(V04, V09); V04 = integer.rrotate(V04, 7i)

		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V04), M12), MASK), integer.lshift(integer.add(integer.add(V00, V04), M12), 32i)); V12 = integer.bxor(V12, V00); V12 = integer.rrotate(V12, 16i)
		V08 = integer.bor(integer.band(integer.add(V08, V12), MASK), integer.lshift(integer.add(V08, V12), 32i)); V04 = integer.bxor(V04, V08); V04 = integer.rrotate(V04, 12i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V04), M13), MASK), integer.lshift(integer.add(integer.add(V00, V04), M13), 32i)); V12 = integer.bxor(V12, V00); V12 = integer.rrotate(V12, 8i)
		V08 = integer.bor(integer.band(integer.add(V08, V12), MASK), integer.lshift(integer.add(V08, V12), 32i)); V04 = integer.bxor(V04, V08); V04 = integer.rrotate(V04, 7i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V05), M09), MASK), integer.lshift(integer.add(integer.add(V01, V05), M09), 32i)); V13 = integer.bxor(V13, V01); V13 = integer.rrotate(V13, 16i)
		V09 = integer.bor(integer.band(integer.add(V09, V13), MASK), integer.lshift(integer.add(V09, V13), 32i)); V05 = integer.bxor(V05, V09); V05 = integer.rrotate(V05, 12i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V05), M11), MASK), integer.lshift(integer.add(integer.add(V01, V05), M11), 32i)); V13 = integer.bxor(V13, V01); V13 = integer.rrotate(V13, 8i)
		V09 = integer.bor(integer.band(integer.add(V09, V13), MASK), integer.lshift(integer.add(V09, V13), 32i)); V05 = integer.bxor(V05, V09); V05 = integer.rrotate(V05, 7i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V06), M15), MASK), integer.lshift(integer.add(integer.add(V02, V06), M15), 32i)); V14 = integer.bxor(V14, V02); V14 = integer.rrotate(V14, 16i)
		V10 = integer.bor(integer.band(integer.add(V10, V14), MASK), integer.lshift(integer.add(V10, V14), 32i)); V06 = integer.bxor(V06, V10); V06 = integer.rrotate(V06, 12i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V06), M10), MASK), integer.lshift(integer.add(integer.add(V02, V06), M10), 32i)); V14 = integer.bxor(V14, V02); V14 = integer.rrotate(V14, 8i)
		V10 = integer.bor(integer.band(integer.add(V10, V14), MASK), integer.lshift(integer.add(V10, V14), 32i)); V06 = integer.bxor(V06, V10); V06 = integer.rrotate(V06, 7i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V07), M14), MASK), integer.lshift(integer.add(integer.add(V03, V07), M14), 32i)); V15 = integer.bxor(V15, V03); V15 = integer.rrotate(V15, 16i)
		V11 = integer.bor(integer.band(integer.add(V11, V15), MASK), integer.lshift(integer.add(V11, V15), 32i)); V07 = integer.bxor(V07, V11); V07 = integer.rrotate(V07, 12i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V07), M08), MASK), integer.lshift(integer.add(integer.add(V03, V07), M08), 32i)); V15 = integer.bxor(V15, V03); V15 = integer.rrotate(V15, 8i)
		V11 = integer.bor(integer.band(integer.add(V11, V15), MASK), integer.lshift(integer.add(V11, V15), 32i)); V07 = integer.bxor(V07, V11); V07 = integer.rrotate(V07, 7i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V05), M07), MASK), integer.lshift(integer.add(integer.add(V00, V05), M07), 32i)); V15 = integer.bxor(V15, V00); V15 = integer.rrotate(V15, 16i)
		V10 = integer.bor(integer.band(integer.add(V10, V15), MASK), integer.lshift(integer.add(V10, V15), 32i)); V05 = integer.bxor(V05, V10); V05 = integer.rrotate(V05, 12i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V05), M02), MASK), integer.lshift(integer.add(integer.add(V00, V05), M02), 32i)); V15 = integer.bxor(V15, V00); V15 = integer.rrotate(V15, 8i)
		V10 = integer.bor(integer.band(integer.add(V10, V15), MASK), integer.lshift(integer.add(V10, V15), 32i)); V05 = integer.bxor(V05, V10); V05 = integer.rrotate(V05, 7i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V06), M05), MASK), integer.lshift(integer.add(integer.add(V01, V06), M05), 32i)); V12 = integer.bxor(V12, V01); V12 = integer.rrotate(V12, 16i)
		V11 = integer.bor(integer.band(integer.add(V11, V12), MASK), integer.lshift(integer.add(V11, V12), 32i)); V06 = integer.bxor(V06, V11); V06 = integer.rrotate(V06, 12i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V06), M03), MASK), integer.lshift(integer.add(integer.add(V01, V06), M03), 32i)); V12 = integer.bxor(V12, V01); V12 = integer.rrotate(V12, 8i)
		V11 = integer.bor(integer.band(integer.add(V11, V12), MASK), integer.lshift(integer.add(V11, V12), 32i)); V06 = integer.bxor(V06, V11); V06 = integer.rrotate(V06, 7i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V07), M00), MASK), integer.lshift(integer.add(integer.add(V02, V07), M00), 32i)); V13 = integer.bxor(V13, V02); V13 = integer.rrotate(V13, 16i)
		V08 = integer.bor(integer.band(integer.add(V08, V13), MASK), integer.lshift(integer.add(V08, V13), 32i)); V07 = integer.bxor(V07, V08); V07 = integer.rrotate(V07, 12i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V07), M01), MASK), integer.lshift(integer.add(integer.add(V02, V07), M01), 32i)); V13 = integer.bxor(V13, V02); V13 = integer.rrotate(V13, 8i)
		V08 = integer.bor(integer.band(integer.add(V08, V13), MASK), integer.lshift(integer.add(V08, V13), 32i)); V07 = integer.bxor(V07, V08); V07 = integer.rrotate(V07, 7i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V04), M06), MASK), integer.lshift(integer.add(integer.add(V03, V04), M06), 32i)); V14 = integer.bxor(V14, V03); V14 = integer.rrotate(V14, 16i)
		V09 = integer.bor(integer.band(integer.add(V09, V14), MASK), integer.lshift(integer.add(V09, V14), 32i)); V04 = integer.bxor(V04, V09); V04 = integer.rrotate(V04, 12i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V04), M04), MASK), integer.lshift(integer.add(integer.add(V03, V04), M04), 32i)); V14 = integer.bxor(V14, V03); V14 = integer.rrotate(V14, 8i)
		V09 = integer.bor(integer.band(integer.add(V09, V14), MASK), integer.lshift(integer.add(V09, V14), 32i)); V04 = integer.bxor(V04, V09); V04 = integer.rrotate(V04, 7i)

		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V04), M09), MASK), integer.lshift(integer.add(integer.add(V00, V04), M09), 32i)); V12 = integer.bxor(V12, V00); V12 = integer.rrotate(V12, 16i)
		V08 = integer.bor(integer.band(integer.add(V08, V12), MASK), integer.lshift(integer.add(V08, V12), 32i)); V04 = integer.bxor(V04, V08); V04 = integer.rrotate(V04, 12i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V04), M14), MASK), integer.lshift(integer.add(integer.add(V00, V04), M14), 32i)); V12 = integer.bxor(V12, V00); V12 = integer.rrotate(V12, 8i)
		V08 = integer.bor(integer.band(integer.add(V08, V12), MASK), integer.lshift(integer.add(V08, V12), 32i)); V04 = integer.bxor(V04, V08); V04 = integer.rrotate(V04, 7i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V05), M11), MASK), integer.lshift(integer.add(integer.add(V01, V05), M11), 32i)); V13 = integer.bxor(V13, V01); V13 = integer.rrotate(V13, 16i)
		V09 = integer.bor(integer.band(integer.add(V09, V13), MASK), integer.lshift(integer.add(V09, V13), 32i)); V05 = integer.bxor(V05, V09); V05 = integer.rrotate(V05, 12i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V05), M05), MASK), integer.lshift(integer.add(integer.add(V01, V05), M05), 32i)); V13 = integer.bxor(V13, V01); V13 = integer.rrotate(V13, 8i)
		V09 = integer.bor(integer.band(integer.add(V09, V13), MASK), integer.lshift(integer.add(V09, V13), 32i)); V05 = integer.bxor(V05, V09); V05 = integer.rrotate(V05, 7i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V06), M08), MASK), integer.lshift(integer.add(integer.add(V02, V06), M08), 32i)); V14 = integer.bxor(V14, V02); V14 = integer.rrotate(V14, 16i)
		V10 = integer.bor(integer.band(integer.add(V10, V14), MASK), integer.lshift(integer.add(V10, V14), 32i)); V06 = integer.bxor(V06, V10); V06 = integer.rrotate(V06, 12i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V06), M12), MASK), integer.lshift(integer.add(integer.add(V02, V06), M12), 32i)); V14 = integer.bxor(V14, V02); V14 = integer.rrotate(V14, 8i)
		V10 = integer.bor(integer.band(integer.add(V10, V14), MASK), integer.lshift(integer.add(V10, V14), 32i)); V06 = integer.bxor(V06, V10); V06 = integer.rrotate(V06, 7i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V07), M15), MASK), integer.lshift(integer.add(integer.add(V03, V07), M15), 32i)); V15 = integer.bxor(V15, V03); V15 = integer.rrotate(V15, 16i)
		V11 = integer.bor(integer.band(integer.add(V11, V15), MASK), integer.lshift(integer.add(V11, V15), 32i)); V07 = integer.bxor(V07, V11); V07 = integer.rrotate(V07, 12i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V07), M01), MASK), integer.lshift(integer.add(integer.add(V03, V07), M01), 32i)); V15 = integer.bxor(V15, V03); V15 = integer.rrotate(V15, 8i)
		V11 = integer.bor(integer.band(integer.add(V11, V15), MASK), integer.lshift(integer.add(V11, V15), 32i)); V07 = integer.bxor(V07, V11); V07 = integer.rrotate(V07, 7i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V05), M13), MASK), integer.lshift(integer.add(integer.add(V00, V05), M13), 32i)); V15 = integer.bxor(V15, V00); V15 = integer.rrotate(V15, 16i)
		V10 = integer.bor(integer.band(integer.add(V10, V15), MASK), integer.lshift(integer.add(V10, V15), 32i)); V05 = integer.bxor(V05, V10); V05 = integer.rrotate(V05, 12i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V05), M03), MASK), integer.lshift(integer.add(integer.add(V00, V05), M03), 32i)); V15 = integer.bxor(V15, V00); V15 = integer.rrotate(V15, 8i)
		V10 = integer.bor(integer.band(integer.add(V10, V15), MASK), integer.lshift(integer.add(V10, V15), 32i)); V05 = integer.bxor(V05, V10); V05 = integer.rrotate(V05, 7i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V06), M00), MASK), integer.lshift(integer.add(integer.add(V01, V06), M00), 32i)); V12 = integer.bxor(V12, V01); V12 = integer.rrotate(V12, 16i)
		V11 = integer.bor(integer.band(integer.add(V11, V12), MASK), integer.lshift(integer.add(V11, V12), 32i)); V06 = integer.bxor(V06, V11); V06 = integer.rrotate(V06, 12i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V06), M10), MASK), integer.lshift(integer.add(integer.add(V01, V06), M10), 32i)); V12 = integer.bxor(V12, V01); V12 = integer.rrotate(V12, 8i)
		V11 = integer.bor(integer.band(integer.add(V11, V12), MASK), integer.lshift(integer.add(V11, V12), 32i)); V06 = integer.bxor(V06, V11); V06 = integer.rrotate(V06, 7i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V07), M02), MASK), integer.lshift(integer.add(integer.add(V02, V07), M02), 32i)); V13 = integer.bxor(V13, V02); V13 = integer.rrotate(V13, 16i)
		V08 = integer.bor(integer.band(integer.add(V08, V13), MASK), integer.lshift(integer.add(V08, V13), 32i)); V07 = integer.bxor(V07, V08); V07 = integer.rrotate(V07, 12i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V07), M06), MASK), integer.lshift(integer.add(integer.add(V02, V07), M06), 32i)); V13 = integer.bxor(V13, V02); V13 = integer.rrotate(V13, 8i)
		V08 = integer.bor(integer.band(integer.add(V08, V13), MASK), integer.lshift(integer.add(V08, V13), 32i)); V07 = integer.bxor(V07, V08); V07 = integer.rrotate(V07, 7i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V04), M04), MASK), integer.lshift(integer.add(integer.add(V03, V04), M04), 32i)); V14 = integer.bxor(V14, V03); V14 = integer.rrotate(V14, 16i)
		V09 = integer.bor(integer.band(integer.add(V09, V14), MASK), integer.lshift(integer.add(V09, V14), 32i)); V04 = integer.bxor(V04, V09); V04 = integer.rrotate(V04, 12i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V04), M07), MASK), integer.lshift(integer.add(integer.add(V03, V04), M07), 32i)); V14 = integer.bxor(V14, V03); V14 = integer.rrotate(V14, 8i)
		V09 = integer.bor(integer.band(integer.add(V09, V14), MASK), integer.lshift(integer.add(V09, V14), 32i)); V04 = integer.bxor(V04, V09); V04 = integer.rrotate(V04, 7i)

		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V04), M11), MASK), integer.lshift(integer.add(integer.add(V00, V04), M11), 32i)); V12 = integer.bxor(V12, V00); V12 = integer.rrotate(V12, 16i)
		V08 = integer.bor(integer.band(integer.add(V08, V12), MASK), integer.lshift(integer.add(V08, V12), 32i)); V04 = integer.bxor(V04, V08); V04 = integer.rrotate(V04, 12i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V04), M15), MASK), integer.lshift(integer.add(integer.add(V00, V04), M15), 32i)); V12 = integer.bxor(V12, V00); V12 = integer.rrotate(V12, 8i)
		V08 = integer.bor(integer.band(integer.add(V08, V12), MASK), integer.lshift(integer.add(V08, V12), 32i)); V04 = integer.bxor(V04, V08); V04 = integer.rrotate(V04, 7i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V05), M05), MASK), integer.lshift(integer.add(integer.add(V01, V05), M05), 32i)); V13 = integer.bxor(V13, V01); V13 = integer.rrotate(V13, 16i)
		V09 = integer.bor(integer.band(integer.add(V09, V13), MASK), integer.lshift(integer.add(V09, V13), 32i)); V05 = integer.bxor(V05, V09); V05 = integer.rrotate(V05, 12i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V05), M00), MASK), integer.lshift(integer.add(integer.add(V01, V05), M00), 32i)); V13 = integer.bxor(V13, V01); V13 = integer.rrotate(V13, 8i)
		V09 = integer.bor(integer.band(integer.add(V09, V13), MASK), integer.lshift(integer.add(V09, V13), 32i)); V05 = integer.bxor(V05, V09); V05 = integer.rrotate(V05, 7i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V06), M01), MASK), integer.lshift(integer.add(integer.add(V02, V06), M01), 32i)); V14 = integer.bxor(V14, V02); V14 = integer.rrotate(V14, 16i)
		V10 = integer.bor(integer.band(integer.add(V10, V14), MASK), integer.lshift(integer.add(V10, V14), 32i)); V06 = integer.bxor(V06, V10); V06 = integer.rrotate(V06, 12i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V06), M09), MASK), integer.lshift(integer.add(integer.add(V02, V06), M09), 32i)); V14 = integer.bxor(V14, V02); V14 = integer.rrotate(V14, 8i)
		V10 = integer.bor(integer.band(integer.add(V10, V14), MASK), integer.lshift(integer.add(V10, V14), 32i)); V06 = integer.bxor(V06, V10); V06 = integer.rrotate(V06, 7i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V07), M08), MASK), integer.lshift(integer.add(integer.add(V03, V07), M08), 32i)); V15 = integer.bxor(V15, V03); V15 = integer.rrotate(V15, 16i)
		V11 = integer.bor(integer.band(integer.add(V11, V15), MASK), integer.lshift(integer.add(V11, V15), 32i)); V07 = integer.bxor(V07, V11); V07 = integer.rrotate(V07, 12i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V07), M06), MASK), integer.lshift(integer.add(integer.add(V03, V07), M06), 32i)); V15 = integer.bxor(V15, V03); V15 = integer.rrotate(V15, 8i)
		V11 = integer.bor(integer.band(integer.add(V11, V15), MASK), integer.lshift(integer.add(V11, V15), 32i)); V07 = integer.bxor(V07, V11); V07 = integer.rrotate(V07, 7i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V05), M14), MASK), integer.lshift(integer.add(integer.add(V00, V05), M14), 32i)); V15 = integer.bxor(V15, V00); V15 = integer.rrotate(V15, 16i)
		V10 = integer.bor(integer.band(integer.add(V10, V15), MASK), integer.lshift(integer.add(V10, V15), 32i)); V05 = integer.bxor(V05, V10); V05 = integer.rrotate(V05, 12i)
		V00 = integer.bor(integer.band(integer.add(integer.add(V00, V05), M10), MASK), integer.lshift(integer.add(integer.add(V00, V05), M10), 32i)); V15 = integer.bxor(V15, V00); V15 = integer.rrotate(V15, 8i)
		V10 = integer.bor(integer.band(integer.add(V10, V15), MASK), integer.lshift(integer.add(V10, V15), 32i)); V05 = integer.bxor(V05, V10); V05 = integer.rrotate(V05, 7i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V06), M02), MASK), integer.lshift(integer.add(integer.add(V01, V06), M02), 32i)); V12 = integer.bxor(V12, V01); V12 = integer.rrotate(V12, 16i)
		V11 = integer.bor(integer.band(integer.add(V11, V12), MASK), integer.lshift(integer.add(V11, V12), 32i)); V06 = integer.bxor(V06, V11); V06 = integer.rrotate(V06, 12i)
		V01 = integer.bor(integer.band(integer.add(integer.add(V01, V06), M12), MASK), integer.lshift(integer.add(integer.add(V01, V06), M12), 32i)); V12 = integer.bxor(V12, V01); V12 = integer.rrotate(V12, 8i)
		V11 = integer.bor(integer.band(integer.add(V11, V12), MASK), integer.lshift(integer.add(V11, V12), 32i)); V06 = integer.bxor(V06, V11); V06 = integer.rrotate(V06, 7i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V07), M03), MASK), integer.lshift(integer.add(integer.add(V02, V07), M03), 32i)); V13 = integer.bxor(V13, V02); V13 = integer.rrotate(V13, 16i)
		V08 = integer.bor(integer.band(integer.add(V08, V13), MASK), integer.lshift(integer.add(V08, V13), 32i)); V07 = integer.bxor(V07, V08); V07 = integer.rrotate(V07, 12i)
		V02 = integer.bor(integer.band(integer.add(integer.add(V02, V07), M04), MASK), integer.lshift(integer.add(integer.add(V02, V07), M04), 32i)); V13 = integer.bxor(V13, V02); V13 = integer.rrotate(V13, 8i)
		V08 = integer.bor(integer.band(integer.add(V08, V13), MASK), integer.lshift(integer.add(V08, V13), 32i)); V07 = integer.bxor(V07, V08); V07 = integer.rrotate(V07, 7i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V04), M07), MASK), integer.lshift(integer.add(integer.add(V03, V04), M07), 32i)); V14 = integer.bxor(V14, V03); V14 = integer.rrotate(V14, 16i)
		V09 = integer.bor(integer.band(integer.add(V09, V14), MASK), integer.lshift(integer.add(V09, V14), 32i)); V04 = integer.bxor(V04, V09); V04 = integer.rrotate(V04, 12i)
		V03 = integer.bor(integer.band(integer.add(integer.add(V03, V04), M13), MASK), integer.lshift(integer.add(integer.add(V03, V04), M13), 32i)); V14 = integer.bxor(V14, V03); V14 = integer.rrotate(V14, 8i)
		V09 = integer.bor(integer.band(integer.add(V09, V14), MASK), integer.lshift(integer.add(V09, V14), 32i)); V04 = integer.bxor(V04, V09); V04 = integer.rrotate(V04, 7i)

	if IsFull then
		local Result = buffer.create(EXTENDED_CV_SIZE)
		buffer.writeu32(Result, 0, integer.tonumber(integer.band(integer.bxor(V00, V08), MASK)))
		buffer.writeu32(Result, 4, integer.tonumber(integer.band(integer.bxor(V01, V09), MASK)))
		buffer.writeu32(Result, 8, integer.tonumber(integer.band(integer.bxor(V02, V10), MASK)))
		buffer.writeu32(Result, 12, integer.tonumber(integer.band(integer.bxor(V03, V11), MASK)))
		buffer.writeu32(Result, 16, integer.tonumber(integer.band(integer.bxor(V04, V12), MASK)))
		buffer.writeu32(Result, 20, integer.tonumber(integer.band(integer.bxor(V05, V13), MASK)))
		buffer.writeu32(Result, 24, integer.tonumber(integer.band(integer.bxor(V06, V14), MASK)))
		buffer.writeu32(Result, 28, integer.tonumber(integer.band(integer.bxor(V07, V15), MASK)))
		buffer.writeu32(Result, 32, integer.tonumber(integer.band(integer.bxor(V08, Hash00), MASK)))
		buffer.writeu32(Result, 36, integer.tonumber(integer.band(integer.bxor(V09, Hash01), MASK)))
		buffer.writeu32(Result, 40, integer.tonumber(integer.band(integer.bxor(V10, Hash02), MASK)))
		buffer.writeu32(Result, 44, integer.tonumber(integer.band(integer.bxor(V11, Hash03), MASK)))
		buffer.writeu32(Result, 48, integer.tonumber(integer.band(integer.bxor(V12, Hash04), MASK)))
		buffer.writeu32(Result, 52, integer.tonumber(integer.band(integer.bxor(V13, Hash05), MASK)))
		buffer.writeu32(Result, 56, integer.tonumber(integer.band(integer.bxor(V14, Hash06), MASK)))
		buffer.writeu32(Result, 60, integer.tonumber(integer.band(integer.bxor(V15, Hash07), MASK)))
		return Result
	else
		local Result = Storage or buffer.create(CV_SIZE)
		buffer.writeu32(Result, 0, integer.tonumber(integer.band(integer.bxor(V00, V08), MASK)))
		buffer.writeu32(Result, 4, integer.tonumber(integer.band(integer.bxor(V01, V09), MASK)))
		buffer.writeu32(Result, 8, integer.tonumber(integer.band(integer.bxor(V02, V10), MASK)))
		buffer.writeu32(Result, 12, integer.tonumber(integer.band(integer.bxor(V03, V11), MASK)))
		buffer.writeu32(Result, 16, integer.tonumber(integer.band(integer.bxor(V04, V12), MASK)))
		buffer.writeu32(Result, 20, integer.tonumber(integer.band(integer.bxor(V05, V13), MASK)))
		buffer.writeu32(Result, 24, integer.tonumber(integer.band(integer.bxor(V06, V14), MASK)))
		buffer.writeu32(Result, 28, integer.tonumber(integer.band(integer.bxor(V07, V15), MASK)))
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

function Blake3.DigestBuffer(Message: buffer, Length: number?): buffer
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

	return ProcessMessage(INITIAL_VECTORS, 0, Message, Length or 32)
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
