--[=[
	Cryptography library: Blake3 Luau path, used by Blake3 when EncodingService can't serve a call

	Example usage:
		local Digest = Blake3Core.ProcessMessage(Blake3Core.INITIAL_VECTORS, 0, Message, 32)
--]=]

--!strict
--!optimize 2

local BLOCK_SIZE = 64
local CV_SIZE = 32
local EXTENDED_CV_SIZE = 64
local CHUNK_SIZE = 1024
local MAX_STACK_DEPTH = 64

local CHUNK_START = 0x01
local CHUNK_END = 0x02
local PARENT_FLAG = 0x04
local ROOT_FLAG = 0x08
local HASH_FLAG = 0x10
local DERIVE_CONTEXT_FLAG = 0x20
local DERIVE_MATERIAL_FLAG = 0x40
local SINGLE_ROOT_FLAGS = CHUNK_START + CHUNK_END + ROOT_FLAG

local INITIAL_VECTORS: buffer = buffer.fromstring("\x67\xE6\x09\x6A\x85\xAE\x67\xBB\x72\xF3\x6E\x3C\x3A\xF5\x4F\xA5\x7F\x52\x0E\x51\x8C\x68\x05\x9B\xAB\xD9\x83\x1F\x19\xCD\xE0\x5B")
local ZERO_BLOCK: buffer = buffer.create(BLOCK_SIZE)
local OUTPUT_SCRATCH: buffer = buffer.create(EXTENDED_CV_SIZE)
local STACK_SCRATCH: buffer = buffer.create(MAX_STACK_DEPTH * CV_SIZE)
local STATE_CV_SCRATCH: buffer = buffer.create(CV_SIZE)
local MERGE_BLOCK_SCRATCH: buffer = buffer.create(EXTENDED_CV_SIZE)
local MERGE_CV_SCRATCH: buffer = buffer.create(CV_SIZE)
local PADDED_SCRATCH: buffer = buffer.create(BLOCK_SIZE)
local OUTPUT_BLOCK_SCRATCH: buffer = buffer.create(EXTENDED_CV_SIZE)

@native
local function CompressBlocks(
	Cv: buffer,
	Message: buffer,
	Offset: number,
	Counter: number,
	BlockLength: number,
	Flags: number,
	BlockCount: number,
	Out: buffer
): ()
	local V00 = buffer.readu32(Cv, 0)
	local V01 = buffer.readu32(Cv, 4)
	local V02 = buffer.readu32(Cv, 8)
	local V03 = buffer.readu32(Cv, 12)
	local V04 = buffer.readu32(Cv, 16)
	local V05 = buffer.readu32(Cv, 20)
	local V06 = buffer.readu32(Cv, 24)
	local V07 = buffer.readu32(Cv, 28)
	local CounterLow = Counter % 0x100000000
	local CounterHigh = (Counter - CounterLow) * (2 ^ -32)

	for BlockIndex = 1, BlockCount do
		local BlockFlags = Flags + (if BlockIndex == 1 and BlockCount > 1 then CHUNK_START elseif BlockIndex == 16 then CHUNK_END else 0)
		local V08, V09, V10, V11 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
		local V12, V13, V14, V15 = CounterLow, CounterHigh, BlockLength, BlockFlags
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Message, Offset), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 16)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 20)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Message, Offset + 4), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 24)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 25)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Message, Offset + 8), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 16)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 20)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Message, Offset + 12), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 24)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 25)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Message, Offset + 16), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 16)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 20)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Message, Offset + 20), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 24)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 25)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Message, Offset + 24), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 16)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 20)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Message, Offset + 28), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 24)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 25)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Message, Offset + 32), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 16)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 20)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Message, Offset + 36), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 24)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 25)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Message, Offset + 40), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 16)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 20)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Message, Offset + 44), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 24)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 25)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Message, Offset + 48), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 16)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 20)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Message, Offset + 52), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 24)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 25)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Message, Offset + 56), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 16)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 20)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Message, Offset + 60), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 24)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 25)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Message, Offset + 8), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 16)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 20)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Message, Offset + 24), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 24)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 25)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Message, Offset + 12), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 16)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 20)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Message, Offset + 40), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 24)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 25)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Message, Offset + 28), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 16)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 20)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Message, Offset), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 24)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 25)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Message, Offset + 16), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 16)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 20)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Message, Offset + 52), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 24)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 25)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Message, Offset + 4), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 16)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 20)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Message, Offset + 44), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 24)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 25)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Message, Offset + 48), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 16)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 20)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Message, Offset + 20), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 24)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 25)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Message, Offset + 36), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 16)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 20)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Message, Offset + 56), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 24)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 25)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Message, Offset + 60), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 16)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 20)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Message, Offset + 32), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 24)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 25)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Message, Offset + 12), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 16)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 20)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Message, Offset + 16), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 24)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 25)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Message, Offset + 40), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 16)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 20)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Message, Offset + 48), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 24)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 25)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Message, Offset + 52), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 16)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 20)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Message, Offset + 8), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 24)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 25)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Message, Offset + 28), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 16)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 20)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Message, Offset + 56), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 24)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 25)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Message, Offset + 24), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 16)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 20)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Message, Offset + 20), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 24)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 25)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Message, Offset + 36), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 16)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 20)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Message, Offset), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 24)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 25)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Message, Offset + 44), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 16)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 20)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Message, Offset + 60), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 24)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 25)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Message, Offset + 32), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 16)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 20)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Message, Offset + 4), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 24)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 25)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Message, Offset + 40), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 16)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 20)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Message, Offset + 28), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 24)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 25)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Message, Offset + 48), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 16)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 20)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Message, Offset + 36), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 24)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 25)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Message, Offset + 56), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 16)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 20)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Message, Offset + 12), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 24)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 25)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Message, Offset + 52), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 16)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 20)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Message, Offset + 60), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 24)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 25)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Message, Offset + 16), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 16)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 20)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Message, Offset), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 24)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 25)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Message, Offset + 44), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 16)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 20)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Message, Offset + 8), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 24)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 25)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Message, Offset + 20), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 16)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 20)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Message, Offset + 32), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 24)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 25)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Message, Offset + 4), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 16)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 20)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Message, Offset + 24), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 24)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 25)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Message, Offset + 48), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 16)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 20)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Message, Offset + 52), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 24)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 25)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Message, Offset + 36), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 16)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 20)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Message, Offset + 44), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 24)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 25)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Message, Offset + 60), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 16)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 20)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Message, Offset + 40), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 24)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 25)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Message, Offset + 56), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 16)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 20)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Message, Offset + 32), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 24)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 25)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Message, Offset + 28), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 16)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 20)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Message, Offset + 8), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 24)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 25)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Message, Offset + 20), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 16)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 20)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Message, Offset + 12), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 24)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 25)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Message, Offset), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 16)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 20)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Message, Offset + 4), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 24)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 25)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Message, Offset + 24), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 16)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 20)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Message, Offset + 16), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 24)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 25)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Message, Offset + 36), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 16)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 20)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Message, Offset + 56), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 24)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 25)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Message, Offset + 44), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 16)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 20)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Message, Offset + 20), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 24)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 25)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Message, Offset + 32), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 16)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 20)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Message, Offset + 48), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 24)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 25)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Message, Offset + 60), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 16)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 20)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Message, Offset + 4), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 24)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 25)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Message, Offset + 52), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 16)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 20)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Message, Offset + 12), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 24)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 25)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Message, Offset), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 16)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 20)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Message, Offset + 40), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 24)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 25)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Message, Offset + 8), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 16)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 20)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Message, Offset + 24), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 24)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 25)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Message, Offset + 16), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 16)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 20)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Message, Offset + 28), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 24)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 25)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Message, Offset + 44), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 16)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 20)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Message, Offset + 60), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 24)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 25)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Message, Offset + 20), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 16)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 20)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Message, Offset), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 24)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 25)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Message, Offset + 4), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 16)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 20)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Message, Offset + 36), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 24)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 25)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Message, Offset + 32), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 16)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 20)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Message, Offset + 24), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 24)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 25)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Message, Offset + 56), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 16)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 20)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Message, Offset + 40), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 24)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 25)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Message, Offset + 8), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 16)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 20)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Message, Offset + 48), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 24)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 25)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Message, Offset + 12), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 16)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 20)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Message, Offset + 16), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 24)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 25)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Message, Offset + 28), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 16)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 20)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Message, Offset + 52), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 24)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 25)

		V00 = bit32.bxor(V00, V08)
		V01 = bit32.bxor(V01, V09)
		V02 = bit32.bxor(V02, V10)
		V03 = bit32.bxor(V03, V11)
		V04 = bit32.bxor(V04, V12)
		V05 = bit32.bxor(V05, V13)
		V06 = bit32.bxor(V06, V14)
		V07 = bit32.bxor(V07, V15)
		Offset += BLOCK_SIZE
	end

	buffer.writeu32(Out, 28, V07)
	buffer.writeu32(Out, 0, V00)
	buffer.writeu32(Out, 4, V01)
	buffer.writeu32(Out, 8, V02)
	buffer.writeu32(Out, 12, V03)
	buffer.writeu32(Out, 16, V04)
	buffer.writeu32(Out, 20, V05)
	buffer.writeu32(Out, 24, V06)
end

@native
local function OutputBlocks(
	Cv: buffer,
	Block: buffer,
	BlockLength: number,
	Flags: number,
	Out: buffer,
	StartCounter: number,
	EndCounter: number
): ()
	local OutOffset = 0
	for Counter = StartCounter, EndCounter do
		local V00 = buffer.readu32(Cv, 0)
		local V01 = buffer.readu32(Cv, 4)
		local V02 = buffer.readu32(Cv, 8)
		local V03 = buffer.readu32(Cv, 12)
		local V04 = buffer.readu32(Cv, 16)
		local V05 = buffer.readu32(Cv, 20)
		local V06 = buffer.readu32(Cv, 24)
		local V07 = buffer.readu32(Cv, 28)
		local V08, V09, V10, V11 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
		local V12, V13, V14, V15 = Counter, 0, BlockLength, Flags
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Block, 0), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 16)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 20)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Block, 4), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 24)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 25)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Block, 8), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 16)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 20)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Block, 12), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 24)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 25)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Block, 16), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 16)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 20)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Block, 20), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 24)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 25)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Block, 24), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 16)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 20)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Block, 28), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 24)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 25)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Block, 32), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 16)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 20)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Block, 36), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 24)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 25)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Block, 40), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 16)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 20)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Block, 44), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 24)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 25)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Block, 48), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 16)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 20)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Block, 52), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 24)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 25)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Block, 56), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 16)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 20)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Block, 60), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 24)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 25)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Block, 8), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 16)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 20)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Block, 24), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 24)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 25)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Block, 12), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 16)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 20)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Block, 40), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 24)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 25)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Block, 28), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 16)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 20)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Block, 0), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 24)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 25)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Block, 16), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 16)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 20)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Block, 52), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 24)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 25)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Block, 4), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 16)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 20)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Block, 44), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 24)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 25)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Block, 48), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 16)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 20)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Block, 20), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 24)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 25)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Block, 36), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 16)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 20)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Block, 56), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 24)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 25)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Block, 60), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 16)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 20)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Block, 32), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 24)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 25)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Block, 12), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 16)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 20)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Block, 16), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 24)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 25)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Block, 40), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 16)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 20)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Block, 48), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 24)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 25)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Block, 52), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 16)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 20)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Block, 8), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 24)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 25)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Block, 28), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 16)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 20)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Block, 56), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 24)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 25)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Block, 24), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 16)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 20)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Block, 20), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 24)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 25)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Block, 36), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 16)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 20)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Block, 0), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 24)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 25)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Block, 44), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 16)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 20)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Block, 60), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 24)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 25)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Block, 32), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 16)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 20)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Block, 4), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 24)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 25)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Block, 40), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 16)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 20)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Block, 28), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 24)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 25)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Block, 48), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 16)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 20)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Block, 36), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 24)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 25)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Block, 56), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 16)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 20)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Block, 12), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 24)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 25)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Block, 52), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 16)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 20)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Block, 60), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 24)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 25)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Block, 16), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 16)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 20)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Block, 0), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 24)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 25)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Block, 44), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 16)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 20)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Block, 8), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 24)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 25)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Block, 20), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 16)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 20)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Block, 32), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 24)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 25)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Block, 4), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 16)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 20)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Block, 24), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 24)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 25)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Block, 48), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 16)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 20)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Block, 52), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 24)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 25)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Block, 36), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 16)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 20)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Block, 44), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 24)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 25)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Block, 60), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 16)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 20)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Block, 40), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 24)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 25)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Block, 56), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 16)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 20)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Block, 32), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 24)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 25)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Block, 28), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 16)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 20)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Block, 8), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 24)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 25)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Block, 20), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 16)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 20)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Block, 12), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 24)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 25)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Block, 0), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 16)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 20)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Block, 4), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 24)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 25)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Block, 24), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 16)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 20)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Block, 16), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 24)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 25)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Block, 36), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 16)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 20)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Block, 56), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 24)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 25)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Block, 44), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 16)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 20)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Block, 20), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 24)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 25)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Block, 32), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 16)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 20)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Block, 48), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 24)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 25)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Block, 60), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 16)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 20)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Block, 4), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 24)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 25)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Block, 52), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 16)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 20)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Block, 12), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 24)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 25)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Block, 0), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 16)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 20)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Block, 40), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 24)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 25)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Block, 8), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 16)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 20)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Block, 24), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 24)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 25)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Block, 16), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 16)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 20)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Block, 28), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 24)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 25)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Block, 44), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 16)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 20)
		V00 = bit32.bor(bit32.bor(V00 + V04, 0) + buffer.readu32(Block, 60), 0); V12 = bit32.lrotate(bit32.bxor(V12, V00), 24)
		V08 = bit32.bor(V08 + V12, 0); V04 = bit32.lrotate(bit32.bxor(V04, V08), 25)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Block, 20), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 16)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 20)
		V01 = bit32.bor(bit32.bor(V01 + V05, 0) + buffer.readu32(Block, 0), 0); V13 = bit32.lrotate(bit32.bxor(V13, V01), 24)
		V09 = bit32.bor(V09 + V13, 0); V05 = bit32.lrotate(bit32.bxor(V05, V09), 25)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Block, 4), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 16)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 20)
		V02 = bit32.bor(bit32.bor(V02 + V06, 0) + buffer.readu32(Block, 36), 0); V14 = bit32.lrotate(bit32.bxor(V14, V02), 24)
		V10 = bit32.bor(V10 + V14, 0); V06 = bit32.lrotate(bit32.bxor(V06, V10), 25)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Block, 32), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 16)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 20)
		V03 = bit32.bor(bit32.bor(V03 + V07, 0) + buffer.readu32(Block, 24), 0); V15 = bit32.lrotate(bit32.bxor(V15, V03), 24)
		V11 = bit32.bor(V11 + V15, 0); V07 = bit32.lrotate(bit32.bxor(V07, V11), 25)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Block, 56), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 16)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 20)
		V00 = bit32.bor(bit32.bor(V00 + V05, 0) + buffer.readu32(Block, 40), 0); V15 = bit32.lrotate(bit32.bxor(V15, V00), 24)
		V10 = bit32.bor(V10 + V15, 0); V05 = bit32.lrotate(bit32.bxor(V05, V10), 25)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Block, 8), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 16)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 20)
		V01 = bit32.bor(bit32.bor(V01 + V06, 0) + buffer.readu32(Block, 48), 0); V12 = bit32.lrotate(bit32.bxor(V12, V01), 24)
		V11 = bit32.bor(V11 + V12, 0); V06 = bit32.lrotate(bit32.bxor(V06, V11), 25)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Block, 12), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 16)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 20)
		V02 = bit32.bor(bit32.bor(V02 + V07, 0) + buffer.readu32(Block, 16), 0); V13 = bit32.lrotate(bit32.bxor(V13, V02), 24)
		V08 = bit32.bor(V08 + V13, 0); V07 = bit32.lrotate(bit32.bxor(V07, V08), 25)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Block, 28), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 16)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 20)
		V03 = bit32.bor(bit32.bor(V03 + V04, 0) + buffer.readu32(Block, 52), 0); V14 = bit32.lrotate(bit32.bxor(V14, V03), 24)
		V09 = bit32.bor(V09 + V14, 0); V04 = bit32.lrotate(bit32.bxor(V04, V09), 25)

		buffer.writeu32(Out, OutOffset + 60, bit32.bxor(V15, buffer.readu32(Cv, 28)))
		buffer.writeu32(Out, OutOffset + 0, bit32.bxor(V00, V08))
		buffer.writeu32(Out, OutOffset + 4, bit32.bxor(V01, V09))
		buffer.writeu32(Out, OutOffset + 8, bit32.bxor(V02, V10))
		buffer.writeu32(Out, OutOffset + 12, bit32.bxor(V03, V11))
		buffer.writeu32(Out, OutOffset + 16, bit32.bxor(V04, V12))
		buffer.writeu32(Out, OutOffset + 20, bit32.bxor(V05, V13))
		buffer.writeu32(Out, OutOffset + 24, bit32.bxor(V06, V14))
		buffer.writeu32(Out, OutOffset + 28, bit32.bxor(V07, V15))
		buffer.writeu32(Out, OutOffset + 32, bit32.bxor(V08, buffer.readu32(Cv, 0)))
		buffer.writeu32(Out, OutOffset + 36, bit32.bxor(V09, buffer.readu32(Cv, 4)))
		buffer.writeu32(Out, OutOffset + 40, bit32.bxor(V10, buffer.readu32(Cv, 8)))
		buffer.writeu32(Out, OutOffset + 44, bit32.bxor(V11, buffer.readu32(Cv, 12)))
		buffer.writeu32(Out, OutOffset + 48, bit32.bxor(V12, buffer.readu32(Cv, 16)))
		buffer.writeu32(Out, OutOffset + 52, bit32.bxor(V13, buffer.readu32(Cv, 20)))
		buffer.writeu32(Out, OutOffset + 56, bit32.bxor(V14, buffer.readu32(Cv, 24)))
		OutOffset += EXTENDED_CV_SIZE
	end
end

@native
local function ProcessChunks(
	InitialHashVector: buffer,
	Flags: number,
	Message: buffer,
	MessageLength: number
): (number, number, number)
	local StateCvs = STACK_SCRATCH
	local StateCv = STATE_CV_SCRATCH
	local MergeBlock = MERGE_BLOCK_SCRATCH
	local MergeCv = MERGE_CV_SCRATCH
	local FlagsParent = Flags + PARENT_FLAG

	local StackSize = 0
	local StateCounter = 0
	local BlockOffset = 0
	local FullLimit = MessageLength - CHUNK_SIZE

	while BlockOffset < FullLimit do
		CompressBlocks(InitialHashVector, Message, BlockOffset, StateCounter, BLOCK_SIZE, Flags, 16, StateCv)
		BlockOffset += CHUNK_SIZE
		StateCounter += 1

		local CurrentCv = StateCv
		local MergeAmount = StateCounter
		while MergeAmount % 2 == 0 do
			StackSize -= 1
			buffer.copy(MergeBlock, 0, StateCvs, StackSize * CV_SIZE, CV_SIZE)
			buffer.copy(MergeBlock, CV_SIZE, CurrentCv, 0, CV_SIZE)
			CompressBlocks(InitialHashVector, MergeBlock, 0, 0, BLOCK_SIZE, FlagsParent, 1, MergeCv)
			CurrentCv = MergeCv
			MergeAmount /= 2
		end

		buffer.copy(StateCvs, StackSize * CV_SIZE, CurrentCv, 0, CV_SIZE)
		StackSize += 1
	end

	return BlockOffset, StateCounter, StackSize
end

local function EmitOutput(Cv: buffer, Block: buffer, BlockOffset: number, BlockLength: number, Flags: number, Length: number): buffer
	local Output = buffer.create(Length)
	if Length == CV_SIZE then
		CompressBlocks(Cv, Block, BlockOffset, 0, BlockLength, Flags, 1, Output)
		return Output
	end

	if Length < CV_SIZE then
		CompressBlocks(Cv, Block, BlockOffset, 0, BlockLength, Flags, 1, OUTPUT_SCRATCH)
		buffer.copy(Output, 0, OUTPUT_SCRATCH, 0, Length)
		return Output
	end

	local SourceBlock = Block
	if BlockOffset ~= 0 then
		SourceBlock = PADDED_SCRATCH
		buffer.copy(SourceBlock, 0, Block, BlockOffset, BLOCK_SIZE)
	end

	local FullBlocks = Length // EXTENDED_CV_SIZE
	if FullBlocks > 0 then
		OutputBlocks(Cv, SourceBlock, BlockLength, Flags, Output, 0, FullBlocks - 1)
	end

	local Produced = FullBlocks * EXTENDED_CV_SIZE
	local Remaining = Length - Produced
	if Remaining > 0 then
		if Remaining <= CV_SIZE then
			CompressBlocks(Cv, SourceBlock, 0, FullBlocks, BlockLength, Flags, 1, OUTPUT_SCRATCH)
		else
			OutputBlocks(Cv, SourceBlock, BlockLength, Flags, OUTPUT_SCRATCH, FullBlocks, FullBlocks)
		end
		buffer.copy(Output, Produced, OUTPUT_SCRATCH, 0, Remaining)
	end

	return Output
end

local function ProcessMessage(InitialHashVector: buffer, Flags: number, Message: buffer, Length: number): buffer
	local MessageLength = buffer.len(Message)
	if MessageLength <= BLOCK_SIZE then
		local RootFlags = Flags + SINGLE_ROOT_FLAGS
		if MessageLength == BLOCK_SIZE then
			return EmitOutput(InitialHashVector, Message, 0, BLOCK_SIZE, RootFlags, Length)
		end

		local Block: buffer
		if MessageLength == 0 then
			Block = ZERO_BLOCK
		else
			Block = PADDED_SCRATCH
			buffer.copy(Block, 0, Message, 0, MessageLength)
			buffer.fill(Block, MessageLength, 0, BLOCK_SIZE - MessageLength)
		end
		return EmitOutput(InitialHashVector, Block, 0, MessageLength, RootFlags, Length)
	end

	local BlockOffset, StateCounter, StackSize = 0, 0, 0
	if MessageLength > CHUNK_SIZE then
		BlockOffset, StateCounter, StackSize = ProcessChunks(InitialHashVector, Flags, Message, MessageLength)
	end

	local StateCv = STATE_CV_SCRATCH
	local StateStartFlag = CHUNK_START
	local Remaining = MessageLength - BlockOffset
	if Remaining > BLOCK_SIZE then
		local Count = (Remaining - 1) // BLOCK_SIZE
		CompressBlocks(InitialHashVector, Message, BlockOffset, StateCounter, BLOCK_SIZE, if Count == 1 then Flags + CHUNK_START else Flags, Count, StateCv)
		BlockOffset += Count * BLOCK_SIZE
		StateStartFlag = 0
	end

	local LastLength = MessageLength - BlockOffset
	local LastBlock: buffer
	local LastOffset: number
	if LastLength == BLOCK_SIZE then
		LastBlock = Message
		LastOffset = BlockOffset
	else
		LastBlock = PADDED_SCRATCH
		LastOffset = 0
		buffer.copy(LastBlock, 0, Message, BlockOffset, LastLength)
		buffer.fill(LastBlock, LastLength, 0, BLOCK_SIZE - LastLength)
	end

	if StateCounter > 0 then
		local StateCvs = STACK_SCRATCH
		local MergeBlock = MERGE_BLOCK_SCRATCH
		local MergeCv = MERGE_CV_SCRATCH
		local FlagsParent = Flags + PARENT_FLAG
		local ChunkCv = if StateStartFlag == CHUNK_START then InitialHashVector else StateCv
		CompressBlocks(ChunkCv, LastBlock, LastOffset, StateCounter, LastLength, Flags + StateStartFlag + CHUNK_END, 1, MergeCv)
		for Index = StackSize, 2, -1 do
			buffer.copy(MergeBlock, 0, StateCvs, (Index - 1) * CV_SIZE, CV_SIZE)
			buffer.copy(MergeBlock, CV_SIZE, MergeCv, 0, CV_SIZE)
			CompressBlocks(InitialHashVector, MergeBlock, 0, 0, BLOCK_SIZE, FlagsParent, 1, MergeCv)
		end

		local OutputBlock = OUTPUT_BLOCK_SCRATCH
		buffer.copy(OutputBlock, 0, StateCvs, 0, CV_SIZE)
		buffer.copy(OutputBlock, CV_SIZE, MergeCv, 0, CV_SIZE)
		return EmitOutput(InitialHashVector, OutputBlock, 0, BLOCK_SIZE, Flags + ROOT_FLAG + PARENT_FLAG, Length)
	end

	return EmitOutput(StateCv, LastBlock, LastOffset, LastLength, Flags + CHUNK_END + ROOT_FLAG, Length)
end

local KEYSTREAM_FLAGS = HASH_FLAG + SINGLE_ROOT_FLAGS

local function KeystreamInto(Key: buffer, OutPool: buffer, BlockCount: number): ()
	OutputBlocks(Key, ZERO_BLOCK, 0, KEYSTREAM_FLAGS, OutPool, 1, BlockCount)
	CompressBlocks(Key, ZERO_BLOCK, 0, 0, 0, KEYSTREAM_FLAGS, 1, Key)
end

return {
	ProcessMessage = ProcessMessage,
	KeystreamInto = KeystreamInto,
	INITIAL_VECTORS = INITIAL_VECTORS,
	HASH_FLAG = HASH_FLAG,
	DERIVE_CONTEXT_FLAG = DERIVE_CONTEXT_FLAG,
	DERIVE_MATERIAL_FLAG = DERIVE_MATERIAL_FLAG,
}
