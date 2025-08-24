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
		local KeyedHash = Blake3.DigestKeyed(Key, Message, 32)
		
		--------Key Derivation--------
		local Context = buffer.fromstring("my context")
		local KeyDeriver = Blake3.DeriveKey(Context)
		local DerivedKey = KeyDeriver(Message, 32)
--]=]

--!strict
--!optimize 2
--!native

local BLOCK_SIZE = 64
local CV_SIZE = 32
local EXTENDED_CV_SIZE = 64
local MAX_STACK_DEPTH = 64
local STACK_BUFFER_SIZE = MAX_STACK_DEPTH * CV_SIZE

local CHUNK_START = 0x01
local CHUNK_END = 0x02
local PARENT_FLAG = 0x04
local ROOT_FLAG = 0x08

local INITIAL_VECTORS = buffer.create(CV_SIZE) do
	local IV = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	}
	for Index, Value in ipairs(IV) do
		buffer.writeu32(INITIAL_VECTORS, (Index - 1) * 4, Value)
	end
end

local function Compress(Hash: buffer, MessageBlock: buffer, Counter: number, V14: number, V15: number, IsFull: boolean?): buffer
	local Hash00 = buffer.readu32(Hash, 0)
	local Hash01 = buffer.readu32(Hash, 4)
	local Hash02 = buffer.readu32(Hash, 8)
	local Hash03 = buffer.readu32(Hash, 12)
	local Hash04 = buffer.readu32(Hash, 16)
	local Hash05 = buffer.readu32(Hash, 20)
	local Hash06 = buffer.readu32(Hash, 24)
	local Hash07 = buffer.readu32(Hash, 28)

	local V00, V01, V02, V03 = Hash00, Hash01, Hash02, Hash03
	local V04, V05, V06, V07 = Hash04, Hash05, Hash06, Hash07
	local V08, V09, V10, V11 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a

	local V12 = Counter % (2 ^ 32)
	local V13 = (Counter - V12) * (2 ^ -32)

	local M00 = buffer.readu32(MessageBlock, 0)
	local M01 = buffer.readu32(MessageBlock, 4)
	local M02 = buffer.readu32(MessageBlock, 8)
	local M03 = buffer.readu32(MessageBlock, 12)
	local M04 = buffer.readu32(MessageBlock, 16)
	local M05 = buffer.readu32(MessageBlock, 20)
	local M06 = buffer.readu32(MessageBlock, 24)
	local M07 = buffer.readu32(MessageBlock, 28)
	local M08 = buffer.readu32(MessageBlock, 32)
	local M09 = buffer.readu32(MessageBlock, 36)
	local M10 = buffer.readu32(MessageBlock, 40)
	local M11 = buffer.readu32(MessageBlock, 44)
	local M12 = buffer.readu32(MessageBlock, 48)
	local M13 = buffer.readu32(MessageBlock, 52)
	local M14 = buffer.readu32(MessageBlock, 56)
	local M15 = buffer.readu32(MessageBlock, 60)

	local XOR = bit32.bxor
	local LEFTROTATE = bit32.lrotate

	local Temp
	for Index = 1, 7 do
		V00 += V04 + M00; V12 = LEFTROTATE(XOR(V12, V00), 16)
		V08 += V12; V04 = LEFTROTATE(XOR(V04, V08), 20)
		V00 += V04 + M01; V12 = LEFTROTATE(XOR(V12, V00), 24)
		V08 += V12; V04 = LEFTROTATE(XOR(V04, V08), 25)

		V01 += V05 + M02; V13 = LEFTROTATE(XOR(V13, V01), 16)
		V09 += V13; V05 = LEFTROTATE(XOR(V05, V09), 20)
		V01 += V05 + M03; V13 = LEFTROTATE(XOR(V13, V01), 24)
		V09 += V13; V05 = LEFTROTATE(XOR(V05, V09), 25)

		V02 += V06 + M04; V14 = LEFTROTATE(XOR(V14, V02), 16)
		V10 += V14; V06 = LEFTROTATE(XOR(V06, V10), 20)
		V02 += V06 + M05; V14 = LEFTROTATE(XOR(V14, V02), 24)
		V10 += V14; V06 = LEFTROTATE(XOR(V06, V10), 25)

		V03 += V07 + M06; V15 = LEFTROTATE(XOR(V15, V03), 16)
		V11 += V15; V07 = LEFTROTATE(XOR(V07, V11), 20)
		V03 += V07 + M07; V15 = LEFTROTATE(XOR(V15, V03), 24)
		V11 += V15; V07 = LEFTROTATE(XOR(V07, V11), 25)

		V00 += V05 + M08; V15 = LEFTROTATE(XOR(V15, V00), 16)
		V10 += V15; V05 = LEFTROTATE(XOR(V05, V10), 20)
		V00 += V05 + M09; V15 = LEFTROTATE(XOR(V15, V00), 24)
		V10 += V15; V05 = LEFTROTATE(XOR(V05, V10), 25)

		V01 += V06 + M10; V12 = LEFTROTATE(XOR(V12, V01), 16)
		V11 += V12; V06 = LEFTROTATE(XOR(V06, V11), 20)
		V01 += V06 + M11; V12 = LEFTROTATE(XOR(V12, V01), 24)
		V11 += V12; V06 = LEFTROTATE(XOR(V06, V11), 25)

		V02 += V07 + M12; V13 = LEFTROTATE(XOR(V13, V02), 16)
		V08 += V13; V07 = LEFTROTATE(XOR(V07, V08), 20)
		V02 += V07 + M13; V13 = LEFTROTATE(XOR(V13, V02), 24)
		V08 += V13; V07 = LEFTROTATE(XOR(V07, V08), 25)

		V03 += V04 + M14; V14 = LEFTROTATE(XOR(V14, V03), 16)
		V09 += V14; V04 = LEFTROTATE(XOR(V04, V09), 20)
		V03 += V04 + M15; V14 = LEFTROTATE(XOR(V14, V03), 24)
		V09 += V14; V04 = LEFTROTATE(XOR(V04, V09), 25)

		if Index ~= 7 then
			Temp = M02
			M02 = M03
			M03 = M10
			M10 = M12
			M12 = M09
			M09 = M11
			M11 = M05
			M05 = M00
			M00 = Temp

			Temp = M06
			M06 = M04
			M04 = M07
			M07 = M13
			M13 = M14
			M14 = M15
			M15 = M08
			M08 = M01
			M01 = Temp
		end
	end

	if IsFull then
		local Result = buffer.create(EXTENDED_CV_SIZE)
		buffer.writeu32(Result, 0, XOR(V00, V08))
		buffer.writeu32(Result, 4, XOR(V01, V09))
		buffer.writeu32(Result, 8, XOR(V02, V10))
		buffer.writeu32(Result, 12, XOR(V03, V11))
		buffer.writeu32(Result, 16, XOR(V04, V12))
		buffer.writeu32(Result, 20, XOR(V05, V13))
		buffer.writeu32(Result, 24, XOR(V06, V14))
		buffer.writeu32(Result, 28, XOR(V07, V15))

		buffer.writeu32(Result, 32, XOR(V08, Hash00))
		buffer.writeu32(Result, 36, XOR(V09, Hash01))
		buffer.writeu32(Result, 40, XOR(V10, Hash02))
		buffer.writeu32(Result, 44, XOR(V11, Hash03))
		buffer.writeu32(Result, 48, XOR(V12, Hash04))
		buffer.writeu32(Result, 52, XOR(V13, Hash05))
		buffer.writeu32(Result, 56, XOR(V14, Hash06))
		buffer.writeu32(Result, 60, XOR(V15, Hash07))

		return Result
	else
		local Result = buffer.create(CV_SIZE)
		buffer.writeu32(Result, 0, XOR(V00, V08))
		buffer.writeu32(Result, 4, XOR(V01, V09))
		buffer.writeu32(Result, 8, XOR(V02, V10))
		buffer.writeu32(Result, 12, XOR(V03, V11))
		buffer.writeu32(Result, 16, XOR(V04, V12))
		buffer.writeu32(Result, 20, XOR(V05, V13))
		buffer.writeu32(Result, 24, XOR(V06, V14))
		buffer.writeu32(Result, 28, XOR(V07, V15))

		return Result
	end
end

local function ProcessMessage(InitialHashVector: buffer, Flags: number, Message: buffer, Length: number): buffer
	local MessageLength = buffer.len(Message)
	local StateCvs = buffer.create(STACK_BUFFER_SIZE)
	local StackSize = 0
	local StateCv = buffer.create(CV_SIZE)
	buffer.copy(StateCv, 0, InitialHashVector, 0, CV_SIZE)

	local StateCounter = 0
	local StateChunkNumber = 0
	local StateEndFlag = 0
	local StateStartFlag = CHUNK_START

	local BlockBuffer = buffer.create(BLOCK_SIZE)

	for BlockOffset = 0, MessageLength - BLOCK_SIZE - 1, BLOCK_SIZE do
		buffer.copy(BlockBuffer, 0, Message, BlockOffset, BLOCK_SIZE)
		local StateFlags = Flags + StateStartFlag + StateEndFlag

		StateCv = Compress(StateCv, BlockBuffer, StateCounter, BLOCK_SIZE, StateFlags)
		StateStartFlag = 0
		StateChunkNumber += 1

		if StateChunkNumber == 15 then
			StateEndFlag = CHUNK_END
		elseif StateChunkNumber == 16 then
			local MergeCv = StateCv
			local MergeAmount = StateCounter + 1

			while MergeAmount % 2 == 0 do
				StackSize = StackSize - 1
				local PopCv = buffer.create(CV_SIZE)
				buffer.copy(PopCv, 0, StateCvs, StackSize * CV_SIZE, CV_SIZE)

				local Block = buffer.create(EXTENDED_CV_SIZE)
				buffer.copy(Block, 0, PopCv, 0, CV_SIZE)
				buffer.copy(Block, CV_SIZE, MergeCv, 0, CV_SIZE)

				MergeCv = Compress(InitialHashVector, Block, 0, BLOCK_SIZE, Flags + PARENT_FLAG)
				MergeAmount = MergeAmount / 2
			end

			buffer.copy(StateCvs, StackSize * CV_SIZE, MergeCv, 0, CV_SIZE)
			StackSize = StackSize + 1
			buffer.copy(StateCv, 0, InitialHashVector, 0, CV_SIZE)
			StateStartFlag = CHUNK_START

			StateCounter += 1
			StateChunkNumber = 0
			StateEndFlag = 0
		end
	end

	local LastLength = MessageLength == 0 and 0 or ((MessageLength - 1) % BLOCK_SIZE + 1)
	local PaddedMessage = buffer.create(BLOCK_SIZE)

	if LastLength > 0 then
		buffer.copy(PaddedMessage, 0, Message, MessageLength - LastLength, LastLength)
	end

	local OutputCv: buffer
	local OutputBlock: buffer
	local OutputLength: number
	local OutputFlags: number

	if StateCounter > 0 then
		local StateFlags = Flags + StateStartFlag + CHUNK_END
		local MergeCv = Compress(StateCv, PaddedMessage, StateCounter, LastLength, StateFlags)

		for Index = StackSize, 2, -1 do
			local StackCv = buffer.create(CV_SIZE)
			buffer.copy(StackCv, 0, StateCvs, (Index - 1) * CV_SIZE, CV_SIZE)

			local Block = buffer.create(EXTENDED_CV_SIZE)
			buffer.copy(Block, 0, StackCv, 0, CV_SIZE)
			buffer.copy(Block, CV_SIZE, MergeCv, 0, CV_SIZE)

			MergeCv = Compress(InitialHashVector, Block, 0, BLOCK_SIZE, Flags + PARENT_FLAG)
		end

		OutputCv = InitialHashVector
		local FirstStackCv = buffer.create(CV_SIZE)
		buffer.copy(FirstStackCv, 0, StateCvs, 0, CV_SIZE)

		OutputBlock = buffer.create(EXTENDED_CV_SIZE)
		buffer.copy(OutputBlock, 0, FirstStackCv, 0, CV_SIZE)
		buffer.copy(OutputBlock, CV_SIZE, MergeCv, 0, CV_SIZE)

		OutputLength = BLOCK_SIZE
		OutputFlags = Flags + ROOT_FLAG + PARENT_FLAG
	else
		OutputCv = StateCv
		OutputBlock = PaddedMessage
		OutputLength = LastLength
		OutputFlags = Flags + StateStartFlag + CHUNK_END + ROOT_FLAG
	end

	local Output = buffer.create(Length)
	local OutputOffset = 0

	for Index = 0, Length // BLOCK_SIZE do
		local MessageDigest = Compress(OutputCv, OutputBlock, Index, OutputLength, OutputFlags, true)

		local BytesToCopy = math.min(BLOCK_SIZE, Length - OutputOffset)
		buffer.copy(Output, OutputOffset, MessageDigest, 0, BytesToCopy)
		OutputOffset += BytesToCopy

		if OutputOffset >= Length then
			break
		end
	end

	return Output
end

return function(Message: buffer, Length: number?): buffer
	return ProcessMessage(INITIAL_VECTORS, 0, Message, Length or 32)
end