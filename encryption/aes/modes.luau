--!native
--!optimize 2

local ZeroesInitializationVector = buffer.create(16)

local CipherModes = {}

local function ValidateBlockData(DataBuffer, BlockSize)
	return buffer.len(DataBuffer) - BlockSize
end

local function ValidateInitializationVector(InitializationVector)
	return InitializationVector or ZeroesInitializationVector
end

local function XorWords(Buffer1, Offset1, Buffer2, Offset2, OutputBuffer, OutputOffset)
	buffer.writeu32(OutputBuffer, OutputOffset, bit32.bxor(buffer.readu32(Buffer1, Offset1), buffer.readu32(Buffer2, Offset2)))
	buffer.writeu32(OutputBuffer, OutputOffset + 4, bit32.bxor(buffer.readu32(Buffer1, Offset1 + 4), buffer.readu32(Buffer2, Offset2 + 4)))
	buffer.writeu32(OutputBuffer, OutputOffset + 8, bit32.bxor(buffer.readu32(Buffer1, Offset1 + 8), buffer.readu32(Buffer2, Offset2 + 8)))
	buffer.writeu32(OutputBuffer, OutputOffset + 12, bit32.bxor(buffer.readu32(Buffer1, Offset1 + 12), buffer.readu32(Buffer2, Offset2 + 12)))
end

local function ReadWords(Buffer, Offset)
	return buffer.readu32(Buffer, Offset), buffer.readu32(Buffer, Offset + 4), buffer.readu32(Buffer, Offset + 8), buffer.readu32(Buffer, Offset + 12)
end

local function WriteWords(Buffer, Offset, Word0, Word1, Word2, Word3)
	buffer.writeu32(Buffer, Offset, Word0)
	buffer.writeu32(Buffer, Offset + 4, Word1)
	buffer.writeu32(Buffer, Offset + 8, Word2)
	buffer.writeu32(Buffer, Offset + 12, Word3)
end

local function AddByteCounter(CounterBuffer, StepSize, StartOffset, EndOffset, IsLittleEndian)
	local ByteValue
	if IsLittleEndian then
		ByteValue = buffer.readu8(CounterBuffer, StartOffset) + StepSize
		buffer.writeu8(CounterBuffer, StartOffset, ByteValue)
		if ByteValue >= 256 then
			for CounterOffset = StartOffset + 1, EndOffset do
				ByteValue = buffer.readu8(CounterBuffer, CounterOffset) + 1
				buffer.writeu8(CounterBuffer, CounterOffset, ByteValue)
				if ByteValue < 256 then
					break
				end
			end
		end
	else
		ByteValue = buffer.readu8(CounterBuffer, EndOffset) + StepSize
		buffer.writeu8(CounterBuffer, EndOffset, ByteValue)
		if ByteValue >= 256 then
			for CounterOffset = EndOffset - 1, StartOffset, -1 do
				ByteValue = buffer.readu8(CounterBuffer, CounterOffset) + 1
				buffer.writeu8(CounterBuffer, CounterOffset, ByteValue)
				if ByteValue < 256 then
					break
				end
			end
		end
	end
end

CipherModes.ECB = table.freeze({
	ForwardMode = function(EncryptionProcessor, _, PlaintextBuffer, OutputBuffer)
		local DataLength = ValidateBlockData(PlaintextBuffer, 16)
		for BlockOffset = 0, DataLength, 16 do
			EncryptionProcessor(PlaintextBuffer, BlockOffset, OutputBuffer, BlockOffset)
		end
	end,

	InverseMode = function(_, DecryptionProcessor, CiphertextBuffer, OutputBuffer)
		local DataLength = ValidateBlockData(CiphertextBuffer, 16)
		for BlockOffset = 0, DataLength, 16 do
			DecryptionProcessor(CiphertextBuffer, BlockOffset, OutputBuffer, BlockOffset)
		end
	end
})

CipherModes.CBC = table.freeze({
	ForwardMode = function(EncryptionProcessor, _, PlaintextBuffer, OutputBuffer, _, InitializationVector)
		local DataLength = ValidateBlockData(PlaintextBuffer, 16)
		local InitializationVector = ValidateInitializationVector(InitializationVector)

		XorWords(PlaintextBuffer, 0, InitializationVector, 0, OutputBuffer, 0)
		EncryptionProcessor(OutputBuffer, 0, OutputBuffer, 0)

		for BlockOffset = 16, DataLength, 16 do
			XorWords(PlaintextBuffer, BlockOffset, OutputBuffer, BlockOffset - 16, OutputBuffer, BlockOffset)
			EncryptionProcessor(OutputBuffer, BlockOffset, OutputBuffer, BlockOffset)
		end
	end,

	InverseMode = function(_, DecryptionProcessor, CiphertextBuffer, OutputBuffer, _, InitializationVector)
		local DataLength = ValidateBlockData(CiphertextBuffer, 16)
		local InitializationVector = ValidateInitializationVector(InitializationVector)

		local Word0, Word1, Word2, Word3 = ReadWords(CiphertextBuffer, 0)
		DecryptionProcessor(CiphertextBuffer, 0, OutputBuffer, 0)
		XorWords(OutputBuffer, 0, InitializationVector, 0, OutputBuffer, 0)

		for BlockOffset = 16, DataLength, 16 do
			local Word4, Word5, Word6, Word7 = ReadWords(CiphertextBuffer, BlockOffset)
			DecryptionProcessor(CiphertextBuffer, BlockOffset, OutputBuffer, BlockOffset)
			WriteWords(OutputBuffer, BlockOffset, 
				bit32.bxor(buffer.readu32(OutputBuffer, BlockOffset), Word0),
				bit32.bxor(buffer.readu32(OutputBuffer, BlockOffset + 4), Word1),
				bit32.bxor(buffer.readu32(OutputBuffer, BlockOffset + 8), Word2),
				bit32.bxor(buffer.readu32(OutputBuffer, BlockOffset + 12), Word3))
			Word0, Word1, Word2, Word3 = Word4, Word5, Word6, Word7
		end
	end
})

CipherModes.PCBC = table.freeze({
	ForwardMode = function(EncryptionProcessor, _, PlaintextBuffer, OutputBuffer, _, InitializationVector)
		local DataLength = ValidateBlockData(PlaintextBuffer, 16)
		local InitializationVector = ValidateInitializationVector(InitializationVector)

		local Word0, Word1, Word2, Word3 = ReadWords(PlaintextBuffer, 0)
		WriteWords(OutputBuffer, 0,
			bit32.bxor(Word0, buffer.readu32(InitializationVector, 0)),
			bit32.bxor(Word1, buffer.readu32(InitializationVector, 4)),
			bit32.bxor(Word2, buffer.readu32(InitializationVector, 8)),
			bit32.bxor(Word3, buffer.readu32(InitializationVector, 12)))
		EncryptionProcessor(OutputBuffer, 0, OutputBuffer, 0)

		for BlockOffset = 16, DataLength, 16 do
			local Word4, Word5, Word6, Word7 = ReadWords(PlaintextBuffer, BlockOffset)
			WriteWords(OutputBuffer, BlockOffset,
				bit32.bxor(Word0, Word4, buffer.readu32(OutputBuffer, BlockOffset - 16)),
				bit32.bxor(Word1, Word5, buffer.readu32(OutputBuffer, BlockOffset - 12)),
				bit32.bxor(Word2, Word6, buffer.readu32(OutputBuffer, BlockOffset - 8)),
				bit32.bxor(Word3, Word7, buffer.readu32(OutputBuffer, BlockOffset - 4)))
			EncryptionProcessor(OutputBuffer, BlockOffset, OutputBuffer, BlockOffset)
			Word0, Word1, Word2, Word3 = Word4, Word5, Word6, Word7
		end
	end,

	InverseMode = function(_, DecryptionProcessor, CiphertextBuffer, OutputBuffer, _, InitializationVector)
		local DataLength = ValidateBlockData(CiphertextBuffer, 16)
		local InitializationVector = ValidateInitializationVector(InitializationVector)

		local Word0, Word1, Word2, Word3 = ReadWords(CiphertextBuffer, 0)
		DecryptionProcessor(CiphertextBuffer, 0, OutputBuffer, 0)
		local Word4 = bit32.bxor(buffer.readu32(OutputBuffer, 0), buffer.readu32(InitializationVector, 0))
		local Word5 = bit32.bxor(buffer.readu32(OutputBuffer, 4), buffer.readu32(InitializationVector, 4))
		local Word6 = bit32.bxor(buffer.readu32(OutputBuffer, 8), buffer.readu32(InitializationVector, 8))
		local Word7 = bit32.bxor(buffer.readu32(OutputBuffer, 12), buffer.readu32(InitializationVector, 12))
		WriteWords(OutputBuffer, 0, Word4, Word5, Word6, Word7)

		for BlockOffset = 16, DataLength, 16 do
			local Word8, Word9, Word10, Word11 = ReadWords(CiphertextBuffer, BlockOffset)
			DecryptionProcessor(CiphertextBuffer, BlockOffset, OutputBuffer, BlockOffset)
			Word4 = bit32.bxor(Word0, Word4, buffer.readu32(OutputBuffer, BlockOffset))
			Word5 = bit32.bxor(Word1, Word5, buffer.readu32(OutputBuffer, BlockOffset + 4))
			Word6 = bit32.bxor(Word2, Word6, buffer.readu32(OutputBuffer, BlockOffset + 8))
			Word7 = bit32.bxor(Word3, Word7, buffer.readu32(OutputBuffer, BlockOffset + 12))
			Word0, Word1, Word2, Word3 = Word8, Word9, Word10, Word11
			WriteWords(OutputBuffer, BlockOffset, Word4, Word5, Word6, Word7)
		end
	end
})

local function CipherFeedbackMode(EncryptionProcessor, _, InputBuffer, OutputBuffer, ModeOptions, InitializationVector, IsDecryption)
	local SegmentSize = ModeOptions.SegmentSize
	local DataLength = buffer.len(InputBuffer)

	local InitializationVector = ValidateInitializationVector(InitializationVector)

	local TemporaryBuffer = ModeOptions.CommonTemp or buffer.create(31)
	if DataLength == SegmentSize then
		EncryptionProcessor(InitializationVector, 0, TemporaryBuffer, 0)
		for ByteOffset = 0, SegmentSize - 1 do
			buffer.writeu8(OutputBuffer, ByteOffset, bit32.bxor(buffer.readu8(InputBuffer, ByteOffset), buffer.readu8(TemporaryBuffer, ByteOffset)))
		end
	else
		local LastBlockOffset = DataLength - SegmentSize
		local BackwardOffset = 16 - SegmentSize
		local LoopIndex
		EncryptionProcessor(InitializationVector, 0, TemporaryBuffer, 0)
		for ByteOffset = 0, SegmentSize - 1 do
			buffer.writeu8(OutputBuffer, ByteOffset, bit32.bxor(buffer.readu8(InputBuffer, ByteOffset), buffer.readu8(TemporaryBuffer, ByteOffset)))
		end
		buffer.copy(TemporaryBuffer, 0, InitializationVector, SegmentSize, BackwardOffset)
		buffer.copy(TemporaryBuffer, BackwardOffset, IsDecryption and InputBuffer or OutputBuffer, 0, SegmentSize)

		for BlockOffset = SegmentSize, LastBlockOffset - SegmentSize, SegmentSize do
			LoopIndex = 0
			buffer.copy(TemporaryBuffer, 16, TemporaryBuffer, SegmentSize, BackwardOffset)
			EncryptionProcessor(TemporaryBuffer, 0, TemporaryBuffer, 0)
			for ByteOffset = BlockOffset, BlockOffset + SegmentSize - 1 do
				buffer.writeu8(OutputBuffer, ByteOffset, bit32.bxor(buffer.readu8(InputBuffer, ByteOffset), buffer.readu8(TemporaryBuffer, LoopIndex)))
				LoopIndex += 1
			end
			buffer.copy(TemporaryBuffer, 0, TemporaryBuffer, 16, BackwardOffset)
			buffer.copy(TemporaryBuffer, BackwardOffset, IsDecryption and InputBuffer or OutputBuffer, BlockOffset, SegmentSize)
		end
		EncryptionProcessor(TemporaryBuffer, 0, TemporaryBuffer, 0)
		LoopIndex = 0

		for ByteOffset = LastBlockOffset, DataLength - 1 do
			buffer.writeu8(OutputBuffer, ByteOffset, bit32.bxor(buffer.readu8(InputBuffer, ByteOffset), buffer.readu8(TemporaryBuffer, LoopIndex)))
			LoopIndex += 1
		end
	end
end

local function OutputFeedbackMode(EncryptionProcessor, _, InputBuffer, OutputBuffer, _, InitializationVector)
	local DataLength = ValidateBlockData(InputBuffer, 16)
	local InitializationVector = ValidateInitializationVector(InitializationVector)

	local Word0, Word1, Word2, Word3 = ReadWords(InputBuffer, 0)
	EncryptionProcessor(InitializationVector, 0, OutputBuffer, 0)
	Word0 = bit32.bxor(Word0, buffer.readu32(OutputBuffer, 0))
	Word1 = bit32.bxor(Word1, buffer.readu32(OutputBuffer, 4))
	Word2 = bit32.bxor(Word2, buffer.readu32(OutputBuffer, 8))
	Word3 = bit32.bxor(Word3, buffer.readu32(OutputBuffer, 12))

	for BlockOffset = 16, DataLength, 16 do
		local Word4, Word5, Word6, Word7 = ReadWords(InputBuffer, BlockOffset)
		EncryptionProcessor(OutputBuffer, BlockOffset - 16, OutputBuffer, BlockOffset)
		WriteWords(OutputBuffer, BlockOffset - 16, Word0, Word1, Word2, Word3)
		Word0 = bit32.bxor(Word4, buffer.readu32(OutputBuffer, BlockOffset))
		Word1 = bit32.bxor(Word5, buffer.readu32(OutputBuffer, BlockOffset + 4))
		Word2 = bit32.bxor(Word6, buffer.readu32(OutputBuffer, BlockOffset + 8))
		Word3 = bit32.bxor(Word7, buffer.readu32(OutputBuffer, BlockOffset + 12))
	end

	WriteWords(OutputBuffer, DataLength, Word0, Word1, Word2, Word3)
end

local function CounterMode(EncryptionProcessor, _, InputBuffer, OutputBuffer, ModeOptions)
	local DataLength = ValidateBlockData(InputBuffer, 16)
	local TemporaryBuffer = ModeOptions.CommonTemp
	local InitialValue = ModeOptions.InitValue
	local PrefixString = ModeOptions.Prefix
	local SuffixString = ModeOptions.Suffix
	local StepSize = ModeOptions.Step
	local IsLittleEndian = ModeOptions.LittleEndian
	local StartOffset = #PrefixString
	local EndOffset = StartOffset + #InitialValue - 1

	buffer.writestring(TemporaryBuffer, 0, PrefixString)
	buffer.writestring(TemporaryBuffer, StartOffset, InitialValue)
	buffer.writestring(TemporaryBuffer, EndOffset + 1, SuffixString)

	local Word0, Word1, Word2, Word3 = ReadWords(InputBuffer, 0)
	EncryptionProcessor(TemporaryBuffer, 0, OutputBuffer, 0)
	WriteWords(OutputBuffer, 0,
		bit32.bxor(buffer.readu32(OutputBuffer, 0), Word0),
		bit32.bxor(buffer.readu32(OutputBuffer, 4), Word1),
		bit32.bxor(buffer.readu32(OutputBuffer, 8), Word2),
		bit32.bxor(buffer.readu32(OutputBuffer, 12), Word3))

	for BlockOffset = 16, DataLength, 16 do
		Word0, Word1, Word2, Word3 = ReadWords(InputBuffer, BlockOffset)
		AddByteCounter(TemporaryBuffer, StepSize, StartOffset, EndOffset, IsLittleEndian)
		EncryptionProcessor(TemporaryBuffer, 0, OutputBuffer, BlockOffset)
		WriteWords(OutputBuffer, BlockOffset,
			bit32.bxor(Word0, buffer.readu32(OutputBuffer, BlockOffset)),
			bit32.bxor(Word1, buffer.readu32(OutputBuffer, BlockOffset + 4)),
			bit32.bxor(Word2, buffer.readu32(OutputBuffer, BlockOffset + 8)),
			bit32.bxor(Word3, buffer.readu32(OutputBuffer, BlockOffset + 12)))
	end
end

CipherModes.OFB = table.freeze({
	ForwardMode = OutputFeedbackMode, 
	InverseMode = OutputFeedbackMode
})

CipherModes.CFB = {
	ForwardMode = function(...)
		CipherFeedbackMode(..., false)
	end,
	InverseMode = function(...)
		CipherFeedbackMode(..., true)
	end,
	SegmentSize = 16,
	CommonTemp = buffer.create(31)
}

CipherModes.CTR = {
	ForwardMode = CounterMode, 
	InverseMode = CounterMode,
	InitValue = string.pack("I2I2I2I2I2I2I2I2", math.random(0, 65535), math.random(0, 65535), math.random(0, 65535),
		math.random(0, 65535), math.random(0, 65535), math.random(0, 65535), math.random(0, 65535), math.random(0, 65535)),
	Prefix = "", 
	Suffix = "", 
	Step = 1, 
	LittleEndian = false,
	CommonTemp = buffer.create(16)
}

return table.freeze(CipherModes)