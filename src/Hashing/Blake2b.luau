--[=[
	Cryptography library: BLAKE2b

	Return type: string
	Example usage:
		local Message = buffer.fromstring("Hello World")

		-- BLAKE2b-128 (128-bit output)
		local Result128 = BLAKE2b(Message, 16)

		-- BLAKE2b-256 (256-bit output)
		local Result256 = BLAKE2b(Message, 32)

		-- BLAKE2b-384 (384-bit output)
		local Result384 = BLAKE2b(Message, 48)

		-- BLAKE2b-512 (512-bit output, default)
		local Result512 = BLAKE2b(Message, 64)
		-- or simply: local Result512 = BLAKE2b(Message)

		-- With optional key
		local OptionalKey = buffer.fromstring("MyKey")
		local Result = BLAKE2b(Message, 64, OptionalKey)
--]=]

--!strict
--!optimize 2
--!native

local BLOCK_SIZE_BYTES = 128
local DEFAULT_OUTPUT_BYTES = 64

local BLAKE2B_MIN_OUTPUT_BYTES = 1
local BLAKE2B_MAX_OUTPUT_BYTES = 64
local BLAKE2B_MAX_KEY_BYTES = 64

local PERMUTATION_VALUES = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	15, 11, 5, 9, 10, 16, 14, 7, 2, 13, 1, 3, 12, 8, 6, 4,
	12, 9, 13, 1, 6, 3, 16, 14, 11, 15, 4, 7, 8, 2, 10, 5,
	8, 10, 4, 2, 14, 13, 12, 15, 3, 7, 6, 11, 5, 1, 16, 9,
	10, 1, 6, 8, 3, 5, 11, 16, 15, 2, 12, 13, 7, 9, 4, 14,
	3, 13, 7, 11, 1, 12, 9, 4, 5, 14, 8, 6, 16, 15, 2, 10,
	13, 6, 2, 16, 15, 14, 5, 11, 1, 8, 7, 4, 10, 3, 9, 12,
	14, 12, 8, 15, 13, 2, 4, 10, 6, 1, 16, 5, 9, 7, 3, 11,
	7, 16, 15, 10, 12, 4, 1, 9, 13, 3, 14, 8, 2, 5, 11, 6,
	11, 3, 9, 5, 8, 7, 2, 6, 16, 12, 10, 15, 4, 13, 14, 1,
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	15, 11, 5, 9, 10, 16, 14, 7, 2, 13, 1, 3, 12, 8, 6, 4
}

local PERMUTATION_TABLE = buffer.create(192)
for I = 1, 192 do
	buffer.writeu8(PERMUTATION_TABLE, I - 1, (PERMUTATION_VALUES[I] - 1) * 8)
end

local Work9, Work10, Work11, Work12, Work13, Work14, Work15, Work16 = 0x6a09e667f3bcc908i, 0xbb67ae8584caa73bi, 0x3c6ef372fe94f82bi, 0xa54ff53a5f1d36f1i, 0x510e527fade682d1i, 0x9b05688c2b3e6c1fi, 0x1f83d9abfb41bd6bi, 0x5be0cd19137e2179i

local function ProcessCompressionRound(Block: buffer, ByteCounter: number, FinalBlock: boolean, State: {integer})
	local W1, W2, W3, W4, W5, W6, W7, W8 = State[1], State[2], State[3], State[4], State[5], State[6], State[7], State[8]
	local W9, W10, W11, W12, W13, W14, W15, W16 = Work9, Work10, Work11, Work12, integer.bxor(Work13, integer.create(ByteCounter)), Work14, Work15, Work16

	if FinalBlock then
		W15 = integer.bnot(W15)
	end

	local MsgX, MsgY = 0i, 0i
	local Permutation = PERMUTATION_TABLE

	for RoundNum = 1, 12 do
		local ScheduleBase = (RoundNum - 1) * 16

		MsgX = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 0))
		MsgY = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 1))

		W1 = integer.add(integer.add(W1, W5), MsgX)
		W13 = integer.rrotate(integer.bxor(W13, W1), 32i)

		W9 = integer.add(W9, W13)
		W5 = integer.rrotate(integer.bxor(W5, W9), 24i)

		W1 = integer.add(integer.add(W1, W5), MsgY)
		W13 = integer.rrotate(integer.bxor(W13, W1), 16i)

		W9 = integer.add(W9, W13)
		W5 = integer.rrotate(integer.bxor(W5, W9), 63i)

		MsgX = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 2))
		MsgY = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 3))

		W2 = integer.add(integer.add(W2, W6), MsgX)
		W14 = integer.rrotate(integer.bxor(W14, W2), 32i)

		W10 = integer.add(W10, W14)
		W6 = integer.rrotate(integer.bxor(W6, W10), 24i)

		W2 = integer.add(integer.add(W2, W6), MsgY)
		W14 = integer.rrotate(integer.bxor(W14, W2), 16i)

		W10 = integer.add(W10, W14)
		W6 = integer.rrotate(integer.bxor(W6, W10), 63i)

		MsgX = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 4))
		MsgY = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 5))

		W3 = integer.add(integer.add(W3, W7), MsgX)
		W15 = integer.rrotate(integer.bxor(W15, W3), 32i)

		W11 = integer.add(W11, W15)
		W7 = integer.rrotate(integer.bxor(W7, W11), 24i)

		W3 = integer.add(integer.add(W3, W7), MsgY)
		W15 = integer.rrotate(integer.bxor(W15, W3), 16i)

		W11 = integer.add(W11, W15)
		W7 = integer.rrotate(integer.bxor(W7, W11), 63i)

		MsgX = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 6))
		MsgY = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 7))

		W4 = integer.add(integer.add(W4, W8), MsgX)
		W16 = integer.rrotate(integer.bxor(W16, W4), 32i)

		W12 = integer.add(W12, W16)
		W8 = integer.rrotate(integer.bxor(W8, W12), 24i)

		W4 = integer.add(integer.add(W4, W8), MsgY)
		W16 = integer.rrotate(integer.bxor(W16, W4), 16i)

		W12 = integer.add(W12, W16)
		W8 = integer.rrotate(integer.bxor(W8, W12), 63i)

		MsgX = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 8))
		MsgY = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 9))

		W1 = integer.add(integer.add(W1, W6), MsgX)
		W16 = integer.rrotate(integer.bxor(W16, W1), 32i)

		W11 = integer.add(W11, W16)
		W6 = integer.rrotate(integer.bxor(W6, W11), 24i)

		W1 = integer.add(integer.add(W1, W6), MsgY)
		W16 = integer.rrotate(integer.bxor(W16, W1), 16i)

		W11 = integer.add(W11, W16)
		W6 = integer.rrotate(integer.bxor(W6, W11), 63i)

		MsgX = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 10))
		MsgY = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 11))

		W2 = integer.add(integer.add(W2, W7), MsgX)
		W13 = integer.rrotate(integer.bxor(W13, W2), 32i)

		W12 = integer.add(W12, W13)
		W7 = integer.rrotate(integer.bxor(W7, W12), 24i)

		W2 = integer.add(integer.add(W2, W7), MsgY)
		W13 = integer.rrotate(integer.bxor(W13, W2), 16i)

		W12 = integer.add(W12, W13)
		W7 = integer.rrotate(integer.bxor(W7, W12), 63i)

		MsgX = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 12))
		MsgY = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 13))

		W3 = integer.add(integer.add(W3, W8), MsgX)
		W14 = integer.rrotate(integer.bxor(W14, W3), 32i)

		W9 = integer.add(W9, W14)
		W8 = integer.rrotate(integer.bxor(W8, W9), 24i)

		W3 = integer.add(integer.add(W3, W8), MsgY)
		W14 = integer.rrotate(integer.bxor(W14, W3), 16i)

		W9 = integer.add(W9, W14)
		W8 = integer.rrotate(integer.bxor(W8, W9), 63i)

		MsgX = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 14))
		MsgY = buffer.readinteger(Block, buffer.readu8(Permutation, ScheduleBase + 15))

		W4 = integer.add(integer.add(W4, W5), MsgX)
		W15 = integer.rrotate(integer.bxor(W15, W4), 32i)

		W10 = integer.add(W10, W15)
		W5 = integer.rrotate(integer.bxor(W5, W10), 24i)

		W4 = integer.add(integer.add(W4, W5), MsgY)
		W15 = integer.rrotate(integer.bxor(W15, W4), 16i)

		W10 = integer.add(W10, W15)
		W5 = integer.rrotate(integer.bxor(W5, W10), 63i)
	end

	State[1] = integer.bxor(State[1], W1, W9)
	State[2] = integer.bxor(State[2], W2, W10)
	State[3] = integer.bxor(State[3], W3, W11)
	State[4] = integer.bxor(State[4], W4, W12)
	State[5] = integer.bxor(State[5], W5, W13)
	State[6] = integer.bxor(State[6], W6, W14)
	State[7] = integer.bxor(State[7], W7, W15)
	State[8] = integer.bxor(State[8], W8, W16)
end

local function HashDigest(InputData: buffer, OutputLength: number, KeyData: buffer?): (string, buffer)
	local KeyLength = KeyData and buffer.len(KeyData) or 0
	local DataLength = buffer.len(InputData)

	local State = { Work9, Work10, Work11, Work12, Work13, Work14, Work15, Work16 }

	local S1Low = integer.band(State[1], 0xFFFFFFFFi)
	State[1] = integer.bor(integer.band(State[1], integer.bnot(0xFFFFFFFFi)), integer.bxor(S1Low, 0x01010000i, integer.lshift(integer.create(KeyLength), 8i), integer.create(OutputLength)))

	local Block = buffer.create(BLOCK_SIZE_BYTES)

	local ProcessedBytes = KeyLength > 0 and 128 or 0

	if KeyLength > 0 and KeyData then
		buffer.fill(Block, 0, 0, BLOCK_SIZE_BYTES)
		buffer.copy(Block, 0, KeyData)
		ProcessCompressionRound(Block, ProcessedBytes, DataLength == 0, State)
	end

	local RemainingBytes = DataLength % BLOCK_SIZE_BYTES
	local FinalBlockSize = RemainingBytes == 0 and BLOCK_SIZE_BYTES or RemainingBytes

	for BlockStart = 0, DataLength - FinalBlockSize - 1, BLOCK_SIZE_BYTES do
		buffer.copy(Block, 0, InputData, BlockStart, BLOCK_SIZE_BYTES)
		ProcessedBytes += BLOCK_SIZE_BYTES
		ProcessCompressionRound(Block, ProcessedBytes, false, State)
	end

	if KeyLength == 0 or DataLength > 0 then
		buffer.fill(Block, 0, 0, BLOCK_SIZE_BYTES)
		local CopyBytes = math.min(FinalBlockSize, DataLength)
		local CopyStart = math.max(0, DataLength - FinalBlockSize)
		if CopyBytes > 0 then
			buffer.copy(Block, 0, InputData, CopyStart, CopyBytes)
		end

		ProcessCompressionRound(Block, ProcessedBytes + CopyBytes, true, State)
	end

	local Digest = buffer.create(OutputLength)
	local Offset = 0

	for Index = 1, 8 do
		if Offset + 8 <= OutputLength then
			buffer.writeinteger(Digest, Offset, State[Index])
			Offset += 8
		end

		if Offset >= OutputLength then
			break
		end
	end

	local FinalDigest = string.format(
		"%016x%016x%016x%016x%016x%016x%016x%016x",
		integer.bswap(State[1]),
		integer.bswap(State[2]),
		integer.bswap(State[3]),
		integer.bswap(State[4]),
		integer.bswap(State[5]),
		integer.bswap(State[6]),
		integer.bswap(State[7]),
		integer.bswap(State[8])
	)

	return string.sub(FinalDigest, 1, OutputLength * 2), Digest
end

local function BLAKE2b(InputData: buffer, OutputLength: number?, KeyData: buffer?): (string, buffer)
	if InputData == nil then
		error("InputData cannot be nil", 2)
	end

	if typeof(InputData) ~= "buffer" then
		error(`InputData must be a buffer, got {typeof(InputData)}`, 2)
	end

	if OutputLength then
		if typeof(OutputLength) ~= "number" then
			error(`OutputLength must be a number, got {typeof(OutputLength)}`, 2)
		end

		if OutputLength ~= math.floor(OutputLength) then
			error(`OutputLength must be an integer, got {OutputLength}`, 2)
		end

		if OutputLength < BLAKE2B_MIN_OUTPUT_BYTES or OutputLength > BLAKE2B_MAX_OUTPUT_BYTES then
			error(`OutputLength must be between {BLAKE2B_MIN_OUTPUT_BYTES} and {BLAKE2B_MAX_OUTPUT_BYTES} bytes, got {OutputLength} bytes`, 2)
		end
	end

	if KeyData then
		if typeof(KeyData) ~= "buffer" then
			error(`KeyData must be a buffer, got {typeof(KeyData)}`, 2)
		end

		local KeyLength = buffer.len(KeyData)
		if KeyLength == 0 then
			error("KeyData cannot be empty", 2)
		end

		if KeyLength > BLAKE2B_MAX_KEY_BYTES then
			error(`KeyData must be at most {BLAKE2B_MAX_KEY_BYTES} bytes long, got {KeyLength} bytes`, 2)
		end
	end

	return HashDigest(InputData, OutputLength or DEFAULT_OUTPUT_BYTES, KeyData)
end

return BLAKE2b
