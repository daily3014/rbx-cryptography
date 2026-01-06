--[=[
	Cryptography library: ChaCha20
	
	Sizes:
		Nonce: 12 bytes
		Key: 16/32 bytes
	
	Return type: buffer
	Example usage:
		local Data = buffer.fromstring("Hello World")
		local Key = buffer.fromstring(string.rep("k", 32))
		local Nonce = buffer.fromstring(string.rep("n", 12))
		
		--------Usage Case 1--------
		local Encrypted = ChaCha20(Data, Key, Nonce)
		
		--------Usage Case 2--------
		local Decrypted = ChaCha20(Encrypted, Key, Nonce)
--]=]

--!strict
--!native
--!optimize 2

local DWORD = 4
local BLOCK_SIZE = 64
local STATE_SIZE = 16

local CHACHA20_NONCE_SIZE = 12
local CHACHA20_KEY_SIZE_16 = 16
local CHACHA20_KEY_SIZE_32 = 32

local SIGMA_CONSTANTS = buffer.create(16) do
	local SigmaBytes = { string.byte("expand 32-byte k", 1, -1) }
	for Index, ByteValue in SigmaBytes do
		buffer.writeu8(SIGMA_CONSTANTS, Index - 1, ByteValue)
	end
end

local TAU_CONSTANTS = buffer.create(16) do
	local TauBytes = { string.byte("expand 16-byte k", 1, -1) }
	for Index, ByteValue in TauBytes do
		buffer.writeu8(TAU_CONSTANTS, Index - 1, ByteValue)
	end
end

local function ProcessBlock(InitialState: buffer, Rounds: number)
	local S0: number, S1: number, S2: number, S3: number, S4: number, S5: number, S6: number, S7: number, S8: number, S9: number, S10: number, S11: number, S12: number, S13: number, S14: number, S15: number =
		buffer.readu32(InitialState, 0), buffer.readu32(InitialState, 4),
		buffer.readu32(InitialState, 8), buffer.readu32(InitialState, 12),
		buffer.readu32(InitialState, 16), buffer.readu32(InitialState, 20),
		buffer.readu32(InitialState, 24), buffer.readu32(InitialState, 28),
		buffer.readu32(InitialState, 32), buffer.readu32(InitialState, 36),
		buffer.readu32(InitialState, 40), buffer.readu32(InitialState, 44),
		buffer.readu32(InitialState, 48), buffer.readu32(InitialState, 52),
		buffer.readu32(InitialState, 56), buffer.readu32(InitialState, 60)

	for Round = 1, Rounds do
		local IsOddRound = Round % 2 == 1

		if IsOddRound then
			S0 = bit32.bor(S0 + S4, 0); S12 = bit32.lrotate(bit32.bxor(S12, S0), 16)
			S8 = bit32.bor(S8 + S12, 0); S4 = bit32.lrotate(bit32.bxor(S4, S8), 12)
			S0 = bit32.bor(S0 + S4, 0); S12 = bit32.lrotate(bit32.bxor(S12, S0), 8)
			S8 = bit32.bor(S8 + S12, 0); S4 = bit32.lrotate(bit32.bxor(S4, S8), 7)

			S1 = bit32.bor(S1 + S5, 0); S13 = bit32.lrotate(bit32.bxor(S13, S1), 16)
			S9 = bit32.bor(S9 + S13, 0); S5 = bit32.lrotate(bit32.bxor(S5, S9), 12)
			S1 = bit32.bor(S1 + S5, 0); S13 = bit32.lrotate(bit32.bxor(S13, S1), 8)
			S9 = bit32.bor(S9 + S13, 0); S5 = bit32.lrotate(bit32.bxor(S5, S9), 7)

			S2 = bit32.bor(S2 + S6, 0); S14 = bit32.lrotate(bit32.bxor(S14, S2), 16)
			S10 = bit32.bor(S10 + S14, 0); S6 = bit32.lrotate(bit32.bxor(S6, S10), 12)
			S2 = bit32.bor(S2 + S6, 0); S14 = bit32.lrotate(bit32.bxor(S14, S2), 8)
			S10 = bit32.bor(S10 + S14, 0); S6 = bit32.lrotate(bit32.bxor(S6, S10), 7)

			S3 = bit32.bor(S3 + S7, 0); S15 = bit32.lrotate(bit32.bxor(S15, S3), 16)
			S11 = bit32.bor(S11 + S15, 0); S7 = bit32.lrotate(bit32.bxor(S7, S11), 12)
			S3 = bit32.bor(S3 + S7, 0); S15 = bit32.lrotate(bit32.bxor(S15, S3), 8)
			S11 = bit32.bor(S11 + S15, 0); S7 = bit32.lrotate(bit32.bxor(S7, S11), 7)
		else
			S0 = bit32.bor(S0 + S5, 0); S15 = bit32.lrotate(bit32.bxor(S15, S0), 16)
			S10 = bit32.bor(S10 + S15, 0); S5 = bit32.lrotate(bit32.bxor(S5, S10), 12)
			S0 = bit32.bor(S0 + S5, 0); S15 = bit32.lrotate(bit32.bxor(S15, S0), 8)
			S10 = bit32.bor(S10 + S15, 0); S5 = bit32.lrotate(bit32.bxor(S5, S10), 7)

			S1 = bit32.bor(S1 + S6, 0); S12 = bit32.lrotate(bit32.bxor(S12, S1), 16)
			S11 = bit32.bor(S11 + S12, 0); S6 = bit32.lrotate(bit32.bxor(S6, S11), 12)
			S1 = bit32.bor(S1 + S6, 0); S12 = bit32.lrotate(bit32.bxor(S12, S1), 8)
			S11 = bit32.bor(S11 + S12, 0); S6 = bit32.lrotate(bit32.bxor(S6, S11), 7)

			S2 = bit32.bor(S2 + S7, 0); S13 = bit32.lrotate(bit32.bxor(S13, S2), 16)
			S8 = bit32.bor(S8 + S13, 0); S7 = bit32.lrotate(bit32.bxor(S7, S8), 12)
			S2 = bit32.bor(S2 + S7, 0); S13 = bit32.lrotate(bit32.bxor(S13, S2), 8)
			S8 = bit32.bor(S8 + S13, 0); S7 = bit32.lrotate(bit32.bxor(S7, S8), 7)

			S3 = bit32.bor(S3 + S4, 0); S14 = bit32.lrotate(bit32.bxor(S14, S3), 16)
			S9 = bit32.bor(S9 + S14, 0); S4 = bit32.lrotate(bit32.bxor(S4, S9), 12)
			S3 = bit32.bor(S3 + S4, 0); S14 = bit32.lrotate(bit32.bxor(S14, S3), 8)
			S9 = bit32.bor(S9 + S14, 0); S4 = bit32.lrotate(bit32.bxor(S4, S9), 7)
		end
	end
	
	buffer.writeu32(InitialState, 0, buffer.readu32(InitialState, 0) + S0)
	buffer.writeu32(InitialState, 4, buffer.readu32(InitialState, 4) + S1)
	buffer.writeu32(InitialState, 8, buffer.readu32(InitialState, 8) + S2)
	buffer.writeu32(InitialState, 12, buffer.readu32(InitialState, 12) + S3)
	buffer.writeu32(InitialState, 16, buffer.readu32(InitialState, 16) + S4)
	buffer.writeu32(InitialState, 20, buffer.readu32(InitialState, 20) + S5)
	buffer.writeu32(InitialState, 24, buffer.readu32(InitialState, 24) + S6)
	buffer.writeu32(InitialState, 28, buffer.readu32(InitialState, 28) + S7)
	buffer.writeu32(InitialState, 32, buffer.readu32(InitialState, 32) + S8)
	buffer.writeu32(InitialState, 36, buffer.readu32(InitialState, 36) + S9)
	buffer.writeu32(InitialState, 40, buffer.readu32(InitialState, 40) + S10)
	buffer.writeu32(InitialState, 44, buffer.readu32(InitialState, 44) + S11)
	buffer.writeu32(InitialState, 48, buffer.readu32(InitialState, 48) + S12)
	buffer.writeu32(InitialState, 52, buffer.readu32(InitialState, 52) + S13)
	buffer.writeu32(InitialState, 56, buffer.readu32(InitialState, 56) + S14)
	buffer.writeu32(InitialState, 60, buffer.readu32(InitialState, 60) + S15)
end

local function InitializeState(Key: buffer, Nonce: buffer, Counter: number): buffer
	local KeyLength = buffer.len(Key)
	local State = buffer.create(STATE_SIZE * DWORD)

	local Constants = KeyLength == 32 and SIGMA_CONSTANTS or TAU_CONSTANTS

	buffer.copy(State, 0, Constants, 0, 16)

	buffer.copy(State, 16, Key, 0, math.min(KeyLength, 16))
	if KeyLength == 32 then
		buffer.copy(State, 32, Key, 16, 16)
	else
		buffer.copy(State, 32, Key, 0, 16)
	end

	buffer.writeu32(State, 48, Counter)
	buffer.copy(State, 52, Nonce, 0, 12)

	return State
end

local function ChaCha20(Data: buffer, Key: buffer, Nonce: buffer, Counter: number?, Rounds: number?): buffer
	if Data == nil then
		error("Data cannot be nil", 2)
	end

	if typeof(Data) ~= "buffer" then
		error(`Data must be a buffer, got {typeof(Data)}`, 2)
	end

	if Key == nil then
		error("Key cannot be nil", 2)
	end

	if typeof(Key) ~= "buffer" then
		error(`Key must be a buffer, got {typeof(Key)}`, 2)
	end

	local KeyLength = buffer.len(Key)
	if KeyLength ~= CHACHA20_KEY_SIZE_16 and KeyLength ~= CHACHA20_KEY_SIZE_32 then
		error(`Key must be {CHACHA20_KEY_SIZE_16} or {CHACHA20_KEY_SIZE_32} bytes long, got {KeyLength} bytes`, 2)
	end

	if Nonce == nil then
		error("Nonce cannot be nil", 2)
	end

	if typeof(Nonce) ~= "buffer" then
		error(`Nonce must be a buffer, got {typeof(Nonce)}`, 2)
	end

	local NonceLength = buffer.len(Nonce)
	if NonceLength ~= CHACHA20_NONCE_SIZE then
		error(`Nonce must be exactly {CHACHA20_NONCE_SIZE} bytes long, got {NonceLength} bytes`, 2)
	end

	if Counter then
		if typeof(Counter) ~= "number" then
			error(`Counter must be a number, got {typeof(Counter)}`, 2)
		end

		if Counter < 0 then
			error(`Counter cannot be negative, got {Counter}`, 2)
		end

		if Counter ~= math.floor(Counter) then
			error(`Counter must be an integer, got {Counter}`, 2)
		end

		if Counter >= 2^32 then
			error(`Counter must be less than 2^32, got {Counter}`, 2)
		end
	end

	if Rounds then
		if typeof(Rounds) ~= "number" then
			error(`Rounds must be a number, got {typeof(Rounds)}`, 2)
		end

		if Rounds <= 0 then
			error(`Rounds must be positive, got {Rounds}`, 2)
		end

		if Rounds ~= math.floor(Rounds) then
			error(`Rounds must be an integer, got {Rounds}`, 2)
		end

		if Rounds % 2 ~= 0 then
			error(`Rounds must be even, got {Rounds}`, 2)
		end
	end

	local BlockCounter = Counter or 1
	local BlockRounds = Rounds or 20

	local DataLength = buffer.len(Data)
	if DataLength == 0 then
		return buffer.create(0)
	end

	local Output = buffer.create(DataLength)

	local DataOffset = 0

	local State = InitializeState(Key, Nonce, BlockCounter)
	local StateBackup = buffer.create(64)
	buffer.copy(StateBackup, 0, State, 0)
	
	while DataOffset < DataLength do
		ProcessBlock(State, BlockRounds)

		local BytesToProcess = math.min(BLOCK_SIZE, DataLength - DataOffset)

		for Index = 0, BytesToProcess - 1 do
			local DataByte = buffer.readu8(Data, DataOffset + Index)
			local KeystreamByte = buffer.readu8(State, Index)
			buffer.writeu8(Output, DataOffset + Index, bit32.bxor(DataByte, KeystreamByte))
		end

		DataOffset += BytesToProcess
		BlockCounter += 1
		buffer.copy(State, 0, StateBackup, 0)
		buffer.writeu32(State, 48, BlockCounter)
	end
	
	return Output
end

return ChaCha20