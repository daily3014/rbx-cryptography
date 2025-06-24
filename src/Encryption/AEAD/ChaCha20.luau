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
	for Index, ByteValue in ipairs(SigmaBytes) do
		buffer.writeu8(SIGMA_CONSTANTS, Index - 1, ByteValue)
	end
end

local TAU_CONSTANTS = buffer.create(16) do
	local TauBytes = { string.byte("expand 16-byte k", 1, -1) }
	for Index, ByteValue in ipairs(TauBytes) do
		buffer.writeu8(TAU_CONSTANTS, Index - 1, ByteValue)
	end
end

local function QuarterRound(State: buffer, A: number, B: number, C: number, D: number)
	local StateA = buffer.readu32(State, A * DWORD)
	local StateB = buffer.readu32(State, B * DWORD)
	local StateC = buffer.readu32(State, C * DWORD)
	local StateD = buffer.readu32(State, D * DWORD)

	StateA = (StateA + StateB) % 2^32
	StateD = bit32.lrotate(bit32.bxor(StateD, StateA), 16)
	StateC += StateD
	StateB = bit32.lrotate(bit32.bxor(StateB, StateC), 12)
	StateA += StateB
	StateD = bit32.lrotate(bit32.bxor(StateD, StateA), 8)
	StateC += StateD
	StateB = bit32.lrotate(bit32.bxor(StateB, StateC), 7)

	buffer.writeu32(State, A * DWORD, StateA)
	buffer.writeu32(State, B * DWORD, StateB)
	buffer.writeu32(State, C * DWORD, StateC)
	buffer.writeu32(State, D * DWORD, StateD)
end

local function ProcessBlock(InitialState: buffer, Rounds: number): buffer
	local WorkingState = buffer.create(STATE_SIZE * DWORD)
	buffer.copy(WorkingState, 0, InitialState, 0, STATE_SIZE * DWORD)

	for Round = 1, Rounds do
		local IsOddRound = Round % 2 == 1

		if IsOddRound then
			QuarterRound(WorkingState, 0, 4, 8, 12)
			QuarterRound(WorkingState, 1, 5, 9, 13)
			QuarterRound(WorkingState, 2, 6, 10, 14)
			QuarterRound(WorkingState, 3, 7, 11, 15)
		else
			QuarterRound(WorkingState, 0, 5, 10, 15)
			QuarterRound(WorkingState, 1, 6, 11, 12)
			QuarterRound(WorkingState, 2, 7, 8, 13)
			QuarterRound(WorkingState, 3, 4, 9, 14)
		end
	end

	for StateIndex = 0, STATE_SIZE - 1 do
		local OriginalValue = buffer.readu32(InitialState, StateIndex * DWORD)
		local WorkingValue = buffer.readu32(WorkingState, StateIndex * DWORD)
		buffer.writeu32(WorkingState, StateIndex * DWORD, (WorkingValue + OriginalValue))
	end

	return WorkingState
end

local function InitializeState(Key: buffer, Nonce: buffer, Counter: number): buffer
	local KeyLength = buffer.len(Key)

	local State = buffer.create(STATE_SIZE * DWORD)

	local Sigma, Tau = SIGMA_CONSTANTS, TAU_CONSTANTS
	local Constants = KeyLength == 32 and Sigma or Tau

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

	while DataOffset < DataLength do
		local State = InitializeState(Key, Nonce, BlockCounter)
		local Keystream = ProcessBlock(State, BlockRounds)

		local BytesToProcess = math.min(BLOCK_SIZE, DataLength - DataOffset)

		for Index = 0, BytesToProcess - 1 do
			local DataByte = buffer.readu8(Data, DataOffset + Index)
			local KeystreamByte = buffer.readu8(Keystream, Index)
			buffer.writeu8(Output, DataOffset + Index, bit32.bxor(DataByte, KeystreamByte))
		end

		DataOffset += BytesToProcess
		BlockCounter += 1
	end

	return Output
end

return ChaCha20