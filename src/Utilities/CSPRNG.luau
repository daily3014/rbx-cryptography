--[=[
	Cryptography library: Cryptographically Secure RNG

	Usage:
		local RandomFloat = CSPRNG.Random()
		local RandomInt = CSPRNG.RandomInt(1, 100)
		local RandomNumber = CSPRNG.RandomNumber(0.5, 10.5)
		local RandomBytes = CSPRNG.RandomBytes(32)
		local RandomHex = CSPRNG.RandomHex(16)
		local FastString = CSPRNG.RandomString(16, false)
		local FastBuffer = CSPRNG.RandomString(32, true)

		CSPRNG.AddEntropy(SomeBuffer)
		CSPRNG.AddEntropy()

	Key generation just uses RandomBytes(32): X25519 clamps the scalar internally
	and Ed25519 hashes the seed, so neither wants pre-clamped bytes.

	AddEntropy folds the given bytes into the internal state and regenerates the
	keystream pool. The buffer may be any length, and passing nothing simply
	refreshes from the built-in sources. Entropy is only ever mixed in, never
	replaced, so injecting weak bytes can never lower the existing strength.
--]=]

--!strict
--!optimize 2
--!native

local Blake3 = require("../Hashing/Blake3")
local Conversions = require("./Conversions")
local ToHex = Conversions.ToHex

type CSPRNGModule = {
	AddEntropy: (Entropy: buffer?) -> (),

	Random: () -> number,
	RandomInt: (Min: number, Max: number?) -> number,
	RandomNumber: (Min: number, Max: number?) -> number,
	RandomBytes: (Count: number) -> buffer,
	RandomString: (Length: number, AsBuffer: boolean?) -> string | buffer,
	RandomHex: (Length: number) -> string,
}

local KEY_SIZE = 32
local NONCE_SIZE = 12
local MAX_UINT32 = 0xFFFFFFFF

local POOL_SIZE = 2048
local REKEY_BLOCKS = 1024
local JITTER_SAMPLES = 512
local SOURCE_LIMIT = 1024

local CSPRNG = {} :: CSPRNGModule

local INPUT_BUFFER = buffer.create(KEY_SIZE + NONCE_SIZE + 8)

local Key = buffer.create(0)
local Nonce = buffer.create(0)
local StreamBuffer = buffer.create(0)

local Counter = 0
local BufferPosition = 0
local BufferSize = 0

local function GatherEntropy(UserEntropy: buffer?)
	local Sources = buffer.create(SOURCE_LIMIT)
	local Offset = 0

	local function WriteToBuffer(Source: buffer)
		local Size = buffer.len(Source)
		buffer.copy(Sources, Offset, Source, 0, Size)
		Offset += Size
	end

	if tick then
		local TimeBuffer = buffer.create(8)
		buffer.writef64(TimeBuffer, 0, tick())
		WriteToBuffer(TimeBuffer)
	end

	local ClockBuffer = buffer.create(8)
	buffer.writef64(ClockBuffer, 0, os.clock())
	WriteToBuffer(ClockBuffer)

	local UnixTime = os.time()
	local UnixBuffer = buffer.create(8)
	buffer.writeu32(UnixBuffer, 0, UnixTime % 0x100000000)
	buffer.writeu32(UnixBuffer, 4, math.floor(UnixTime / 0x100000000))
	WriteToBuffer(UnixBuffer)

	if DateTime then
		local DateTimeMillis = DateTime.now().UnixTimestampMillis
		local DateTimeBuffer = buffer.create(8)
		buffer.writef64(DateTimeBuffer, 0, DateTimeMillis)
		WriteToBuffer(DateTimeBuffer)
	end

	local JitterSamples = buffer.create(JITTER_SAMPLES)
	local JitterMix = 0
	local LongestRun = 0
	local CurrentRun = 0
	local PreviousSample = -1
	for Index = 0, JITTER_SAMPLES - 1 do
		local StartTime = os.clock()
		local Scratch = buffer.create(64 + JitterMix % 4096)
		buffer.writeu32(Scratch, 0, Index)
		local Sample = math.floor((os.clock() - StartTime) * 1000000000) % 256

		JitterMix += Sample
		buffer.writeu8(JitterSamples, Index, Sample)

		CurrentRun = if Sample == PreviousSample then CurrentRun + 1 else 0
		PreviousSample = Sample
		if CurrentRun > LongestRun then
			LongestRun = CurrentRun
		end
	end

	if LongestRun > JITTER_SAMPLES // 8 then
		warn("CSPRNG: timing jitter appears degenerate (low-resolution clock); entropy may be weak")
	end

	WriteToBuffer(JitterSamples)

	if game then
		local HttpService = game:FindService("HttpService")
		if HttpService then
			WriteToBuffer(buffer.fromstring(HttpService:GenerateGUID(false)))
		end

		if game.JobId and #game.JobId > 0 then
			WriteToBuffer(buffer.fromstring(game.JobId))
		end

		if game.PlaceId then
			local PlaceIdBuffer = buffer.create(8)
			buffer.writeu32(PlaceIdBuffer, 0, game.PlaceId % 0x100000000)
			buffer.writeu32(PlaceIdBuffer, 4, math.floor(game.PlaceId / 0x100000000))
			WriteToBuffer(PlaceIdBuffer)
		end

		if workspace and workspace.DistributedGameTime then
			local DistTimeBuffer = buffer.create(8)
			buffer.writef64(DistTimeBuffer, 0, workspace.DistributedGameTime)
			WriteToBuffer(DistTimeBuffer)
		end
	end

	local Pointers = tostring(newproxy())
	if coroutine then
		Pointers ..= tostring(coroutine.running())
	end
	WriteToBuffer(buffer.fromstring(Pointers))

	local PreviousLength = buffer.len(Key) + buffer.len(Nonce)
	local UserLength = if UserEntropy then buffer.len(UserEntropy) else 0
	local Material = buffer.create(PreviousLength + Offset + UserLength)

	buffer.copy(Material, 0, Key, 0, buffer.len(Key))
	buffer.copy(Material, buffer.len(Key), Nonce, 0, buffer.len(Nonce))
	buffer.copy(Material, PreviousLength, Sources, 0, Offset)
	if UserEntropy then
		buffer.copy(Material, PreviousLength + Offset, UserEntropy, 0, UserLength)
	end

	local KeyMaterial = select(2, Blake3.Digest(Material, KEY_SIZE + NONCE_SIZE))

	Key = buffer.create(KEY_SIZE)
	buffer.copy(Key, 0, KeyMaterial, 0, KEY_SIZE)

	Nonce = buffer.create(NONCE_SIZE)
	buffer.copy(Nonce, 0, KeyMaterial, KEY_SIZE, NONCE_SIZE)

	Counter = 0
end

local function GenerateBlock()
	buffer.copy(INPUT_BUFFER, 0, Key, 0, KEY_SIZE)
	buffer.copy(INPUT_BUFFER, KEY_SIZE, Nonce, 0, NONCE_SIZE)
	buffer.writeu32(INPUT_BUFFER, KEY_SIZE + NONCE_SIZE, Counter % 0x100000000)
	buffer.writeu32(INPUT_BUFFER, KEY_SIZE + NONCE_SIZE + 4, math.floor(Counter / 0x100000000))

	StreamBuffer = select(2, Blake3.Digest(INPUT_BUFFER, POOL_SIZE))
	BufferPosition = 0
	BufferSize = POOL_SIZE
	Counter += 1

	if Counter % REKEY_BLOCKS == 0 then
		GatherEntropy()
	end
end

local function GetBytes(Count: number): buffer
	local Result = buffer.create(Count)
	local ResultPosition = 0

	while ResultPosition < Count do
		local Position = BufferPosition
		if Position >= BufferSize then
			GenerateBlock()
			Position = BufferPosition
		end

		local BytesToCopy = math.min(Count - ResultPosition, BufferSize - Position)

		buffer.copy(Result, ResultPosition, StreamBuffer, Position, BytesToCopy)
		ResultPosition += BytesToCopy
		BufferPosition = Position + BytesToCopy
	end

	return Result
end

local function GetFloat(): number
	if BufferPosition + 8 > BufferSize then
		GenerateBlock()
	end

	local Position = BufferPosition
	local Stream = StreamBuffer
	local Value1 = buffer.readu32(Stream, Position)
	local Value2 = buffer.readu32(Stream, Position + 4)
	BufferPosition = Position + 8

	local High = bit32.rshift(Value1, 5)
	local Low = bit32.rshift(Value2, 6)

	return (High * 67108864.0 + Low) / 9007199254740992.0
end

local function GetIntRange(Min: number, Max: number): number
	local Range = Max - Min + 1

	if Range > 0x100000000 then
		error(`Range must be at most 2^32, got {Range}`, 3)
	end

	if BufferPosition + 4 > BufferSize then
		GenerateBlock()
	end

	local Position = BufferPosition
	local Value = buffer.readu32(StreamBuffer, Position)
	BufferPosition = Position + 4

	if Range == 0x100000000 then
		return Min + Value
	end

	if bit32.band(Range, Range - 1) == 0 then
		return Min + bit32.band(Value, Range - 1)
	end

	local Limit = MAX_UINT32 - (MAX_UINT32 % Range)
	while Value >= Limit do
		if BufferPosition + 4 > BufferSize then
			GenerateBlock()
		end
		Position = BufferPosition
		Value = buffer.readu32(StreamBuffer, Position)
		BufferPosition = Position + 4
	end

	return Min + (Value % Range)
end

local function GetNumberRange(Min: number, Max: number): number
	if Min > Max then
		Min, Max = Max, Min
	end

	local Range = Max - Min
	if Range <= 0 then
		return Min
	end

	return Min + (GetFloat() * Range)
end

local function GetRandomString(Length: number, AsBuffer: boolean?): string | buffer
	local Characters = buffer.create(Length)

	for Index = 0, Length - 1 do
		buffer.writeu8(Characters, Index, GetIntRange(36, 122))
	end

	return if AsBuffer
		then Characters
		else buffer.tostring(Characters)
end

CSPRNG.Random = GetFloat

function CSPRNG.RandomInt(Min: number, Max: number?): number
	if Max and type(Max) ~= "number" then
		error(`Max must be a number or nil, got {typeof(Max)}`, 2)
	end

	if type(Min) ~= "number" then
		error(`Min must be a number, got {typeof(Min)}`, 2)
	end

	if Max and Max < Min then
		error(`Max ({Max}) can't be less than Min ({Min})`, 2)
	end

	if Max and Max == Min then
		error(`Max ({Max}) can't be equal to Min ({Min})`, 2)
	end

	if Min % 1 ~= 0 then
		error(`Min must be an integer, got {Min}`, 2)
	end

	if Max and Max % 1 ~= 0 then
		error(`Max must be an integer, got {Max}`, 2)
	end

	local ActualMax: number
	local ActualMin: number

	if Max == nil then
		ActualMax = Min
		ActualMin = 1
	else
		ActualMax = Max
		ActualMin = Min
	end

	return GetIntRange(ActualMin, ActualMax)
end

function CSPRNG.RandomNumber(Min: number, Max: number?): number
	if Max and type(Max) ~= "number" then
		error(`Max must be a number or nil, got {typeof(Max)}`, 2)
	end

	if type(Min) ~= "number" then
		error(`Min must be a number, got {typeof(Min)}`, 2)
	end

	if Max and Max < Min then
		error(`Max ({Max}) must be bigger than Min ({Min})`, 2)
	end

	if Max and Max == Min then
		error(`Max ({Max}) can't be equal to Min ({Min})`, 2)
	end

	local ActualMax: number
	local ActualMin: number

	if Max == nil then
		ActualMax = Min
		ActualMin = 0
	else
		ActualMax = Max
		ActualMin = Min
	end

	return GetNumberRange(ActualMin, ActualMax)
end

function CSPRNG.RandomBytes(Count: number): buffer
	if type(Count) ~= "number" then
		error(`Count must be a number, got {typeof(Count)}`, 2)
	end

	if Count <= 0 then
		error(`Count must be bigger than 0, got {Count}`, 2)
	end

	if Count % 1 ~= 0 then
		error("Count must be an integer", 2)
	end

	return GetBytes(Count)
end

function CSPRNG.RandomString(Length: number, AsBuffer: boolean?): string | buffer
	if type(Length) ~= "number" then
		error(`Length must be a number, got {typeof(Length)}`, 2)
	end

	if Length <= 0 then
		error(`Length must be bigger than 0, got {Length}`, 2)
	end

	if Length % 1 ~= 0 then
		error("Length must be an integer", 2)
	end

	if AsBuffer ~= nil and type(AsBuffer) ~= "boolean" then
		error(`AsBuffer must be a boolean or nil, got {typeof(AsBuffer)}`, 2)
	end

	return GetRandomString(Length, AsBuffer)
end

function CSPRNG.RandomHex(Length: number): string
	if type(Length) ~= "number" then
		error(`Length must be a number, got {typeof(Length)}`, 2)
	end

	if Length <= 0 then
		error(`Length must be bigger than 0, got {Length}`, 2)
	end

	if Length % 1 ~= 0 then
		error("Length must be an integer", 2)
	end

	if Length % 2 ~= 0 then
		error(`Length must be even, got {Length}`, 2)
	end

	return ToHex(GetBytes(Length / 2))
end

function CSPRNG.AddEntropy(Entropy: buffer?)
	if Entropy ~= nil and type(Entropy) ~= "buffer" then
		error(`Entropy must be a buffer or nil, got {typeof(Entropy)}`, 2)
	end

	GatherEntropy(Entropy)
	GenerateBlock()
end

GatherEntropy()
GenerateBlock()

return CSPRNG