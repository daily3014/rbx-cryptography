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
		
		local Ed25519Clamped = CSPRNG.Ed25519ClampedBytes(SomeBuffer)
		local Ed25519Random = CSPRNG.Ed25519Random()
		
		CSPRNG.AddEntropyProvider(function)
		CSPRNG.RemoveEntropyProvider(function)
		CSPRNG.Reseed()
		
		CSPRNG.BytesLeft
--]=]

--!strict
--!optimize 2
--!native

local Blake3 = require("@self/Blake3")

local HEX_ENCODE_LOOKUP = buffer.create(256 * 2) do
	local HexChars = "0123456789abcdef"
	for Byte = 0, 255 do
		local HighChar = string.byte(HexChars, bit32.rshift(Byte, 4) + 1)
		local LowChar = string.byte(HexChars, Byte % 16 + 1)
		buffer.writeu16(HEX_ENCODE_LOOKUP, Byte * 2, HighChar + bit32.lshift(LowChar, 8))
	end
end

local function ToHex(Buffer: buffer): string
	local Length = buffer.len(Buffer)
	local Hex = buffer.create(Length * 2)
	local Lookup = HEX_ENCODE_LOOKUP
	local Leftover = Length % 8
	local HexCursor = 0

	for Index = 0, Length - Leftover - 1, 8 do
		buffer.writeu16(Hex, HexCursor,      buffer.readu16(Lookup, buffer.readu8(Buffer, Index) * 2))
		buffer.writeu16(Hex, HexCursor + 2,  buffer.readu16(Lookup, buffer.readu8(Buffer, Index + 1) * 2))
		buffer.writeu16(Hex, HexCursor + 4,  buffer.readu16(Lookup, buffer.readu8(Buffer, Index + 2) * 2))
		buffer.writeu16(Hex, HexCursor + 6,  buffer.readu16(Lookup, buffer.readu8(Buffer, Index + 3) * 2))
		buffer.writeu16(Hex, HexCursor + 8,  buffer.readu16(Lookup, buffer.readu8(Buffer, Index + 4) * 2))
		buffer.writeu16(Hex, HexCursor + 10, buffer.readu16(Lookup, buffer.readu8(Buffer, Index + 5) * 2))
		buffer.writeu16(Hex, HexCursor + 12, buffer.readu16(Lookup, buffer.readu8(Buffer, Index + 6) * 2))
		buffer.writeu16(Hex, HexCursor + 14, buffer.readu16(Lookup, buffer.readu8(Buffer, Index + 7) * 2))
		HexCursor += 16
	end

	for Index = Length - Leftover, Length - 1 do
		buffer.writeu16(Hex, HexCursor, buffer.readu16(Lookup, buffer.readu8(Buffer, Index) * 2))
		HexCursor += 2
	end

	return buffer.tostring(Hex)
end

export type EntropyProvider = (BytesLeft: number) -> buffer?

type CSPRNGModule = {
	BlockExpansion: boolean,

	SizeTarget: number,
	RekeyAfter: number,

	Key: buffer,
	Nonce: buffer,
	Buffer: buffer,

	Counter: number,
	BufferPosition: number,
	BufferSize: number,
	BytesLeft: number,

	EntropyProviders: { EntropyProvider },

	Reseed: (CustomEntropy: buffer?) -> (),
	AddEntropyProvider: (ProviderFunction: EntropyProvider) -> (),
	RemoveEntropyProvider: (ProviderFunction: EntropyProvider) -> (),

	Random: () -> number,
	RandomInt: (Min: number, Max: number?) -> number,
	RandomNumber: (Min: number, Max: number?) -> number,
	RandomBytes: (Count: number) -> buffer,
	RandomString: (Length: number, AsBuffer: boolean?) -> string | buffer,
	RandomHex: (Length: number) -> string,
	Ed25519ClampedBytes: (Input: buffer) -> buffer,
	Ed25519Random: () -> buffer,
}

local BLOCK_SIZE = 64
local KEY_SIZE = 32
local NONCE_SIZE = 12

local CSPRNG: CSPRNGModule = {
	BlockExpansion = true,
	SizeTarget = 2048,
	RekeyAfter = 1024,

	Key = buffer.create(0),
	Nonce = buffer.create(0),
	Buffer = buffer.create(0),

	Counter = 0,
	BufferPosition = 0,
	BufferSize = 0,
	BytesLeft = 0,

	EntropyProviders = {}
} :: CSPRNGModule

local INPUT_BUFFER = buffer.create(KEY_SIZE + NONCE_SIZE + 8)

local function Reset()
	CSPRNG.Key = buffer.create(0)
	CSPRNG.Nonce = buffer.create(0)
	CSPRNG.Buffer = buffer.create(0)

	CSPRNG.Counter = 0
	CSPRNG.BufferPosition = 0
	CSPRNG.BufferSize = 0
end

local function GatherEntropy(CustomEntropy: buffer?): number
	local EntropyBuffers = buffer.create(1024)
	local Offset = 0

	local function WriteToBuffer(Source: buffer)
		local Size = buffer.len(Source)
		buffer.copy(EntropyBuffers, Offset, Source, 0, Size)
		Offset += Size
	end

	local CurrentTime = 1.234
	if tick then
		CurrentTime = tick()
		local TimeBuffer = buffer.create(8)
		buffer.writef64(TimeBuffer, 0, CurrentTime)
		WriteToBuffer(TimeBuffer)
	end

	local ClockTime = os.clock()
	local ClockBuffer = buffer.create(8)
	buffer.writef64(ClockBuffer, 0, ClockTime)
	WriteToBuffer(ClockBuffer)

	local UnixTime = os.time()
	local UnixBuffer = buffer.create(8)
	buffer.writeu32(UnixBuffer, 0, UnixTime % 0x100000000)
	buffer.writeu32(UnixBuffer, 4, math.floor(UnixTime / 0x100000000))
	WriteToBuffer(UnixBuffer)

	local DateTimeMillis = 5.678
	if DateTime then
		DateTimeMillis = DateTime.now().UnixTimestampMillis
		local DateTimeBuffer = buffer.create(8)
		buffer.writef64(DateTimeBuffer, 0, DateTimeMillis)
		WriteToBuffer(DateTimeBuffer)

		local DateTimePrecisionBuffer = buffer.create(16)
		buffer.writef32(DateTimePrecisionBuffer, 0, DateTimeMillis / 1000)
		buffer.writef32(DateTimePrecisionBuffer, 4, (DateTimeMillis % 1000) / 100)
		buffer.writef32(DateTimePrecisionBuffer, 8, DateTimeMillis / 86400000)
		buffer.writef32(DateTimePrecisionBuffer, 12, (DateTimeMillis * 0.001) % 1)
		WriteToBuffer(DateTimePrecisionBuffer)
	else
		WriteToBuffer(buffer.create(24))
	end

	local BenchmarkTimings = buffer.create(32)
	for Index = 0, 7 do
		local StartTime = os.clock()
		local Sum = 0

		local Iterations = 50 + (Index * 25)
		for Iteration = 1, Iterations do
			Sum += Iteration * Iteration + math.sin(Iteration / 10) * math.cos(Iteration / 7)
		end

		local EndTime = os.clock()
		local TimingDelta = EndTime - StartTime
		buffer.writef32(BenchmarkTimings, Index * 4, TimingDelta * 1000000)
	end
	WriteToBuffer(BenchmarkTimings)

	local AllocTimings = buffer.create(24)
	for Index = 0, 5 do
		local AllocStart = os.clock()

		for AllocIndex = 1, 20 do
			local _TempBuf = buffer.create(64 + AllocIndex)
		end

		local AllocEnd = os.clock()
		buffer.writef32(AllocTimings, Index * 4, (AllocEnd - AllocStart) * 10000000)
	end
	WriteToBuffer(AllocTimings)

	if game then
		if game.JobId and #game.JobId > 0 then
			local JobIdBuffer = buffer.fromstring(game.JobId)
			WriteToBuffer(JobIdBuffer)
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

			local DistMicroTime = math.floor(workspace.DistributedGameTime * 1000000)
			local DistMicroBuffer = buffer.create(8)
			buffer.writeu32(DistMicroBuffer, 0, DistMicroTime % 0x100000000)
			buffer.writeu32(DistMicroBuffer, 4, math.floor(DistMicroTime / 0x100000000))
			WriteToBuffer(DistMicroBuffer)
		end
	end

	local AddressBuffer = buffer.create(2048)
	local AddressOffset = 0

	for Index = 1, 8 do
		local TableStr = tostring({})
		buffer.writestring(AddressBuffer, AddressOffset, TableStr)
		AddressOffset += #TableStr

		local FuncStr = tostring(function() end)
		buffer.writestring(AddressBuffer, AddressOffset, FuncStr)
		AddressOffset += #FuncStr

		local BufferStr = tostring(buffer.create(0))
		buffer.writestring(AddressBuffer, AddressOffset, BufferStr)
		AddressOffset += #BufferStr

		local UserdataStr = tostring(newproxy())
		buffer.writestring(AddressBuffer, AddressOffset, UserdataStr)
		AddressOffset += #UserdataStr

		if coroutine then
			local ThreadStr = tostring(coroutine.create(function() end))
			buffer.writestring(AddressBuffer, AddressOffset, ThreadStr)
			AddressOffset += #ThreadStr
		end
	end

	local AddressDigest = Blake3(AddressBuffer, 32)
	WriteToBuffer(AddressDigest)

	local function AddExtraEntropy(Entropy: buffer?, Warn: boolean, Provider: string?)
		if not Entropy then
			return
		end

		local BytesLeft = 1024 - Offset

		if BytesLeft > 0 then
			local Extra = buffer.len(Entropy) - BytesLeft
			local Truncated = math.min(BytesLeft, buffer.len(Entropy))

			if Extra > 0 and Warn and Provider then
				warn(`CSPRNG: {Provider} returned {Extra} bytes more than available and was truncated to {Truncated} bytes`)
			end

			buffer.copy(EntropyBuffers, Offset, Entropy, 0, Truncated)
		end
	end

	for Index, Provider in CSPRNG.EntropyProviders do
		local BytesLeft = 1024 - Offset
		if BytesLeft > 0 then
			local Success: boolean, ExtraEntropy: buffer? = pcall(Provider, BytesLeft)
			if not Success then
				warn(`CSPRNG Provider errored with {ExtraEntropy}`)
			end

			AddExtraEntropy(ExtraEntropy, true, `Entropy Provider #{Index}`)
		end
	end

	if CustomEntropy then
		AddExtraEntropy(CustomEntropy, false)
	end

	local KeyMaterial = Blake3(EntropyBuffers, KEY_SIZE + NONCE_SIZE)

	CSPRNG.Key = buffer.create(KEY_SIZE)
	buffer.copy(CSPRNG.Key, 0, KeyMaterial, 0, KEY_SIZE)

	CSPRNG.Nonce = buffer.create(NONCE_SIZE)
	buffer.copy(CSPRNG.Nonce, 0, KeyMaterial, KEY_SIZE, NONCE_SIZE)

	return buffer.len(EntropyBuffers) - Offset
end

local function GenerateBlock()
	local RekeyThreshold = math.max(math.floor(CSPRNG.RekeyAfter), 2)
	local OutputSize = if CSPRNG.BlockExpansion
		then math.clamp(math.floor(CSPRNG.SizeTarget), 64, 4294967295)
		else BLOCK_SIZE

	buffer.copy(INPUT_BUFFER, 0, CSPRNG.Key, 0, KEY_SIZE)
	buffer.copy(INPUT_BUFFER, KEY_SIZE, CSPRNG.Nonce, 0, NONCE_SIZE)
	buffer.writeu32(INPUT_BUFFER, KEY_SIZE + NONCE_SIZE, CSPRNG.Counter % 0x100000000)
	buffer.writeu32(INPUT_BUFFER, KEY_SIZE + NONCE_SIZE + 4, math.floor(CSPRNG.Counter / 0x100000000))

	CSPRNG.Buffer = Blake3(INPUT_BUFFER, OutputSize)
	CSPRNG.BufferPosition = 0
	CSPRNG.BufferSize = buffer.len(CSPRNG.Buffer)
	CSPRNG.Counter += 1

	if CSPRNG.Counter % RekeyThreshold == 0 then
		GatherEntropy()
		CSPRNG.Counter = 0
	end
end

local function GetBytes(Count: number): buffer
	local Result = buffer.create(Count)
	local ResultPosition = 0

	while ResultPosition < Count do
		if CSPRNG.BufferPosition >= CSPRNG.BufferSize then
			GenerateBlock()
		end

		local BytesNeeded = Count - ResultPosition
		local BytesAvailable = CSPRNG.BufferSize - CSPRNG.BufferPosition
		local BytesToCopy = math.min(BytesNeeded, BytesAvailable)

		buffer.copy(Result, ResultPosition, CSPRNG.Buffer, CSPRNG.BufferPosition, BytesToCopy)
		ResultPosition += BytesToCopy
		CSPRNG.BufferPosition += BytesToCopy
	end

	return Result
end

local function GetFloat(): number
	if CSPRNG.BufferPosition + 8 > CSPRNG.BufferSize then
		GenerateBlock()
	end

	local Value1 = buffer.readu32(CSPRNG.Buffer, CSPRNG.BufferPosition)
	local Value2 = buffer.readu32(CSPRNG.Buffer, CSPRNG.BufferPosition + 4)
	CSPRNG.BufferPosition += 8

	local High = bit32.rshift(Value1, 5)
	local Low = bit32.rshift(Value2, 6)

	return (High * 67108864.0 + Low) / 9007199254740992.0
end

local function GetIntRange(Min: number, Max: number): number
	local Range = Max - Min + 1
	local MaxUInt32 = 0xFFFFFFFF
	local Limit = MaxUInt32 - (MaxUInt32 % Range)

	if CSPRNG.BufferPosition + 4 > CSPRNG.BufferSize then
		GenerateBlock()
	end

	local Value = buffer.readu32(CSPRNG.Buffer, CSPRNG.BufferPosition)
	CSPRNG.BufferPosition += 4

	if bit32.band(Range, Range - 1) == 0 then
		return Min + bit32.band(Value, Range - 1)
	else
		while Value > Limit do
			if CSPRNG.BufferPosition + 4 > CSPRNG.BufferSize then
				GenerateBlock()
			end
			Value = buffer.readu32(CSPRNG.Buffer, CSPRNG.BufferPosition)
			CSPRNG.BufferPosition += 4
		end

		return Min + (Value % Range)
	end
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

local function GetEd25519RandomBytes(): buffer
	local Output = buffer.create(32)

	for Index = 0, 31 do
		buffer.writeu8(Output, Index, GetIntRange(0, 255))
	end

	return Output
end

local function GetEd25519ClampedBytes(Input: buffer): buffer
	local Output = buffer.create(32)
	buffer.copy(Output, 0, Input, 0, 32)

	local FirstByte = buffer.readu8(Output, 0)
	FirstByte = bit32.band(FirstByte, 0xF8)
	buffer.writeu8(Output, 0, FirstByte)

	local LastByte = buffer.readu8(Output, 31)
	LastByte = bit32.band(LastByte, 0x7F)
	LastByte = bit32.bor(LastByte, 0x40)
	buffer.writeu8(Output, 31, LastByte)

	local HasVariation = false
	local FirstMiddleByte = buffer.readu8(Output, 1)
	for Index = 2, 30 do
		if buffer.readu8(Output, Index) ~= FirstMiddleByte then
			HasVariation = true
			break
		end
	end

	if not HasVariation then
		buffer.writeu8(Output, 15, bit32.bxor(FirstMiddleByte, 0x55))
	end

	return Output
end

local function GetHexString(Length: number): string
	local BytesNeeded = Length / 2
	local Bytes = GetBytes(BytesNeeded)
	local Hex = ToHex(Bytes)

	return Hex
end

function CSPRNG.AddEntropyProvider(ProviderFunction: EntropyProvider)
	table.insert(CSPRNG.EntropyProviders, ProviderFunction)
end

function CSPRNG.RemoveEntropyProvider(ProviderFunction: EntropyProvider)
	for Index = #CSPRNG.EntropyProviders, 1, -1 do
		if CSPRNG.EntropyProviders[Index] == ProviderFunction then
			table.remove(CSPRNG.EntropyProviders, Index)
			break
		end
	end
end

function CSPRNG.Random(): number
	return GetFloat()
end

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

	return GetHexString(Length)
end

function CSPRNG.Ed25519ClampedBytes(Input: buffer): buffer
	if type(Input) ~= "buffer" then
		error(`Input must be a buffer, got {typeof(Input)}`, 2)
	end

	return GetEd25519ClampedBytes(Input)
end

function CSPRNG.Ed25519Random(): buffer
	return GetEd25519ClampedBytes(GetEd25519RandomBytes())
end

function CSPRNG.Reseed(CustomEntropy: buffer?)
	if CustomEntropy ~= nil and type(CustomEntropy) ~= "buffer" then
		error(`CustomEntropy must be a buffer or nil, got {typeof(CustomEntropy)}`, 2)
	end

	Reset()
	GatherEntropy(CustomEntropy)
end

CSPRNG.BytesLeft = GatherEntropy()
GenerateBlock()

return CSPRNG