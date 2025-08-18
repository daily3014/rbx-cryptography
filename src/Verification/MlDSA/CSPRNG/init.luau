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
		
		local Ed25519Bytes = CSPRNG.Ed25519RandomBytes()
		local Ed25519Clamped = CSPRNG.Ed25519ClampedBytes(SomeBuffer)
		local Ed25519Random = CSPRNG.Ed25519Random()
		
		CSPRNG.Reseed()
--]=]

--!native
--!optimize 2
--!strict

local SHA256 = require("@self/SHA256")
local Conversions = require("@self/Conversions")
local ChaCha20 = require("@self/ChaCha20")
local Blake3 = require("@self/Blake3")

type CSPRNGClass = {
	__index: CSPRNGClass,
	
	New: () -> CSPRNGInstance,
	
	GatherEntropy: (self: CSPRNGInstance, CustomEntropy: buffer?) -> (),
	GenerateBlock: (self: CSPRNGInstance) -> (),
	
	ReKey: (self: CSPRNGInstance) -> (),
	Reset: (self: CSPRNGInstance) -> (),
	
	GetBytes: (self: CSPRNGInstance, Count: number) -> buffer,
	GetUInt32: (self: CSPRNGInstance) -> number,
	GetFloat: (self: CSPRNGInstance) -> number,
	GetIntRange: (self: CSPRNGInstance, Min: number, Max: number) -> number,
	GetNumberRange: (self: CSPRNGInstance, Min: number, Max: number) -> number,
	GetRandomString: (self: CSPRNGInstance, Length: number, AsBuffer: boolean?) -> string | buffer,
	GetEd25519RandomBytes: (self: CSPRNGInstance) -> buffer,
	GetEd25519ClampedBytes: (self: CSPRNGInstance, Input: buffer) -> buffer,
	GetEd25519Random: (self: CSPRNGInstance) -> buffer,
	GetHexString: (self: CSPRNGInstance, Length: number) -> string,
}

type CSPRNGInstance = typeof(setmetatable({} :: {
	Key: buffer,
	Nonce: buffer,
	Counter: number,
	Buffer: buffer,
	BufferPosition: number,
	BufferSize: number,
}, {} :: CSPRNGClass))

type CSPRNGModule = {
	Instance: CSPRNGInstance,
	New: () -> CSPRNGInstance,
	Test: () -> boolean?,
	
	BlockExpansion: boolean,
	SizeTarget: number,
	RekeyAfter: number,
	
	Reseed: (CustomEntropy: buffer?) -> (),
	
	Random: () -> number,
	RandomInt: (Min: number, Max: number?) -> number,
	RandomNumber: (Min: number, Max: number?) -> number,
	RandomBytes: (Count: number) -> buffer,
	RandomString: (Length: number, AsBuffer: boolean?) -> string | buffer,
	RandomHex: (Length: number) -> string,
	Ed25519RandomBytes: () -> buffer,
	Ed25519ClampedBytes: (Input: buffer) -> buffer,
	Ed25519Random: () -> buffer,
}

local CSPRNG: CSPRNGModule = {
	BlockExpansion = false,
	SizeTarget = 2048,
	RekeyAfter = 1024
} :: CSPRNGModule

local CSPRNGClass = {} :: CSPRNGClass
CSPRNGClass.__index = CSPRNGClass

local BLOCK_SIZE = 64
local KEY_SIZE = 32
local NONCE_SIZE = 12

function CSPRNGClass:Reset()
	self.Key = buffer.create(0)
	self.Nonce = buffer.create(0)
	self.Counter = 0
	self.Buffer = buffer.create(0)
	self.BufferPosition = 0
	self.BufferSize = 0
end

function CSPRNGClass.New(): CSPRNGInstance
	local self = setmetatable({
		Key = buffer.create(0),
		Nonce = buffer.create(0),
		Counter = 0,
		Buffer = buffer.create(0),
		BufferPosition = 0,
		BufferSize = 0,
	}, CSPRNGClass)

	self:GatherEntropy()
	self.Counter = 0
	self.Buffer = buffer.create(0)
	self.BufferPosition = 0
	self.BufferSize = 0
	self:GenerateBlock()

	self:GetBytes(32)

	return self
end

function CSPRNGClass:GatherEntropy(CustomEntropy: buffer?): ()
	local EntropyBuffers = buffer.create(1024)
	local Offset = 0

	local function WriteToBuffer(Source: buffer): ()
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

	local FracTimeBuffer = buffer.create(16)
	buffer.writef32(FracTimeBuffer, 0, ClockTime / 100)
	buffer.writef32(FracTimeBuffer, 4, CurrentTime / 1000)
	buffer.writef32(FracTimeBuffer, 8, (ClockTime * 12345.6789) % 1)
	buffer.writef32(FracTimeBuffer, 12, (CurrentTime * 98765.4321) % 1)
	WriteToBuffer(FracTimeBuffer)

	local NoiseBuffer = buffer.create(32)
	for Index = 0, 7 do
		local Noise1 = math.noise(ClockTime + Index, UnixTime + Index, ClockTime + UnixTime + Index)
		local Noise2 = math.noise(CurrentTime + Index * 0.1, DateTimeMillis * 0.0001 + Index, ClockTime * 1.5 + Index)
		local Noise3 = math.noise(UnixTime * 0.01 + Index, ClockTime + DateTimeMillis * 0.001, CurrentTime + Index * 2)
		local Noise4 = math.noise(DateTimeMillis * 0.00001 + Index, UnixTime + ClockTime + Index, CurrentTime * 0.1 + Index)

		buffer.writef32(NoiseBuffer, Index * 4, Noise1 + Noise2 + Noise3 + Noise4)
	end
	WriteToBuffer(NoiseBuffer)

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

	local MicroTime = math.floor(CurrentTime * 1000000)
	local MicroTimeBuffer = buffer.create(8)
	buffer.writeu32(MicroTimeBuffer, 0, MicroTime % 0x100000000)
	buffer.writeu32(MicroTimeBuffer, 4, math.floor(MicroTime / 0x100000000))
	WriteToBuffer(MicroTimeBuffer)

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

	local AddressEntropy = buffer.create(128)
	for Index = 0, 7 do
		local TempTable = {}
		local TempFunc = function() end
		local TempBuffer = buffer.create(0)
		local TempUserdata = newproxy()

		local TableAddr = string.gsub(tostring(TempTable), "table: ", "")
		local FuncAddr = string.gsub(tostring(TempFunc), "function: ", "")
		local BufferAddr = string.gsub(tostring(TempBuffer), "buffer: ", "")
		local UserdataAddr = string.gsub(tostring(TempUserdata), "userdata: ", "")

		local TableHash = 0
		local ThreadHash = 0
		local FuncHash = 0
		local BufferHash = 0
		local UserdataHash = 0

		for AddrIndex = 1, #TableAddr do
			TableHash = bit32.bxor(TableHash, string.byte(TableAddr, AddrIndex)) * 31
		end
		
		if coroutine then
			local ThreadAddr = string.gsub(tostring(coroutine.create(function() end)), "thread: ", "")
			for AddrIndex = 1, #ThreadAddr do
				ThreadHash = bit32.bxor(ThreadHash, string.byte(ThreadAddr, AddrIndex)) * 31
			end
		end
		
		for AddrIndex = 1, #FuncAddr do
			FuncHash = bit32.bxor(FuncHash, string.byte(FuncAddr, AddrIndex)) * 37
		end
		for AddrIndex = 1, #BufferAddr do
			BufferHash = bit32.bxor(BufferHash, string.byte(BufferAddr, AddrIndex)) * 41
		end
		for AddrIndex = 1, #UserdataAddr do
			UserdataHash = bit32.bxor(UserdataHash, string.byte(UserdataAddr, AddrIndex)) * 43
		end

		buffer.writeu32(AddressEntropy, Index * 16, TableHash)
		buffer.writeu32(AddressEntropy, Index * 16 + 4, ThreadHash)
		buffer.writeu32(AddressEntropy, Index * 16 + 8, FuncHash)
		buffer.writeu32(AddressEntropy, Index * 16 + 12, bit32.bxor(BufferHash, UserdataHash))
	end
	WriteToBuffer(AddressEntropy)
	
	if CustomEntropy then
		local BytesLeft = 1024 - Offset
		if BytesLeft > 0 then
			buffer.copy(EntropyBuffers, Offset, CustomEntropy, 0, math.min(BytesLeft, buffer.len(CustomEntropy)))
		end
	end

	local EntropyHash = SHA256(EntropyBuffers)
	local EntropyHashBuffer = Conversions.FromHex(EntropyHash)

	local KeySeed = buffer.readu32(EntropyHashBuffer, 28)
	local KeyMaterial = buffer.create(KEY_SIZE + NONCE_SIZE)
	for Index = 0, (KEY_SIZE + NONCE_SIZE) - 4, 4 do
		KeySeed *= 1664525 + 1013904223
		buffer.writeu32(KeyMaterial, Index, KeySeed)
	end

	self.Key = buffer.create(KEY_SIZE)
	buffer.copy(self.Key, 0, KeyMaterial, 0, KEY_SIZE)

	self.Nonce = buffer.create(NONCE_SIZE)
	buffer.copy(self.Nonce, 0, KeyMaterial, KEY_SIZE, NONCE_SIZE)
end

function CSPRNGClass:GenerateBlock(): ()
	local InputBuffer = buffer.create(BLOCK_SIZE)
	local ChaChaOutput = ChaCha20(InputBuffer, self.Key, self.Nonce, self.Counter, 20)
	
	if CSPRNG.BlockExpansion then
		self.Buffer = Blake3(ChaChaOutput, math.clamp(math.floor(CSPRNG.SizeTarget), 64, 2^32 - 1))
	else
		self.Buffer = ChaChaOutput
	end
	
	self.BufferPosition = 0
	self.BufferSize = buffer.len(self.Buffer)

	self.Counter += 1
	if self.Counter % math.max(math.floor(CSPRNG.RekeyAfter), 2) == 0 then
		self:ReKey()
	end
end

function CSPRNGClass:ReKey(): ()
	local NewKeyMaterial = buffer.create(KEY_SIZE + NONCE_SIZE)
	local RandomData = self:GetBytes(KEY_SIZE + NONCE_SIZE)
	buffer.copy(NewKeyMaterial, 0, RandomData, 0, KEY_SIZE + NONCE_SIZE)

	local HashedMaterial = SHA256(NewKeyMaterial)
	local HashedBuffer = Conversions.FromHex(HashedMaterial)

	buffer.copy(self.Key, 0, HashedBuffer, 0, KEY_SIZE)
	self:GatherEntropy()
	self.Counter = 0
end

function CSPRNGClass:GetBytes(Count: number): buffer
	local Result = buffer.create(Count)
	local ResultPosition = 0

	local MaxChunks = math.ceil(Count / BLOCK_SIZE) + 1

	for Chunk = 1, MaxChunks do
		if ResultPosition >= Count then
			break
		end

		if self.BufferPosition >= self.BufferSize then
			self:GenerateBlock()
		end

		local BytesNeeded = Count - ResultPosition
		local BytesAvailable = self.BufferSize - self.BufferPosition
		local BytesToCopy = math.min(BytesNeeded, BytesAvailable)

		buffer.copy(Result, ResultPosition, self.Buffer, self.BufferPosition, BytesToCopy)

		ResultPosition += BytesToCopy
		self.BufferPosition += BytesToCopy
	end

	return Result
end

function CSPRNGClass:GetUInt32(): number
	local Bytes: buffer = self:GetBytes(4)
	return buffer.readu32(Bytes, 0)
end

function CSPRNGClass:GetFloat(): number
	local Value1 = self:GetUInt32()
	local Value2 = self:GetUInt32()

	local High = bit32.rshift(Value1, 5)
	local Low = bit32.rshift(Value2, 6)

	return (High * 67108864.0 + Low) / 9007199254740992.0
end

function CSPRNGClass:GetIntRange(Min: number, Max: number): number
	if Min > Max then
		Min, Max = Max, Min
	end

	local Range: number = Max - Min + 1
	if Range <= 0 then
		return Min
	end

	if Range <= 256 then
		local Value = self:GetUInt32()
		return Min + (Value % Range)
	end

	local MaxValid = math.floor(0x100000000 / Range) * Range - 1

	for Attempt = 1, 16 do
		local Value = self:GetUInt32()
		if Value <= MaxValid then
			return Min + (Value % Range)
		end
	end

	local FallbackValue = self:GetUInt32()
	return Min + (FallbackValue % Range)
end

function CSPRNGClass:GetNumberRange(Min: number, Max: number): number
	if Min > Max then
		Min, Max = Max, Min
	end

	local Range = Max - Min
	if Range <= 0 then
		return Min
	end

	return Min + (self:GetFloat() * Range)
end

function CSPRNGClass:GetRandomString(Length: number, AsBuffer: boolean?): string | buffer
	local FixedLength = if Length % 4 ~= 0 then Length + (4 - Length % 4) else Length

	local Characters = buffer.create(FixedLength)
	local Packs = bit32.rshift(FixedLength, 2)

	for Index = 0, Packs * 4 - 1, 4 do
		local U32 = bit32.bor(
			bit32.lshift(self:GetIntRange(36, 122), 0),
			bit32.lshift(self:GetIntRange(36, 122), 8),
			bit32.lshift(self:GetIntRange(36, 122), 16),
			bit32.lshift(self:GetIntRange(36, 122), 24)
		)
		buffer.writeu32(Characters, Index, U32)
	end

	if AsBuffer then
		if FixedLength == Length then
			return Characters
		end

		local Buf = buffer.create(Length)
		buffer.copy(Buf, 0, Characters, 0, Length)
		return Buf
	end

	return buffer.readstring(Characters, 0, Length)
end

function CSPRNGClass:GetEd25519RandomBytes(): buffer
	local Output = buffer.create(32)
	for Index = 0, 31, 4 do
		buffer.writeu32(Output, Index, bit32.bor(
			bit32.lshift(self:GetIntRange(0, 255), 0),
			bit32.lshift(self:GetIntRange(0, 255), 8),
			bit32.lshift(self:GetIntRange(0, 255), 16),
			bit32.lshift(self:GetIntRange(0, 255), 24)
			))
	end

	return Output
end

function CSPRNGClass:GetEd25519ClampedBytes(Input: buffer): buffer
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

function CSPRNGClass:GetEd25519Random(): buffer
	return self:GetEd25519ClampedBytes(self:GetEd25519RandomBytes())
end

function CSPRNGClass:GetHexString(Length)
	local BytesNeeded = Length / 2
	local Bytes = self:GetBytes(BytesNeeded)
	local Hex = Conversions.ToHex(Bytes)

	return Hex
end

CSPRNG.Instance = CSPRNGClass.New()

function CSPRNG.Random(): number
	return CSPRNG.Instance:GetFloat()
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

	return CSPRNG.Instance:GetIntRange(ActualMin, ActualMax)
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

	return CSPRNG.Instance:GetNumberRange(ActualMin, ActualMax)
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
	
	return CSPRNG.Instance:GetBytes(Count)
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
	
	return CSPRNG.Instance:GetRandomString(Length, AsBuffer)
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
	
	return CSPRNG.Instance:GetHexString(Length)
end

function CSPRNG.Ed25519RandomBytes(): buffer
	return CSPRNG.Instance:GetEd25519RandomBytes()
end

function CSPRNG.Ed25519ClampedBytes(Input: buffer): buffer
	if type(Input) ~= "buffer" then
		error(`Input must be a buffer, got {typeof(Input)}`, 2)
	end
	
	return CSPRNG.Instance:GetEd25519ClampedBytes(Input)
end

function CSPRNG.Ed25519Random(): buffer
	return CSPRNG.Instance:GetEd25519Random()
end

function CSPRNG.Reseed(CustomEntropy: buffer?): ()
	if CustomEntropy ~= nil and type(CustomEntropy) ~= "buffer" then
		error(`CustomEntropy must be a buffer or nil, got {typeof(CustomEntropy)}`, 2)
	end
	
	CSPRNG.Instance:Reset()
	CSPRNG.Instance:GatherEntropy(CustomEntropy)
end

CSPRNG.New = CSPRNGClass.New

return CSPRNG