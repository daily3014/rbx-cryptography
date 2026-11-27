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

local Blake3 = require("../Hashing/Blake3")
local Blake3Core = require("../Hashing/Blake3Core")
local Conversions = require("./Conversions")
local ToHex = Conversions.ToHex

type RandomStringSig =
	& ((Length: number, AsBuffer: false?) -> string)
	& ((Length: number, AsBuffer: true) -> buffer)
	& ((Length: number, AsBuffer: boolean) -> string | buffer)

type CSPRNGModule = {
	AddEntropy: (Entropy: buffer?) -> (),

	Random: () -> number,
	RandomInt: (Min: number, Max: number?) -> number,
	RandomNumber: (Min: number, Max: number?) -> number,
	RandomBytes: (Count: number) -> buffer,
	RandomHex: (Length: number) -> string,
	RandomString: RandomStringSig,
	MakeRandomString: (CharacterSet: string | buffer) -> RandomStringSig,
}

local KEY_SIZE = 32
local MAX_UINT32 = 0xFFFFFFFF
local TWO_POW_32 = 4294967296.0
local INV_2_32 = 2 ^ -32
local INV_2_53 = 2 ^ -53
local MAX_SAFE_INTEGER = 2 ^ 53
local LEMIRE_MAX_RANGE = 2097152

local POOL_BLOCKS = 64
local POOL_SIZE = POOL_BLOCKS * 64
local POS_OFFSET = POOL_SIZE
local REKEY_BLOCKS = 1024
local GUID_COUNT = 3
local JITTER_SAMPLES = 512
local SOURCE_LIMIT = 1024

local CSPRNG = {} :: CSPRNGModule

local KeystreamInto = Blake3Core.KeystreamInto

local STREAM: buffer = buffer.create(POOL_SIZE + 4)
local Key: buffer = buffer.create(KEY_SIZE)
local HasKey = false
local Counter = 0

local function GatherEntropy(UserEntropy: buffer?): ()
	local Sources = buffer.create(SOURCE_LIMIT)
	local Offset = 0

	local function WriteToBuffer(Source: buffer): ()
		local Size = buffer.len(Source)
		if Offset + Size > SOURCE_LIMIT then
			error("Exceeded the size of Sources, this is a bug!", 2)
		end

		buffer.copy(Sources, Offset, Source, 0, Size)
		Offset += Size
	end

	local HttpService = if game then game:GetService("HttpService") else nil
	if HttpService then
		for _ = 1, GUID_COUNT do
			WriteToBuffer(buffer.fromstring(HttpService:GenerateGUID(false)))
		end
	else
		local ClockBuffer = buffer.create(16)
		buffer.writef64(ClockBuffer, 0, os.clock())
		buffer.writef64(ClockBuffer, 8, os.time())
		WriteToBuffer(ClockBuffer)

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
			(warn or print)("CSPRNG: timing jitter appears degenerate (low-resolution clock); entropy may be weak")
		end

		WriteToBuffer(JitterSamples)

		local Pointers = tostring(newproxy())
		if coroutine then
			Pointers ..= tostring(coroutine.running())
		end
		WriteToBuffer(buffer.fromstring(Pointers))
	end

	local PreviousLength = if HasKey then KEY_SIZE else 0
	local UserLength = if UserEntropy then buffer.len(UserEntropy) else 0
	local Material = buffer.create(PreviousLength + Offset + UserLength)

	if HasKey then
		buffer.copy(Material, 0, Key, 0, KEY_SIZE)
	end
	buffer.copy(Material, PreviousLength, Sources, 0, Offset)
	if UserEntropy then
		buffer.copy(Material, PreviousLength + Offset, UserEntropy, 0, UserLength)
	end

	local KeyMaterial = Blake3.DigestBuffer(Material, KEY_SIZE)
	buffer.copy(Key, 0, KeyMaterial, 0, KEY_SIZE)
	HasKey = true

	buffer.fill(KeyMaterial, 0, 0)
	buffer.fill(Material, 0, 0)
	buffer.fill(Sources, 0, 0)

	Counter = 0
end

local function GenerateBlock(): ()
	if Counter >= REKEY_BLOCKS then
		GatherEntropy()
	end

	KeystreamInto(Key, STREAM, POOL_BLOCKS)
	buffer.writeu32(STREAM, POS_OFFSET, 0)
	Counter += 1
end

local function ArgumentError(Name: string, Value: any, Integer: boolean, Optional: boolean): string?
	if Value == nil then
		return if Optional then nil else `{Name} must be a number`
	end

	if type(Value) ~= "number" then
		return `{Name} must be a number, got {typeof(Value)}`
	end

	if not math.isfinite(Value) then
		local Type = if math.isnan(Value) then "NaN" else "inf"
		return `{Name} must be a finite number, got {Type}`
	end

	if Integer and Value % 1 ~= 0 then
		return `{Name} must be an integer, got {Value}`
	end

	return nil
end

@native
local function GetBytes(Count: number): buffer
	local Result = buffer.create(Count)
	local ResultPosition = 0
	local Pos = buffer.readu32(STREAM, POS_OFFSET)

	while ResultPosition < Count do
		if Pos >= POOL_SIZE then
			GenerateBlock()
			Pos = 0
		end

		local BytesToCopy = math.min(Count - ResultPosition, POOL_SIZE - Pos)
		buffer.copy(Result, ResultPosition, STREAM, Pos, BytesToCopy)
		ResultPosition += BytesToCopy
		Pos += BytesToCopy
	end

	buffer.writeu32(STREAM, POS_OFFSET, Pos)
	return Result
end

@native
local function GetFloat(): number
	local Pos = buffer.readu32(STREAM, POS_OFFSET)
	if Pos > POOL_SIZE - 8 then
		GenerateBlock()
		Pos = 0
	end

	local Value1 = buffer.readu32(STREAM, Pos)
	local Value2 = buffer.readu32(STREAM, Pos + 4)
	buffer.writeu32(STREAM, POS_OFFSET, Pos + 8)

	return Value1 * INV_2_32 + bit32.rshift(Value2, 11) * INV_2_53
end

@native
local function GetLargeIntRange(Min: number, Range: number): number
	if Range > TWO_POW_32 then
		error(`Range must be at most 2^32, got {Range}`, 3)
	end

	local Pos = buffer.readu32(STREAM, POS_OFFSET)
	if Pos > POOL_SIZE - 4 then
		GenerateBlock()
		Pos = 0
	end

	local Value = buffer.readu32(STREAM, Pos)
	Pos += 4

	if Range == TWO_POW_32 then
		buffer.writeu32(STREAM, POS_OFFSET, Pos)
		return Min + Value
	end

	if not bit32.btest(Range, Range - 1) then
		buffer.writeu32(STREAM, POS_OFFSET, Pos)
		return Min + bit32.band(Value, Range - 1)
	end

	local Limit = MAX_UINT32 - (MAX_UINT32 % Range)
	while Value >= Limit do
		if Pos > POOL_SIZE - 4 then
			GenerateBlock()
			Pos = 0
		end
		Value = buffer.readu32(STREAM, Pos)
		Pos += 4
	end

	buffer.writeu32(STREAM, POS_OFFSET, Pos)
	return Min + (Value % Range)
end

local function RetryNumberRange(Min: number, Max: number, Range: number): number
	local Value: number

	if Range == math.huge then
		local HalfMin = Min * 0.5
		local HalfRange = Max * 0.5 - HalfMin
		repeat
			Value = (HalfMin + GetFloat() * HalfRange) * 2
		until Value < Max
	else
		repeat
			Value = Min + (GetFloat() * Range)
		until Value < Max
	end

	return Value
end

@native
local function GetRandomString(Length: number, CharacterSet: buffer?, AsBuffer: boolean?): string | buffer
	local Characters = buffer.create(Length)
	local Pos = buffer.readu32(STREAM, POS_OFFSET)

	if CharacterSet then
		local SetLen = buffer.len(CharacterSet)
		if SetLen == 1 then
			buffer.fill(Characters, 0, buffer.readu8(CharacterSet, 0), Length)
			return if AsBuffer then Characters else buffer.tostring(Characters)
		end

		if SetLen <= 65535 then
			local Threshold = 65536 % SetLen
			for Index = 0, Length - 1 do
				if Pos > POOL_SIZE - 2 then
					GenerateBlock()
					Pos = 0
				end
				local Prod = buffer.readu16(STREAM, Pos) * SetLen
				Pos += 2
				local Low = bit32.band(Prod, 0xFFFF)
				if Low < SetLen then
					while Low < Threshold do
						if Pos > POOL_SIZE - 2 then
							GenerateBlock()
							Pos = 0
						end
						Prod = buffer.readu16(STREAM, Pos) * SetLen
						Pos += 2
						Low = bit32.band(Prod, 0xFFFF)
					end
				end
				buffer.writeu8(Characters, Index, buffer.readu8(CharacterSet, bit32.rshift(Prod, 16)))
			end
		else
			for Index = 0, Length - 1 do
				buffer.writeu32(STREAM, POS_OFFSET, Pos)
				local Pick = GetLargeIntRange(0, SetLen)
				Pos = buffer.readu32(STREAM, POS_OFFSET)
				buffer.writeu8(Characters, Index, buffer.readu8(CharacterSet, Pick))
			end
		end
	else
		for Index = 0, Length - 1 do
			if Pos > POOL_SIZE - 2 then
				GenerateBlock()
				Pos = 0
			end
			local Prod = buffer.readu16(STREAM, Pos) * 87
			Pos += 2
			local Low = bit32.band(Prod, 0xFFFF)
			if Low < 87 then
				while Low < 25 do
					if Pos > POOL_SIZE - 2 then
						GenerateBlock()
						Pos = 0
					end
					Prod = buffer.readu16(STREAM, Pos) * 87
					Pos += 2
					Low = bit32.band(Prod, 0xFFFF)
				end
			end
			buffer.writeu8(Characters, Index, 36 + bit32.rshift(Prod, 16))
		end
	end

	buffer.writeu32(STREAM, POS_OFFSET, Pos)
	return if AsBuffer then Characters else buffer.tostring(Characters)
end

CSPRNG.Random = GetFloat

@native
function CSPRNG.RandomInt(Min: number, Max: number?): number
	local ActualMin: number
	local Range: number

	if Max ~= nil then
		if not (type(Min) == "number" and type(Max) == "number" and Min >= -MAX_SAFE_INTEGER and Max <= MAX_SAFE_INTEGER and Max > Min and math.floor(Min) == Min and math.floor(Max) == Max) then
			local Problem = ArgumentError("Min", Min, true, false) or ArgumentError("Max", Max, true, true)
			if Problem then
				error(Problem, 2)
			end

			if Min < -MAX_SAFE_INTEGER or Min > MAX_SAFE_INTEGER or Max < -MAX_SAFE_INTEGER or Max > MAX_SAFE_INTEGER then
				error("Min and Max must be between -2^53 and 2^53", 2)
			end

			if Max < Min then
				error(`Max ({Max}) can't be less than Min ({Min})`, 2)
			end

			if Max == Min then
				error(`Max ({Max}) can't be equal to Min ({Min})`, 2)
			end

			error("Invalid RandomInt arguments", 2)
		end

		ActualMin = Min
		Range = Max - Min + 1
	else
		if not (type(Min) == "number" and Min >= 1 and Min <= MAX_SAFE_INTEGER and math.floor(Min) == Min) then
			local Problem = ArgumentError("Min", Min, true, false)
			if Problem then
				error(Problem, 2)
			end

			if Min < -MAX_SAFE_INTEGER or Min > MAX_SAFE_INTEGER then
				error("Min and Max must be between -2^53 and 2^53", 2)
			end

			if Min < 1 then
				error(`When passing one argument, Min must be at least 1, got {Min}`, 2)
			end

			error("Invalid RandomInt arguments", 2)
		end

		ActualMin = 1
		Range = Min
	end

	if Range > LEMIRE_MAX_RANGE then
		return GetLargeIntRange(ActualMin, Range)
	end

	local Pos = buffer.readu32(STREAM, POS_OFFSET)
	if Pos > POOL_SIZE - 4 then
		GenerateBlock()
		Pos = 0
	end

	local Prod = buffer.readu32(STREAM, Pos) * Range
	Pos += 4
	local Result = math.floor(Prod * INV_2_32)
	local Low = Prod - Result * TWO_POW_32

	if Low < Range then
		local Threshold = TWO_POW_32 % Range
		while Low < Threshold do
			if Pos > POOL_SIZE - 4 then
				GenerateBlock()
				Pos = 0
			end
			Prod = buffer.readu32(STREAM, Pos) * Range
			Pos += 4
			Result = math.floor(Prod * INV_2_32)
			Low = Prod - Result * TWO_POW_32
		end
	end

	buffer.writeu32(STREAM, POS_OFFSET, Pos)
	return ActualMin + Result
end

@native
function CSPRNG.RandomNumber(Min: number, Max: number?): number
	local ActualMin: number
	local ActualMax: number

	if Max ~= nil then
		if not (type(Min) == "number" and type(Max) == "number" and Min > -math.huge and Max < math.huge and Max > Min) then
			local Problem = ArgumentError("Min", Min, false, false) or ArgumentError("Max", Max, false, true)
			if Problem then
				error(Problem, 2)
			end

			if Max < Min then
				error(`Max ({Max}) must be bigger than Min ({Min})`, 2)
			end

			if Max == Min then
				error(`Max ({Max}) can't be equal to Min ({Min})`, 2)
			end

			error("Invalid RandomNumber arguments", 2)
		end

		ActualMin = Min
		ActualMax = Max
	else
		if not (type(Min) == "number" and Min > 0 and Min < math.huge) then
			local Problem = ArgumentError("Min", Min, false, false)
			if Problem then
				error(Problem, 2)
			end

			if Min <= 0 then
				error(`When passing one argument, Min must be more than 0, got {Min}`, 2)
			end

			error("Invalid RandomNumber arguments", 2)
		end

		ActualMin = 0
		ActualMax = Min
	end

	local Pos = buffer.readu32(STREAM, POS_OFFSET)
	if Pos > POOL_SIZE - 8 then
		GenerateBlock()
		Pos = 0
	end

	local Value1 = buffer.readu32(STREAM, Pos)
	local Value2 = buffer.readu32(STREAM, Pos + 4)
	buffer.writeu32(STREAM, POS_OFFSET, Pos + 8)

	local Float = Value1 * INV_2_32 + bit32.rshift(Value2, 11) * INV_2_53
	local Range = ActualMax - ActualMin
	if Range < math.huge then
		local Value = ActualMin + Float * Range
		if Value < ActualMax then
			return Value
		end
	end

	return RetryNumberRange(ActualMin, ActualMax, Range)
end

@native
function CSPRNG.RandomBytes(Count: number): buffer
	if type(Count) ~= "number" or Count <= 0 or math.floor(Count) ~= Count or Count > MAX_SAFE_INTEGER then
		if type(Count) ~= "number" then
			error(`Count must be a number, got {typeof(Count)}`, 2)
		elseif Count <= 0 then
			error(`Count must be bigger than 0, got {Count}`, 2)
		else
			error("Count must be an integer", 2)
		end
	end

	return GetBytes(Count)
end

@native
local function RandomString(Length: number, AsBuffer: boolean?): string | buffer
	if type(Length) ~= "number" or Length <= 0 or Length > MAX_SAFE_INTEGER or math.floor(Length) ~= Length or (AsBuffer ~= nil and type(AsBuffer) ~= "boolean") then
		local Problem = ArgumentError("Length", Length, true, false)
		if Problem then
			error(Problem, 2)
		end

		if Length <= 0 then
			error(`Length must be bigger than 0, got {Length}`, 2)
		end

		if AsBuffer ~= nil and type(AsBuffer) ~= "boolean" then
			error(`AsBuffer must be a boolean or nil, got {typeof(AsBuffer)}`, 2)
		end

		error("Invalid RandomString arguments", 2)
	end

	return GetRandomString(Length, nil, AsBuffer)
end

CSPRNG.RandomString = RandomString :: any

function CSPRNG.MakeRandomString(CharacterSet: string | buffer): RandomStringSig
	if type(CharacterSet) ~= "string" and typeof(CharacterSet) ~= "buffer" then
		error(`CharacterSet must be a string or buffer, got {typeof(CharacterSet)}`, 2)
	end

	local Set = if type(CharacterSet) == "buffer" then CharacterSet else buffer.fromstring(CharacterSet)
	if buffer.len(Set) == 0 then
		error("CharacterSet cannot be empty", 2)
	end

	return @native function(Length: number, AsBuffer: boolean?): string | buffer
		if type(Length) ~= "number" or Length <= 0 or Length > MAX_SAFE_INTEGER or math.floor(Length) ~= Length or (AsBuffer ~= nil and type(AsBuffer) ~= "boolean") then
			local Problem = ArgumentError("Length", Length, true, false)
			if Problem then
				error(Problem, 2)
			end

			if Length <= 0 then
				error(`Length must be bigger than 0, got {Length}`, 2)
			end

			if AsBuffer ~= nil and type(AsBuffer) ~= "boolean" then
				error(`AsBuffer must be a boolean or nil, got {typeof(AsBuffer)}`, 2)
			end

			error("Invalid RandomString arguments", 2)
		end

		return GetRandomString(Length, Set, AsBuffer)
	end :: any
end

@native
function CSPRNG.RandomHex(Length: number): string
	if type(Length) ~= "number" or Length <= 0 or Length > MAX_SAFE_INTEGER or Length % 2 ~= 0 then
		if type(Length) ~= "number" then
			error(`Length must be a number, got {typeof(Length)}`, 2)
		elseif Length <= 0 then
			error(`Length must be bigger than 0, got {Length}`, 2)
		elseif Length % 1 ~= 0 then
			error("Length must be an integer", 2)
		else
			error(`Length must be even, got {Length}`, 2)
		end
	end

	return ToHex(GetBytes(Length / 2))
end

function CSPRNG.AddEntropy(Entropy: buffer?): ()
	if Entropy ~= nil and type(Entropy) ~= "buffer" then
		error(`Entropy must be a buffer or nil, got {typeof(Entropy)}`, 2)
	end

	GatherEntropy(Entropy)
	GenerateBlock()
end

GatherEntropy()
GenerateBlock()

return CSPRNG
