--[=[
	Cryptography library: KMAC (Keccak Message Authentication Code)

	KMAC128 and KMAC256 are keyed hash functions based on cSHAKE128 and cSHAKE256.
	They give variable length output and strong authentication.

	Unlike SHAKE and cSHAKE, changing the output length generates a new,
	unrelated output. Both variants support up to 256 bits of security strength.

	Key Derivation Usage:
		For key derivation, use information related to the derived keying material
		as input data. Include identities and optionally a nonce.

	Return type: (string, buffer)
	Example usage:
		local Key = buffer.fromstring("my-secret-key")
		local Message = buffer.fromstring("Hello World")
		local Output = buffer.create(32)

		-- KMAC128 with 32-byte output
		local Hex, Digest = KMAC128(Message, Key, Output, buffer.create(0))

		-- KMAC256 with custom string
		local Hex2, Digest2 = KMAC256(Message, Key, Output, buffer.fromstring("super-code"))
--]=]

--!strict
--!optimize 2
--!native

local Conversions = require("../Utilities/Conversions")
local ToHex = Conversions.ToHex
local Keccak = require("./SHA3").Keccak_Internal

local KMAC = {}

local FUNCTION_NAME = buffer.fromstring("KMAC")
local EMPTY_CUSTOMIZATION = buffer.create(0)

local LEFT_ENCODE_RESULT = buffer.create(5)
local RIGHT_ENCODE_RESULT = buffer.create(5)

local function LeftEncode(Value: number): (buffer, number)
	local Result = LEFT_ENCODE_RESULT

	if Value <= 0xFF then
		buffer.writeu8(Result, 0, 1)
		buffer.writeu8(Result, 1, Value)
		return Result, 2
	end

	if Value <= 0xFFFF then
		buffer.writeu8(Result, 0, 2)
		buffer.writeu16(Result, 1, bit32.byteswap(bit32.lshift(Value, 16)))
		return Result, 3
	end

	local ByteLength = if Value > 0xFFFFFF then 4 else 3
	buffer.writeu8(Result, 0, ByteLength)
	buffer.writeu32(Result, 1, bit32.byteswap(bit32.lshift(Value, (4 - ByteLength) * 8)))
	return Result, ByteLength + 1
end

local function RightEncode(Value: number): (buffer, number)
	local Result = RIGHT_ENCODE_RESULT

	if Value <= 0xFF then
		buffer.writeu8(Result, 0, Value)
		buffer.writeu8(Result, 1, 1)
		return Result, 2
	end

	if Value <= 0xFFFF then
		buffer.writeu16(Result, 0, bit32.byteswap(bit32.lshift(Value, 16)))
		buffer.writeu8(Result, 2, 2)
		return Result, 3
	end

	local ByteLength = if Value > 0xFFFFFF then 4 else 3
	buffer.writeu32(Result, 0, bit32.byteswap(bit32.lshift(Value, (4 - ByteLength) * 8)))
	buffer.writeu8(Result, ByteLength, ByteLength)
	return Result, ByteLength + 1
end

local function EncodeString(Data: buffer): buffer
	local DataLength = buffer.len(Data)

	local LengthEncoding, LengthEncodingSize = LeftEncode(DataLength * 8)

	local Result = buffer.create(LengthEncodingSize + DataLength)

	buffer.copy(Result, 0, LengthEncoding, 0, LengthEncodingSize)
	buffer.copy(Result, LengthEncodingSize, Data, 0, DataLength)

	return Result
end

local function Bytepad(Data: buffer, Rate: number): buffer
	local DataLength = buffer.len(Data)

	local RateEncoding, RateEncodingSize = LeftEncode(Rate)

	local TotalPrePadLength = RateEncodingSize + DataLength
	local PadLength = Rate - (TotalPrePadLength % Rate)
	if PadLength == Rate then
		PadLength = 0
	end

	local Result = buffer.create(TotalPrePadLength + PadLength)
	buffer.copy(Result, 0, RateEncoding, 0, RateEncodingSize)
	buffer.copy(Result, RateEncodingSize, Data, 0, DataLength)

	return Result
end

local SQUEEZE_ZERO = buffer.create(168)
local TAIL = buffer.create(2 * 168)

local function KMACCore(Data: buffer, Key: buffer, Output: buffer, CustomBuffer: buffer?, RateBytes: number): ()
	local LanesLow = buffer.create(100)
	local LanesHigh = buffer.create(100)

	local OutputBytes = buffer.len(Output)

	local EncodedFunctionName = EncodeString(FUNCTION_NAME)
	local EncodedFunctionNameSize = buffer.len(EncodedFunctionName)

	local EncodedCustomization = EncodeString(CustomBuffer or EMPTY_CUSTOMIZATION)
	local EncodedCustomizationSize = buffer.len(EncodedCustomization)
	local PrefixData = buffer.create(EncodedFunctionNameSize + EncodedCustomizationSize)
	buffer.copy(PrefixData, 0, EncodedFunctionName, 0, EncodedFunctionNameSize)
	buffer.copy(PrefixData, EncodedFunctionNameSize, EncodedCustomization, 0, EncodedCustomizationSize)

	local BytepaddedPrefix = Bytepad(PrefixData, RateBytes)
	Keccak(LanesLow, LanesHigh, BytepaddedPrefix, 0, buffer.len(BytepaddedPrefix), RateBytes)

	local BytepaddedKey = Bytepad(EncodeString(Key), RateBytes)
	Keccak(LanesLow, LanesHigh, BytepaddedKey, 0, buffer.len(BytepaddedKey), RateBytes)

	local DataSize = buffer.len(Data)
	local FullBytes = DataSize - DataSize % RateBytes
	if FullBytes > 0 then
		Keccak(LanesLow, LanesHigh, Data, 0, FullBytes, RateBytes)
	end

	local RightEncodedLength, RightEncodedLengthSize = RightEncode(OutputBytes * 8)
	local Remaining = DataSize - FullBytes
	local TailInputSize = Remaining + RightEncodedLengthSize

	local TailLength = TailInputSize + 1
	local Remainder = TailLength % RateBytes
	if Remainder ~= 0 then
		TailLength += (RateBytes - Remainder)
	end

	buffer.fill(TAIL, 0, 0, TailLength)
	buffer.copy(TAIL, 0, Data, FullBytes, Remaining)
	buffer.copy(TAIL, Remaining, RightEncodedLength, 0, RightEncodedLengthSize)

	local DomainSeparator = 0x04
	if TailLength - TailInputSize == 1 then
		buffer.writeu8(TAIL, TailInputSize, bit32.bor(DomainSeparator, 0x80))
	else
		buffer.writeu8(TAIL, TailInputSize, DomainSeparator)
		buffer.writeu8(TAIL, TailLength - 1, 0x80)
	end

	Keccak(LanesLow, LanesHigh, TAIL, 0, TailLength, RateBytes)

	local Keccak = Keccak
	local SqueezeZero = SQUEEZE_ZERO
	local OutputOffset = 0
	while OutputOffset < OutputBytes do
		local BytesThisRound = math.min(RateBytes, OutputBytes - OutputOffset)
		local FullLanes = BytesThisRound // 8

		for Lane = 0, FullLanes - 1 do
			buffer.writeu32(Output, OutputOffset + Lane * 8, buffer.readu32(LanesLow, Lane * 4))
			buffer.writeu32(Output, OutputOffset + Lane * 8 + 4, buffer.readu32(LanesHigh, Lane * 4))
		end

		for ByteIndex = FullLanes * 8, BytesThisRound - 1 do
			local LaneOffset = (ByteIndex // 8) * 4
			local ByteInLane = ByteIndex % 8
			local Value = if ByteInLane < 4
				then bit32.extract(buffer.readu32(LanesLow, LaneOffset), ByteInLane * 8, 8)
				else bit32.extract(buffer.readu32(LanesHigh, LaneOffset), (ByteInLane - 4) * 8, 8)
			buffer.writeu8(Output, OutputOffset + ByteIndex, Value)
		end

		OutputOffset += BytesThisRound

		if OutputOffset < OutputBytes then
			Keccak(LanesLow, LanesHigh, SqueezeZero, 0, RateBytes, RateBytes)
		end
	end
end

function KMAC.KMAC128(Data: buffer, Key: buffer, Output: buffer, CustomBuffer: buffer?): (string, buffer)
	KMACCore(Data, Key, Output, CustomBuffer, 168)

	return ToHex(Output), Output
end

function KMAC.KMAC256(Data: buffer, Key: buffer, Output: buffer, CustomBuffer: buffer?): (string, buffer)
	KMACCore(Data, Key, Output, CustomBuffer, 136)

	return ToHex(Output), Output
end

return KMAC
