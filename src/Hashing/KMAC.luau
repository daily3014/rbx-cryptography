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
local SHA3 = require("./SHA3")
local Keccak = SHA3.Keccak_Internal
local Permute = SHA3.Permute_Internal
local Extract = SHA3.Extract_Internal

local KMAC = {}

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

local STATE_A = buffer.create(100)
local STATE_B = buffer.create(100)
local TAIL = buffer.create(2 * 168)
local PAD_BLOCK = buffer.create(2 * 168)

local function KMACCore(Data: buffer, Key: buffer, Output: buffer, CustomBuffer: buffer?, RateBytes: number): ()
	local LanesLow = STATE_A
	local LanesHigh = STATE_B

	local OutputBytes = buffer.len(Output)

	local CustomLength = if CustomBuffer then buffer.len(CustomBuffer) else 0
	local CustomEncoding, CustomEncodingSize = LeftEncode(CustomLength * 8)
	local PrefixSize = 8 + CustomEncodingSize + CustomLength
	local PrefixPadded = PrefixSize + (-PrefixSize) % RateBytes
	local Prefix = if PrefixPadded <= 336 then PAD_BLOCK else buffer.create(PrefixPadded)
	buffer.fill(Prefix, 0, 0, PrefixPadded)
	buffer.writeu8(Prefix, 0, 1)
	buffer.writeu8(Prefix, 1, RateBytes)
	buffer.writeu16(Prefix, 2, 0x2001)
	buffer.writeu32(Prefix, 4, 0x43414D4B)
	buffer.copy(Prefix, 8, CustomEncoding, 0, CustomEncodingSize)
	if CustomBuffer and CustomLength > 0 then
		buffer.copy(Prefix, 8 + CustomEncodingSize, CustomBuffer, 0, CustomLength)
	end
	Keccak(LanesLow, LanesHigh, Prefix, 0, PrefixPadded, RateBytes, true)

	local KeyLength = buffer.len(Key)
	local KeyEncoding, KeyEncodingSize = LeftEncode(KeyLength * 8)
	local KeySize = 2 + KeyEncodingSize + KeyLength
	local KeyPadded = KeySize + (-KeySize) % RateBytes
	local KeyBlock = if KeyPadded <= 336 then PAD_BLOCK else buffer.create(KeyPadded)
	buffer.fill(KeyBlock, 0, 0, KeyPadded)
	buffer.writeu8(KeyBlock, 0, 1)
	buffer.writeu8(KeyBlock, 1, RateBytes)
	buffer.copy(KeyBlock, 2, KeyEncoding, 0, KeyEncodingSize)
	buffer.copy(KeyBlock, 2 + KeyEncodingSize, Key, 0, KeyLength)
	Keccak(LanesLow, LanesHigh, KeyBlock, 0, KeyPadded, RateBytes)

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

	local OutputOffset = 0
	while true do
		local BytesThisRound = math.min(RateBytes, OutputBytes - OutputOffset)
		Extract(LanesLow, LanesHigh, Output, OutputOffset, BytesThisRound)
		OutputOffset += BytesThisRound

		if OutputOffset >= OutputBytes then
			break
		end

		Permute(LanesLow, LanesHigh)
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
