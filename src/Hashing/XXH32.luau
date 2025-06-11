--[=[
	Cryptography library: XXHash32
	
	⚠️ WARNING: XXHash32 wasn't designed with cryptographic security in mind!
	Only use for non-security purposes. For security, use SHA256 or higher. ⚠️
	
	Return type: number
	Example usage:
		local Message = buffer.fromstring("Hello World")

		--------Usage Case 1--------
		local Result = XXHash32(Message)
		
		--------Usage Case 2--------
		local Seed = 0xDEADBEEF
		local Result = XXHash32(Message, Seed)
--]=]

--!native
--!optimize 2
--!strict

local PRIME_1 = 0x9e3779B1
local PRIME_2 = 0x85ebca77
local PRIME_3 = 0xc2B2ae3d
local PRIME_4 = 0x27d4eb2f
local PRIME_5 = 0x165667b1

local function Multiply32(A: number, B: number): number
	local AHigh, ALow = bit32.rshift(A, 16), A % 65536
	local BHigh, BLow = bit32.rshift(B, 16), B % 65536
	return bit32.lshift((AHigh * BLow) + (ALow * BHigh), 16) + (ALow * BLow)
end

local function ProcessLargeBlock(Message: buffer, Offset: number, Accum1: number, Accum2: number, Accum3: number, Accum4: number): (number, number, number, number)
	local Word1 = buffer.readu32(Message, Offset)
	local Word2 = buffer.readu32(Message, Offset + 4)
	local Word3 = buffer.readu32(Message, Offset + 8)
	local Word4 = buffer.readu32(Message, Offset + 12)

	Accum1 = Multiply32(bit32.lrotate(Accum1 + Multiply32(Word1, PRIME_2), 13), PRIME_1)
	Accum2 = Multiply32(bit32.lrotate(Accum2 + Multiply32(Word2, PRIME_2), 13), PRIME_1)
	Accum3 = Multiply32(bit32.lrotate(Accum3 + Multiply32(Word3, PRIME_2), 13), PRIME_1)
	Accum4 = Multiply32(bit32.lrotate(Accum4 + Multiply32(Word4, PRIME_2), 13), PRIME_1)

	return Accum1, Accum2, Accum3, Accum4
end

local function ProcessSmallWord(Message: buffer, Offset: number, Digest: number): number
	if Offset + 4 > buffer.len(Message) then
		return Digest
	end
	local Word = buffer.readu32(Message, Offset)
	Digest = Digest + Multiply32(Word, PRIME_3)
	
	return Multiply32(bit32.lrotate(Digest, 17), PRIME_4)
end

local function ProcessByte(Message: buffer, Offset: number, Digest: number): number
	if Offset >= buffer.len(Message) then
		return Digest
	end
	local ByteValue = buffer.readu8(Message, Offset)
	Digest = Digest + Multiply32(ByteValue, PRIME_5)
	return Multiply32(bit32.lrotate(Digest, 11), PRIME_1)
end

local function FinalizeDigest(Digest: number): number
	Digest = Multiply32(bit32.bxor(Digest, bit32.rshift(Digest, 15)), PRIME_2)
	Digest = Multiply32(bit32.bxor(Digest, bit32.rshift(Digest, 13)), PRIME_3)
	return bit32.bxor(Digest, bit32.rshift(Digest, 16))
end

local function XXHash32(Message: buffer, Seed: number?): number
	local Seed = Seed or 0
	local MessageLength = buffer.len(Message)
	local Digest: number
	local CurrentOffset = 0

	if MessageLength >= 16 then
		local Accumulator1 = Seed + PRIME_1 + PRIME_2
		local Accumulator2 = Seed + PRIME_2
		local Accumulator3 = Seed
		local ACcumulator4 = Seed - PRIME_1

		while CurrentOffset <= MessageLength - 16 do
			Accumulator1, Accumulator2, Accumulator3, ACcumulator4 = ProcessLargeBlock(Message, CurrentOffset, Accumulator1, Accumulator2, Accumulator3, ACcumulator4)
			CurrentOffset += 16
		end

		Digest = bit32.lrotate(Accumulator1, 1) + bit32.lrotate(Accumulator2, 7) + bit32.lrotate(Accumulator3, 12) + bit32.lrotate(ACcumulator4, 18)
	else
		Digest = Seed + PRIME_5
	end

	Digest  += MessageLength

	while CurrentOffset <= MessageLength - 4 do
		Digest = ProcessSmallWord(Message, CurrentOffset, Digest)
		CurrentOffset += 4
	end

	while CurrentOffset < MessageLength do
		Digest = ProcessByte(Message, CurrentOffset, Digest)
		CurrentOffset += 1
	end

	Digest = FinalizeDigest(Digest)

	return Digest
end

return XXHash32