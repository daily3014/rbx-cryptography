--[=[
	Cryptography library: MurmurHash3-32
	
	⚠️ WARNING: MurmurHash3 wasn't designed with cryptographic security in mind!
	Only use for non-security purposes like hash tables or hyperloglog. For security, use SHA256 or higher. ⚠️
	
	MurmurHash3 is a fast non-cryptographic hash that is well-distributed.
	
	Return type: number
	Example usage:
		local Message = buffer.fromstring("Hello World")

		--------Usage Case 1--------
		local Result = MurmurHash3(Message)
		
		--------Usage Case 2--------
		local Seed = 0xDEADBEEF
		local Result = MurmurHash3(Message, Seed)
--]=]

--!strict
--!optimize 2
--!native

local function Mul32(A: number, B: number): number
	local AHigh = bit32.rshift(A, 16)
	local ALow = bit32.band(A, 0xFFFF)
	local BHigh = bit32.rshift(B, 16)
	local BLow = bit32.band(B, 0xFFFF)

	local LoLo = ALow * BLow
	local HiLo = bit32.lshift(AHigh * BLow, 16)
	local LoHi = bit32.lshift(ALow * BHigh, 16)

	local Result = bit32.bor(LoLo + HiLo, 0)
	return bit32.bor(Result + LoHi, 0)
end

local function FMix32(Hash: number): number
	Hash = Mul32(bit32.bxor(Hash, bit32.rshift(Hash, 16)), 0x85ebca6b)
	Hash = Mul32(bit32.bxor(Hash, bit32.rshift(Hash, 13)), 0xc2b2ae35)
	Hash = bit32.bxor(Hash, bit32.rshift(Hash, 16))
	return Hash
end

local function MurmurHash3(Message: buffer, Seed: number?): number
	local C1 = 0xcc9e2d51
	local C2 = 0x1b873593
	local M = 5
	local N = 0xe6546b64

	local Hash = bit32.bor(Seed or 0, 0)
	local MessageLength = buffer.len(Message)
	local BlockCount = MessageLength // 4
	local UnrolledBlocks = BlockCount // 4
	local CurrentOffset = 0

	for _ = 1, UnrolledBlocks do
		local K1 = buffer.readu32(Message, CurrentOffset)
		K1 = Mul32(bit32.lrotate(Mul32(K1, 0xcc9e2d51), 15), 0x1b873593)
		Hash = bit32.bor(bit32.lrotate(bit32.bxor(Hash, K1), 13) * 5 + 0xe6546b64, 0)

		local K2 = buffer.readu32(Message, CurrentOffset + 4)
		K2 = Mul32(bit32.lrotate(Mul32(K2, 0xcc9e2d51), 15), 0x1b873593)
		Hash = bit32.bor(bit32.lrotate(bit32.bxor(Hash, K2), 13) * 5 + 0xe6546b64, 0)

		local K3 = buffer.readu32(Message, CurrentOffset + 8)
		K3 = Mul32(bit32.lrotate(Mul32(K3, 0xcc9e2d51), 15), 0x1b873593)
		Hash = bit32.bor(bit32.lrotate(bit32.bxor(Hash, K3), 13) * 5 + 0xe6546b64, 0)

		local K4 = buffer.readu32(Message, CurrentOffset + 12)
		K4 = Mul32(bit32.lrotate(Mul32(K4, 0xcc9e2d51), 15), 0x1b873593)
		Hash = bit32.bor(bit32.lrotate(bit32.bxor(Hash, K4), 13) * 5 + 0xe6546b64, 0)

		CurrentOffset += 16
	end

	local RemainingBlocks = BlockCount % 4
	for _ = 1, RemainingBlocks do
		local K = buffer.readu32(Message, CurrentOffset)
		K = Mul32(K, 0xcc9e2d51)
		K = bit32.lrotate(K, 15)
		K = Mul32(K, 0x1b873593)
		Hash = bit32.bxor(Hash, K)
		Hash = bit32.lrotate(Hash, 13)
		Hash = bit32.bor(Hash * 5 + 0xe6546b64, 0)

		CurrentOffset += 4
	end

	local Remainder = MessageLength % 4
	if Remainder > 0 then
		local K1 = 0

		if Remainder >= 3 then
			K1 = bit32.bxor(K1, bit32.lshift(buffer.readu8(Message, CurrentOffset + 2), 16))
		end

		if Remainder >= 2 then
			K1 = bit32.bxor(K1, bit32.lshift(buffer.readu8(Message, CurrentOffset + 1), 8))
		end

		K1 = bit32.bxor(K1, buffer.readu8(Message, CurrentOffset))

		K1 = Mul32(K1, C1)
		K1 = bit32.lrotate(K1, 15)
		K1 = Mul32(K1, C2)
		Hash = bit32.bxor(Hash, K1)
	end

	Hash = bit32.bxor(Hash, MessageLength)
	Hash = FMix32(Hash)

	return Hash
end

return MurmurHash3