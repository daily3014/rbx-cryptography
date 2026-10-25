--[=[
	Cryptography library: HMAC core shared by HMAC and HKDF

	Example usage:
		local Digest, Hex = HMACCore.Compute(Message, Key, SHA2.SHA256, 64)
--]=]

--!strict
--!optimize 2
--!native

local EncodingService = if game then game:GetService("EncodingService") else nil
local SHA2 = require("./SHA2")

export type HashFunction = (...any) -> (string, buffer)
type DigestOnly = (Message: buffer) -> buffer

local INNER_PAD = 0x36363636
local OUTER_PAD = 0x5c5c5c5c

local DIGEST_ONLY: {[HashFunction]: DigestOnly | false} = setmetatable({}, {__mode = "k"}) :: any

local function ResolveDigestOnly(HashFunction: HashFunction): DigestOnly | false
	if HashFunction == rawget(SHA2, "SHA256") then
		if EncodingService then
			local Service = EncodingService
			return function(Message: buffer): buffer
				return Service:ComputeBufferHash(Message, Enum.HashAlgorithm.Sha256)
			end
		end

		local SHA256Core = require("./SHA2/SHA256Core")
		local Digest256, IV_256 = SHA256Core.Digest_Internal, SHA256Core.IV_256
		return function(Message: buffer): buffer
			return Digest256(Message, IV_256, 32)
		end
	end

	if HashFunction == rawget(SHA2, "SHA224") then
		local SHA256Core = require("./SHA2/SHA256Core")
		local Digest256, IV_224 = SHA256Core.Digest_Internal, SHA256Core.IV_224
		return function(Message: buffer): buffer
			return Digest256(Message, IV_224, 28)
		end
	end

	if HashFunction == rawget(SHA2, "SHA384") then
		local SHA512Core = require("./SHA2/SHA512")
		local Digest512, IV_384 = SHA512Core.Digest_Internal, SHA512Core.IV_384
		return function(Message: buffer): buffer
			return Digest512(Message, IV_384, 48)
		end
	end

	if HashFunction == rawget(SHA2, "SHA512") then
		return require("./SHA2/SHA512").SHA512_Internal
	end

	return false
end

local function WritePaddedKey(Target: buffer, Key: buffer, KeyLength: number, BlockSizeBytes: number, Pad: number)
	if KeyLength > 0 then
		buffer.copy(Target, 0, Key, 0, KeyLength)
	end

	local WordBytes = BlockSizeBytes - BlockSizeBytes % 4
	for Offset = 0, WordBytes - 4, 4 do
		buffer.writeu32(Target, Offset, bit32.bxor(buffer.readu32(Target, Offset), Pad))
	end

	local BytePad = bit32.band(Pad, 0xff)
	for Offset = WordBytes, BlockSizeBytes - 1 do
		buffer.writeu8(Target, Offset, bit32.bxor(buffer.readu8(Target, Offset), BytePad))
	end
end

local function Compute(Message: buffer, Key: buffer, HashFunction: HashFunction, BlockSizeBytes: number): (buffer, string?)
	local DigestOnly = DIGEST_ONLY[HashFunction]
	if DigestOnly == nil then
		DigestOnly = ResolveDigestOnly(HashFunction)
		DIGEST_ONLY[HashFunction] = DigestOnly
	end

	local BlockKey = Key
	local KeyLength = buffer.len(Key)
	if KeyLength > BlockSizeBytes then
		if DigestOnly then
			BlockKey = DigestOnly(Key)
		else
			local _, Digest = HashFunction(Key)
			BlockKey = Digest
		end
		KeyLength = buffer.len(BlockKey)
	end

	local MessageLength = buffer.len(Message)
	local Inner = buffer.create(BlockSizeBytes + MessageLength)
	WritePaddedKey(Inner, BlockKey, KeyLength, BlockSizeBytes, INNER_PAD)
	if MessageLength > 0 then
		buffer.copy(Inner, BlockSizeBytes, Message, 0, MessageLength)
	end

	local InnerDigest: buffer
	if DigestOnly then
		InnerDigest = DigestOnly(Inner)
	else
		local _, Digest = HashFunction(Inner)
		InnerDigest = Digest
	end
	local InnerLength = buffer.len(InnerDigest)
	local Outer = buffer.create(BlockSizeBytes + InnerLength)
	WritePaddedKey(Outer, BlockKey, KeyLength, BlockSizeBytes, OUTER_PAD)
	buffer.copy(Outer, BlockSizeBytes, InnerDigest, 0, InnerLength)

	if DigestOnly then
		return DigestOnly(Outer), nil
	end

	local Hex, Digest = HashFunction(Outer)
	return Digest, Hex
end

return {
	Compute = Compute,
}
