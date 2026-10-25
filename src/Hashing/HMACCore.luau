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
local SHA256Core = require("./SHA2/SHA256Core")
local SHA512Core = require("./SHA2/SHA512")

export type HashFunction = (...any) -> (string, buffer)

local INNER_PAD = 0x36363636
local OUTER_PAD = 0x5c5c5c5c

local Digest256 = SHA256Core.Digest_Internal
local Digest512 = SHA512Core.Digest_Internal
local IV_224, IV_256 = SHA256Core.IV_224, SHA256Core.IV_256
local IV_384 = SHA512Core.IV_384

local DIGEST_ONLY: {[HashFunction]: (buffer) -> buffer} = {
	[SHA2.SHA224] = function(Message: buffer): buffer
		return Digest256(Message, IV_224, 28)
	end,
	[SHA2.SHA256] = function(Message: buffer): buffer
		if EncodingService then
			return EncodingService:ComputeBufferHash(Message, Enum.HashAlgorithm.Sha256)
		end

		return Digest256(Message, IV_256, 32)
	end,
	[SHA2.SHA384] = function(Message: buffer): buffer
		return Digest512(Message, IV_384, 48)
	end,
	[SHA2.SHA512] = SHA512Core.SHA512_Internal,
}

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
