--[=[
	Cryptography library: HMAC core shared by HMAC and HKDF

	Example usage:
		local Digest, Hex = HMACCore.Compute(Message, Key, SHA2.SHA256, 64)
--]=]

--!strict
--!optimize 2
--!native

local EncodingService = if game then game:GetService("EncodingService") else nil
local SHA2: {[string]: unknown} = require("./SHA2") :: any

export type HashFunction = (...any) -> (string, buffer)
export type Prepared = (Message: buffer) -> (buffer, string?)
type DigestOnly = (Message: buffer) -> buffer
type Core = {
	Digest: (Message: buffer, InitialState: buffer, OutputBytes: number, PrefixBytes: number?) -> buffer,
	Compress: (Blocks: buffer, Offset: number, Length: number, State: buffer) -> (),
	IV: buffer,
	StateBytes: number,
	BlockBytes: number,
	OutputBytes: number,
}

local INNER_PAD = 0x36363636
local OUTER_PAD = 0x5c5c5c5c

local DIGEST_ONLY: {[HashFunction]: DigestOnly | false} = setmetatable({}, {__mode = "k"}) :: any
local CORES: {[HashFunction]: Core | false} = setmetatable({}, {__mode = "k"}) :: any

local KEY_BLOCK = buffer.create(128)
local INNER_SCRATCH = buffer.create(64)
local OUTER_SCRATCH = buffer.create(64)

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

local function ResolveCore(HashFunction: HashFunction): Core | false
	if HashFunction == rawget(SHA2, "SHA256") or HashFunction == rawget(SHA2, "SHA224") then
		if HashFunction == rawget(SHA2, "SHA256") and EncodingService then
			return false
		end

		local SHA256Core = require("./SHA2/SHA256Core")
		local Is256 = HashFunction == rawget(SHA2, "SHA256")
		return {
			Digest = SHA256Core.Digest_Internal,
			Compress = SHA256Core.Compress_Internal,
			IV = if Is256 then SHA256Core.IV_256 else SHA256Core.IV_224,
			StateBytes = 32,
			BlockBytes = 64,
			OutputBytes = if Is256 then 32 else 28,
		}
	end

	if HashFunction == rawget(SHA2, "SHA384") or HashFunction == rawget(SHA2, "SHA512") then
		local SHA512Core = require("./SHA2/SHA512")
		local Is512 = HashFunction == rawget(SHA2, "SHA512")
		return {
			Digest = SHA512Core.Digest_Internal,
			Compress = SHA512Core.Compress_Internal,
			IV = if Is512 then SHA512Core.IV_512 else SHA512Core.IV_384,
			StateBytes = 64,
			BlockBytes = 128,
			OutputBytes = if Is512 then 64 else 48,
		}
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

local function KeyState(Core: Core, BlockKey: buffer, KeyLength: number, Pad: number, State: buffer): buffer
	local Block = KEY_BLOCK
	buffer.fill(Block, 0, 0, Core.BlockBytes)
	WritePaddedKey(Block, BlockKey, KeyLength, Core.BlockBytes, Pad)

	buffer.copy(State, 0, Core.IV, 0, Core.StateBytes)
	Core.Compress(Block, 0, Core.BlockBytes, State)
	return State
end

local function Resolve(HashFunction: HashFunction): (DigestOnly | false, Core | false)
	local DigestOnly = DIGEST_ONLY[HashFunction]
	if DigestOnly == nil then
		DigestOnly = ResolveDigestOnly(HashFunction)
		DIGEST_ONLY[HashFunction] = DigestOnly
	end

	local Core = CORES[HashFunction]
	if Core == nil then
		Core = ResolveCore(HashFunction)
		CORES[HashFunction] = Core
	end

	return DigestOnly :: DigestOnly | false, Core :: Core | false
end

local function BlockKeyOf(Key: buffer, HashFunction: HashFunction, DigestOnly: DigestOnly | false, BlockSizeBytes: number): (buffer, number)
	local KeyLength = buffer.len(Key)
	if KeyLength <= BlockSizeBytes then
		return Key, KeyLength
	end

	if DigestOnly then
		local Digest = DigestOnly(Key)
		return Digest, buffer.len(Digest)
	end

	local _, Digest = HashFunction(Key)
	return Digest, buffer.len(Digest)
end

local function Prepare(Key: buffer, HashFunction: HashFunction, BlockSizeBytes: number): Prepared
	local DigestOnly, Core = Resolve(HashFunction)
	local BlockKey, KeyLength = BlockKeyOf(Key, HashFunction, DigestOnly, BlockSizeBytes)

	if Core and Core.BlockBytes == BlockSizeBytes then
		local InnerState = KeyState(Core, BlockKey, KeyLength, INNER_PAD, buffer.create(Core.StateBytes))
		local OuterState = KeyState(Core, BlockKey, KeyLength, OUTER_PAD, buffer.create(Core.StateBytes))
		local Digest, OutputBytes = Core.Digest, Core.OutputBytes

		return function(Message: buffer): (buffer, string?)
			local InnerDigest = Digest(Message, InnerState, OutputBytes, BlockSizeBytes)
			return Digest(InnerDigest, OuterState, OutputBytes, BlockSizeBytes), nil
		end
	end

	local InnerPad = buffer.create(BlockSizeBytes)
	WritePaddedKey(InnerPad, BlockKey, KeyLength, BlockSizeBytes, INNER_PAD)
	local OuterPad = buffer.create(BlockSizeBytes)
	WritePaddedKey(OuterPad, BlockKey, KeyLength, BlockSizeBytes, OUTER_PAD)

	return function(Message: buffer): (buffer, string?)
		local MessageLength = buffer.len(Message)
		local Inner = buffer.create(BlockSizeBytes + MessageLength)
		buffer.copy(Inner, 0, InnerPad, 0, BlockSizeBytes)
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
		buffer.copy(Outer, 0, OuterPad, 0, BlockSizeBytes)
		buffer.copy(Outer, BlockSizeBytes, InnerDigest, 0, InnerLength)

		if DigestOnly then
			return DigestOnly(Outer), nil
		end

		local Hex, Digest = HashFunction(Outer)
		return Digest, Hex
	end
end

local function Compute(Message: buffer, Key: buffer, HashFunction: HashFunction, BlockSizeBytes: number): (buffer, string?)
	local DigestOnly, Core = Resolve(HashFunction)
	local BlockKey, KeyLength = BlockKeyOf(Key, HashFunction, DigestOnly, BlockSizeBytes)

	if Core and Core.BlockBytes == BlockSizeBytes then
		local Digest, OutputBytes = Core.Digest, Core.OutputBytes
		KeyState(Core, BlockKey, KeyLength, INNER_PAD, INNER_SCRATCH)
		KeyState(Core, BlockKey, KeyLength, OUTER_PAD, OUTER_SCRATCH)
		local InnerDigest = Digest(Message, INNER_SCRATCH, OutputBytes, BlockSizeBytes)
		return Digest(InnerDigest, OUTER_SCRATCH, OutputBytes, BlockSizeBytes), nil
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
	Prepare = Prepare,
}
