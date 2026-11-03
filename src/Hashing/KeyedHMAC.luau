--[=[
	Cryptography library: KeyedHMAC

	HMAC with the key prepared once, for many messages under one key. With SHA224, SHA384, SHA512,
	and SHA256 when EncodingService is absent, each message runs two compressions fewer than HMAC
	(HMACCore says when). The returned function keeps no reference to the key buffer.

	Return type: (Message: buffer) -> (string, buffer)
	Example usage:
		local Key = buffer.fromstring("Key")
		local Mac = KeyedHMAC(Key, SHA2.SHA512, 128)

		local Hex, Tag = Mac(buffer.fromstring("Hello World"))
--]=]

--!strict
--!optimize 2
--!native

local Conversions = require("../Utilities/Conversions")
local HMACCore = require("./HMACCore")

local ToHex = Conversions.ToHex
local Prepare = HMACCore.Prepare

export type HashFunction = HMACCore.HashFunction

local function KeyedHMAC(Key: buffer, HashFunction: HashFunction, BlockSizeBytes: number): (Message: buffer) -> (string, buffer)
	local Mac = Prepare(Key, HashFunction, BlockSizeBytes)

	return function(Message: buffer): (string, buffer)
		local Digest, Hex = Mac(Message)
		return Hex or ToHex(Digest), Digest
	end
end

return KeyedHMAC
