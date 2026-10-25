--[=[
	Cryptography library: HMAC

	Return type: (string, buffer)
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Key = buffer.fromstring("Key")
		local BlockSize = 64 -- SHA256 block length (= string.len(SHA256(...)))

		local Result = HMAC(Message, Key, SHA2.SHA256, BlockSize)
--]=]

--!strict
--!optimize 2
--!native

local Conversions = require("../Utilities/Conversions")
local HMACCore = require("./HMACCore")

local ToHex = Conversions.ToHex
local Compute = HMACCore.Compute

export type HashFunction = (...any) -> (string, buffer)

local function HMAC(Message: buffer, Key: buffer, HashFunction: HashFunction, BlockSizeBytes: number, _BigEndian: boolean?): (string, buffer)
	local Digest, Hex = Compute(Message, Key, HashFunction, BlockSizeBytes)
	return Hex or ToHex(Digest), Digest
end

return HMAC
