--[=[
	Cryptography library: SHA256

	Sizes:
		Digest: 32 bytes
	
	Return type: (string, buffer)
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Hash, HashBuffer = SHA256(Message)
--]=]

--!strict
--!optimize 2
--!native

local EncodingService = if game then game:GetService("EncodingService") else nil
local Conversions = require("../../Utilities/Conversions")
local SHA256Core = require("./SHA256Core")
local ToHex = Conversions.ToHex
local Digest = SHA256Core.Digest_Internal
local IV_256 = SHA256Core.IV_256

local function SHA256(Message: buffer): (string, buffer)
	if EncodingService then
		local Result = EncodingService:ComputeBufferHash(Message, Enum.HashAlgorithm.Sha256)
		return ToHex(Result), Result
	end

	local Result = Digest(Message, IV_256, 32)
	return ToHex(Result), Result
end

return SHA256
