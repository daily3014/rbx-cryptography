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
local ToHex = Conversions.ToHex

local function SHA256(Message: buffer): (string, buffer)
	local Digest = EncodingService:ComputeBufferHash(Message, Enum.HashAlgorithm.Sha256)
	return ToHex(Digest), Digest
end

return SHA256
