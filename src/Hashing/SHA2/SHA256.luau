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

local Digest: (Message: buffer) -> buffer
if EncodingService then
	local Service = EncodingService
	Digest = function(Message: buffer): buffer
		return Service:ComputeBufferHash(Message, Enum.HashAlgorithm.Sha256)
	end
else
	local SHA256Core = require("./SHA256Core")
	local Digest256 = SHA256Core.Digest_Internal
	local IV_256 = SHA256Core.IV_256
	Digest = function(Message: buffer): buffer
		return Digest256(Message, IV_256, 32)
	end
end

local function SHA256(Message: buffer): (string, buffer)
	local Result = Digest(Message)
	return ToHex(Result), Result
end

return SHA256
