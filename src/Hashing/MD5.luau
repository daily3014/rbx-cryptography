--[=[
	Cryptography library: MD5

	⚠️ WARNING: MD5 is cryptographically broken!
	Only use for legacy compatibility, checksums, or non-security purposes.
	For security, use SHA256 or higher. ⚠️

	Return type: (string, buffer)
	Usage:
		local Message = buffer.fromstring("Hello World")
		local Hash, HashBuffer = MD5(Message)
--]=]

--!strict
--!optimize 2
--!native

local EncodingService = if game then game:GetService("EncodingService") else nil
local Conversions = require("../Utilities/Conversions")
local ToHex = Conversions.ToHex

local Digest: (Message: buffer) -> buffer
if EncodingService then
	local Service = EncodingService
	Digest = function(Message: buffer): buffer
		return Service:ComputeBufferHash(Message, Enum.HashAlgorithm.Md5)
	end
else
	Digest = require("./MD5Core").Digest
end

local function MD5(Message: buffer, Salt: buffer?): (string, buffer)
	if Salt and buffer.len(Salt) > 0 then
		local MessageWithSalt = buffer.create(buffer.len(Message) + buffer.len(Salt))
		buffer.copy(MessageWithSalt, 0, Message)
		buffer.copy(MessageWithSalt, buffer.len(Message), Salt)
		Message = MessageWithSalt
	end

	local Result = Digest(Message)
	return ToHex(Result), Result
end

return MD5
