--[=[
	Cryptography library: SHA1

	⚠️ WARNING: SHA1 is cryptographically broken!
	Only use for legacy compatibility, checksums, or non-security purposes.
	For security, use SHA256 or higher. ⚠️

	Sizes:
		Digest: 20 bytes

	Return type: (string, buffer)
	Example usage:
		local Message = buffer.fromstring("Hello World")

		--------Usage Case 1--------
		local Hash, HashBuffer = SHA1(Message)

		--------Usage Case 2--------
		local OptionalSalt = buffer.fromstring("Salty")
		local Hash, HashBuffer = SHA1(Message, OptionalSalt)
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
		return Service:ComputeBufferHash(Message, Enum.HashAlgorithm.Sha1)
	end
else
	Digest = require("./SHA1Core").Digest
end

local function SHA1(Message: buffer, Salt: buffer?): (string, buffer)
	if Salt and buffer.len(Salt) > 0 then
		local MessageWithSalt = buffer.create(buffer.len(Message) + buffer.len(Salt))

		buffer.copy(MessageWithSalt, 0, Message)
		buffer.copy(MessageWithSalt, buffer.len(Message), Salt)

		Message = MessageWithSalt
	end

	local Result = Digest(Message)
	return ToHex(Result), Result
end

return SHA1
