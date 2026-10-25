--[=[
	Cryptography library: SHA384

	Sizes:
		Digest: 48 bytes

	Return type: (string, buffer)
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Hash, HashBuffer = SHA384(Message)
--]=]

--!strict
--!optimize 2
--!native

local Conversions = require("../../Utilities/Conversions")
local SHA512 = require("./SHA512")
local ToHex = Conversions.ToHex
local Digest = SHA512.Digest_Internal
local IV_384 = SHA512.IV_384

local function SHA384(Message: buffer): (string, buffer)
	local Result = Digest(Message, IV_384, 48)

	return ToHex(Result), Result
end

return SHA384
