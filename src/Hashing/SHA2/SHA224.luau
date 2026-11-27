--[=[
	Cryptography library: SHA224
	
	Sizes:
		Digest: 28 bytes

	Return type: (string, buffer)
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Hash, HashBuffer = SHA224(Message)
--]=]

--!strict
--!optimize 2

local Conversions = require("../../Utilities/Conversions")
local SHA256 = require("./SHA256")
local ToHex = Conversions.ToHex
local Digest = SHA256.Digest_Internal
local IV_224 = SHA256.IV_224

local function SHA224(Message: buffer): (string, buffer)
	local Result = Digest(Message, IV_224, 28)
	return ToHex(Result), Result
end

return SHA224
