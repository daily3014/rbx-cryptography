--[=[
	Cryptography library: Base64

	Return type: buffer
	Example usage:
		local Input = buffer.fromstring("Hello World")
		local Encoded = Base64.Encode(Input)
		local Decoded = Base64.Decode(Encoded)
--]=]

--!strict
--!optimize 2
--!native

local EncodingService = if game then game:GetService("EncodingService") else nil

if EncodingService then
	return {
		Encode = function(Input: buffer): buffer
			return EncodingService:Base64Encode(Input)
		end,
		Decode = function(Input: buffer): buffer
			return EncodingService:Base64Decode(Input)
		end
	}
end

return require("./Base64Core")
