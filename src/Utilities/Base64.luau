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

local function Encode(Input: buffer): buffer
	return EncodingService:Base64Encode(Input)
end

local function Decode(Input: buffer): buffer
	return EncodingService:Base64Decode(Input)
end

return {
	Encode = Encode,
	Decode = Decode
}
