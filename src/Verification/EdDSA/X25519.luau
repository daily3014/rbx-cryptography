--[=[
   Cryptography library: X25519 (Curve25519 ECDH)
   
   Return type: varies by function
   Example usage:
   	local X25519 = require("X25519")
   	
   	--------Usage Case 1: Generate keypair--------
   	local SecretKey = RandomBytes.Generate(32) -- use your random module
   	local PublicKey = X25519.PublicKey(SecretKey)
   	
   	--------Usage Case 2: Key exchange--------
   	local SharedSecret = X25519.Exchange(MySecretKey, TheirPublicKey)
--]=]

--!native
--!optimize 2

local Curve25519 = require(script.Parent.Curve25519)

-- decode bits with x25519/ed25519 exponent clamping rules
local function DecodeBits(EncodedString)
	-- turn bytes into individual bits
	local ByteArray = { EncodedString:byte(1, 32) }
	local BitOutput = {}
	for ByteIndex = 1, 32 do
		local CurrentByte = ByteArray[ByteIndex]
		for BitOffset = -7, 0 do
			local SingleBit = CurrentByte % 2
			BitOutput[8 * ByteIndex + BitOffset] = SingleBit
			CurrentByte = (CurrentByte - SingleBit) / 2
		end
	end

	-- apply the clamping rules to make it a valid scalar
	BitOutput[1] = 0
	BitOutput[2] = 0
	BitOutput[3] = 0
	BitOutput[255] = 1
	BitOutput[256] = 0
	return BitOutput
end

-- decode bits with clamping and divide by 8 (for cofactor clearing)
local function DecodeBits8(EncodedString)
	return { unpack(DecodeBits(EncodedString), 4) }
end

-- compute the public key from a secret key
local function PublicKey(SecretKey)
	return Curve25519.Encode(Curve25519.Scale(Curve25519.MulG(DecodeBits(SecretKey))))
end

-- perform the diffie-hellman key exchange
local function Exchange(MySecretKey, TheirPublicKey)
	return Curve25519.Encode(
		Curve25519.Scale(Curve25519.Ladder8(Curve25519.Decode(TheirPublicKey), DecodeBits8(MySecretKey)))
	)
end

return {
	PublicKey = PublicKey,
	Exchange = Exchange,
}
