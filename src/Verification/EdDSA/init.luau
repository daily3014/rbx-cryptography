--[=[
   Cryptography library: EdDSA (Ed25519)

   Return type: varies by function
   Example usage:
		local SecretKey = GenerateRandomString(32) -- use your random module or our randomstring function
		local PublicKey = EdDSA.PublicKey(SecretKey)

		local Message = "Hello World"
		local Signature = EdDSA.Sign(SecretKey, PublicKey, Message)

		local IsValid = EdDSA.Verify(PublicKey, Message, Signature)
--]=]

--!native
--!optimize 2

local FieldQuadratic = require(script.FieldQuadratic)
local SHA512 = require(script.SHA512)
local Edwards25519 = require(script.Edwards25519)

local function PublicKey(SecretKey: string): string
	if #SecretKey ~= 32 then
		error("SecretKey must be 32 bytes long", 2)
	end

	local Hash = SHA512.Digest(SecretKey)
	local ScalarX = FieldQuadratic.DecodeClamped(Hash:sub(1, 32))
	return Edwards25519.Encode(Edwards25519.MulG(FieldQuadratic.Bits(ScalarX)))
end

local function Sign(SecretKey: string, PublicKey: string, Message: string): string
	if #SecretKey ~= 32 then
		error("SecretKey must be 32 bytes long", 2)
	end
	if #PublicKey ~= 32 then
		error("PublicKey must be 32 bytes long", 2)
	end

	local Hash = SHA512.Digest(SecretKey)
	local ScalarX = FieldQuadratic.DecodeClamped(Hash:sub(1, 32))

	local NonceSource = Hash:sub(33, 64) .. Message
	local NonceHash = SHA512.Digest(NonceSource)
	local NonceK = FieldQuadratic.DecodeWide(NonceHash)

	local CommitmentR = Edwards25519.MulG(FieldQuadratic.Bits(NonceK))
	local CommitmentString = Edwards25519.Encode(CommitmentR)

	local ChallengeE = FieldQuadratic.DecodeWide(SHA512.Digest(CommitmentString .. PublicKey .. Message))

	local ResponseS = FieldQuadratic.Add(NonceK, FieldQuadratic.Mul(ScalarX, ChallengeE))
	local ResponseString = FieldQuadratic.Encode(ResponseS)

	return CommitmentString .. ResponseString
end

local function Verify(PublicKey: string, Message: string, Signature: string): boolean
	if #PublicKey ~= 32 then
		return false
	end

	local PublicPoint = Edwards25519.Decode(PublicKey)
	if not PublicPoint then
		return false
	end

	if #Signature ~= 64 then
		return false
	end

	local CommitmentString = Signature:sub(1, 32)
	local ResponseString = Signature:sub(33, 64)
	if #ResponseString ~= 32 then
		return false
	end

	local ChallengeE = FieldQuadratic.DecodeWide(SHA512.Digest(CommitmentString .. PublicKey .. Message))

	local LeftSide = Edwards25519.MulG(FieldQuadratic.Bits(FieldQuadratic.Decode(ResponseString)))
	local RightSideYE = Edwards25519.Mul(PublicPoint, FieldQuadratic.Bits(ChallengeE))
	local RightSideResult = Edwards25519.Sub(LeftSide, Edwards25519.Niels(RightSideYE))

	return Edwards25519.Encode(RightSideResult) == CommitmentString
end

return {
	PublicKey = PublicKey,
	Sign = Sign,
	Verify = Verify,
}
