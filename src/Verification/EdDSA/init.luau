--[=[
	Cryptography library: EdDSA (Ed25519)

	Return type: varies by function
	Example usage:
		local EdDSA = require("EdDSA")

		--------Usage Case 1--------
		local SecretKey = RandomBytes.Generate(32) -- use your random module
		local PublicKey = EdDSA.PublicKey(SecretKey)

		--------Usage Case 2--------
		local Message = buffer.fromstring("Hello World") -- or use buffer directly
		local Signature = EdDSA.Sign(SecretKey, PublicKey, Message)

		--------Usage Case 3--------
		local IsValid = EdDSA.Verify(PublicKey, Message, Signature)
--]=]

--!native
--!optimize 2
--!strict

local FieldQuadratic = require("@self/FieldQuadratic")
local SHA512 = require("@self/SHA512")
local Edwards25519 = require("@self/Edwards25519")
local Mask = require("@self/Mask")
local CSPRNG = require("@self/CSPRNG")

local ED25519_SECRET_KEY_SIZE = 32
local ED25519_PUBLIC_KEY_SIZE = 32
local ED25519_SIGNATURE_SIZE = 64

local function ConcatBuffers(...): buffer
	local Buffers = {...}
	local TotalLength = 0

	for _, Buffer in Buffers do
		TotalLength += buffer.len(Buffer)
	end

	local Result = buffer.create(TotalLength)
	local Offset = 0

	for _, Buffer in Buffers do
		local Length = buffer.len(Buffer)
		buffer.copy(Result, Offset, Buffer, 0, Length)
		Offset += Length
	end

	return Result
end

local EDDSA = {
	CSPRNG = CSPRNG,
	MaskedX25519 = Mask
}

function EDDSA.PublicKey(SecretKey: buffer): buffer
	if SecretKey == nil then
		error("SecretKey cannot be nil", 2)
	end
	
	if typeof(SecretKey) ~= "buffer" then
		error(`SecretKey must be a buffer, got {typeof(SecretKey)}`, 2)
	end
	
	local SecretKeyLength = buffer.len(SecretKey)
	if SecretKeyLength ~= ED25519_SECRET_KEY_SIZE then
		error(`SecretKey must be exactly {ED25519_SECRET_KEY_SIZE} bytes long, got {SecretKeyLength} bytes`, 2)
	end

	local Hash = SHA512(SecretKey)

	local FirstHalf = buffer.create(32)
	buffer.copy(FirstHalf, 0, Hash, 0, 32)

	local ScalarX = FieldQuadratic.DecodeClamped(FirstHalf)
	local ScalarBits, BitCount = FieldQuadratic.Bits(ScalarX)

	return Edwards25519.Encode(Edwards25519.MulG(ScalarBits, BitCount))
end

function EDDSA.Sign(SecretKey: buffer, PublicKey: buffer, Message: buffer): buffer
	if SecretKey == nil then
		error("SecretKey cannot be nil", 2)
	end
	
	if typeof(SecretKey) ~= "buffer" then
		error(`SecretKey must be a buffer, got {typeof(SecretKey)}`, 2)
	end
	
	local SecretKeyLength = buffer.len(SecretKey)
	if SecretKeyLength ~= ED25519_SECRET_KEY_SIZE then
		error(`SecretKey must be exactly {ED25519_SECRET_KEY_SIZE} bytes long, got {SecretKeyLength} bytes`, 2)
	end

	if PublicKey == nil then
		error("PublicKey cannot be nil", 2)
	end
	
	if typeof(PublicKey) ~= "buffer" then
		error(`PublicKey must be a buffer, got {typeof(PublicKey)}`, 2)
	end
	
	local PublicKeyLength = buffer.len(PublicKey)
	if PublicKeyLength ~= ED25519_PUBLIC_KEY_SIZE then
		error(`PublicKey must be exactly {ED25519_PUBLIC_KEY_SIZE} bytes long, got {PublicKeyLength} bytes`, 2)
	end

	if Message == nil then
		error("Message cannot be nil", 2)
	end
	
	if typeof(Message) ~= "buffer" then
		error(`Message must be a buffer, got {typeof(Message)}`, 2)
	end

	local Hash = SHA512(SecretKey)

	local FirstHalf = buffer.create(32)
	buffer.copy(FirstHalf, 0, Hash, 0, 32)
	local ScalarX = FieldQuadratic.DecodeClamped(FirstHalf)

	local SecondHalf = buffer.create(32)
	buffer.copy(SecondHalf, 0, Hash, 32, 32)

	local NonceSource = ConcatBuffers(SecondHalf, Message)
	local NonceHash = SHA512(NonceSource)
	local NonceK = FieldQuadratic.DecodeWide(NonceHash)

	local NonceBits, NonceBitCount = FieldQuadratic.Bits(NonceK)
	local CommitmentR = Edwards25519.MulG(NonceBits, NonceBitCount)
	local CommitmentString = Edwards25519.Encode(CommitmentR)

	local ChallengeInput = ConcatBuffers(CommitmentString, PublicKey, Message)
	local ChallengeHash = SHA512(ChallengeInput)
	local ChallengeE = FieldQuadratic.DecodeWide(ChallengeHash)

	local ResponseS = FieldQuadratic.Add(NonceK, FieldQuadratic.Mul(ScalarX, ChallengeE))
	local ResponseString = FieldQuadratic.Encode(ResponseS)

	return ConcatBuffers(CommitmentString, ResponseString)
end

function EDDSA.Verify(PublicKey: buffer, Message: buffer, Signature: buffer): boolean
	if PublicKey == nil then
		error("PublicKey cannot be nil", 2)
	end
	
	if typeof(PublicKey) ~= "buffer" then
		error(`PublicKey must be a buffer, got {typeof(PublicKey)}`, 2)
	end
	
	local PublicKeyLength = buffer.len(PublicKey)
	if PublicKeyLength ~= ED25519_PUBLIC_KEY_SIZE then
		error(`PublicKey must be exactly {ED25519_PUBLIC_KEY_SIZE} bytes long, got {PublicKeyLength} bytes`, 2)
	end

	if Message == nil then
		error("Message cannot be nil", 2)
	end
	
	if typeof(Message) ~= "buffer" then
		error(`Message must be a buffer, got {typeof(Message)}`, 2)
	end

	if Signature == nil then
		error("Signature cannot be nil", 2)
	end
	
	if typeof(Signature) ~= "buffer" then
		error(`Signature must be a buffer, got {typeof(Signature)}`, 2)
	end
	
	local SignatureLength = buffer.len(Signature)
	if SignatureLength ~= ED25519_SIGNATURE_SIZE then
		error(`Signature must be exactly {ED25519_SIGNATURE_SIZE} bytes long, got {SignatureLength} bytes`, 2)
	end

	local PublicPoint = Edwards25519.Decode(PublicKey)
	if not PublicPoint then
		return false
	end

	local CommitmentString = buffer.create(32)
	buffer.copy(CommitmentString, 0, Signature, 0, 32)

	local ResponseString = buffer.create(32)
	buffer.copy(ResponseString, 0, Signature, 32, 32)

	local ChallengeInput = ConcatBuffers(CommitmentString, PublicKey, Message)
	local ChallengeHash = SHA512(ChallengeInput)
	local ChallengeE = FieldQuadratic.DecodeWide(ChallengeHash)

	local ResponseScalar = FieldQuadratic.Decode(ResponseString)
	local ResponseBits, ResponseBitCount = FieldQuadratic.Bits(ResponseScalar)
	local LeftSide = Edwards25519.MulG(ResponseBits, ResponseBitCount)

	local ChallengeBits, ChallengeBitCount = FieldQuadratic.Bits(ChallengeE)
	local RightSideYE = Edwards25519.Mul(PublicPoint, ChallengeBits, ChallengeBitCount)
	local RightSideYENiels = Edwards25519.Niels(RightSideYE)
	local RightSideResult = Edwards25519.Sub(LeftSide, RightSideYENiels)

	local VerificationR = Edwards25519.Encode(RightSideResult)

	if buffer.len(VerificationR) ~= buffer.len(CommitmentString) then
		return false
	end
	
	for Index = 0, buffer.len(CommitmentString) - 1 do
		if buffer.readu8(VerificationR, Index) ~= buffer.readu8(CommitmentString, Index) then
			return false
		end
	end

	return true
end

return EDDSA