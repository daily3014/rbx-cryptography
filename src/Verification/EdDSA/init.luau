--[=[
	Cryptography library: EdDSA (Ed25519)

	Return type: varies by function
	Example usage:
		local EdDSA = require("EdDSA")

		--------Usage Case 1: Generate keypair--------
		local SecretKey = RandomBytes.Generate(32) -- use your random module
		local PublicKey = EdDSA.PublicKey(SecretKey)

		--------Usage Case 2: Sign message--------
		local Message = buffer.fromstring("Hello World") -- or use buffer directly
		local Signature = EdDSA.Sign(SecretKey, PublicKey, Message)

		--------Usage Case 3: Verify signature--------
		local IsValid = EdDSA.Verify(PublicKey, Message, Signature)
--]=]

--!native
--!optimize 2

local FieldQuadratic = require("@self/FieldQuadratic")
local SHA512 = require("@self/SHA512")
local Edwards25519 = require("@self/Edwards25519")
local Mask = require("@self/Mask")

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

local function PublicKey(SecretKey: buffer): buffer
	local Hash = SHA512(SecretKey)

	local FirstHalf = buffer.create(32)
	buffer.copy(FirstHalf, 0, Hash, 0, 32)

	local ScalarX = FieldQuadratic.DecodeClamped(FirstHalf)
	local ScalarBits, BitCount = FieldQuadratic.Bits(ScalarX)

	return Edwards25519.Encode(Edwards25519.MulG(ScalarBits, BitCount))
end

local function Sign(SecretKey: buffer, PublicKey: buffer, Message: buffer): buffer
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

local function Verify(PublicKey: buffer, Message: buffer, Signature: buffer): boolean
	local PublicPoint = Edwards25519.Decode(PublicKey)
	if not PublicPoint then
		return false
	end

	if buffer.len(Signature) ~= 64 then
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

return {
	PublicKey = PublicKey,
	Sign = Sign,
	Verify = Verify,

	Masked25519 = Mask
}