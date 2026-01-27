--[=[
	Cryptography library: EdDSA (Ed25519) with Batch Verification

	Return type: varies by function
	Example usage:
		local EdDSA = require("EdDSA")

		--------Usage Case 1--------
		local SecretKey = RandomBytes.Generate(32)
		local PublicKey = EdDSA.PublicKey(SecretKey)

		--------Usage Case 2--------
		local Message = buffer.fromstring("Hello World")
		local Signature = EdDSA.Sign(Message, SecretKey, PublicKey)

		--------Usage Case 3--------
		local IsValid = EdDSA.Verify(Message, PublicKey, Signature)

		--------Usage Case 4: Batch Verification--------
		local AllValid = EdDSA.VerifyBatch({
			{Message = M1, PublicKey = PK1, Signature = S1},
			{Message = M2, PublicKey = PK2, Signature = S2},
			...
		})
--]=]

--!strict
--!optimize 2
--!native

local FieldQuadratic = require("@self/FieldQuadratic")
local FieldPrime = require("@self/FieldPrime")
local SHA512 = require("@self/SHA512")
local Edwards25519 = require("@self/Edwards25519")
local X25519 = require("@self/X25519")
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

export type SignatureEntry = {
	PublicKey: buffer,
	Message: buffer,
	Signature: buffer,
}

local EDDSA = {
	CSPRNG = CSPRNG,
	X25519 = X25519
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

function EDDSA.Sign(Message: buffer, SecretKey: buffer, PublicKey: buffer): buffer
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

function EDDSA.Verify(Message: buffer, PublicKey: buffer, Signature: buffer): boolean
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

	local LastByte = buffer.readu8(Signature, 63)
	if bit32.band(LastByte, 0xE0) ~= 0x00 then
		return false
	end

	local CommitmentBytes = buffer.create(32)
	buffer.copy(CommitmentBytes, 0, Signature, 0, 32)
	local ResponseBytes = buffer.create(32)
	buffer.copy(ResponseBytes, 0, Signature, 32, 32)

	if not FieldQuadratic.IsValidScalar(ResponseBytes) then
		return false
	end

	local PublicPoint = Edwards25519.Decode(PublicKey)
	if not PublicPoint then
		return false
	end

	local CommitmentPoint = Edwards25519.Decode(CommitmentBytes)
	if not CommitmentPoint then
		return false
	end

	local ChallengeInput = ConcatBuffers(CommitmentBytes, PublicKey, Message)
	local ChallengeHash = SHA512(ChallengeInput)
	local ChallengeScalar = FieldQuadratic.DecodeWide(ChallengeHash)

	local ResponseScalar = FieldQuadratic.Decode(ResponseBytes)
	local ResponseBits, ResponseBitCount = FieldQuadratic.Bits(ResponseScalar)
	local SB = Edwards25519.MulG(ResponseBits, ResponseBitCount)

	local ChallengeBits, ChallengeBitCount = FieldQuadratic.Bits(ChallengeScalar)
	local KA = Edwards25519.Mul(PublicPoint, ChallengeBits, ChallengeBitCount)

	local KANiels = Edwards25519.Niels(KA)
	local RKA = Edwards25519.Add(CommitmentPoint, KANiels)

	local SBNiels = Edwards25519.Niels(SB)
	local Difference = Edwards25519.Sub(RKA, SBNiels)

	Difference = Edwards25519.Double(Difference)
	Difference = Edwards25519.Double(Difference)
	Difference = Edwards25519.Double(Difference)

	local DifferenceX = buffer.create(104)
	local DifferenceT = buffer.create(104)
	buffer.copy(DifferenceX, 0, Difference, 0 * 104, 104)
	buffer.copy(DifferenceT, 0, Difference, 3 * 104, 104)

	local XIsZero = FieldPrime.Eqz(DifferenceX)
	local TIsZero = FieldPrime.Eqz(DifferenceT)

	return XIsZero and TIsZero
end

function EDDSA.VerifyBatch(Entries: {SignatureEntry}): boolean
	local Count = #Entries
	if Count == 0 then
		return true
	end

	if Count == 1 then
		local Entry = Entries[1]
		return EDDSA.Verify(Entry.Message, Entry.PublicKey, Entry.Signature)
	end

	local TranscriptData = {}
	local ParsedData = {}

	for Index, Entry in Entries do
		local PublicKey = Entry.PublicKey
		local Message = Entry.Message
		local Signature = Entry.Signature

		if typeof(PublicKey) ~= "buffer" or buffer.len(PublicKey) ~= ED25519_PUBLIC_KEY_SIZE then
			return false
		end

		if typeof(Message) ~= "buffer" then
			return false
		end

		if typeof(Signature) ~= "buffer" or buffer.len(Signature) ~= ED25519_SIGNATURE_SIZE then
			return false
		end

		local LastByte = buffer.readu8(Signature, 63)
		if bit32.band(LastByte, 0xE0) ~= 0x00 then
			return false
		end

		local CommitmentBytes = buffer.create(32)
		buffer.copy(CommitmentBytes, 0, Signature, 0, 32)
		local ResponseBytes = buffer.create(32)
		buffer.copy(ResponseBytes, 0, Signature, 32, 32)

		if not FieldQuadratic.IsValidScalar(ResponseBytes) then
			return false
		end

		local PublicPoint = Edwards25519.Decode(PublicKey)
		if not PublicPoint then
			return false
		end

		local CommitmentPoint = Edwards25519.Decode(CommitmentBytes)
		if not CommitmentPoint then
			return false
		end

		local ChallengeInput = ConcatBuffers(CommitmentBytes, PublicKey, Message)
		local ChallengeHash = SHA512(ChallengeInput)
		local ChallengeScalar = FieldQuadratic.DecodeWide(ChallengeHash)

		local ResponseScalar = FieldQuadratic.Decode(ResponseBytes)

		table.insert(TranscriptData, ChallengeHash)
		table.insert(TranscriptData, ResponseBytes)

		ParsedData[Index] = {
			PublicPoint = PublicPoint,
			CommitmentPoint = CommitmentPoint,
			ChallengeScalar = ChallengeScalar,
			ResponseScalar = ResponseScalar,
		}
	end

	local TranscriptBuffer = ConcatBuffers(table.unpack(TranscriptData))

	local SumS: buffer? = nil
	local Accumulator: buffer? = nil

	for Index, Parsed in ParsedData do
		local IndexBuffer = buffer.create(2)
		buffer.writeu16(IndexBuffer, 0, Index)
		local ZInput = ConcatBuffers(IndexBuffer, TranscriptBuffer)
		local ZHash = SHA512(ZInput)

		local ZBytes = buffer.create(32)
		buffer.copy(ZBytes, 0, ZHash, 0, 32)
		buffer.writeu8(ZBytes, 31, bit32.band(buffer.readu8(ZBytes, 31), 0x0F))
		local Z = FieldQuadratic.Decode(ZBytes)

		local ZS = FieldQuadratic.Mul(Z, Parsed.ResponseScalar)
		if SumS == nil then
			SumS = ZS
		else
			SumS = FieldQuadratic.Add(SumS, ZS)
		end

		local ZH = FieldQuadratic.Mul(Z, Parsed.ChallengeScalar)
		local ZHBits, ZHBitCount = FieldQuadratic.Bits(ZH)
		local ZHA = Edwards25519.Mul(Parsed.PublicPoint, ZHBits, ZHBitCount)

		local ZBits, ZBitCount = FieldQuadratic.Bits(Z)
		local ZR = Edwards25519.Mul(Parsed.CommitmentPoint, ZBits, ZBitCount)

		local ZHANiels = Edwards25519.Niels(ZHA)
		local ZRHA = Edwards25519.Add(ZR, ZHANiels)

		if Accumulator == nil then
			Accumulator = ZRHA
		else
			local ZRHANiels = Edwards25519.Niels(ZRHA)
			Accumulator = Edwards25519.Add(Accumulator, ZRHANiels)
		end
	end

	if SumS == nil or Accumulator == nil then
		return false
	end

	local SumSBits, SumSBitCount = FieldQuadratic.Bits(SumS)
	local LeftSide = Edwards25519.MulG(SumSBits, SumSBitCount)

	local LeftNiels = Edwards25519.Niels(LeftSide)
	local Difference = Edwards25519.Sub(Accumulator :: buffer, LeftNiels)

	Difference = Edwards25519.Double(Difference)
	Difference = Edwards25519.Double(Difference)
	Difference = Edwards25519.Double(Difference)

	local DifferenceX = buffer.create(104)
	local DifferenceT = buffer.create(104)
	buffer.copy(DifferenceX, 0, Difference, 0 * 104, 104)
	buffer.copy(DifferenceT, 0, Difference, 3 * 104, 104)

	local XIsZero = FieldPrime.Eqz(DifferenceX)
	local TIsZero = FieldPrime.Eqz(DifferenceT)

	return XIsZero and TIsZero
end

return EDDSA