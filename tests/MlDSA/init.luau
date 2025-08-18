--!strict
local Testing = require("./")

type Constants = {
	Seed: string,
	Pkey: string,
	Skey: string,
	Mlen: string,
	Message: string,
	CtxLen: string,
	Context: string,
	Rnd: string,
	Signature: string
}

local MLDSA = require("../Verification/MlDSA")
local Conversions = require("../Utilities/Conversions")
local Constants: {Constants} = require("@self/Constants")

local function GetMLDSAVariant(SecurityLevel: number)
	if SecurityLevel == 44 then
		return MLDSA.ML_DSA_44
	elseif SecurityLevel == 65 then
		return MLDSA.ML_DSA_65
	elseif SecurityLevel == 87 then
		return MLDSA.ML_DSA_87
	else
		error("Invalid ML-DSA security level")
	end
end

local function BuffersEqual(Buffer1: buffer, Buffer2: buffer): boolean
	if buffer.len(Buffer1) ~= buffer.len(Buffer2) then
		return false
	end

	for I = 0, buffer.len(Buffer1) - 1 do
		if buffer.readu8(Buffer1, I) ~= buffer.readu8(Buffer2, I) then
			return false
		end
	end

	return true
end

Testing.Describe("ML-DSA-87 Known Answer Tests", function()
	for TestIndex, TestVector in ipairs(Constants) do
		task.wait()
		Testing.Test(`Test Vector {TestIndex}`, function()
			local Seed = Conversions.FromHex(TestVector.Seed)
			local ExpectedPubKey = TestVector.Pkey
			local ExpectedSecKey = TestVector.Skey
			local Message = Conversions.FromHex(TestVector.Message)
			local Context = Conversions.FromHex(TestVector.Context)
			local Randomness = Conversions.FromHex(TestVector.Rnd)
			local ExpectedSignature = TestVector.Signature

			Testing.Expect(buffer.len(Seed)).ToBe(32)
			Testing.Expect(buffer.len(Randomness)).ToBe(32)

			local Variant = GetMLDSAVariant(87)
			local ComputedPubKey = buffer.create(Variant.PubKeyByteLen)
			local ComputedSecKey = buffer.create(Variant.SecKeyByteLen)
			local ComputedSignature = buffer.create(Variant.SigByteLen)

			Variant.KeyGen(Seed, ComputedPubKey, ComputedSecKey)

			local HasSigned = Variant.Sign(Randomness, ComputedSecKey, Message, Context, ComputedSignature)
			Testing.Expect(HasSigned).ToBe(true)

			local IsValid = Variant.Verify(ComputedPubKey, Message, Context, ComputedSignature)
			Testing.Expect(IsValid).ToBe(true)

			local ComputedPubKeyHex = Conversions.ToHex(ComputedPubKey)
			local ComputedSecKeyHex = Conversions.ToHex(ComputedSecKey)
			local ComputedSignatureHex = Conversions.ToHex(ComputedSignature)

			Testing.Expect(ComputedPubKeyHex).ToBe(ExpectedPubKey)
			Testing.Expect(ComputedSecKeyHex).ToBe(ExpectedSecKey)
			Testing.Expect(ComputedSignatureHex).ToBe(ExpectedSignature)
		end)
	end
end)

Testing.Describe("ML-DSA Functional Tests", function()
	Testing.Test("All Variants Basic Functionality", function()
		local Message = buffer.fromstring("Hello, ML-DSA!")
		local Context = buffer.create(0)

		local PubKey44, SecKey44 = MLDSA.ML_DSA_44.GenerateKeys()
		local Randomness44 = buffer.create(32)
		local Signature44 = buffer.create(MLDSA.ML_DSA_44.SigByteLen)

		local Success44 = MLDSA.ML_DSA_44.Sign(Randomness44, SecKey44, Message, Context, Signature44)
		Testing.Expect(Success44).ToBe(true)

		local Valid44 = MLDSA.ML_DSA_44.Verify(PubKey44, Message, Context, Signature44)
		Testing.Expect(Valid44).ToBe(true)

		local PubKey65, SecKey65 = MLDSA.ML_DSA_65.GenerateKeys()
		local Randomness65 = buffer.create(32)
		local Signature65 = buffer.create(MLDSA.ML_DSA_65.SigByteLen)

		local Success65 = MLDSA.ML_DSA_65.Sign(Randomness65, SecKey65, Message, Context, Signature65)
		Testing.Expect(Success65).ToBe(true)

		local Valid65 = MLDSA.ML_DSA_65.Verify(PubKey65, Message, Context, Signature65)
		Testing.Expect(Valid65).ToBe(true)

		local PubKey87, SecKey87 = MLDSA.ML_DSA_87.GenerateKeys()
		local Randomness87 = buffer.create(32)
		local Signature87 = buffer.create(MLDSA.ML_DSA_87.SigByteLen)

		local Success87 = MLDSA.ML_DSA_87.Sign(Randomness87, SecKey87, Message, Context, Signature87)
		Testing.Expect(Success87).ToBe(true)

		local Valid87 = MLDSA.ML_DSA_87.Verify(PubKey87, Message, Context, Signature87)
		Testing.Expect(Valid87).ToBe(true)

		Testing.Expect(buffer.len(Signature44)).ToBe(2420)
		Testing.Expect(buffer.len(Signature65)).ToBe(3309)
		Testing.Expect(buffer.len(Signature87)).ToBe(4627)
	end)

	Testing.Test("Context Length Validation", function()
		local PubKey, SecKey = MLDSA.ML_DSA_44.GenerateKeys()
		local Message = buffer.fromstring("test message")
		local Randomness = buffer.create(32)
		local Signature = buffer.create(MLDSA.ML_DSA_44.SigByteLen)

		local LongContext = buffer.create(256)
		buffer.fill(LongContext, 0, 0xAA, 256)

		local SignSuccess = MLDSA.ML_DSA_44.Sign(Randomness, SecKey, Message, LongContext, Signature)
		Testing.Expect(SignSuccess).ToBe(false)

		local VerifySuccess = MLDSA.ML_DSA_44.Verify(PubKey, Message, LongContext, Signature)
		Testing.Expect(VerifySuccess).ToBe(false)

		local ValidContext = buffer.create(255)
		buffer.fill(ValidContext, 0, 0xBB, 255)

		local ValidSignSuccess = MLDSA.ML_DSA_44.Sign(Randomness, SecKey, Message, ValidContext, Signature)
		Testing.Expect(ValidSignSuccess).ToBe(true)

		if ValidSignSuccess then
			local ValidVerifySuccess = MLDSA.ML_DSA_44.Verify(PubKey, Message, ValidContext, Signature)
			Testing.Expect(ValidVerifySuccess).ToBe(true)
		end
	end)

	Testing.Test("Empty Message and Context", function()
		local PubKey, SecKey = MLDSA.ML_DSA_44.GenerateKeys()
		local EmptyMessage = buffer.create(0)
		local EmptyContext = buffer.create(0)
		local Randomness = buffer.create(32)
		local Signature = buffer.create(MLDSA.ML_DSA_44.SigByteLen)

		local SignSuccess = MLDSA.ML_DSA_44.Sign(Randomness, SecKey, EmptyMessage, EmptyContext, Signature)
		Testing.Expect(SignSuccess).ToBe(true)

		if SignSuccess then
			local VerifySuccess = MLDSA.ML_DSA_44.Verify(PubKey, EmptyMessage, EmptyContext, Signature)
			Testing.Expect(VerifySuccess).ToBe(true)
		end
	end)

	Testing.Test("Wrong Message/Context Rejection", function()
		local PubKey, SecKey = MLDSA.ML_DSA_44.GenerateKeys()
		local Message = buffer.fromstring("correct message")
		local Context = buffer.fromstring("correct context")
		local Randomness = buffer.create(32)
		local Signature = buffer.create(MLDSA.ML_DSA_44.SigByteLen)

		local SignSuccess = MLDSA.ML_DSA_44.Sign(Randomness, SecKey, Message, Context, Signature)
		Testing.Expect(SignSuccess).ToBe(true)

		if SignSuccess then
			local ValidVerify = MLDSA.ML_DSA_44.Verify(PubKey, Message, Context, Signature)
			Testing.Expect(ValidVerify).ToBe(true)

			local WrongMessage = buffer.fromstring("wrong message")
			local WrongMessageVerify = MLDSA.ML_DSA_44.Verify(PubKey, WrongMessage, Context, Signature)
			Testing.Expect(WrongMessageVerify).ToBe(false)

			local WrongContext = buffer.fromstring("wrong context")
			local WrongContextVerify = MLDSA.ML_DSA_44.Verify(PubKey, Message, WrongContext, Signature)
			Testing.Expect(WrongContextVerify).ToBe(false)
		end
	end)

	Testing.Test("Deterministic vs Hedged Signing", function()
		local Seed = buffer.create(32)
		for I = 0, 31 do
			buffer.writeu8(Seed, I, I)
		end

		local PubKey = buffer.create(MLDSA.ML_DSA_44.PubKeyByteLen)
		local SecKey = buffer.create(MLDSA.ML_DSA_44.SecKeyByteLen)
		MLDSA.ML_DSA_44.KeyGen(Seed, PubKey, SecKey)

		local Message = buffer.fromstring("deterministic test")
		local Context = buffer.create(0)

		local ZeroRand = buffer.create(32)
		buffer.fill(ZeroRand, 0, 0, 32)

		local Sig1 = buffer.create(MLDSA.ML_DSA_44.SigByteLen)
		local Sig2 = buffer.create(MLDSA.ML_DSA_44.SigByteLen)

		local Success1 = MLDSA.ML_DSA_44.Sign(ZeroRand, SecKey, Message, Context, Sig1)
		local Success2 = MLDSA.ML_DSA_44.Sign(ZeroRand, SecKey, Message, Context, Sig2)

		Testing.Expect(Success1).ToBe(true)
		Testing.Expect(Success2).ToBe(true)

		Testing.Expect(BuffersEqual(Sig1, Sig2)).ToBe(true)

		Testing.Expect(MLDSA.ML_DSA_44.Verify(PubKey, Message, Context, Sig1)).ToBe(true)
		Testing.Expect(MLDSA.ML_DSA_44.Verify(PubKey, Message, Context, Sig2)).ToBe(true)
	end)
end)

Testing.Complete()

return 0