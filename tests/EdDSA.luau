--[=[
	Ed25519 Wycheproof Test Suite + Batch Verification Tests
	
	Test Vector Source:
		https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/ed25519_test.json
	
	Test Categories:
		Valid - Ordinary valid signatures
		InvalidSignature - Edge case values (0, group order)
		SignatureMalleability - S value range checks
		TruncatedSignature - Shortened signatures
		SignatureWithGarbage - Extra bytes appended
		InvalidEncoding - Malformed encodings
		BatchVerification - Batch verification functionalty
--]=]
--!strict
--!optimize 2

local Http = game:GetService("HttpService")
local Testing = require("./")
local Cryptography = require("../")
local Ed25519 = Cryptography.Verification.EdDSA
local CSPRNG = Ed25519.CSPRNG
local Conversions = Cryptography.Utilities.Conversions
local FromHex = Conversions.FromHex

type PublicKeyInfo = {
	type: string,
	curve: string,
	keySize: number,
	pk: string,
}

type WycheproofTest = {
	tcId: number,
	comment: string?,
	flags: {string}?,
	msg: string,
	sig: string,
	result: string,
}

type WycheproofGroup = {
	type: string,
	source: {name: string, version: string}?,
	publicKey: PublicKeyInfo,
	publicKeyDer: string?,
	publicKeyPem: string?,
	tests: {WycheproofTest},
}

type WycheproofData = {
	algorithm: string,
	schema: string,
	numberOfTests: number,
	testGroups: {WycheproofGroup},
}

local WYCHEPROOF_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/ed25519_test.json"

local function FetchTestVectors(): WycheproofData
	local Response = Http:GetAsync(WYCHEPROOF_URL)
	return Http:JSONDecode(Response) :: WycheproofData
end

Testing.Describe("Ed25519 Wycheproof Tests", function()
	local Data = FetchTestVectors()

	for GroupIndex, Group in ipairs(Data.testGroups) do
		local PublicKeyHex = Group.publicKey.pk
		local PublicKeyBytes = FromHex(PublicKeyHex)
		local SourceName = if Group.source then Group.source.name else "unknown"

		Testing.Describe(`Group_{GroupIndex}: {Group.type} (Source: {SourceName})`, function()
			for _, Test in ipairs(Group.tests) do
				local TestId = Test.tcId
				local ExpectedResult = Test.result
				local Comment = Test.comment or ""

				local TestName = `Test_{TestId}`
				if Comment ~= "" then
					TestName = `Test_{TestId}_{Comment:sub(1, 30):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local MessageBytes = FromHex(Test.msg)
					local SignatureBytes = FromHex(Test.sig)

					local Success, IsValid = pcall(function()
						return Ed25519.Verify(MessageBytes, PublicKeyBytes, SignatureBytes)
					end)

					if ExpectedResult == "valid" then
						Testing.Expect(Success).ToBe(true)
						Testing.Expect(IsValid).ToBe(true)
					elseif ExpectedResult == "invalid" then
						local VerificationFailed = not Success or not IsValid
						Testing.Expect(VerificationFailed).ToBe(true)
					elseif ExpectedResult == "acceptable" then
						Testing.Expect(true).ToBe(true)
					end
				end)
			end
		end)
	end
end)

Testing.Describe("Ed25519 Batch Verification Tests", function()

	Testing.Describe("Basic Batch Operations", function()

		Testing.Test("Empty batch returns true", function()
			local Result = Ed25519.VerifyBatch({})
			Testing.Expect(Result).ToBe(true)
		end)

		Testing.Test("Single valid signature batch", function()
			local SecretKey = CSPRNG.RandomBytes(32)
			local PublicKey = Ed25519.PublicKey(SecretKey)
			local GivenMessage = buffer.fromstring("Test message")
			local Signature = Ed25519.Sign(GivenMessage, SecretKey, PublicKey)

			local Result = Ed25519.VerifyBatch({
				{Message = GivenMessage, PublicKey = PublicKey, Signature = Signature}
			})
			Testing.Expect(Result).ToBe(true)
		end)

		Testing.Test("Single invalid signature batch", function()
			local SecretKey = CSPRNG.RandomBytes(32)
			local PublicKey = Ed25519.PublicKey(SecretKey)
			local GivenMessage = buffer.fromstring("Test message")
			local Signature = Ed25519.Sign(GivenMessage, SecretKey, PublicKey)

			local WrongMessage = buffer.fromstring("Wrong message")

			local Result = Ed25519.VerifyBatch({
				{Message = WrongMessage, PublicKey = PublicKey, Signature = Signature}
			})
			Testing.Expect(Result).ToBe(false)
		end)

	end)

	Testing.Describe("Multiple Signatures - Same Key", function()

		Testing.Test("Two valid signatures, same key", function()
			local SecretKey = CSPRNG.RandomBytes(32)
			local PublicKey = Ed25519.PublicKey(SecretKey)

			local Message1 = buffer.fromstring("Message one")
			local Message2 = buffer.fromstring("Message two")
			local Signature1 = Ed25519.Sign(Message1, SecretKey, PublicKey)
			local Signature2 = Ed25519.Sign(Message2, SecretKey, PublicKey)

			local Result = Ed25519.VerifyBatch({
				{Message = Message1, PublicKey = PublicKey, Signature = Signature1},
				{Message = Message2, PublicKey = PublicKey, Signature = Signature2},
			})
			Testing.Expect(Result).ToBe(true)
		end)

		Testing.Test("Five valid signatures, same key", function()
			local SecretKey = CSPRNG.RandomBytes(32)
			local PublicKey = Ed25519.PublicKey(SecretKey)

			local Entries = {}
			for I = 1, 5 do
				local GivenMessage = buffer.fromstring(`Message number {I}`)
				local Signature = Ed25519.Sign(GivenMessage, SecretKey, PublicKey)
				table.insert(Entries, {
					Message = GivenMessage,
					PublicKey = PublicKey,
					Signature = Signature,
				})
			end

			local Result = Ed25519.VerifyBatch(Entries)
			Testing.Expect(Result).ToBe(true)
		end)

		Testing.Test("One invalid among valid - same key", function()
			local SecretKey = CSPRNG.RandomBytes(32)
			local PublicKey = Ed25519.PublicKey(SecretKey)

			local Message1 = buffer.fromstring("Valid message 1")
			local Message2 = buffer.fromstring("Valid message 2")
			local Message3 = buffer.fromstring("Valid message 3")

			local Signature1 = Ed25519.Sign(Message1, SecretKey, PublicKey)
			local Signature2 = Ed25519.Sign(Message2, SecretKey, PublicKey)
			local Signature3 = Ed25519.Sign(Message3, SecretKey, PublicKey)

			local WrongMessage = buffer.fromstring("Tampered message")

			local Result = Ed25519.VerifyBatch({
				{Message = Message1, PublicKey = PublicKey, Signature = Signature1},
				{Message = WrongMessage, PublicKey = PublicKey, Signature = Signature2},
				{Message = Message3, PublicKey = PublicKey, Signature = Signature3},
			})
			Testing.Expect(Result).ToBe(false)
		end)

	end)

	Testing.Describe("Multiple Signatures - Different Keys", function()

		Testing.Test("Two valid signatures, different keys", function()
			local SecretKey1 = CSPRNG.RandomBytes(32)
			local PublicKey1 = Ed25519.PublicKey(SecretKey1)
			local SecretKey2 = CSPRNG.RandomBytes(32)
			local PublicKey2 = Ed25519.PublicKey(SecretKey2)

			local Message1 = buffer.fromstring("Message from key 1")
			local Message2 = buffer.fromstring("Message from key 2")
			local Signature1 = Ed25519.Sign(Message1, SecretKey1, PublicKey1)
			local Signature2 = Ed25519.Sign(Message2, SecretKey2, PublicKey2)

			local Result = Ed25519.VerifyBatch({
				{Message = Message1, PublicKey = PublicKey1, Signature = Signature1},
				{Message = Message2, PublicKey = PublicKey2, Signature = Signature2},
			})
			Testing.Expect(Result).ToBe(true)
		end)

		Testing.Test("Eight valid signatures, different keys", function()
			local Entries = {}
			for I = 1, 8 do
				local SecretKey = CSPRNG.RandomBytes(32)
				local PublicKey = Ed25519.PublicKey(SecretKey)
				local GivenMessage = buffer.fromstring(`Unique message {I} with random data`)
				local Signature = Ed25519.Sign(GivenMessage, SecretKey, PublicKey)
				table.insert(Entries, {
					PublicKey = PublicKey,
					Message = GivenMessage,
					Signature = Signature,
				})
			end

			local Result = Ed25519.VerifyBatch(Entries)
			Testing.Expect(Result).ToBe(true)
		end)

		Testing.Test("One invalid among valid - different keys", function()
			local SecretKey1 = CSPRNG.RandomBytes(32)
			local PublicKey1 = Ed25519.PublicKey(SecretKey1)
			local SecretKey2 = CSPRNG.RandomBytes(32)
			local PublicKey2 = Ed25519.PublicKey(SecretKey2)
			local SecretKey3 = CSPRNG.RandomBytes(32)
			local PublicKey3 = Ed25519.PublicKey(SecretKey3)

			local Message1 = buffer.fromstring("Message 1")
			local Message2 = buffer.fromstring("Message 2")
			local Message3 = buffer.fromstring("Message 3")

			local Signature1 = Ed25519.Sign(Message1, SecretKey1, PublicKey1)
			local Signature2 = Ed25519.Sign(Message2, SecretKey2, PublicKey2)
			local Signature3 = Ed25519.Sign(Message3, SecretKey3, PublicKey3)

			local Result = Ed25519.VerifyBatch({
				{Message = Message1, PublicKey = PublicKey1, Signature = Signature1},
				{Message = Message2, PublicKey = PublicKey2, Signature = Signature2},
				{Message = Message3, PublicKey = PublicKey1, Signature = Signature3},
			})
			Testing.Expect(Result).ToBe(false)
		end)

	end)

	Testing.Describe("Determinism", function()

		Testing.Test("Same batch produces same result", function()
			local SecretKey1 = CSPRNG.RandomBytes(32)
			local PublicKey1 = Ed25519.PublicKey(SecretKey1)
			local SecretKey2 = CSPRNG.RandomBytes(32)
			local PublicKey2 = Ed25519.PublicKey(SecretKey2)

			local Message1 = buffer.fromstring("Determinism test 1")
			local Message2 = buffer.fromstring("Determinism test 2")
			local Signature1 = Ed25519.Sign(Message1, SecretKey1, PublicKey1)
			local Signature2 = Ed25519.Sign(Message2, SecretKey2, PublicKey2)

			local Entries = {
				{Message = Message1, PublicKey = PublicKey1, Signature = Signature1},
				{Message = Message2, PublicKey = PublicKey2, Signature = Signature2},
			}

			local Result1 = Ed25519.VerifyBatch(Entries)
			local Result2 = Ed25519.VerifyBatch(Entries)
			local Result3 = Ed25519.VerifyBatch(Entries)

			Testing.Expect(Result1).ToBe(true)
			Testing.Expect(Result2).ToBe(true)
			Testing.Expect(Result3).ToBe(true)
		end)

	end)

	Testing.Describe("Edge Cases", function()

		Testing.Test("Invalid signature length rejected", function()
			local SecretKey = CSPRNG.RandomBytes(32)
			local PublicKey = Ed25519.PublicKey(SecretKey)
			local GivenMessage = buffer.fromstring("Test")
			local ShortSignature = buffer.create(32)

			Testing.Expect(function()
				Ed25519.VerifyBatch({
					{Message = GivenMessage, PublicKey = PublicKey, Signature = ShortSignature}
				})
			end).ToThrow("Signature must be exactly 64 bytes long, got 32 bytes")
		end)

		Testing.Test("Invalid public key length rejected", function()
			local SecretKey = CSPRNG.RandomBytes(32)
			local PublicKey = Ed25519.PublicKey(SecretKey)
			local GivenMessage = buffer.fromstring("Test")
			local Signature = Ed25519.Sign(GivenMessage, SecretKey, PublicKey)
			local ShortPublicKey = buffer.create(16)

			Testing.Expect(function()
				Ed25519.VerifyBatch({
					{Message = GivenMessage, PublicKey = ShortPublicKey, Signature = Signature}
				})
			end).ToThrow("PublicKey must be exactly 32 bytes long, got 16 bytes")
		end)

		Testing.Test("Empty message works", function()
			local SecretKey = CSPRNG.RandomBytes(32)
			local PublicKey = Ed25519.PublicKey(SecretKey)
			local EmptyMessage = buffer.create(0)
			local Signature = Ed25519.Sign(EmptyMessage, SecretKey, PublicKey)

			local Result = Ed25519.VerifyBatch({
				{Message = EmptyMessage, PublicKey = PublicKey, Signature = Signature}
			})
			Testing.Expect(Result).ToBe(true)
		end)

		Testing.Test("Large message works", function()
			local SecretKey = CSPRNG.RandomBytes(32)
			local PublicKey = Ed25519.PublicKey(SecretKey)
			local LargeMessage = buffer.create(10000)
			for I = 0, 9999 do
				buffer.writeu8(LargeMessage, I, I % 256)
			end
			local Signature = Ed25519.Sign(LargeMessage, SecretKey, PublicKey)

			local Result = Ed25519.VerifyBatch({
				{Message = LargeMessage, PublicKey = PublicKey, Signature = Signature}
			})
			Testing.Expect(Result).ToBe(true)
		end)

	end)

	Testing.Describe("Consistency with Single Verify", function()

		Testing.Test("Batch and single verify agree on valid", function()
			local SecretKey = CSPRNG.RandomBytes(32)
			local PublicKey = Ed25519.PublicKey(SecretKey)
			local GivenMessage = buffer.fromstring("Consistency test")
			local Signature = Ed25519.Sign(GivenMessage, SecretKey, PublicKey)

			local SingleResult = Ed25519.Verify(GivenMessage, PublicKey, Signature)
			local BatchResult = Ed25519.VerifyBatch({
				{Message = GivenMessage, PublicKey = PublicKey, Signature = Signature}
			})

			Testing.Expect(SingleResult).ToBe(true)
			Testing.Expect(BatchResult).ToBe(true)
		end)

		Testing.Test("Batch and single verify agree on invalid", function()
			local SecretKey = CSPRNG.RandomBytes(32)
			local PublicKey = Ed25519.PublicKey(SecretKey)
			local GivenMessage = buffer.fromstring("Original")
			local Signature = Ed25519.Sign(GivenMessage, SecretKey, PublicKey)
			local WrongMessage = buffer.fromstring("Tampered")

			local SingleResult = Ed25519.Verify(WrongMessage, PublicKey, Signature)
			local BatchResult = Ed25519.VerifyBatch({
				{Message = WrongMessage, PublicKey = PublicKey, Signature = Signature}
			})

			Testing.Expect(SingleResult).ToBe(false)
			Testing.Expect(BatchResult).ToBe(false)
		end)

	end)

end)

Testing.Complete()

return 0