--!strict

local Testing = require("./")

type Constants = {
	D: string,
	Z: string,
	PK: number,
	SK: number,
	Message: string,
	CipherText: number,
	SharedSecret: string,
}

local MlKem = require("../Verification/MlKEM")
local CSPRNG = require("../Utilities/CSPRNG")
local SHA3 = require("../Hashing/SHA3")
local XXH32 = require("../Hashing/XXH32")
local Conversions = require("../Utilities/Conversions")

local Constants: {Constants} = require("@self/Constants")

local function GenRandomBytes(Size: number): buffer
	return CSPRNG.RandomBytes(Size)
end

local function MakeBadPubkey(PublicKey: buffer)
	local DataSize = buffer.len(PublicKey) - 32
	for Index = 0, 50 do
		local Position = DataSize - 1 - Index
		if Index < Position then
			local Byte1 = buffer.readu8(PublicKey, Index)
			local Byte2 = buffer.readu8(PublicKey, Position)
			buffer.writeu8(PublicKey, Index, Byte2)
			buffer.writeu8(PublicKey, Position, Byte1)
		end
	end
end

local function FlipBit(Ciphertext: buffer)
	local Size = buffer.len(Ciphertext)
	local RandomByte = math.random(0, Size - 1)
	local RandomBit = math.random(0, 7)
	
	local CurrentByte = buffer.readu8(Ciphertext, RandomByte)
	local FlippedByte = bit32.bxor(CurrentByte, bit32.lshift(1, RandomBit))
	
	buffer.writeu8(Ciphertext, RandomByte, FlippedByte)
end

local function BuffersEqual(A: buffer, B: buffer): boolean
	if buffer.len(A) ~= buffer.len(B) then
		return false
	end
	
	for Index = 0, buffer.len(A) - 1 do
		if buffer.readu8(A, Index) ~= buffer.readu8(B, Index) then
			return false
		end
	end
	
	return true
end

local function GetLastBytes(SecretKey: buffer, Count: number): buffer
	local Size = buffer.len(SecretKey)
	local Result = buffer.create(Count)
	buffer.copy(Result, 0, SecretKey, Size - Count, Count)
	
	return Result
end

Testing.Describe("ML-KEM-1024 Tests", function()
	Testing.Test("BasicTest", function()
		local SeedD = GenRandomBytes(32)
		local SeedZ = GenRandomBytes(32) 
		local SeedM = GenRandomBytes(32)

		local PublicKey, SecretKey = MlKem.MLKEM_1024.KeyGen(SeedD, SeedZ)
		local Ciphertext, SharedSecretSender = MlKem.MLKEM_1024.Encapsulate(PublicKey, SeedM)

		if not Ciphertext then
			error("Ciphertext is nil")
		end
		if not SharedSecretSender then
			error("SharedSecretSender is nil")
		end

		local SharedSecretReceiver = MlKem.MLKEM_1024.Decapsulate(SecretKey, Ciphertext)
		Testing.Expect(BuffersEqual(SharedSecretSender, SharedSecretReceiver)).ToBe(true)
	end)

	Testing.Test("EmptyKeyTest", function()
		local EmptyKey = buffer.create(10)
		local SeedM = GenRandomBytes(32)

		Testing.Expect(function()
			MlKem.MLKEM_1024.Encapsulate(EmptyKey, SeedM)
		end).ToThrow("Invalid public key length")
	end)

	Testing.Test("BadKeyTest", function()
		local SeedD = GenRandomBytes(32)
		local SeedZ = GenRandomBytes(32)
		local SeedM = GenRandomBytes(32)

		local PublicKey, SecretKey = MlKem.MLKEM_1024.KeyGen(SeedD, SeedZ)

		local OriginalKey = buffer.create(buffer.len(PublicKey))
		buffer.copy(OriginalKey, 0, PublicKey, 0, buffer.len(PublicKey))

		MakeBadPubkey(PublicKey)

		local Error = function()
			MlKem.MLKEM_1024.Encapsulate(PublicKey, SeedM)
		end
		
		Testing.Expect(Error).ToThrow("Invalid polynomial coefficient encoding")
	end)

	Testing.Test("BitFlipTest", function()
		local SeedD = GenRandomBytes(32)
		local SeedZ = GenRandomBytes(32)
		local SeedM = GenRandomBytes(32)

		local PublicKey, SecretKey = MlKem.MLKEM_1024.KeyGen(SeedD, SeedZ)
		local Ciphertext, SharedSecretSender = MlKem.MLKEM_1024.Encapsulate(PublicKey, SeedM)

		if not Ciphertext then
			error("Ciphertext is nil")
		end
		if not SharedSecretSender then
			error("SharedSecretSender is nil")
		end

		local OriginalCiphertext = buffer.create(buffer.len(Ciphertext))
		buffer.copy(OriginalCiphertext, 0, Ciphertext, 0, buffer.len(Ciphertext))

		FlipBit(Ciphertext)

		local SharedSecretReceiver = MlKem.MLKEM_1024.Decapsulate(SecretKey, Ciphertext)
		local SeedZFromSecretKey = GetLastBytes(SecretKey, 32)

		local SecretsMatch = BuffersEqual(SharedSecretSender, SharedSecretReceiver)

		local ExpectedFailureSecret = buffer.create(32 + buffer.len(Ciphertext))
		buffer.copy(ExpectedFailureSecret, 0, SeedZFromSecretKey, 0, 32)
		buffer.copy(ExpectedFailureSecret, 32, Ciphertext, 0, buffer.len(Ciphertext))

		local _, ExpectedOutput = SHA3.SHAKE256(ExpectedFailureSecret, 32)
		local ExpectedSecret = buffer.create(32)
		buffer.copy(ExpectedSecret, 0, ExpectedOutput, 0, 32)

		local ReceiverMatchesExpected = BuffersEqual(SharedSecretReceiver, ExpectedSecret)

		Testing.Expect(SecretsMatch).ToBe(false)
		Testing.Expect(ReceiverMatchesExpected).ToBe(true)
	end)

	Testing.Test("KeySizes", function()
		local SeedD = GenRandomBytes(32)
		local SeedZ = GenRandomBytes(32)
		local PublicKey, SecretKey = MlKem.MLKEM_1024.KeyGen(SeedD, SeedZ)

		Testing.Expect(buffer.len(PublicKey)).ToBe(1568)
		Testing.Expect(buffer.len(SecretKey)).ToBe(3168)

		local SeedM = GenRandomBytes(32)
		local Ciphertext, SharedSecret = MlKem.MLKEM_1024.Encapsulate(PublicKey, SeedM)

		if not Ciphertext then
			error("Ciphertext is nil")
		end
		if not SharedSecret then
			error("SharedSecret is nil")
		end

		Testing.Expect(buffer.len(Ciphertext)).ToBe(1568)
		Testing.Expect(buffer.len(SharedSecret)).ToBe(32)
	end)
	
	for TestIndex, TestVector in ipairs(Constants) do
		Testing.Test(`KAT_{TestIndex}`, function()
			local D = Conversions.FromHex(TestVector.D)
			local Z = Conversions.FromHex(TestVector.Z)
			local ExpectedPK = TestVector.PK
			local ExpectedSK = TestVector.SK
			local Message = Conversions.FromHex(TestVector.Message)
			local ExpectedCT = TestVector.CipherText

			local GeneratedPK, GeneratedSK = MlKem.MLKEM_1024.KeyGen(D, Z)

			Testing.Expect(XXH32(buffer.fromstring(Conversions.ToHex(GeneratedPK)))).ToBe(ExpectedPK)
			Testing.Expect(XXH32(buffer.fromstring(Conversions.ToHex(GeneratedSK)))).ToBe(ExpectedSK)

			local GeneratedCT, GeneratedSS = MlKem.MLKEM_1024.Encapsulate(GeneratedPK, Message)

			Testing.Expect(GeneratedCT).ToBeDefined()
			Testing.Expect(GeneratedSS).ToBeDefined()

			if GeneratedCT and GeneratedSS then
				Testing.Expect(XXH32(buffer.fromstring(Conversions.ToHex(GeneratedCT)))).ToBe(ExpectedCT)

				if TestVector.SharedSecret then
					local ExpectedSS = Conversions.FromHex(TestVector.SharedSecret)
					Testing.Expect(BuffersEqual(GeneratedSS, ExpectedSS)).ToBe(true)
				end

				local RecoveredSS = MlKem.MLKEM_1024.Decapsulate(GeneratedSK, GeneratedCT)
				Testing.Expect(BuffersEqual(GeneratedSS, RecoveredSS)).ToBe(true)
			end
		end)
	end
end)

Testing.Complete()

return 0