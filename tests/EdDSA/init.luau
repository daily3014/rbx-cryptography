--!strict
local Testing = require("./")

type Ed25519TestVector = {
	PrivateKey: string,
	PublicKey: string,
	Message: string,
	Signature: string
}

type X25519TestVector = {
	Description: string,
	SecretKey: string,
	PublicKey: string,
	Expected: string
}

local Algorithm = require("../Verification/EdDSA")
local MaskedX25519 = Algorithm.MaskedX25519
local RandomBytes = Algorithm.RandomBytes

local function FromHex(Hex: string): buffer
	local Length = #Hex
	local Buffer = buffer.create(Length / 2)
	for Index = 0, Length - 2, 2 do
		buffer.writeu8(Buffer, Index / 2, tonumber(string.sub(Hex, Index + 1, Index + 2), 16) :: number)
	end

	return Buffer
end

local function ToHex(Buffer: buffer) : string
	local Hex = ""
	for Index = 0, buffer.len(Buffer) - 1 do
		Hex ..= string.format("%02x", buffer.readu8(Buffer, Index))
	end

	return Hex
end

local function IsValidX25519Key(Key: buffer): (boolean, string)
	if buffer.len(Key) ~= 32 then
		return false, "Key must be exactly 32 bytes"
	end

	local FirstByte = buffer.readu8(Key, 0)
	local LastByte = buffer.readu8(Key, 31)

	if bit32.band(FirstByte, 0x07) ~= 0 then
		return false, "First byte must have lowest 3 bits set to 0 (X25519 clamping)"
	end

	if bit32.band(LastByte, 0x80) ~= 0 then
		return false, "Last byte must have highest bit set to 0 (X25519 clamping)"
	end

	if bit32.band(LastByte, 0x40) == 0 then
		return false, "Last byte must have second highest bit set to 1 (X25519 clamping)"
	end

	local AllZeros = true
	local AllOnes = true

	for I = 0, 31 do
		local Byte = buffer.readu8(Key, I)
		if Byte ~= 0 then
			AllZeros = false
		end
		if Byte ~= 255 then
			AllOnes = false
		end
	end

	if AllZeros then
		return false, "Key cannot be all zeros (weak key)"
	end

	if AllOnes then
		return false, "Key cannot be all ones (weak key)"
	end

	local IsIdentity = true
	if buffer.readu8(Key, 0) ~= 1 then
		IsIdentity = false
	else
		for I = 1, 31 do
			if buffer.readu8(Key, I) ~= 0 then
				IsIdentity = false
				break
			end
		end
	end

	if IsIdentity then
		return false, "Key cannot be the identity element"
	end

	return true, "Valid X25519 key"
end

local function Exchange(SecretKey: buffer, PublicKey: buffer): buffer
	local MaskedSecretKey = MaskedX25519.Mask(SecretKey)
	MaskedSecretKey = MaskedX25519.Remask(MaskedSecretKey)
	local SharedSecret, _ = MaskedX25519.Exchange(MaskedSecretKey, PublicKey)
	
	return SharedSecret
end

local Ed25519_TestVectors: {Ed25519TestVector} = require("@self/Constants")
local Test = Testing.Test
local Expect = Testing.Expect

for Index, TestVector in Ed25519_TestVectors do
	Test(`Ed25519 Public Key Test {Index}`, function()
		local PrivateKey = TestVector.PrivateKey
		local ExpectedPublicKey = TestVector.PublicKey
		local PrivateKeyBytes = FromHex(PrivateKey)
		local GeneratedPublicKeyBytes = Algorithm.PublicKey(PrivateKeyBytes)
		local GeneratedPublicKey = ToHex(GeneratedPublicKeyBytes)
		Expect(GeneratedPublicKey).ToBe(ExpectedPublicKey)
	end)
end

for Index, TestVector in Ed25519_TestVectors do
	Test(`Ed25519 Signature Generation Test {Index}`, function()
		local PrivateKey = TestVector.PrivateKey
		local PublicKey = TestVector.PublicKey
		local Message = TestVector.Message
		local PrivateKeyBytes = FromHex(PrivateKey)
		local PublicKeyBytes = FromHex(PublicKey)
		local MessageBytes = FromHex(Message)
		local GeneratedSignatureBytes = Algorithm.Sign(PrivateKeyBytes, PublicKeyBytes, MessageBytes)
		local IsValid = Algorithm.Verify(PublicKeyBytes, MessageBytes, GeneratedSignatureBytes)
		Expect(IsValid).ToBeTruthy()
	end)
end

for Index, TestVector in Ed25519_TestVectors do
	Test(`Ed25519 Signature Verification Test {Index}`, function()
		local PublicKey = TestVector.PublicKey
		local Message = TestVector.Message
		local Signature = TestVector.Signature
		local PublicKeyBytes = FromHex(PublicKey)
		local MessageBytes = FromHex(Message)
		local SignatureBytes = FromHex(Signature)
		local IsValid = Algorithm.Verify(PublicKeyBytes, MessageBytes, SignatureBytes)
		Expect(IsValid).ToBeTruthy()
	end)
end

local X25519_TestVectors: {X25519TestVector} = {
	{
		Description = "RFC 7748 Section 5.2 Test Vector 1",
		SecretKey = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
		PublicKey = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
		Expected = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
	},
	{
		Description = "RFC 7748 Section 5.2 Test Vector 2 (Zero Result)",
		SecretKey = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
		PublicKey = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
		Expected = "0000000000000000000000000000000000000000000000000000000000000000"
	},
	{
		Description = "RFC 7748 Section 5.2 Test Vector 3 (Initial Check)",
		SecretKey = "0900000000000000000000000000000000000000000000000000000000000000",
		PublicKey = "0900000000000000000000000000000000000000000000000000000000000000",
		Expected = "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
	},
	{
		Description = "CPace Zero Input",
		SecretKey = "af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff",
		PublicKey = "0000000000000000000000000000000000000000000000000000000000000000",
		Expected = "0000000000000000000000000000000000000000000000000000000000000000"
	},
	{
		Description = "CPace One Input",
		SecretKey = "af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff",
		PublicKey = "0100000000000000000000000000000000000000000000000000000000000000",
		Expected = "0000000000000000000000000000000000000000000000000000000000000000"
	},
	{
		Description = "CPace Non-Zero Result",
		SecretKey = "af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff",
		PublicKey = "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
		Expected = "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175"
	}
}

for Index, TestVector in X25519_TestVectors do
	Test(`Masked X25519 {TestVector.Description}`, function()
		local SecretKeyBytes = FromHex(TestVector.SecretKey)
		local PublicKeyBytes = FromHex(TestVector.PublicKey)
		local Result = Exchange(SecretKeyBytes, PublicKeyBytes)
		local ResultHex = ToHex(Result)
		Expect(ResultHex).ToBe(TestVector.Expected)
	end)
end

Test("Generated X25519 Keys Validation (1000 Keys)", function()
	local ValidCount = 0
	local InvalidCount = 0
	local InvalidReasons = {}

	for I = 1, 1e3 do
		local GeneratedKey = RandomBytes.Random()
		local IsValid, Message = IsValidX25519Key(GeneratedKey)

		if IsValid then
			ValidCount = ValidCount + 1
		else
			InvalidCount = InvalidCount + 1
			if not InvalidReasons[Message] then
				InvalidReasons[Message] = 0
			end
			InvalidReasons[Message] = InvalidReasons[Message] + 1
		end
	end

	if InvalidCount > 0 then
		print("Invalid key reasons:")
		for Reason, Count in InvalidReasons do
			print(string.format("  %s: %d", Reason, Count))
		end
	end

	Expect(ValidCount).ToBe(1e3)
	Expect(InvalidCount).ToBe(0)
end)

Testing.Complete()
return 0