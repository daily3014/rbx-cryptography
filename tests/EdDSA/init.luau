--!strict
local Testing = require("./")
type Ed25519TestVector = {
	PrivateKey: string,
	PublicKey: string,
	Message: string,
	Signature: string
}

local Algorithm = require("../Verification/EdDSA")

local function HexToBuffer(Hex: string): buffer
	local Length = #Hex
	local Buffer = buffer.create(Length / 2)
	for Index = 0, Length - 2, 2 do
		buffer.writeu8(Buffer, Index / 2, tonumber(string.sub(Hex, Index + 1, Index + 2), 16) :: number)
	end

	return Buffer
end

local function BufferToHex(Buffer: buffer): string
	local Hex = ""
	for Index = 0, buffer.len(Buffer) - 1 do
		Hex ..= string.format("%02x", buffer.readu8(Buffer, Index))
	end

	return Hex
end

local Ed25519_TestVectors: {Ed25519TestVector} = require("@self/Constants")

local Test = Testing.Test
local Expect = Testing.Expect

for Index, TestVector in Ed25519_TestVectors do
	Test(`Ed25519 Public Key Test {Index}`, function()
		local PrivateKey = TestVector.PrivateKey
		local ExpectedPublicKey = TestVector.PublicKey
		local PrivateKeyBytes = HexToBuffer(PrivateKey)
		local GeneratedPublicKeyBytes = Algorithm.PublicKey(PrivateKeyBytes)
		local GeneratedPublicKey = BufferToHex(GeneratedPublicKeyBytes)

		Expect(GeneratedPublicKey).ToBe(ExpectedPublicKey)
	end)
end

for Index, TestVector in Ed25519_TestVectors do
	Test(`Ed25519 Signature Generation Test {Index}`, function()
		local PrivateKey = TestVector.PrivateKey
		local PublicKey = TestVector.PublicKey
		local Message = TestVector.Message
		local PrivateKeyBytes = HexToBuffer(PrivateKey)
		local PublicKeyBytes = HexToBuffer(PublicKey)
		local MessageBytes = HexToBuffer(Message)
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
		local PublicKeyBytes = HexToBuffer(PublicKey)
		local MessageBytes = HexToBuffer(Message)
		local SignatureBytes = HexToBuffer(Signature)
		local IsValid = Algorithm.Verify(PublicKeyBytes, MessageBytes, SignatureBytes)

		Expect(IsValid).ToBeTruthy()
	end)
end

Testing.Complete()

return 0