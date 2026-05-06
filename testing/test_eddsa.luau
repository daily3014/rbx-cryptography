--!strict
--!optimize 2

local EdDSA = require("../src/Verification/EdDSA")

local Failures = 0
local Total = 0

local function FromHex(Hex: string): buffer
	local Buf = buffer.create(#Hex // 2)
	for Index = 0, #Hex // 2 - 1 do
		local Byte = tonumber(Hex:sub(Index * 2 + 1, Index * 2 + 2), 16) :: number
		buffer.writeu8(Buf, Index, Byte)
	end
	return Buf
end

local function ToHex(Buf: buffer): string
	local Parts = {}
	for Index = 0, buffer.len(Buf) - 1 do
		Parts[Index + 1] = string.format("%02x", buffer.readu8(Buf, Index))
	end
	return table.concat(Parts)
end

local function Check(Name: string, Pass: boolean, Detail: string?)
	Total += 1
	if Pass then
		print(`[OK]   {Name}`)
	else
		Failures += 1
		print(`[FAIL] {Name}` .. (Detail and `: {Detail}` or ""))
	end
end

print(" EdDSA integration ")

-- RFC 8032 Test 1: empty message
do
	local SecretKey = FromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	local ExpectedPK = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	local Message = buffer.create(0)
	local ExpectedSig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

	local PK = EdDSA.PublicKey(SecretKey)
	Check("RFC8032 test 1 PublicKey", ToHex(PK) == ExpectedPK, `got {ToHex(PK)}`)

	local Sig = EdDSA.Sign(Message, SecretKey, PK)
	Check("RFC8032 test 1 Sign", ToHex(Sig) == ExpectedSig, `got {ToHex(Sig)}`)

	Check("RFC8032 test 1 Verify(real sig)", EdDSA.Verify(Message, PK, Sig))
end

-- RFC 8032 Test 2: single byte
do
	local SecretKey = FromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	local ExpectedPK = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	local Message = FromHex("72")
	local ExpectedSig = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"

	local PK = EdDSA.PublicKey(SecretKey)
	Check("RFC8032 test 2 PublicKey", ToHex(PK) == ExpectedPK)

	local Sig = EdDSA.Sign(Message, SecretKey, PK)
	Check("RFC8032 test 2 Sign", ToHex(Sig) == ExpectedSig)

	Check("RFC8032 test 2 Verify", EdDSA.Verify(Message, PK, Sig))
end

-- RFC 8032 Test 3: 2 bytes
do
	local SecretKey = FromHex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
	local ExpectedPK = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
	local Message = FromHex("af82")
	local ExpectedSig = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"

	local PK = EdDSA.PublicKey(SecretKey)
	Check("RFC8032 test 3 PublicKey", ToHex(PK) == ExpectedPK)

	local Sig = EdDSA.Sign(Message, SecretKey, PK)
	Check("RFC8032 test 3 Sign", ToHex(Sig) == ExpectedSig)

	Check("RFC8032 test 3 Verify", EdDSA.Verify(Message, PK, Sig))
end

-- Tampered message must not verify
do
	local SecretKey = FromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	local PK = EdDSA.PublicKey(SecretKey)
	local Message = FromHex("72")
	local Sig = EdDSA.Sign(Message, SecretKey, PK)

	local Tampered = FromHex("73")
	Check("Tampered message rejected", not EdDSA.Verify(Tampered, PK, Sig))
end

-- Batch verify two valid signatures
do
	local SK1 = FromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	local SK2 = FromHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	local PK1 = EdDSA.PublicKey(SK1)
	local PK2 = EdDSA.PublicKey(SK2)
	local Msg1 = buffer.fromstring("hello")
	local Msg2 = buffer.fromstring("world")
	local Sig1 = EdDSA.Sign(Msg1, SK1, PK1)
	local Sig2 = EdDSA.Sign(Msg2, SK2, PK2)

	Check("Batch verify (2 valid)", EdDSA.VerifyBatch({
		{PublicKey = PK1, Message = Msg1, Signature = Sig1},
		{PublicKey = PK2, Message = Msg2, Signature = Sig2},
	}))
end

print(`\n{Total - Failures}/{Total} passed, {Failures} failed.`)
