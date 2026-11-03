--!strict

--[=[
	Counters workload: runs every algorithm's Luau path a few times so luau.exe --counters sees
	each native block. Without game, EncodingService is nil and every fallback core runs.

	Run through counters.py, which copies it and a src tree into a temporary folder:
		python counters.py [--src <tree>]
--]=]

local C = require("./src")

local REPEATS = 8

local function Rand(N: number): buffer
	local B = buffer.create(N)
	for I = 0, N - 1 do
		buffer.writeu8(B, I, (I * 131 + 7) % 256)
	end
	return B
end

local function Run(Name: string, F: () -> ())
	local Ok, Err = pcall(function()
		for _ = 1, REPEATS do
			F()
		end
	end)
	if not Ok then
		print(`FAILED {Name}: {Err}`)
	end
end

local H, E, U, V = C.Hashing, C.Encryption, C.Utilities, C.Verification
local Key32, Nonce12, Nonce24 = Rand(32), Rand(12), Rand(24)

for _, Size in { 0, 3, 64, 1000, 16384 } do
	local Data = Rand(Size)
	Run(`SHA224 {Size}`, function() H.SHA2.SHA224(Data) end)
	Run(`SHA256 {Size}`, function() H.SHA2.SHA256(Data) end)
	Run(`SHA384 {Size}`, function() H.SHA2.SHA384(Data) end)
	Run(`SHA512 {Size}`, function() H.SHA2.SHA512(Data) end)
	Run(`MD5 {Size}`, function() H.MD5(Data) end)
	Run(`SHA1 {Size}`, function() H.SHA1(Data) end)
	Run(`SHA3_224 {Size}`, function() H.SHA3.SHA3_224(Data) end)
	Run(`SHA3_256 {Size}`, function() H.SHA3.SHA3_256(Data) end)
	Run(`SHA3_384 {Size}`, function() H.SHA3.SHA3_384(Data) end)
	Run(`SHA3_512 {Size}`, function() H.SHA3.SHA3_512(Data) end)
	Run(`SHAKE128 {Size}`, function() H.SHA3.SHAKE128(Data, 300) end)
	Run(`SHAKE256 {Size}`, function() H.SHA3.SHAKE256(Data, 300) end)
	Run(`Blake3 {Size}`, function() H.Blake3.Digest(Data, 32) end)
	Run(`Blake3 L64 {Size}`, function() H.Blake3.Digest(Data, 64) end)
	Run(`Blake3 Keyed {Size}`, function() H.Blake3.DigestKeyed(Data, Key32) end)
	Run(`Blake3 DeriveKey {Size}`, function() H.Blake3.DeriveKey(Key32)(Data, 32) end)
	Run(`Blake2b 64 {Size}`, function() H.Blake2b.Digest(Data, 64) end)
	Run(`Blake2b 32 keyed {Size}`, function() H.Blake2b.Digest(Data, 32, Key32) end)
	Run(`KMAC128 {Size}`, function() H.KMAC.KMAC128(Data, Key32, buffer.create(32)) end)
	Run(`KMAC256 {Size}`, function() H.KMAC.KMAC256(Data, Key32, buffer.create(32)) end)
	Run(`HMAC-SHA256 {Size}`, function() H.HMAC(Data, Key32, H.SHA2.SHA256, 64) end)
	Run(`HMAC-SHA512 {Size}`, function() H.HMAC(Data, Key32, H.SHA2.SHA512, 128) end)
	Run(`HKDF {Size}`, function() H.HKDF(Data, Key32, Key32, 64, H.SHA2.SHA256, 64, 32) end)
	Run(`ChaCha20 {Size}`, function() E.AEAD.ChaCha20(Data, Key32, Nonce12) end)
	Run(`XChaCha20 {Size}`, function() E.AEAD.XChaCha20(Data, Key32, Nonce24) end)
	Run(`Poly1305 {Size}`, function() E.AEAD.Poly1305(Data, Key32) end)
	Run(`AEAD {Size}`, function()
		local Ciphertext, Tag = E.AEAD.Encrypt(Data, Key32, Nonce12)
		E.AEAD.Decrypt(Ciphertext, Key32, Nonce12, Tag)
	end)
	Run(`AES-GCM {Size}`, function() E.AES.Encrypt(Data, Key32, Nonce12) end)
	Run(`Base64 {Size}`, function() U.Base64.Decode(U.Base64.Encode(Data)) end)
	Run(`Hex {Size}`, function() U.Conversions.FromHex(U.Conversions.ToHex(Data)) end)
	Run(`XOR {Size}`, function() U.XOR(Data, Key32) end)
end

Run("CSPRNG", function()
	U.CSPRNG.Random()
	U.CSPRNG.RandomInt(1, 100)
	U.CSPRNG.RandomBytes(4096)
end)

local Message = Rand(64)
local Ed = V.EdDSA
local EdPK = Ed.PublicKey(Key32)
local EdSig = Ed.Sign(Message, Key32, EdPK)
Run("Ed25519", function()
	Ed.PublicKey(Key32)
	Ed.Verify(Message, EdPK, Ed.Sign(Message, Key32, EdPK))
	Ed.Verify(Message, EdPK, EdSig)
end)
local XPK = Ed.X25519.PublicKey(Rand(32))
Run("X25519", function() Ed.X25519.Exchange(Key32, XPK) end)

for _, Name in { "MLKEM_512", "MLKEM_768", "MLKEM_1024" } do
	local K = V.MlKEM[Name]
	Run(Name, function()
		local PK, SK = K.KeyGen(Key32, Key32)
		local CT = K.Encapsulate(Key32, PK)
		K.Decapsulate(CT :: buffer, SK)
	end)
end

for _, Name in { "ML_DSA_44", "ML_DSA_65", "ML_DSA_87" } do
	local D = V.MlDSA[Name]
	local PK, SK, Sig = buffer.create(D.PubKeyByteLen), buffer.create(D.SecKeyByteLen), buffer.create(D.SigByteLen)
	local Ctx = buffer.create(0)
	Run(Name, function()
		D.KeyGen(Key32, PK, SK)
		D.Sign(Message, Key32, SK, Ctx, Sig)
		D.Verify(Message, PK, Ctx, Sig)
	end)
end

print("workload done")
