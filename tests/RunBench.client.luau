--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")

local BATCH_SECONDS = 0.02
local BATCHES = 5

local function Load(Path: { string }): any
	local Ok, Result = pcall(function(): any
		local Instance: Instance = ReplicatedStorage
		for _, Name in Path do
			Instance = Instance:WaitForChild(Name, 5) :: Instance
		end
		return (require :: any)(Instance)
	end)
	return if Ok then Result else nil
end

local function Bytes(Size: number, Salt: number): buffer
	local Result = buffer.create(Size)
	for Index = 0, Size - 1 do
		buffer.writeu8(Result, Index, (Index * 131 + Salt) % 256)
	end
	return Result
end

local function Run(Case: string, Library: string, Callback: () -> ())
	local Ok = pcall(Callback)
	if not Ok then
		print(string.format("%-28s %-24s %s", Case, Library, "unavailable"))
		return
	end

	local Calls = 1
	while true do
		local Start = os.clock()
		for _ = 1, Calls do
			Callback()
		end
		if os.clock() - Start >= BATCH_SECONDS then
			break
		end
		Calls *= 2
		task.wait()
	end

	local Best = math.huge
	for _ = 1, BATCHES do
		local Start = os.clock()
		for _ = 1, Calls do
			Callback()
		end
		Best = math.min(Best, (os.clock() - Start) / Calls)
		task.wait()
	end

	print(string.format("%-28s %-24s %12.2f us", Case, Library, Best * 1e6))
end

local Cryptography = Load({ "Cryptography" })
local HashLib = Load({ "Hashlib" })
local Gamer = Load({ "Gamer" })
local Service = {
	Sha2 = Load({ "CryptographyService", "Util", "Sha2" }),
	Sha3 = Load({ "CryptographyService", "Util", "Sha3" }),
	Blake2 = Load({ "CryptographyService", "Util", "Blake2" }),
	Hmac = Load({ "CryptographyService", "Util", "Hmac" }),
	ChaCha20 = Load({ "CryptographyService", "Util", "ChaCha20" }),
	Poly1305 = Load({ "CryptographyService", "Util", "Poly1305" }),
}
local Orbit = {
	ChaCha = Load({ "Crypto", "ChaChaBor" }),
	Poly1305 = Load({ "Crypto", "Poly1305" }),
}

local Hashing, Encryption, Verification, Utilities =
	Cryptography.Hashing, Cryptography.Encryption, Cryptography.Verification, Cryptography.Utilities
local SHA256Core = Load({ "Cryptography", "Hashing", "SHA2", "SHA256Core" })

local Data, Large = Bytes(51200, 7), Bytes(1048576, 3)
local Message, Key, Nonce = Bytes(64, 11), Bytes(32, 13), Bytes(12, 17)
local DataString, KeyString = buffer.tostring(Data), buffer.tostring(Key)
local Output = buffer.create(32)

print("Cryptography bench, best of five batches")

local SHA256, SHA512 = Hashing.SHA2.SHA256, Hashing.SHA2.SHA512
Run("SHA-256 50 KB", "rbx-cryptography", function() SHA256(Data) end)
Run("SHA-256 50 KB", "rbx-cryptography Luau", function() SHA256Core.Digest_Internal(Data, SHA256Core.IV_256, 32) end)
Run("SHA-256 50 KB", "HashLib", function() HashLib.sha256(DataString) end)
Run("SHA-256 50 KB", "Gamer", function() Gamer.SHA256.hash(DataString) end)
Run("SHA-256 50 KB", "CryptographyService", function() Service.Sha2.SHA256.Hash(Data) end)

Run("SHA-512 50 KB", "rbx-cryptography", function() SHA512(Data) end)
Run("SHA-512 50 KB", "HashLib", function() HashLib.sha512(DataString) end)
Run("SHA-512 50 KB", "CryptographyService", function() Service.Sha2.SHA512.Hash(Data) end)

Run("SHA3-512 50 KB", "rbx-cryptography", function() Hashing.SHA3.SHA3_512(Data) end)
Run("SHA3-512 50 KB", "HashLib", function() HashLib.sha3x512(DataString) end)
Run("SHA3-512 50 KB", "CryptographyService", function() Service.Sha3.SHA3_512.Hash(Data) end)

Run("BLAKE2b 50 KB", "rbx-cryptography", function() Hashing.Blake2b.Digest(Data, 32) end)
Run("BLAKE2b 50 KB", "rbx-cryptography Luau", function() Hashing.Blake2b.Digest(Data, 64) end)
Run("BLAKE2b 50 KB", "CryptographyService", function() Service.Blake2.Blake2bSpec().Hash(Data) end)

Run("BLAKE3 50 KB", "rbx-cryptography", function() Hashing.Blake3.Digest(Data) end)
Run("BLAKE3 50 KB", "rbx-cryptography Luau", function() Hashing.Blake3.Digest(Data, 64) end)

Run("HMAC-SHA256 50 KB", "rbx-cryptography", function() Hashing.HMAC(Data, Key, SHA256, 64) end)
Run("HMAC-SHA256 50 KB", "HashLib", function() HashLib.hmac(HashLib.sha256, KeyString, DataString) end)
Run("HMAC-SHA256 50 KB", "Gamer", function() Gamer.HMAC.sha256(KeyString, DataString) end)
Run("HMAC-SHA256 50 KB", "CryptographyService", function() Service.Hmac.Compute(Service.Sha2.SHA256, Key, Data) end)
Run("HMAC-BLAKE3 50 KB", "rbx-cryptography", function() Hashing.HMAC(Data, Key, Hashing.Blake3.Digest, 64) end)
Run("KMAC-128 50 KB", "rbx-cryptography", function() Hashing.KMAC.KMAC128(Data, Key, Output) end)
Run("KMAC-256 50 KB", "rbx-cryptography", function() Hashing.KMAC.KMAC256(Data, Key, Output) end)

Run("ChaCha20 50 KB", "rbx-cryptography", function() Encryption.AEAD.ChaCha20(Data, Key, Nonce) end)
Run("ChaCha20 50 KB", "CryptographyService", function() Service.ChaCha20.Apply(Key, Nonce, 1, Data) end)
Run("ChaCha20 50 KB", "Orbit", function()
	local Length = buffer.len(Data)
	local Result = buffer.create(Length)
	Orbit.ChaCha.Xor(Key, 0, 1, buffer.readu32(Nonce, 0), buffer.readu32(Nonce, 4), buffer.readu32(Nonce, 8), Data, 0, Result, 0, Length, 20)
end)
Run("Poly1305 50 KB", "rbx-cryptography", function() Encryption.AEAD.Poly1305(Data, Key) end)
Run("Poly1305 50 KB", "CryptographyService", function() Service.Poly1305.Mac(Key, Data) end)
Run("Poly1305 50 KB", "Orbit", function() Orbit.Poly1305.Bor.Tag(Key, 0, nil, 0, 0, Data, 0, buffer.len(Data), false) end)
Run("AES-256-GCM 50 KB", "rbx-cryptography", function() Encryption.AES.Encrypt(Data, Key, Nonce) end)
Run("XOR 1 MB", "rbx-cryptography", function() Utilities.XOR(Large, Key) end)
Run("XOR 1 MB", "Gamer", function() Gamer.XOR.crypt(Large, Key) end)

local EdDSA = Verification.EdDSA
local PublicKey = EdDSA.PublicKey(Key)
local Signature = EdDSA.Sign(Message, Key, PublicKey)
Run("EdDSA public key", "rbx-cryptography", function() EdDSA.PublicKey(Key) end)
Run("EdDSA sign", "rbx-cryptography", function() EdDSA.Sign(Message, Key, PublicKey) end)
Run("EdDSA verify", "rbx-cryptography", function() EdDSA.Verify(Message, PublicKey, Signature) end)
local PeerKey = EdDSA.X25519.PublicKey(Bytes(32, 19))
Run("X25519 exchange", "rbx-cryptography", function() EdDSA.X25519.Exchange(Key, PeerKey) end)

local MLDSA44 = Verification.MlDSA.ML_DSA_44
local DsaPublic, DsaSecret = buffer.create(MLDSA44.PubKeyByteLen), buffer.create(MLDSA44.SecKeyByteLen)
local DsaSignature, Context = buffer.create(MLDSA44.SigByteLen), buffer.create(0)
Run("ML-DSA-44 keygen", "rbx-cryptography", function() MLDSA44.KeyGen(Key, DsaPublic, DsaSecret) end)
Run("ML-DSA-44 sign", "rbx-cryptography", function() MLDSA44.Sign(Message, Key, DsaSecret, Context, DsaSignature) end)
Run("ML-DSA-44 verify", "rbx-cryptography", function() MLDSA44.Verify(Message, DsaPublic, Context, DsaSignature) end)

local MLKEM512 = Verification.MlKEM.MLKEM_512
local KemPublic, KemSecret = MLKEM512.KeyGen(Key, Key)
local KemCiphertext = MLKEM512.Encapsulate(Key, KemPublic)
Run("ML-KEM-512 keygen", "rbx-cryptography", function() MLKEM512.KeyGen(Key, Key) end)
Run("ML-KEM-512 encapsulate", "rbx-cryptography", function() MLKEM512.Encapsulate(Key, KemPublic) end)
Run("ML-KEM-512 decapsulate", "rbx-cryptography", function() MLKEM512.Decapsulate(KemCiphertext :: buffer, KemSecret) end)

local Base64 = Utilities.Base64
Run("Base64 round trip 50 KB", "rbx-cryptography", function() Base64.Decode(Base64.Encode(Data)) end)
Run("Base64 round trip 50 KB", "HashLib", function() HashLib.base64Decode(HashLib.base64Encode(DataString)) end)
Run("Base64 round trip 50 KB", "Gamer", function() Gamer.Base64.Decode(Gamer.Base64.Encode(Data)) end)

print("Cryptography bench done")
