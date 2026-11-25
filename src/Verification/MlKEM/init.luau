--[=[
	ML-KEM Main Module (Key Encapsulation Mechanism)
	
	The complete ML-KEM post quantum key encapsulation.
	Key generation, encapsulation, and decapsulation operations with
	CCA security using the Fujisaki Okamoto transform.
	
	Example usage:
		local D = CSPRNG.RandomBytes(32)
		local Z = CSPRNG.RandomBytes(32)
		local PublicKey, SecretKey = MlKem.MLKEM_1024.KeyGen(D, Z)
		
		local Message = CSPRNG.RandomBytes(32)
		local Ciphertext, SharedSecret = MlKem.MLKEM_1024.Encapsulate(Message, PublicKey)

		local RecoveredSecret = MlKem.MLKEM_1024.Decapsulate(Ciphertext, SecretKey)
--]=]

--!strict
--!optimize 2
--!native

local Pke = require("@self/PKE")
local Packing = require("@self/Packing")
local CSPRNG = require("../Utilities/CSPRNG")
local Params = require("@self/Params")
local Utils = require("@self/Utils")
local SHA3 = require("../Hashing/SHA3")
local Functions = require("../Utilities/Functions")
local CtCompareMask = Functions.CtCompareMask
local CtSelectBuffer = Functions.CtSelectBuffer
local CtCompare = Functions.CtCompare

local ENCAP_G_INPUT = buffer.create(64)

local DECAP_G_INPUT = buffer.create(64)
local DECAP_MESSAGE = buffer.create(32)
local DECAP_K_PRIME = buffer.create(32)
local DECAP_J_INPUT: { [number]: buffer } = {
	[2] = buffer.create(32 + 768),
	[3] = buffer.create(32 + 1088),
	[4] = buffer.create(32 + 1568),
}
local DECAP_CIPHERTEXT: { [number]: buffer } = {
	[2] = buffer.create(768),
	[3] = buffer.create(1088),
	[4] = buffer.create(1568),
}

local VALIDATE_VECTOR = buffer.create(4 * 512)

type PublicKeyCache = {
	Hashed: buffer,
	T: buffer,
	IsFilled: boolean,
	IsValid: boolean,
}

type SecretKeyCache = {
	Encoded: buffer,
	S: buffer,
	IsFilled: boolean,
	IsValid: boolean,
}

local PUBLIC_KEYS: { [number]: PublicKeyCache } = {}
local SECRET_KEYS: { [number]: SecretKeyCache } = {}

local function SameBytes(Source: buffer, SourceOffset: number, Checked: buffer, CheckedOffset: number, Length: number): boolean
	local Difference = 0

	for Index = 0, Length - 16, 16 do
		local At = SourceOffset + Index
		local CheckedAt = CheckedOffset + Index
		Difference = bit32.bor(
			Difference,
			bit32.bxor(buffer.readu32(Source, At + 12), buffer.readu32(Checked, CheckedAt + 12)),
			bit32.bxor(buffer.readu32(Source, At), buffer.readu32(Checked, CheckedAt)),
			bit32.bxor(buffer.readu32(Source, At + 4), buffer.readu32(Checked, CheckedAt + 4)),
			bit32.bxor(buffer.readu32(Source, At + 8), buffer.readu32(Checked, CheckedAt + 8))
		)
	end

	return Difference == 0
end

local function PublicKeySlot(K: number, PublicKeyLength: number): PublicKeyCache
	local Slot = PUBLIC_KEYS[K]
	if not Slot then
		Slot = {
			Hashed = buffer.create(PublicKeyLength + 32),
			T = buffer.create(K * 512),
			IsFilled = false,
			IsValid = false,
		}
		PUBLIC_KEYS[K] = Slot
	end

	Slot.IsFilled = false
	return Slot
end

local function SecretKeySlot(K: number): SecretKeyCache
	local Slot = SECRET_KEYS[K]
	if not Slot then
		Slot = {
			Encoded = buffer.create(K * 384),
			S = buffer.create(K * 512),
			IsFilled = false,
			IsValid = false,
		}
		SECRET_KEYS[K] = Slot
	end

	Slot.IsFilled = false
	return Slot
end

local function KnownPublicKey(K: number, Source: buffer, SourceOffset: number, PublicKeyLength: number): PublicKeyCache
	local Known = PUBLIC_KEYS[K]
	if Known and Known.IsFilled and SameBytes(Source, SourceOffset, Known.Hashed, 0, PublicKeyLength) then
		return Known
	end

	local Slot = PublicKeySlot(K, PublicKeyLength)
	local PublicKey = buffer.create(PublicKeyLength)
	buffer.copy(PublicKey, 0, Source, SourceOffset, PublicKeyLength)
	buffer.copy(Slot.Hashed, 0, PublicKey, 0, PublicKeyLength)
	buffer.copy(Slot.Hashed, PublicKeyLength, SHA3.SHA3_256_Internal(PublicKey), 0, 32)
	Slot.IsValid = Packing.Decode12(Source, SourceOffset, K * 256, Slot.T)
	Slot.IsFilled = true

	return Slot
end

local function KnownSecretKey(K: number, SecretKey: buffer): SecretKeyCache
	local EncodedLength = K * 384
	local Known = SECRET_KEYS[K]
	if Known and Known.IsFilled and SameBytes(SecretKey, 0, Known.Encoded, 0, EncodedLength) then
		return Known
	end

	local Slot = SecretKeySlot(K)
	buffer.copy(Slot.Encoded, 0, SecretKey, 0, EncodedLength)
	Slot.IsValid = Packing.Decode12(SecretKey, 0, K * 256, Slot.S)
	Slot.IsFilled = true

	return Slot
end

local MlKem = {
	CSPRNG = CSPRNG
}

function MlKem.KeyGen(K: number, Eta1: number, D: buffer, Z: buffer): (buffer, buffer)
	if not Params.CheckKeygenParams(K, Eta1) then
		error("Invalid keygen parameters")
	end

	if buffer.len(D) ~= 32 then
		error("D must be 32 bytes")
	end
	
	if buffer.len(Z) ~= 32 then
		error("Z must be 32 bytes")
	end

	local PkeSecretKeyLength = Utils.GetPkeSecretKeyLen(K)
	local PublicKeyLength = Utils.GetKemPublicKeyLen(K)
	local PublicKey = buffer.create(PublicKeyLength)
	local SecretKey = buffer.create(Utils.GetKemSecretKeyLen(K))
	local Public = PublicKeySlot(K, PublicKeyLength)
	local Secret = SecretKeySlot(K)
	Pke.KeyGen(K, Eta1, D, PublicKey, SecretKey, Public.T, Secret.S)

	local Hashed = Public.Hashed
	buffer.copy(Hashed, 0, PublicKey, 0, PublicKeyLength)
	buffer.copy(Hashed, PublicKeyLength, SHA3.SHA3_256_Internal(PublicKey), 0, 32)

	local HashOffset = PkeSecretKeyLength + PublicKeyLength
	buffer.copy(SecretKey, PkeSecretKeyLength, Hashed, 0, PublicKeyLength + 32)
	buffer.copy(SecretKey, HashOffset + 32, Z, 0, 32)
	buffer.copy(Secret.Encoded, 0, SecretKey, 0, PkeSecretKeyLength)

	Public.IsValid = true
	Public.IsFilled = true
	Secret.IsValid = true
	Secret.IsFilled = true

	return PublicKey, SecretKey
end

function MlKem.Encapsulate(Message: buffer, K: number, Eta1: number, Eta2: number, Du: number, Dv: number, PublicKey: buffer): (buffer, buffer)
	if not Params.CheckEncapParams(K, Eta1, Eta2, Du, Dv) then
		error("Invalid encapsulation parameters")
	end

	local PublicKeyLength = Utils.GetKemPublicKeyLen(K)
	if buffer.len(PublicKey) ~= PublicKeyLength then
		error("Invalid public key length")
	end

	if buffer.len(Message) ~= 32 then
		error("Message must be 32 bytes")
	end

	local Known = KnownPublicKey(K, PublicKey, 0, PublicKeyLength)
	if not Known.IsValid then
		error("Invalid public key encoding")
	end

	local GInput = ENCAP_G_INPUT
	buffer.copy(GInput, 0, Message, 0, 32)
	buffer.copy(GInput, 32, Known.Hashed, PublicKeyLength, 32)
	local SharedSecretAndRandomness = SHA3.SHA3_512_Internal(GInput)

	local Ciphertext = buffer.create(Utils.GetKemCipherTextLen(K, Du, Dv))
	Pke.Encrypt(K, Eta1, Eta2, Du, Dv, Known.T, PublicKey, K * 384, Message, SharedSecretAndRandomness, 32, Ciphertext)

	local SharedSecret = buffer.create(32)
	buffer.copy(SharedSecret, 0, SharedSecretAndRandomness, 0, 32)

	return Ciphertext, SharedSecret
end

function MlKem.Decapsulate(Ciphertext: buffer, K: number, Eta1: number, Eta2: number, Du: number, Dv: number, SecretKey: buffer): buffer
	if not Params.CheckDecapParams(K, Eta1, Eta2, Du, Dv) then
		error("Invalid decapsulation parameters")
	end
	if buffer.len(SecretKey) ~= Utils.GetKemSecretKeyLen(K) then
		error("Invalid secret key length")
	end
	
	local CiphertextLength = Utils.GetKemCipherTextLen(K, Du, Dv)
	if buffer.len(Ciphertext) ~= CiphertextLength then
		error("Invalid ciphertext length")
	end

	local PublicKeyOffset = Utils.GetPkeSecretKeyLen(K)
	local PublicKeyLength = Utils.GetPkePublicKeyLen(K)
	local HashOffset = PublicKeyOffset + PublicKeyLength
	local ZOffset = HashOffset + 32

	local Known = KnownPublicKey(K, SecretKey, PublicKeyOffset, PublicKeyLength)
	if not SameBytes(SecretKey, HashOffset, Known.Hashed, PublicKeyLength, 32) then
		error("Invalid secret key, the hash it stores does not match its public key")
	end

	local JInput = DECAP_J_INPUT[K]
	buffer.copy(JInput, 0, SecretKey, ZOffset, 32)
	buffer.copy(JInput, 32, Ciphertext, 0, CiphertextLength)
	local RejectionSecret = SHA3.SHAKE256_Internal(JInput, 32)

	local KPrime = DECAP_K_PRIME
	local ValidMask = 0x00000000

	local MPrime = DECAP_MESSAGE
	local Secret = KnownSecretKey(K, SecretKey)
	if Secret.IsValid then
		Pke.Decrypt(K, Du, Dv, Secret.S, Ciphertext, MPrime)

		local GInput = DECAP_G_INPUT
		buffer.copy(GInput, 0, MPrime, 0, 32)
		buffer.copy(GInput, 32, SecretKey, HashOffset, 32)
		local GOutput = SHA3.SHA3_512_Internal(GInput)
		buffer.copy(KPrime, 0, GOutput, 0, 32)

		if Known.IsValid then
			local CiphertextPrime = DECAP_CIPHERTEXT[K]
			Pke.Encrypt(K, Eta1, Eta2, Du, Dv, Known.T, SecretKey, PublicKeyOffset + K * 384, MPrime, GOutput, 32, CiphertextPrime)
			ValidMask = CtCompareMask(Ciphertext, CiphertextPrime)
		end
	end

	local SharedSecret = buffer.create(32)
	CtSelectBuffer(ValidMask, SharedSecret, KPrime, RejectionSecret)

	return SharedSecret
end

function MlKem.SecretsEqual(Secret1: buffer, Secret2: buffer): boolean
	return CtCompare(Secret1, Secret2)
end

function MlKem.ClearCaches()
	for _, Slot in SECRET_KEYS do
		buffer.fill(Slot.Encoded, 0, 0)
		buffer.fill(Slot.S, 0, 0)
		Slot.IsFilled = false
	end

	for _, Slot in PUBLIC_KEYS do
		Slot.IsFilled = false
	end
end

function MlKem.ValidateDecapsulationKey(K: number, SecretKey: buffer): boolean
	local PkeSecretKeyLength = Utils.GetPkeSecretKeyLen(K)
	local PublicKeyLength = Utils.GetPkePublicKeyLen(K)

	if typeof(SecretKey) ~= "buffer" or buffer.len(SecretKey) ~= Utils.GetKemSecretKeyLen(K) then
		return false
	end

	local Known = KnownPublicKey(K, SecretKey, PkeSecretKeyLength, PublicKeyLength)
	if not (Known.IsValid and Packing.Decode12(SecretKey, 0, K * 256, VALIDATE_VECTOR)) then
		return false
	end

	return SameBytes(SecretKey, PkeSecretKeyLength + PublicKeyLength, Known.Hashed, PublicKeyLength, 32)
end

MlKem.MLKEM_512 = {
	KeyGen = function(D: buffer, Z: buffer): (buffer, buffer)
		return MlKem.KeyGen(2, 3, D, Z)
	end,

	Encapsulate = function(Message: buffer, PublicKey: buffer): (buffer, buffer)
		return MlKem.Encapsulate(Message, 2, 3, 2, 10, 4, PublicKey)
	end,

	Decapsulate = function(Ciphertext: buffer, SecretKey: buffer): buffer
		return MlKem.Decapsulate(Ciphertext, 2, 3, 2, 10, 4, SecretKey)
	end,

	GenerateKeys = function(): (buffer, buffer)
		local D = CSPRNG.RandomBytes(32)
		local Z = CSPRNG.RandomBytes(32)

		return MlKem.MLKEM_512.KeyGen(D, Z)
	end,
	
	ValidateDecapsulationKey = function(SecretKey: buffer): boolean
		return MlKem.ValidateDecapsulationKey(2, SecretKey)
	end
}

MlKem.MLKEM_768 = {
	KeyGen = function(D: buffer, Z: buffer): (buffer, buffer)
		return MlKem.KeyGen(3, 2, D, Z)
	end,

	Encapsulate = function(Message: buffer, PublicKey: buffer): (buffer, buffer)
		return MlKem.Encapsulate(Message, 3, 2, 2, 10, 4, PublicKey)
	end,

	Decapsulate = function(Ciphertext: buffer, SecretKey: buffer): buffer
		return MlKem.Decapsulate(Ciphertext, 3, 2, 2, 10, 4, SecretKey)
	end,

	GenerateKeys = function(): (buffer, buffer)
		local D = CSPRNG.RandomBytes(32)
		local Z = CSPRNG.RandomBytes(32)

		return MlKem.MLKEM_768.KeyGen(D, Z)
	end,
	
	ValidateDecapsulationKey = function(SecretKey: buffer): boolean
		return MlKem.ValidateDecapsulationKey(3, SecretKey)
	end
}

MlKem.MLKEM_1024 = {
	KeyGen = function(D: buffer, Z: buffer): (buffer, buffer)
		return MlKem.KeyGen(4, 2, D, Z)
	end,

	Encapsulate = function(Message: buffer, PublicKey: buffer): (buffer, buffer)
		return MlKem.Encapsulate(Message, 4, 2, 2, 11, 5, PublicKey)
	end,

	Decapsulate = function(Ciphertext: buffer, SecretKey: buffer): buffer
		return MlKem.Decapsulate(Ciphertext, 4, 2, 2, 11, 5, SecretKey)
	end,

	GenerateKeys = function(): (buffer, buffer)
		local D = CSPRNG.RandomBytes(32)
		local Z = CSPRNG.RandomBytes(32)

		return MlKem.MLKEM_1024.KeyGen(D, Z)
	end,
	
	ValidateDecapsulationKey = function(SecretKey: buffer): boolean
		return MlKem.ValidateDecapsulationKey(4, SecretKey)
	end
}

return MlKem