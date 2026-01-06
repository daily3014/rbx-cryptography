--[=[
	ML-KEM Main Module (Key Encapsulation Mechanism)
	
	The complete ML-KEM post quantum key encapsulation.
	Key generation, encapsulation, and decapsulation operations with
	CCA security using the Fujisaki Okamoto transform.
	
	Example usage:
		local MlKem = require(script.MlKem)
		local CSPRNG = require(script.CSPRNG)
		
		local D = CSPRNG.RandomBytes(32)
		local Z = CSPRNG.RandomBytes(32)
		local PublicKey, SecretKey = MlKem.MLKEM_1024.KeyGen(D, Z)
		
		local Message = CSPRNG.RandomBytes(32)
		local Success, Ciphertext, SharedSecret = MlKem.MLKEM_1024.Encapsulate(PublicKey, Message)
		
		if Success then
			local RecoveredSecret = MlKem.MLKEM_1024.Decapsulate(SecretKey, Ciphertext)
			-- RecoveredSecret should equal SharedSecret
		end
--]=]

--!strict
--!optimize 2
--!native

local Pke = require("@self/PKE")
local Polyvec = require("@self/PolyVec")
local CSPRNG = require("@self/CSPRNG")
local Params = require("@self/Params")
local Utils = require("@self/Utils")
local SHA3 = require("@self/SHA3")

local DECAP_G_INPUT = buffer.create(64)
local DECAP_K_PRIME = buffer.create(32)
local DECAP_R_PRIME = buffer.create(32)
local DECAP_J_OUTPUT = buffer.create(32)

local ENCAP_G_INPUT = buffer.create(64)
local ENCAP_R = buffer.create(32)

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

	local KpkePublicKey, KpkeSecretKey = Pke.KeyGen(K, Eta1, D)
	local _, PublicKeyHash = SHA3.SHA3_256(KpkePublicKey)

	local SecretKeyLen = Utils.GetKemSecretKeyLen(K)
	local SecretKey = buffer.create(SecretKeyLen)
	
	local Offset = 0

	local KpkeSecretKeyLen = buffer.len(KpkeSecretKey)
	buffer.copy(SecretKey, Offset, KpkeSecretKey, 0, KpkeSecretKeyLen)
	Offset = Offset + KpkeSecretKeyLen

	local KpkePublicKeyLen = buffer.len(KpkePublicKey)
	buffer.copy(SecretKey, Offset, KpkePublicKey, 0, KpkePublicKeyLen)
	Offset += KpkePublicKeyLen

	buffer.copy(SecretKey, Offset, PublicKeyHash, 0, 32)
	Offset += 32

	buffer.copy(SecretKey, Offset, Z, 0, 32)

	return KpkePublicKey, SecretKey
end

function MlKem.Encapsulate(K: number, Eta1: number, Eta2: number, Du: number, Dv: number, PublicKey: buffer, Message: buffer): (buffer?, buffer?)
	if not Params.CheckEncapParams(K, Eta1, Eta2, Du, Dv) then
		error("Invalid encapsulation parameters")
	end
	
	if buffer.len(PublicKey) ~= Utils.GetKemPublicKeyLen(K) then
		error("Invalid public key length")
	end
	
	if buffer.len(Message) ~= 32 then
		error("Message must be 32 bytes")
	end

	local RhoOffset = K * 12 * 32
	local EncodedTPrime = buffer.create(RhoOffset)
	buffer.copy(EncodedTPrime, 0, PublicKey, 0, RhoOffset)

	local TPrime = Polyvec.VecDecode(EncodedTPrime, K, 12)
	local ReEncodedTPrime = Polyvec.VecEncode(TPrime, K, 12)

	local IsValid = Utils.CtMemcmp(EncodedTPrime, ReEncodedTPrime)
	if IsValid ~= 0xFFFFFFFF then
		error("malformed public key encoding")
	end

	local _, PublicKeyHash = SHA3.SHA3_256(PublicKey)

	local GInput = ENCAP_G_INPUT
	buffer.copy(GInput, 0, Message, 0, 32)
	buffer.copy(GInput, 32, PublicKeyHash, 0, 32)

	local _, GOutput = SHA3.SHA3_512(GInput)

	local K_bytes = buffer.create(32)
	local R = ENCAP_R
	buffer.copy(K_bytes, 0, GOutput, 0, 32)
	buffer.copy(R, 0, GOutput, 32, 32)

	local Ciphertext = Pke.Encrypt(K, Eta1, Eta2, Du, Dv, PublicKey, Message, R)

	return Ciphertext, K_bytes
end

function MlKem.Decapsulate(K: number, Eta1: number, Eta2: number, Du: number, Dv: number, SecretKey: buffer, Ciphertext: buffer): buffer
	if not Params.CheckDecapParams(K, Eta1, Eta2, Du, Dv) then
		error("Invalid decapsulation parameters")
	end
	if buffer.len(SecretKey) ~= Utils.GetKemSecretKeyLen(K) then
		error("Invalid secret key length")
	end
	
	if buffer.len(Ciphertext) ~= Utils.GetKemCipherTextLen(K, Du, Dv) then
		error("Invalid ciphertext length")
	end

	local KpkeSecretKeyLen = Utils.GetPkeSecretKeyLen(K)
	local KpkePublicKeyLen = Utils.GetPkePublicKeyLen(K)

	local KpkeSecretKey = buffer.create(KpkeSecretKeyLen)
	local KpkePublicKey = buffer.create(KpkePublicKeyLen)
	local H = buffer.create(32)
	local Z = buffer.create(32)

	local Offset = 0
	buffer.copy(KpkeSecretKey, 0, SecretKey, Offset, KpkeSecretKeyLen)
	Offset += KpkeSecretKeyLen

	buffer.copy(KpkePublicKey, 0, SecretKey, Offset, KpkePublicKeyLen)
	Offset += KpkePublicKeyLen

	buffer.copy(H, 0, SecretKey, Offset, 32)
	Offset += 32

	buffer.copy(Z, 0, SecretKey, Offset, 32)

	local MPrime = Pke.Decrypt(K, Du, Dv, KpkeSecretKey, Ciphertext)

	local GInput = DECAP_G_INPUT
	buffer.copy(GInput, 0, MPrime, 0, 32)
	buffer.copy(GInput, 32, H, 0, 32)

	local _, GOutput = SHA3.SHA3_512(GInput)

	local KPrime = DECAP_K_PRIME
	local RPrime = DECAP_R_PRIME
	buffer.copy(KPrime, 0, GOutput, 0, 32)
	buffer.copy(RPrime, 0, GOutput, 32, 32)

	local JInput = buffer.create(32 + buffer.len(Ciphertext))
	buffer.copy(JInput, 0, Z, 0, 32)
	buffer.copy(JInput, 32, Ciphertext, 0, buffer.len(Ciphertext))

	local _, JOutputBuffer = SHA3.SHAKE256(JInput, 32)
	local JOutput = DECAP_J_OUTPUT
	buffer.copy(JOutput, 0, JOutputBuffer, 0, 32)

	local CiphertextPrime = Pke.Encrypt(K, Eta1, Eta2, Du, Dv, KpkePublicKey, MPrime, RPrime)
	local IsValid = Utils.CtMemcmp(Ciphertext, CiphertextPrime)

	local SharedSecret = buffer.create(32)
	Utils.CtCondMemcpy(IsValid, SharedSecret, KPrime, JOutput)

	return SharedSecret
end

function MlKem.SecretsEqual(Secret1: buffer, Secret2: buffer): boolean
	if buffer.len(Secret1) ~= 32 or buffer.len(Secret2) ~= 32 then
		return false
	end

	return Utils.CtMemcmp(Secret1, Secret2) == 0xFFFFFFFF
end

function MlKem.ValidateDecapsulationKey(K: number, SecretKey: buffer): boolean
	local KpkeSecretKeyLen = Utils.GetPkeSecretKeyLen(K)
	local KpkePublicKeyLen = Utils.GetPkePublicKeyLen(K)

	local EkOffset = KpkeSecretKeyLen
	local HOffset = KpkeSecretKeyLen + KpkePublicKeyLen

	local Ek = buffer.create(KpkePublicKeyLen)
	local StoredH = buffer.create(32)
	buffer.copy(Ek, 0, SecretKey, EkOffset, KpkePublicKeyLen)
	buffer.copy(StoredH, 0, SecretKey, HOffset, 32)

	local _, ComputedH = SHA3.SHA3_256(Ek)
	return Utils.CtMemcmp(StoredH, ComputedH) == 0xFFFFFFFF
end

MlKem.MLKEM_512 = {
	KeyGen = function(D: buffer, Z: buffer): (buffer, buffer)
		return MlKem.KeyGen(2, 3, D, Z)
	end,

	Encapsulate = function(PublicKey: buffer, Message: buffer): (buffer?, buffer?)
		return MlKem.Encapsulate(2, 3, 2, 10, 4, PublicKey, Message)
	end,

	Decapsulate = function(SecretKey: buffer, Ciphertext: buffer): buffer
		return MlKem.Decapsulate(2, 3, 2, 10, 4, SecretKey, Ciphertext)
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

	Encapsulate = function(PublicKey: buffer, Message: buffer): (buffer?, buffer?)
		return MlKem.Encapsulate(3, 2, 2, 10, 4, PublicKey, Message)
	end,

	Decapsulate = function(SecretKey: buffer, Ciphertext: buffer): buffer
		return MlKem.Decapsulate(3, 2, 2, 10, 4, SecretKey, Ciphertext)
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

	Encapsulate = function(PublicKey: buffer, Message: buffer): (buffer?, buffer?)
		return MlKem.Encapsulate(4, 2, 2, 11, 5, PublicKey, Message)
	end,

	Decapsulate = function(SecretKey: buffer, Ciphertext: buffer): buffer
		return MlKem.Decapsulate(4, 2, 2, 11, 5, SecretKey, Ciphertext)
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
