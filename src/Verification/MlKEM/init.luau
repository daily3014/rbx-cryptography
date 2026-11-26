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

local Lazy = require("../Lazy")
local Pke = require("@self/PKE")
local Packing = require("@self/Packing")
local Sampling = require("@self/Sampling")
local SHA3 = require("../Hashing/SHA3")
local Functions = require("../Utilities/Functions")
local CtCompareMask = Functions.CtCompareMask
local CtSelectBuffer = Functions.CtSelectBuffer
local CtCompare = Functions.CtCompare

type CSPRNGModule = typeof(require("../Utilities/CSPRNG"))

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

type Scheme = {
	KeyGen: (D: buffer, Z: buffer) -> (buffer, buffer),
	Encapsulate: (Message: buffer, PublicKey: buffer) -> (buffer?, buffer?),
	Decapsulate: (Ciphertext: buffer, SecretKey: buffer) -> buffer?,
	GenerateKeys: () -> (buffer, buffer),
	ValidateDecapsulationKey: (SecretKey: buffer) -> boolean,
}

export type MlKemModule = {
	CSPRNG: CSPRNGModule,
	KeyGen: (K: number, Eta1: number, D: buffer, Z: buffer) -> (buffer, buffer),
	Encapsulate: (Message: buffer, K: number, Eta1: number, Eta2: number, Du: number, Dv: number, PublicKey: buffer) -> (buffer?, buffer?),
	Decapsulate: (Ciphertext: buffer, K: number, Eta1: number, Eta2: number, Du: number, Dv: number, SecretKey: buffer) -> buffer?,
	SecretsEqual: (Secret1: buffer, Secret2: buffer) -> boolean,
	ClearCaches: () -> (),
	ValidateDecapsulationKey: (K: number, SecretKey: buffer) -> boolean,
	MLKEM_512: Scheme,
	MLKEM_768: Scheme,
	MLKEM_1024: Scheme,
}

local G_INPUT: buffer = buffer.create(64)
local G_OUTPUT: buffer = buffer.create(64)
local DECAP_MESSAGE: buffer = buffer.create(32)
local DECAP_REJECTION: buffer = buffer.create(32)

local DECAP_J_INPUT: buffer? = nil
local DECAP_CIPHERTEXT: buffer? = nil
local VALIDATE_VECTOR: buffer? = nil

local PUBLIC_KEYS: { [number]: PublicKeyCache } = {}
local SECRET_KEYS: { [number]: SecretKeyCache } = {}

local function Copy32(Dest: buffer, DestOffset: number, Src: buffer, SrcOffset: number): ()
	buffer.writef64(Dest, DestOffset, buffer.readf64(Src, SrcOffset))
	buffer.writef64(Dest, DestOffset + 8, buffer.readf64(Src, SrcOffset + 8))
	buffer.writef64(Dest, DestOffset + 16, buffer.readf64(Src, SrcOffset + 16))
	buffer.writef64(Dest, DestOffset + 24, buffer.readf64(Src, SrcOffset + 24))
end

@native
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

local function CheckEncapParams(K: number, Eta1: number, Eta2: number, Du: number, Dv: number): boolean
	return ((K == 2) and (Eta1 == 3) and (Eta2 == 2) and (Du == 10) and (Dv == 4))
		or ((K == 3) and (Eta1 == 2) and (Eta2 == 2) and (Du == 10) and (Dv == 4))
		or ((K == 4) and (Eta1 == 2) and (Eta2 == 2) and (Du == 11) and (Dv == 5))
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
	local Hashed = Slot.Hashed
	buffer.copy(Hashed, 0, Source, SourceOffset, PublicKeyLength)
	SHA3.SHA3_256_Into(Source, SourceOffset, PublicKeyLength, Hashed, PublicKeyLength)
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

local function KeyGen(K: number, Eta1: number, D: buffer, Z: buffer): (buffer, buffer)
	if not (((K == 2) and (Eta1 == 3)) or ((K == 3) and (Eta1 == 2)) or ((K == 4) and (Eta1 == 2))) then
		error("Invalid keygen parameters")
	end

	if buffer.len(D) ~= 32 then
		error("D must be 32 bytes")
	end

	if buffer.len(Z) ~= 32 then
		error("Z must be 32 bytes")
	end

	local PkeSecretKeyLength = K * 384
	local PublicKeyLength = PkeSecretKeyLength + 32
	local PublicKey = buffer.create(PublicKeyLength)
	local SecretKey = buffer.create(PkeSecretKeyLength + PublicKeyLength + 64)
	local Public = PublicKeySlot(K, PublicKeyLength)
	local Secret = SecretKeySlot(K)
	Pke.KeyGen(K, Eta1, D, PublicKey, SecretKey, Public.T, Secret.S)

	local Hashed = Public.Hashed
	buffer.copy(Hashed, 0, PublicKey, 0, PublicKeyLength)
	SHA3.SHA3_256_Into(PublicKey, 0, PublicKeyLength, Hashed, PublicKeyLength)

	local HashOffset = PkeSecretKeyLength + PublicKeyLength
	buffer.copy(SecretKey, PkeSecretKeyLength, Hashed, 0, PublicKeyLength + 32)
	Copy32(SecretKey, HashOffset + 32, Z, 0)
	buffer.copy(Secret.Encoded, 0, SecretKey, 0, PkeSecretKeyLength)

	Public.IsValid = true
	Public.IsFilled = true
	Secret.IsValid = true
	Secret.IsFilled = true

	return PublicKey, SecretKey
end

local function Encapsulate(Message: buffer, K: number, Eta1: number, Eta2: number, Du: number, Dv: number, PublicKey: buffer): (buffer?, buffer?)
	if not CheckEncapParams(K, Eta1, Eta2, Du, Dv) then
		error("Invalid encapsulation parameters")
	end

	if buffer.len(Message) ~= 32 then
		error("Message must be 32 bytes")
	end

	local PublicKeyLength = K * 384 + 32
	if typeof(PublicKey) ~= "buffer" or buffer.len(PublicKey) ~= PublicKeyLength then
		return nil, nil
	end

	local Known = KnownPublicKey(K, PublicKey, 0, PublicKeyLength)
	if not Known.IsValid then
		return nil, nil
	end

	local GInput = G_INPUT
	local GOutput = G_OUTPUT
	Copy32(GInput, 0, Message, 0)
	Copy32(GInput, 32, Known.Hashed, PublicKeyLength)
	SHA3.SHA3_512_Into(GInput, 0, 64, GOutput, 0)

	local Ciphertext = buffer.create(32 * (K * Du + Dv))
	Pke.Encrypt(K, Eta1, Eta2, Du, Dv, Known.T, PublicKey, K * 384, Message, GOutput, 32, Ciphertext)

	local SharedSecret = buffer.create(32)
	Copy32(SharedSecret, 0, GOutput, 0)

	return Ciphertext, SharedSecret
end

local function Decapsulate(Ciphertext: buffer, K: number, Eta1: number, Eta2: number, Du: number, Dv: number, SecretKey: buffer): buffer?
	if not CheckEncapParams(K, Eta1, Eta2, Du, Dv) then
		error("Invalid decapsulation parameters")
	end

	local PublicKeyOffset = K * 384
	local PublicKeyLength = PublicKeyOffset + 32
	local HashOffset = PublicKeyOffset + PublicKeyLength
	local ZOffset = HashOffset + 32

	if buffer.len(SecretKey) ~= ZOffset + 32 then
		error("Invalid secret key length")
	end

	local Known = KnownPublicKey(K, SecretKey, PublicKeyOffset, PublicKeyLength)
	if not SameBytes(SecretKey, HashOffset, Known.Hashed, PublicKeyLength, 32) then
		error("Invalid secret key, the hash it stores does not match its public key")
	end

	local CiphertextLength = 32 * (K * Du + Dv)
	if typeof(Ciphertext) ~= "buffer" or buffer.len(Ciphertext) ~= CiphertextLength then
		return nil
	end

	local JInput: buffer
	if DECAP_J_INPUT and buffer.len(DECAP_J_INPUT) >= 32 + CiphertextLength then
		JInput = DECAP_J_INPUT
	else
		JInput = buffer.create(32 + CiphertextLength)
		DECAP_J_INPUT = JInput
	end
	Copy32(JInput, 0, SecretKey, ZOffset)
	buffer.copy(JInput, 32, Ciphertext, 0, CiphertextLength)

	local RejectionSecret = DECAP_REJECTION
	SHA3.SHAKE256_Into(JInput, 0, 32 + CiphertextLength, RejectionSecret, 0, 32)

	local GOutput = G_OUTPUT
	local ValidMask = 0x00000000

	local MPrime = DECAP_MESSAGE
	local Secret = KnownSecretKey(K, SecretKey)
	if Secret.IsValid then
		Pke.Decrypt(K, Du, Dv, Secret.S, Ciphertext, MPrime)

		local GInput = G_INPUT
		Copy32(GInput, 0, MPrime, 0)
		Copy32(GInput, 32, SecretKey, HashOffset)
		SHA3.SHA3_512_Into(GInput, 0, 64, GOutput, 0)

		if Known.IsValid then
			local CiphertextPrime: buffer
			if DECAP_CIPHERTEXT and buffer.len(DECAP_CIPHERTEXT) >= CiphertextLength then
				CiphertextPrime = DECAP_CIPHERTEXT
			else
				CiphertextPrime = buffer.create(CiphertextLength)
				DECAP_CIPHERTEXT = CiphertextPrime
			end
			Pke.Encrypt(K, Eta1, Eta2, Du, Dv, Known.T, SecretKey, PublicKeyOffset + K * 384, MPrime, GOutput, 32, CiphertextPrime)
			ValidMask = CtCompareMask(Ciphertext, CiphertextPrime, CiphertextLength)
		end
	end

	local SharedSecret = buffer.create(32)
	CtSelectBuffer(ValidMask, SharedSecret, GOutput, RejectionSecret, 32)

	return SharedSecret
end

local function SecretsEqual(Secret1: buffer, Secret2: buffer): boolean
	return CtCompare(Secret1, Secret2)
end

local function ClearCaches(): ()
	for _, Slot in SECRET_KEYS do
		buffer.fill(Slot.Encoded, 0, 0)
		buffer.fill(Slot.S, 0, 0)
		Slot.IsFilled = false
	end

	for _, Slot in PUBLIC_KEYS do
		Slot.IsFilled = false
	end

	buffer.fill(G_INPUT, 0, 0)
	buffer.fill(G_OUTPUT, 0, 0)
	buffer.fill(DECAP_MESSAGE, 0, 0)
	buffer.fill(DECAP_REJECTION, 0, 0)
	if DECAP_J_INPUT then
		buffer.fill(DECAP_J_INPUT, 0, 0)
	end
	if DECAP_CIPHERTEXT then
		buffer.fill(DECAP_CIPHERTEXT, 0, 0)
	end
	if VALIDATE_VECTOR then
		buffer.fill(VALIDATE_VECTOR, 0, 0)
	end

	Pke.ClearCaches()
	Sampling.ClearCaches()
	SHA3.ClearCaches()
end

local function ValidateDecapsulationKey(K: number, SecretKey: buffer): boolean
	if K ~= 2 and K ~= 3 and K ~= 4 then
		error("Invalid K parameter")
	end

	local PkeSecretKeyLength = K * 384
	local PublicKeyLength = PkeSecretKeyLength + 32

	if typeof(SecretKey) ~= "buffer" or buffer.len(SecretKey) ~= PkeSecretKeyLength + PublicKeyLength + 64 then
		return false
	end

	local ValidateVector: buffer
	if VALIDATE_VECTOR then
		ValidateVector = VALIDATE_VECTOR
	else
		ValidateVector = buffer.create(4 * 512)
		VALIDATE_VECTOR = ValidateVector
	end

	local Known = KnownPublicKey(K, SecretKey, PkeSecretKeyLength, PublicKeyLength)
	if not (Known.IsValid and Packing.Decode12(SecretKey, 0, K * 256, ValidateVector)) then
		return false
	end

	return SameBytes(SecretKey, PkeSecretKeyLength + PublicKeyLength, Known.Hashed, PublicKeyLength, 32)
end

local MlKem: MlKemModule

local function MakeScheme(K: number, Eta1: number, Eta2: number, Du: number, Dv: number): Scheme
	return {
		KeyGen = function(D: buffer, Z: buffer): (buffer, buffer)
			return KeyGen(K, Eta1, D, Z)
		end,

		Encapsulate = function(Message: buffer, PublicKey: buffer): (buffer?, buffer?)
			return Encapsulate(Message, K, Eta1, Eta2, Du, Dv, PublicKey)
		end,

		Decapsulate = function(Ciphertext: buffer, SecretKey: buffer): buffer?
			return Decapsulate(Ciphertext, K, Eta1, Eta2, Du, Dv, SecretKey)
		end,

		GenerateKeys = function(): (buffer, buffer)
			local Csprng = MlKem.CSPRNG
			return KeyGen(K, Eta1, Csprng.RandomBytes(32), Csprng.RandomBytes(32))
		end,

		ValidateDecapsulationKey = function(SecretKey: buffer): boolean
			return ValidateDecapsulationKey(K, SecretKey)
		end,
	}
end

MlKem = Lazy.Attach({
	KeyGen = KeyGen,
	Encapsulate = Encapsulate,
	Decapsulate = Decapsulate,
	SecretsEqual = SecretsEqual,
	ClearCaches = ClearCaches,
	ValidateDecapsulationKey = ValidateDecapsulationKey,
	MLKEM_512 = MakeScheme(2, 3, 2, 10, 4),
	MLKEM_768 = MakeScheme(3, 2, 2, 10, 4),
	MLKEM_1024 = MakeScheme(4, 2, 2, 11, 5),
}, {
	CSPRNG = function()
		return require("../Utilities/CSPRNG")
	end,
})

return MlKem
