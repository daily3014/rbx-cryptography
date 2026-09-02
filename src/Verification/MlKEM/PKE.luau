--[=[
	ML-KEM Public Key Encryption Module
	
	K-PKE (CPA-secure public key encryption) implementation for ML-KEM.
	Provides key generation, encryption, and decryption operations
	as specified in NIST FIPS 203.
	
	Example usage:
		local Seed = buffer.fromstring("32_byte_seed_here...")
		local PublicKey, SecretKey = PKE.MLKEM_1024.KeyGen(Seed)
		
		local Message = buffer.create(32)
		local Randomness = buffer.create(32)
		local Ciphertext = PKE.MLKEM_1024.Encrypt(PublicKey, Message, Randomness)
		
		local Plaintext = PKE.MLKEM_1024.Decrypt(SecretKey, Ciphertext)
--]=]

--!strict
--!optimize 2
--!native

local Ntt = require("./NTT")

local PolyVec = require("./PolyVec")
local Sampling = require("./Sampling")

local Serialize = require("./Serialize")
local Compression = require("./Compression")

local Params = require("./Params")
local Utils = require("./Utils")
local SHA3 = require("../../Hashing/SHA3")

local LOG2N = 8
local N = 2^LOG2N
local Q = 3329

local TEMP_V = buffer.create(N * 2)
local TEMP_T = buffer.create(N * 2)

local KEYGEN_G_INPUT = buffer.create(33)
local KEYGEN_RHO = buffer.create(32)
local KEYGEN_SIGMA = buffer.create(32)

local Pke = {}

local function AddNoiseAndMessage(V: buffer, E2: buffer, Message: buffer)
	local Modulus = Q
	local Half = 1665

	for ByteIndex = 0, 31 do
		local Byte = buffer.readu8(Message, ByteIndex)
		local Base = ByteIndex * 16

		for Bit = 0, 7 do
			local Offset = Base + Bit * 2
			local M = bit32.band(bit32.rshift(Byte, Bit), 1) * Half
			buffer.writeu16(V, Offset, (buffer.readu16(V, Offset) + buffer.readu16(E2, Offset) + M) % Modulus)
		end
	end
end

local function SubCompressEncode1(V: buffer, T: buffer): buffer
	local Modulus = Q
	local Output = buffer.create(32)

	for ByteIndex = 0, 31 do
		local Base = ByteIndex * 16
		local Byte = 0

		for Bit = 0, 7 do
			local Offset = Base + Bit * 2
			local Diff = buffer.readu16(V, Offset) - buffer.readu16(T, Offset)
			local Rounded = (Diff * 2 + 1664) // Modulus
			Byte = bit32.bor(Byte, bit32.lshift(bit32.band(Rounded, 1), Bit))
		end

		buffer.writeu8(Output, ByteIndex, Byte)
	end

	return Output
end

function Pke.KeyGen(K: number, Eta1: number, Seed: buffer): (buffer, buffer)
	if not Params.CheckKeygenParams(K, Eta1) then
		error("Invalid keygen parameters")
	end
	if buffer.len(Seed) ~= 32 then
		error("Seed must be 32 bytes")
	end

	local GInput = KEYGEN_G_INPUT
	buffer.copy(GInput, 0, Seed, 0, 32)
	buffer.writeu8(GInput, 32, K)

	local GOutput = SHA3.SHA3_512_Internal(GInput)
	local Rho = KEYGEN_RHO
	local Sigma = KEYGEN_SIGMA
	buffer.copy(Rho, 0, GOutput, 0, 32)
	buffer.copy(Sigma, 0, GOutput, 32, 32)

	local APrime = Sampling.GenerateMatrix(K, Rho, false)

	local Nonce = 0
	local S = Sampling.GenerateVector(K, Eta1, Sigma, Nonce)
	Nonce += K
	local E = Sampling.GenerateVector(K, Eta1, Sigma, Nonce)

	PolyVec.VecNtt(S, K)
	PolyVec.VecNtt(E, K)

	local TPrime = PolyVec.VecCreate(K)
	PolyVec.MatVecMultiply(APrime, S, TPrime, K, K, K)
	PolyVec.VecAddTo(E, TPrime, K)

	local PublicKeyLen = Utils.GetPkePublicKeyLen(K)
	local PublicKey = buffer.create(PublicKeyLen)

	local EncodedTPrime = PolyVec.VecEncode(TPrime, K, 12)
	local RhoOffset = K * 12 * 32
	buffer.copy(PublicKey, 0, EncodedTPrime, 0, RhoOffset)
	buffer.copy(PublicKey, RhoOffset, Rho, 0, 32)

	return PublicKey, PolyVec.VecEncode(S, K, 12)
end

function Pke.Encrypt(K: number, Eta1: number, Eta2: number, Du: number, Dv: number, PublicKey: buffer, Message: buffer, Randomness: buffer): buffer?
	if not Params.CheckEncryptParams(K, Eta1, Eta2, Du, Dv) then
		error("Invalid encryption parameters")
	end
	if buffer.len(PublicKey) ~= Utils.GetPkePublicKeyLen(K) then
		error("Invalid public key length")
	end
	if buffer.len(Message) ~= 32 then
		error("Message must be 32 bytes")
	end
	if buffer.len(Randomness) ~= 32 then
		error("Randomness must be 32 bytes")
	end
	
	local RhoOffset = K * 12 * 32
	local EncodedTPrime = buffer.create(RhoOffset)
	local Rho = buffer.create(32)
	buffer.copy(EncodedTPrime, 0, PublicKey, 0, RhoOffset)
	buffer.copy(Rho, 0, PublicKey, RhoOffset, 32)

	local TPrime, TValid = PolyVec.VecDecode(EncodedTPrime, K, 12)
	if not TValid then
		return nil
	end

	local APrime = Sampling.GenerateMatrix(K, Rho, true)

	local Nonce = 0
	local R = Sampling.GenerateVector(K, Eta1, Randomness, Nonce)
	Nonce += K
	local E1 = Sampling.GenerateVector(K, Eta2, Randomness, Nonce)
	Nonce += K
	local E2 = Sampling.GenerateNoisePoly(Eta2, Randomness, Nonce)

	PolyVec.VecNtt(R, K)
	
	local U = PolyVec.VecCreate(K)
	PolyVec.MatVecMultiply(APrime, R, U, K, K, K)

	PolyVec.VecIntt(U, K)
	PolyVec.VecAddTo(E1, U, K)

	local V = TEMP_V
	Ntt.PolyVecDotAt(TPrime, 0, R, 0, K, V, 0)
	Ntt.InttAt(V, 0)
	AddNoiseAndMessage(V, E2, Message)

	PolyVec.VecCompress(U, K, Du)
	local EncodedU = PolyVec.VecEncode(U, K, Du)

	Compression.PolyCompress(V, Dv)
	local EncodedV = Serialize.Encode(V, Dv)

	local CiphertextLen = Utils.GetPkeCipherTextLen(K, Du, Dv)
	local Ciphertext = buffer.create(CiphertextLen)
	local ULen = buffer.len(EncodedU)
	buffer.copy(Ciphertext, 0, EncodedU, 0, ULen)
	buffer.copy(Ciphertext, ULen, EncodedV, 0, buffer.len(EncodedV))

	return Ciphertext
end

function Pke.Decrypt(K: number, Du: number, Dv: number, SecretKey: buffer, Ciphertext: buffer): buffer?
	if not Params.CheckDecryptParams(K, Du, Dv) then
		error("Invalid decryption parameters")
	end
	if buffer.len(SecretKey) ~= Utils.GetPkeSecretKeyLen(K) then
		error("Invalid secret key length")
	end
	if buffer.len(Ciphertext) ~= Utils.GetPkeCipherTextLen(K, Du, Dv) then
		error("Invalid ciphertext length")
	end

	local ULen = K * Du * 32
	local VLen = Dv * 32

	local EncodedU = buffer.create(ULen)
	local EncodedV = buffer.create(VLen)
	buffer.copy(EncodedU, 0, Ciphertext, 0, ULen)
	buffer.copy(EncodedV, 0, Ciphertext, ULen, VLen)

	local U = PolyVec.VecDecode(EncodedU, K, Du)
	PolyVec.VecDecompress(U, K, Du)

	local V = Serialize.Decode(EncodedV, Dv)
	Compression.PolyDecompress(V, Dv)

	local SPrime, SValid = PolyVec.VecDecode(SecretKey, K, 12)
	if not SValid then
		return nil
	end

	PolyVec.VecNtt(U, K)

	local T = TEMP_T
	Ntt.PolyVecDotAt(SPrime, 0, U, 0, K, T, 0)
	Ntt.InttAt(T, 0)
	local Plaintext = SubCompressEncode1(V, T)

	return Plaintext
end

Pke.MLKEM_512 = {
	KeyGen = function(Seed: buffer): (buffer, buffer)
		return Pke.KeyGen(2, 3, Seed)
	end,

	Encrypt = function(PublicKey: buffer, Message: buffer, Randomness: buffer): buffer?
		return Pke.Encrypt(2, 3, 2, 10, 4, PublicKey, Message, Randomness)
	end,

	Decrypt = function(SecretKey: buffer, Ciphertext: buffer): buffer?
		return Pke.Decrypt(2, 10, 4, SecretKey, Ciphertext)
	end
}

Pke.MLKEM_768 = {
	KeyGen = function(Seed: buffer): (buffer, buffer)
		return Pke.KeyGen(3, 2, Seed)
	end,

	Encrypt = function(PublicKey: buffer, Message: buffer, Randomness: buffer): buffer?
		return Pke.Encrypt(3, 2, 2, 10, 4, PublicKey, Message, Randomness)
	end,

	Decrypt = function(SecretKey: buffer, Ciphertext: buffer): buffer?
		return Pke.Decrypt(3, 10, 4, SecretKey, Ciphertext)
	end
}

Pke.MLKEM_1024 = {
	KeyGen = function(Seed: buffer): (buffer, buffer)
		return Pke.KeyGen(4, 2, Seed)
	end,

	Encrypt = function(PublicKey: buffer, Message: buffer, Randomness: buffer): buffer?
		return Pke.Encrypt(4, 2, 2, 11, 5, PublicKey, Message, Randomness)
	end,

	Decrypt = function(SecretKey: buffer, Ciphertext: buffer): buffer?
		return Pke.Decrypt(4, 11, 5, SecretKey, Ciphertext)
	end
}

return Pke