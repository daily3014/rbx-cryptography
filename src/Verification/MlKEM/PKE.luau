--[=[
	ML-KEM Public Key Encryption Module
	
	K-PKE (CPA-secure public key encryption) implementation for ML-KEM.
	Provides key generation, encryption, and decryption operations
	as specified in NIST FIPS 203.
	
	Example usage:
		local PKE = require(script.PKE)
		
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
local SHA3 = require("./SHA3")

local LOG2N = 8
local N = 2^LOG2N
local POLY_SIZE = N * 2 

local TEMP_V = buffer.create(N * 2)
local TEMP_V2 = buffer.create(N * 2)
local TEMP_SINGLE_POLY = buffer.create(N * 2)
local TEMP_R_POLY = buffer.create(N * 2)
local TEMP_T = buffer.create(N * 2)
local TEMP_T2 = buffer.create(N * 2)
local TEMP_U_POLY = buffer.create(N * 2)

local KEYGEN_G_INPUT = buffer.create(33)
local KEYGEN_RHO = buffer.create(32)
local KEYGEN_SIGMA = buffer.create(32)

local Pke = {}

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

	local GOutput = SHA3.SHA3_512(GInput)
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

function Pke.Encrypt(K: number, Eta1: number, Eta2: number, Du: number, Dv: number, PublicKey: buffer, Message: buffer, Randomness: buffer): buffer
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

	local TPrime = PolyVec.VecDecode(EncodedTPrime, K, 12)
	local ReEncodedTPrime = PolyVec.VecEncode(TPrime, K, 12)
	local IsValid = Utils.CtMemcmp(EncodedTPrime, ReEncodedTPrime)
	if IsValid ~= 0xFFFFFFFF then
		error("Key encapsulation verification failed")
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

	local V = buffer.create(N * 2)
	local TempV = buffer.create(N * 2)
	local SinglePoly = buffer.create(N * 2)

	local V = TEMP_V
	local TempV = TEMP_V2
	local SinglePoly = TEMP_SINGLE_POLY
	local RPoly = TEMP_R_POLY
	buffer.fill(V, 0, 0, N * 2)

	local PolySize = POLY_SIZE
	for I = 0, K - 1 do
		local TPolyOffset = I * PolySize
		local RPolyOffset = I * PolySize
		buffer.copy(SinglePoly, 0, TPrime, TPolyOffset, PolySize)
		buffer.copy(RPoly, 0, R, RPolyOffset, PolySize)
		Ntt.PolyMul(SinglePoly, RPoly, TempV)
		Ntt.PolyAdd(V, TempV, V)
	end

	Ntt.Intt(V)
	Ntt.PolyAdd(V, E2, V)

	local M = Serialize.Decode(Message, 1)
	Compression.PolyDecompress(M, 1)
	Ntt.PolyAdd(V, M, V)

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

function Pke.Decrypt(K: number, Du: number, Dv: number, SecretKey: buffer, Ciphertext: buffer): buffer
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

	local SPrime = PolyVec.VecDecode(SecretKey, K, 12)

	PolyVec.VecNtt(U, K)

	local T = buffer.create(N * 2)
	local TempT = buffer.create(N * 2)
	local SinglePoly = buffer.create(N * 2)

	local T = TEMP_T
	local TempT = TEMP_T2
	local SinglePoly = TEMP_SINGLE_POLY
	local UPoly = TEMP_U_POLY
	buffer.fill(T, 0, 0, N * 2)

	local PolySize = POLY_SIZE
	for I = 0, K - 1 do
		local SPolyOffset = I * PolySize
		local UPolyOffset = I * PolySize

		buffer.copy(SinglePoly, 0, SPrime, SPolyOffset, PolySize)
		buffer.copy(UPoly, 0, U, UPolyOffset, PolySize)

		Ntt.PolyMul(SinglePoly, UPoly, TempT)
		Ntt.PolyAdd(T, TempT, T)
	end

	Ntt.Intt(T)
	Ntt.PolySub(V, T, V)

	Compression.PolyCompress(V, 1)
	local Plaintext = Serialize.Encode(V, 1)

	return Plaintext
end

Pke.MLKEM_512 = {
	KeyGen = function(Seed: buffer): (buffer, buffer)
		return Pke.KeyGen(2, 3, Seed)
	end,

	Encrypt = function(PublicKey: buffer, Message: buffer, Randomness: buffer): buffer
		return Pke.Encrypt(2, 3, 2, 10, 4, PublicKey, Message, Randomness)
	end,

	Decrypt = function(SecretKey: buffer, Ciphertext: buffer): buffer
		return Pke.Decrypt(2, 10, 4, SecretKey, Ciphertext)
	end
}

Pke.MLKEM_768 = {
	KeyGen = function(Seed: buffer): (buffer, buffer)
		return Pke.KeyGen(3, 2, Seed)
	end,

	Encrypt = function(PublicKey: buffer, Message: buffer, Randomness: buffer): buffer
		return Pke.Encrypt(3, 2, 2, 10, 4, PublicKey, Message, Randomness)
	end,

	Decrypt = function(SecretKey: buffer, Ciphertext: buffer): buffer
		return Pke.Decrypt(3, 10, 4, SecretKey, Ciphertext)
	end
}

Pke.MLKEM_1024 = {
	KeyGen = function(Seed: buffer): (buffer, buffer)
		return Pke.KeyGen(4, 2, Seed)
	end,

	Encrypt = function(PublicKey: buffer, Message: buffer, Randomness: buffer): buffer
		return Pke.Encrypt(4, 2, 2, 11, 5, PublicKey, Message, Randomness)
	end,

	Decrypt = function(SecretKey: buffer, Ciphertext: buffer): buffer
		return Pke.Decrypt(4, 11, 5, SecretKey, Ciphertext)
	end
}

return Pke