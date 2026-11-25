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
local Packing = require("./Packing")
local SHA3 = require("../../Hashing/SHA3")

local N = 256
local POLY_SIZE = 512
local VECTOR_SIZE = 4 * POLY_SIZE

local KEYGEN_G_INPUT = buffer.create(33)
local KEYGEN_S = buffer.create(VECTOR_SIZE)
local KEYGEN_T = buffer.create(VECTOR_SIZE)

local ENCRYPT_T = buffer.create(VECTOR_SIZE)
local ENCRYPT_R = buffer.create(VECTOR_SIZE)
local ENCRYPT_E1 = buffer.create(VECTOR_SIZE)
local ENCRYPT_U = buffer.create(VECTOR_SIZE)
local ENCRYPT_E2 = buffer.create(POLY_SIZE)
local ENCRYPT_V = buffer.create(POLY_SIZE)

local DECRYPT_S = buffer.create(VECTOR_SIZE)
local DECRYPT_U = buffer.create(VECTOR_SIZE)
local DECRYPT_PRODUCT = buffer.create(POLY_SIZE)

local Pke = {}

function Pke.KeyGen(K: number, Eta1: number, Seed: buffer, PublicKey: buffer, SecretKey: buffer)
	local GInput = KEYGEN_G_INPUT
	buffer.copy(GInput, 0, Seed, 0, 32)
	buffer.writeu8(GInput, 32, K)
	local RhoSigma = SHA3.SHA3_512_Internal(GInput)

	local A = Sampling.GenerateMatrix(K, RhoSigma, 0, false)
	local S = KEYGEN_S
	local T = KEYGEN_T
	Sampling.GenerateVector(K, Eta1, RhoSigma, 32, 0, S)
	Sampling.GenerateVector(K, Eta1, RhoSigma, 32, K, T)

	PolyVec.VecNtt(S, K)
	PolyVec.VecNtt(T, K)
	PolyVec.MatVecMultiplyAccumulate(A, S, T, K)

	local Coefficients = K * N
	local RhoOffset = Coefficients * 3 / 2
	Packing.Encode12(T, Coefficients, PublicKey, 0)
	buffer.copy(PublicKey, RhoOffset, RhoSigma, 0, 32)
	Packing.Encode12(S, Coefficients, SecretKey, 0)
end

function Pke.Encrypt(K: number, Eta1: number, Eta2: number, Du: number, Dv: number, PublicKey: buffer, PublicKeyOffset: number, Message: buffer, Randomness: buffer, RandomnessOffset: number, Ciphertext: buffer): boolean
	local Coefficients = K * N
	local T = ENCRYPT_T
	if not Packing.Decode12(PublicKey, PublicKeyOffset, Coefficients, T) then
		return false
	end

	local A = Sampling.GenerateMatrix(K, PublicKey, PublicKeyOffset + Coefficients * 3 / 2, true)
	local R = ENCRYPT_R
	local E1 = ENCRYPT_E1
	local E2 = ENCRYPT_E2
	Sampling.GenerateVector(K, Eta1, Randomness, RandomnessOffset, 0, R)
	Sampling.GenerateVector(K, Eta2, Randomness, RandomnessOffset, K, E1)
	Sampling.GenerateVector(1, Eta2, Randomness, RandomnessOffset, 2 * K, E2)

	PolyVec.VecNtt(R, K)

	local U = ENCRYPT_U
	buffer.fill(U, 0, 0, Coefficients * 2)
	PolyVec.MatVecMultiplyAccumulate(A, R, U, K)
	PolyVec.VecIntt(U, K)
	Packing.EncodeU(U, E1, Coefficients, Du, Ciphertext)

	local V = ENCRYPT_V
	buffer.fill(V, 0, 0, POLY_SIZE)
	Ntt.DotAccumulate(T, 0, R, 0, K, V, 0)
	Ntt.InttAt(V, 0)
	Packing.EncodeV(V, E2, Message, Dv, Ciphertext, Coefficients * Du / 8)

	return true
end

function Pke.Decrypt(K: number, Du: number, Dv: number, SecretKey: buffer, Ciphertext: buffer, Message: buffer): boolean
	local Coefficients = K * N
	local S = DECRYPT_S
	if not Packing.Decode12(SecretKey, 0, Coefficients, S) then
		return false
	end

	local U = DECRYPT_U
	Packing.DecodeU(Ciphertext, Coefficients, Du, U)
	PolyVec.VecNtt(U, K)

	local Product = DECRYPT_PRODUCT
	buffer.fill(Product, 0, 0, POLY_SIZE)
	Ntt.DotAccumulate(S, 0, U, 0, K, Product, 0)
	Ntt.InttAt(Product, 0)
	Packing.DecodeMessage(Ciphertext, Coefficients * Du / 8, Dv, Product, Message)

	return true
end

return Pke
