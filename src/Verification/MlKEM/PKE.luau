--[=[
	ML-KEM Public Key Encryption Module

	K-PKE (CPA-secure public key encryption) implementation for ML-KEM.
	Provides key generation, encryption, and decryption operations
	as specified in NIST FIPS 203.
--]=]

--!strict
--!optimize 2

local Ntt = require("./NTT")
local Sampling = require("./Sampling")
local Packing = require("./Packing")
local SHA3 = require("../../Hashing/SHA3")

local NttAt = Ntt.NttAt
local InttAt = Ntt.InttAt

local N = 256
local POLY_SIZE = 512
local VECTOR_SIZE = 4 * POLY_SIZE

local KEYGEN_G_INPUT: buffer = buffer.create(33)
local KEYGEN_RHO_SIGMA: buffer = buffer.create(64)

local WORK_R: buffer = buffer.create(VECTOR_SIZE)
local WORK_E1: buffer = buffer.create(VECTOR_SIZE)
local WORK_U: buffer = buffer.create(VECTOR_SIZE)
local WORK_E2: buffer = buffer.create(POLY_SIZE)
local WORK_V: buffer = buffer.create(POLY_SIZE)

local Pke = {}

function Pke.KeyGen(K: number, Eta1: number, Seed: buffer, PublicKey: buffer, SecretKey: buffer, T: buffer, S: buffer): ()
	local GInput = KEYGEN_G_INPUT
	buffer.writef64(GInput, 0, buffer.readf64(Seed, 0))
	buffer.writef64(GInput, 8, buffer.readf64(Seed, 8))
	buffer.writef64(GInput, 16, buffer.readf64(Seed, 16))
	buffer.writef64(GInput, 24, buffer.readf64(Seed, 24))
	buffer.writeu8(GInput, 32, K)

	local RhoSigma = KEYGEN_RHO_SIGMA
	SHA3.SHA3_512_Into(GInput, 0, 33, RhoSigma, 0)

	local A = Sampling.GenerateMatrix(K, RhoSigma, 0, false)
	Sampling.GenerateVector(K, Eta1, RhoSigma, 32, 0, S)
	Sampling.GenerateVector(K, Eta1, RhoSigma, 32, K, T)

	for Index = 0, (K - 1) * POLY_SIZE, POLY_SIZE do
		NttAt(S, Index)
		NttAt(T, Index)
	end
	Ntt.MatrixAccumulate(A, S, T, K)

	local Coefficients = K * N
	local RhoOffset = Coefficients * 3 / 2
	Packing.Encode12(T, Coefficients, PublicKey, 0)
	buffer.writef64(PublicKey, RhoOffset, buffer.readf64(RhoSigma, 0))
	buffer.writef64(PublicKey, RhoOffset + 8, buffer.readf64(RhoSigma, 8))
	buffer.writef64(PublicKey, RhoOffset + 16, buffer.readf64(RhoSigma, 16))
	buffer.writef64(PublicKey, RhoOffset + 24, buffer.readf64(RhoSigma, 24))
	Packing.Encode12(S, Coefficients, SecretKey, 0)
end

function Pke.Encrypt(K: number, Eta1: number, Eta2: number, Du: number, Dv: number, T: buffer, Rho: buffer, RhoOffset: number, Message: buffer, Randomness: buffer, RandomnessOffset: number, Ciphertext: buffer): ()
	local Coefficients = K * N
	local A = Sampling.GenerateMatrix(K, Rho, RhoOffset, true)
	local R = WORK_R
	local E1 = WORK_E1
	local E2 = WORK_E2
	Sampling.GenerateVector(K, Eta1, Randomness, RandomnessOffset, 0, R)
	Sampling.GenerateVector(K, Eta2, Randomness, RandomnessOffset, K, E1)
	Sampling.GenerateVector(1, Eta2, Randomness, RandomnessOffset, 2 * K, E2)

	for Index = 0, (K - 1) * POLY_SIZE, POLY_SIZE do
		NttAt(R, Index)
	end

	local U = WORK_U
	Ntt.MatrixMul(A, R, U, K)
	for Index = 0, (K - 1) * POLY_SIZE, POLY_SIZE do
		InttAt(U, Index)
	end
	Packing.EncodeU(U, E1, Coefficients, Du, Ciphertext)

	local V = WORK_V
	Ntt.DotMul(T, 0, R, 0, K, V, 0)
	InttAt(V, 0)
	Packing.EncodeV(V, E2, Message, Dv, Ciphertext, Coefficients * Du / 8)
end

function Pke.Decrypt(K: number, Du: number, Dv: number, S: buffer, Ciphertext: buffer, Message: buffer): ()
	local Coefficients = K * N
	local U = WORK_U
	Packing.DecodeU(Ciphertext, Coefficients, Du, U)
	for Index = 0, (K - 1) * POLY_SIZE, POLY_SIZE do
		NttAt(U, Index)
	end

	local Product = WORK_V
	Ntt.DotMul(S, 0, U, 0, K, Product, 0)
	InttAt(Product, 0)
	Packing.DecodeMessage(Ciphertext, Coefficients * Du / 8, Dv, Product, Message)
end

function Pke.ClearCaches(): ()
	buffer.fill(KEYGEN_G_INPUT, 0, 0)
	buffer.fill(KEYGEN_RHO_SIGMA, 0, 0)
	buffer.fill(WORK_R, 0, 0)
	buffer.fill(WORK_E1, 0, 0)
	buffer.fill(WORK_U, 0, 0)
	buffer.fill(WORK_E2, 0, 0)
	buffer.fill(WORK_V, 0, 0)
end

return Pke
