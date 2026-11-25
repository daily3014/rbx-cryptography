--[=[
	ML-DSA (FIPS 204) Digital Signature Algorithm
	
	Post quantum digital signature scheme based on lattice cryptography.
	Has three security levels: ML-DSA-44, ML-DSA-65, ML-DSA-87.

	Example usage:
		local PubKey, SecKey = MLDSA.ML_DSA_44.GenerateKeys()
		local Message = buffer.fromstring("Hello World")
		local Context = buffer.create(0)
		local Signature = buffer.create(MLDSA.ML_DSA_44.SigByteLen)
		local Random = CSPRNG.RandomBytes(32)

		local Success = MLDSA.ML_DSA_44.Sign(Message, Random, SecKey, Context, Signature)
		local Valid = MLDSA.ML_DSA_44.Verify(Message, PubKey, Context, Signature)
--]=]

--!strict
--!optimize 2
--!native

local SHA3 = require("../Hashing/SHA3")
local NTT = require("@self/NTT")

local PolyVec = require("@self/PolyVec")
local BitPack = require("@self/BitPack")
local BitPacking = require("@self/Pack")

local Sampling = require("@self/Sampling")
local Params = require("@self/Params")

local Utils = require("@self/Utils")
local CSPRNG = require("../Utilities/CSPRNG")
local CtCompare = require("../Utilities/Functions").CtCompare

local KEYGEN_SEED_BYTE_LEN = 32
local RND_BYTE_LEN = 32

local N = 256
local Q = 8380417
local POLY_SIZE = N * 4

local Mldsa = {
	CSPRNG = CSPRNG
}

type SignKey = {
	SecretKey: buffer,
	S1: buffer,
	S2: buffer,
	T0: buffer,
}

type VerifyKey = {
	PublicKey: buffer,
	T1: buffer,
	Tr: buffer,
}

type Scratch = {
	Y: buffer,
	YHat: buffer,
	W: buffer,
	Z: buffer,
	R: buffer,
	Product: buffer,
	C: buffer,
	Hints: buffer,
	CTilda: buffer,
	ChallengeInput: buffer,
}

local SIGN_KEY: SignKey? = nil
local VERIFY_KEY: VerifyKey? = nil
local SCRATCH: { [number]: Scratch } = {}

local function BuffersEqual(A: buffer, B: buffer): boolean
	local Length = buffer.len(A)
	if buffer.len(B) ~= Length then
		return false
	end

	local WordBytes = Length - Length % 8
	for Offset = 0, WordBytes - 8, 8 do
		if buffer.readu32(A, Offset) ~= buffer.readu32(B, Offset) or buffer.readu32(A, Offset + 4) ~= buffer.readu32(B, Offset + 4) then
			return false
		end
	end

	for Offset = WordBytes, Length - 1 do
		if buffer.readu8(A, Offset) ~= buffer.readu8(B, Offset) then
			return false
		end
	end

	return true
end

local function ScratchFor(K: number, L: number, W1Bw: number, CTildaSize: number): Scratch
	local Existing = SCRATCH[K]
	if Existing then
		return Existing
	end

	local VectorL, VectorK = L * POLY_SIZE, K * POLY_SIZE
	local Created: Scratch = {
		Y = buffer.create(VectorL),
		YHat = buffer.create(VectorL),
		W = buffer.create(VectorK),
		Z = buffer.create(VectorL),
		R = buffer.create(VectorK),
		Product = buffer.create(VectorK),
		C = buffer.create(POLY_SIZE),
		Hints = buffer.create(VectorK),
		CTilda = buffer.create(CTildaSize),
		ChallengeInput = buffer.create(64 + K * W1Bw * 32),
	}
	SCRATCH[K] = Created
	return Created
end

local function MessageHash(Tr: buffer, TrOffset: number, Ctx: buffer, Msg: buffer): buffer
	local ContextLength = buffer.len(Ctx)
	local MuInput = buffer.create(64 + 2 + ContextLength + buffer.len(Msg))
	buffer.copy(MuInput, 0, Tr, TrOffset, 64)
	buffer.writeu8(MuInput, 64, 0)
	buffer.writeu8(MuInput, 65, ContextLength)
	buffer.copy(MuInput, 66, Ctx, 0, ContextLength)
	buffer.copy(MuInput, 66 + ContextLength, Msg, 0, buffer.len(Msg))

	return SHA3.SHAKE256_Internal(MuInput, 64)
end

local function SignKeySetup(SecKey: buffer, K: number, L: number, D: number, Eta: number): (buffer, buffer, buffer)
	local Cached = SIGN_KEY
	if Cached and BuffersEqual(Cached.SecretKey, SecKey) then
		return Cached.S1, Cached.S2, Cached.T0
	end

	local EtaBw = Utils.BitWidth(2 * Eta)
	local S1Offset = 128
	local S2Offset = S1Offset + L * EtaBw * 32
	local T0Offset = S2Offset + K * EtaBw * 32

	local S1 = buffer.create(L * POLY_SIZE)
	local S2 = buffer.create(K * POLY_SIZE)
	local T0 = buffer.create(K * POLY_SIZE)
	BitPack.DecodeCentered(SecKey, S1Offset, L * N, Eta, EtaBw, S1, 0)
	BitPack.DecodeCentered(SecKey, S2Offset, K * N, Eta, EtaBw, S2, 0)
	BitPack.DecodeCentered(SecKey, T0Offset, K * N, bit32.lshift(1, D - 1), D, T0, 0)
	PolyVec.ForwardNTT(S1, L)
	PolyVec.ForwardNTT(S2, K)
	PolyVec.ForwardNTT(T0, K)

	local SecretKey = buffer.create(buffer.len(SecKey))
	buffer.copy(SecretKey, 0, SecKey)
	SIGN_KEY = {
		SecretKey = SecretKey,
		S1 = S1,
		S2 = S2,
		T0 = T0,
	}

	return S1, S2, T0
end

local function VerifyKeySetup(PubKey: buffer, K: number): (buffer, buffer)
	local Cached = VERIFY_KEY
	if Cached and BuffersEqual(Cached.PublicKey, PubKey) then
		return Cached.T1, Cached.Tr
	end

	local T1 = buffer.create(K * POLY_SIZE)
	BitPack.DecodeT1(PubKey, 32, K * N, T1, 0)
	PolyVec.ForwardNTT(T1, K)

	local Tr = SHA3.SHAKE256_Internal(PubKey, 64)

	local PublicKey = buffer.create(buffer.len(PubKey))
	buffer.copy(PublicKey, 0, PubKey)
	VERIFY_KEY = {
		PublicKey = PublicKey,
		T1 = T1,
		Tr = Tr,
	}

	return T1, Tr
end

local function Keygen(Seed: buffer, PubKey: buffer, SecKey: buffer, K: number, L: number, D: number, Eta: number)
	if not Params.CheckKeygenParams(K, L, D, Eta) then
		error("Invalid keygen parameters")
	end

	if buffer.len(Seed) ~= KEYGEN_SEED_BYTE_LEN then
		error("Seed must be 32 bytes")
	end

	if buffer.len(PubKey) ~= Utils.PubKeyLen(K, D) then
		error("Invalid public key buffer length")
	end

	if buffer.len(SecKey) ~= Utils.SecKeyLen(K, L, Eta, D) then
		error("Invalid secret key buffer length")
	end

	local EtaBw = Utils.BitWidth(2 * Eta)
	local S1Offset = 128
	local S2Offset = S1Offset + L * EtaBw * 32
	local T0Offset = S2Offset + K * EtaBw * 32

	local SeedHashInput = buffer.create(34)
	buffer.copy(SeedHashInput, 0, Seed, 0, 32)
	buffer.writeu8(SeedHashInput, 32, K)
	buffer.writeu8(SeedHashInput, 33, L)
	local SeedHash = SHA3.SHAKE256_Internal(SeedHashInput, 128)

	local A = Sampling.ExpandA(SeedHash, 0, K, L)

	local S1 = buffer.create(L * POLY_SIZE)
	local S2 = buffer.create(K * POLY_SIZE)
	Sampling.ExpandS(SeedHash, 32, S1, Eta, L, 0)
	Sampling.ExpandS(SeedHash, 32, S2, Eta, K, L)

	local S1Hat = buffer.create(L * POLY_SIZE)
	buffer.copy(S1Hat, 0, S1, 0, L * POLY_SIZE)
	PolyVec.ForwardNTT(S1Hat, L)

	local T = buffer.create(K * POLY_SIZE)
	PolyVec.MatrixMultiply(A, S1Hat, T, L)
	PolyVec.InverseNTT(T, K)

	local T1 = buffer.create(K * POLY_SIZE)
	local T0 = buffer.create(K * POLY_SIZE)
	PolyVec.Power2RoundSum(T, S2, T1, T0, K)

	buffer.copy(PubKey, 0, SeedHash, 0, 32)
	BitPack.EncodeT1(T1, 0, K * N, PubKey, 32)
	local Tr = SHA3.SHAKE256_Internal(PubKey, 64)

	buffer.copy(SecKey, 0, SeedHash, 0, 32)
	buffer.copy(SecKey, 32, SeedHash, 96, 32)
	buffer.copy(SecKey, 64, Tr, 0, 64)
	BitPack.EncodeCentered(S1, 0, L * N, Eta, EtaBw, SecKey, S1Offset)
	BitPack.EncodeCentered(S2, 0, K * N, Eta, EtaBw, SecKey, S2Offset)
	BitPack.EncodeCentered(T0, 0, K * N, bit32.lshift(1, D - 1), D, SecKey, T0Offset)
end

local function SignMuCore(Mu: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer, K: number, L: number, D: number, Eta: number, Gamma1: number, Gamma2: number, Tau: number, Beta: number, Omega: number, Lambda: number): boolean
	if buffer.len(Rnd) ~= RND_BYTE_LEN then
		error("Rnd must be 32 bytes")
	end

	if buffer.len(SecKey) ~= Utils.SecKeyLen(K, L, Eta, D) then
		error("Invalid secret key length")
	end

	if buffer.len(Sig) ~= Utils.SigLen(K, L, Gamma1, Omega, Lambda) then
		error("Invalid signature buffer length")
	end

	local Alpha = bit32.lshift(Gamma2, 1)
	local W1Bw = Utils.BitWidth(math.floor((Q - 1) / Alpha) - 1)
	local CTildaSize = math.floor((2 * Lambda) / 8)
	local Gamma1Bw = Utils.BitWidth(Gamma1)

	local A = Sampling.ExpandA(SecKey, 0, K, L)

	local RhoPrimeInput = buffer.create(128)
	buffer.copy(RhoPrimeInput, 0, SecKey, 32, 32)
	buffer.copy(RhoPrimeInput, 32, Rnd, 0, 32)
	buffer.copy(RhoPrimeInput, 64, Mu, 0, 64)
	local RhoPrime = SHA3.SHAKE256_Internal(RhoPrimeInput, 64)

	local S1, S2, T0 = SignKeySetup(SecKey, K, L, D, Eta)

	local Work = ScratchFor(K, L, W1Bw, CTildaSize)
	local Y = Work.Y
	local YHat = Work.YHat
	local W = Work.W
	local Z = Work.Z
	local R = Work.R
	local Product = Work.Product
	local C = Work.C
	local Hints = Work.Hints
	local ChallengeInput = Work.ChallengeInput
	buffer.copy(ChallengeInput, 0, Mu, 0, 64)

	local CTilda = Work.CTilda
	local HasSigned = false
	local Kappa = 0

	while not HasSigned do
		if Kappa + L > 65536 then
			return false
		end

		Sampling.ExpandMask(RhoPrime, Kappa, Y, Gamma1, L)
		buffer.copy(YHat, 0, Y, 0, L * POLY_SIZE)
		PolyVec.ForwardNTT(YHat, L)
		PolyVec.MatrixMultiply(A, YHat, W, L)
		PolyVec.InverseNTT(W, K)

		PolyVec.HighBitsEncode(W, K, Gamma2, ChallengeInput, 64)
		CTilda = SHA3.SHAKE256_Internal(ChallengeInput, CTildaSize)

		Sampling.SampleInBall(CTilda, C, Tau)
		NTT.ForwardNTTWithOffset(C, 0)

		PolyVec.InverseNTTProduct(C, S2, R, K)
		local Rejected = PolyVec.SubtractLowBitsExceeds(W, R, K, Gamma2, Gamma2 - Beta)

		if not Rejected then
			PolyVec.InverseNTTProduct(C, S1, Z, L)
			Rejected = PolyVec.AddExceeds(Y, Z, Z, L, Gamma1 - Beta)
		end

		if not Rejected then
			PolyVec.InverseNTTProduct(C, T0, Product, K)
			local Exceeds, Count = PolyVec.MakeHints(R, Product, Hints, K, Gamma2)
			HasSigned = not Exceeds and Count <= Omega
		end

		Kappa += L
	end

	local ZOffset = CTildaSize
	local HintOffset = ZOffset + 32 * L * Gamma1Bw

	buffer.copy(Sig, 0, CTilda, 0, CTildaSize)
	BitPack.EncodeCentered(Z, 0, L * N, Gamma1, Gamma1Bw, Sig, ZOffset)

	local HEncoded = buffer.create(buffer.len(Sig) - HintOffset)
	BitPacking.EncodeHintBits(Hints, HEncoded, K, Omega)
	buffer.copy(Sig, HintOffset, HEncoded, 0, buffer.len(HEncoded))

	return HasSigned
end

local function Sign(Msg: buffer, Rnd: buffer, SecKey: buffer, Ctx: buffer, Sig: buffer, K: number, L: number, D: number, Eta: number, Gamma1: number, Gamma2: number, Tau: number, Beta: number, Omega: number, Lambda: number): boolean
	if not Params.CheckSigningParams(K, L, D, Eta, Gamma1, Gamma2, Tau, Beta, Omega, Lambda) then
		error("Invalid signing parameters")
	end

	if buffer.len(Ctx) > 255 then
		return false
	end

	if buffer.len(SecKey) ~= Utils.SecKeyLen(K, L, Eta, D) then
		error("Invalid secret key length")
	end

	local Mu = MessageHash(SecKey, 64, Ctx, Msg)

	return SignMuCore(Mu, Rnd, SecKey, Sig, K, L, D, Eta, Gamma1, Gamma2, Tau, Beta, Omega, Lambda)
end

local function SignInternal(MPrime: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer, K: number, L: number, D: number, Eta: number, Gamma1: number, Gamma2: number, Tau: number, Beta: number, Omega: number, Lambda: number): boolean
	if not Params.CheckSigningParams(K, L, D, Eta, Gamma1, Gamma2, Tau, Beta, Omega, Lambda) then
		error("Invalid signing parameters")
	end

	if buffer.len(SecKey) ~= Utils.SecKeyLen(K, L, Eta, D) then
		error("Invalid secret key length")
	end

	local MuInput = buffer.create(64 + buffer.len(MPrime))
	buffer.copy(MuInput, 0, SecKey, 64, 64)
	buffer.copy(MuInput, 64, MPrime, 0, buffer.len(MPrime))
	local Mu = SHA3.SHAKE256_Internal(MuInput, 64)

	return SignMuCore(Mu, Rnd, SecKey, Sig, K, L, D, Eta, Gamma1, Gamma2, Tau, Beta, Omega, Lambda)
end

local function SignMu(Mu: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer, K: number, L: number, D: number, Eta: number, Gamma1: number, Gamma2: number, Tau: number, Beta: number, Omega: number, Lambda: number): boolean
	if not Params.CheckSigningParams(K, L, D, Eta, Gamma1, Gamma2, Tau, Beta, Omega, Lambda) then
		error("Invalid signing parameters")
	end

	if buffer.len(Mu) ~= 64 then
		error("Mu must be 64 bytes")
	end

	return SignMuCore(Mu, Rnd, SecKey, Sig, K, L, D, Eta, Gamma1, Gamma2, Tau, Beta, Omega, Lambda)
end

local function Verify(Msg: buffer, PubKey: buffer, Ctx: buffer, Sig: buffer, K: number, L: number, D: number, Gamma1: number, Gamma2: number, Tau: number, Beta: number, Omega: number, Lambda: number): boolean
	if not Params.CheckVerifyParams(K, L, D, Gamma1, Gamma2, Tau, Beta, Omega, Lambda) then
		error("Invalid verify parameters")
	end

	if buffer.len(Ctx) > 255 then
		return false
	end

	if buffer.len(PubKey) ~= Utils.PubKeyLen(K, D) then
		return false
	end

	if buffer.len(Sig) ~= Utils.SigLen(K, L, Gamma1, Omega, Lambda) then
		return false
	end

	local Gamma1Bw = Utils.BitWidth(Gamma1)
	local CTildaSize = math.floor((2 * Lambda) / 8)
	local W1Bw = Utils.BitWidth(math.floor((Q - 1) / bit32.lshift(Gamma2, 1)) - 1)
	local ZOffset = CTildaSize
	local HintOffset = ZOffset + 32 * L * Gamma1Bw

	local T1, Tr = VerifyKeySetup(PubKey, K)
	local Work = ScratchFor(K, L, W1Bw, CTildaSize)

	local Z = Work.Z
	BitPack.DecodeCentered(Sig, ZOffset, L * N, Gamma1, Gamma1Bw, Z, 0)
	local VerificationFailed = PolyVec.InfinityNorm(Z, L) >= Gamma1 - Beta

	local HEncoded = buffer.create(buffer.len(Sig) - HintOffset)
	buffer.copy(HEncoded, 0, Sig, HintOffset, buffer.len(HEncoded))
	local Hints = Work.Hints
	local HintsFailed = BitPacking.DecodeHintBits(HEncoded, Hints, K, Omega)
	VerificationFailed = VerificationFailed or HintsFailed

	local A = Sampling.ExpandA(PubKey, 0, K, L)
	local Mu = MessageHash(Tr, 0, Ctx, Msg)

	local CTilda = Work.CTilda
	buffer.copy(CTilda, 0, Sig, 0, CTildaSize)
	local C = Work.C
	Sampling.SampleInBall(CTilda, C, Tau)
	NTT.ForwardNTTWithOffset(C, 0)

	local W = Work.W
	PolyVec.ForwardNTT(Z, L)
	PolyVec.MatrixMultiplySubtract(A, Z, C, T1, W, L)
	PolyVec.InverseNTT(W, K)

	local ChallengeInput = Work.ChallengeInput
	buffer.copy(ChallengeInput, 0, Mu, 0, 64)
	PolyVec.UseHintEncode(Hints, W, K, Gamma2, ChallengeInput, 64)
	local CTildaPrime = SHA3.SHAKE256_Internal(ChallengeInput, CTildaSize)

	return not VerificationFailed and CtCompare(CTilda, CTildaPrime)
end

Mldsa.ML_DSA_44 = {
	D = 13,
	Tau = 39,
	Gamma1 = bit32.lshift(1, 17),
	Gamma2 = math.floor((Q - 1) / 88),
	K = 4,
	L = 4,
	Eta = 2,
	Beta = 39 * 2,
	Omega = 80,
	Lambda = 128,

	KeygenSeedByteLen = KEYGEN_SEED_BYTE_LEN,
	PubKeyByteLen = Utils.PubKeyLen(4, 13),
	SecKeyByteLen = Utils.SecKeyLen(4, 4, 2, 13), 
	SigningSeedByteLen = RND_BYTE_LEN,
	SigByteLen = Utils.SigLen(4, 4, 131072, 80, 128),

	KeyGen = function(Seed: buffer, PubKey: buffer, SecKey: buffer)
		Keygen(Seed, PubKey, SecKey, 4, 4, 13, 2)
	end,

	Sign = function(Msg: buffer, Rnd: buffer, SecKey: buffer, Ctx: buffer, Sig: buffer): boolean
		return Sign(Msg, Rnd, SecKey, Ctx, Sig, 4, 4, 13, 2, 131072, 95232, 39, 78, 80, 128)
	end,

	SignInternal = function(MPrime: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer): boolean
		return SignInternal(MPrime, Rnd, SecKey, Sig, 4, 4, 13, 2, 131072, 95232, 39, 78, 80, 128)
	end,

	SignMu = function(Mu: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer): boolean
		return SignMu(Mu, Rnd, SecKey, Sig, 4, 4, 13, 2, 131072, 95232, 39, 78, 80, 128)
	end,

	Verify = function(Msg: buffer, PubKey: buffer, Ctx: buffer, Sig: buffer): boolean
		return Verify(Msg, PubKey, Ctx, Sig, 4, 4, 13, 131072, 95232, 39, 78, 80, 128)
	end,

	GenerateKeys = function(): (buffer, buffer)
		local Seed = CSPRNG.RandomBytes(32)
		local PubKey = buffer.create(1312)
		local SecKey = buffer.create(2560)
		Mldsa.ML_DSA_44.KeyGen(Seed, PubKey, SecKey)
		return PubKey, SecKey
	end
}

Mldsa.ML_DSA_65 = {
	D = 13,
	Tau = 49,
	Gamma1 = bit32.lshift(1, 19),
	Gamma2 = math.floor((Q - 1) / 32),
	K = 6,
	L = 5,
	Eta = 4,
	Beta = 49 * 4,
	Omega = 55,
	Lambda = 192,

	KeygenSeedByteLen = KEYGEN_SEED_BYTE_LEN,
	PubKeyByteLen = Utils.PubKeyLen(6, 13),
	SecKeyByteLen = Utils.SecKeyLen(6, 5, 4, 13),
	SigningSeedByteLen = RND_BYTE_LEN,
	SigByteLen = Utils.SigLen(6, 5, 524288, 55, 192), 

	KeyGen = function(Seed: buffer, PubKey: buffer, SecKey: buffer)
		Keygen(Seed, PubKey, SecKey, 6, 5, 13, 4)
	end,

	Sign = function(Msg: buffer, Rnd: buffer, SecKey: buffer, Ctx: buffer, Sig: buffer): boolean
		return Sign(Msg, Rnd, SecKey, Ctx, Sig, 6, 5, 13, 4, 524288, 261888, 49, 196, 55, 192)
	end,

	SignInternal = function(MPrime: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer): boolean
		return SignInternal(MPrime, Rnd, SecKey, Sig, 6, 5, 13, 4, 524288, 261888, 49, 196, 55, 192)
	end,

	SignMu = function(Mu: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer): boolean
		return SignMu(Mu, Rnd, SecKey, Sig, 6, 5, 13, 4, 524288, 261888, 49, 196, 55, 192)
	end,

	Verify = function(Msg: buffer, PubKey: buffer, Ctx: buffer, Sig: buffer): boolean
		return Verify(Msg, PubKey, Ctx, Sig, 6, 5, 13, 524288, 261888, 49, 196, 55, 192)
	end,

	GenerateKeys = function(): (buffer, buffer)
		local Seed = CSPRNG.RandomBytes(32)
		local PubKey = buffer.create(1952)
		local SecKey = buffer.create(4032)
		Mldsa.ML_DSA_65.KeyGen(Seed, PubKey, SecKey)
		return PubKey, SecKey
	end
}

Mldsa.ML_DSA_87 = {
	D = 13,
	Tau = 60,
	Gamma1 = bit32.lshift(1, 19),
	Gamma2 = math.floor((Q - 1) / 32),
	K = 8,
	L = 7,
	Eta = 2,
	Beta = 60 * 2,
	Omega = 75,
	Lambda = 256,

	KeygenSeedByteLen = KEYGEN_SEED_BYTE_LEN,
	PubKeyByteLen = Utils.PubKeyLen(8, 13),
	SecKeyByteLen = Utils.SecKeyLen(8, 7, 2, 13),
	SigningSeedByteLen = RND_BYTE_LEN,
	SigByteLen = Utils.SigLen(8, 7, 524288, 75, 256),

	KeyGen = function(Seed: buffer, PubKey: buffer, SecKey: buffer)
		Keygen(Seed, PubKey, SecKey, 8, 7, 13, 2)
	end,

	Sign = function(Msg: buffer, Rnd: buffer, SecKey: buffer, Ctx: buffer, Sig: buffer): boolean
		return Sign(Msg, Rnd, SecKey, Ctx, Sig, 8, 7, 13, 2, 524288, 261888, 60, 120, 75, 256)
	end,

	SignInternal = function(MPrime: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer): boolean
		return SignInternal(MPrime, Rnd, SecKey, Sig, 8, 7, 13, 2, 524288, 261888, 60, 120, 75, 256)
	end,

	SignMu = function(Mu: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer): boolean
		return SignMu(Mu, Rnd, SecKey, Sig, 8, 7, 13, 2, 524288, 261888, 60, 120, 75, 256)
	end,

	Verify = function(Msg: buffer, PubKey: buffer, Ctx: buffer, Sig: buffer): boolean
		return Verify(Msg, PubKey, Ctx, Sig, 8, 7, 13, 524288, 261888, 60, 120, 75, 256)
	end,

	GenerateKeys = function(): (buffer, buffer)
		local Seed = CSPRNG.RandomBytes(32)
		local PubKey = buffer.create(2592)
		local SecKey = buffer.create(4896)
		Mldsa.ML_DSA_87.KeyGen(Seed, PubKey, SecKey)
		return PubKey, SecKey
	end
}

function Mldsa.ClearCaches()
	local Cached = SIGN_KEY
	if Cached then
		buffer.fill(Cached.SecretKey, 0, 0)
		buffer.fill(Cached.S1, 0, 0)
		buffer.fill(Cached.S2, 0, 0)
		buffer.fill(Cached.T0, 0, 0)
		SIGN_KEY = nil
	end

	VERIFY_KEY = nil
end

Mldsa.PubKeyLen = Utils.PubKeyLen
Mldsa.SecKeyLen = Utils.SecKeyLen
Mldsa.SigLen = Utils.SigLen

return Mldsa