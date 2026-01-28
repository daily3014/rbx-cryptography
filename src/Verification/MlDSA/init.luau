--[=[
	ML-DSA (FIPS 204) Digital Signature Algorithm
	
	Post quantum digital signature scheme based on lattice cryptography.
	Has three security levels: ML-DSA-44, ML-DSA-65, ML-DSA-87.

	Example usage:
		local MLDSA = require("@self/MlDSA")
		
		local PubKey, SecKey = MLDSA.ML_DSA_44.GenerateKeys()
		local Message = buffer.fromstring("Hello World")
		local Context = buffer.create(0)
		local Signature = buffer.create(MLDSA.ML_DSA_44.SigByteLen)
		local Random = buffer.create(32)
		
		local Success = MLDSA.ML_DSA_44.Sign(Message, Random, SecKey, Context, Signature)
		local Valid = MLDSA.ML_DSA_44.Verify(Message, PubKey, Context, Signature)
--]=]

--!strict
--!optimize 2
--!native

local SHA3 = require("@self/SHA3")
local NTT = require("@self/NTT")

local PolyVec = require("@self/PolyVec")
local BitPacking = require("@self/Pack")

local Sampling = require("@self/Sampling")
local Params = require("@self/Params")

local Utils = require("@self/Utils")
local CSPRNG = require("@self/CSPRNG")

local KEYGEN_SEED_BYTE_LEN = 32
local RND_BYTE_LEN = 32

local N = 256
local Q = 8380417

local Mldsa = {
	CSPRNG = CSPRNG
}

local function CompareBufferSlices(A: buffer, AOffset: number, B: buffer, BOffset: number, Length: number): boolean
	local Difference = 0

	if Length == 32 then
		Difference = bit32.bor(
			bit32.bxor(buffer.readu32(A, AOffset), buffer.readu32(B, BOffset)),
			bit32.bxor(buffer.readu32(A, AOffset + 4), buffer.readu32(B, BOffset + 4)),
			bit32.bxor(buffer.readu32(A, AOffset + 8), buffer.readu32(B, BOffset + 8)),
			bit32.bxor(buffer.readu32(A, AOffset + 12), buffer.readu32(B, BOffset + 12)),
			bit32.bxor(buffer.readu32(A, AOffset + 16), buffer.readu32(B, BOffset + 16)),
			bit32.bxor(buffer.readu32(A, AOffset + 20), buffer.readu32(B, BOffset + 20)),
			bit32.bxor(buffer.readu32(A, AOffset + 24), buffer.readu32(B, BOffset + 24)),
			bit32.bxor(buffer.readu32(A, AOffset + 28), buffer.readu32(B, BOffset + 28))
		)
		return Difference == 0
	end

	local AlignedLength = bit32.band(Length, bit32.bnot(3))
	for I = 0, AlignedLength - 4, 4 do
		Difference = bit32.bor(Difference, bit32.bxor(buffer.readu32(A, AOffset + I), buffer.readu32(B, BOffset + I)))
	end

	for I = AlignedLength, Length - 1 do
		Difference = bit32.bor(Difference, bit32.bxor(buffer.readu8(A, AOffset + I), buffer.readu8(B, BOffset + I)))
	end

	return Difference == 0
end

local function Keygen(Seed: buffer, PubKey: buffer, SecKey: buffer, K: number, L: number, D: number, Eta: number)
	if not Params.CheckKeygenParams(K, L, D, Eta) then
		error("Invalid keygen parameters")
	end

	local T1Bw = Utils.BitWidth(Q) - D
	local EtaBw = Utils.BitWidth(2 * Eta)
	local S1Len = L * EtaBw * 32
	local S2Len = K * EtaBw * 32
	local T0Rng = bit32.lshift(1, D - 1)

	local PkOff1 = 32
	local SkOff0 = 0
	local SkOff1 = SkOff0 + 32
	local SkOff2 = SkOff1 + 32
	local SkOff3 = SkOff2 + 64
	local SkOff4 = SkOff3 + S1Len 
	local SkOff5 = SkOff4 + S2Len

	local DomainSeparator = buffer.create(2)
	buffer.writeu8(DomainSeparator, 0, K)
	buffer.writeu8(DomainSeparator, 1, L)

	local SeedHashInput = buffer.create(34)
	buffer.copy(SeedHashInput, 0, Seed, 0, 32)
	buffer.copy(SeedHashInput, 32, DomainSeparator, 0, 2)

	local SeedHash = SHA3.SHAKE256(SeedHashInput, 128)

	local Rho = buffer.create(32)
	local RhoPrime = buffer.create(64)
	local Key = buffer.create(32)

	buffer.copy(Rho, 0, SeedHash, 0, 32)
	buffer.copy(RhoPrime, 0, SeedHash, 32, 64)
	buffer.copy(Key, 0, SeedHash, 96, 32)

	local A = buffer.create(K * L * N * 4)
	Sampling.ExpandA(Rho, A, K, L)

	local S1 = buffer.create(L * N * 4)
	local S2 = buffer.create(K * N * 4)

	Sampling.ExpandS(RhoPrime, S1, Eta, L, 0)
	Sampling.ExpandS(RhoPrime, S2, Eta, K, L)

	local S1Prime = buffer.create(L * N * 4)
	PolyVec.Copy(S1, S1Prime, L)
	PolyVec.ForwardNTT(S1Prime, L)

	local T = buffer.create(K * N * 4)
	PolyVec.MatrixMultiply(A, S1Prime, T, K, L, L, 1)
	PolyVec.InverseNTT(T, K)
	PolyVec.AddTo(S2, T, K)

	local T1 = buffer.create(K * N * 4)
	local T0 = buffer.create(K * N * 4)
	PolyVec.Power2Round(T, T1, T0, K, D)

	buffer.copy(PubKey, 0, Rho, 0, 32)
	local T1Encoded = buffer.create(buffer.len(PubKey) - PkOff1)
	PolyVec.Encode(T1, T1Encoded, K, T1Bw)
	buffer.copy(PubKey, PkOff1, T1Encoded, 0, buffer.len(T1Encoded))

	local Tr = SHA3.SHAKE256(PubKey, 64)

	buffer.copy(SecKey, SkOff0, Rho, 0, 32)
	buffer.copy(SecKey, SkOff1, Key, 0, 32)
	buffer.copy(SecKey, SkOff2, Tr, 0, 64)

	PolyVec.SubFromX(S1, L, Eta)
	PolyVec.SubFromX(S2, K, Eta)

	local S1Encoded = buffer.create(S1Len)
	local S2Encoded = buffer.create(S2Len)
	PolyVec.Encode(S1, S1Encoded, L, EtaBw)
	PolyVec.Encode(S2, S2Encoded, K, EtaBw)

	buffer.copy(SecKey, SkOff3, S1Encoded, 0, S1Len)
	buffer.copy(SecKey, SkOff4, S2Encoded, 0, S2Len)

	PolyVec.SubFromX(T0, K, T0Rng)

	local T0Encoded = buffer.create(buffer.len(SecKey) - SkOff5)
	PolyVec.Encode(T0, T0Encoded, K, D)
	buffer.copy(SecKey, SkOff5, T0Encoded, 0, buffer.len(T0Encoded))
end

local function SignMuCore(Mu: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer, K: number, L: number, D: number, Eta: number, Gamma1: number, Gamma2: number, Tau: number, Beta: number, Omega: number, Lambda: number): boolean
	local T0Rng = bit32.lshift(1, D - 1)
	local EtaBw = Utils.BitWidth(2 * Eta)
	local S1Len = L * EtaBw * 32
	local S2Len = K * EtaBw * 32
	local Alpha = bit32.lshift(Gamma2, 1)
	local M = math.floor((Q - 1) / Alpha)
	local W1Bw = Utils.BitWidth(M - 1)
	local CTildaSize = math.floor((2 * Lambda) / 8)
	local Gamma1Bw = Utils.BitWidth(Gamma1)

	local SkOff0 = 0
	local SkOff1 = SkOff0 + 32
	local SkOff2 = SkOff1 + 32
	local SkOff3 = SkOff2 + 64
	local SkOff4 = SkOff3 + S1Len
	local SkOff5 = SkOff4 + S2Len

	local Rho = buffer.create(32)
	local Key = buffer.create(32)

	buffer.copy(Rho, 0, SecKey, SkOff0, 32)
	buffer.copy(Key, 0, SecKey, SkOff1, 32)

	local A = buffer.create(K * L * N * 4)
	Sampling.ExpandA(Rho, A, K, L)

	local RhoPrimeInput = buffer.create(32 + 32 + 64)
	buffer.copy(RhoPrimeInput, 0, Key, 0, 32)
	buffer.copy(RhoPrimeInput, 32, Rnd, 0, 32)
	buffer.copy(RhoPrimeInput, 64, Mu, 0, 64)

	local RhoPrime = SHA3.SHAKE256(RhoPrimeInput, 64)

	local S1 = buffer.create(L * N * 4)
	local S2 = buffer.create(K * N * 4)
	local T0 = buffer.create(K * N * 4)

	local S1Encoded = buffer.create(S1Len)
	local S2Encoded = buffer.create(S2Len)
	local T0Encoded = buffer.create(buffer.len(SecKey) - SkOff5)

	buffer.copy(S1Encoded, 0, SecKey, SkOff3, S1Len)
	buffer.copy(S2Encoded, 0, SecKey, SkOff4, S2Len)
	buffer.copy(T0Encoded, 0, SecKey, SkOff5, buffer.len(T0Encoded))

	PolyVec.Decode(S1Encoded, S1, L, EtaBw)
	PolyVec.Decode(S2Encoded, S2, K, EtaBw)
	PolyVec.Decode(T0Encoded, T0, K, D)

	PolyVec.SubFromX(S1, L, Eta)
	PolyVec.SubFromX(S2, K, Eta)
	PolyVec.SubFromX(T0, K, T0Rng)

	PolyVec.ForwardNTT(S1, L)
	PolyVec.ForwardNTT(S2, K)
	PolyVec.ForwardNTT(T0, K)

	local HasSigned = false
	local Kappa = 0

	local Y = buffer.create(L * N * 4)
	local YPrime = buffer.create(L * N * 4)
	local W = buffer.create(K * N * 4)
	local W1 = buffer.create(K * N * 4)
	local C = buffer.create(N * 4)
	local Z = buffer.create(L * N * 4)
	local R0 = buffer.create(K * N * 4)
	local R1 = buffer.create(K * N * 4)
	local H0 = buffer.create(K * N * 4)
	local H1 = buffer.create(K * N * 4)
	local H = buffer.create(K * N * 4)
	local CTilda = buffer.create(CTildaSize)
	local W1Encoded = buffer.create(K * W1Bw * 32)

	while not HasSigned do
		Sampling.ExpandMask(RhoPrime, Kappa, Y, Gamma1, L)

		PolyVec.Copy(Y, YPrime, L)
		PolyVec.ForwardNTT(YPrime, L)
		PolyVec.MatrixMultiply(A, YPrime, W, K, L, L, 1)
		PolyVec.InverseNTT(W, K)

		PolyVec.HighBits(W, W1, K, Alpha)
		PolyVec.Encode(W1, W1Encoded, K, W1Bw)

		local ChallengeInput = buffer.create(64 + buffer.len(W1Encoded))
		buffer.copy(ChallengeInput, 0, Mu, 0, 64)
		buffer.copy(ChallengeInput, 64, W1Encoded, 0, buffer.len(W1Encoded))

		local CTildaFull = SHA3.SHAKE256(ChallengeInput, CTildaSize)
		buffer.copy(CTilda, 0, CTildaFull, 0, CTildaSize)

		Sampling.SampleInBall(CTilda, C, Tau, Lambda)
		NTT.ForwardNTT(C)

		PolyVec.MultiplyByPoly(C, S1, Z, L)
		PolyVec.InverseNTT(Z, L)
		PolyVec.AddTo(Y, Z, L)

		PolyVec.MultiplyByPoly(C, S2, R1, K)
		PolyVec.InverseNTT(R1, K)
		PolyVec.Negate(R1, K)
		PolyVec.AddTo(W, R1, K)
		PolyVec.LowBits(R1, R0, K, Alpha)

		local ZNorm = PolyVec.InfinityNorm(Z, L)
		local R0Norm = PolyVec.InfinityNorm(R0, K)

		if ZNorm >= (Gamma1 - Beta) or R0Norm >= (Gamma2 - Beta) then
			HasSigned = false
		else
			PolyVec.MultiplyByPoly(C, T0, H0, K)
			PolyVec.InverseNTT(H0, K)

			PolyVec.Copy(H0, H1, K)
			PolyVec.Negate(H0, K)
			PolyVec.AddTo(H1, R1, K)
			PolyVec.MakeHint(H0, R1, H, K, Alpha)

			local CT0Norm = PolyVec.InfinityNorm(H1, K)
			local Count1s = PolyVec.Count1s(H, K)

			if CT0Norm >= Gamma2 or Count1s > Omega then
				HasSigned = false
			else
				HasSigned = true
			end
		end

		Kappa += L
	end

	local SigOff0 = 0
	local SigOff1 = SigOff0 + CTildaSize
	local SigOff2 = SigOff1 + (32 * L * Gamma1Bw)

	buffer.copy(Sig, SigOff0, CTilda, 0, CTildaSize)

	PolyVec.SubFromX(Z, L, Gamma1)
	local ZEncoded = buffer.create(32 * L * Gamma1Bw)
	PolyVec.Encode(Z, ZEncoded, L, Gamma1Bw)
	buffer.copy(Sig, SigOff1, ZEncoded, 0, buffer.len(ZEncoded))

	local HEncoded = buffer.create(buffer.len(Sig) - SigOff2)
	BitPacking.EncodeHintBits(H, HEncoded, K, Omega)
	buffer.copy(Sig, SigOff2, HEncoded, 0, buffer.len(HEncoded))

	return HasSigned
end

local function Sign(Msg: buffer, Rnd: buffer, SecKey: buffer, Ctx: buffer, Sig: buffer, K: number, L: number, D: number, Eta: number, Gamma1: number, Gamma2: number, Tau: number, Beta: number, Omega: number, Lambda: number): boolean
	if not Params.CheckSigningParams(K, L, D, Eta, Gamma1, Gamma2, Tau, Beta, Omega, Lambda) then
		error("Invalid signing parameters")
	end

	if buffer.len(Ctx) > 255 then
		return false
	end

	local SkOff2 = 64

	local Tr = buffer.create(64)
	buffer.copy(Tr, 0, SecKey, SkOff2, 64)

	local DomainSeparator = buffer.create(2)
	buffer.writeu8(DomainSeparator, 0, 0)
	buffer.writeu8(DomainSeparator, 1, buffer.len(Ctx))

	local MuInput = buffer.create(64 + 2 + buffer.len(Ctx) + buffer.len(Msg))
	local Offset = 0
	buffer.copy(MuInput, Offset, Tr, 0, 64)
	Offset += 64
	buffer.copy(MuInput, Offset, DomainSeparator, 0, 2)
	Offset += 2
	buffer.copy(MuInput, Offset, Ctx, 0, buffer.len(Ctx))
	Offset += buffer.len(Ctx)
	buffer.copy(MuInput, Offset, Msg, 0, buffer.len(Msg))

	local Mu = SHA3.SHAKE256(MuInput, 64)

	return SignMuCore(Mu, Rnd, SecKey, Sig, K, L, D, Eta, Gamma1, Gamma2, Tau, Beta, Omega, Lambda)
end

local function SignInternal(MPrime: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer, K: number, L: number, D: number, Eta: number, Gamma1: number, Gamma2: number, Tau: number, Beta: number, Omega: number, Lambda: number): boolean
	if not Params.CheckSigningParams(K, L, D, Eta, Gamma1, Gamma2, Tau, Beta, Omega, Lambda) then
		error("Invalid signing parameters")
	end

	local SkOff2 = 64

	local Tr = buffer.create(64)
	buffer.copy(Tr, 0, SecKey, SkOff2, 64)

	local MuInput = buffer.create(64 + buffer.len(MPrime))
	buffer.copy(MuInput, 0, Tr, 0, 64)
	buffer.copy(MuInput, 64, MPrime, 0, buffer.len(MPrime))

	local Mu = SHA3.SHAKE256(MuInput, 64)

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

	local T1Bw = Utils.BitWidth(Q) - D
	local Gamma1Bw = Utils.BitWidth(Gamma1)
	local CTildaSize = math.floor((2 * Lambda) / 8)

	local ExpectedPkLen = Utils.PubKeyLen(K, D)
	if buffer.len(PubKey) ~= ExpectedPkLen then
		return false
	end

	local ExpectedSigLen = Utils.SigLen(K, L, Gamma1, Omega, Lambda)
	if buffer.len(Sig) ~= ExpectedSigLen then
		return false
	end

	local Alpha = bit32.lshift(Gamma2, 1)
	local M = math.floor((Q - 1) / Alpha)
	local W1Bw = Utils.BitWidth(M - 1)

	local PkOff1 = 32

	local SigOff0 = 0
	local SigOff1 = SigOff0 + CTildaSize
	local SigOff2 = SigOff1 + (32 * L * Gamma1Bw)

	local VerificationFailed = false

	local Rho = buffer.create(32)
	buffer.copy(Rho, 0, PubKey, 0, 32)

	local T1Encoded = buffer.create(buffer.len(PubKey) - PkOff1)
	buffer.copy(T1Encoded, 0, PubKey, PkOff1, buffer.len(T1Encoded))

	local T1 = buffer.create(K * N * 4)
	PolyVec.Decode(T1Encoded, T1, K, T1Bw)

	local CTilda = buffer.create(CTildaSize)
	buffer.copy(CTilda, 0, Sig, SigOff0, CTildaSize)

	local ZEncoded = buffer.create(32 * L * Gamma1Bw)
	buffer.copy(ZEncoded, 0, Sig, SigOff1, buffer.len(ZEncoded))

	local Z = buffer.create(L * N * 4)
	PolyVec.Decode(ZEncoded, Z, L, Gamma1Bw)
	PolyVec.SubFromX(Z, L, Gamma1)

	local ZNorm = PolyVec.InfinityNorm(Z, L)
	VerificationFailed = VerificationFailed or (ZNorm >= (Gamma1 - Beta))

	local HEncoded = buffer.create(buffer.len(Sig) - SigOff2)
	buffer.copy(HEncoded, 0, Sig, SigOff2, buffer.len(HEncoded))

	local H = buffer.create(K * N * 4)
	local HintDecodeFailed = BitPacking.DecodeHintBits(HEncoded, H, K, Omega)
	VerificationFailed = VerificationFailed or HintDecodeFailed

	local A = buffer.create(K * L * N * 4)
	Sampling.ExpandA(Rho, A, K, L)

	local Tr = SHA3.SHAKE256(PubKey, 64)

	local DomainSeparator = buffer.create(2)
	buffer.writeu8(DomainSeparator, 0, 0)
	buffer.writeu8(DomainSeparator, 1, buffer.len(Ctx))

	local MuInput = buffer.create(64 + 2 + buffer.len(Ctx) + buffer.len(Msg))
	local Offset = 0
	buffer.copy(MuInput, Offset, Tr, 0, 64)
	Offset += 64
	buffer.copy(MuInput, Offset, DomainSeparator, 0, 2)
	Offset += 2
	buffer.copy(MuInput, Offset, Ctx, 0, buffer.len(Ctx))
	Offset += buffer.len(Ctx)
	buffer.copy(MuInput, Offset, Msg, 0, buffer.len(Msg))

	local Mu = SHA3.SHAKE256(MuInput, 64)

	local C = buffer.create(N * 4)
	Sampling.SampleInBall(CTilda, C, Tau, Lambda)
	NTT.ForwardNTT(C)

	local W0 = buffer.create(K * N * 4)
	local W1 = buffer.create(K * N * 4)
	local W2 = buffer.create(K * N * 4)

	PolyVec.ForwardNTT(Z, L)
	PolyVec.MatrixMultiply(A, Z, W0, K, L, L, 1)

	PolyVec.LeftShift(T1, K, D)
	PolyVec.ForwardNTT(T1, K)
	PolyVec.MultiplyByPoly(C, T1, W2, K)
	PolyVec.Negate(W2, K)

	PolyVec.AddTo(W0, W2, K)
	PolyVec.InverseNTT(W2, K)

	PolyVec.UseHint(H, W2, W1, K, Alpha)

	local W1Encoded = buffer.create(K * W1Bw * 32)
	PolyVec.Encode(W1, W1Encoded, K, W1Bw)

	local ChallengeInput = buffer.create(64 + buffer.len(W1Encoded))
	buffer.copy(ChallengeInput, 0, Mu, 0, 64)
	buffer.copy(ChallengeInput, 64, W1Encoded, 0, buffer.len(W1Encoded))

	local CTildaPrime = SHA3.SHAKE256(ChallengeInput, CTildaSize)

	local CompareResult = CompareBufferSlices(CTilda, 0, CTildaPrime, 0, CTildaSize)
	VerificationFailed = VerificationFailed or (not CompareResult)

	return not VerificationFailed
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

Mldsa.PubKeyLen = Utils.PubKeyLen
Mldsa.SecKeyLen = Utils.SecKeyLen
Mldsa.SigLen = Utils.SigLen

return Mldsa