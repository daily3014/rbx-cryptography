--[=[
	ML-DSA (FIPS 204) Digital Signature Algorithm

	Post quantum digital signature scheme based on lattice cryptography.
	Has three security levels: ML-DSA-44, ML-DSA-65, ML-DSA-87.

	Example usage:
		local PubKey, SecKey = MLDSA.ML_DSA_44.GenerateKeys()
		local Message = buffer.fromstring("Hello World")
		local Context = buffer.create(0)
		local Signature = buffer.create(MLDSA.ML_DSA_44.SigByteLen)
		local Random = MLDSA.CSPRNG.RandomBytes(32)

		local Success = MLDSA.ML_DSA_44.Sign(Message, Random, SecKey, Context, Signature)
		local Valid = MLDSA.ML_DSA_44.Verify(Message, PubKey, Context, Signature)
--]=]

--!strict
--!optimize 2

local Lazy = require("../Lazy")
local SHA3 = require("../Hashing/SHA3")
local NTT = require("@self/NTT")
local PolyVec = require("@self/PolyVec")
local BitPack = require("@self/BitPack")
local Sampling = require("@self/Sampling")
local CtCompareMask = require("../Utilities/Functions").CtCompareMask

type CSPRNGModule = typeof(require("../Utilities/CSPRNG"))

type Scheme = {
	D: number,
	Tau: number,
	Gamma1: number,
	Gamma2: number,
	K: number,
	L: number,
	Eta: number,
	Beta: number,
	Omega: number,
	Lambda: number,

	KeygenSeedByteLen: number,
	PubKeyByteLen: number,
	SecKeyByteLen: number,
	SigningSeedByteLen: number,
	SigByteLen: number,

	KeyGen: (Seed: buffer, PubKey: buffer, SecKey: buffer) -> (),
	Sign: (Msg: buffer, Rnd: buffer, SecKey: buffer, Ctx: buffer, Sig: buffer) -> boolean,
	SignInternal: (MPrime: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer) -> boolean,
	SignMu: (Mu: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer) -> boolean,
	Verify: (Msg: buffer, PubKey: buffer, Ctx: buffer, Sig: buffer) -> boolean,
	GenerateKeys: () -> (buffer, buffer),
}

export type MldsaModule = {
	CSPRNG: CSPRNGModule,
	ML_DSA_44: Scheme,
	ML_DSA_65: Scheme,
	ML_DSA_87: Scheme,
	ClearCaches: () -> (),
	PubKeyLen: (K: number, D: number) -> number,
	SecKeyLen: (K: number, L: number, Eta: number, D: number) -> number,
	SigLen: (K: number, L: number, Gamma1: number, Omega: number, Lambda: number) -> number,
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

local KEYGEN_SEED_BYTE_LEN = 32
local RND_BYTE_LEN = 32
local Q_BIT_WIDTH = 23
local N = 256
local Q = 8380417
local POLY_SIZE = N * 4

local SEED_HASH_INPUT: buffer = buffer.create(34)
local SEED_HASH: buffer = buffer.create(128)
local RHO_PRIME_INPUT: buffer = buffer.create(128)
local RHO_PRIME: buffer = buffer.create(64)
local MU_OUT: buffer = buffer.create(64)

local MU_INPUT: buffer? = nil
local SIGN_KEY: SignKey? = nil
local VERIFY_KEY: VerifyKey? = nil
local SCRATCH: { [number]: Scratch } = {}

local function BitWidth(Value: number): number
	return 32 - bit32.countlz(Value)
end

local function PubKeyLen(K: number, D: number): number
	return 32 + K * 32 * (Q_BIT_WIDTH - D)
end

local function SecKeyLen(K: number, L: number, Eta: number, D: number): number
	return 128 + 32 * (BitWidth(2 * Eta) * (K + L) + K * D)
end

local function SigLen(K: number, L: number, Gamma1: number, Omega: number, Lambda: number): number
	return math.floor((2 * Lambda) / 8) + 32 * L * BitWidth(Gamma1) + Omega + K
end

@native
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

local function EnsureMuInput(Needed: number): buffer
	local Buf = MU_INPUT
	if Buf and buffer.len(Buf) >= Needed then
		return Buf
	end

	local NewBuf = buffer.create(Needed)
	MU_INPUT = NewBuf
	return NewBuf
end

local function ScratchFor(K: number, L: number, W1Bw: number, CTildaSize: number): Scratch
	local Existing = SCRATCH[K]
	if Existing then
		return Existing
	end

	local VectorL = L * POLY_SIZE
	local VectorK = K * POLY_SIZE
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

local function HashMessageInto(Tr: buffer, TrOffset: number, Ctx: buffer, Msg: buffer, Output: buffer, OutputOffset: number): ()
	local ContextLength = buffer.len(Ctx)
	local MsgLength = buffer.len(Msg)
	local TotalLength = 66 + ContextLength + MsgLength
	local MuInput = EnsureMuInput(TotalLength)
	buffer.copy(MuInput, 0, Tr, TrOffset, 64)
	buffer.writeu8(MuInput, 64, 0)
	buffer.writeu8(MuInput, 65, ContextLength)
	buffer.copy(MuInput, 66, Ctx, 0, ContextLength)
	buffer.copy(MuInput, 66 + ContextLength, Msg, 0, MsgLength)
	SHA3.SHAKE256_Into(MuInput, 0, TotalLength, Output, OutputOffset, 64)
end

local function SignKeySetup(SecKey: buffer, K: number, L: number, D: number, Eta: number): (buffer, buffer, buffer)
	local Cached = SIGN_KEY
	if Cached and BuffersEqual(Cached.SecretKey, SecKey) then
		return Cached.S1, Cached.S2, Cached.T0
	end

	local EtaBw = BitWidth(2 * Eta)
	local S1Offset = 128
	local S2Offset = S1Offset + L * EtaBw * 32
	local T0Offset = S2Offset + K * EtaBw * 32
	local SecLen = buffer.len(SecKey)

	local SecretKey: buffer
	local S1: buffer
	local S2: buffer
	local T0: buffer
	if Cached and buffer.len(Cached.SecretKey) == SecLen then
		SecretKey = Cached.SecretKey
		S1 = Cached.S1
		S2 = Cached.S2
		T0 = Cached.T0
	else
		SecretKey = buffer.create(SecLen)
		S1 = buffer.create(L * POLY_SIZE)
		S2 = buffer.create(K * POLY_SIZE)
		T0 = buffer.create(K * POLY_SIZE)
		SIGN_KEY = {
			SecretKey = SecretKey,
			S1 = S1,
			S2 = S2,
			T0 = T0,
		}
	end

	BitPack.DecodeCentered(SecKey, S1Offset, L * N, Eta, EtaBw, S1, 0)
	BitPack.DecodeCentered(SecKey, S2Offset, K * N, Eta, EtaBw, S2, 0)
	BitPack.DecodeCentered(SecKey, T0Offset, K * N, bit32.lshift(1, D - 1), D, T0, 0)
	PolyVec.ForwardNTT(S1, L)
	PolyVec.ForwardNTT(S2, K)
	PolyVec.ForwardNTT(T0, K)
	buffer.copy(SecretKey, 0, SecKey, 0, SecLen)

	return S1, S2, T0
end

local function VerifyKeySetup(PubKey: buffer, K: number): (buffer, buffer)
	local Cached = VERIFY_KEY
	if Cached and BuffersEqual(Cached.PublicKey, PubKey) then
		return Cached.T1, Cached.Tr
	end

	local PubLen = buffer.len(PubKey)
	local PublicKey: buffer
	local T1: buffer
	local Tr: buffer
	if Cached and buffer.len(Cached.PublicKey) == PubLen then
		PublicKey = Cached.PublicKey
		T1 = Cached.T1
		Tr = Cached.Tr
	else
		PublicKey = buffer.create(PubLen)
		T1 = buffer.create(K * POLY_SIZE)
		Tr = buffer.create(64)
		VERIFY_KEY = {
			PublicKey = PublicKey,
			T1 = T1,
			Tr = Tr,
		}
	end

	BitPack.DecodeT1(PubKey, 32, K * N, T1, 0)
	PolyVec.ForwardNTT(T1, K)
	SHA3.SHAKE256_Into(PubKey, 0, PubLen, Tr, 0, 64)
	buffer.copy(PublicKey, 0, PubKey, 0, PubLen)

	return T1, Tr
end

local function Keygen(
	Seed: buffer,
	PubKey: buffer,
	SecKey: buffer,
	K: number,
	L: number,
	D: number,
	Eta: number,
	W1Bw: number,
	CTildaSize: number,
	PubKeyByteLen: number,
	SecKeyByteLen: number
): ()
	if buffer.len(Seed) ~= KEYGEN_SEED_BYTE_LEN then
		error("Seed must be 32 bytes")
	end

	if buffer.len(PubKey) ~= PubKeyByteLen then
		error("Invalid public key buffer length")
	end

	if buffer.len(SecKey) ~= SecKeyByteLen then
		error("Invalid secret key buffer length")
	end

	local EtaBw = BitWidth(2 * Eta)
	local S1Offset = 128
	local S2Offset = S1Offset + L * EtaBw * 32
	local T0Offset = S2Offset + K * EtaBw * 32

	buffer.copy(SEED_HASH_INPUT, 0, Seed, 0, 32)
	buffer.writeu8(SEED_HASH_INPUT, 32, K)
	buffer.writeu8(SEED_HASH_INPUT, 33, L)
	SHA3.SHAKE256_Into(SEED_HASH_INPUT, 0, 34, SEED_HASH, 0, 128)

	local A = Sampling.ExpandA(SEED_HASH, 0, K, L)
	local Work = ScratchFor(K, L, W1Bw, CTildaSize)
	local S1 = Work.Y
	local S1Hat = Work.YHat
	local S2 = Work.W
	local T = Work.R
	local T1 = Work.Product
	local T0 = Work.Hints

	Sampling.ExpandS(SEED_HASH, 32, S1, Eta, L, 0)
	Sampling.ExpandS(SEED_HASH, 32, S2, Eta, K, L)

	buffer.copy(S1Hat, 0, S1, 0, L * POLY_SIZE)
	PolyVec.ForwardNTT(S1Hat, L)
	PolyVec.MatrixMultiply(A, S1Hat, T, L)
	PolyVec.InverseNTT(T, K)
	PolyVec.Power2RoundSum(T, S2, T1, T0, K)

	buffer.copy(PubKey, 0, SEED_HASH, 0, 32)
	BitPack.EncodeT1(T1, 0, K * N, PubKey, 32)

	buffer.copy(SecKey, 0, SEED_HASH, 0, 32)
	buffer.copy(SecKey, 32, SEED_HASH, 96, 32)
	SHA3.SHAKE256_Into(PubKey, 0, PubKeyByteLen, SecKey, 64, 64)
	BitPack.EncodeCentered(S1, 0, L * N, Eta, EtaBw, SecKey, S1Offset)
	BitPack.EncodeCentered(S2, 0, K * N, Eta, EtaBw, SecKey, S2Offset)
	BitPack.EncodeCentered(T0, 0, K * N, bit32.lshift(1, D - 1), D, SecKey, T0Offset)
end

local function SignMuCore(
	Mu: buffer,
	Rnd: buffer,
	SecKey: buffer,
	Sig: buffer,
	K: number,
	L: number,
	D: number,
	Eta: number,
	Gamma1: number,
	Gamma2: number,
	Tau: number,
	Beta: number,
	Omega: number,
	W1Bw: number,
	CTildaSize: number,
	Gamma1Bw: number,
	SecKeyByteLen: number,
	SigByteLen: number
): boolean
	if buffer.len(Rnd) ~= RND_BYTE_LEN then
		error("Rnd must be 32 bytes")
	end

	if buffer.len(SecKey) ~= SecKeyByteLen then
		error("Invalid secret key length")
	end

	if buffer.len(Sig) ~= SigByteLen then
		error("Invalid signature buffer length")
	end

	local A = Sampling.ExpandA(SecKey, 0, K, L)

	buffer.copy(RHO_PRIME_INPUT, 0, SecKey, 32, 32)
	buffer.copy(RHO_PRIME_INPUT, 32, Rnd, 0, 32)
	buffer.copy(RHO_PRIME_INPUT, 64, Mu, 0, 64)
	SHA3.SHAKE256_Into(RHO_PRIME_INPUT, 0, 128, RHO_PRIME, 0, 64)

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
	local CTilda = Work.CTilda
	local ChallengeInput = Work.ChallengeInput
	local ChallengeLen = buffer.len(ChallengeInput)
	buffer.copy(ChallengeInput, 0, Mu, 0, 64)

	local HasSigned = false
	local Kappa = 0

	while not HasSigned do
		if Kappa + L > 65536 then
			return false
		end

		Sampling.ExpandMask(RHO_PRIME, Kappa, Y, Gamma1, L)
		buffer.copy(YHat, 0, Y, 0, L * POLY_SIZE)
		PolyVec.ForwardNTT(YHat, L)
		PolyVec.MatrixMultiply(A, YHat, W, L)
		PolyVec.InverseNTT(W, K)

		PolyVec.HighBitsEncode(W, K, Gamma2, ChallengeInput, 64)
		SHA3.SHAKE256_Into(ChallengeInput, 0, ChallengeLen, CTilda, 0, CTildaSize)

		Sampling.SampleInBall(CTilda, 0, CTildaSize, C, Tau)
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
	BitPack.EncodeHintBits(Hints, Sig, HintOffset, K, Omega)

	return HasSigned
end

local function VerifyCore(
	Msg: buffer,
	PubKey: buffer,
	Ctx: buffer,
	Sig: buffer,
	K: number,
	L: number,
	Gamma1: number,
	Gamma2: number,
	Tau: number,
	Beta: number,
	Omega: number,
	W1Bw: number,
	CTildaSize: number,
	Gamma1Bw: number,
	PubKeyByteLen: number,
	SigByteLen: number
): boolean
	if typeof(Ctx) ~= "buffer" then
		error(`Context must be a buffer, got {typeof(Ctx)}`, 3)
	end

	if typeof(Msg) ~= "buffer" or typeof(PubKey) ~= "buffer" or typeof(Sig) ~= "buffer" then
		return false
	end

	if buffer.len(Ctx) > 255 or buffer.len(PubKey) ~= PubKeyByteLen or buffer.len(Sig) ~= SigByteLen then
		return false
	end

	local ZOffset = CTildaSize
	local HintOffset = ZOffset + 32 * L * Gamma1Bw

	local Work = ScratchFor(K, L, W1Bw, CTildaSize)
	local Hints = Work.Hints
	if BitPack.DecodeHintBits(Sig, HintOffset, Hints, K, Omega) then
		return false
	end

	local Z = Work.Z
	BitPack.DecodeCentered(Sig, ZOffset, L * N, Gamma1, Gamma1Bw, Z, 0)
	if PolyVec.InfinityNorm(Z, L) >= Gamma1 - Beta then
		return false
	end

	local T1, Tr = VerifyKeySetup(PubKey, K)
	local A = Sampling.ExpandA(PubKey, 0, K, L)

	local ChallengeInput = Work.ChallengeInput
	HashMessageInto(Tr, 0, Ctx, Msg, ChallengeInput, 0)

	local C = Work.C
	Sampling.SampleInBall(Sig, 0, CTildaSize, C, Tau)
	NTT.ForwardNTTWithOffset(C, 0)

	local W = Work.W
	PolyVec.ForwardNTT(Z, L)
	PolyVec.MatrixMultiplySubtract(A, Z, C, T1, W, L)
	PolyVec.InverseNTT(W, K)

	PolyVec.UseHintEncode(Hints, W, K, Gamma2, ChallengeInput, 64)
	local CTilda = Work.CTilda
	SHA3.SHAKE256_Into(ChallengeInput, 0, buffer.len(ChallengeInput), CTilda, 0, CTildaSize)

	return CtCompareMask(Sig, CTilda, CTildaSize) ~= 0
end

local Mldsa: MldsaModule

local function MakeScheme(
	K: number,
	L: number,
	D: number,
	Eta: number,
	Gamma1: number,
	Gamma2: number,
	Tau: number,
	Beta: number,
	Omega: number,
	Lambda: number
): Scheme
	local PubKeyByteLen = PubKeyLen(K, D)
	local SecKeyByteLen = SecKeyLen(K, L, Eta, D)
	local SigByteLen = SigLen(K, L, Gamma1, Omega, Lambda)
	local W1Bw = BitWidth(math.floor((Q - 1) / bit32.lshift(Gamma2, 1)) - 1)
	local CTildaSize = math.floor((2 * Lambda) / 8)
	local Gamma1Bw = BitWidth(Gamma1)

	return {
		D = D,
		Tau = Tau,
		Gamma1 = Gamma1,
		Gamma2 = Gamma2,
		K = K,
		L = L,
		Eta = Eta,
		Beta = Beta,
		Omega = Omega,
		Lambda = Lambda,

		KeygenSeedByteLen = KEYGEN_SEED_BYTE_LEN,
		PubKeyByteLen = PubKeyByteLen,
		SecKeyByteLen = SecKeyByteLen,
		SigningSeedByteLen = RND_BYTE_LEN,
		SigByteLen = SigByteLen,

		KeyGen = function(Seed: buffer, PubKey: buffer, SecKey: buffer): ()
			Keygen(Seed, PubKey, SecKey, K, L, D, Eta, W1Bw, CTildaSize, PubKeyByteLen, SecKeyByteLen)
		end,

		Sign = function(Msg: buffer, Rnd: buffer, SecKey: buffer, Ctx: buffer, Sig: buffer): boolean
			if buffer.len(Ctx) > 255 then
				return false
			end
			if buffer.len(SecKey) ~= SecKeyByteLen then
				error("Invalid secret key length")
			end
			HashMessageInto(SecKey, 64, Ctx, Msg, MU_OUT, 0)
			return SignMuCore(MU_OUT, Rnd, SecKey, Sig, K, L, D, Eta, Gamma1, Gamma2, Tau, Beta, Omega, W1Bw, CTildaSize, Gamma1Bw, SecKeyByteLen, SigByteLen)
		end,

		SignInternal = function(MPrime: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer): boolean
			if buffer.len(SecKey) ~= SecKeyByteLen then
				error("Invalid secret key length")
			end
			local MPrimeLength = buffer.len(MPrime)
			local TotalLength = 64 + MPrimeLength
			local MuInput = EnsureMuInput(TotalLength)
			buffer.copy(MuInput, 0, SecKey, 64, 64)
			buffer.copy(MuInput, 64, MPrime, 0, MPrimeLength)
			SHA3.SHAKE256_Into(MuInput, 0, TotalLength, MU_OUT, 0, 64)
			return SignMuCore(MU_OUT, Rnd, SecKey, Sig, K, L, D, Eta, Gamma1, Gamma2, Tau, Beta, Omega, W1Bw, CTildaSize, Gamma1Bw, SecKeyByteLen, SigByteLen)
		end,

		SignMu = function(Mu: buffer, Rnd: buffer, SecKey: buffer, Sig: buffer): boolean
			if buffer.len(Mu) ~= 64 then
				error("Mu must be 64 bytes")
			end
			return SignMuCore(Mu, Rnd, SecKey, Sig, K, L, D, Eta, Gamma1, Gamma2, Tau, Beta, Omega, W1Bw, CTildaSize, Gamma1Bw, SecKeyByteLen, SigByteLen)
		end,

		Verify = function(Msg: buffer, PubKey: buffer, Ctx: buffer, Sig: buffer): boolean
			return VerifyCore(Msg, PubKey, Ctx, Sig, K, L, Gamma1, Gamma2, Tau, Beta, Omega, W1Bw, CTildaSize, Gamma1Bw, PubKeyByteLen, SigByteLen)
		end,

		GenerateKeys = function(): (buffer, buffer)
			local Seed = Mldsa.CSPRNG.RandomBytes(KEYGEN_SEED_BYTE_LEN)
			local PubKey = buffer.create(PubKeyByteLen)
			local SecKey = buffer.create(SecKeyByteLen)
			Keygen(Seed, PubKey, SecKey, K, L, D, Eta, W1Bw, CTildaSize, PubKeyByteLen, SecKeyByteLen)
			return PubKey, SecKey
		end,
	}
end

local function ClearCaches(): ()
	local Cached = SIGN_KEY
	if Cached then
		buffer.fill(Cached.SecretKey, 0, 0)
		buffer.fill(Cached.S1, 0, 0)
		buffer.fill(Cached.S2, 0, 0)
		buffer.fill(Cached.T0, 0, 0)
		SIGN_KEY = nil
	end

	VERIFY_KEY = nil

	buffer.fill(SEED_HASH_INPUT, 0, 0)
	buffer.fill(SEED_HASH, 0, 0)
	buffer.fill(RHO_PRIME_INPUT, 0, 0)
	buffer.fill(RHO_PRIME, 0, 0)
	buffer.fill(MU_OUT, 0, 0)
	local MuBuf = MU_INPUT
	if MuBuf then
		buffer.fill(MuBuf, 0, 0)
		MU_INPUT = nil
	end

	for _, Work in SCRATCH do
		buffer.fill(Work.Y, 0, 0)
		buffer.fill(Work.YHat, 0, 0)
		buffer.fill(Work.W, 0, 0)
		buffer.fill(Work.Z, 0, 0)
		buffer.fill(Work.R, 0, 0)
		buffer.fill(Work.Product, 0, 0)
		buffer.fill(Work.C, 0, 0)
		buffer.fill(Work.Hints, 0, 0)
		buffer.fill(Work.CTilda, 0, 0)
		buffer.fill(Work.ChallengeInput, 0, 0)
	end

	Sampling.ClearCaches()
	SHA3.ClearCaches()
end

Mldsa = Lazy.Attach({
	ML_DSA_44 = MakeScheme(4, 4, 13, 2, 131072, 95232, 39, 78, 80, 128),
	ML_DSA_65 = MakeScheme(6, 5, 13, 4, 524288, 261888, 49, 196, 55, 192),
	ML_DSA_87 = MakeScheme(8, 7, 13, 2, 524288, 261888, 60, 120, 75, 256),
	ClearCaches = ClearCaches,
	PubKeyLen = PubKeyLen,
	SecKeyLen = SecKeyLen,
	SigLen = SigLen,
}, {
	CSPRNG = function()
		return require("../Utilities/CSPRNG")
	end,
})

return Mldsa
