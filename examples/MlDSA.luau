--!strict
local ReplicatedStorage = game:GetService("ReplicatedStorage")

-- Get the library
local Cryptography = require(ReplicatedStorage:WaitForChild("Cryptography"))
local MLDSA = Cryptography.Verification.MlDSA
local CSPRNG = Cryptography.Utilities.CSPRNG

--[[
	ML-DSA stands for:
		Module-Lattice-based
		Digital Signature Algorithm
	
	ML-DSA is a post-quantum digital signature scheme standardized
	in NIST FIPS 204. It provides three security levels and supports
	both deterministic and hedged (randomized) signing.
	
	Hedged signing uses 32 bytes of randomness for enhanced security.
	Context can be used for domain separation (max 255 bytes).
--]]

-- Generate key pair
local PubKey, SecKey = MLDSA.ML_DSA_44.GenerateKeys()

-- Sign message with hedged signing (recommended)
local Message = buffer.fromstring("Hello, post-quantum world!")
local Context = buffer.create(0) -- Empty context
local Randomness = CSPRNG.RandomBytes(32)
local Signature = buffer.create(MLDSA.ML_DSA_44.SigByteLen)

local SignSuccess = MLDSA.ML_DSA_44.Sign(Message, Randomness, SecKey, Context, Signature)
if not SignSuccess then
	error("Signing failed")
end

-- Verify signature
local Valid = MLDSA.ML_DSA_44.Verify(Message, PubKey, Context, Signature)
print("Signature valid:", Valid)

-- Deterministic signing (zero randomness)
local DetRandom = buffer.create(32)
local DetSig = buffer.create(MLDSA.ML_DSA_44.SigByteLen)
MLDSA.ML_DSA_44.Sign(Message, DetRandom, SecKey, Context, DetSig)

-- Context example
local ContextData = buffer.fromstring("game-session")
local CtxSig = buffer.create(MLDSA.ML_DSA_44.SigByteLen)
MLDSA.ML_DSA_44.Sign(Message, CSPRNG.RandomBytes(32), SecKey, ContextData, CtxSig)
local CtxValid = MLDSA.ML_DSA_44.Verify(Message, PubKey, ContextData, CtxSig)
print("Context signature valid:", CtxValid)

-- Different security levels
local Pub65, Sec65 = MLDSA.ML_DSA_65.GenerateKeys()
local Pub87, Sec87 = MLDSA.ML_DSA_87.GenerateKeys()

-- Key and signature sizes
print("ML-DSA-44 sizes:", buffer.len(PubKey), buffer.len(SecKey), buffer.len(Signature))
print("ML-DSA-65 sizes:", buffer.len(Pub65), buffer.len(Sec65), MLDSA.ML_DSA_65.SigByteLen)
print("ML-DSA-87 sizes:", buffer.len(Pub87), buffer.len(Sec87), MLDSA.ML_DSA_87.SigByteLen)
-- Quite big