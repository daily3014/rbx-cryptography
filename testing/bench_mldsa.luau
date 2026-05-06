--!strict
local IsCLI = warn == nil
local Cryptography = if IsCLI then require("../src") else require("../")
local MLDSA = Cryptography.Verification.MlDSA

local Variant = MLDSA.ML_DSA_44

local PubKey, SecKey = Variant.GenerateKeys()
local Message = buffer.fromstring("Test message")
local Context = buffer.create(0)
local Signature = buffer.create(Variant.SigByteLen)
local Random = buffer.create(32)
for I = 0, 31 do buffer.writeu8(Random, I, I * 7 + 3) end

assert(Variant.Sign(Message, Random, SecKey, Context, Signature), "sign failed")
assert(Variant.Verify(Message, PubKey, Context, Signature), "verify failed")

local function timeit(name, fn, iters)
	for _ = 1, 3 do fn() end
	local t0 = os.clock()
	for _ = 1, iters do fn() end
	local elapsed = os.clock() - t0
	print(string.format("%-30s %.2f us/op", name, elapsed / iters * 1e6))
	return elapsed / iters
end

local k = timeit("KeyGen", function() Variant.GenerateKeys() end, 100)
local s = timeit("Sign",   function() Variant.Sign(Message, Random, SecKey, Context, Signature) end, 100)
local v = timeit("Verify", function() Variant.Verify(Message, PubKey, Context, Signature) end, 100)
print(string.format("Sign+Verify roundtrip: %.2f us", (s + v) * 1e6))
