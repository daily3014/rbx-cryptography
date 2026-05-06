--!strict
--!optimize 2
--!native

local AESBS = require("./algorithms/AESBitsliceCore")

local function Format(D: number): string
	if D < 1e-9 then return string.format("%.2fps", D * 1e12) end
	if D < 1e-6 then return string.format("%.2fns", D * 1e9) end
	if D < 1e-3 then return string.format("%.2fus", D * 1e6) end
	if D < 1 then return string.format("%.2fms", D * 1e3) end
	return string.format("%.2fs", D)
end

local function Work()
	for i = 1, 1000 do for j = 1, 1000 do math.random(1, 2^30) end end
end

-- AES-256 setup
local Key = buffer.create(32)
for i = 0, 31 do buffer.writeu8(Key, i, i + 1) end
local Skey, Nr = AESBS.KeySchedule(Key)
local In = buffer.create(64)
for i = 0, 63 do buffer.writeu8(In, i, i) end
local Out = buffer.create(64)

-- Compare against existing table-based EncryptBlock
-- We need to call it 4 times to encrypt 64 bytes for fair comparison
local TableAES = require("./algorithms/AESOld") :: any

-- Hack: extract the EncryptBlock function via reflection of the module's internals
-- Actually the module only exports Encrypt/Decrypt. Let's call full Encrypt for fair-ish comparison.

-- Fair comparison: time how long it takes to produce 64 bytes of AES output
-- Bitsliced: 1 call to EncryptBlocks4
-- Table: would be 4 calls to EncryptBlock (which we can't access directly)

-- Instead, time the full GCM Encrypt with a fixed AAD/IV and see total throughput.
-- That's actually the more useful bench anyway.

print("Bitsliced AES-256 EncryptBlocks4 (encrypts 64 bytes per call)")

do
	Work()
	local Iter = 100_000
	local s = os.clock()
	for _ = 1, Iter do AESBS.EncryptBlocks4(Skey, Nr, In, 0, Out, 0) end
	local t = os.clock() - s
	print(string.format("  %s/op (4 blocks)  =  %s/block  =  %s/byte",
		Format(t / Iter), Format(t / Iter / 4), Format(t / Iter / 64)))
end

print("\nBitsliced AES-256 EncryptBlock (encrypts 16 bytes per call, 3 wasted)")
do
	Work()
	local Iter = 100_000
	local s = os.clock()
	for _ = 1, Iter do AESBS.EncryptBlock(Skey, Nr, In, 0, Out, 0) end
	local t = os.clock() - s
	print(string.format("  %s/op", Format(t / Iter)))
end

print("\nKey schedule (one time setup cost)")
do
	Work()
	local Iter = 10_000
	local s = os.clock()
	for _ = 1, Iter do AESBS.KeySchedule(Key) end
	local t = os.clock() - s
	print(string.format("  %s/op", Format(t / Iter)))
end
