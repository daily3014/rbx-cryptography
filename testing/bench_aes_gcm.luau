--!strict
--!optimize 2
--!native

local NewAES = require("../src/Encryption/AES")  -- now T-table
local OldAES = require("./algorithms/AESOld")     -- original (Hyper-S-Box, pre-surgical-port)

local function Format(D: number): string
	if D < 1e-6 then return string.format("%.2fns", D * 1e9) end
	if D < 1e-3 then return string.format("%.2fus", D * 1e6) end
	if D < 1 then return string.format("%.2fms", D * 1e3) end
	return string.format("%.2fs", D)
end

local function Work()
	for i = 1, 1000 do for j = 1, 1000 do math.random(1, 2^30) end end
end

local Key = buffer.create(32)
for i = 0, 31 do buffer.writeu8(Key, i, i + 1) end

local IV = buffer.create(12)
for i = 0, 11 do buffer.writeu8(IV, i, i * 17) end

local AAD = buffer.fromstring("aad-context")

-- Sanity: outputs match
do
	local Msg = buffer.fromstring("hello world this is a test message that spans some blocks")
	local NC, NT = NewAES.Encrypt(Msg, Key, IV, AAD)
	local OC, OT = OldAES.Encrypt(Msg, Key, IV, AAD)

	local function Hex(B: buffer): string
		local Parts = {}
		for I = 0, buffer.len(B) - 1 do Parts[I + 1] = string.format("%02x", buffer.readu8(B, I)) end
		return table.concat(Parts)
	end

	if Hex(NC) == Hex(OC) and Hex(NT) == Hex(OT) then
		print("[OK] outputs match")
	else
		print("[FAIL] outputs differ")
		print("  NC:", Hex(NC))
		print("  OC:", Hex(OC))
		print("  NT:", Hex(NT))
		print("  OT:", Hex(OT))
		return
	end
end

local function BenchSize(Size: number, Iterations: number)
	local Msg = buffer.create(Size)
	for i = 0, Size - 1 do buffer.writeu8(Msg, i, i % 256) end

	Work()
	local s = os.clock()
	for _ = 1, Iterations do NewAES.Encrypt(Msg, Key, IV, AAD) end
	local NewTime = os.clock() - s

	Work()
	s = os.clock()
	for _ = 1, Iterations do OldAES.Encrypt(Msg, Key, IV, AAD) end
	local OldTime = os.clock() - s

	print(string.format("%-10s  new: %s  old: %s  speedup: %.2fx",
		`{Size}B`, Format(NewTime / Iterations), Format(OldTime / Iterations), OldTime / NewTime))
end

print("\nAES-256-GCM Encrypt (per-call)")
BenchSize(64, 5000)
BenchSize(256, 2000)
BenchSize(1024, 1000)
BenchSize(4096, 500)
BenchSize(16384, 200)
