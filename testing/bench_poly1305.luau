--!strict
--!optimize 2
--!native

local NewPoly = require("../src/Encryption/AEAD/Poly1305")
local OldPoly = require("./algorithms/Poly1305Old")

local function Format(Difference: number): string
	if Difference < 0.001 then return string.format("%.2fus", Difference * 1_000_000) end
	if Difference < 1 then return string.format("%.2fms", Difference * 1_000) end
	return string.format("%.2fs", Difference)
end

local function Work()
	for i = 1, 1000 do
		for j = 1, 1000 do
			math.random(1, 2^30)
		end
	end
end

local Key = buffer.create(32)
for i = 0, 31 do buffer.writeu8(Key, i, i + 1) end

local function BenchSize(Size: number, Iterations: number)
	local Msg = buffer.create(Size)
	for i = 0, Size - 1 do buffer.writeu8(Msg, i, i % 256) end

	Work()
	local s = os.clock(); for _ = 1, Iterations do NewPoly(Msg, Key) end
	local NewTime = os.clock() - s

	Work()
	s = os.clock(); for _ = 1, Iterations do OldPoly(Msg, Key) end
	local OldTime = os.clock() - s

	print(string.format("%-12s  new: %s  old: %s  speedup: %.2fx",
		`{Size}B`, Format(NewTime / Iterations), Format(OldTime / Iterations), OldTime / NewTime))
end

print("Poly1305 (per-call, varying message sizes)")
BenchSize(64, 10000)
BenchSize(256, 5000)
BenchSize(1024, 2000)
BenchSize(4096, 500)
BenchSize(16384, 200)
