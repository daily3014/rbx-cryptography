--!strict
--!optimize 2
--!native
local OldB = require("./algorithms/Base64Old")
local NewB = require("./algorithms/Base64New")

local function Format(D: number): string
	if D < 1e-9 then return string.format("%.2fps", D * 1e12) end
	if D < 1e-6 then return string.format("%.2fns", D * 1e9) end
	if D < 1e-3 then return string.format("%.2fus", D * 1e6) end
	return string.format("%.2fms", D * 1e3)
end
local function Work() for i=1,1000 do for j=1,1000 do math.random(1, 2^30) end end end

local function BenchSize(Size: number, Iter: number)
	local In = buffer.create(Size)
	for I = 0, Size - 1 do buffer.writeu8(In, I, I % 256) end

	Work()
	local s = os.clock(); for _ = 1, Iter do OldB.Encode(In) end
	local O = (os.clock() - s) / Iter

	Work()
	s = os.clock(); for _ = 1, Iter do NewB.Encode(In) end
	local N = (os.clock() - s) / Iter

	print(string.format("%-10s old: %s  new: %s  speedup: %.2fx",
		`{Size}B`, Format(O), Format(N), O / N))
end

print("Base64.Encode (per-call, varying input sizes)")
BenchSize(64, 50000)
BenchSize(256, 20000)
BenchSize(1024, 10000)
BenchSize(4096, 5000)
BenchSize(16384, 1000)

print("\nBase64.Decode (per-call, varying input sizes)")
local function BenchDecodeSize(Size: number, Iter: number)
	local In = buffer.create(Size)
	for I = 0, Size - 1 do buffer.writeu8(In, I, I % 256) end
	local Encoded = OldB.Encode(In)

	Work()
	local s = os.clock(); for _ = 1, Iter do OldB.Decode(Encoded) end
	local O = (os.clock() - s) / Iter

	Work()
	s = os.clock(); for _ = 1, Iter do NewB.Decode(Encoded) end
	local N = (os.clock() - s) / Iter

	print(string.format("%-10s old: %s  new: %s  speedup: %.2fx",
		`{Size}B`, Format(O), Format(N), O / N))
end
BenchDecodeSize(64, 50000)
BenchDecodeSize(256, 20000)
BenchDecodeSize(1024, 10000)
BenchDecodeSize(4096, 5000)
BenchDecodeSize(16384, 1000)
