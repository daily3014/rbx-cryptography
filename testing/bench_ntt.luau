--!strict
--!optimize 2
--!native

local IsLuauCLI = warn == nil
local NTT = if IsLuauCLI then require("../src/Verification/MlDSA/NTT") else require("../Verification/MlDSA/NTT")

local Q = 8380417

local Poly = buffer.create(256 * 4)
for I = 0, 255 do buffer.writeu32(Poly, I * 4, (I * 137 + 13) % Q) end

local function timeit(name, fn, iters)
	for _ = 1, 3 do fn() end
	local t0 = os.clock()
	for _ = 1, iters do fn() end
	local elapsed = os.clock() - t0
	print(string.format("%-25s %.2f us/op", name, elapsed / iters * 1e6))
	return elapsed / iters
end

-- Reset poly between iterations to avoid drifting state
local function reset()
	for I = 0, 255 do buffer.writeu32(Poly, I * 4, (I * 137 + 13) % Q) end
end

-- Bench Forward NTT
local function fwd()
	reset()
	NTT.ForwardNTT(Poly)
end

local function inv()
	NTT.InverseNTT(Poly)
end

local function rt()
	reset()
	NTT.ForwardNTT(Poly)
	NTT.InverseNTT(Poly)
end

timeit("ForwardNTT", fwd, 5000)
timeit("InverseNTT", inv, 5000)
timeit("Roundtrip", rt, 5000)
