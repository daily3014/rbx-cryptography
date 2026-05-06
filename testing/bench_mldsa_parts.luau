--!strict
local IsCLI = warn == nil
local NTT = if IsCLI then require("../src/Verification/MlDSA/NTT") else require("../Verification/MlDSA/NTT")
local PolyVec = if IsCLI then require("../src/Verification/MlDSA/PolyVec") else require("../Verification/MlDSA/PolyVec")
local Sampling = if IsCLI then require("../src/Verification/MlDSA/Sampling") else require("../Verification/MlDSA/Sampling")
local XOF = if IsCLI then require("../src/Verification/MlDSA/XOF") else require("../Verification/MlDSA/XOF")

local Q = 8380417
local N = 256

-- ML-DSA-44 dimensions
local K, L = 4, 4

local Poly = buffer.create(N * 4)
for I = 0, N-1 do buffer.writeu32(Poly, I * 4, (I * 137 + 13) % Q) end

-- Vectors of K and L polys
local VecK = buffer.create(K * N * 4)
local VecL = buffer.create(L * N * 4)
local Mat = buffer.create(K * L * N * 4)
for I = 0, K * N - 1 do buffer.writeu32(VecK, I * 4, (I * 31 + 7) % Q) end
for I = 0, L * N - 1 do buffer.writeu32(VecL, I * 4, (I * 53 + 11) % Q) end
for I = 0, K * L * N - 1 do buffer.writeu32(Mat, I * 4, (I * 17 + 3) % Q) end

local Rho = buffer.create(32)
for I = 0, 31 do buffer.writeu8(Rho, I, I) end

local function timeit(name, fn, iters)
	for _ = 1, 3 do fn() end
	local t0 = os.clock()
	for _ = 1, iters do fn() end
	local elapsed = os.clock() - t0
	print(string.format("%-30s %.2f us/op", name, elapsed / iters * 1e6))
end

timeit("ForwardNTT (1 poly)",  function() NTT.ForwardNTT(Poly) end, 5000)
timeit("InverseNTT (1 poly)",  function() NTT.InverseNTT(Poly) end, 5000)
timeit("PolyVec.MatMul (4x4)", function() PolyVec.MatrixMultiply(Mat, VecL, VecK, K, L, L, 1) end, 1000)
timeit("PolyVec.AddTo (K=4)",  function() PolyVec.AddTo(VecK, VecK, K) end, 5000)
timeit("PolyVec.Negate (K=4)", function() PolyVec.Negate(VecK, K) end, 5000)
timeit("Sampling.ExpandA",     function() Sampling.ExpandA(Rho, Mat, K, L) end, 200)
