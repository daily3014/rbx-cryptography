--!strict
--!optimize 2
--!native
local CSPRNG = require("../src/Utilities/CSPRNG")

local function Format(D: number): string
	if D < 1e-9 then return string.format("%.2fps", D * 1e12) end
	if D < 1e-6 then return string.format("%.2fns", D * 1e9) end
	return string.format("%.2fus", D * 1e6)
end
local function Work() for i=1,1000 do for j=1,1000 do math.random(1,2^30) end end end

print("CSPRNG.RandomBytes (Blake3-only)")
for _, N in {16, 64, 256, 1024, 8192} :: {number} do
	Work()
	local Iter = 10000
	local s = os.clock()
	for _ = 1, Iter do CSPRNG.RandomBytes(N) end
	print(string.format("  %-6s  %s/op", `{N}B`, Format((os.clock() - s) / Iter)))
end
