--!strict
--!optimize 2
--!native

local function Format(D: number): string
	if D < 1e-9 then return string.format("%.2fps", D * 1e12) end
	if D < 1e-6 then return string.format("%.2fns", D * 1e9) end
	return string.format("%.2fus", D * 1e6)
end
local function Work() for i=1,1000 do for j=1,1000 do math.random(1,2^30) end end end

local Buf = buffer.create(64)
for i = 0, 63 do buffer.writeu8(Buf, i, i) end

-- 11 limbs, mimicking DecodeWide low part
local function ThreeByteV1()  -- 3x readu8 + 2 mul + 2 add
	local Sum = 0
	for I = 0, 30, 3 do
		Sum = Sum + buffer.readu8(Buf, I) + buffer.readu8(Buf, I+1) * 256 + buffer.readu8(Buf, I+2) * 65536
	end
	return Sum
end

local function ThreeByteV2()  -- readu16 + readu8 * 65536
	local Sum = 0
	for I = 0, 30, 3 do
		Sum = Sum + buffer.readu16(Buf, I) + buffer.readu8(Buf, I+2) * 65536
	end
	return Sum
end

local function ThreeByteV3()  -- readu32 & 0xFFFFFF (band)
	local Sum = 0
	for I = 0, 30, 3 do
		Sum = Sum + bit32.band(buffer.readu32(Buf, I), 0xFFFFFF)
	end
	return Sum
end

local function Bench(Name: string, Iter: number, Fn: () -> number)
	Work()
	local s = os.clock()
	local R = 0
	for _ = 1, Iter do R = R + Fn() end
	local t = (os.clock() - s) / Iter
	if R == -999 then print("noop") end
	print(string.format("%-30s %s/op", Name, Format(t)))
end

local Iter = 1_000_000
Bench("V1: 3x readu8 + 2 mul/add", Iter, ThreeByteV1)
Bench("V2: readu16 + readu8 * 65536", Iter, ThreeByteV2)
Bench("V3: bit32.band(readu32, ...)", Iter, ThreeByteV3)
