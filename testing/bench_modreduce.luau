--!strict
--!optimize 2
--!native

local function Format(D: number): string
	if D < 1e-9 then return string.format("%.2fps", D * 1e12) end
	if D < 1e-6 then return string.format("%.2fns", D * 1e9) end
	return string.format("%.2fus", D * 1e6)
end
local function Work() for i=1,1000 do for j=1,1000 do math.random(1,2^30) end end end

local Q_KEM = 3329
local Q_DSA = 8380417

-- For Barrett reduction with Q_KEM=3329:
-- 2^24 / 3329 = 5039 (rounded down)
-- For input x < 2^24 (= 12-bit * 12-bit max),
-- q_est = (x * 5039) / 2^24
-- r = x - q_est * Q
local M_KEM = 5039  -- floor(2^24 / 3329)

-- For Q_DSA: 2^46 / 8380417 ≈ 8398174
-- For input x < 2^46, q_est = (x * 8398174) / 2^46
-- But x * 8398174 can be ~2^69, exceeds 53-bit mantissa. Won't work in number-space.
-- Need integer for that.
local M_DSA = 8398174

-- Generate test vectors
local A_KEM = buffer.create(8192)
local B_KEM = buffer.create(8192)
local A_DSA = buffer.create(8192)
local B_DSA = buffer.create(8192)
math.randomseed(1)
for I = 0, 4095 do
	buffer.writeu16(A_KEM, I*2, math.random(0, Q_KEM - 1))
	buffer.writeu16(B_KEM, I*2, math.random(0, Q_KEM - 1))
end
for I = 0, 1023 do
	buffer.writeu32(A_DSA, I*4, math.random(0, Q_DSA - 1))
	buffer.writeu32(B_DSA, I*4, math.random(0, Q_DSA - 1))
end

local Iter = 100_000

print(" ML-KEM Q=3329 (12-bit field) ")

do  -- Baseline: (A * B) % Q
	Work()
	local s = os.clock()
	local Sink = 0
	for _ = 1, Iter do
		for I = 0, 4095 do
			local A = buffer.readu16(A_KEM, I*2)
			local B = buffer.readu16(B_KEM, I*2)
			Sink = Sink + (A * B) % Q_KEM
		end
	end
	if Sink == 0 then print("noop") end
	local t = (os.clock() - s) / Iter / 4096
	print(string.format("  baseline (a*b)%%Q: %s/op", Format(t)))
end

do  -- Barrett with bit32
	Work()
	local s = os.clock()
	local Sink = 0
	for _ = 1, Iter do
		for I = 0, 4095 do
			local A = buffer.readu16(A_KEM, I*2)
			local B = buffer.readu16(B_KEM, I*2)
			local Tmp = A * B  -- < 2^24
			local Q_est = bit32.rshift(Tmp * M_KEM, 24)  -- Tmp*M < 2^36, fits in 53-bit mantissa, but bit32 truncates to u32!
			local R = Tmp - Q_est * Q_KEM
			if R >= Q_KEM then R = R - Q_KEM end
			Sink = Sink + R
		end
	end
	if Sink == 0 then print("noop") end
	local t = (os.clock() - s) / Iter / 4096
	print(string.format("  barrett bit32: %s/op (NOTE: may be wrong due to u32 truncation)", Format(t)))
end

do  -- Barrett with math.floor
	Work()
	local s = os.clock()
	local Sink = 0
	for _ = 1, Iter do
		for I = 0, 4095 do
			local A = buffer.readu16(A_KEM, I*2)
			local B = buffer.readu16(B_KEM, I*2)
			local Tmp = A * B  -- < 2^24
			local Q_est = (Tmp * M_KEM) // 16777216  -- floor div by 2^24
			local R = Tmp - Q_est * Q_KEM
			if R >= Q_KEM then R = R - Q_KEM end
			Sink = Sink + R
		end
	end
	if Sink == 0 then print("noop") end
	local t = (os.clock() - s) / Iter / 4096
	print(string.format("  barrett // 2^24: %s/op", Format(t)))
end

print("\n ML-DSA Q=8380417 (23-bit field) ")

do  -- Baseline
	Work()
	local s = os.clock()
	local Sink = 0
	for _ = 1, Iter // 4 do
		for I = 0, 1023 do
			local A = buffer.readu32(A_DSA, I*4)
			local B = buffer.readu32(B_DSA, I*4)
			Sink = Sink + (A * B) % Q_DSA
		end
	end
	if Sink == 0 then print("noop") end
	local t = (os.clock() - s) / (Iter // 4) / 1024
	print(string.format("  baseline (a*b)%%Q: %s/op", Format(t)))
end

do  -- Barrett: but a*b can be 46 bits, *M_DSA gets to ~70 bits, exceeds float precision
	-- Need to use integer for this. Convert to integer, do mul, then back.
	-- Actually let's just compare via integer.mod
	Work()
	local s = os.clock()
	local Sink = 0
	local Q_DSA_i = integer.create(Q_DSA) :: integer
	for _ = 1, Iter // 4 do
		for I = 0, 1023 do
			local A = buffer.readu32(A_DSA, I*4)
			local B = buffer.readu32(B_DSA, I*4)
			local AB = integer.mul(integer.create(A) :: integer, integer.create(B) :: integer)
			local R = integer.tonumber(integer.mod(AB, Q_DSA_i))
			Sink = Sink + R
		end
	end
	if Sink == 0 then print("noop") end
	local t = (os.clock() - s) / (Iter // 4) / 1024
	print(string.format("  integer.mod: %s/op", Format(t)))
end
