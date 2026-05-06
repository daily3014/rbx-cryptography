--!strict
--!optimize 2
--!native

local Q = 8380417

-- generate a buffer of (a, b) pairs to "multiply"
local N = 100000
local Buf = buffer.create(N * 8)
for I = 0, N - 1 do
	buffer.writeu32(Buf, I * 8, ((I * 137 + 3) % Q))
	buffer.writeu32(Buf, I * 8 + 4, ((I * 17 + 11) % Q))
end

local function bench(name, fn, iters)
	local sum = 0
	for _ = 1, 3 do sum += fn() end
	local t0 = os.clock()
	for _ = 1, iters do sum += fn() end
	local elapsed = os.clock() - t0
	print(string.format("%-30s %.3f ns/iter (sink=%d)", name, elapsed / (iters * N) * 1e9, sum))
end

local function plain_mod()
	local s = 0
	for I = 0, N - 1 do
		local a = buffer.readu32(Buf, I * 8)
		local b = buffer.readu32(Buf, I * 8 + 4)
		s += (a * b) % Q
	end
	return s
end

local function int_mul_mod()
	local s = 0i
	for I = 0, N - 1 do
		local a = buffer.readu32(Buf, I * 8)
		local b = buffer.readu32(Buf, I * 8 + 4)
		s = integer.add(s, integer.mod(integer.mul(integer.create(a) :: integer, integer.create(b) :: integer), 8380417i))
	end
	return integer.tonumber(s)
end

-- Montgomery reduction using integer
-- R = 2^32, R*R^-1 ≡ 1 mod Q
-- mont_inv = -Q^-1 mod 2^32 = 4236238847
local MONT_INV = 4236238847i
local Q_I = 8380417i
local MASK_32 = 0xFFFFFFFFi

local function mont_reduce()
	local s = 0i
	for I = 0, N - 1 do
		local a = buffer.readu32(Buf, I * 8)
		local b = buffer.readu32(Buf, I * 8 + 4)
		local t = integer.mul(integer.create(a) :: integer, integer.create(b) :: integer)
		local q = integer.band(integer.mul(t, MONT_INV), MASK_32)
		local r = integer.rshift(integer.add(t, integer.mul(q, Q_I)), 32i)
		-- r is in [0, 2Q); fix:
		if integer.ge(r, Q_I) then r = integer.sub(r, Q_I) end
		s = integer.add(s, r)
	end
	return integer.tonumber(s)
end

bench("plain (a*b) % Q double",      plain_mod, 50)
bench("integer.mul + integer.mod",   int_mul_mod, 50)
bench("Montgomery via integer",      mont_reduce, 50)
