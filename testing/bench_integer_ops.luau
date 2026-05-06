--!strict
--!optimize 2
--!native

-- Micro-benchmarks for individual integer.* operations and common combos.
-- Goal: figure out what's actually fast on Luau's integer impl so the
-- Ed25519 port can target the right idioms.

local function Format(Difference: number): string
	if Difference < 1e-9 then return string.format("%.2fps", Difference * 1e12) end
	if Difference < 1e-6 then return string.format("%.2fns", Difference * 1e9) end
	if Difference < 1e-3 then return string.format("%.2fus", Difference * 1e6) end
	if Difference < 1 then return string.format("%.2fms", Difference * 1e3) end
	return string.format("%.2fs", Difference)
end

local function Work()
	for i = 1, 1000 do
		for j = 1, 1000 do
			math.random(1, 2^30)
		end
	end
end

local Iterations = 5_000_000
local InnerUnroll = 10

local Results: {{Name: string, PerOp: number}} = {}

local function Bench(Name: string, Body: () -> ())
	Work()
	local start = os.clock()
	Body()
	local took = os.clock() - start
	local PerOp = took / (Iterations * InnerUnroll)
	table.insert(Results, {Name = Name, PerOp = PerOp})
	print(string.format("%-44s  total %s  per-op %s", Name, Format(took), Format(PerOp)))
end

local A = 0x123456789ABCDEFi
local B = 0x0FEDCBA987654321i
local SmallA = 0x1A3A3A3i
local SmallB = 0x05C5C5Ci

Bench("integer.add", function()
	local x = A
	for _ = 1, Iterations do
		x = integer.add(x, B); x = integer.add(x, B); x = integer.add(x, B); x = integer.add(x, B); x = integer.add(x, B)
		x = integer.add(x, B); x = integer.add(x, B); x = integer.add(x, B); x = integer.add(x, B); x = integer.add(x, B)
	end
	if x == 999i then print("noop") end
end)

Bench("integer.sub", function()
	local x = A
	for _ = 1, Iterations do
		x = integer.sub(x, B); x = integer.sub(x, B); x = integer.sub(x, B); x = integer.sub(x, B); x = integer.sub(x, B)
		x = integer.sub(x, B); x = integer.sub(x, B); x = integer.sub(x, B); x = integer.sub(x, B); x = integer.sub(x, B)
	end
	if x == 999i then print("noop") end
end)

Bench("integer.mul", function()
	local x = SmallA
	for _ = 1, Iterations do
		x = integer.mul(x, SmallB); x = integer.mul(x, SmallB); x = integer.mul(x, SmallB); x = integer.mul(x, SmallB); x = integer.mul(x, SmallB)
		x = integer.mul(x, SmallB); x = integer.mul(x, SmallB); x = integer.mul(x, SmallB); x = integer.mul(x, SmallB); x = integer.mul(x, SmallB)
	end
	if x == 999i then print("noop") end
end)

Bench("integer.mul (one side const literal 19i)", function()
	local x = SmallA
	for _ = 1, Iterations do
		x = integer.mul(x, 19i); x = integer.mul(x, 19i); x = integer.mul(x, 19i); x = integer.mul(x, 19i); x = integer.mul(x, 19i)
		x = integer.mul(x, 19i); x = integer.mul(x, 19i); x = integer.mul(x, 19i); x = integer.mul(x, 19i); x = integer.mul(x, 19i)
	end
	if x == 999i then print("noop") end
end)

Bench("integer.neg", function()
	local x = A
	for _ = 1, Iterations do
		x = integer.neg(x); x = integer.neg(x); x = integer.neg(x); x = integer.neg(x); x = integer.neg(x)
		x = integer.neg(x); x = integer.neg(x); x = integer.neg(x); x = integer.neg(x); x = integer.neg(x)
	end
	if x == 999i then print("noop") end
end)

Bench("integer.band", function()
	local x = A
	local M = 0x3FFFFFFi
	for _ = 1, Iterations do
		x = integer.band(x, M); x = integer.band(x, M); x = integer.band(x, M); x = integer.band(x, M); x = integer.band(x, M)
		x = integer.band(x, M); x = integer.band(x, M); x = integer.band(x, M); x = integer.band(x, M); x = integer.band(x, M)
	end
	if x == 999i then print("noop") end
end)

Bench("integer.bor", function()
	local x = A
	for _ = 1, Iterations do
		x = integer.bor(x, B); x = integer.bor(x, B); x = integer.bor(x, B); x = integer.bor(x, B); x = integer.bor(x, B)
		x = integer.bor(x, B); x = integer.bor(x, B); x = integer.bor(x, B); x = integer.bor(x, B); x = integer.bor(x, B)
	end
	if x == 999i then print("noop") end
end)

Bench("integer.bxor", function()
	local x = A
	for _ = 1, Iterations do
		x = integer.bxor(x, B); x = integer.bxor(x, B); x = integer.bxor(x, B); x = integer.bxor(x, B); x = integer.bxor(x, B)
		x = integer.bxor(x, B); x = integer.bxor(x, B); x = integer.bxor(x, B); x = integer.bxor(x, B); x = integer.bxor(x, B)
	end
	if x == 999i then print("noop") end
end)

Bench("integer.lshift (const 26i)", function()
	local x = SmallA
	for _ = 1, Iterations do
		x = integer.lshift(x, 26i); x = integer.lshift(x, 26i); x = integer.lshift(x, 26i); x = integer.lshift(x, 26i); x = integer.lshift(x, 26i)
		x = integer.lshift(x, 26i); x = integer.lshift(x, 26i); x = integer.lshift(x, 26i); x = integer.lshift(x, 26i); x = integer.lshift(x, 26i)
	end
	if x == 999i then print("noop") end
end)

Bench("integer.rshift (const 26i)", function()
	local x = A
	for _ = 1, Iterations do
		x = integer.rshift(x, 26i); x = integer.rshift(x, 26i); x = integer.rshift(x, 26i); x = integer.rshift(x, 26i); x = integer.rshift(x, 26i)
		x = integer.rshift(x, 26i); x = integer.rshift(x, 26i); x = integer.rshift(x, 26i); x = integer.rshift(x, 26i); x = integer.rshift(x, 26i)
	end
	if x == 999i then print("noop") end
end)

Bench("integer.arshift (const 26i)", function()
	local x = A
	for _ = 1, Iterations do
		x = integer.arshift(x, 26i); x = integer.arshift(x, 26i); x = integer.arshift(x, 26i); x = integer.arshift(x, 26i); x = integer.arshift(x, 26i)
		x = integer.arshift(x, 26i); x = integer.arshift(x, 26i); x = integer.arshift(x, 26i); x = integer.arshift(x, 26i); x = integer.arshift(x, 26i)
	end
	if x == 999i then print("noop") end
end)

local ShiftAmount: integer = 26i
Bench("integer.arshift (variable shift)", function()
	local x = A
	for _ = 1, Iterations do
		x = integer.arshift(x, ShiftAmount); x = integer.arshift(x, ShiftAmount); x = integer.arshift(x, ShiftAmount); x = integer.arshift(x, ShiftAmount); x = integer.arshift(x, ShiftAmount)
		x = integer.arshift(x, ShiftAmount); x = integer.arshift(x, ShiftAmount); x = integer.arshift(x, ShiftAmount); x = integer.arshift(x, ShiftAmount); x = integer.arshift(x, ShiftAmount)
	end
	if x == 999i then print("noop") end
end)

local IAdd = integer.add
Bench("local alias: IAdd (vs integer.add above)", function()
	local x = A
	for _ = 1, Iterations do
		x = IAdd(x, B); x = IAdd(x, B); x = IAdd(x, B); x = IAdd(x, B); x = IAdd(x, B)
		x = IAdd(x, B); x = IAdd(x, B); x = IAdd(x, B); x = IAdd(x, B); x = IAdd(x, B)
	end
	if x == 999i then print("noop") end
end)

local IMul = integer.mul
Bench("local alias: IMul (vs integer.mul above)", function()
	local x = SmallA
	for _ = 1, Iterations do
		x = IMul(x, SmallB); x = IMul(x, SmallB); x = IMul(x, SmallB); x = IMul(x, SmallB); x = IMul(x, SmallB)
		x = IMul(x, SmallB); x = IMul(x, SmallB); x = IMul(x, SmallB); x = IMul(x, SmallB); x = IMul(x, SmallB)
	end
	if x == 999i then print("noop") end
end)

local M26 = 0x3FFFFFFi
Bench("carry step: arshift + add + band (chained 10x)", function()
	local Lo, Hi = A, B
	for _ = 1, Iterations do
		local C = integer.arshift(Lo, 26i); Hi = integer.add(Hi, C); Lo = integer.band(Lo, M26)
		C = integer.arshift(Lo, 26i); Hi = integer.add(Hi, C); Lo = integer.band(Lo, M26)
		C = integer.arshift(Lo, 26i); Hi = integer.add(Hi, C); Lo = integer.band(Lo, M26)
		C = integer.arshift(Lo, 26i); Hi = integer.add(Hi, C); Lo = integer.band(Lo, M26)
		C = integer.arshift(Lo, 26i); Hi = integer.add(Hi, C); Lo = integer.band(Lo, M26)
		C = integer.arshift(Lo, 26i); Hi = integer.add(Hi, C); Lo = integer.band(Lo, M26)
		C = integer.arshift(Lo, 26i); Hi = integer.add(Hi, C); Lo = integer.band(Lo, M26)
		C = integer.arshift(Lo, 26i); Hi = integer.add(Hi, C); Lo = integer.band(Lo, M26)
		C = integer.arshift(Lo, 26i); Hi = integer.add(Hi, C); Lo = integer.band(Lo, M26)
		C = integer.arshift(Lo, 26i); Hi = integer.add(Hi, C); Lo = integer.band(Lo, M26)
	end
	if Lo == 999i and Hi == 999i then print("noop") end
end)

local Buf = buffer.create(80) do
	for i = 0, 9 do buffer.writeinteger(Buf, i * 8, integer.add(A, integer.create(i) :: integer)) end
end

Bench("buffer.readinteger (10 reads from buf)", function()
	local x = 0i
	for _ = 1, Iterations do
		x = buffer.readinteger(Buf, 0)
		x = buffer.readinteger(Buf, 8)
		x = buffer.readinteger(Buf, 16)
		x = buffer.readinteger(Buf, 24)
		x = buffer.readinteger(Buf, 32)
		x = buffer.readinteger(Buf, 40)
		x = buffer.readinteger(Buf, 48)
		x = buffer.readinteger(Buf, 56)
		x = buffer.readinteger(Buf, 64)
		x = buffer.readinteger(Buf, 72)
	end
	if x == 999i then print("noop") end
end)

Bench("buffer.writeinteger (10 writes)", function()
	local v = A
	for _ = 1, Iterations do
		buffer.writeinteger(Buf, 0, v)
		buffer.writeinteger(Buf, 8, v)
		buffer.writeinteger(Buf, 16, v)
		buffer.writeinteger(Buf, 24, v)
		buffer.writeinteger(Buf, 32, v)
		buffer.writeinteger(Buf, 40, v)
		buffer.writeinteger(Buf, 48, v)
		buffer.writeinteger(Buf, 56, v)
		buffer.writeinteger(Buf, 64, v)
		buffer.writeinteger(Buf, 72, v)
	end
end)

local FA = 12345.6789
local FB = 9876.54321
Bench("[f64] number add (10x)", function()
	local x = FA
	for _ = 1, Iterations do
		x = x + FB; x = x + FB; x = x + FB; x = x + FB; x = x + FB
		x = x + FB; x = x + FB; x = x + FB; x = x + FB; x = x + FB
	end
	if x == 999 then print("noop") end
end)

Bench("[f64] number mul (10x)", function()
	local x = 1.0001
	for _ = 1, Iterations do
		x = x * 1.0001; x = x * 1.0001; x = x * 1.0001; x = x * 1.0001; x = x * 1.0001
		x = x * 1.0001; x = x * 1.0001; x = x * 1.0001; x = x * 1.0001; x = x * 1.0001
	end
	if x == 999 then print("noop") end
end)

local FBuf = buffer.create(80) do
	for i = 0, 9 do buffer.writef64(FBuf, i * 8, FA + i) end
end
Bench("[f64] buffer.readf64 (10 reads)", function()
	local x = 0.0
	for _ = 1, Iterations do
		x = buffer.readf64(FBuf, 0)
		x = buffer.readf64(FBuf, 8)
		x = buffer.readf64(FBuf, 16)
		x = buffer.readf64(FBuf, 24)
		x = buffer.readf64(FBuf, 32)
		x = buffer.readf64(FBuf, 40)
		x = buffer.readf64(FBuf, 48)
		x = buffer.readf64(FBuf, 56)
		x = buffer.readf64(FBuf, 64)
		x = buffer.readf64(FBuf, 72)
	end
	if x == 999 then print("noop") end
end)

print("\n sorted (fastest -> slowest) ")
table.sort(Results, function(a, b) return a.PerOp < b.PerOp end)
for _, R in Results do
	print(string.format("%-50s  %s", R.Name, Format(R.PerOp)))
end
