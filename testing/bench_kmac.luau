local ported_kmac = require("../src/Hashing/KMAC")
local old_kmac = require("./algorithms/KMACold")

local msg = buffer.fromstring(string.rep("A", 20_000))
local key = buffer.fromstring(string.rep("B", 32))
local out_32, out_64 = buffer.create(32), buffer.create(64)

local function Format(Difference)
	if Difference < 0.001 then
		return string.format("%.2fus", Difference * 1_000_000)
	elseif Difference < 1 then
		return string.format("%.2fms", Difference * 1_000)
	end

	return string.format("%.2fs", Difference)
end

local function Work()
	for i = 1, 1000 do
		for j = 1, 1000 do
			math.random(1, 2^30)
		end
	end
end

print(`Size of message: {buffer.len(msg)} bytes`)
local Iterations = 1000

do
	Work()

	local start = os.clock()
	for i = 1, Iterations do
		ported_kmac.KMAC128(msg, key, out_32)
	end
	local took = os.clock() - start
	print(`[Int KMAC128] {Iterations}/1 iteration(s) took:`, `{Format(took)} / {Format(took / Iterations)}`)
end

do
	Work()
	
	local start = os.clock()
	for i = 1, Iterations do
		old_kmac.KMAC128(msg, key, out_32)
	end
	local took = os.clock() - start
	print(`[Old KMAC128] {Iterations}/1 iteration(s) took:`, `{Format(took)} / {Format(took / Iterations)}`)
end

do
	Work()

	local start = os.clock()
	for i = 1, Iterations do
		ported_kmac.KMAC256(msg, key, out_64)
	end
	local took = os.clock() - start
	print(`[Int KMAC256] {Iterations}/1 iteration(s) took:`, `{Format(took)} / {Format(took / Iterations)}`)
end

do
	Work()
	
	local start = os.clock()
	for i = 1, Iterations do
		old_kmac.KMAC256(msg, key, out_64)
	end
	local took = os.clock() - start
	print(`[Old KMAC256] {Iterations}/1 iteration(s) took:`, `{Format(took)} / {Format(took / Iterations)}`)
end