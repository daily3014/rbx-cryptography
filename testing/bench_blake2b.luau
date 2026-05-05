local ported_blake2b = require("../src/Hashing/Blake2b")
local old_blake2b = require("./algorithms/Blake2bold")

local msg = buffer.fromstring(string.rep("A", 20_000))

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

do
	Work()

	local start = os.clock()
	for i = 1, 100 do
		ported_blake2b(msg)
	end
	local took = os.clock() - start
	print("[Int Blake2b] 100/1 iteration(s) took:", `{Format(took)} / {Format(took / 100)}`)
end

do
	Work()
	
	local start = os.clock()
	for i = 1, 100 do
		old_blake2b(msg)
	end
	local took = os.clock() - start
	print("[Old Blake2b] 100/1 iteration(s) took:", `{Format(took)} / {Format(took / 100)}`)
end