local ported_sha3 = require("../src/Hashing/SHA3")
local old_sha3 = require("./algorithms/SHA3old")

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
local Iterations = 1000

do
	Work()

	local start = os.clock()
	for i = 1, Iterations do
		ported_sha3.SHA3_512(msg)
	end
	local took = os.clock() - start
	print(`[Int SHA3] {Iterations}/1 iteration(s) took:`, `{Format(took)} / {Format(took / Iterations)}`)
end

do
	Work()
	
	local start = os.clock()
	for i = 1, Iterations do
		old_sha3.SHA3_512(msg)
	end
	local took = os.clock() - start
	print(`[Old SHA3] {Iterations}/1 iteration(s) took:`, `{Format(took)} / {Format(took / Iterations)}`)
end