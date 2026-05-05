local ported_sha512, ported_sha384 = require("../src/Hashing/SHA2/SHA512"), require("../src/Hashing/SHA2/SHA384")
local old_sha512, old_sha384 = require("./algorithms/SHA512old"), require("./algorithms/SHA384old")

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
		ported_sha512(msg)
	end
	local took = os.clock() - start
	print("[Int SHA512] 100/1 iteration(s) took:", `{Format(took)} / {Format(took / 100)}`)
end

do
	Work()

	local start = os.clock()
	for i = 1, 100 do
		old_sha512(msg)
	end
	local took = os.clock() - start
	print("[Old SHA512] 100/1 iteration(s) took:", `{Format(took)} / {Format(took / 100)}`)
end

do
	Work()

	local start = os.clock()
	for i = 1, 100 do
		ported_sha384(msg)
	end
	local took = os.clock() - start
	print("[Int SHA384] 100/1 iteration(s) took:", `{Format(took)} / {Format(took / 100)}`)
end

do
	Work()

	local start = os.clock()
	for i = 1, 100 do
		old_sha384(msg)
	end
	local took = os.clock() - start
	print("[Old SHA384] 100/1 iteration(s) took:", `{Format(took)} / {Format(took / 100)}`)
end