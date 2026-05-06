--!strict
--!optimize 2
--!native

local NewED = require("../src/Verification/EdDSA")

local function Format(Difference: number): string
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

local SecretKey = buffer.create(32)
for i = 0, 31 do buffer.writeu8(SecretKey, i, i + 1) end

local PublicKey = NewED.PublicKey(SecretKey)
local Message = buffer.fromstring(string.rep("hello", 100))
local Signature = NewED.Sign(Message, SecretKey, PublicKey)

print(`Message size: {buffer.len(Message)} bytes`)

do
	Work()
	local Iterations = 100
	local start = os.clock()
	for _ = 1, Iterations do
		NewED.PublicKey(SecretKey)
	end
	local took = os.clock() - start
	print(`PublicKey: {Iterations} ops in {Format(took)} = {Format(took / Iterations)}/op`)
end

do
	Work()
	local Iterations = 100
	local start = os.clock()
	for _ = 1, Iterations do
		NewED.Sign(Message, SecretKey, PublicKey)
	end
	local took = os.clock() - start
	print(`Sign:      {Iterations} ops in {Format(took)} = {Format(took / Iterations)}/op`)
end

do
	Work()
	local Iterations = 50
	local start = os.clock()
	for _ = 1, Iterations do
		NewED.Verify(Message, PublicKey, Signature)
	end
	local took = os.clock() - start
	print(`Verify:    {Iterations} ops in {Format(took)} = {Format(took / Iterations)}/op`)
end
