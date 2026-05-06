--!strict
--!optimize 2
--!native

local NewED = require("../src/Verification/EdDSA")
local OldED = require("./algorithms/old_eddsa")

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

local NewPK = NewED.PublicKey(SecretKey)
local OldPK = OldED.PublicKey(SecretKey)
print(`PublicKey match: {buffer.tostring(NewPK) == buffer.tostring(OldPK)}`)

local Message = buffer.fromstring(string.rep("hello", 100))
local NewSig = NewED.Sign(Message, SecretKey, NewPK)
local OldSig = OldED.Sign(Message, SecretKey, OldPK)
print(`Sign match:      {buffer.tostring(NewSig) == buffer.tostring(OldSig)}`)
print(`Cross-verify:    new sig with old verifier = {OldED.Verify(Message, OldPK, NewSig)}`)

print(`\nMessage size: {buffer.len(Message)} bytes`)

local function BenchOp(Name: string, Iterations: number, NewOp: () -> any, OldOp: () -> any)
	Work()
	local s = os.clock()
	for _ = 1, Iterations do NewOp() end
	local NewTime = os.clock() - s

	Work()
	s = os.clock()
	for _ = 1, Iterations do OldOp() end
	local OldTime = os.clock() - s

	local Speedup = OldTime / NewTime
	print(string.format("%-12s  new: %s  old: %s  speedup: %.2fx",
		Name, Format(NewTime / Iterations), Format(OldTime / Iterations), Speedup))
end

BenchOp("PublicKey", 50, function() NewED.PublicKey(SecretKey) end, function() OldED.PublicKey(SecretKey) end)
BenchOp("Sign", 50, function() NewED.Sign(Message, SecretKey, NewPK) end, function() OldED.Sign(Message, SecretKey, OldPK) end)
BenchOp("Verify", 30, function() NewED.Verify(Message, NewPK, NewSig) end, function() OldED.Verify(Message, OldPK, OldSig) end)
