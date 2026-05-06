--!strict
--!optimize 2
--!native

local AESBS = require("./algorithms/AESBitsliceCore")
local AESBSv2 = require("./algorithms/AESBitsliceCoreV2")
local AESOld = (require)("./algorithms/AESOldExposed") :: any

local function Format(D: number): string
	if D < 1e-9 then return string.format("%.2fps", D * 1e12) end
	if D < 1e-6 then return string.format("%.2fns", D * 1e9) end
	if D < 1e-3 then return string.format("%.2fus", D * 1e6) end
	return string.format("%.2fms", D * 1e3)
end

local function Work() for i = 1, 1000 do for j = 1, 1000 do math.random(1, 2^30) end end end

local Key = buffer.create(32)
for i = 0, 31 do buffer.writeu8(Key, i, i + 1) end

local OldKeyConfig = AESOld._KEY_CONFIGS[32]
local OldRoundKeys = AESOld._ExpandKeySchedule(Key, 32, buffer.create(OldKeyConfig.ExpandedLength))

local BSSkey1, BSNr1 = AESBS.KeySchedule(Key)
local BSSkey2, BSNr2 = AESBSv2.KeySchedule(Key)

local In = buffer.create(64)
for i = 0, 63 do buffer.writeu8(In, i, i) end
local Out = buffer.create(64)

-- Sanity check v2
do
	local OldOut = buffer.create(64)
	for I = 0, 3 do AESOld._EncryptBlock(OldRoundKeys, OldKeyConfig.MaterialLength, In, I * 16, OldOut, I * 16) end
	local V2Out = buffer.create(64)
	AESBSv2.EncryptBlocks4(BSSkey2, BSNr2, In, 0, V2Out, 0)
	local Match = true
	for I = 0, 63 do
		if buffer.readu8(OldOut, I) ~= buffer.readu8(V2Out, I) then Match = false; break end
	end
	print(`v2 outputs match table: {Match}`)
end

print("AES-256, 64 bytes (4 blocks)")
local function Bench(Name: string, Iter: number, Fn: () -> ()): number
	Work()
	local s = os.clock(); for _ = 1, Iter do Fn() end
	local t = (os.clock() - s) / Iter
	print(string.format("%-25s %s/op  (%s/block)", Name, Format(t), Format(t / 4)))
	return t
end

local Iter = 50_000
local Table4 = Bench("Table 4×EncryptBlock", Iter, function()
	AESOld._EncryptBlock(OldRoundKeys, OldKeyConfig.MaterialLength, In, 0, Out, 0)
	AESOld._EncryptBlock(OldRoundKeys, OldKeyConfig.MaterialLength, In, 16, Out, 16)
	AESOld._EncryptBlock(OldRoundKeys, OldKeyConfig.MaterialLength, In, 32, Out, 32)
	AESOld._EncryptBlock(OldRoundKeys, OldKeyConfig.MaterialLength, In, 48, Out, 48)
end)
local BS1 = Bench("Bitslice v1 (table Q)", Iter, function() AESBS.EncryptBlocks4(BSSkey1, BSNr1, In, 0, Out, 0) end)
local BS2 = Bench("Bitslice v2 (locals)", Iter, function() AESBSv2.EncryptBlocks4(BSSkey2, BSNr2, In, 0, Out, 0) end)

print(string.format("\nv1 vs table: %.2fx", Table4 / BS1))
print(string.format("v2 vs table: %.2fx", Table4 / BS2))
print(string.format("v2 vs v1:    %.2fx (improvement)", BS1 / BS2))
