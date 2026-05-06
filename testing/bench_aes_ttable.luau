--!strict
--!optimize 2
--!native

local AESTT = require("./algorithms/AESTtableCore")
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

local OldCfg = AESOld._KEY_CONFIGS[32]
local OldRoundKeys = AESOld._ExpandKeySchedule(Key, 32, buffer.create(OldCfg.ExpandedLength))

local TTRoundKeys, TTNr = AESTT.KeySchedule(Key)

local In = buffer.create(64)
for i = 0, 63 do buffer.writeu8(In, i, i) end
local Out = buffer.create(64)

-- Sanity: T-table matches Hyper-S-Box on 4 blocks
do
	local OldOut = buffer.create(64)
	for I = 0, 3 do AESOld._EncryptBlock(OldRoundKeys, OldCfg.MaterialLength, In, I * 16, OldOut, I * 16) end
	local TTOut = buffer.create(64)
	for I = 0, 3 do AESTT.EncryptBlock(TTRoundKeys, TTNr, In, I * 16, TTOut, I * 16) end
	local Match = true
	for I = 0, 63 do
		if buffer.readu8(OldOut, I) ~= buffer.readu8(TTOut, I) then Match = false; break end
	end
	print(`T-table outputs match Hyper-S-Box: {Match}`)
end

print("\n AES-256 single block ")
local Iter = 200_000
do
	Work()
	local s = os.clock(); for _ = 1, Iter do AESOld._EncryptBlock(OldRoundKeys, OldCfg.MaterialLength, In, 0, Out, 0) end
	local Hs = (os.clock() - s) / Iter
	print(string.format("Hyper-S-Box: %s/op", Format(Hs)))

	Work()
	s = os.clock(); for _ = 1, Iter do AESTT.EncryptBlock(TTRoundKeys, TTNr, In, 0, Out, 0) end
	local Tt = (os.clock() - s) / Iter
	print(string.format("T-table:     %s/op  (%.2fx %s)", Format(Tt), math.abs(Hs / Tt - 1) + 1, Tt < Hs and "FASTER" or "slower"))
end

print("\n AES-128 single block ")
local Key128 = buffer.create(16)
for i = 0, 15 do buffer.writeu8(Key128, i, i + 1) end
local OldCfg128 = AESOld._KEY_CONFIGS[16]
local OldRK128 = AESOld._ExpandKeySchedule(Key128, 16, buffer.create(OldCfg128.ExpandedLength))
local TTRK128, TTNr128 = AESTT.KeySchedule(Key128)
do
	Work()
	local s = os.clock(); for _ = 1, Iter do AESOld._EncryptBlock(OldRK128, OldCfg128.MaterialLength, In, 0, Out, 0) end
	local Hs = (os.clock() - s) / Iter
	print(string.format("Hyper-S-Box: %s/op", Format(Hs)))

	Work()
	s = os.clock(); for _ = 1, Iter do AESTT.EncryptBlock(TTRK128, TTNr128, In, 0, Out, 0) end
	local Tt = (os.clock() - s) / Iter
	print(string.format("T-table:     %s/op  (%.2fx %s)", Format(Tt), math.abs(Hs / Tt - 1) + 1, Tt < Hs and "FASTER" or "slower"))
end
