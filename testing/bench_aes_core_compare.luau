--!strict
--!optimize 2
--!native

local AESBS = require("./algorithms/AESBitsliceCore")
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

-- Build both schedules
local OldKeyConfig = AESOld._KEY_CONFIGS[32]
local OldRoundKeys = AESOld._ExpandKeySchedule(Key, 32, buffer.create(OldKeyConfig.ExpandedLength))
local OldMatLen = OldKeyConfig.MaterialLength

local BSSkey, BSNr = AESBS.KeySchedule(Key)

-- Test data
local In = buffer.create(64)
for i = 0, 63 do buffer.writeu8(In, i, i) end
local Out = buffer.create(64)

-- Sanity: results match
do
	local TableOut = buffer.create(64)
	for I = 0, 3 do AESOld._EncryptBlock(OldRoundKeys, OldMatLen, In, I * 16, TableOut, I * 16) end
	local BSOut = buffer.create(64)
	AESBS.EncryptBlocks4(BSSkey, BSNr, In, 0, BSOut, 0)
	local Match = true
	for I = 0, 63 do
		if buffer.readu8(TableOut, I) ~= buffer.readu8(BSOut, I) then Match = false; break end
	end
	print(`Outputs match: {Match}`)
end

print("\nAES-256 core: 64 bytes (4 blocks)")
do
	Work()
	local Iter = 50_000
	local s = os.clock()
	for _ = 1, Iter do
		AESOld._EncryptBlock(OldRoundKeys, OldMatLen, In, 0, Out, 0)
		AESOld._EncryptBlock(OldRoundKeys, OldMatLen, In, 16, Out, 16)
		AESOld._EncryptBlock(OldRoundKeys, OldMatLen, In, 32, Out, 32)
		AESOld._EncryptBlock(OldRoundKeys, OldMatLen, In, 48, Out, 48)
	end
	local TableTime = os.clock() - s
	print(string.format("Table-based: 4×EncryptBlock: %s/op (%s/block)",
		Format(TableTime / Iter), Format(TableTime / Iter / 4)))

	Work()
	s = os.clock()
	for _ = 1, Iter do AESBS.EncryptBlocks4(BSSkey, BSNr, In, 0, Out, 0) end
	local BSTime = os.clock() - s
	print(string.format("Bitsliced  : 1×EncryptBlocks4: %s/op (%s/block)",
		Format(BSTime / Iter), Format(BSTime / Iter / 4)))

	print(string.format("\n  ratio: bitsliced is %.2fx %s than 4×table",
		math.abs(BSTime / TableTime - 1) + 1, BSTime < TableTime and "FASTER" or "SLOWER"))
end

print("\n Single block (1 invocation) ")
do
	Work()
	local Iter = 200_000
	local s = os.clock()
	for _ = 1, Iter do AESOld._EncryptBlock(OldRoundKeys, OldMatLen, In, 0, Out, 0) end
	print(string.format("Table-based EncryptBlock: %s/op", Format((os.clock() - s) / Iter)))
end
