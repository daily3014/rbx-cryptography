--!strict
--!optimize 2
--!native

local ChaCha20 = require("../src/Utilities/CSPRNG/ChaCha20")
local Blake3 = require("../src/Utilities/CSPRNG/Blake3")

local function Format(D: number): string
	if D < 1e-9 then return string.format("%.2fps", D * 1e12) end
	if D < 1e-6 then return string.format("%.2fns", D * 1e9) end
	return string.format("%.2fus", D * 1e6)
end
local function Work() for i=1,1000 do for j=1,1000 do math.random(1,2^30) end end end

local KEY_SIZE = 32
local NONCE_SIZE = 12
local BLOCK_SIZE = 64
local SIZE_TARGET = 2048

local Key = buffer.create(KEY_SIZE)
for i = 0, 31 do buffer.writeu8(Key, i, i + 1) end
local Nonce = buffer.create(NONCE_SIZE)
for i = 0, 11 do buffer.writeu8(Nonce, i, i + 100) end
local InputZeros = buffer.create(BLOCK_SIZE)

print("CSPRNG block-generation strategies (output: 2048 bytes)")

do
	-- Current: ChaCha20(zeros, key, nonce, counter) -> Blake3 expansion
	Work()
	local Iter = 5000
	local Counter = 0
	local s = os.clock()
	for _ = 1, Iter do
		local ChaChaOut = ChaCha20(InputZeros, Key, Nonce, Counter, 20)
		local Buf = Blake3(ChaChaOut, SIZE_TARGET)
		Counter += 1
		if buffer.len(Buf) ~= SIZE_TARGET then error("size mismatch") end
	end
	print(string.format("ChaCha20 + Blake3 expansion: %s/op", Format((os.clock() - s) / Iter)))
end

do
	-- New: Blake3(key || nonce || counter, 2048)
	Work()
	local Iter = 5000
	local Counter = 0
	local Input = buffer.create(KEY_SIZE + NONCE_SIZE + 8)
	buffer.copy(Input, 0, Key, 0, KEY_SIZE)
	buffer.copy(Input, KEY_SIZE, Nonce, 0, NONCE_SIZE)
	local s = os.clock()
	for _ = 1, Iter do
		buffer.writeu32(Input, KEY_SIZE + NONCE_SIZE, Counter)
		buffer.writeu32(Input, KEY_SIZE + NONCE_SIZE + 4, 0)
		local Buf = Blake3(Input, SIZE_TARGET)
		Counter += 1
		if buffer.len(Buf) ~= SIZE_TARGET then error("size mismatch") end
	end
	print(string.format("Blake3 XOF only:             %s/op", Format((os.clock() - s) / Iter)))
end

do
	-- ChaCha20 alone (no expansion - 64 bytes)
	Work()
	local Iter = 50000
	local Counter = 0
	local s = os.clock()
	for _ = 1, Iter do
		local Out = ChaCha20(InputZeros, Key, Nonce, Counter, 20)
		Counter += 1
		if buffer.len(Out) ~= 64 then error("size mismatch") end
	end
	print(string.format("\nChaCha20 alone (64 bytes):   %s/op", Format((os.clock() - s) / Iter)))
end

do
	-- Blake3 alone for 64 bytes
	Work()
	local Iter = 50000
	local Counter = 0
	local Input = buffer.create(KEY_SIZE + NONCE_SIZE + 8)
	buffer.copy(Input, 0, Key, 0, KEY_SIZE)
	buffer.copy(Input, KEY_SIZE, Nonce, 0, NONCE_SIZE)
	local s = os.clock()
	for _ = 1, Iter do
		buffer.writeu32(Input, KEY_SIZE + NONCE_SIZE, Counter)
		buffer.writeu32(Input, KEY_SIZE + NONCE_SIZE + 4, 0)
		local Out = Blake3(Input, 64)
		Counter += 1
		if buffer.len(Out) ~= 64 then error("size mismatch") end
	end
	print(string.format("Blake3 alone (64 bytes):     %s/op", Format((os.clock() - s) / Iter)))
end
