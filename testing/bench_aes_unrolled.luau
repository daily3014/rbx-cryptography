--!strict
--!optimize 2
--!native

local Generic = require("./algorithms/AESTtableCore")
local Unrolled = (require)("./algorithms/AESTtableUnrolled") :: any

local function Format(D: number): string
	if D < 1e-9 then return string.format("%.2fps", D * 1e12) end
	if D < 1e-6 then return string.format("%.2fns", D * 1e9) end
	return string.format("%.2fus", D * 1e6)
end

local function Work() for i = 1, 1000 do for j = 1, 1000 do math.random(1, 2^30) end end end

local Key = buffer.create(32)
for i = 0, 31 do buffer.writeu8(Key, i, i + 1) end
local RKeys, _ = Generic.KeySchedule(Key)
local In = buffer.create(64); for i = 0, 63 do buffer.writeu8(In, i, i) end
local Out = buffer.create(64)

-- Sanity
do
	local Out1 = buffer.create(16)
	local Out2 = buffer.create(16)
	Generic.EncryptBlock(RKeys, 14, In, 0, Out1, 0)
	Unrolled.EncryptBlock256(RKeys, In, 0, Out2, 0)
	local M = true
	for I = 0, 15 do
		if buffer.readu8(Out1, I) ~= buffer.readu8(Out2, I) then M = false; break end
	end
	print(`Outputs match: {M}`)
end

local Iter = 200_000
do
	Work()
	local s = os.clock(); for _ = 1, Iter do Generic.EncryptBlock(RKeys, 14, In, 0, Out, 0) end
	local G = (os.clock() - s) / Iter

	Work()
	s = os.clock(); for _ = 1, Iter do Unrolled.EncryptBlock256(RKeys, In, 0, Out, 0) end
	local U = (os.clock() - s) / Iter

	print(string.format("Generic (loop):    %s/op", Format(G)))
	print(string.format("Fully unrolled:    %s/op  (%.2fx)", Format(U), G / U))
end
