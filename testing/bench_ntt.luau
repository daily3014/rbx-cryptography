--!strict
--!optimize 2
--!native

local Old = require("./algorithms/MlDSANTTOld")
local New = require("./algorithms/MlDSANTTNew")

local function Format(D: number): string
	if D < 1e-9 then return string.format("%.2fps", D * 1e12) end
	if D < 1e-6 then return string.format("%.2fns", D * 1e9) end
	return string.format("%.2fus", D * 1e6)
end
local function Work() for i=1,1000 do for j=1,1000 do math.random(1,2^30) end end end

-- Make a poly buffer with random coefficients in [0, Q)
local Q = 8380417
local function MakePoly(): buffer
	local P = buffer.create(256 * 4)
	for I = 0, 255 do buffer.writeu32(P, I*4, math.random(0, Q - 1)) end
	return P
end

-- Sanity: Old and New produce same NTT
do
	math.randomseed(1)
	local PolyA = MakePoly()
	local PolyB = buffer.create(256 * 4)
	buffer.copy(PolyB, 0, PolyA, 0, 256 * 4)
	Old.ForwardNTT(PolyA)
	New.ForwardNTT(PolyB)
	local Match = true
	for I = 0, 255 do
		if buffer.readu32(PolyA, I*4) ~= buffer.readu32(PolyB, I*4) then
			Match = false
			print(`mismatch at {I}: old={buffer.readu32(PolyA, I*4)}, new={buffer.readu32(PolyB, I*4)}`)
			break
		end
	end
	print(`ForwardNTT outputs match: {Match}`)
end

-- Bench
do
	math.randomseed(1)
	local Polys = {}
	for I = 1, 100 do Polys[I] = MakePoly() end
	-- Need to reset polys per iter since NTT mutates in place. Make backups.
	local Backups = {}
	for I = 1, 100 do
		Backups[I] = buffer.create(256 * 4)
		buffer.copy(Backups[I], 0, Polys[I], 0, 256 * 4)
	end

	Work()
	local Iter = 1000
	local s = os.clock()
	for _ = 1, Iter do
		for I = 1, 100 do
			buffer.copy(Polys[I], 0, Backups[I], 0, 256 * 4)
			Old.ForwardNTT(Polys[I])
		end
	end
	local OldTime = (os.clock() - s) / Iter / 100
	print(string.format("Old ForwardNTT: %s/op", Format(OldTime)))

	Work()
	s = os.clock()
	for _ = 1, Iter do
		for I = 1, 100 do
			buffer.copy(Polys[I], 0, Backups[I], 0, 256 * 4)
			New.ForwardNTT(Polys[I])
		end
	end
	local NewTime = (os.clock() - s) / Iter / 100
	print(string.format("New ForwardNTT: %s/op  (%.2fx)", Format(NewTime), OldTime / NewTime))
end
