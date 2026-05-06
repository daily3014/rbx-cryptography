--!strict
local CSPRNG = require("../src/Utilities/CSPRNG")

local Failures = 0
local Total = 0
local function Check(Name: string, Pass: boolean, Detail: string?)
	Total += 1
	if Pass then print(`[OK]   {Name}`) else
		Failures += 1; print(`[FAIL] {Name}` .. (Detail and `: {Detail}` or ""))
	end
end

-- Random returns float in [0,1)
do
	local R = CSPRNG.Random()
	Check("Random in [0,1)", R >= 0 and R < 1, `got {R}`)
end

-- RandomBytes produces requested length
for _, N in {1, 16, 64, 1024, 8192} :: {number} do
	local B = CSPRNG.RandomBytes(N)
	Check(`RandomBytes({N}) length`, buffer.len(B) == N, `got {buffer.len(B)}`)
end

-- Bytes look random (not all zeros, not all same)
do
	local B = CSPRNG.RandomBytes(256)
	local AllZero = true
	local AllSame = true
	local First = buffer.readu8(B, 0)
	for I = 0, 255 do
		local V = buffer.readu8(B, I)
		if V ~= 0 then AllZero = false end
		if V ~= First then AllSame = false end
	end
	Check("RandomBytes not all zero", not AllZero)
	Check("RandomBytes not all same", not AllSame)
end

-- Two consecutive calls should differ
do
	local B1 = CSPRNG.RandomBytes(64)
	local B2 = CSPRNG.RandomBytes(64)
	local Same = true
	for I = 0, 63 do
		if buffer.readu8(B1, I) ~= buffer.readu8(B2, I) then Same = false; break end
	end
	Check("Consecutive calls differ", not Same)
end

-- RandomInt range
do
	local Mn, Mx = math.huge, -math.huge
	for _ = 1, 1000 do
		local V = CSPRNG.RandomInt(10, 20)
		if V < Mn then Mn = V end
		if V > Mx then Mx = V end
		if V < 10 or V > 20 then Check(`RandomInt out of range`, false, `got {V}`); break end
	end
	Check(`RandomInt(10,20) hit range`, Mn == 10 and Mx == 20, `range [{Mn}, {Mx}]`)
end

-- Reseed works
do
	local Ok = pcall(function() CSPRNG.Reseed() end)
	Check("Reseed succeeds", Ok)
end

-- Ed25519Random
do
	local B = CSPRNG.Ed25519Random()
	Check("Ed25519Random size", buffer.len(B) == 32)
	-- Clamping: top byte should have bit 7 cleared, bit 6 set; bottom byte bits 0-2 cleared
	local Last = buffer.readu8(B, 31)
	local First = buffer.readu8(B, 0)
	Check("Ed25519Random clamping (top)", bit32.band(Last, 0x80) == 0 and bit32.band(Last, 0x40) ~= 0, `last byte {Last}`)
	Check("Ed25519Random clamping (bot)", bit32.band(First, 0x07) == 0, `first byte {First}`)
end

print(`\n{Total - Failures}/{Total} passed`)
