--!strict
--!optimize 2
local OldB = require("./algorithms/Base64Old")
local NewB = require("./algorithms/Base64New")

local function ToHex(B: buffer): string
	local P = {}
	for I = 0, buffer.len(B) - 1 do P[I + 1] = string.format("%02x", buffer.readu8(B, I)) end
	return table.concat(P)
end

local Failures = 0
local Total = 0
math.randomseed(1)
for _, Len in {0, 1, 2, 3, 14, 15, 16, 17, 100, 1024, 10000} :: {number} do
	local In = buffer.create(Len)
	for I = 0, Len - 1 do buffer.writeu8(In, I, math.random(0, 255)) end
	local OE = OldB.Encode(In)
	local NE = NewB.Encode(In)
	Total += 1
	if ToHex(OE) ~= ToHex(NE) then
		Failures += 1
		print(`[FAIL] encode len={Len}\n  old: {ToHex(OE)}\n  new: {ToHex(NE)}`)
	else
		print(`[OK]   encode len={Len} -> {buffer.len(NE)}B`)
	end

	-- Decode roundtrip
	local OD = OldB.Decode(OE)
	local ND = NewB.Decode(NE)
	Total += 1
	if ToHex(OD) ~= ToHex(In) or ToHex(ND) ~= ToHex(In) then
		Failures += 1
		print(`[FAIL] decode len={Len}`)
	else
		print(`[OK]   decode roundtrip len={Len}`)
	end
end
print(`{Total - Failures}/{Total} passed`)
