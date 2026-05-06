--!strict
--!optimize 2

local NewE = require("../src/Verification/EdDSA/Edwards25519")
local OldE = require("./algorithms/Edwards25519Old")
local NewFQ = require("../src/Verification/EdDSA/FieldQuadratic")
local OldFQ = require("./algorithms/FieldQuadraticOld")

local Failures = 0
local Total = 0

local function Hex(Buf: buffer): string
	local Parts = {}
	for Index = 0, buffer.len(Buf) - 1 do
		Parts[Index + 1] = string.format("%02x", buffer.readu8(Buf, Index))
	end
	return table.concat(Parts)
end

local function BuffersEqual(A: buffer, B: buffer): boolean
	if buffer.len(A) ~= buffer.len(B) then return false end
	for Index = 0, buffer.len(A) - 1 do
		if buffer.readu8(A, Index) ~= buffer.readu8(B, Index) then return false end
	end
	return true
end

local function Check(Name: string, NewBytes: buffer, OldBytes: buffer)
	Total += 1
	if BuffersEqual(NewBytes, OldBytes) then
		print(`[OK]   {Name}`)
	else
		Failures += 1
		print(`[FAIL] {Name}`)
		print(`       new: {Hex(NewBytes)}`)
		print(`       old: {Hex(OldBytes)}`)
	end
end

-- Generate a 32-byte point that's likely to decode (valid Y)
local function ValidPointBytes(Seed: number): buffer
	-- Just use the encoded basepoint multiplied by Seed scalar
	local Buf = buffer.create(32)
	math.randomseed(Seed)
	for Index = 0, 31 do
		buffer.writeu8(Buf, Index, math.random(0, 255))
	end
	return Buf
end

local function ScalarBytes(Seed: number): buffer
	local Buf = buffer.create(32)
	math.randomseed(Seed)
	for Index = 0, 31 do
		buffer.writeu8(Buf, Index, math.random(0, 255))
	end
	-- Clear top bits to make it < 2^252 (valid scalar range)
	buffer.writeu8(Buf, 31, bit32.band(buffer.readu8(Buf, 31), 0x0F))
	return Buf
end

print(" Edwards25519 correctness ")

-- Decode -> Encode round-trip on the basepoint and a few hand-picked y values
do
	local BasepointBytes = buffer.create(32)
	-- Standard basepoint: y = 4/5 mod p, encoded as 0x5866...66
	buffer.writeu8(BasepointBytes, 0, 0x58)
	for Index = 1, 31 do buffer.writeu8(BasepointBytes, Index, 0x66) end
	local NewP = NewE.Decode(BasepointBytes)
	local OldP = OldE.Decode(BasepointBytes)
	Total += 1
	if NewP == nil or OldP == nil then
		Failures += 1
		print(`[FAIL] basepoint decode (new={NewP ~= nil}, old={OldP ~= nil})`)
	else
		Check("basepoint Decode->Encode", NewE.Encode(NewP :: buffer), OldE.Encode(OldP :: buffer))
	end
end

-- MulG: multiply basepoint by random scalar; compare encoded result.
for Seed = 1, 5 do
	local Bytes = ScalarBytes(Seed)
	local NewS = NewFQ.Decode(Bytes)
	local OldS = OldFQ.Decode(Bytes)
	local NewBits, NewCount = NewFQ.Bits(NewS)
	local OldBits, OldCount = OldFQ.Bits(OldS)

	local NewResult = NewE.MulG(NewBits, NewCount)
	local OldResult = OldE.MulG(OldBits, OldCount)

	Check(`MulG seed={Seed}`, NewE.Encode(NewResult), OldE.Encode(OldResult))
end

-- Mul: arbitrary point, scalar mul; compare encoded result.
do
	local BasepointBytes = buffer.create(32)
	buffer.writeu8(BasepointBytes, 0, 0x58)
	for Index = 1, 31 do buffer.writeu8(BasepointBytes, Index, 0x66) end

	for Seed = 1, 3 do
		local NewP = NewE.Decode(BasepointBytes)
		local OldP = OldE.Decode(BasepointBytes)
		if NewP and OldP then
			local Scalar = ScalarBytes(Seed * 11 + 3)
			local NewS = NewFQ.Decode(Scalar)
			local OldS = OldFQ.Decode(Scalar)
			local NewBits, NewCount = NewFQ.Bits(NewS)
			local OldBits, OldCount = OldFQ.Bits(OldS)

			local NewResult = NewE.Mul(NewP :: buffer, NewBits, NewCount)
			local OldResult = OldE.Mul(OldP :: buffer, OldBits, OldCount)

			Check(`Mul seed={Seed}`, NewE.Encode(NewResult), OldE.Encode(OldResult))
		end
	end
end

-- Double on the basepoint
do
	local BasepointBytes = buffer.create(32)
	buffer.writeu8(BasepointBytes, 0, 0x58)
	for Index = 1, 31 do buffer.writeu8(BasepointBytes, Index, 0x66) end
	local NewP = NewE.Decode(BasepointBytes)
	local OldP = OldE.Decode(BasepointBytes)
	if NewP and OldP then
		Check("Double(basepoint)",
			NewE.Encode(NewE.Double(NewP :: buffer)),
			OldE.Encode(OldE.Double(OldP :: buffer)))
	end
end

-- Add: basepoint + Niels(basepoint) = 2*basepoint, compare to Double
do
	local BasepointBytes = buffer.create(32)
	buffer.writeu8(BasepointBytes, 0, 0x58)
	for Index = 1, 31 do buffer.writeu8(BasepointBytes, Index, 0x66) end
	local NewP = NewE.Decode(BasepointBytes)
	local OldP = OldE.Decode(BasepointBytes)
	if NewP and OldP then
		local NewN = NewE.Niels(NewP :: buffer)
		local OldN = OldE.Niels(OldP :: buffer)
		Check("Add(basepoint, Niels(basepoint))",
			NewE.Encode(NewE.Add(NewP :: buffer, NewN)),
			OldE.Encode(OldE.Add(OldP :: buffer, OldN)))
	end
end

print(`\n{Total - Failures}/{Total} passed, {Failures} failed.`)
