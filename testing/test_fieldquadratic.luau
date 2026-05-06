--!strict
--!optimize 2

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

local function CheckBool(Name: string, NewVal: boolean, OldVal: boolean)
	Total += 1
	if NewVal == OldVal then
		print(`[OK]   {Name} ({NewVal})`)
	else
		Failures += 1
		print(`[FAIL] {Name}: new={NewVal} old={OldVal}`)
	end
end

local function RandBytes(Seed: number, ClearTopBit: boolean?): buffer
	local Buf = buffer.create(32)
	math.randomseed(Seed)
	for Index = 0, 31 do
		buffer.writeu8(Buf, Index, math.random(0, 255))
	end
	if ClearTopBit then
		buffer.writeu8(Buf, 31, bit32.band(buffer.readu8(Buf, 31), 0x0F))
	end
	return Buf
end

print(" FieldQuadratic correctness ")

-- Decode -> Encode round-trip should match
for Seed = 1, 5 do
	local Bytes = RandBytes(Seed, true)
	local NewS = NewFQ.Decode(Bytes)
	local OldS = OldFQ.Decode(Bytes)
	Check(`Decode/Encode seed={Seed}`, NewFQ.Encode(NewS), OldFQ.Encode(OldS))
end

-- Add
for Seed = 1, 5 do
	local A = RandBytes(Seed * 7, true)
	local B = RandBytes(Seed * 11 + 1, true)
	Check(`Add seed={Seed}`,
		NewFQ.Encode(NewFQ.Add(NewFQ.Decode(A), NewFQ.Decode(B))),
		OldFQ.Encode(OldFQ.Add(OldFQ.Decode(A), OldFQ.Decode(B))))
end

-- Sub
for Seed = 1, 5 do
	local A = RandBytes(Seed * 13, true)
	local B = RandBytes(Seed * 17 + 1, true)
	Check(`Sub seed={Seed}`,
		NewFQ.Encode(NewFQ.Sub(NewFQ.Decode(A), NewFQ.Decode(B))),
		OldFQ.Encode(OldFQ.Sub(OldFQ.Decode(A), OldFQ.Decode(B))))
end

-- Neg
for Seed = 1, 5 do
	local Bytes = RandBytes(Seed * 19, true)
	Check(`Neg seed={Seed}`,
		NewFQ.Encode(NewFQ.Neg(NewFQ.Decode(Bytes))),
		OldFQ.Encode(OldFQ.Neg(OldFQ.Decode(Bytes))))
end

-- Mul
for Seed = 1, 5 do
	local A = RandBytes(Seed * 23, true)
	local B = RandBytes(Seed * 29 + 1, true)
	Check(`Mul seed={Seed}`,
		NewFQ.Encode(NewFQ.Mul(NewFQ.Decode(A), NewFQ.Decode(B))),
		OldFQ.Encode(OldFQ.Mul(OldFQ.Decode(A), OldFQ.Decode(B))))
end

-- Eighth
for Seed = 1, 5 do
	local Bytes = RandBytes(Seed * 31, true)
	Check(`Eighth seed={Seed}`,
		NewFQ.Encode(NewFQ.Eighth(NewFQ.Decode(Bytes))),
		OldFQ.Encode(OldFQ.Eighth(OldFQ.Decode(Bytes))))
end

-- DecodeClamped (32-byte secret-key style input)
for Seed = 1, 5 do
	local Bytes = RandBytes(Seed * 37)
	Check(`DecodeClamped seed={Seed}`,
		NewFQ.Encode(NewFQ.DecodeClamped(Bytes)),
		OldFQ.Encode(OldFQ.DecodeClamped(Bytes)))
end

-- DecodeWide (64-byte input)
for Seed = 1, 5 do
	local Wide = buffer.create(64)
	math.randomseed(Seed * 41)
	for Index = 0, 63 do buffer.writeu8(Wide, Index, math.random(0, 255)) end
	Check(`DecodeWide seed={Seed}`,
		NewFQ.Encode(NewFQ.DecodeWide(Wide)),
		OldFQ.Encode(OldFQ.DecodeWide(Wide)))
end

-- IsValidScalar
do
	local OrderBytes = buffer.create(32)
	for Index = 0, 31 do buffer.writeu8(OrderBytes, Index, 0) end
	-- value 0 is valid
	CheckBool("IsValidScalar(0)", NewFQ.IsValidScalar(OrderBytes), OldFQ.IsValidScalar(OrderBytes))
	-- max 32-byte value (definitely > L) → invalid
	for Index = 0, 31 do buffer.writeu8(OrderBytes, Index, 0xFF) end
	CheckBool("IsValidScalar(0xFF...)", NewFQ.IsValidScalar(OrderBytes), OldFQ.IsValidScalar(OrderBytes))
	-- random
	for Seed = 1, 5 do
		local Bytes = RandBytes(Seed * 43)
		CheckBool(`IsValidScalar seed={Seed}`, NewFQ.IsValidScalar(Bytes), OldFQ.IsValidScalar(Bytes))
	end
end

-- Bits (compare bit sequence)
for Seed = 1, 5 do
	local Bytes = RandBytes(Seed * 47, true)
	local NewBits, NewCount = NewFQ.Bits(NewFQ.Decode(Bytes))
	local OldBits, OldCount = OldFQ.Bits(OldFQ.Decode(Bytes))
	Total += 1
	if NewCount ~= OldCount then
		Failures += 1
		print(`[FAIL] Bits count seed={Seed}: new={NewCount} old={OldCount}`)
	else
		local AllMatch = true
		for Index = 0, NewCount - 1 do
			local NewBit = buffer.readu8(NewBits, Index)
			local OldBit = math.floor(buffer.readf64(OldBits, Index * 8))
			if NewBit ~= OldBit then
				AllMatch = false
				break
			end
		end
		if AllMatch then
			print(`[OK]   Bits seed={Seed} ({NewCount} bits)`)
		else
			Failures += 1
			print(`[FAIL] Bits seed={Seed} (count match but values differ)`)
		end
	end
end

-- MakeRuleset
for Seed = 1, 3 do
	local A = RandBytes(Seed * 53, true)
	local B = RandBytes(Seed * 59 + 1, true)
	local NewBits, NewBitCount, NewRules, NewRuleCount = NewFQ.MakeRuleset(NewFQ.Decode(A), NewFQ.Decode(B))
	local OldBits, OldBitCount, OldRules, OldRuleCount = OldFQ.MakeRuleset(OldFQ.Decode(A), OldFQ.Decode(B))

	Total += 1
	local Pass = NewBitCount == OldBitCount and NewRuleCount == OldRuleCount
	if Pass then
		for Index = 0, NewBitCount - 1 do
			if buffer.readu8(NewBits, Index) ~= math.floor(buffer.readf64(OldBits, Index * 8)) then
				Pass = false
				break
			end
		end
		for Index = 0, NewRuleCount - 1 do
			if buffer.readu8(NewRules, Index) ~= math.floor(buffer.readf64(OldRules, Index * 8)) then
				Pass = false
				break
			end
		end
	end

	if Pass then
		print(`[OK]   MakeRuleset seed={Seed} ({NewBitCount} bits, {NewRuleCount} rules)`)
	else
		Failures += 1
		print(`[FAIL] MakeRuleset seed={Seed}: bitcount new={NewBitCount} old={OldBitCount}, rulecount new={NewRuleCount} old={OldRuleCount}`)
	end
end

print(`\n{Total - Failures}/{Total} passed, {Failures} failed.`)
