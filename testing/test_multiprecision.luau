--!strict
--!optimize 2

local NewMP = require("../src/Verification/EdDSA/MultiPrecision")
local OldMP = require("./algorithms/MultiPrecisionOld")

local Failures = 0
local Total = 0

local function ReadOldLimbs(Buf: buffer): {number}
	local Out = table.create(12)
	for Index = 0, 11 do
		Out[Index + 1] = buffer.readf64(Buf, Index * 8)
	end
	return Out
end

local function ReadNewLimbs(Buf: buffer): {number}
	local Out = table.create(12)
	for Index = 0, 11 do
		Out[Index + 1] = integer.tonumber(buffer.readinteger(Buf, Index * 8))
	end
	return Out
end

local function LimbsString(Limbs: {number}): string
	local Parts = {}
	for Index, Value in Limbs do
		Parts[Index] = string.format("%d", Value)
	end
	return "[" .. table.concat(Parts, ", ") .. "]"
end

local function LimbsEqual(A: {number}, B: {number}): boolean
	if #A ~= #B then return false end
	for Index, Value in A do
		if Value ~= B[Index] then return false end
	end
	return true
end

local function Check(Name: string, OldBuf: buffer, NewBuf: buffer)
	Total += 1
	local OldL = ReadOldLimbs(OldBuf)
	local NewL = ReadNewLimbs(NewBuf)
	if LimbsEqual(OldL, NewL) then
		print(`[OK]   {Name}`)
	else
		Failures += 1
		print(`[FAIL] {Name}`)
		print(`       new: {LimbsString(NewL)}`)
		print(`       old: {LimbsString(OldL)}`)
	end
end

local function CheckNumber(Name: string, OldVal: number, NewVal: number)
	Total += 1
	if OldVal == NewVal then
		print(`[OK]   {Name}`)
	else
		Failures += 1
		print(`[FAIL] {Name}: new={NewVal} old={OldVal}`)
	end
end

local function MakeBuffers(Seed: number, Carried: boolean): (buffer, buffer)
	math.randomseed(Seed)
	local OldBuf = buffer.create(96)
	local NewBuf = buffer.create(96)
	for Index = 0, 10 do
		local Value: number
		if Carried then
			Value = math.random(0, 0xFFFFFF)
		else
			Value = math.random(-0x800000, 0x7FFFFF)
		end
		buffer.writef64(OldBuf, Index * 8, Value)
		buffer.writeinteger(NewBuf, Index * 8, integer.create(Value) :: integer)
	end
	return OldBuf, NewBuf
end

local function TestUnary(Name: string, NewOp: (buffer) -> buffer, OldOp: (buffer) -> buffer, Carried: boolean?)
	for Seed = 1, 5 do
		local OldA, NewA = MakeBuffers(Seed * 11, Carried ~= false)
		Check(`{Name} seed={Seed}`, OldOp(OldA), NewOp(NewA))
	end
end

local function TestBinary(Name: string, NewOp: (buffer, buffer) -> buffer, OldOp: (buffer, buffer) -> buffer, Carried: boolean?)
	for Seed = 1, 5 do
		local OldA, NewA = MakeBuffers(Seed * 13, Carried ~= false)
		local OldB, NewB = MakeBuffers(Seed * 17 + 5, Carried ~= false)
		Check(`{Name} seed={Seed}`, OldOp(OldA, OldB), NewOp(NewA, NewB))
	end
end

print(" MultiPrecision correctness ")

TestUnary("Carry (signed limbs)", NewMP.Carry, OldMP.Carry, false)
TestUnary("Carry (carried limbs)", NewMP.Carry, OldMP.Carry, true)
TestUnary("CarryWeak (signed)", NewMP.CarryWeak, OldMP.CarryWeak, false)
TestBinary("Add", NewMP.Add, OldMP.Add)
TestBinary("Sub", NewMP.Sub, OldMP.Sub)

-- LMul / Mul require carried inputs (low 24 bits each).
TestBinary("LMul", NewMP.LMul, OldMP.LMul, true)

do
	for Seed = 1, 5 do
		local OldA, NewA = MakeBuffers(Seed * 23, true)
		local OldB, NewB = MakeBuffers(Seed * 29 + 7, true)
		local OldLow, OldHigh = OldMP.Mul(OldA, OldB)
		local NewLow, NewHigh = NewMP.Mul(NewA, NewB)
		Check(`Mul-low seed={Seed}`, OldLow, NewLow)
		Check(`Mul-high seed={Seed}`, OldHigh, NewHigh)
	end
end

TestUnary("Half (carried, even)", function(B)
	-- ensure even
	local A0 = buffer.readinteger(B, 0)
	buffer.writeinteger(B, 0, integer.band(A0, 0xFFFFFEi))
	return NewMP.Half(B)
end, function(B)
	local A0 = buffer.readf64(B, 0)
	buffer.writef64(B, 0, A0 - (A0 % 2))
	return OldMP.Half(B)
end, true)

TestUnary("Third", NewMP.Third, OldMP.Third, true)

do
	for Seed = 1, 5 do
		local OldA, NewA = MakeBuffers(Seed * 31, true)
		CheckNumber(`Mod2 seed={Seed}`, OldMP.Mod2(OldA), NewMP.Mod2(NewA))
		CheckNumber(`Mod3 seed={Seed}`, OldMP.Mod3(OldA), NewMP.Mod3(NewA))
	end
end

do
	for Seed = 1, 5 do
		local OldA, NewA = MakeBuffers(Seed * 37, true)
		local OldApprox = OldMP.Approx(OldA)
		local NewApprox = NewMP.Approx(NewA)
		Total += 1
		if math.abs(OldApprox - NewApprox) < 1e-30 * math.max(math.abs(OldApprox), 1) then
			print(`[OK]   Approx seed={Seed}`)
		else
			Failures += 1
			print(`[FAIL] Approx seed={Seed}: old={OldApprox} new={NewApprox}`)
		end
	end
end

do
	for Seed = 1, 5 do
		local OldA, NewA = MakeBuffers(Seed * 41, true)
		local OldB, NewB = MakeBuffers(Seed * 43 + 9, true)
		local OldCmp = OldMP.Cmp(OldA, OldB)
		local NewCmp = NewMP.Cmp(NewA, NewB)
		Total += 1
		if (OldCmp < 0) == (NewCmp < 0) and (OldCmp > 0) == (NewCmp > 0) then
			print(`[OK]   Cmp sign seed={Seed}`)
		else
			Failures += 1
			print(`[FAIL] Cmp sign seed={Seed}: old={OldCmp} new={NewCmp}`)
		end
	end
end

do
	for _, Value in {0, 1, 17, 0xFFFF, 0xFFFFFF} do
		Check(`Num({Value})`, OldMP.Num(Value), NewMP.Num(Value))
	end
end

print(`\n{Total - Failures}/{Total} passed, {Failures} failed.`)
