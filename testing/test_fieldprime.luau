--!strict
--!optimize 2

local NewFP = require("../src/Verification/EdDSA/FieldPrime")
local OldFP = require("./algorithms/FieldPrimeOld")

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
	if buffer.len(A) ~= buffer.len(B) then
		return false
	end
	for Index = 0, buffer.len(A) - 1 do
		if buffer.readu8(A, Index) ~= buffer.readu8(B, Index) then
			return false
		end
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

local function RandBytes(Seed: number): buffer
	local Buf = buffer.create(32)
	math.randomseed(Seed)
	for Index = 0, 31 do
		buffer.writeu8(Buf, Index, math.random(0, 255))
	end
	buffer.writeu8(Buf, 31, bit32.band(buffer.readu8(Buf, 31), 0x7F))
	return Buf
end

local function TestRoundtrip()
	for Seed = 1, 5 do
		local Bytes = RandBytes(Seed)
		local NewElem = NewFP.Decode(Bytes)
		local OldElem = OldFP.Decode(Bytes)
		Check(`Roundtrip seed={Seed}`, NewFP.Encode(NewElem), OldFP.Encode(OldElem))
	end
end

local function TestUnary(Name: string, NewOp: (buffer) -> buffer, OldOp: (buffer) -> buffer)
	for Seed = 1, 5 do
		local Bytes = RandBytes(Seed)
		local NewResult = NewFP.Encode(NewOp(NewFP.Decode(Bytes)))
		local OldResult = OldFP.Encode(OldOp(OldFP.Decode(Bytes)))
		Check(`{Name} seed={Seed}`, NewResult, OldResult)
	end
end

local function TestBinary(Name: string, NewOp: (buffer, buffer) -> buffer, OldOp: (buffer, buffer) -> buffer)
	for Seed = 1, 5 do
		local A = RandBytes(Seed * 7)
		local B = RandBytes(Seed * 13 + 1)
		local NewResult = NewFP.Encode(NewOp(NewFP.Decode(A), NewFP.Decode(B)))
		local OldResult = OldFP.Encode(OldOp(OldFP.Decode(A), OldFP.Decode(B)))
		Check(`{Name} seed={Seed}`, NewResult, OldResult)
	end
end

local function TestEq()
	Total += 1
	local Bytes = RandBytes(42)
	local NewA = NewFP.Decode(Bytes)
	local NewB = NewFP.Decode(Bytes)
	local NewC = NewFP.Decode(RandBytes(43))
	if NewFP.Eq(NewA, NewB) and not NewFP.Eq(NewA, NewC) then
		print("[OK]   Eq sanity")
	else
		Failures += 1
		print("[FAIL] Eq sanity")
	end

	Total += 1
	local Zero = NewFP.Num(0)
	if NewFP.Eqz(Zero) then
		print("[OK]   Eqz(0)")
	else
		Failures += 1
		print("[FAIL] Eqz(0)")
	end

	Total += 1
	if not NewFP.Eqz(NewFP.Num(7)) then
		print("[OK]   not Eqz(7)")
	else
		Failures += 1
		print("[FAIL] not Eqz(7)")
	end
end

print(" FieldPrime correctness ")

TestRoundtrip()
TestUnary("Neg", NewFP.Neg, OldFP.Neg)
TestBinary("Add", NewFP.Add, OldFP.Add)
TestBinary("Sub", NewFP.Sub, OldFP.Sub)
TestBinary("Mul", NewFP.Mul, OldFP.Mul)
TestUnary("Square", NewFP.Square, OldFP.Square)
TestUnary("KMul*7", function(E) return NewFP.KMul(E, 7) end, function(E) return OldFP.KMul(E, 7) end)
TestUnary("Invert", NewFP.Invert, OldFP.Invert)

local function TestSqrtDiv()
	for Seed = 1, 10 do
		Total += 1
		local U = RandBytes(Seed * 11)
		local V = RandBytes(Seed * 17 + 3)
		local NewU, NewV = NewFP.Decode(U), NewFP.Decode(V)
		local OldU, OldV = OldFP.Decode(U), OldFP.Decode(V)
		local NewR = NewFP.SqrtDiv(NewU, NewV)
		local OldR = OldFP.SqrtDiv(OldU, OldV)
		if (NewR == nil) ~= (OldR == nil) then
			Failures += 1
			print(`[FAIL] SqrtDiv nil-status seed={Seed} (new nil={NewR == nil}, old nil={OldR == nil})`)
		elseif NewR == nil then
			print(`[OK]   SqrtDiv seed={Seed} (both nil)`)
		else
			local NewBytes = NewFP.Encode(NewR :: buffer)
			local OldBytes = OldFP.Encode(OldR :: buffer)
			if BuffersEqual(NewBytes, OldBytes) then
				print(`[OK]   SqrtDiv seed={Seed}`)
			else
				Failures += 1
				print(`[FAIL] SqrtDiv seed={Seed}`)
				print(`       new: {Hex(NewBytes)}`)
				print(`       old: {Hex(OldBytes)}`)
			end
		end
	end
end

TestSqrtDiv()
TestEq()

print(`\n{Total - Failures}/{Total} passed, {Failures} failed.`)
