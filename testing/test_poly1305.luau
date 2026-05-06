--!strict
--!optimize 2

local NewPoly = require("../src/Encryption/AEAD/Poly1305")
local OldPoly = require("./algorithms/Poly1305Old")

local Failures = 0
local Total = 0

local function FromHex(Hex: string): buffer
	local Buf = buffer.create(#Hex // 2)
	for Index = 0, #Hex // 2 - 1 do
		local Byte = tonumber(Hex:sub(Index * 2 + 1, Index * 2 + 2), 16) :: number
		buffer.writeu8(Buf, Index, Byte)
	end
	return Buf
end

local function ToHex(Buf: buffer): string
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
		print(`       new: {ToHex(NewBytes)}`)
		print(`       old: {ToHex(OldBytes)}`)
	end
end

local function CheckExpected(Name: string, Got: buffer, Expected: string)
	Total += 1
	local GotHex = ToHex(Got)
	if GotHex == Expected then
		print(`[OK]   {Name}`)
	else
		Failures += 1
		print(`[FAIL] {Name}`)
		print(`       got:      {GotHex}`)
		print(`       expected: {Expected}`)
	end
end

print(" Poly1305 correctness ")

-- RFC 7539 §2.5.2 test vector
do
	local Key = FromHex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
	local Message = buffer.fromstring("Cryptographic Forum Research Group")
	local Expected = "a8061dc1305136c6c22b8baf0c0127a9"
	CheckExpected("RFC 7539 vector 1 (new)", NewPoly(Message, Key), Expected)
	CheckExpected("RFC 7539 vector 1 (old)", OldPoly(Message, Key), Expected)
end

-- Cross-impl: random keys + random message lengths
for Seed = 1, 10 do
	math.randomseed(Seed)
	local Key = buffer.create(32)
	for Index = 0, 31 do buffer.writeu8(Key, Index, math.random(0, 255)) end

	local MsgLen = math.random(0, 200)
	local Message = buffer.create(MsgLen)
	for Index = 0, MsgLen - 1 do buffer.writeu8(Message, Index, math.random(0, 255)) end

	Check(`Random seed={Seed} len={MsgLen}`, NewPoly(Message, Key), OldPoly(Message, Key))
end

-- Edge cases
do
	local Key = FromHex("00000000000000000000000000000000ffffffffffffffffffffffffffffffff")
	local Empty = buffer.create(0)
	Check("Empty message", NewPoly(Empty, Key), OldPoly(Empty, Key))

	local OneByte = FromHex("ff")
	Check("One byte", NewPoly(OneByte, Key), OldPoly(OneByte, Key))

	local FifteenBytes = buffer.fromstring(string.rep("a", 15))
	Check("15 bytes (partial)", NewPoly(FifteenBytes, Key), OldPoly(FifteenBytes, Key))

	local SixteenBytes = buffer.fromstring(string.rep("a", 16))
	Check("16 bytes (one full)", NewPoly(SixteenBytes, Key), OldPoly(SixteenBytes, Key))

	local SeventeenBytes = buffer.fromstring(string.rep("a", 17))
	Check("17 bytes (full+partial)", NewPoly(SeventeenBytes, Key), OldPoly(SeventeenBytes, Key))
end

print(`\n{Total - Failures}/{Total} passed, {Failures} failed.`)
