--!strict
local NewAES = require("../src/Encryption/AES")
local OldAES = require("./algorithms/AESOld")

local function FromHex(Hex: string): buffer
	local Buf = buffer.create(#Hex // 2)
	for I = 0, #Hex // 2 - 1 do
		buffer.writeu8(Buf, I, tonumber(Hex:sub(I * 2 + 1, I * 2 + 2), 16) :: number)
	end
	return Buf
end

local function ToHex(Buf: buffer): string
	local P = {}
	for I = 0, buffer.len(Buf) - 1 do P[I + 1] = string.format("%02x", buffer.readu8(Buf, I)) end
	return table.concat(P)
end

local Failures = 0
local Total = 0

local function Check(Name: string, Got: string, Expected: string)
	Total += 1
	if Got == Expected then
		print(`[OK]   {Name}`)
	else
		Failures += 1
		print(`[FAIL] {Name}\n       got: {Got}\n       exp: {Expected}`)
	end
end

-- Cross-check NewAES vs OldAES on random inputs
math.randomseed(42)
for _, KeyLen in {16, 24, 32} :: {number} do
	for _, MsgLen in {0, 1, 15, 16, 17, 31, 32, 100, 1024} :: {number} do
		local Key = buffer.create(KeyLen)
		for I = 0, KeyLen - 1 do buffer.writeu8(Key, I, math.random(0, 255)) end
		local IV = buffer.create(12)
		for I = 0, 11 do buffer.writeu8(IV, I, math.random(0, 255)) end
		local Msg = buffer.create(MsgLen)
		for I = 0, MsgLen - 1 do buffer.writeu8(Msg, I, math.random(0, 255)) end
		local AAD = buffer.fromstring("test-aad")

		local NCt, NTag = NewAES.Encrypt(Msg, Key, IV, AAD)
		local OCt, OTag = OldAES.Encrypt(Msg, Key, IV, AAD)

		Check(`AES-{KeyLen * 8} encrypt msg={MsgLen}B ciphertext`, ToHex(NCt), ToHex(OCt))
		Check(`AES-{KeyLen * 8} encrypt msg={MsgLen}B tag`, ToHex(NTag), ToHex(OTag))

		-- Decrypt roundtrip
		local Ok, Pt = NewAES.Decrypt(NCt, Key, IV, NTag, AAD)
		Total += 1
		if Ok and Pt and ToHex(Pt :: buffer) == ToHex(Msg) then
			print(`[OK]   AES-{KeyLen * 8} decrypt roundtrip msg={MsgLen}B`)
		else
			Failures += 1
			print(`[FAIL] AES-{KeyLen * 8} decrypt roundtrip msg={MsgLen}B (ok={Ok})`)
		end
	end
end

print(`\n{Total - Failures}/{Total} passed, {Failures} failed.`)
