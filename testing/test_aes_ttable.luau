--!strict
--!optimize 2

local AESTT = require("./algorithms/AESTtableCore")

local Failures = 0
local Total = 0

local function FromHex(Hex: string): buffer
	local Buf = buffer.create(#Hex // 2)
	for I = 0, #Hex // 2 - 1 do
		buffer.writeu8(Buf, I, tonumber(Hex:sub(I * 2 + 1, I * 2 + 2), 16) :: number)
	end
	return Buf
end

local function ToHex(Buf: buffer): string
	local Parts = {}
	for I = 0, buffer.len(Buf) - 1 do
		Parts[I + 1] = string.format("%02x", buffer.readu8(Buf, I))
	end
	return table.concat(Parts)
end

local function TestVector(Name: string, KeyHex: string, PlainHex: string, ExpectedHex: string)
	Total += 1
	local Key = FromHex(KeyHex)
	local Plain = FromHex(PlainHex)
	local RKeys, Nr = AESTT.KeySchedule(Key)
	local Out = buffer.create(16)
	AESTT.EncryptBlock(RKeys, Nr, Plain, 0, Out, 0)
	local Got = ToHex(Out)
	if Got == ExpectedHex then
		print(`[OK]   {Name}`)
	else
		Failures += 1
		print(`[FAIL] {Name}`)
		print(`       got:      {Got}`)
		print(`       expected: {ExpectedHex}`)
	end
end

print(" AES T-table single-block (NIST FIPS-197 / SP800-38A) ")
TestVector("AES-128 Appx C.1", "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a")
TestVector("AES-192 Appx C.2", "000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191")
TestVector("AES-256 Appx C.3", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089")
TestVector("SP800-38A AES-128 #1", "2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97")
TestVector("SP800-38A AES-256 #1", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8")

print(`\n{Total - Failures}/{Total} passed, {Failures} failed.`)
