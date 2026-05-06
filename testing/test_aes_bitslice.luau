--!strict
--!optimize 2

local AESBS = require("./algorithms/AESBitsliceCore")

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
	local Skey, Nr = AESBS.KeySchedule(Key)
	local Out = buffer.create(16)
	AESBS.EncryptBlock(Skey, Nr, Plain, 0, Out, 0)
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

print(" AES Bitslice single-block (NIST FIPS-197 / SP800-38A vectors) ")

-- FIPS-197 Appendix C.1: AES-128
TestVector("AES-128 Appx C.1",
	"000102030405060708090a0b0c0d0e0f",
	"00112233445566778899aabbccddeeff",
	"69c4e0d86a7b0430d8cdb78070b4c55a")

-- FIPS-197 Appendix C.2: AES-192
TestVector("AES-192 Appx C.2",
	"000102030405060708090a0b0c0d0e0f1011121314151617",
	"00112233445566778899aabbccddeeff",
	"dda97ca4864cdfe06eaf70a0ec0d7191")

-- FIPS-197 Appendix C.3: AES-256
TestVector("AES-256 Appx C.3",
	"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	"00112233445566778899aabbccddeeff",
	"8ea2b7ca516745bfeafc49904b496089")

-- SP800-38A AES-128
TestVector("SP800-38A AES-128 #1",
	"2b7e151628aed2a6abf7158809cf4f3c",
	"6bc1bee22e409f96e93d7e117393172a",
	"3ad77bb40d7a3660a89ecaf32466ef97")

-- SP800-38A AES-256
TestVector("SP800-38A AES-256 #1",
	"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
	"6bc1bee22e409f96e93d7e117393172a",
	"f3eed1bdb5d2a03c064b5a7e3db181f8")

-- 4-block test: encrypt 4 different blocks at once, check each individually
do
	Total += 1
	local Key = FromHex("2b7e151628aed2a6abf7158809cf4f3c")
	local In = buffer.create(64)
	local Plains = {
		"6bc1bee22e409f96e93d7e117393172a",
		"ae2d8a571e03ac9c9eb76fac45af8e51",
		"30c81c46a35ce411e5fbc1191a0a52ef",
		"f69f2445df4f9b17ad2b417be66c3710",
	}
	local Expected = {
		"3ad77bb40d7a3660a89ecaf32466ef97",
		"f5d3d58503b9699de785895a96fdbaaf",
		"43b1cd7f598ece23881b00e3ed030688",
		"7b0c785e27e8ad3f8223207104725dd4",
	}
	for I, P in Plains do
		buffer.copy(In, (I - 1) * 16, FromHex(P), 0, 16)
	end

	local Skey, Nr = AESBS.KeySchedule(Key)
	local Out = buffer.create(64)
	AESBS.EncryptBlocks4(Skey, Nr, In, 0, Out, 0)

	local AllPass = true
	for I, E in Expected do
		local Slice = buffer.create(16)
		buffer.copy(Slice, 0, Out, (I - 1) * 16, 16)
		if ToHex(Slice) ~= E then
			AllPass = false
			print(`       block {I}: got {ToHex(Slice)}, expected {E}`)
		end
	end
	if AllPass then
		print("[OK]   AES-128 4-block parallel (SP800-38A vectors 1-4)")
	else
		Failures += 1
		print("[FAIL] AES-128 4-block parallel")
	end
end

print(`\n{Total - Failures}/{Total} passed, {Failures} failed.`)
