--!strict
local AESTT = require("./algorithms/AESTtableCore")
local AESOld = (require)("./algorithms/AESOldExposed") :: any

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

-- AES-128 NIST vector
local Key = FromHex("000102030405060708090a0b0c0d0e0f")
local Plain = FromHex("00112233445566778899aabbccddeeff")
local Expected = "69c4e0d86a7b0430d8cdb78070b4c55a"

-- Use existing key schedule
local OldCfg = AESOld._KEY_CONFIGS[16]
local OldRK = AESOld._ExpandKeySchedule(Key, 16, buffer.create(OldCfg.ExpandedLength))

-- Use T-table EncryptBlock with old round keys
local Out = buffer.create(16)
AESTT.EncryptBlock(OldRK, 10, Plain, 0, Out, 0)
print(`old KS + new EncryptBlock: {ToHex(Out)}`)
print(`expected:                   {Expected}`)
print(`match: {ToHex(Out) == Expected}`)
