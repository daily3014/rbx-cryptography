--!strict
--!optimize 2
--!native
local Core = require('./AESTtableCore')
local M = {KeySchedule = Core.KeySchedule}

-- We need access to the internal tables. Hack: put them on the module.
-- For simplicity, we re-build the tables here.
local SBOX_BYTES = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
}
local SBOX = buffer.create(256)
local TTABLE0 = buffer.create(1024)
local TTABLE1 = buffer.create(1024)
local TTABLE2 = buffer.create(1024)
local TTABLE3 = buffer.create(1024)
do
  for B = 0, 255 do
    local S = SBOX_BYTES[B + 1]
    buffer.writeu8(SBOX, B, S)
    local S2 = bit32.band(bit32.lshift(S, 1), 0xFF)
    if bit32.band(S, 0x80) ~= 0 then S2 = bit32.bxor(S2, 0x1B) end
    local S3 = bit32.bxor(S2, S)
    buffer.writeu32(TTABLE0, B * 4, bit32.bor(S2, bit32.lshift(S, 8), bit32.lshift(S, 16), bit32.lshift(S3, 24)))
    buffer.writeu32(TTABLE1, B * 4, bit32.bor(S3, bit32.lshift(S2, 8), bit32.lshift(S, 16), bit32.lshift(S, 24)))
    buffer.writeu32(TTABLE2, B * 4, bit32.bor(S, bit32.lshift(S3, 8), bit32.lshift(S2, 16), bit32.lshift(S, 24)))
    buffer.writeu32(TTABLE3, B * 4, bit32.bor(S, bit32.lshift(S, 8), bit32.lshift(S3, 16), bit32.lshift(S2, 24)))
  end
end

function M.EncryptBlock256(RoundKeys: buffer, In: buffer, InOff: number, Out: buffer, OutOff: number)
  local C0 = bit32.bxor(buffer.readu32(In, InOff + 0), buffer.readu32(RoundKeys, 0))
  local C1 = bit32.bxor(buffer.readu32(In, InOff + 4), buffer.readu32(RoundKeys, 4))
  local C2 = bit32.bxor(buffer.readu32(In, InOff + 8), buffer.readu32(RoundKeys, 8))
  local C3 = bit32.bxor(buffer.readu32(In, InOff + 12), buffer.readu32(RoundKeys, 12))

  -- Round, KOff=16
  do
    local A = bit32.band(C0, 0xFF)
    local B = bit32.band(bit32.rshift(C1, 8), 0xFF)
    local Cc = bit32.band(bit32.rshift(C2, 16), 0xFF)
    local D = bit32.rshift(C3, 24)
    local NewC0 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 16))
    A = bit32.band(C1, 0xFF)
    B = bit32.band(bit32.rshift(C2, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C3, 16), 0xFF)
    D = bit32.rshift(C0, 24)
    local NewC1 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 20))
    A = bit32.band(C2, 0xFF)
    B = bit32.band(bit32.rshift(C3, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C0, 16), 0xFF)
    D = bit32.rshift(C1, 24)
    local NewC2 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 24))
    A = bit32.band(C3, 0xFF)
    B = bit32.band(bit32.rshift(C0, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C1, 16), 0xFF)
    D = bit32.rshift(C2, 24)
    local NewC3 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 28))
    C0, C1, C2, C3 = NewC0, NewC1, NewC2, NewC3
  end
  -- Round, KOff=32
  do
    local A = bit32.band(C0, 0xFF)
    local B = bit32.band(bit32.rshift(C1, 8), 0xFF)
    local Cc = bit32.band(bit32.rshift(C2, 16), 0xFF)
    local D = bit32.rshift(C3, 24)
    local NewC0 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 32))
    A = bit32.band(C1, 0xFF)
    B = bit32.band(bit32.rshift(C2, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C3, 16), 0xFF)
    D = bit32.rshift(C0, 24)
    local NewC1 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 36))
    A = bit32.band(C2, 0xFF)
    B = bit32.band(bit32.rshift(C3, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C0, 16), 0xFF)
    D = bit32.rshift(C1, 24)
    local NewC2 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 40))
    A = bit32.band(C3, 0xFF)
    B = bit32.band(bit32.rshift(C0, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C1, 16), 0xFF)
    D = bit32.rshift(C2, 24)
    local NewC3 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 44))
    C0, C1, C2, C3 = NewC0, NewC1, NewC2, NewC3
  end
  -- Round, KOff=48
  do
    local A = bit32.band(C0, 0xFF)
    local B = bit32.band(bit32.rshift(C1, 8), 0xFF)
    local Cc = bit32.band(bit32.rshift(C2, 16), 0xFF)
    local D = bit32.rshift(C3, 24)
    local NewC0 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 48))
    A = bit32.band(C1, 0xFF)
    B = bit32.band(bit32.rshift(C2, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C3, 16), 0xFF)
    D = bit32.rshift(C0, 24)
    local NewC1 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 52))
    A = bit32.band(C2, 0xFF)
    B = bit32.band(bit32.rshift(C3, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C0, 16), 0xFF)
    D = bit32.rshift(C1, 24)
    local NewC2 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 56))
    A = bit32.band(C3, 0xFF)
    B = bit32.band(bit32.rshift(C0, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C1, 16), 0xFF)
    D = bit32.rshift(C2, 24)
    local NewC3 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 60))
    C0, C1, C2, C3 = NewC0, NewC1, NewC2, NewC3
  end
  -- Round, KOff=64
  do
    local A = bit32.band(C0, 0xFF)
    local B = bit32.band(bit32.rshift(C1, 8), 0xFF)
    local Cc = bit32.band(bit32.rshift(C2, 16), 0xFF)
    local D = bit32.rshift(C3, 24)
    local NewC0 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 64))
    A = bit32.band(C1, 0xFF)
    B = bit32.band(bit32.rshift(C2, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C3, 16), 0xFF)
    D = bit32.rshift(C0, 24)
    local NewC1 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 68))
    A = bit32.band(C2, 0xFF)
    B = bit32.band(bit32.rshift(C3, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C0, 16), 0xFF)
    D = bit32.rshift(C1, 24)
    local NewC2 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 72))
    A = bit32.band(C3, 0xFF)
    B = bit32.band(bit32.rshift(C0, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C1, 16), 0xFF)
    D = bit32.rshift(C2, 24)
    local NewC3 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 76))
    C0, C1, C2, C3 = NewC0, NewC1, NewC2, NewC3
  end
  -- Round, KOff=80
  do
    local A = bit32.band(C0, 0xFF)
    local B = bit32.band(bit32.rshift(C1, 8), 0xFF)
    local Cc = bit32.band(bit32.rshift(C2, 16), 0xFF)
    local D = bit32.rshift(C3, 24)
    local NewC0 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 80))
    A = bit32.band(C1, 0xFF)
    B = bit32.band(bit32.rshift(C2, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C3, 16), 0xFF)
    D = bit32.rshift(C0, 24)
    local NewC1 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 84))
    A = bit32.band(C2, 0xFF)
    B = bit32.band(bit32.rshift(C3, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C0, 16), 0xFF)
    D = bit32.rshift(C1, 24)
    local NewC2 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 88))
    A = bit32.band(C3, 0xFF)
    B = bit32.band(bit32.rshift(C0, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C1, 16), 0xFF)
    D = bit32.rshift(C2, 24)
    local NewC3 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 92))
    C0, C1, C2, C3 = NewC0, NewC1, NewC2, NewC3
  end
  -- Round, KOff=96
  do
    local A = bit32.band(C0, 0xFF)
    local B = bit32.band(bit32.rshift(C1, 8), 0xFF)
    local Cc = bit32.band(bit32.rshift(C2, 16), 0xFF)
    local D = bit32.rshift(C3, 24)
    local NewC0 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 96))
    A = bit32.band(C1, 0xFF)
    B = bit32.band(bit32.rshift(C2, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C3, 16), 0xFF)
    D = bit32.rshift(C0, 24)
    local NewC1 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 100))
    A = bit32.band(C2, 0xFF)
    B = bit32.band(bit32.rshift(C3, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C0, 16), 0xFF)
    D = bit32.rshift(C1, 24)
    local NewC2 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 104))
    A = bit32.band(C3, 0xFF)
    B = bit32.band(bit32.rshift(C0, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C1, 16), 0xFF)
    D = bit32.rshift(C2, 24)
    local NewC3 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 108))
    C0, C1, C2, C3 = NewC0, NewC1, NewC2, NewC3
  end
  -- Round, KOff=112
  do
    local A = bit32.band(C0, 0xFF)
    local B = bit32.band(bit32.rshift(C1, 8), 0xFF)
    local Cc = bit32.band(bit32.rshift(C2, 16), 0xFF)
    local D = bit32.rshift(C3, 24)
    local NewC0 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 112))
    A = bit32.band(C1, 0xFF)
    B = bit32.band(bit32.rshift(C2, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C3, 16), 0xFF)
    D = bit32.rshift(C0, 24)
    local NewC1 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 116))
    A = bit32.band(C2, 0xFF)
    B = bit32.band(bit32.rshift(C3, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C0, 16), 0xFF)
    D = bit32.rshift(C1, 24)
    local NewC2 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 120))
    A = bit32.band(C3, 0xFF)
    B = bit32.band(bit32.rshift(C0, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C1, 16), 0xFF)
    D = bit32.rshift(C2, 24)
    local NewC3 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 124))
    C0, C1, C2, C3 = NewC0, NewC1, NewC2, NewC3
  end
  -- Round, KOff=128
  do
    local A = bit32.band(C0, 0xFF)
    local B = bit32.band(bit32.rshift(C1, 8), 0xFF)
    local Cc = bit32.band(bit32.rshift(C2, 16), 0xFF)
    local D = bit32.rshift(C3, 24)
    local NewC0 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 128))
    A = bit32.band(C1, 0xFF)
    B = bit32.band(bit32.rshift(C2, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C3, 16), 0xFF)
    D = bit32.rshift(C0, 24)
    local NewC1 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 132))
    A = bit32.band(C2, 0xFF)
    B = bit32.band(bit32.rshift(C3, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C0, 16), 0xFF)
    D = bit32.rshift(C1, 24)
    local NewC2 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 136))
    A = bit32.band(C3, 0xFF)
    B = bit32.band(bit32.rshift(C0, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C1, 16), 0xFF)
    D = bit32.rshift(C2, 24)
    local NewC3 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 140))
    C0, C1, C2, C3 = NewC0, NewC1, NewC2, NewC3
  end
  -- Round, KOff=144
  do
    local A = bit32.band(C0, 0xFF)
    local B = bit32.band(bit32.rshift(C1, 8), 0xFF)
    local Cc = bit32.band(bit32.rshift(C2, 16), 0xFF)
    local D = bit32.rshift(C3, 24)
    local NewC0 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 144))
    A = bit32.band(C1, 0xFF)
    B = bit32.band(bit32.rshift(C2, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C3, 16), 0xFF)
    D = bit32.rshift(C0, 24)
    local NewC1 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 148))
    A = bit32.band(C2, 0xFF)
    B = bit32.band(bit32.rshift(C3, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C0, 16), 0xFF)
    D = bit32.rshift(C1, 24)
    local NewC2 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 152))
    A = bit32.band(C3, 0xFF)
    B = bit32.band(bit32.rshift(C0, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C1, 16), 0xFF)
    D = bit32.rshift(C2, 24)
    local NewC3 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 156))
    C0, C1, C2, C3 = NewC0, NewC1, NewC2, NewC3
  end
  -- Round, KOff=160
  do
    local A = bit32.band(C0, 0xFF)
    local B = bit32.band(bit32.rshift(C1, 8), 0xFF)
    local Cc = bit32.band(bit32.rshift(C2, 16), 0xFF)
    local D = bit32.rshift(C3, 24)
    local NewC0 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 160))
    A = bit32.band(C1, 0xFF)
    B = bit32.band(bit32.rshift(C2, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C3, 16), 0xFF)
    D = bit32.rshift(C0, 24)
    local NewC1 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 164))
    A = bit32.band(C2, 0xFF)
    B = bit32.band(bit32.rshift(C3, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C0, 16), 0xFF)
    D = bit32.rshift(C1, 24)
    local NewC2 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 168))
    A = bit32.band(C3, 0xFF)
    B = bit32.band(bit32.rshift(C0, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C1, 16), 0xFF)
    D = bit32.rshift(C2, 24)
    local NewC3 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 172))
    C0, C1, C2, C3 = NewC0, NewC1, NewC2, NewC3
  end
  -- Round, KOff=176
  do
    local A = bit32.band(C0, 0xFF)
    local B = bit32.band(bit32.rshift(C1, 8), 0xFF)
    local Cc = bit32.band(bit32.rshift(C2, 16), 0xFF)
    local D = bit32.rshift(C3, 24)
    local NewC0 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 176))
    A = bit32.band(C1, 0xFF)
    B = bit32.band(bit32.rshift(C2, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C3, 16), 0xFF)
    D = bit32.rshift(C0, 24)
    local NewC1 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 180))
    A = bit32.band(C2, 0xFF)
    B = bit32.band(bit32.rshift(C3, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C0, 16), 0xFF)
    D = bit32.rshift(C1, 24)
    local NewC2 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 184))
    A = bit32.band(C3, 0xFF)
    B = bit32.band(bit32.rshift(C0, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C1, 16), 0xFF)
    D = bit32.rshift(C2, 24)
    local NewC3 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 188))
    C0, C1, C2, C3 = NewC0, NewC1, NewC2, NewC3
  end
  -- Round, KOff=192
  do
    local A = bit32.band(C0, 0xFF)
    local B = bit32.band(bit32.rshift(C1, 8), 0xFF)
    local Cc = bit32.band(bit32.rshift(C2, 16), 0xFF)
    local D = bit32.rshift(C3, 24)
    local NewC0 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 192))
    A = bit32.band(C1, 0xFF)
    B = bit32.band(bit32.rshift(C2, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C3, 16), 0xFF)
    D = bit32.rshift(C0, 24)
    local NewC1 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 196))
    A = bit32.band(C2, 0xFF)
    B = bit32.band(bit32.rshift(C3, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C0, 16), 0xFF)
    D = bit32.rshift(C1, 24)
    local NewC2 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 200))
    A = bit32.band(C3, 0xFF)
    B = bit32.band(bit32.rshift(C0, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C1, 16), 0xFF)
    D = bit32.rshift(C2, 24)
    local NewC3 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 204))
    C0, C1, C2, C3 = NewC0, NewC1, NewC2, NewC3
  end
  -- Round, KOff=208
  do
    local A = bit32.band(C0, 0xFF)
    local B = bit32.band(bit32.rshift(C1, 8), 0xFF)
    local Cc = bit32.band(bit32.rshift(C2, 16), 0xFF)
    local D = bit32.rshift(C3, 24)
    local NewC0 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 208))
    A = bit32.band(C1, 0xFF)
    B = bit32.band(bit32.rshift(C2, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C3, 16), 0xFF)
    D = bit32.rshift(C0, 24)
    local NewC1 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 212))
    A = bit32.band(C2, 0xFF)
    B = bit32.band(bit32.rshift(C3, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C0, 16), 0xFF)
    D = bit32.rshift(C1, 24)
    local NewC2 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 216))
    A = bit32.band(C3, 0xFF)
    B = bit32.band(bit32.rshift(C0, 8), 0xFF)
    Cc = bit32.band(bit32.rshift(C1, 16), 0xFF)
    D = bit32.rshift(C2, 24)
    local NewC3 = bit32.bxor(buffer.readu32(TTABLE0, A*4), buffer.readu32(TTABLE1, B*4), buffer.readu32(TTABLE2, Cc*4), buffer.readu32(TTABLE3, D*4), buffer.readu32(RoundKeys, 220))
    C0, C1, C2, C3 = NewC0, NewC1, NewC2, NewC3
  end
  -- Final round
  do
    local KOff = 14 * 16
    local A = buffer.readu8(SBOX, bit32.band(C0, 0xFF))
    local B = buffer.readu8(SBOX, bit32.band(bit32.rshift(C1, 8), 0xFF))
    local Cc = buffer.readu8(SBOX, bit32.band(bit32.rshift(C2, 16), 0xFF))
    local D = buffer.readu8(SBOX, bit32.rshift(C3, 24))
    buffer.writeu32(Out, OutOff + 0, bit32.bxor(bit32.bor(A, bit32.lshift(B, 8), bit32.lshift(Cc, 16), bit32.lshift(D, 24)), buffer.readu32(RoundKeys, KOff)))
    A = buffer.readu8(SBOX, bit32.band(C1, 0xFF))
    B = buffer.readu8(SBOX, bit32.band(bit32.rshift(C2, 8), 0xFF))
    Cc = buffer.readu8(SBOX, bit32.band(bit32.rshift(C3, 16), 0xFF))
    D = buffer.readu8(SBOX, bit32.rshift(C0, 24))
    buffer.writeu32(Out, OutOff + 4, bit32.bxor(bit32.bor(A, bit32.lshift(B, 8), bit32.lshift(Cc, 16), bit32.lshift(D, 24)), buffer.readu32(RoundKeys, KOff + 4)))
    A = buffer.readu8(SBOX, bit32.band(C2, 0xFF))
    B = buffer.readu8(SBOX, bit32.band(bit32.rshift(C3, 8), 0xFF))
    Cc = buffer.readu8(SBOX, bit32.band(bit32.rshift(C0, 16), 0xFF))
    D = buffer.readu8(SBOX, bit32.rshift(C1, 24))
    buffer.writeu32(Out, OutOff + 8, bit32.bxor(bit32.bor(A, bit32.lshift(B, 8), bit32.lshift(Cc, 16), bit32.lshift(D, 24)), buffer.readu32(RoundKeys, KOff + 8)))
    A = buffer.readu8(SBOX, bit32.band(C3, 0xFF))
    B = buffer.readu8(SBOX, bit32.band(bit32.rshift(C0, 8), 0xFF))
    Cc = buffer.readu8(SBOX, bit32.band(bit32.rshift(C1, 16), 0xFF))
    D = buffer.readu8(SBOX, bit32.rshift(C2, 24))
    buffer.writeu32(Out, OutOff + 12, bit32.bxor(bit32.bor(A, bit32.lshift(B, 8), bit32.lshift(Cc, 16), bit32.lshift(D, 24)), buffer.readu32(RoundKeys, KOff + 12)))
  end
end

return M

