--!optimize 2
--!native
--- The SHA512 cryptographic hash function.

local expect  = require "./expect".expect
local packing = require "./packing"

local shl = bit32.lshift
local shr = bit32.rshift
local bxor = bit32.bxor
local bnot = bit32.bnot
local band = bit32.band
local p1x16, fmt1x16 = packing.compilePack(">I16")
local p16x4, fmt16x4 = packing.compilePack(">I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4")
local u32x4, fmt32x4 = packing.compileUnpack(">I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4")

local function carry64(a1, a0)
    local r0 = a0 % 2 ^ 32
    a1 = a1 + (a0 - r0) / 2 ^ 32
    return a1 % 2 ^ 32, r0
end

local K = {
    0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f,
    0xe9b5dba5, 0x8189dbbc, 0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
    0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118, 0xd807aa98, 0xa3030242,
    0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
    0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235,
    0xc19bf174, 0xcf692694, 0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
    0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65, 0x2de92c6f, 0x592b0275,
    0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
    0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f,
    0xbf597fc7, 0xbeef0ee4, 0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
    0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70, 0x27b70a85, 0x46d22ffc,
    0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
    0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6,
    0x92722c85, 0x1482353b, 0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
    0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30, 0xd192e819, 0xd6ef5218,
    0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
    0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99,
    0x34b0bcb5, 0xe19b48a8, 0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
    0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3, 0x748f82ee, 0x5defb2fc,
    0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
    0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915,
    0xc67178f2, 0xe372532b, 0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
    0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178, 0x06f067aa, 0x72176fba,
    0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
    0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc,
    0x431d67c4, 0x9c100d4c, 0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
    0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
}

--- Hashes data bytes using SHA512.
--- @param data string The input data.
--- @return string hash The 64-byte hash value.
local function digest(data)
    expect(1, data, "string")

    -- Pad input.
    local bitlen = #data * 8
    local padlen = -(#data + 17) % 128
    data = data .. "\x80" .. ("\0"):rep(padlen) .. p1x16(fmt1x16, bitlen)

    -- Initialize state.
    local h01, h00 = 0x6a09e667, 0xf3bcc908
    local h11, h10 = 0xbb67ae85, 0x84caa73b
    local h21, h20 = 0x3c6ef372, 0xfe94f82b
    local h31, h30 = 0xa54ff53a, 0x5f1d36f1
    local h41, h40 = 0x510e527f, 0xade682d1
    local h51, h50 = 0x9b05688c, 0x2b3e6c1f
    local h61, h60 = 0x1f83d9ab, 0xfb41bd6b
    local h71, h70 = 0x5be0cd19, 0x137e2179

    -- Digest.
    for i = 1, #data, 128 do
        local w = {u32x4(fmt32x4, data, i)}

        -- Message schedule.
        for j = 33, 160, 2 do
            local wf1, wf0 = w[j - 30], w[j - 29]
            local t1 = shr(wf1, 1) + shl(wf0, 31)
            local t0 = shr(wf0, 1) + shl(wf1, 31)
            local u1 = shr(wf1, 8) + shl(wf0, 24)
            local u0 = shr(wf0, 8) + shl(wf1, 24)
            local v1 = shr(wf1, 7)
            local v0 = shr(wf0, 7) + shl(wf1, 25)

            local w21, w20 = w[j - 4], w[j - 3]
            local w1 = shr(w21, 19) + shl(w20, 13)
            local w0 = shr(w20, 19) + shl(w21, 13)
            local x0 = shr(w21, 29) + shl(w20, 3)
            local x1 = shr(w20, 29) + shl(w21, 3)
            local y1 = shr(w21, 6)
            local y0 = shr(w20, 6) + shl(w21, 26)

            local r1, r0 =
                w[j - 32] + bxor(t1, u1, v1) + w[j - 14] + bxor(w1, x1, y1),
                w[j - 31] + bxor(t0, u0, v0) + w[j - 13] + bxor(w0, x0, y0)

            w[j], w[j + 1] = carry64(r1, r0)
        end

        -- Block function.
        local a1, a0 = h01, h00
        local b1, b0 = h11, h10
        local c1, c0 = h21, h20
        local d1, d0 = h31, h30
        local e1, e0 = h41, h40
        local f1, f0 = h51, h50
        local g1, g0 = h61, h60
        local h1, h0 = h71, h70
        for j = 1, 160, 2 do
            local t1 = shr(e1, 14) + shl(e0, 18)
            local t0 = shr(e0, 14) + shl(e1, 18)
            local u1 = shr(e1, 18) + shl(e0, 14)
            local u0 = shr(e0, 18) + shl(e1, 14)
            local v0 = shr(e1, 9) + shl(e0, 23)
            local v1 = shr(e0, 9) + shl(e1, 23)
            local s11 = bxor(t1, u1, v1)
            local s10 = bxor(t0, u0, v0)

            local ch1 = bxor(band(e1, f1), band(bnot(e1), g1))
            local ch0 = bxor(band(e0, f0), band(bnot(e0), g0))

            local temp11 = h1 + s11 + ch1 + K[j] + w[j]
            local temp10 = h0 + s10 + ch0 + K[j + 1] + w[j + 1]

            local w1 = shr(a1, 28) + shl(a0, 4)
            local w0 = shr(a0, 28) + shl(a1, 4)
            local x0 = shr(a1, 2) + shl(a0, 30)
            local x1 = shr(a0, 2) + shl(a1, 30)
            local y0 = shr(a1, 7) + shl(a0, 25)
            local y1 = shr(a0, 7) + shl(a1, 25)
            local s01 = bxor(w1, x1, y1)
            local s00 = bxor(w0, x0, y0)

            local maj1 = bxor(band(a1, b1), band(a1, c1), band(b1, c1))
            local maj0 = bxor(band(a0, b0), band(a0, c0), band(b0, c0))

            local temp21 = s01 + maj1
            local temp20 = s00 + maj0

            h1 = g1  h0 = g0
            g1 = f1  g0 = f0
            f1 = e1  f0 = e0
            e1, e0 = carry64(d1 + temp11, d0 + temp10)
            d1 = c1  d0 = c0
            c1 = b1  c0 = b0
            b1 = a1  b0 = a0
            a1, a0 = carry64(temp11 + temp21, temp10 + temp20)
        end

        h01, h00 = carry64(h01 + a1, h00 + a0)
        h11, h10 = carry64(h11 + b1, h10 + b0)
        h21, h20 = carry64(h21 + c1, h20 + c0)
        h31, h30 = carry64(h31 + d1, h30 + d0)
        h41, h40 = carry64(h41 + e1, h40 + e0)
        h51, h50 = carry64(h51 + f1, h50 + f0)
        h61, h60 = carry64(h61 + g1, h60 + g0)
        h71, h70 = carry64(h71 + h1, h70 + h0)
    end

    return p16x4(fmt16x4,
        h01, h00, h11, h10, h21, h20, h31, h30,
        h41, h40, h51, h50, h61, h60, h71, h70
    )
end

return {
    digest = digest,
}
