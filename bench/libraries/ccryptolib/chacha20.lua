--!optimize 2
--!native
--- The ChaCha20 stream cipher.

local expect  = require "./internal/expect".expect
local lassert = require "./internal/util".lassert
local packing = require "./internal/packing"

local bxor = bit32.bxor
local rol = bit32.lrotate
local u8x4, fmt8x4 = packing.compileUnpack("<I4I4I4I4I4I4I4I4")
local u3x4, fmt3x4 = packing.compileUnpack("<I4I4I4")
local p16x4, fmt16x4 = packing.compilePack("<I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4")
local u16x4 = packing.compileUnpack(fmt16x4)

--- Encrypts/Decrypts data using ChaCha20.
--- @param key string A 32-byte random key.
--- @param nonce string A 12-byte per-message unique nonce.
--- @param message string A plaintext or ciphertext.
--- @param rounds number? The number of ChaCha20 rounds to use. Defaults to 20.
--- @param offset number? The block offset to generate the keystream at. Defaults to 1.
--- @return string out The resulting ciphertext or plaintext.
local function crypt(key, nonce, message, rounds, offset)
    expect(1, key, "string")
    lassert(#key == 32, "key length must be 32", 2)
    expect(2, nonce, "string")
    lassert(#nonce == 12, "nonce length must be 12", 2)
    expect(3, message, "string")
    rounds = expect(4, rounds, "number", "nil") or 20
    lassert(rounds % 2 == 0, "round number must be even", 2)
    lassert(rounds >= 8, "round number must be no smaller than 8", 2)
    lassert(rounds <= 20, "round number must be no larger than 20", 2)
    offset = expect(5, offset, "number", "nil") or 1
    lassert(offset % 1 == 0, "offset must be an integer", 2)
    lassert(offset >= 0, "offset must be nonnegative", 2)
    lassert(#message + 64 * offset <= 2 ^ 38, "offset too large", 2)

    -- Build the state block.
    local i0, i1, i2, i3 = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    local k0, k1, k2, k3, k4, k5, k6, k7 = u8x4(fmt8x4, key, 1)
    local cr, n0, n1, n2 = offset, u3x4(fmt3x4, nonce, 1)

    -- Pad the message.
    local padded = message .. ("\0"):rep(-#message % 64)

    -- Expand and combine.
    local out = {}
    local idx = 1
    for i = 1, #padded / 64 do
        -- Copy the block.
        local s00, s01, s02, s03 = i0, i1, i2, i3
        local s04, s05, s06, s07 = k0, k1, k2, k3
        local s08, s09, s10, s11 = k4, k5, k6, k7
        local s12, s13, s14, s15 = cr, n0, n1, n2

        -- Iterate.
        for _ = 1, rounds, 2 do
            s00 = s00 + s04 s12 = rol(bxor(s12, s00), 16)
            s08 = s08 + s12 s04 = rol(bxor(s04, s08), 12)
            s00 = s00 + s04 s12 = rol(bxor(s12, s00), 8)
            s08 = s08 + s12 s04 = rol(bxor(s04, s08), 7)

            s01 = s01 + s05 s13 = rol(bxor(s13, s01), 16)
            s09 = s09 + s13 s05 = rol(bxor(s05, s09), 12)
            s01 = s01 + s05 s13 = rol(bxor(s13, s01), 8)
            s09 = s09 + s13 s05 = rol(bxor(s05, s09), 7)

            s02 = s02 + s06 s14 = rol(bxor(s14, s02), 16)
            s10 = s10 + s14 s06 = rol(bxor(s06, s10), 12)
            s02 = s02 + s06 s14 = rol(bxor(s14, s02), 8)
            s10 = s10 + s14 s06 = rol(bxor(s06, s10), 7)

            s03 = s03 + s07 s15 = rol(bxor(s15, s03), 16)
            s11 = s11 + s15 s07 = rol(bxor(s07, s11), 12)
            s03 = s03 + s07 s15 = rol(bxor(s15, s03), 8)
            s11 = s11 + s15 s07 = rol(bxor(s07, s11), 7)

            s00 = s00 + s05 s15 = rol(bxor(s15, s00), 16)
            s10 = s10 + s15 s05 = rol(bxor(s05, s10), 12)
            s00 = s00 + s05 s15 = rol(bxor(s15, s00), 8)
            s10 = s10 + s15 s05 = rol(bxor(s05, s10), 7)

            s01 = s01 + s06 s12 = rol(bxor(s12, s01), 16)
            s11 = s11 + s12 s06 = rol(bxor(s06, s11), 12)
            s01 = s01 + s06 s12 = rol(bxor(s12, s01), 8)
            s11 = s11 + s12 s06 = rol(bxor(s06, s11), 7)

            s02 = s02 + s07 s13 = rol(bxor(s13, s02), 16)
            s08 = s08 + s13 s07 = rol(bxor(s07, s08), 12)
            s02 = s02 + s07 s13 = rol(bxor(s13, s02), 8)
            s08 = s08 + s13 s07 = rol(bxor(s07, s08), 7)

            s03 = s03 + s04 s14 = rol(bxor(s14, s03), 16)
            s09 = s09 + s14 s04 = rol(bxor(s04, s09), 12)
            s03 = s03 + s04 s14 = rol(bxor(s14, s03), 8)
            s09 = s09 + s14 s04 = rol(bxor(s04, s09), 7)
        end

        -- Decode message block.
        local m00, m01, m02, m03, m04, m05, m06, m07
        local m08, m09, m10, m11, m12, m13, m14, m15

        m00, m01, m02, m03, m04, m05, m06, m07,
        m08, m09, m10, m11, m12, m13, m14, m15, idx =
            u16x4(fmt16x4, padded, idx)

        -- Feed-forward and combine.
        out[i] = p16x4(fmt16x4,
            bxor(m00, s00 + i0), bxor(m01, s01 + i1),
            bxor(m02, s02 + i2), bxor(m03, s03 + i3),
            bxor(m04, s04 + k0), bxor(m05, s05 + k1),
            bxor(m06, s06 + k2), bxor(m07, s07 + k3),
            bxor(m08, s08 + k4), bxor(m09, s09 + k5),
            bxor(m10, s10 + k6), bxor(m11, s11 + k7),
            bxor(m12, s12 + cr), bxor(m13, s13 + n0),
            bxor(m14, s14 + n1), bxor(m15, s15 + n2)
        )

        -- Increment counter.
        cr = cr + 1
    end

    return table.concat(out):sub(1, #message)
end

return {
    crypt = crypt,
}
