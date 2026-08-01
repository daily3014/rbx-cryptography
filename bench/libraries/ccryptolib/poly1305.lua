--!optimize 2
--!native
--- The Poly1305 one-time authenticator.

local expect  = require "./internal/expect".expect
local lassert = require "./internal/util".lassert
local packing = require "./internal/packing"

local u4x4, fmt4x4 = packing.compileUnpack("<I4I4I4I4")
local p4x4 = packing.compilePack(fmt4x4)

--- Computes a Poly1305 message authentication code.
--- @param key string A 32-byte single-use random key.
--- @param message string The message to authenticate.
--- @return string tag The 16-byte authentication tag.
local function mac(key, message)
    expect(1, key, "string")
    lassert(#key == 32, "key length must be 32", 2)
    expect(2, message, "string")

    -- Pad message.
    local pbplen = #message - 15
    if #message % 16 ~= 0 or #message == 0 then
        message = message .. "\1"
        message = message .. ("\0"):rep(-#message % 16)
    end

    -- Decode r.
    local R0, R1, R2, R3 = u4x4(fmt4x4, key, 1)

    -- Clamp and shift.
    R0 = R0 % 2 ^ 28
    R1 = (R1 - R1 % 4) % 2 ^ 28 * 2 ^ 32
    R2 = (R2 - R2 % 4) % 2 ^ 28 * 2 ^ 64
    R3 = (R3 - R3 % 4) % 2 ^ 28 * 2 ^ 96

    -- Split.
    local r0 = R0 % 2 ^ 18   local r1 = R0 - r0
    local r2 = R1 % 2 ^ 50   local r3 = R1 - r2
    local r4 = R2 % 2 ^ 82   local r5 = R2 - r4
    local r6 = R3 % 2 ^ 112  local r7 = R3 - r6

    -- Generate scaled key.
    local S1 = 5 / 2 ^ 130 * R1
    local S2 = 5 / 2 ^ 130 * R2
    local S3 = 5 / 2 ^ 130 * R3

    -- Split.
    local s2 = S1 % 2 ^ -80  local s3 = S1 - s2
    local s4 = S2 % 2 ^ -48  local s5 = S2 - s4
    local s6 = S3 % 2 ^ -16  local s7 = S3 - s6

    local h0, h1, h2, h3, h4, h5, h6, h7 = 0, 0, 0, 0, 0, 0, 0, 0

    for i = 1, #message, 16 do
        -- Decode message block.
        local m0, m1, m2, m3 = u4x4(fmt4x4, message, i)

        -- Shift message and add.
        local x0 = h0 + h1 + m0
        local x2 = h2 + h3 + m1 * 2 ^ 32
        local x4 = h4 + h5 + m2 * 2 ^ 64
        local x6 = h6 + h7 + m3 * 2 ^ 96

        -- Apply per-block padding when applicable.
        if i <= pbplen then x6 = x6 + 2 ^ 128 end

        -- Multiply
        h0 = x0 * r0 + x2 * s6 + x4 * s4 + x6 * s2
        h1 = x0 * r1 + x2 * s7 + x4 * s5 + x6 * s3
        h2 = x0 * r2 + x2 * r0 + x4 * s6 + x6 * s4
        h3 = x0 * r3 + x2 * r1 + x4 * s7 + x6 * s5
        h4 = x0 * r4 + x2 * r2 + x4 * r0 + x6 * s6
        h5 = x0 * r5 + x2 * r3 + x4 * r1 + x6 * s7
        h6 = x0 * r6 + x2 * r4 + x4 * r2 + x6 * r0
        h7 = x0 * r7 + x2 * r5 + x4 * r3 + x6 * r1

        -- Carry.
        local y0 = h0 + 3 * 2 ^ 69  - 3 * 2 ^ 69   h0 = h0 - y0  h1 = h1 + y0
        local y1 = h1 + 3 * 2 ^ 83  - 3 * 2 ^ 83   h1 = h1 - y1  h2 = h2 + y1
        local y2 = h2 + 3 * 2 ^ 101 - 3 * 2 ^ 101  h2 = h2 - y2  h3 = h3 + y2
        local y3 = h3 + 3 * 2 ^ 115 - 3 * 2 ^ 115  h3 = h3 - y3  h4 = h4 + y3
        local y4 = h4 + 3 * 2 ^ 133 - 3 * 2 ^ 133  h4 = h4 - y4  h5 = h5 + y4
        local y5 = h5 + 3 * 2 ^ 147 - 3 * 2 ^ 147  h5 = h5 - y5  h6 = h6 + y5
        local y6 = h6 + 3 * 2 ^ 163 - 3 * 2 ^ 163  h6 = h6 - y6  h7 = h7 + y6
        local y7 = h7 + 3 * 2 ^ 181 - 3 * 2 ^ 181  h7 = h7 - y7

        -- Reduce carry overflow into first limb.
        h0 = h0 + 5 / 2 ^ 130 * y7
    end

    -- Carry canonically.
    local c0 = h0 % 2 ^ 16   h1 = h0 - c0 + h1
    local c1 = h1 % 2 ^ 32   h2 = h1 - c1 + h2
    local c2 = h2 % 2 ^ 48   h3 = h2 - c2 + h3
    local c3 = h3 % 2 ^ 64   h4 = h3 - c3 + h4
    local c4 = h4 % 2 ^ 80   h5 = h4 - c4 + h5
    local c5 = h5 % 2 ^ 96   h6 = h5 - c5 + h6
    local c6 = h6 % 2 ^ 112  h7 = h6 - c6 + h7
    local c7 = h7 % 2 ^ 130

    -- Reduce carry overflow.
    h0 = c0 + 5 / 2 ^ 130 * (h7 - c7)
    c0 = h0 % 2 ^ 16
    c1 = h0 - c0 + c1

    -- Canonicalize.
    if      c7 == 0x3ffff * 2 ^ 112
        and c6 == 0xffff * 2 ^ 96
        and c5 == 0xffff * 2 ^ 80
        and c4 == 0xffff * 2 ^ 64
        and c3 == 0xffff * 2 ^ 48
        and c2 == 0xffff * 2 ^ 32
        and c1 == 0xffff * 2 ^ 16
        and c0 >= 0xfffb
    then
        c7, c6, c5, c4, c3, c2, c1, c0 = 0, 0, 0, 0, 0, 0, 0, c0 - 0xfffb
    end

    -- Decode s.
    local s0, s1, s2, s3 = u4x4(fmt4x4, key, 17)

    -- Add.
    local t0 =           s0          + c0 + c1  local u0 = t0 % 2 ^ 32
    local t1 = t0 - u0 + s1 * 2 ^ 32 + c2 + c3  local u1 = t1 % 2 ^ 64
    local t2 = t1 - u1 + s2 * 2 ^ 64 + c4 + c5  local u2 = t2 % 2 ^ 96
    local t3 = t2 - u2 + s3 * 2 ^ 96 + c6 + c7  local u3 = t3 % 2 ^ 128

    -- Encode.
    return p4x4(fmt4x4, u0, u1 / 2 ^ 32, u2 / 2 ^ 64, u3 / 2 ^ 96)
end

return {
    mac = mac,
}
