--!optimize 2
--!native
--- Arithmetic on Curve25519's scalar field.

local mp = require "./mp"
local util = require "./util"
local packing = require "./packing"

local unpack = unpack or table.unpack
local pfq, fmtfq = packing.compilePack("<I3I3I3I3I3I3I3I3I3I3I2")
local ufq = packing.compileUnpack(fmtfq)
local ufql, fmtfql = packing.compileUnpack("<I3I3I3I3I3I3I3I3I3I3I3")
local ufqh, fmtfqh = packing.compileUnpack("<I3I3I3I3I3I3I3I3I3I3I1")

--- The scalar field's order, q = 2²⁵² + 27742317777372353535851937790883648493.
local Q = {
    16110573,
    06494812,
    14047250,
    10680220,
    14612958,
    00000020,
    00000000,
    00000000,
    00000000,
    00000000,
    00004096,
}

--- The first Montgomery precomputed constant, -q⁻¹ mod 2²⁶⁴.
local T0 = {
    05537307,
    01942290,
    16765621,
    16628356,
    10618610,
    07072433,
    03735459,
    01369940,
    15276086,
    13038191,
    13409718,
}

--- The second Montgomery precomputed constant, 2⁵²⁸ mod q.
local T1 = {
    11711996,
    01747860,
    08326961,
    03814718,
    01859974,
    13327461,
    16105061,
    07590423,
    04050668,
    08138906,
    00000283,
}

local T8 = {
    5110253,
    3039345,
    2503500,
    11779568,
    15416472,
    16766550,
    16777215,
    16777215,
    16777215,
    16777215,
    4095,
}

local ZERO = mp.num(0)

--- Reduces a number modulo q.
--
-- @tparam {number...} a A number a < 2q as 11 limbs in [0..2²⁵).
-- @treturn {number...} a mod q as 11 limbs in [0..2²⁴).
--
local function reduce(a)
    local c = mp.sub(a, Q)

    -- Return carry(a) if a < q.
    if mp.approx(c) < 0 then return (mp.carry(a)) end

    -- c >= q means c - q >= 0.
    -- Since q < 2²⁸⁸, c < 2q means c - q < q < 2²⁸⁸.
    -- c's limbs fit in (-2²⁶..2²⁶), since subtraction adds at most one bit.
    return (mp.carry(c)) -- cc < q implies that the carry number is 0.
end

--- Adds two scalars mod q.
--
-- If the two operands are in Montgomery form, returns the correct result also
-- in Montgomery form, since (2²⁶⁴ × a) + (2²⁶⁴ × b) ≡ 2²⁶⁴ × (a + b) (mod q).
--
-- @tparam {number...} a A number a < q as 11 limbs in [0..2²⁴).
-- @tparam {number...} b A number b < q as 11 limbs in [0..2²⁴).
-- @treturn {number...} a + b mod q as 11 limbs in [0..2²⁴).
--
local function add(a, b)
    return reduce(mp.add(a, b))
end

--- Negates a scalar mod q.
--
-- @tparam {number...} a A number a < q as 11 limbs in [0..2²⁴).
-- @treturn {number...} -a mod q as 11 limbs in [0..2²⁴).
--
local function neg(a)
    return reduce(mp.sub(Q, a))
end

--- Subtracts scalars mod q.
--
-- If the two operands are in Montgomery form, returns the correct result also
-- in Montgomery form, since (2²⁶⁴ × a) - (2²⁶⁴ × b) ≡ 2²⁶⁴ × (a - b) (mod q).
--
-- @tparam {number...} a A number a < q as 11 limbs in [0..2²⁴).
-- @tparam {number...} b A number b < q as 11 limbs in [0..2²⁴).
-- @treturn {number...} a - b mod q as 11 limbs in [0..2²⁴).
--
local function sub(a, b)
    return add(a, neg(b))
end

--- Given two scalars a and b, computes 2⁻²⁶⁴ × a × b mod q.
--
-- @tparam {number...} a A number a as 11 limbs in [0..2²⁴).
-- @tparam {number...} b A number b < q as 11 limbs in [0..2²⁴).
-- @treturn {number...} 2⁻²⁶⁴ × a × b mod q as 11 limbs in [0..2²⁴).
--
local function mul(a, b)
    local t0, t1 = mp.mul(a, b)
    local mq0, mq1 = mp.mul(mp.lmul(t0, T0), Q)
    local _, s1 = mp.dwadd(t0, t1, mq0, mq1)
    return reduce(s1)
end

--- Converts a scalar into Montgomery form.
--
-- @tparam {number...} a A number a as 11 limbs in [0..2²⁴).
-- @treturn {number...} 2²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
--
local function montgomery(a)
    -- 0 ≤ a < 2²⁶⁴ and 0 ≤ T1 < q.
    return mul(a, T1)
end

--- Converts a scalar from Montgomery form.
--
-- @tparam {number...} a A number a < q as 11 limbs in [0..2²⁴).
-- @treturn {number...} 2⁻²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
--
local function demontgomery(a)
    -- It's REDC all over again except b is 1.
    local mq0, mq1 = mp.mul(mp.lmul(a, T0), Q)
    local _, s1 = mp.dwadd(a, ZERO, mq0, mq1)
    return reduce(s1)
end

--- Encodes a scalar.
--
-- @tparam {number...} a A number 2²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
-- @treturn string The 32-byte string encoding of a.
--
local function encode(a)
    return pfq(fmtfq, unpack(demontgomery(a)))
end

--- Decodes a scalar.
--
-- @tparam string str A 32-byte string encoding some little-endian number a.
-- @treturn {number...} 2²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
--
local function decode(str)
    local dec = {ufq(fmtfq, str, 1)} dec[12] = nil
    return montgomery(dec)
end

--- Decodes a scalar from a "wide" string.
--
-- @tparam string str A 64-byte string encoding some little-endian number a.
-- @treturn {number...} 2²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
--
local function decodeWide(str)
    local low = {ufql(fmtfql, str, 1)} low[12] = nil
    local high = {ufqh(fmtfqh, str, 34)} high[12] = nil
    return add(montgomery(low), montgomery(montgomery(high)))
end

--- Decodes a scalar using the X25519/Ed25519 bit clamping scheme.
--
-- @tparam string str A 32-byte string encoding some little-endian number a.
-- @treturn {number...} 2²⁶⁴ × clamp(a) mod q as 11 limbs in [0..2²⁴).
--
local function decodeClamped(str)
    -- Decode.
    local words = {ufq(fmtfq, str, 1)} words[12] = nil

    -- Clamp.
    words[1] = bit32.band(words[1], 0xfffff8)
    words[11] = bit32.band(words[11], 0x7fff)
    words[11] = bit32.bor(words[11], 0x4000)

    return montgomery(words)
end

--- Divides a scalar by 8.
--
-- @tparam {number...} 2²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
-- @treturn {number...} 2²⁶⁵ × a ÷ 8 mod q as 11 limbs in [0..2²⁴).
local function eighth(a)
    return mul(a, T8)
end

--- Returns a scalar in binary.
--
-- @tparam {number...} a A number a < q as 11 limbs in [0..2²⁴).
-- @treturn {number...} 2⁻²⁶⁴ × a mod q as 253 bits.
--
local function bits(a)
    local out = util.rebaseLE(demontgomery(a), 2 ^ 24, 2)
    for i = 254, 289 do out[i] = nil end
    return out
end

--- Makes a PRAC ruleset from a pair of scalars.
--
-- For more information see section 3.3 of Speeding up subgroup cryptosystems:
-- Martijn Stam. Speeding up subgroup cryptosystems. PhD thesis, Technische
-- Universiteit Eindhoven, 2003. https://dx.doi.org/10.6100/IR564670.
--
-- @tparam {number...} a A scalar 2²⁶⁴ × a mod q as 11 limbs in [0..2²⁴).
-- @tparam {number...} b A scalar 2²⁶⁴ × b mod q as 11 limbs in [0..2²⁴).
-- @treturn {{number...}, {number...}} The generated ruleset.
--
local function makeRuleset(a, b)
    -- The numbers in raw multiprecision tables.
    local dt = demontgomery(a) -- (-2²⁴..2²⁴)
    local et = demontgomery(b) -- (-2²⁴..2²⁴)
    local ft = mp.sub(dt, et)  -- (-2²⁵..2²⁵)

    -- Residue classes of (d, e) modulo 2.
    local d2 = mp.mod2(dt)
    local e2 = mp.mod2(et)

    -- Residue classes of (d, e) modulo 3.
    local d3 = mp.mod3(dt)
    local e3 = mp.mod3(et)

    -- (e, d - e) in limited-precision floating-point numbers.
    local ef = mp.approx(et)
    local ff = mp.approx(ft)

    -- Lookup table for inversions and halvings modulo 3.
    local lut3 = {[0] = 0, 2, 1}

    local rules = {}
    while ff ~= 0 do
        if ff < 0 then
            -- M0. d < e
            rules[#rules + 1] = 0
            -- (d, e) ← (e, d)
            dt, et = et, dt
            d2, e2 = e2, d2
            d3, e3 = e3, d3
            ef = mp.approx(et)
            ft = mp.sub(dt, et)
            ff = -ff
        elseif 4 * ff < ef and d3 == lut3[e3] then
            -- M1. e < d ≤ 5/4 e, d ≡ -e (mod 3)
            rules[#rules + 1] = 1
            -- (d, e) ← ((2d - e)/3, (2e - d)/3)
            dt, et = mp.third(mp.add(dt, ft)), mp.third(mp.sub(et, ft))
            d2, e2 = e2, d2
            d3, e3 = mp.mod3(dt), mp.mod3(et)
            ef = mp.approx(et)
        elseif 4 * ff < ef and d2 == e2 and d3 == e3 then
            -- M2. e < d ≤ 5/4 e, d ≡ e (mod 6)
            rules[#rules + 1] = 2
            -- (d, e) ← ((d - e)/2, e)
            dt = mp.half(ft)
            d2 = mp.mod2(dt)
            d3 = lut3[(d3 - e3) % 3]
            ft = mp.sub(dt, et)
            ff = mp.approx(ft)
        elseif ff < 3 * ef then
            -- M3. d ≤ 4e
            rules[#rules + 1] = 3
            -- (d, e) ← (d - e, e)
            dt = mp.carryWeak(ft)
            d2 = (d2 - e2) % 2
            d3 = (d3 - e3) % 3
            ft = mp.sub(dt, et)
            ff = mp.approx(ft)
        elseif d2 == e2 then
            -- M4. d ≡ e (mod 2)
            rules[#rules + 1] = 2
            -- (d, e) ← ((d - e)/2, e)
            dt = mp.half(ft)
            d2 = mp.mod2(dt)
            d3 = lut3[(d3 - e3) % 3]
            ft = mp.sub(dt, et)
            ff = mp.approx(ft)
        elseif d2 == 0 then
            -- M5. d ≡ 0 (mod 2)
            rules[#rules + 1] = 5
            -- (d, e) ← (d/2, e)
            dt = mp.half(dt)
            d2 = mp.mod2(dt)
            d3 = lut3[d3]
            ft = mp.sub(dt, et)
            ff = mp.approx(ft)
        elseif d3 == 0 then
            -- M6. d ≡ 0 (mod 3)
            rules[#rules + 1] = 6
            -- (d, e) ← (d/3 - e, e)
            dt = mp.carryWeak(mp.sub(mp.third(dt), et))
            d2 = (d2 - e2) % 2
            d3 = mp.mod3(dt)
            ft = mp.sub(dt, et)
            ff = mp.approx(ft)
        elseif d3 == lut3[e3] then
            -- M7. d ≡ -e (mod 3)
            rules[#rules + 1] = 7
            -- (d, e) ← ((d - 2e)/3, e)
            dt = mp.third(mp.sub(ft, et))
            d3 = mp.mod3(dt)
            ft = mp.sub(dt, et)
            ff = mp.approx(ft)
        elseif d3 == e3 then
            -- M8. d ≡ e (mod 3)
            rules[#rules + 1] = 8
            -- (d, e) ← ((d - e)/3, e)
            dt = mp.third(ft)
            d2 = (d2 - e2) % 2
            d3 = mp.mod3(dt)
            ft = mp.sub(dt, et)
            ff = mp.approx(ft)
        else
            -- M9. e ≡ 0 (mod 2)
            rules[#rules + 1] = 9
            -- (d, e) ← (d, e/2)
            et = mp.half(et)
            e2 = mp.mod2(et)
            e3 = lut3[e3]
            ef = mp.approx(et)
            ft = mp.sub(dt, et)
            ff = mp.approx(ft)
        end
    end

    local ubits = util.rebaseLE(dt, 2 ^ 24, 2)
    while ubits[#ubits] == 0 do ubits[#ubits] = nil end

    return {ubits, rules}
end

return {
    add = add,
    sub = sub,
    mul = mul,
    encode = encode,
    decode = decode,
    decodeWide = decodeWide,
    decodeClamped = decodeClamped,
    eighth = eighth,
    bits = bits,
    makeRuleset = makeRuleset,
}
