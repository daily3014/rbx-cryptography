--!optimize 2
--!native
--- The SHA256 cryptographic hash function.

local expect  = require "./internal/expect".expect
local lassert = require "./internal/util".lassert
local packing = require "./internal/packing"

local rol = bit32.lrotate
local shr = bit32.rshift
local bxor = bit32.bxor
local bnot = bit32.bnot
local band = bit32.band
local unpack = unpack or table.unpack
local p1x8, fmt1x8 = packing.compilePack(">I8")
local p16x4, fmt16x4 = packing.compilePack(">I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4")
local u16x4 = packing.compileUnpack(fmt16x4)
local p8x4, fmt8x4 = packing.compilePack(">I4I4I4I4I4I4I4I4")
local u8x4 = packing.compileUnpack(fmt8x4)

local function primes(n, exp)
    local out = {}
    local p = 2
    for i = 1, n do
        out[i] = bxor(p ^ exp % 1 * 2 ^ 32)
        repeat p = p + 1 until 2 ^ p % p == 2
    end
    return out
end

--local K = primes(64, 1 / 3)
local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
}

--local h0 = primes(8, 1 / 2)
local h0 = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}

local function compress(h, w)
    local h0, h1, h2, h3, h4, h5, h6, h7 = unpack(h)
    local K = K

    -- Message schedule.
    for j = 17, 64 do
        local wf = w[j - 15]
        local w2 = w[j - 2]
        local s0 = bxor(rol(wf, 25), rol(wf, 14), shr(wf, 3))
        local s1 = bxor(rol(w2, 15), rol(w2, 13), shr(w2, 10))
        w[j] = w[j - 16] + s0 + w[j - 7] + s1
    end

    -- Block.
    local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
    for j = 1, 64 do
        local s1 = bxor(rol(e, 26), rol(e, 21), rol(e, 7))
        local ch = bxor(band(e, f), band(bnot(e), g))
        local temp1 = h + s1 + ch + K[j] + w[j]
        local s0 = bxor(rol(a, 30), rol(a, 19), rol(a, 10))
        local maj = bxor(band(a, b), band(a, c), band(b, c))
        local temp2 = s0 + maj

        h = g
        g = f
        f = e
        e = d + temp1
        d = c
        c = b
        b = a
        a = temp1 + temp2
    end

    return {
        (h0 + a) % 2 ^ 32,
        (h1 + b) % 2 ^ 32,
        (h2 + c) % 2 ^ 32,
        (h3 + d) % 2 ^ 32,
        (h4 + e) % 2 ^ 32,
        (h5 + f) % 2 ^ 32,
        (h6 + g) % 2 ^ 32,
        (h7 + h) % 2 ^ 32,
    }
end

--- Hashes data using SHA256.
--- @param data string Input bytes.
--- @return string hash The 32-byte hash value.
local function digest(data)
    expect(1, data, "string")

    -- Pad input.
    local bitlen = #data * 8
    local padlen = -(#data + 9) % 64
    data = data .. "\x80" .. ("\0"):rep(padlen) .. p1x8(fmt1x8, bitlen)

    -- Digest.
    local h = h0
    for i = 1, #data, 64 do
        h = compress(h, {u16x4(fmt16x4, data, i)})
    end

    return p8x4(fmt8x4, unpack(h))
end

-- Reports once every ~10ms on a standard CCEmuX emulator.
local PBKDF2_CB_ITERATIONS = 50

--- Hashes a password using PBKDF2-HMAC-SHA256.
--- @param password string The password to hash.
--- @param salt string The password's salt.
--- @param iter number The number of iterations to perform.
--- @param progress fun(iter: number)? An optional function to periodically call with the current iteration number as argument.
--- @return string dk The 32-byte derived key.
local function pbkdf2(password, salt, iter, progress)
    expect(1, password, "string")
    expect(2, salt, "string")
    expect(3, iter, "number")
    lassert(iter % 1 == 0, "iteration number must be an integer", 2)
    lassert(iter > 0, "iteration number must be positive", 2)
    expect(4, progress, "function", "nil")

    -- Pad password.
    if #password > 64 then password = digest(password) end
    password = {u16x4(fmt16x4, password .. ("\0"):rep(64), 1)}

    -- Compute password blocks.
    local ikp = {}
    local okp = {}
    for i = 1, 16 do
        ikp[i] = bxor(password[i], 0x36363636)
        okp[i] = bxor(password[i], 0x5c5c5c5c)
    end

    local hikp = compress(h0, ikp)
    local hokp = compress(h0, okp)

    -- 96-byte padding.
    local pad96 = {2 ^ 31, 0, 0, 0, 0, 0, 0, 0x300}

    -- First iteration.
    local pre = p16x4(fmt16x4, unpack(ikp))
    local hs = {u8x4(fmt8x4, digest(pre .. salt .. "\0\0\0\1"), 1)}
    for i = 1, 8 do hs[i + 8] = pad96[i] end
    hs = compress(hokp, hs)

    -- Second iteration onwards.
    local out = {unpack(hs)}
    for i = 2, iter do
        for j = 1, 8 do hs[j + 8] = pad96[j] end
        hs = compress(hikp, hs)
        for j = 1, 8 do hs[j + 8] = pad96[j] end
        hs = compress(hokp, hs)
        for j = 1, 8 do out[j] = bxor(out[j], hs[j]) end
        if progress and i % PBKDF2_CB_ITERATIONS == 0 then progress(i) end
    end

    return p8x4(fmt8x4, unpack(out))
end

return {
    digest = digest,
    pbkdf2 = pbkdf2,
}
