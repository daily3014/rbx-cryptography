--!optimize 2
--!native
--- The BLAKE3 cryptographic hash function.

local expect = require "./internal/expect".expect
local lassert = require "./internal/util".lassert
local packing = require "./internal/packing"

local unpack = unpack or table.unpack
local bxor = bit32.bxor
local rol = bit32.lrotate
local p16x4, fmt16x4 = packing.compilePack("<I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4")
local u16x4 = packing.compileUnpack(fmt16x4)
local u8x4, fmt8x4 = packing.compileUnpack("<I4I4I4I4I4I4I4I4")

local CHUNK_START = 0x01
local CHUNK_END = 0x02
local PARENT = 0x04
local ROOT = 0x08
local KEYED_HASH = 0x10
local DERIVE_KEY_CONTEXT = 0x20
local DERIVE_KEY_MATERIAL = 0x40

local IV = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

local function compress(h, msg, t, v14, v15, full)
    local h00, h01, h02, h03, h04, h05, h06, h07 = unpack(h)
    local v00, v01, v02, v03 = h00, h01, h02, h03
    local v04, v05, v06, v07 = h04, h05, h06, h07
    local v08, v09, v10, v11 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    local v12 = t % 2 ^ 32
    local v13 = (t - v12) * 2 ^ -32

    local m00, m01, m02, m03, m04, m05, m06, m07,
          m08, m09, m10, m11, m12, m13, m14, m15 = unpack(msg)

    local tmp
    for i = 1, 7 do
        v00 = v00 + v04 + m00 v12 = rol(bxor(v12, v00), 16)
        v08 = v08 + v12       v04 = rol(bxor(v04, v08), 20)
        v00 = v00 + v04 + m01 v12 = rol(bxor(v12, v00), 24)
        v08 = v08 + v12       v04 = rol(bxor(v04, v08), 25)

        v01 = v01 + v05 + m02 v13 = rol(bxor(v13, v01), 16)
        v09 = v09 + v13       v05 = rol(bxor(v05, v09), 20)
        v01 = v01 + v05 + m03 v13 = rol(bxor(v13, v01), 24)
        v09 = v09 + v13       v05 = rol(bxor(v05, v09), 25)

        v02 = v02 + v06 + m04 v14 = rol(bxor(v14, v02), 16)
        v10 = v10 + v14       v06 = rol(bxor(v06, v10), 20)
        v02 = v02 + v06 + m05 v14 = rol(bxor(v14, v02), 24)
        v10 = v10 + v14       v06 = rol(bxor(v06, v10), 25)

        v03 = v03 + v07 + m06 v15 = rol(bxor(v15, v03), 16)
        v11 = v11 + v15       v07 = rol(bxor(v07, v11), 20)
        v03 = v03 + v07 + m07 v15 = rol(bxor(v15, v03), 24)
        v11 = v11 + v15       v07 = rol(bxor(v07, v11), 25)

        v00 = v00 + v05 + m08 v15 = rol(bxor(v15, v00), 16)
        v10 = v10 + v15       v05 = rol(bxor(v05, v10), 20)
        v00 = v00 + v05 + m09 v15 = rol(bxor(v15, v00), 24)
        v10 = v10 + v15       v05 = rol(bxor(v05, v10), 25)

        v01 = v01 + v06 + m10 v12 = rol(bxor(v12, v01), 16)
        v11 = v11 + v12       v06 = rol(bxor(v06, v11), 20)
        v01 = v01 + v06 + m11 v12 = rol(bxor(v12, v01), 24)
        v11 = v11 + v12       v06 = rol(bxor(v06, v11), 25)

        v02 = v02 + v07 + m12 v13 = rol(bxor(v13, v02), 16)
        v08 = v08 + v13       v07 = rol(bxor(v07, v08), 20)
        v02 = v02 + v07 + m13 v13 = rol(bxor(v13, v02), 24)
        v08 = v08 + v13       v07 = rol(bxor(v07, v08), 25)

        v03 = v03 + v04 + m14 v14 = rol(bxor(v14, v03), 16)
        v09 = v09 + v14       v04 = rol(bxor(v04, v09), 20)
        v03 = v03 + v04 + m15 v14 = rol(bxor(v14, v03), 24)
        v09 = v09 + v14       v04 = rol(bxor(v04, v09), 25)

        if i ~= 7 then
            tmp = m02
            m02 = m03
            m03 = m10
            m10 = m12
            m12 = m09
            m09 = m11
            m11 = m05
            m05 = m00
            m00 = tmp

            tmp = m06
            m06 = m04
            m04 = m07
            m07 = m13
            m13 = m14
            m14 = m15
            m15 = m08
            m08 = m01
            m01 = tmp
        end
    end

    if full then
        return {
            bxor(v00, v08), bxor(v01, v09), bxor(v02, v10), bxor(v03, v11),
            bxor(v04, v12), bxor(v05, v13), bxor(v06, v14), bxor(v07, v15),
            bxor(v08, h00), bxor(v09, h01), bxor(v10, h02), bxor(v11, h03),
            bxor(v12, h04), bxor(v13, h05), bxor(v14, h06), bxor(v15, h07),
        }
    else
        return {
            bxor(v00, v08), bxor(v01, v09), bxor(v02, v10), bxor(v03, v11),
            bxor(v04, v12), bxor(v05, v13), bxor(v06, v14), bxor(v07, v15),
        }
    end
end

local function merge(cvl, cvr)
    for i = 1, 8 do cvl[i + 8] = cvr[i] end
    return cvl
end

local function blake3(iv, flags, msg, len)
    -- Set up the state.
    local stateCvs = {}
    local stateCv = iv
    local stateT = 0
    local stateN = 0
    local stateStart = CHUNK_START
    local stateEnd = 0

    -- Digest complete blocks.
    for i = 1, #msg - 64, 64 do
        -- Compress the block.
        local block = {u16x4(fmt16x4, msg, i)}
        local stateFlags = flags + stateStart + stateEnd
        stateCv = compress(stateCv, block, stateT, 64, stateFlags)
        stateStart = 0
        stateN = stateN + 1

        if stateN == 15 then
            -- Last block in chunk.
            stateEnd = CHUNK_END
        elseif stateN == 16 then
            -- Chunk complete, merge.
            local mergeCv = stateCv
            local mergeAmt = stateT + 1
            while mergeAmt % 2 == 0 do
                local block = merge(table.remove(stateCvs), mergeCv)
                mergeCv = compress(iv, block, 0, 64, flags + PARENT)
                mergeAmt = mergeAmt / 2
            end

            -- Push back.
            table.insert(stateCvs, mergeCv)

            -- Update state back to next chunk.
            stateCv = iv
            stateT = stateT + 1
            stateN = 0
            stateStart = CHUNK_START
            stateEnd = 0
        end
    end

    -- Pad the last message block.
    local lastLen = #msg == 0 and 0 or (#msg - 1) % 64 + 1
    local padded = msg:sub(-lastLen) .. ("\0"):rep(64)
    local last = {u16x4(fmt16x4, padded, 1)}

    -- Prepare output expansion state.
    local outCv, outBlock, outLen, outFlags
    if stateT > 0 then
        -- Root is a parent, digest last block now and merge parents.
        local stateFlags = flags + stateStart + CHUNK_END
        local mergeCv = compress(stateCv, last, stateT, lastLen, stateFlags)
        for i = #stateCvs, 2, -1 do
            local block = merge(stateCvs[i], mergeCv)
            mergeCv = compress(iv, block, 0, 64, flags + PARENT)
        end

        -- Set output state.
        outCv = iv
        outBlock = merge(stateCvs[1], mergeCv)
        outLen = 64
        outFlags = flags + ROOT + PARENT
    else
        -- Root block is in the first chunk, set output state.
        outCv = stateCv
        outBlock = last
        outLen = lastLen
        outFlags = flags + stateStart + CHUNK_END + ROOT
    end

    -- Expand output.
    local out = {}
    for i = 0, len / 64 do
        local md = compress(outCv, outBlock, i, outLen, outFlags, true)
        out[i + 1] = p16x4(fmt16x4, unpack(md))
    end

    return table.concat(out):sub(1, len)
end

--- Hashes data using BLAKE3.
--- @param message string The input message.
--- @param len number? The desired hash length, in bytes. Defaults to 32.
--- @return string hash The hash.
local function digest(message, len)
    expect(1, message, "string")
    len = expect(2, len, "number", "nil") or 32
    lassert(len % 1 == 0, "desired output length must be an integer", 2)
    lassert(len >= 1, "desired output length must be positive", 2)
    return blake3(IV, 0, message, len)
end

--- Performs a keyed hash.
--- @param key string A 32-byte random key.
--- @param message string The input message.
--- @param len number? The desired hash length, in bytes. Defaults to 32.
--- @return string hash The keyed hash.
local function digestKeyed(key, message, len)
    expect(1, key, "string")
    lassert(#key == 32, "key length must be 32", 2)
    expect(2, message, "string")
    len = expect(3, len, "number", "nil") or 32
    lassert(len % 1 == 0, "desired output length must be an integer", 2)
    lassert(len >= 1, "desired output length must be positive", 2)
    return blake3({u8x4(fmt8x4, key, 1)}, KEYED_HASH, message, len)
end

--- Makes a context-based key derivation function (KDF).
--- @param context string The context for the KDF.
--- @return fun(material: string, len: number?): string kdf The KDF.
local function deriveKey(context)
    expect(1, context, "string")
    local iv = {u8x4(fmt8x4, blake3(IV, DERIVE_KEY_CONTEXT, context, 32), 1)}

    --- Derives a key.
    --- @param material string The keying material.
    --- @param len number? The desired hash length, in bytes. Defaults to 32.
    return function(material, len)
        expect(1, material, "string")
        len = expect(2, len, "number", "nil") or 32
        lassert(len % 1 == 0, "desired output length must be an integer", 2)
        lassert(len >= 1, "desired output length must be positive", 2)
        return blake3(iv, DERIVE_KEY_MATERIAL, material, len)
    end
end

return {
    digest = digest,
    digestKeyed = digestKeyed,
    deriveKey = deriveKey,
}
