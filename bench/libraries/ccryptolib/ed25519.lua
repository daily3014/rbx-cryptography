--!optimize 2
--!native
--- The Ed25519 digital signature scheme.

local expect = require "./internal/expect".expect
local lassert = require "./internal/util".lassert
local fq     = require "./internal/fq"
local sha512 = require "./internal/sha512"
local ed     = require "./internal/edwards25519"
local random = require "./random"

random.init("seed 1 2 3 4 5")

--- Computes a public key from a secret key.
--- @param sk string A random 32-byte secret key.
--- @return string pk The matching 32-byte public key.
local function publicKey(sk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")

    local h = sha512.digest(sk)
    local x = fq.decodeClamped(h:sub(1, 32))

    return ed.encode(ed.mulG(fq.bits(x)))
end

--- Signs a message.
--- @param sk string The signer's secret key.
--- @param pk string The signer's public key.
--- @param msg string The message to be signed.
--- @return string sig The 64-byte signature on the message.
local function sign(sk, pk, msg)
    expect(1, sk, "string")
    lassert(#sk == 32, "secret key length must be 32", 2)
    expect(2, pk, "string")
    lassert(#pk == 32, "public key length must be 32", 2)
    expect(3, msg, "string")

    -- Secret key.
    local h = sha512.digest(sk)
    local x = fq.decodeClamped(h:sub(1, 32))

    -- Commitment.
    local k = fq.decodeWide(random.random(64))
    local r = ed.mulG(fq.bits(k))
    local rStr = ed.encode(r)

    -- Challenge.
    local e = fq.decodeWide(sha512.digest(rStr .. pk .. msg))

    -- Response.
    local m = fq.decodeWide(random.random(64))
    local s = fq.sub(fq.add(k, fq.mul(fq.add(x, m), e)), fq.mul(m, e))
    local sStr = fq.encode(s)

    return rStr .. sStr
end

--- Verifies a signature on a message.
--- @param pk string The signer's public key.
--- @param msg string The signed message.
--- @param sig string The alleged signature.
--- @return boolean valid Whether the signature is valid or not.
local function verify(pk, msg, sig)
    expect(1, pk, "string")
    lassert(#pk == 32, "public key length must be 32", 2) --- @cast pk String32
    expect(2, msg, "string")
    expect(3, sig, "string")
    lassert(#sig == 64, "signature length must be 64", 2)

    local y = ed.decode(pk)
    if not y then return false end

    local rStr = sig:sub(1, 32)
    local sStr = sig:sub(33)

    local e = fq.decodeWide(sha512.digest(rStr .. pk .. msg))

    local gs = ed.mulG(fq.bits(fq.decode(sStr)))
    local ye = ed.mul(y, fq.bits(e))
    local rv = ed.sub(gs, ed.niels(ye))

    return ed.encode(rv) == rStr
end

return {
    publicKey = publicKey,
    sign = sign,
    verify = verify,
}
