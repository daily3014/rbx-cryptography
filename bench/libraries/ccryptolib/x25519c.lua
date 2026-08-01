--!optimize 2
--!native

local expect = require "./internal/expect".expect
local lassert = require "./internal/util".lassert
local fq     = require "./internal/fq"
local fp     = require "./internal/fp"
local c25    = require "./internal/curve25519"
local sha512 = require "./internal/sha512"
local random = require "./random"

--- Masks an exchange secret key.
--- @param sk string A random 32-byte Curve25519 secret key.
--- @return string msk A masked secret key.
local function mask(sk)
    expect(1, sk, "string")
    lassert(#sk == 32, "secret key length must be 32", 2)
    local mask = random.random(32)
    local x = fq.decodeClamped(sk)
    local r = fq.decodeClamped(mask)
    local xr = fq.sub(x, r)
    return fq.encode(xr) .. mask
end

--- Masks a signature secret key.
--- @param sk string A random 32-byte Edwards25519 secret key.
--- @return string msk A masked secret key.
local function maskS(sk)
    expect(1, sk, "string")
    lassert(#sk == 32, "secret key length must be 32", 2)
    return mask(sha512.digest(sk):sub(1, 32))
end

--- Rerandomizes the masking on a masked key.
--- @param msk string A masked secret key.
--- @return string msk The same secret key, but with another mask.
local function remask(msk)
    expect(1, msk, "string")
    lassert(#msk == 64, "masked secret key length must be 64", 2)
    local newMask = random.random(32)
    local xr = fq.decode(msk:sub(1, 32))
    local r = fq.decodeClamped(msk:sub(33))
    local s = fq.decodeClamped(newMask)
    local xs = fq.add(xr, fq.sub(r, s))
    return fq.encode(xs) .. newMask
end

--- Returns the ephemeral exchange secret key of this masked key.
--- This is the second secret key in the "double key exchange" in @{exchange},
--- the first being the key that has been masked. The ephemeral key changes
--- every time @{remask} is called.
--- @param msk string A masked secret key.
--- @return string esk The ephemeral half of the masked secret key.
local function ephemeralSk(msk)
    expect(1, msk, "string")
    lassert(#msk == 64, "masked secret key length must be 64", 2)
    return msk:sub(33)
end

local function exchangeOnPoint(sk, P)
    local xr = fq.decode(sk:sub(1, 32))
    local r = fq.decodeClamped(sk:sub(33))
    local rP, xrP, dP = c25.prac(P, fq.makeRuleset(fq.eighth(r), fq.eighth(xr)))

    -- Return early if P has small order or if r = xr. (1)
    if not rP then
        local out = fp.encode(fp.num(0))
        return out, out
    end

    local xP = c25.dadd(dP, rP, xrP)

    -- Extract coordinates for scaling.
    local Px, Pz = P[1], P[2]
    local xPx, xPz = xP[1], xP[2]
    local rPx, rPz = rP[1], rP[2]

    -- Ensure all Z coordinates are squares.
    Px, Pz = fp.mul(Px, Pz), fp.square(Pz)
    xPx, xPz = fp.mul(xPx, xPz), fp.square(xPz)
    rPx, rPz = fp.mul(rPx, rPz), fp.square(rPz)

    -- We're splitting the secret x into (x - r (mod q), r). The multiplication
    -- adds them back together, but this only works if P's order is q, which is
    -- not the case on the twist.
    -- As a result, we need to check if P is on the twist and return 0 so as to
    -- not leak part of x. We do this by checking the curve equation against P.
    -- The projective equation for curve25519 is Y²Z = X(X² + AXZ + Z²). Since Z
    -- is a square, checking validity means checking the right-hand side to be a
    -- square.
    local Px2 = fp.square(Px)
    local Pz2 = fp.square(Pz)
    local Pxz = fp.mul(Px, Pz)
    local APxz = fp.kmul(Pxz, 486662)
    local rhs = fp.mul(Px, fp.add(Px2, fp.carry(fp.add(APxz, Pz2))))

    -- Find the square root of 1 / (rhs * xPz * rPz).
    -- Neither rPz, xPz, nor rhs are 0:
    -- - If rhs was 0, then P would be low order, which would return at (1).
    -- - Since P isn't low order, clamping prevents the ladder from returning O.
    -- Since we've just squared both xPz and rPz, the root will exist iff rhs is
    -- a square. This checks the curve equation, so we're done.
    local root = fp.sqrtDiv(fp.num(1), fp.mul(fp.mul(xPz, rPz), rhs))
    if not root then
        local out = fp.encode(fp.num(0))
        return out, out
    end

    -- Get the inverses of both Z values.
    local xPzrPzInv = fp.mul(fp.square(root), rhs)
    local xPzInv = fp.mul(xPzrPzInv, rPz)
    local rPzInv = fp.mul(xPzrPzInv, xPz)

    -- Finish scaling and encode the output.
    return fp.encode(fp.mul(xPx, xPzInv)), fp.encode(fp.mul(rPx, rPzInv))
end

--- Returns the X25519 public key of this masked key.
--- @param msk string A masked secret key.
local function publicKey(msk)
    expect(1, msk, "string")
    lassert(#msk == 64, "masked secret key length must be 64", 2)
    return (exchangeOnPoint(msk, c25.G))
end

--- Performs a double key exchange.
---
--- Returns 0 if the input public key has small order or if it isn't in the base
--- curve. This is different from standard X25519, which performs the exchange
--- even on the twist.
---
--- May incorrectly return 0 with negligible chance if the mask happens to match
--- the masked key. I haven't checked if clamping prevents that from happening.
---
--- @param sk string A masked secret key.
--- @param pk string An X25519 public key.
--- @return string sss The shared secret between the public key and the static half of the masked key.
--- @return string sse The shared secret betwen the public key and the ephemeral half of the masked key.
local function exchange(sk, pk)
    expect(1, sk, "string")
    lassert(#sk == 64, "masked secret key length must be 64", 2)
    expect(2, pk, "string")
    lassert(#pk == 32, "public key length must be 32", 2) --- @cast pk String32
    return exchangeOnPoint(sk, c25.decode(pk))
end

return {
    mask = mask,
    remask = remask,
    publicKey = publicKey,
    ephemeralSk = ephemeralSk,
    exchange = exchange,
}
