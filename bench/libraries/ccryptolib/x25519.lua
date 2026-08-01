--!optimize 2
--!native
--- The X25519 key exchange scheme.

local expect = require "./internal/expect".expect
local lassert = require "./internal/util".lassert
local util = require "./internal/util"
local c25 = require "./internal/curve25519"

--- Computes the public key from a secret key.
--- @param sk string A random 32-byte secret key.
--- @return string pk The matching public key.
local function publicKey(sk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")
    return c25.encode(c25.scale(c25.mulG(util.bits(sk))))
end

--- Performs the key exchange.
--- @param sk string A Curve25519 secret key.
--- @param pk string A public key, usually derived from someone else's secret key.
--- @return string ss The 32-byte shared secret between both keys.
local function exchange(sk, pk)
    expect(1, sk, "string")
    lassert(#sk == 32, "secret key length must be 32", 2)
    expect(2, pk, "string")
    lassert(#pk == 32, "public key length must be 32", 2) --- @cast pk String32
    return c25.encode(c25.scale(c25.ladder8(c25.decode(pk), util.bits8(sk))))
end

return {
    publicKey = publicKey,
    exchange = exchange,
}
