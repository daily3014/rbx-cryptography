--!optimize 2
--!native
--- The ChaCha20Poly1305AEAD authenticated encryption with associated data (AEAD) construction.

local expect   = require "./internal/expect".expect
local lassert = require "./internal/util".lassert
local packing  = require "./internal/packing"
local chacha20 = require "./chacha20"
local poly1305 = require "./poly1305"

local p8x1, fmt8x1 = packing.compilePack("<I8")
local u4x4, fmt4x4 = packing.compileUnpack("<I4I4I4I4")
local bxor = bit32.bxor

--- Encrypts a message.
--- @param key string A 32-byte random key.
--- @param nonce string A 12-byte per-message unique nonce.
--- @param message string The message to be encrypted.
--- @param aad string aad Arbitrary associated data to also authenticate.
--- @param rounds number? The number of ChaCha20 rounds to use. Defaults to 20.
--- @return string ctx The ciphertext.
--- @return string tag The 16-byte authentication tag.
local function encrypt(key, nonce, message, aad, rounds)
    expect(1, key, "string")
    lassert(#key == 32, "key length must be 32", 2)
    expect(2, nonce, "string")
    lassert(#nonce == 12, "nonce length must be 12", 2)
    expect(3, message, "string")
    expect(4, aad, "string")
    rounds = expect(5, rounds, "number", "nil") or 20
    lassert(rounds % 2 == 0, "round number must be even", 2)
    lassert(rounds >= 8, "round number must be no smaller than 8", 2)
    lassert(rounds <= 20, "round number must be no larger than 20", 2)

    -- Generate auth key and encrypt.
    local msgLong = ("\0"):rep(64) .. message
    local ctxLong = chacha20.crypt(key, nonce, msgLong, rounds, 0)
    local authKey = ctxLong:sub(1, 32)
    local ciphertext = ctxLong:sub(65)

    -- Authenticate.
    local pad1 = ("\0"):rep(-#aad % 16)
    local pad2 = ("\0"):rep(-#ciphertext % 16)
    local aadLen = p8x1("<I8", #aad)
    local ctxLen = p8x1("<I8", #ciphertext)
    local combined = aad .. pad1 .. ciphertext .. pad2 .. aadLen .. ctxLen
    local tag = poly1305.mac(authKey, combined)

    return ciphertext, tag
end

--- Decrypts a message.
--- @param key string The key used on encryption.
--- @param nonce string The nonce used on encryption.
--- @param tag string The authentication tag returned on encryption.
--- @param ciphertext string The ciphertext to be decrypted.
--- @param aad string The arbitrary associated data used on encryption.
--- @param rounds number The number of rounds used on encryption.
--- @return string? msg The decrypted plaintext. Or nil on auth failure.
local function decrypt(key, nonce, tag, ciphertext, aad, rounds)
    expect(1, key, "string")
    lassert(#key == 32, "key length must be 32", 2)
    expect(2, nonce, "string")
    lassert(#nonce == 12, "nonce length must be 12", 2)
    expect(3, tag, "string")
    lassert(#tag == 16, "tag length must be 16", 2)
    expect(4, ciphertext, "string")
    expect(5, aad, "string")
    rounds = expect(6, rounds, "number", "nil") or 20
    lassert(rounds % 2 == 0, "round number must be even", 2)
    lassert(rounds >= 8, "round number must be no smaller than 8", 2)
    lassert(rounds <= 20, "round number must be no larger than 20", 2)

    -- Generate auth key.
    local authKey = chacha20.crypt(key, nonce, ("\0"):rep(32), rounds, 0)

    -- Check tag.
    local pad1 = ("\0"):rep(-#aad % 16)
    local pad2 = ("\0"):rep(-#ciphertext % 16)
    local aadLen = p8x1(fmt8x1, #aad)
    local ctxLen = p8x1(fmt8x1, #ciphertext)
    local combined = aad .. pad1 .. ciphertext .. pad2 .. aadLen .. ctxLen
    local t1, t2, t3, t4 = u4x4(fmt4x4, tag, 1)
    local u1, u2, u3, u4 = u4x4(fmt4x4, poly1305.mac(authKey, combined), 1)
    local eq = bxor(t1, u1) + bxor(t2, u2) + bxor(t3, u3) + bxor(t4, u4)
    if eq ~= 0 then return nil end

    -- Decrypt
    return chacha20.crypt(key, nonce, ciphertext, rounds)
end

return {
    encrypt = encrypt,
    decrypt = decrypt,
}
