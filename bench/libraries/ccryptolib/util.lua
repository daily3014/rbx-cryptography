--!optimize 2
--!native
--- General utilities for handling byte strings.

local expect = require "./internal/expect".expect
local random = require "./random"
local poly1305 = require "./poly1305"

--- Returns the hexadecimal version of a string.
--- @param str string A string.
--- @return string hex The hexadecimal version of the string.
local function toHex(str)
    expect(1, str, "string")
    return ("%02x"):rep(#str):format(str:byte(1, -1))
end

--- Converts back a string from hexadecimal.
--- @param hex string A hexadecimal string.
--- @return string? str The original string, or nil if the input is invalid.
local function fromHex(hex)
    expect(1, hex, "string")
    local out = {}
    local n = 0
    for c in hex:gmatch("%x%x") do
        n = n + 1
        out[n] = tonumber(c, 16)
    end
    if 2 * n == #hex then return string.char(table.unpack(out)) end
end

--- Compares two strings while mitigating secret leakage through timing.
--- @param a string
--- @param b string
--- @return boolean eq Whether a == b.
local function compare(a, b)
    expect(1, a, "string")
    expect(2, b, "string")
    if #a ~= #b then return false end
    local kaux = random.random(32)
    return poly1305.mac(kaux, a) == poly1305.mac(kaux, b)
end

return {
    toHex = toHex,
    fromHex = fromHex,
    compare = compare,
}
