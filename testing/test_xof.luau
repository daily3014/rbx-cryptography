local old_xof = require("../src/Verification/MlDSA/_XOF")
local xof = require("../src/Verification/MlDSA/XOF")

local hex = require("../src/Utilities/Conversions").ToHex

local msg = buffer.fromstring("HEllo world lol")

xof.Absorb128(msg)
old_xof.Absorb128(msg)

print("new:", hex(xof.Squeeze128(64)))
print("old:", hex(old_xof.Squeeze128(64)))
