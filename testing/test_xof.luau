local old_xof = require("../src/Verification/MlDSA/_XOF")
local xof = require("../src/Verification/MlDSA/XOF")

local hex = require("../src/Utilities/Conversions").ToHex

local msg = buffer.fromstring("HEllo world lol")

for i = 1, 512 do
	xof.Reset128()
	old_xof.Reset128()

	xof.Absorb128(msg)
	old_xof.Absorb128(msg)


	local new, old = hex(xof.Squeeze128(i)), hex(old_xof.Squeeze128(i))

	if new ~= old then
		print(new)
		print(old)
		print(`didnt match at {i} bytes`)
		break
	end
end
