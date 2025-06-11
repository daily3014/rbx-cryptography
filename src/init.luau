--!strict

local Cryptography = table.freeze({
	Hashing = require(script:WaitForChild("Hashing")),
	Checksums = require(script:WaitForChild("Checksums")),
	Utilities = require(script:WaitForChild("Utilities")),
	Encryption = require(script:WaitForChild("Encryption")),
	Verification = require(script:WaitForChild("Verification")),
})

return Cryptography
