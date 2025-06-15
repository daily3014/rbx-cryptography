--!strict 

local Cryptography = table.freeze({
	Hashing = require("@self/Hashing"),
	Checksums = require("@self/Checksums"),
	Utilities = require("@self/Utilities"),
	Encryption = require("@self/Encryption"),
	Verification = require("@self/Verification")
})

return Cryptography