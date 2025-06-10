--!strict

local Algorithms = table.freeze({
	HMAC = require(script:WaitForChild("HMAC")),
	MD5 = require(script:WaitForChild("MD5")),
	SHA1 = require(script:WaitForChild("SHA1")),
	SHA2 = require(script:WaitForChild("SHA2")),
	Keccak = require(script:WaitForChild("Keccak")),
	XXH32 = require(script:WaitForChild("XXH32")),
	Blake2b = require(script:WaitForChild("Blake2b")),
})

return Algorithms
