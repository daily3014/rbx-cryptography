--!strict

local Algorithms = table.freeze({
	ChaCha20 = require(script:WaitForChild("ChaCha20")),
	AES = require(script:WaitForChild("AES")),
})

return Algorithms
