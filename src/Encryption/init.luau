--!strict

local Algorithms = table.freeze({
	AEAD = require("@self/AEAD"),
	AES = require("@self/AES"),
	XOR = require("@self/XOR"),
	Simon = require("@self/Simon"),
	Speck = require("@self/Speck")
})

return Algorithms