--!strict

local Algorithms = table.freeze({
	EdDSA = require("@self/EdDSA"),
	MlDSA = require("@self/MlDSA"),
	MlKEM = require("@self/MlKEM"),
})

return Algorithms