--!strict

local Lazy = require("./Lazy")

export type Algorithms = {
	EdDSA: typeof(require("@self/EdDSA")),
	MlDSA: typeof(require("@self/MlDSA")),
	MlKEM: typeof(require("@self/MlKEM")),
}

local Algorithms: Algorithms = Lazy.Group("Verification", {
	EdDSA = function() return require("@self/EdDSA") end,
	MlDSA = function() return require("@self/MlDSA") end,
	MlKEM = function() return require("@self/MlKEM") end,
})

return Algorithms
