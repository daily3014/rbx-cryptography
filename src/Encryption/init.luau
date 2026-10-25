--!strict

local Lazy = require("./Lazy")

export type Algorithms = {
	AEAD: typeof(require("@self/AEAD")),
	AES: typeof(require("@self/AES")),
}

local Algorithms: Algorithms = Lazy.Group("Encryption", {
	AEAD = function() return require("@self/AEAD") end,
	AES = function() return require("@self/AES") end,
})

return Algorithms
