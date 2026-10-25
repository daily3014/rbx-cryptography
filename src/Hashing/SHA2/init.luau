--[[
	Cryptography library: SHA2 Family
--]]

--!strict

local Lazy = require("../Lazy")

export type Algorithms = {
	SHA224: typeof(require("@self/SHA224")),
	SHA256: typeof(require("@self/SHA256")),
	SHA384: typeof(require("@self/SHA384")),
	SHA512: typeof(require("@self/SHA512").SHA512),
}

local Algorithms: Algorithms = Lazy.Group("SHA2", {
	SHA224 = function() return require("@self/SHA224") end,
	SHA256 = function() return require("@self/SHA256") end,
	SHA384 = function() return require("@self/SHA384") end,
	SHA512 = function() return require("@self/SHA512").SHA512 end,
})

return Algorithms
