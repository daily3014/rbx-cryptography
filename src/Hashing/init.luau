--!strict

local Lazy = require("./Lazy")

export type Algorithms = {
	HMAC: typeof(require("@self/HMAC")),
	HKDF: typeof(require("@self/HKDF")),
	KMAC: typeof(require("@self/KMAC")),
	MD5: typeof(require("@self/MD5")),
	SHA1: typeof(require("@self/SHA1")),
	SHA2: typeof(require("@self/SHA2")),
	SHA3: typeof(require("@self/SHA3")),
	Blake2b: typeof(require("@self/Blake2b")),
	Blake3: typeof(require("@self/Blake3")),
}

local Algorithms: Algorithms = Lazy.Group("Hashing", {
	HMAC = function() return require("@self/HMAC") end,
	HKDF = function() return require("@self/HKDF") end,
	KMAC = function() return require("@self/KMAC") end,
	MD5 = function() return require("@self/MD5") end,
	SHA1 = function() return require("@self/SHA1") end,
	SHA2 = function() return require("@self/SHA2") end,
	SHA3 = function() return require("@self/SHA3") end,
	Blake2b = function() return require("@self/Blake2b") end,
	Blake3 = function() return require("@self/Blake3") end,
})

return Algorithms
