-- @ScriptType: ModuleScript
--!strict

local Algorithms = table.freeze({
	HMAC = require("@self/HMAC"),
	KMAC = require("@self/KMAC"),
	MD5 = require("@self/MD5"),
	SHA1 = require("@self/SHA1"),
	SHA2 = require("@self/SHA2"),
	SHA3 = require("@self/SHA3"),
	XXH32 = require("@self/XXH32"),
	Blake2b = require("@self/Blake2b"),
	Blake3 = require("@self/Blake3"),
	MurMur = require("@self/Murmur")
})

return Algorithms