-- @ScriptType: ModuleScript
--!strict

local Algorithms = table.freeze({
	CRC32 = require("@self/CRC32"),
	Adler = require("@self/Adler")
})

return Algorithms