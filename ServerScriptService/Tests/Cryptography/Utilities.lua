-- @ScriptType: ModuleScript
--!strict

local Algorithms = table.freeze({
	RandomString = require("@self/RandomString"),
	Conversions = require("@self/Conversions"),
	Base64 = require("@self/Base64"),
	CSPRNG = require("@self/CSPRNG")
})

return Algorithms