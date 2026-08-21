--!strict

local Functions = require("@self/Functions")

local Algorithms = table.freeze({
	Conversions = require("@self/Conversions"),
	Base64 = require("@self/Base64"),
	CSPRNG = require("@self/CSPRNG"),
	XOR = require("@self/XOR"),

	CtCompare = Functions.CtCompare,
	Concatenate = Functions.Concatenate
})

return Algorithms