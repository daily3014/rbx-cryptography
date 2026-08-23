--!strict

local Functions = require("@self/Functions")

local Algorithms = table.freeze({
	Conversions = require("@self/Conversions"),
	Base64 = require("@self/Base64"),
	CSPRNG = require("@self/CSPRNG"),
	XOR = require("@self/XOR"),

	CtCompare = Functions.CtCompare,
	CtIsAllZero = Functions.CtIsAllZero,
	CtSwapBuffers = Functions.CtSwapBuffers,
	CtCopyIf = Functions.CtCopyIf,
	CtIsZeroMask = Functions.CtIsZeroMask,
	CtEqMask = Functions.CtEqMask,
	CtLtMask = Functions.CtLtMask,
	CtSelect = Functions.CtSelect,
	CtSwap = Functions.CtSwap,
	CtSelectBuffer = Functions.CtSelectBuffer,
	Concatenate = Functions.Concatenate
})

return Algorithms