--!strict

local Lazy = require("./Lazy")
local Functions = require("@self/Functions")

export type Algorithms = {
	Conversions: typeof(require("@self/Conversions")),
	Base64: typeof(require("@self/Base64")),
	CSPRNG: typeof(require("@self/CSPRNG")),
	XOR: typeof(require("@self/XOR")),

	CtCompare: typeof(Functions.CtCompare),
	CtCompareMask: typeof(Functions.CtCompareMask),
	CtNonZeroMask: typeof(Functions.CtNonZeroMask),
	CtIsAllZero: typeof(Functions.CtIsAllZero),
	CtSwapBuffers: typeof(Functions.CtSwapBuffers),
	CtCopyIf: typeof(Functions.CtCopyIf),
	CtIsZeroMask: typeof(Functions.CtIsZeroMask),
	CtEqMask: typeof(Functions.CtEqMask),
	CtLtMask: typeof(Functions.CtLtMask),
	CtSelect: typeof(Functions.CtSelect),
	CtSwap: typeof(Functions.CtSwap),
	CtSelectBuffer: typeof(Functions.CtSelectBuffer),
	Concatenate: typeof(Functions.Concatenate),
}

local Algorithms: Algorithms = Lazy.Group("Utilities", {
	Conversions = function() return require("@self/Conversions") end,
	Base64 = function() return require("@self/Base64") end,
	CSPRNG = function() return require("@self/CSPRNG") end,
	XOR = function() return require("@self/XOR") end,

	CtCompare = function() return Functions.CtCompare end,
	CtCompareMask = function() return Functions.CtCompareMask end,
	CtNonZeroMask = function() return Functions.CtNonZeroMask end,
	CtIsAllZero = function() return Functions.CtIsAllZero end,
	CtSwapBuffers = function() return Functions.CtSwapBuffers end,
	CtCopyIf = function() return Functions.CtCopyIf end,
	CtIsZeroMask = function() return Functions.CtIsZeroMask end,
	CtEqMask = function() return Functions.CtEqMask end,
	CtLtMask = function() return Functions.CtLtMask end,
	CtSelect = function() return Functions.CtSelect end,
	CtSwap = function() return Functions.CtSwap end,
	CtSelectBuffer = function() return Functions.CtSelectBuffer end,
	Concatenate = function() return Functions.Concatenate end,
})

return Algorithms
