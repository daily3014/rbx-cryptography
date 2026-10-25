--!strict

local Lazy = require("@self/Lazy")

export type Cryptography = {
	Hashing: typeof(require("@self/Hashing")),
	Utilities: typeof(require("@self/Utilities")),
	Encryption: typeof(require("@self/Encryption")),
	Verification: typeof(require("@self/Verification")),

	Preload: (...string) -> (),
}

local Preload: (...string) -> ()

local Cryptography: Cryptography = Lazy.Group("Cryptography", {
	Hashing = function() return require("@self/Hashing") end,
	Utilities = function() return require("@self/Utilities") end,
	Encryption = function() return require("@self/Encryption") end,
	Verification = function() return require("@self/Verification") end,

	Preload = function() return Preload end,
})

function Preload(...: string)
	if select("#", ...) == 0 then
		Lazy.LoadAll(Cryptography)
		return
	end

	for Index = 1, select("#", ...) do
		local Path = select(Index, ...)
		local Current: any = Cryptography

		for Part in string.gmatch(Path, "[^/]+") do
			Current = Current[Part]
		end

		if Lazy.IsGroup(Current) then
			Lazy.LoadAll(Current)
		end
	end
end

return Cryptography
