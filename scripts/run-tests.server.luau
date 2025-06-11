_G.NOCOLOR = 1

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local DevPackages = ReplicatedStorage.DevPackages

local Jest = require(DevPackages:WaitForChild("Jest"))

local runCLIOptions = {
	verbose = true,
	ci = false,
	testTimeout = 60_000, -- 60 seconds
}

local projects = {
	ReplicatedStorage.Tests,
}

Jest.runCLI(script, runCLIOptions, projects):await()

return nil
