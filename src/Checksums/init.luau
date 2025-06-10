--!strict

local Algorithms = table.freeze {
	CRC32 = require(script:WaitForChild("CRC32")),
	Adler = require(script:WaitForChild("Adler"))
}

return Algorithms