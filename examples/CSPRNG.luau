--[[ Cryptography library: CSPRNG Example ]]--
--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")

-- Get the library
local Cryptography = require(ReplicatedStorage:WaitForChild("Cryptography"))
local CSPRNG = Cryptography.Utilities.CSPRNG
-- Also accessible through EdDSA, MLKEM andMLDSA: Verification.EdDSA/MLKEM/MLDSA.CSPRNG

--[[
	CSPRNG stands for:
		Cryptographically Secure
		Pseudo Random Number Generator

	CSPRNG works by creating entropy out of various factors
	then using the entropy as the internal state of the RNG

	To generate random numbers, CSPRNG keeps a keystream pool produced from the
	internal state with Blake3, and serves however many bytes each call needs.
	When the pool runs out, a new one is generated. The state automatically
	renews itself from fresh entropy in the background as output is consumed.
--]]

-- Generate a random number between 0 and 1
print(CSPRNG.Random()) 

-- Generate a random number between 10 and 100
print(CSPRNG.RandomNumber(10, 100))

-- Generate a random number between 0 and 100
print(CSPRNG.RandomNumber(100))

-- Generate a random key for EdDSA
local PrivateKey = CSPRNG.RandomBytes(32)

--[[
	Mix your own entropy into the state with CSPRNG.AddEntropy. The buffer may be
	any length, it is folded into the existing state (never replaces it) and the
	pool is regenerated immediately. Calling it with no argument just refreshes
	from the built-in sources. Feed it whatever unpredictable game state you have,
	the more, and the more often, the better.
]]
local LastPlayerWeaponUse = 12317127.123
local AmountOfRemoteCalls = 1282
local CustomEntropy = buffer.create(8 + 4)
buffer.writef64(CustomEntropy, 0, LastPlayerWeaponUse)
buffer.writeu32(CustomEntropy, 8, AmountOfRemoteCalls)

CSPRNG.AddEntropy(CustomEntropy)
