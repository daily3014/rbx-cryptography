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

	To generate random numbers, CSPRNG creates a 64 byte block
	of random data and takes however many bytes is needed for 
	the output data i.e 8 bytes for a float/integer, 20 bytes for a 20
	character long string. Once all 64 bytes are used up, an
	another block is generated which may slow down the call.
	The generated block can be extended to an arbitrary length
	with Blake3 by enabling CSPRNG.BlockExpansion

	Developers can renew the state and add their own entropy by passing it as a buffer in CSRNG.Reseed/CSPRNG.AddEntropyProvider

	CSPRNG will also automatically renew the state after a certain amount of calls controlled
	by CSRNG.RekeyAfter (by default 1024, so 64 * 1024 bytes without block expansion)
--]]

-- Generate a random number between 0 and 1
print(CSPRNG.Random()) 

-- Generate a random number between 10 and 100
print(CSPRNG.RandomNumber(10, 100))

-- Generate a random number between 0 and 100
print(CSPRNG.RandomNumber(100))

-- Generate a random key for EdDSA
local PrivateKey = CSPRNG.Ed25519Random()

--[[
	Reseed the CSPRNG instance with custom entropy for extra security
	You can pass any buffer as long as it's 1024 bytes or less, althought not all of it
	may be used as the normal entropy is added first, custom has last priority
	You can also use CSPRNG.AddEntropyProvider to add a function that returns a buffer
	AddEntropyProvider will only be called once its used up all the entropy from init
	So you need to do `CSPRNG.Reseed(CustomEntropy())` if you want it from the gecko
]]
local LastPlayerWeaponUse = 12317127.123
local AmountOfRemoteCalls = 1282
local CustomEntropy = buffer.create(8 + 4)
buffer.writef64(CustomEntropy, 0, LastPlayerWeaponUse) -- 8 bytes
buffer.writeu32(CustomEntropy, 8, AmountOfRemoteCalls) -- 4 bytes

local Provider = function()
	return CustomEntropy
end

CSPRNG.AddEntropyProvider(Provider)
CSPRNG.RemoveEntropyProvider(Provider)
CSPRNG.Reseed(CustomEntropy)
