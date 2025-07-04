--[=[
	Cryptography library: Cryptographically Secure RNG
	
	Usage:
		local RandomFloat = CSPRNG.Random()
		local RandomInt = CSPRNG.RandomInt(1, 100)
		local RandomNumber = CSPRNG.RandomNumber(0.5, 10.5)
		local RandomBytes = CSPRNG.RandomBytes(32)
		local RandomHex = CSPRNG.RandomHex(16)
		local FastString = CSPRNG.RandomString(16, false)
		local FastBuffer = CSPRNG.RandomString(32, true)
		
		local Ed25519Bytes = CSPRNG.Ed25519RandomBytes()
		local Ed25519Clamped = CSPRNG.Ed25519ClampedBytes(SomeBuffer)
		local Ed25519Random = CSPRNG.Ed25519Random()
		
		CSPRNG.Reseed()
--]=]

--!strict

return require("../Verification/EdDSA/CSPRNG")