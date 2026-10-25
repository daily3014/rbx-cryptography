--[=[
	Cryptography library: HKDF (HMAC-based Key Derivation Function)

	RFC 5869 extract-then-expand key derivation built on HMAC.

	Return type: buffer
	Example usage:
		local IKM = buffer.fromstring("input key material")
		local OKM = HKDF(IKM, Salt, Info, 32, SHA2.SHA256, 64, 32)
--]=]

--!strict
--!optimize 2
--!native

local Compute = require("./HMACCore").Compute

type HashFunction = (...any) -> (string, buffer)

local function HKDF(IKM: buffer, Salt: buffer?, Info: buffer?, Length: number, HashFunction: HashFunction, BlockSize: number, HashLength: number, _BigEndian: boolean?): buffer
	local ActualSalt = if Salt and buffer.len(Salt) > 0 then Salt else buffer.create(HashLength)
	local InfoLength = if Info then buffer.len(Info) else 0

	local Iterations = math.ceil(Length / HashLength)
	if Iterations > 255 then
		error(`HKDF output length {Length} exceeds maximum {255 * HashLength}`)
	end

	local PRK = Compute(IKM, ActualSalt, HashFunction, BlockSize)

	local OKM = buffer.create(Length)

	local First = buffer.create(InfoLength + 1)
	if Info and InfoLength > 0 then
		buffer.copy(First, 0, Info, 0, InfoLength)
	end
	buffer.writeu8(First, InfoLength, 1)

	local Block = Compute(First, PRK, HashFunction, BlockSize)
	buffer.copy(OKM, 0, Block, 0, math.min(HashLength, Length))

	if Iterations > 1 then
		local Input = buffer.create(HashLength + InfoLength + 1)
		if Info and InfoLength > 0 then
			buffer.copy(Input, HashLength, Info, 0, InfoLength)
		end

		for Index = 2, Iterations do
			buffer.copy(Input, 0, Block, 0, HashLength)
			buffer.writeu8(Input, HashLength + InfoLength, Index)

			Block = Compute(Input, PRK, HashFunction, BlockSize)

			local Offset = (Index - 1) * HashLength
			buffer.copy(OKM, Offset, Block, 0, math.min(HashLength, Length - Offset))
		end
	end

	return OKM
end

return HKDF
