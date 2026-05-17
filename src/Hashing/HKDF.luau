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

local HMAC = require("./HMAC")

type HashFunction = (...any) -> (string, buffer)

local function HKDF(IKM: buffer, Salt: buffer?, Info: buffer?, Length: number, HashFunction: HashFunction, BlockSize: number, HashLength: number, _BigEndian: boolean?): buffer
	local ActualSalt = if Salt and buffer.len(Salt) > 0 then Salt else buffer.create(HashLength)
	local ActualInfo = Info or buffer.create(0)
	local InfoLength = buffer.len(ActualInfo)

	local Iterations = math.ceil(Length / HashLength)
	if Iterations > 255 then
		error(`HKDF output length {Length} exceeds maximum {255 * HashLength}`)
	end

	local _, PRK = HMAC(IKM, ActualSalt, HashFunction, BlockSize)

	local MaxInputSize = HashLength + InfoLength + 1
	local Input = buffer.create(MaxInputSize)

	local OKM = buffer.create(Length)
	local PreviousLength = 0

	for Index = 1, Iterations do
		local InputSize = PreviousLength + InfoLength + 1

		if InfoLength > 0 then
			buffer.copy(Input, PreviousLength, ActualInfo)
		end
		buffer.writeu8(Input, PreviousLength + InfoLength, Index)

		local InputSlice: buffer
		if InputSize == MaxInputSize then
			InputSlice = Input
		else
			InputSlice = buffer.create(InputSize)
			buffer.copy(InputSlice, 0, Input, 0, InputSize)
		end

		local _, Block = HMAC(InputSlice, PRK, HashFunction, BlockSize)

		local Offset = (Index - 1) * HashLength
		buffer.copy(OKM, Offset, Block, 0, math.min(HashLength, Length - Offset))

		buffer.copy(Input, 0, Block)
		PreviousLength = HashLength
	end

	return OKM
end

return HKDF