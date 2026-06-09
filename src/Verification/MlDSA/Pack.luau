--[=[
	Hint bit packing and unpacking utilities

	Serializes ML-DSA hint vectors to and from the Omega + K byte
	signature encoding defined in FIPS 204.

	Example usage:
		local BitPacking = require(script)

		local H = buffer.create(4 * 256 * 4)
		local Encoded = buffer.create(80 + 4) -- Omega + K for ML-DSA-44
		BitPacking.EncodeHintBits(H, Encoded, 4, 80)
		local Failed = BitPacking.DecodeHintBits(Encoded, H, 4, 80)
--]=]

--!strict
--!optimize 2
--!native

local N = 256

local BitPacking = {}

function BitPacking.EncodeHintBits(H: buffer, Arr: buffer, K: number, Omega: number)
	buffer.fill(Arr, 0, 0, Omega + K)

	local Idx = 0

	for I = 0, K - 1 do
		local PolyOffset = I * N * 4

		for J = 0, N - 1 do
			if buffer.readu32(H, PolyOffset + J * 4) ~= 0 then
				buffer.writeu8(Arr, Idx, J)
				Idx += 1

				if Idx >= Omega then
					break
				end
			end
		end

		buffer.writeu8(Arr, Omega + I, Idx)
	end
end

function BitPacking.DecodeHintBits(Arr: buffer, H: buffer, K: number, Omega: number): boolean
	buffer.fill(H, 0, 0, K * N * 4)

	local Idx = 0
	local Failed = false

	for I = 0, K - 1 do
		local PolyOffset = I * N * 4
		local Till = buffer.readu8(Arr, Omega + I)

		if Till < Idx or Till > Omega then
			Failed = true
		end

		if not Failed then
			local Prev = -1

			for J = Idx, Till - 1 do
				local Position = buffer.readu8(Arr, J)

				if Position <= Prev or Position >= N then
					Failed = true
					break
				end

				buffer.writeu32(H, PolyOffset + Position * 4, 1)
				Prev = Position
			end
		end

		Idx = Till
	end

	if not Failed then
		for I = Idx, Omega - 1 do
			if buffer.readu8(Arr, I) ~= 0 then
				Failed = true
				break
			end
		end
	end

	return Failed
end

return BitPacking