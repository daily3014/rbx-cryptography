--[=[
	Bit packing and unpacking utilities
	
	Serializes polynomials to byte arrays with various bit widths.
	Supports encoding/decoding of polynomial coefficients and hint bits.

	Example usage:
		local BitPacking = require(script)
		
		local Poly = buffer.create(256 * 4)
		local Encoded = buffer.create(96) -- For 3-bit encoding
		BitPacking.Encode(Poly, Encoded, 3)
		BitPacking.Decode(Encoded, Poly, 3)
--]=]

--!strict
--!optimize 2
--!native

local N = 256
local POLY_BYTES = N * 4

local BitPacking = {}

function BitPacking.Encode(Poly: buffer, Arr: buffer, Sbw: number)
	local ArrLen = buffer.len(Arr)
	buffer.fill(Arr, 0, 0, ArrLen)

	if Sbw == 3 then
		for I = 0, 31 do
			local PBase = I * 32
			local BBase = I * 3

			local P0 = bit32.band(buffer.readu32(Poly, PBase), 0x7)
			local P1 = bit32.band(buffer.readu32(Poly, PBase + 4), 0x7)
			local P2 = bit32.band(buffer.readu32(Poly, PBase + 8), 0x7)
			local P3 = bit32.band(buffer.readu32(Poly, PBase + 12), 0x7)
			local P4 = bit32.band(buffer.readu32(Poly, PBase + 16), 0x7)
			local P5 = bit32.band(buffer.readu32(Poly, PBase + 20), 0x7)
			local P6 = bit32.band(buffer.readu32(Poly, PBase + 24), 0x7)
			local P7 = bit32.band(buffer.readu32(Poly, PBase + 28), 0x7)

			local Byte0 = bit32.bor(P0, bit32.lshift(P1, 3), bit32.lshift(P2, 6))
			local Byte1 = bit32.bor(bit32.rshift(P2, 2), bit32.lshift(P3, 1), bit32.lshift(P4, 4), bit32.lshift(P5, 7))
			local Byte2 = bit32.bor(bit32.rshift(P5, 1), bit32.lshift(P6, 2), bit32.lshift(P7, 5))

			buffer.writeu8(Arr, BBase, Byte0)
			buffer.writeu8(Arr, BBase + 1, Byte1)
			buffer.writeu8(Arr, BBase + 2, Byte2)
		end

	elseif Sbw == 4 then
		for I = 0, 31 do
			local PBase = I * 32
			local BBase = I * 4

			local Word = buffer.readu32(Poly, PBase)
			local P0 = bit32.band(Word, 0xF)
			Word = buffer.readu32(Poly, PBase + 4)
			local P1 = bit32.band(Word, 0xF)
			Word = buffer.readu32(Poly, PBase + 8)
			local P2 = bit32.band(Word, 0xF)
			Word = buffer.readu32(Poly, PBase + 12)
			local P3 = bit32.band(Word, 0xF)
			Word = buffer.readu32(Poly, PBase + 16)
			local P4 = bit32.band(Word, 0xF)
			Word = buffer.readu32(Poly, PBase + 20)
			local P5 = bit32.band(Word, 0xF)
			Word = buffer.readu32(Poly, PBase + 24)
			local P6 = bit32.band(Word, 0xF)
			Word = buffer.readu32(Poly, PBase + 28)
			local P7 = bit32.band(Word, 0xF)

			buffer.writeu32(Arr, BBase, bit32.bor(
				P0, bit32.lshift(P1, 4), bit32.lshift(P2, 8), bit32.lshift(P3, 12),
				bit32.lshift(P4, 16), bit32.lshift(P5, 20), bit32.lshift(P6, 24), bit32.lshift(P7, 28)
				))
		end

	elseif Sbw == 6 then
		for I = 0, 63 do
			local PBase = I * 16
			local BBase = I * 3

			local P0 = bit32.band(buffer.readu32(Poly, PBase), 0x3F)
			local P1 = bit32.band(buffer.readu32(Poly, PBase + 4), 0x3F)
			local P2 = bit32.band(buffer.readu32(Poly, PBase + 8), 0x3F)
			local P3 = bit32.band(buffer.readu32(Poly, PBase + 12), 0x3F)

			local Packed = bit32.bor(P0, bit32.lshift(P1, 6), bit32.lshift(P2, 12), bit32.lshift(P3, 18))

			buffer.writeu8(Arr, BBase, bit32.band(Packed, 0xFF))
			buffer.writeu8(Arr, BBase + 1, bit32.band(bit32.rshift(Packed, 8), 0xFF))
			buffer.writeu8(Arr, BBase + 2, bit32.rshift(Packed, 16))
		end

	elseif Sbw == 10 then
		for I = 0, 63 do
			local PBase = I * 16
			local BBase = I * 5

			local P0 = bit32.band(buffer.readu32(Poly, PBase), 0x3FF)
			local P1 = bit32.band(buffer.readu32(Poly, PBase + 4), 0x3FF)
			local P2 = bit32.band(buffer.readu32(Poly, PBase + 8), 0x3FF)
			local P3 = bit32.band(buffer.readu32(Poly, PBase + 12), 0x3FF)

			local Lo = bit32.bor(P0, bit32.lshift(P1, 10), bit32.lshift(P2, 20))
			local Hi = bit32.bor(bit32.rshift(P2, 12), bit32.lshift(P3, 8))

			buffer.writeu32(Arr, BBase, Lo)
			buffer.writeu8(Arr, BBase + 4, bit32.band(Hi, 0xFF))
		end

	elseif Sbw == 13 then
		for I = 0, 31 do
			local PBase = I * 32
			local BBase = I * 13

			local P0 = bit32.band(buffer.readu32(Poly, PBase), 0x1FFF)
			local P1 = bit32.band(buffer.readu32(Poly, PBase + 4), 0x1FFF)
			local P2 = bit32.band(buffer.readu32(Poly, PBase + 8), 0x1FFF)
			local P3 = bit32.band(buffer.readu32(Poly, PBase + 12), 0x1FFF)
			local P4 = bit32.band(buffer.readu32(Poly, PBase + 16), 0x1FFF)
			local P5 = bit32.band(buffer.readu32(Poly, PBase + 20), 0x1FFF)
			local P6 = bit32.band(buffer.readu32(Poly, PBase + 24), 0x1FFF)
			local P7 = bit32.band(buffer.readu32(Poly, PBase + 28), 0x1FFF)

			local W0 = bit32.bor(P0, bit32.lshift(P1, 13), bit32.lshift(P2, 26))
			local W1 = bit32.bor(bit32.rshift(P2, 6), bit32.lshift(P3, 7), bit32.lshift(P4, 20))
			local W2 = bit32.bor(bit32.rshift(P4, 12), bit32.lshift(P5, 1), bit32.lshift(P6, 14), bit32.lshift(P7, 27))
			local W3 = bit32.rshift(P7, 5)

			buffer.writeu32(Arr, BBase, W0)
			buffer.writeu32(Arr, BBase + 4, W1)
			buffer.writeu32(Arr, BBase + 8, W2)
			buffer.writeu8(Arr, BBase + 12, W3)
		end

	elseif Sbw == 18 then
		for I = 0, 63 do
			local PBase = I * 16
			local BBase = I * 9

			local P0 = bit32.band(buffer.readu32(Poly, PBase), 0x3FFFF)
			local P1 = bit32.band(buffer.readu32(Poly, PBase + 4), 0x3FFFF)
			local P2 = bit32.band(buffer.readu32(Poly, PBase + 8), 0x3FFFF)
			local P3 = bit32.band(buffer.readu32(Poly, PBase + 12), 0x3FFFF)

			local W0 = bit32.bor(P0, bit32.lshift(P1, 18))
			local W1 = bit32.bor(bit32.rshift(P1, 14), bit32.lshift(P2, 4), bit32.lshift(P3, 22))
			local W2 = bit32.rshift(P3, 10)

			buffer.writeu32(Arr, BBase, W0)
			buffer.writeu32(Arr, BBase + 4, W1)
			buffer.writeu8(Arr, BBase + 8, W2)
		end

	elseif Sbw == 20 then
		for I = 0, 63 do
			local PBase = I * 16
			local BBase = I * 10

			local P0 = bit32.band(buffer.readu32(Poly, PBase), 0xFFFFF)
			local P1 = bit32.band(buffer.readu32(Poly, PBase + 4), 0xFFFFF)
			local P2 = bit32.band(buffer.readu32(Poly, PBase + 8), 0xFFFFF)
			local P3 = bit32.band(buffer.readu32(Poly, PBase + 12), 0xFFFFF)

			local W0 = bit32.bor(P0, bit32.lshift(P1, 20))
			local W1 = bit32.bor(bit32.rshift(P1, 12), bit32.lshift(P2, 8), bit32.lshift(P3, 28))
			local W2 = bit32.rshift(P3, 4)

			buffer.writeu32(Arr, BBase, W0)
			buffer.writeu32(Arr, BBase + 4, W1)
			buffer.writeu16(Arr, BBase + 8, W2)
		end

	else
		local Mask = bit32.lshift(1, Sbw) - 1
		local BitPos = 0

		for I = 0, N - 1 do
			local Value = bit32.band(buffer.readu32(Poly, I * 4), Mask)
			local BitsRemaining = Sbw

			while BitsRemaining > 0 do
				local ByteIdx = bit32.rshift(BitPos, 3)
				local BitOffset = bit32.band(BitPos, 7)
				local BitsInByte = math.min(BitsRemaining, 8 - BitOffset)

				local BitMask = bit32.lshift(1, BitsInByte) - 1
				local Bits = bit32.band(Value, BitMask)
				local Current = buffer.readu8(Arr, ByteIdx)

				buffer.writeu8(Arr, ByteIdx, bit32.bor(Current, bit32.lshift(Bits, BitOffset)))

				Value = bit32.rshift(Value, BitsInByte)
				BitPos += BitsInByte
				BitsRemaining -= BitsInByte
			end
		end
	end
end

function BitPacking.Decode(Arr: buffer, Poly: buffer, Sbw: number)
	buffer.fill(Poly, 0, 0, POLY_BYTES)

	if Sbw == 3 then
		for I = 0, 31 do
			local BBase = I * 3
			local PBase = I * 32

			local B0 = buffer.readu8(Arr, BBase)
			local B1 = buffer.readu8(Arr, BBase + 1)
			local B2 = buffer.readu8(Arr, BBase + 2)

			buffer.writeu32(Poly, PBase, bit32.band(B0, 0x7))
			buffer.writeu32(Poly, PBase + 4, bit32.band(bit32.rshift(B0, 3), 0x7))
			buffer.writeu32(Poly, PBase + 8, bit32.bor(bit32.rshift(B0, 6), bit32.lshift(bit32.band(B1, 0x1), 2)))
			buffer.writeu32(Poly, PBase + 12, bit32.band(bit32.rshift(B1, 1), 0x7))
			buffer.writeu32(Poly, PBase + 16, bit32.band(bit32.rshift(B1, 4), 0x7))
			buffer.writeu32(Poly, PBase + 20, bit32.bor(bit32.rshift(B1, 7), bit32.lshift(bit32.band(B2, 0x3), 1)))
			buffer.writeu32(Poly, PBase + 24, bit32.band(bit32.rshift(B2, 2), 0x7))
			buffer.writeu32(Poly, PBase + 28, bit32.rshift(B2, 5))
		end

	elseif Sbw == 4 then
		for I = 0, 31 do
			local BBase = I * 4
			local PBase = I * 32

			local Word = buffer.readu32(Arr, BBase)

			buffer.writeu32(Poly, PBase, bit32.band(Word, 0xF))
			buffer.writeu32(Poly, PBase + 4, bit32.band(bit32.rshift(Word, 4), 0xF))
			buffer.writeu32(Poly, PBase + 8, bit32.band(bit32.rshift(Word, 8), 0xF))
			buffer.writeu32(Poly, PBase + 12, bit32.band(bit32.rshift(Word, 12), 0xF))
			buffer.writeu32(Poly, PBase + 16, bit32.band(bit32.rshift(Word, 16), 0xF))
			buffer.writeu32(Poly, PBase + 20, bit32.band(bit32.rshift(Word, 20), 0xF))
			buffer.writeu32(Poly, PBase + 24, bit32.band(bit32.rshift(Word, 24), 0xF))
			buffer.writeu32(Poly, PBase + 28, bit32.rshift(Word, 28))
		end

	elseif Sbw == 6 then
		for I = 0, 63 do
			local BBase = I * 3
			local PBase = I * 16

			local B0 = buffer.readu8(Arr, BBase)
			local B1 = buffer.readu8(Arr, BBase + 1)
			local B2 = buffer.readu8(Arr, BBase + 2)

			local Packed = bit32.bor(B0, bit32.lshift(B1, 8), bit32.lshift(B2, 16))

			buffer.writeu32(Poly, PBase, bit32.band(Packed, 0x3F))
			buffer.writeu32(Poly, PBase + 4, bit32.band(bit32.rshift(Packed, 6), 0x3F))
			buffer.writeu32(Poly, PBase + 8, bit32.band(bit32.rshift(Packed, 12), 0x3F))
			buffer.writeu32(Poly, PBase + 12, bit32.rshift(Packed, 18))
		end

	elseif Sbw == 10 then
		for I = 0, 63 do
			local BBase = I * 5
			local PBase = I * 16

			local Lo = buffer.readu32(Arr, BBase)
			local Hi = buffer.readu8(Arr, BBase + 4)

			buffer.writeu32(Poly, PBase, bit32.band(Lo, 0x3FF))
			buffer.writeu32(Poly, PBase + 4, bit32.band(bit32.rshift(Lo, 10), 0x3FF))
			buffer.writeu32(Poly, PBase + 8, bit32.bor(bit32.rshift(Lo, 20), bit32.lshift(bit32.band(Hi, 0x3), 12)))
			buffer.writeu32(Poly, PBase + 12, bit32.rshift(Hi, 2))
		end

	elseif Sbw == 13 then
		for I = 0, 31 do
			local BBase = I * 13
			local PBase = I * 32

			local W0 = buffer.readu32(Arr, BBase)
			local W1 = buffer.readu32(Arr, BBase + 4)
			local W2 = buffer.readu32(Arr, BBase + 8)
			local W3 = buffer.readu8(Arr, BBase + 12)

			buffer.writeu32(Poly, PBase, bit32.band(W0, 0x1FFF))
			buffer.writeu32(Poly, PBase + 4, bit32.band(bit32.rshift(W0, 13), 0x1FFF))
			buffer.writeu32(Poly, PBase + 8, bit32.bor(bit32.rshift(W0, 26), bit32.lshift(bit32.band(W1, 0x7F), 6)))
			buffer.writeu32(Poly, PBase + 12, bit32.band(bit32.rshift(W1, 7), 0x1FFF))
			buffer.writeu32(Poly, PBase + 16, bit32.bor(bit32.rshift(W1, 20), bit32.lshift(bit32.band(W2, 0x1), 12)))
			buffer.writeu32(Poly, PBase + 20, bit32.band(bit32.rshift(W2, 1), 0x1FFF))
			buffer.writeu32(Poly, PBase + 24, bit32.band(bit32.rshift(W2, 14), 0x1FFF))
			buffer.writeu32(Poly, PBase + 28, bit32.bor(bit32.rshift(W2, 27), bit32.lshift(W3, 5)))
		end

	elseif Sbw == 18 then
		for I = 0, 63 do
			local BBase = I * 9
			local PBase = I * 16

			local W0 = buffer.readu32(Arr, BBase)
			local W1 = buffer.readu32(Arr, BBase + 4)
			local W2 = buffer.readu8(Arr, BBase + 8)

			buffer.writeu32(Poly, PBase, bit32.band(W0, 0x3FFFF))
			buffer.writeu32(Poly, PBase + 4, bit32.bor(bit32.rshift(W0, 18), bit32.lshift(bit32.band(W1, 0xF), 14)))
			buffer.writeu32(Poly, PBase + 8, bit32.band(bit32.rshift(W1, 4), 0x3FFFF))
			buffer.writeu32(Poly, PBase + 12, bit32.bor(bit32.rshift(W1, 22), bit32.lshift(W2, 10)))
		end

	elseif Sbw == 20 then
		for I = 0, 63 do
			local BBase = I * 10
			local PBase = I * 16

			local W0 = buffer.readu32(Arr, BBase)
			local W1 = buffer.readu32(Arr, BBase + 4)
			local W2 = buffer.readu16(Arr, BBase + 8)

			buffer.writeu32(Poly, PBase, bit32.band(W0, 0xFFFFF))
			buffer.writeu32(Poly, PBase + 4, bit32.bor(bit32.rshift(W0, 20), bit32.lshift(bit32.band(W1, 0xFF), 12)))
			buffer.writeu32(Poly, PBase + 8, bit32.bor(bit32.rshift(W1, 8), bit32.lshift(bit32.band(W2, 0xF), 24)))
			buffer.writeu32(Poly, PBase + 12, bit32.bor(bit32.rshift(W1, 28), bit32.lshift(W2, 4)))
		end

	else
		local Mask = bit32.lshift(1, Sbw) - 1
		local BitPos = 0

		for I = 0, N - 1 do
			local Value = 0
			local BitsCollected = 0

			while BitsCollected < Sbw do
				local ByteIdx = bit32.rshift(BitPos, 3)
				local BitOffset = bit32.band(BitPos, 7)
				local BitsAvailable = 8 - BitOffset
				local BitsToRead = math.min(Sbw - BitsCollected, BitsAvailable)

				local ByteVal = buffer.readu8(Arr, ByteIdx)
				local Extracted = bit32.band(bit32.rshift(ByteVal, BitOffset), bit32.lshift(1, BitsToRead) - 1)

				Value = bit32.bor(Value, bit32.lshift(Extracted, BitsCollected))

				BitPos += BitsToRead
				BitsCollected += BitsToRead
			end

			buffer.writeu32(Poly, I * 4, bit32.band(Value, Mask))
		end
	end
end

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