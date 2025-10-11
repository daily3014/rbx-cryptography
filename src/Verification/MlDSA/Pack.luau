--[=[
	Bit packing and unpacking utilities
	
	Serializes polynomials to byte arrays with various bit widths.
	Supports encoding/decoding of polynomial coefficients and hint bits.

	Example usage:
		local BitPacking = require(script)
		
		local Poly = buffer.create(256 * 4)
		local Encoded = buffer.create(96)  -- For 3-bit encoding
		BitPacking.Encode(Poly, Encoded, 3)
		BitPacking.Decode(Encoded, Poly, 3)
--]=]

--!strict
--!optimize 2
--!native

local BitPacking = {}

function BitPacking.Encode(Poly: buffer, Arr: buffer, Sbw: number)
	buffer.fill(Arr, 0, 0, buffer.len(Arr))

	if Sbw == 3 then
		local ItrCnt = bit32.rshift(256, 3)

		for I = 0, ItrCnt - 1 do
			local POffset = bit32.lshift(I, 3)
			local BOffset = I * 3

			local P0 = bit32.band(buffer.readu32(Poly, (POffset + 0) * 4), 0x7)
			local P1 = bit32.band(buffer.readu32(Poly, (POffset + 1) * 4), 0x7)
			local P2 = bit32.band(buffer.readu32(Poly, (POffset + 2) * 4), 0x7)
			local P3 = bit32.band(buffer.readu32(Poly, (POffset + 3) * 4), 0x7)
			local P4 = bit32.band(buffer.readu32(Poly, (POffset + 4) * 4), 0x7)
			local P5 = bit32.band(buffer.readu32(Poly, (POffset + 5) * 4), 0x7)
			local P6 = bit32.band(buffer.readu32(Poly, (POffset + 6) * 4), 0x7)
			local P7 = bit32.band(buffer.readu32(Poly, (POffset + 7) * 4), 0x7)

			buffer.writeu8(Arr, BOffset + 0, 
				bit32.bor(
					bit32.lshift(bit32.band(P2, 0x3), 6),
					bit32.lshift(P1, 3),
					P0
				)
			)

			buffer.writeu8(Arr, BOffset + 1,
				bit32.bor(
					bit32.lshift(bit32.band(P5, 0x1), 7),
					bit32.lshift(P4, 4),
					bit32.lshift(P3, 1),
					bit32.rshift(P2, 2)
				)
			)

			buffer.writeu8(Arr, BOffset + 2,
				bit32.bor(
					bit32.lshift(P7, 5),
					bit32.lshift(P6, 2),
					bit32.rshift(P5, 1)
				)
			)
		end
	elseif Sbw == 4 then
		local ItrCnt = bit32.rshift(256, 1)

		for I = 0, ItrCnt - 1 do
			local Off = bit32.lshift(I, 1)
			local P0 = bit32.band(buffer.readu32(Poly, (Off + 0) * 4), 0xF)
			local P1 = bit32.band(buffer.readu32(Poly, (Off + 1) * 4), 0xF)

			buffer.writeu8(Arr, I, bit32.bor(bit32.lshift(P1, 4), P0))
		end
	elseif Sbw == 6 then
		local ItrCnt = bit32.rshift(256, 2)

		for I = 0, ItrCnt - 1 do
			local POffset = bit32.lshift(I, 2)
			local BOffset = I * 3

			local P0 = bit32.band(buffer.readu32(Poly, (POffset + 0) * 4), 0x3F)
			local P1 = bit32.band(buffer.readu32(Poly, (POffset + 1) * 4), 0x3F)
			local P2 = bit32.band(buffer.readu32(Poly, (POffset + 2) * 4), 0x3F)
			local P3 = bit32.band(buffer.readu32(Poly, (POffset + 3) * 4), 0x3F)

			buffer.writeu8(Arr, BOffset + 0, bit32.bor(bit32.lshift(bit32.band(P1, 0x3), 6), P0))
			buffer.writeu8(Arr, BOffset + 1, bit32.bor(bit32.lshift(bit32.band(P2, 0xF), 4), bit32.rshift(P1, 2)))
			buffer.writeu8(Arr, BOffset + 2, bit32.bor(bit32.lshift(P3, 2), bit32.rshift(P2, 4)))
		end
	elseif Sbw == 10 then
		local ItrCnt = bit32.rshift(256, 2)

		for I = 0, ItrCnt - 1 do
			local POffset = I * 4
			local BOffset = I * 5

			local P0 = bit32.band(buffer.readu32(Poly, POffset * 4), 0x3FF)
			local P1 = bit32.band(buffer.readu32(Poly, (POffset + 1) * 4), 0x3FF)
			local P2 = bit32.band(buffer.readu32(Poly, (POffset + 2) * 4), 0x3FF)
			local P3 = bit32.band(buffer.readu32(Poly, (POffset + 3) * 4), 0x3FF)

			buffer.writeu8(Arr, BOffset + 0, bit32.band(P0, 0xFF))
			buffer.writeu8(Arr, BOffset + 1, bit32.bor(bit32.lshift(bit32.band(P1, 0x3F), 2), bit32.rshift(P0, 8)))
			buffer.writeu8(Arr, BOffset + 2, bit32.bor(bit32.lshift(bit32.band(P2, 0xF), 4), bit32.rshift(P1, 6)))
			buffer.writeu8(Arr, BOffset + 3, bit32.bor(bit32.lshift(bit32.band(P3, 0x3), 6), bit32.rshift(P2, 4)))
			buffer.writeu8(Arr, BOffset + 4, bit32.rshift(P3, 2))
		end
	elseif Sbw == 13 then
		local ItrCnt = bit32.rshift(256, 3)

		for I = 0, ItrCnt - 1 do
			local POffset = bit32.lshift(I, 3)
			local BOffset = I * 13

			local P0 = bit32.band(buffer.readu32(Poly, (POffset + 0) * 4), 0x1FFF)
			local P1 = bit32.band(buffer.readu32(Poly, (POffset + 1) * 4), 0x1FFF)
			local P2 = bit32.band(buffer.readu32(Poly, (POffset + 2) * 4), 0x1FFF)
			local P3 = bit32.band(buffer.readu32(Poly, (POffset + 3) * 4), 0x1FFF)
			local P4 = bit32.band(buffer.readu32(Poly, (POffset + 4) * 4), 0x1FFF)
			local P5 = bit32.band(buffer.readu32(Poly, (POffset + 5) * 4), 0x1FFF)
			local P6 = bit32.band(buffer.readu32(Poly, (POffset + 6) * 4), 0x1FFF)
			local P7 = bit32.band(buffer.readu32(Poly, (POffset + 7) * 4), 0x1FFF)

			buffer.writeu8(Arr, BOffset + 0, bit32.band(P0, 0xFF))
			buffer.writeu8(Arr, BOffset + 1, bit32.bor(bit32.lshift(bit32.band(P1, 0x7), 5), bit32.rshift(P0, 8)))
			buffer.writeu8(Arr, BOffset + 2, bit32.rshift(P1, 3))
			buffer.writeu8(Arr, BOffset + 3, bit32.bor(bit32.lshift(bit32.band(P2, 0x3F), 2), bit32.rshift(P1, 11)))
			buffer.writeu8(Arr, BOffset + 4, bit32.bor(bit32.lshift(bit32.band(P3, 0x1), 7), bit32.rshift(P2, 6)))
			buffer.writeu8(Arr, BOffset + 5, bit32.rshift(P3, 1))
			buffer.writeu8(Arr, BOffset + 6, bit32.bor(bit32.lshift(bit32.band(P4, 0xF), 4), bit32.rshift(P3, 9)))
			buffer.writeu8(Arr, BOffset + 7, bit32.rshift(P4, 4))
			buffer.writeu8(Arr, BOffset + 8, bit32.bor(bit32.lshift(bit32.band(P5, 0x7F), 1), bit32.rshift(P4, 12)))
			buffer.writeu8(Arr, BOffset + 9, bit32.bor(bit32.lshift(bit32.band(P6, 0x3), 6), bit32.rshift(P5, 7)))
			buffer.writeu8(Arr, BOffset + 10, bit32.rshift(P6, 2))
			buffer.writeu8(Arr, BOffset + 11, bit32.bor(bit32.lshift(bit32.band(P7, 0x1F), 3), bit32.rshift(P6, 10)))
			buffer.writeu8(Arr, BOffset + 12, bit32.rshift(P7, 5))
		end
	else
		local Mask = bit32.lshift(1, Sbw) - 1
		for I = 0, buffer.len(Arr) * 8 - 1 do
			local PIdx = math.floor(I / Sbw)
			local POffset = I % Sbw

			local AIdx = bit32.rshift(I, 3)
			local AOffset = bit32.band(I, 7)

			if PIdx < 256 then
				local PolyValue = bit32.band(buffer.readu32(Poly, PIdx * 4), Mask)
				local Bit = bit32.band(bit32.rshift(PolyValue, POffset), 1)
				local CurrentByte = buffer.readu8(Arr, AIdx)
				buffer.writeu8(Arr, AIdx, bit32.bxor(CurrentByte, bit32.lshift(Bit, AOffset)))
			end
		end
	end
end

function BitPacking.Decode(Arr: buffer, Poly: buffer, Sbw: number)
	buffer.fill(Poly, 0, 0, 256 * 4)

	if Sbw == 3 then
		local ItrCnt = bit32.rshift(256, 3)

		for I = 0, ItrCnt - 1 do
			local POffset = bit32.lshift(I, 3)
			local BOffset = I * 3

			local B0 = buffer.readu8(Arr, BOffset + 0)
			local B1 = buffer.readu8(Arr, BOffset + 1)
			local B2 = buffer.readu8(Arr, BOffset + 2)

			buffer.writeu32(Poly, (POffset + 0) * 4, bit32.band(B0, 0x7))
			buffer.writeu32(Poly, (POffset + 1) * 4, bit32.band(bit32.rshift(B0, 3), 0x7))
			buffer.writeu32(Poly, (POffset + 2) * 4, bit32.bor(bit32.lshift(bit32.band(B1, 0x1), 2), bit32.rshift(B0, 6)))
			buffer.writeu32(Poly, (POffset + 3) * 4, bit32.band(bit32.rshift(B1, 1), 0x7))
			buffer.writeu32(Poly, (POffset + 4) * 4, bit32.band(bit32.rshift(B1, 4), 0x7))
			buffer.writeu32(Poly, (POffset + 5) * 4, bit32.bor(bit32.lshift(bit32.band(B2, 0x3), 1), bit32.rshift(B1, 7)))
			buffer.writeu32(Poly, (POffset + 6) * 4, bit32.band(bit32.rshift(B2, 2), 0x7))
			buffer.writeu32(Poly, (POffset + 7) * 4, bit32.rshift(B2, 5))
		end
	elseif Sbw == 4 then
		local ItrCnt = bit32.rshift(256, 1)

		for I = 0, ItrCnt - 1 do
			local Off = bit32.lshift(I, 1)
			local Byte = buffer.readu8(Arr, I)

			buffer.writeu32(Poly, (Off + 0) * 4, bit32.band(Byte, 0xF))
			buffer.writeu32(Poly, (Off + 1) * 4, bit32.rshift(Byte, 4))
		end
	elseif Sbw == 6 then
		local ItrCnt = bit32.rshift(256, 2)

		for I = 0, ItrCnt - 1 do
			local POffset = bit32.lshift(I, 2)
			local BOffset = I * 3

			local B0 = buffer.readu8(Arr, BOffset + 0)
			local B1 = buffer.readu8(Arr, BOffset + 1)
			local B2 = buffer.readu8(Arr, BOffset + 2)

			buffer.writeu32(Poly, (POffset + 0) * 4, bit32.band(B0, 0x3F))
			buffer.writeu32(Poly, (POffset + 1) * 4, bit32.bor(bit32.lshift(bit32.band(B1, 0xF), 2), bit32.rshift(B0, 6)))
			buffer.writeu32(Poly, (POffset + 2) * 4, bit32.bor(bit32.lshift(bit32.band(B2, 0x3), 4), bit32.rshift(B1, 4)))
			buffer.writeu32(Poly, (POffset + 3) * 4, bit32.rshift(B2, 2))
		end
	elseif Sbw == 10 then
		local ItrCnt = bit32.rshift(256, 2)

		for I = 0, ItrCnt - 1 do
			local POffset = I * 4
			local BOffset = I * 5

			local B0 = buffer.readu8(Arr, BOffset + 0)
			local B1 = buffer.readu8(Arr, BOffset + 1)
			local B2 = buffer.readu8(Arr, BOffset + 2)
			local B3 = buffer.readu8(Arr, BOffset + 3)
			local B4 = buffer.readu8(Arr, BOffset + 4)

			buffer.writeu32(Poly, POffset * 4, bit32.bor(bit32.lshift(bit32.band(B1, 0x3), 8), B0))
			buffer.writeu32(Poly, (POffset + 1) * 4, bit32.bor(bit32.lshift(bit32.band(B2, 0xF), 6), bit32.rshift(B1, 2)))
			buffer.writeu32(Poly, (POffset + 2) * 4, bit32.bor(bit32.lshift(bit32.band(B3, 0x3F), 4), bit32.rshift(B2, 4)))
			buffer.writeu32(Poly, (POffset + 3) * 4, bit32.bor(bit32.lshift(B4, 2), bit32.rshift(B3, 6)))
		end
	elseif Sbw == 13 then
		local ItrCnt = bit32.rshift(256, 3)

		for I = 0, ItrCnt - 1 do
			local POffset = bit32.lshift(I, 3)
			local BOffset = I * 13

			local B0 = buffer.readu8(Arr, BOffset + 0)
			local B1 = buffer.readu8(Arr, BOffset + 1)
			local B2 = buffer.readu8(Arr, BOffset + 2)
			local B3 = buffer.readu8(Arr, BOffset + 3)
			local B4 = buffer.readu8(Arr, BOffset + 4)
			local B5 = buffer.readu8(Arr, BOffset + 5)
			local B6 = buffer.readu8(Arr, BOffset + 6)
			local B7 = buffer.readu8(Arr, BOffset + 7)
			local B8 = buffer.readu8(Arr, BOffset + 8)
			local B9 = buffer.readu8(Arr, BOffset + 9)
			local B10 = buffer.readu8(Arr, BOffset + 10)
			local B11 = buffer.readu8(Arr, BOffset + 11)
			local B12 = buffer.readu8(Arr, BOffset + 12)

			buffer.writeu32(Poly, (POffset + 0) * 4, bit32.bor(bit32.lshift(bit32.band(B1, 0x1F), 8), B0))
			buffer.writeu32(Poly, (POffset + 1) * 4, bit32.bor(bit32.lshift(bit32.band(B3, 0x3), 11), bit32.lshift(B2, 3), bit32.rshift(B1, 5)))
			buffer.writeu32(Poly, (POffset + 2) * 4, bit32.bor(bit32.lshift(bit32.band(B4, 0x7F), 6), bit32.rshift(B3, 2)))
			buffer.writeu32(Poly, (POffset + 3) * 4, bit32.bor(bit32.lshift(bit32.band(B6, 0xF), 9), bit32.lshift(B5, 1), bit32.rshift(B4, 7)))
			buffer.writeu32(Poly, (POffset + 4) * 4, bit32.bor(bit32.lshift(bit32.band(B8, 0x1), 12), bit32.lshift(B7, 4), bit32.rshift(B6, 4)))
			buffer.writeu32(Poly, (POffset + 5) * 4, bit32.bor(bit32.lshift(bit32.band(B9, 0x3F), 7), bit32.rshift(B8, 1)))
			buffer.writeu32(Poly, (POffset + 6) * 4, bit32.bor(bit32.lshift(bit32.band(B11, 0x7), 10), bit32.lshift(B10, 2), bit32.rshift(B9, 6)))
			buffer.writeu32(Poly, (POffset + 7) * 4, bit32.bor(bit32.lshift(B12, 5), bit32.rshift(B11, 3)))
		end
	else
		for I = 0, buffer.len(Arr) * 8 - 1 do
			local AIdx = bit32.rshift(I, 3)
			local AOffset = bit32.band(I, 7)

			local PIdx = math.floor(I / Sbw)
			local POffset = I % Sbw

			if PIdx < 256 then
				local Bit = bit32.band(bit32.rshift(buffer.readu8(Arr, AIdx), AOffset), 1)
				local CurrentPoly = buffer.readu32(Poly, PIdx * 4)
				buffer.writeu32(Poly, PIdx * 4, bit32.bxor(CurrentPoly, bit32.lshift(Bit, POffset)))
			end
		end
	end
end

function BitPacking.EncodeHintBits(H: buffer, Arr: buffer, K: number, Omega: number)
	buffer.fill(Arr, 0, 0, buffer.len(Arr))

	local Idx = 0

	for I = 0, K - 1 do
		local Off = I * 256

		for J = 0, 256 - 1 do
			local HValue = buffer.readu32(H, (Off + J) * 4)
			if HValue ~= 0 then
				buffer.writeu8(Arr, Idx, J)
				Idx += 1
			end
		end

		buffer.writeu8(Arr, Omega + I, Idx)
	end
end

function BitPacking.DecodeHintBits(Arr: buffer, H: buffer, K: number, Omega: number): boolean
	buffer.fill(H, 0, 0, K * 256 * 4)

	local Idx = 0
	local Failed = false

	for I = 0, K - 1 do
		local Off = I * 256
		local Till = buffer.readu8(Arr, Omega + I)

		if Till < Idx or Till > Omega then
			Failed = true
		end

		for J = Idx, Till - 1 do
			if Failed then
				break
			end

			if J > Idx then
				local CurrentJ = buffer.readu8(Arr, J)
				local PrevJ = buffer.readu8(Arr, J - 1)
				if CurrentJ <= PrevJ then
					Failed = true
				end
			end

			if not Failed then
				local Position = buffer.readu8(Arr, J)
				if Position >= 256 then
					Failed = true
					break
				end
				buffer.writeu32(H, (Off + Position) * 4, 1)
			end
		end

		Idx = Till
	end

	for I = Idx, Omega - 1 do
		if buffer.readu8(Arr, I) ~= 0 then
			Failed = true
		end
	end

	return Failed
end

return BitPacking