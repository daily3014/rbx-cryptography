--[=[
	ML-KEM Serialization Module
	
	Polynomial encoding and decoding operations for ML-KEM.
	Converts polynomials to/from byte arrays with different bit lengths.
		
	Example usage:
		local Serialize = require(script.Serialize)
		
		local Poly = buffer.create(512) -- 256 coefficients
		local Encoded = Serialize.Encode(Poly, 12)
		local Decoded = Serialize.Decode(Encoded, 12)
--]=]

--!strict
--!optimize 2
--!native

local Field = require("./Field")
local Params = require("./Params")

local LOG2N = 8
local N = 2^LOG2N
local POLY_SIZE = N * 2 

local Q = 13 * 256 + 1
local Q_BIT_WIDTH = 12
local WIDTH = (2^(2 * Q_BIT_WIDTH))
local R = math.floor((2^(2 * Q_BIT_WIDTH)) / Q)

local Serialize = {}

function Serialize.Encode(Poly: buffer, L: number): buffer
	if not Params.CheckL(L) then
		error("Invalid encoding parameter l")
	end

	local OutputSize = 32 * L
	local Output = buffer.create(OutputSize)

	if L == 1 then
		local IterCount = N / 8

		for I = 0, IterCount - 1 do
			local Offset = I * 8
			local Byte = 0

			for J = 0, 7 do
				local Coeff = buffer.readu16(Poly, (Offset + J) * 2)
				local Bit = bit32.band(Coeff, 1)
				Byte = bit32.bor(Byte, bit32.lshift(Bit, J))
			end

			buffer.writeu8(Output, I, Byte)
		end

	elseif L == 4 then
		local IterCount = N / 2

		for I = 0, IterCount - 1 do
			local Offset = I * 2
			local C0 = bit32.band(buffer.readu16(Poly, Offset * 2), 0xF)
			local C1 = bit32.band(buffer.readu16(Poly, (Offset + 1) * 2), 0xF)

			local Byte = bit32.bor(C0, bit32.lshift(C1, 4))
			buffer.writeu8(Output, I, Byte)
		end

	elseif L == 5 then
		local IterCount = N / 8

		for I = 0, IterCount - 1 do
			local PolyOffset = I * 8
			local ByteOffset = I * 5

			local T0 = buffer.readu16(Poly, (PolyOffset + 0) * 2)
			local T1 = buffer.readu16(Poly, (PolyOffset + 1) * 2)
			local T2 = buffer.readu16(Poly, (PolyOffset + 2) * 2)
			local T3 = buffer.readu16(Poly, (PolyOffset + 3) * 2)
			local T4 = buffer.readu16(Poly, (PolyOffset + 4) * 2)
			local T5 = buffer.readu16(Poly, (PolyOffset + 5) * 2)
			local T6 = buffer.readu16(Poly, (PolyOffset + 6) * 2)
			local T7 = buffer.readu16(Poly, (PolyOffset + 7) * 2)

			buffer.writeu8(Output, ByteOffset + 0, bit32.bor(bit32.band(T0, 0x1F), bit32.lshift(bit32.band(T1, 0x07), 5)))
			buffer.writeu8(Output, ByteOffset + 1, bit32.bor(bit32.rshift(T1, 3), bit32.lshift(bit32.band(T2, 0x1F), 2), bit32.lshift(bit32.band(T3, 0x01), 7)))
			buffer.writeu8(Output, ByteOffset + 2, bit32.bor(bit32.rshift(T3, 1), bit32.lshift(bit32.band(T4, 0x0F), 4)))
			buffer.writeu8(Output, ByteOffset + 3, bit32.bor(bit32.rshift(T4, 4), bit32.lshift(bit32.band(T5, 0x1F), 1), bit32.lshift(bit32.band(T6, 0x03), 6)))
			buffer.writeu8(Output, ByteOffset + 4, bit32.bor(bit32.rshift(T6, 2), bit32.lshift(bit32.band(T7, 0x1F), 3)))
		end

	elseif L == 10 then
		local IterCount = N / 4

		for I = 0, IterCount - 1 do
			local PolyOffset = I * 4
			local ByteOffset = I * 5

			local T0 = buffer.readu16(Poly, (PolyOffset + 0) * 2)
			local T1 = buffer.readu16(Poly, (PolyOffset + 1) * 2)
			local T2 = buffer.readu16(Poly, (PolyOffset + 2) * 2)
			local T3 = buffer.readu16(Poly, (PolyOffset + 3) * 2)

			buffer.writeu8(Output, ByteOffset + 0, bit32.band(T0, 0xFF))
			buffer.writeu8(Output, ByteOffset + 1, bit32.bor(bit32.rshift(T0, 8), bit32.lshift(bit32.band(T1, 0x3F), 2)))
			buffer.writeu8(Output, ByteOffset + 2, bit32.bor(bit32.rshift(T1, 6), bit32.lshift(bit32.band(T2, 0x0F), 4)))
			buffer.writeu8(Output, ByteOffset + 3, bit32.bor(bit32.rshift(T2, 4), bit32.lshift(bit32.band(T3, 0x03), 6)))
			buffer.writeu8(Output, ByteOffset + 4, bit32.rshift(T3, 2))
		end

	elseif L == 11 then
		local IterCount = N / 8

		for I = 0, IterCount - 1 do
			local PolyOffset = I * 8
			local ByteOffset = I * 11

			local T0 = buffer.readu16(Poly, (PolyOffset + 0) * 2)
			local T1 = buffer.readu16(Poly, (PolyOffset + 1) * 2)
			local T2 = buffer.readu16(Poly, (PolyOffset + 2) * 2)
			local T3 = buffer.readu16(Poly, (PolyOffset + 3) * 2)
			local T4 = buffer.readu16(Poly, (PolyOffset + 4) * 2)
			local T5 = buffer.readu16(Poly, (PolyOffset + 5) * 2)
			local T6 = buffer.readu16(Poly, (PolyOffset + 6) * 2)
			local T7 = buffer.readu16(Poly, (PolyOffset + 7) * 2)

			buffer.writeu8(Output, ByteOffset + 0, bit32.band(T0, 0xFF))
			buffer.writeu8(Output, ByteOffset + 1, bit32.bor(bit32.rshift(T0, 8), bit32.lshift(bit32.band(T1, 0x1F), 3)))
			buffer.writeu8(Output, ByteOffset + 2, bit32.bor(bit32.rshift(T1, 5), bit32.lshift(bit32.band(T2, 0x03), 6)))
			buffer.writeu8(Output, ByteOffset + 3, bit32.rshift(T2, 2))
			buffer.writeu8(Output, ByteOffset + 4, bit32.bor(bit32.rshift(T2, 10), bit32.lshift(bit32.band(T3, 0x7F), 1)))
			buffer.writeu8(Output, ByteOffset + 5, bit32.bor(bit32.rshift(T3, 7), bit32.lshift(bit32.band(T4, 0x0F), 4)))
			buffer.writeu8(Output, ByteOffset + 6, bit32.bor(bit32.rshift(T4, 4), bit32.lshift(bit32.band(T5, 0x01), 7)))
			buffer.writeu8(Output, ByteOffset + 7, bit32.rshift(T5, 1))
			buffer.writeu8(Output, ByteOffset + 8, bit32.bor(bit32.rshift(T5, 9), bit32.lshift(bit32.band(T6, 0x3F), 2)))
			buffer.writeu8(Output, ByteOffset + 9, bit32.bor(bit32.rshift(T6, 6), bit32.lshift(bit32.band(T7, 0x07), 5)))
			buffer.writeu8(Output, ByteOffset + 10, bit32.rshift(T7, 3))
		end
	else 
		local IterCount = N / 2

		for I = 0, IterCount - 1 do
			local PolyOffset = I * 2
			local ByteOffset = I * 3

			local T0 = buffer.readu16(Poly, (PolyOffset + 0) * 2)
			local T1 = buffer.readu16(Poly, (PolyOffset + 1) * 2)

			buffer.writeu8(Output, ByteOffset + 0, bit32.band(T0, 0xFF))
			buffer.writeu8(Output, ByteOffset + 1, bit32.bor(bit32.rshift(T0, 8), bit32.lshift(bit32.band(T1, 0x0F), 4)))
			buffer.writeu8(Output, ByteOffset + 2, bit32.rshift(T1, 4))
		end
	end

	return Output
end

function Serialize.EncodeAt(Poly: buffer, PolyOffset: number, Output: buffer, OutOffset: number, L: number)
	if L == 12 then
		for I = 0, 127 do
			local PolyIdx = PolyOffset + I * 4
			local ByteIdx = OutOffset + I * 3

			local T0 = buffer.readu16(Poly, PolyIdx)
			local T1 = buffer.readu16(Poly, PolyIdx + 2)

			buffer.writeu8(Output, ByteIdx, bit32.band(T0, 0xFF))
			buffer.writeu8(Output, ByteIdx + 1, bit32.bor(bit32.rshift(T0, 8), bit32.lshift(bit32.band(T1, 0x0F), 4)))
			buffer.writeu8(Output, ByteIdx + 2, bit32.rshift(T1, 4))
		end
	end
end

function Serialize.Decode(Data: buffer, L: number): buffer
	if not Params.CheckL(L) then
		error("Invalid encoding parameter l")
	end

	local Poly = buffer.create(N * 2)
	if L == 1 then
		local IterCount = N / 8

		for I = 0, IterCount - 1 do
			local Byte = buffer.readu8(Data, I)
			local Offset = I * 8

			for J = 0, 7 do
				local Bit = bit32.band(bit32.rshift(Byte, J), 1)
				buffer.writeu16(Poly, (Offset + J) * 2, Bit)
			end
		end

	elseif L == 4 then
		local IterCount = N / 2

		for I = 0, IterCount - 1 do
			local Byte = buffer.readu8(Data, I)
			local Offset = I * 2

			buffer.writeu16(Poly, (Offset + 0) * 2, bit32.band(Byte, 0x0F))
			buffer.writeu16(Poly, (Offset + 1) * 2, bit32.rshift(Byte, 4))
		end

	elseif L == 5 then
		local IterCount = N / 8

		for I = 0, IterCount - 1 do
			local PolyOffset = I * 8
			local ByteOffset = I * 5

			local B0 = buffer.readu8(Data, ByteOffset + 0)
			local B1 = buffer.readu8(Data, ByteOffset + 1)
			local B2 = buffer.readu8(Data, ByteOffset + 2)
			local B3 = buffer.readu8(Data, ByteOffset + 3)
			local B4 = buffer.readu8(Data, ByteOffset + 4)

			local T0 = bit32.band(B0, 0x1F)
			local T1 = bit32.bor(bit32.rshift(B0, 5), bit32.lshift(bit32.band(B1, 0x03), 3))
			local T2 = bit32.band(bit32.rshift(B1, 2), 0x1F)
			local T3 = bit32.bor(bit32.rshift(B1, 7), bit32.lshift(bit32.band(B2, 0x0F), 1))
			local T4 = bit32.bor(bit32.rshift(B2, 4), bit32.lshift(bit32.band(B3, 0x01), 4))
			local T5 = bit32.band(bit32.rshift(B3, 1), 0x1F)
			local T6 = bit32.bor(bit32.rshift(B3, 6), bit32.lshift(bit32.band(B4, 0x07), 2))
			local T7 = bit32.rshift(B4, 3)

			buffer.writeu16(Poly, (PolyOffset + 0) * 2, T0)
			buffer.writeu16(Poly, (PolyOffset + 1) * 2, T1)
			buffer.writeu16(Poly, (PolyOffset + 2) * 2, T2)
			buffer.writeu16(Poly, (PolyOffset + 3) * 2, T3)
			buffer.writeu16(Poly, (PolyOffset + 4) * 2, T4)
			buffer.writeu16(Poly, (PolyOffset + 5) * 2, T5)
			buffer.writeu16(Poly, (PolyOffset + 6) * 2, T6)
			buffer.writeu16(Poly, (PolyOffset + 7) * 2, T7)
		end

	elseif L == 10 then
		local IterCount = N / 4

		for I = 0, IterCount - 1 do
			local PolyOffset = I * 4
			local ByteOffset = I * 5

			local B0 = buffer.readu8(Data, ByteOffset + 0)
			local B1 = buffer.readu8(Data, ByteOffset + 1)
			local B2 = buffer.readu8(Data, ByteOffset + 2)
			local B3 = buffer.readu8(Data, ByteOffset + 3)
			local B4 = buffer.readu8(Data, ByteOffset + 4)

			local T0 = bit32.bor(B0, bit32.lshift(bit32.band(B1, 0x03), 8))
			local T1 = bit32.bor(bit32.rshift(B1, 2), bit32.lshift(bit32.band(B2, 0x0F), 6))
			local T2 = bit32.bor(bit32.rshift(B2, 4), bit32.lshift(bit32.band(B3, 0x3F), 4))
			local T3 = bit32.bor(bit32.rshift(B3, 6), bit32.lshift(B4, 2))

			buffer.writeu16(Poly, (PolyOffset + 0) * 2, T0)
			buffer.writeu16(Poly, (PolyOffset + 1) * 2, T1)
			buffer.writeu16(Poly, (PolyOffset + 2) * 2, T2)
			buffer.writeu16(Poly, (PolyOffset + 3) * 2, T3)
		end

	elseif L == 11 then
		local IterCount = N / 8

		for I = 0, IterCount - 1 do
			local PolyOffset = I * 8
			local ByteOffset = I * 11

			local B0 = buffer.readu8(Data, ByteOffset + 0)
			local B1 = buffer.readu8(Data, ByteOffset + 1)
			local B2 = buffer.readu8(Data, ByteOffset + 2)
			local B3 = buffer.readu8(Data, ByteOffset + 3)
			local B4 = buffer.readu8(Data, ByteOffset + 4)
			local B5 = buffer.readu8(Data, ByteOffset + 5)
			local B6 = buffer.readu8(Data, ByteOffset + 6)
			local B7 = buffer.readu8(Data, ByteOffset + 7)
			local B8 = buffer.readu8(Data, ByteOffset + 8)
			local B9 = buffer.readu8(Data, ByteOffset + 9)
			local B10 = buffer.readu8(Data, ByteOffset + 10)

			local T0 = bit32.bor(B0, bit32.lshift(bit32.band(B1, 0x07), 8))
			local T1 = bit32.bor(bit32.rshift(B1, 3), bit32.lshift(bit32.band(B2, 0x3F), 5))
			local T2 = bit32.bor(bit32.rshift(B2, 6), bit32.lshift(B3, 2), bit32.lshift(bit32.band(B4, 0x01), 10))
			local T3 = bit32.bor(bit32.rshift(B4, 1), bit32.lshift(bit32.band(B5, 0x0F), 7))
			local T4 = bit32.bor(bit32.rshift(B5, 4), bit32.lshift(bit32.band(B6, 0x7F), 4))
			local T5 = bit32.bor(bit32.rshift(B6, 7), bit32.lshift(B7, 1), bit32.lshift(bit32.band(B8, 0x03), 9))
			local T6 = bit32.bor(bit32.rshift(B8, 2), bit32.lshift(bit32.band(B9, 0x1F), 6))
			local T7 = bit32.bor(bit32.rshift(B9, 5), bit32.lshift(B10, 3))

			buffer.writeu16(Poly, (PolyOffset + 0) * 2, T0)
			buffer.writeu16(Poly, (PolyOffset + 1) * 2, T1)
			buffer.writeu16(Poly, (PolyOffset + 2) * 2, T2)
			buffer.writeu16(Poly, (PolyOffset + 3) * 2, T3)
			buffer.writeu16(Poly, (PolyOffset + 4) * 2, T4)
			buffer.writeu16(Poly, (PolyOffset + 5) * 2, T5)
			buffer.writeu16(Poly, (PolyOffset + 6) * 2, T6)
			buffer.writeu16(Poly, (PolyOffset + 7) * 2, T7)
		end
	else
		local IterCount = N / 2

		for I = 0, IterCount - 1 do
			local PolyOffset = I * 2
			local ByteOffset = I * 3

			local B0 = buffer.readu8(Data, ByteOffset + 0)
			local B1 = buffer.readu8(Data, ByteOffset + 1)
			local B2 = buffer.readu8(Data, ByteOffset + 2)

			local T0 = bit32.bor(B0, bit32.lshift(bit32.band(B1, 0x0F), 8))
			local T1 = bit32.bor(bit32.rshift(B1, 4), bit32.lshift(B2, 4))

			if T0 >= 3329 or T1 >= 3329 then
				error("Invalid polynomial coefficient encoding")
			end

			buffer.writeu16(Poly, (PolyOffset + 0) * 2, T0)
			buffer.writeu16(Poly, (PolyOffset + 1) * 2, T1)
		end
	end

	return Poly
end

function Serialize.DecodeAt(Data: buffer, DataOffset: number, Poly: buffer, PolyOffset: number, L: number)
	if L == 12 then
		for I = 0, 127 do
			local ByteIdx = DataOffset + I * 3
			local PolyIdx = PolyOffset + I * 4

			local B0 = buffer.readu8(Data, ByteIdx)
			local B1 = buffer.readu8(Data, ByteIdx + 1)
			local B2 = buffer.readu8(Data, ByteIdx + 2)

			local T0 = bit32.bor(B0, bit32.lshift(bit32.band(B1, 0x0F), 8))
			local T1 = bit32.bor(bit32.rshift(B1, 4), bit32.lshift(B2, 4))

			if T0 >= 3329 or T1 >= 3329 then
				error("Invalid polynomial coefficient encoding")
			end

			buffer.writeu16(Poly, PolyIdx, T0)
			buffer.writeu16(Poly, PolyIdx + 2, T1)
		end
	end
end

return Serialize