--[=[
	ML-KEM Compression Module
	
	Polynomial coefficient compression and decompression operations for ML-KEM.
	Maps field elements to and from reduced bit representations.
--]=]

--!strict
--!optimize 2
--!native

local Params = require("./Params")

local N = 256
local Q = 3329

local Compression = {}

function Compression.Compress(Value: number, D: number): number
	local Shifted = Value * (2^D)
	local QHalf = 1664
	local Rounded = Shifted + QHalf
	local Quotient = Rounded // Q
	local Mask = (2^D) - 1
	
	return bit32.band(Quotient, Mask)
end

function Compression.Decompress(Value: number, D: number): number
	local Product = Value * Q
	local Quotient = bit32.rshift(Product, D)
	local RoundBit = bit32.band(bit32.rshift(Product, D - 1), 1)
	return Quotient + RoundBit
end

function Compression.PolyCompress(Poly: buffer, D: number)
	if not Params.CheckD(D) then
		error("Invalid compression parameter d")
	end

	local Modulus = Q

	if D == 1 then
		for Index = 0, N / 2 - 1 do
			local Pair = buffer.readu32(Poly, Index * 4)
			local V0 = bit32.band(Pair, 0xFFFF)
			local V1 = bit32.rshift(Pair, 16)
			local Q0 = bit32.band((V0 * 2 + 1664) // Modulus, 1)
			local Q1 = bit32.band((V1 * 2 + 1664) // Modulus, 1)
			buffer.writeu32(Poly, Index * 4, Q0 + bit32.lshift(Q1, 16))
		end
	elseif D == 4 then
		for Index = 0, N / 2 - 1 do
			local Pair = buffer.readu32(Poly, Index * 4)
			local V0 = bit32.band(Pair, 0xFFFF)
			local V1 = bit32.rshift(Pair, 16)
			local Q0 = bit32.band((V0 * 16 + 1664) // Modulus, 15)
			local Q1 = bit32.band((V1 * 16 + 1664) // Modulus, 15)
			buffer.writeu32(Poly, Index * 4, Q0 + bit32.lshift(Q1, 16))
		end
	elseif D == 5 then
		for Index = 0, N / 2 - 1 do
			local Pair = buffer.readu32(Poly, Index * 4)
			local V0 = bit32.band(Pair, 0xFFFF)
			local V1 = bit32.rshift(Pair, 16)
			local Q0 = bit32.band((V0 * 32 + 1664) // Modulus, 31)
			local Q1 = bit32.band((V1 * 32 + 1664) // Modulus, 31)
			buffer.writeu32(Poly, Index * 4, Q0 + bit32.lshift(Q1, 16))
		end
	elseif D == 10 then
		for Index = 0, N / 2 - 1 do
			local Pair = buffer.readu32(Poly, Index * 4)
			local V0 = bit32.band(Pair, 0xFFFF)
			local V1 = bit32.rshift(Pair, 16)
			local Q0 = bit32.band((V0 * 1024 + 1664) // Modulus, 1023)
			local Q1 = bit32.band((V1 * 1024 + 1664) // Modulus, 1023)
			buffer.writeu32(Poly, Index * 4, Q0 + bit32.lshift(Q1, 16))
		end
	elseif D == 11 then
		for Index = 0, N / 2 - 1 do
			local Pair = buffer.readu32(Poly, Index * 4)
			local V0 = bit32.band(Pair, 0xFFFF)
			local V1 = bit32.rshift(Pair, 16)
			local Q0 = bit32.band((V0 * 2048 + 1664) // Modulus, 2047)
			local Q1 = bit32.band((V1 * 2048 + 1664) // Modulus, 2047)
			buffer.writeu32(Poly, Index * 4, Q0 + bit32.lshift(Q1, 16))
		end
	else
		local Compress = Compression.Compress
		for Index = 0, N - 1 do
			local Value = buffer.readu16(Poly, Index * 2)
			local Compressed = Compress(Value, D)
			buffer.writeu16(Poly, Index * 2, Compressed)
		end
	end
end

function Compression.PolyDecompress(Poly: buffer, D: number)
	if not Params.CheckD(D) then
		error("Invalid decompression parameter d")
	end

	local Modulus = Q

	if D == 1 then
		for Index = 0, N / 2 - 1 do
			local Pair = buffer.readu32(Poly, Index * 4)
			local V0 = bit32.band(Pair, 0xFFFF)
			local V1 = bit32.rshift(Pair, 16)
			local P0 = V0 * Modulus
			local P1 = V1 * Modulus
			local R0 = bit32.rshift(P0, 1) + bit32.band(P0, 1)
			local R1 = bit32.rshift(P1, 1) + bit32.band(P1, 1)
			buffer.writeu32(Poly, Index * 4, R0 + bit32.lshift(R1, 16))
		end
	elseif D == 4 then
		for Index = 0, N / 2 - 1 do
			local Pair = buffer.readu32(Poly, Index * 4)
			local V0 = bit32.band(Pair, 0xFFFF)
			local V1 = bit32.rshift(Pair, 16)
			local P0 = V0 * Modulus
			local P1 = V1 * Modulus
			local R0 = bit32.rshift(P0, 4) + bit32.band(bit32.rshift(P0, 3), 1)
			local R1 = bit32.rshift(P1, 4) + bit32.band(bit32.rshift(P1, 3), 1)
			buffer.writeu32(Poly, Index * 4, R0 + bit32.lshift(R1, 16))
		end
	elseif D == 5 then
		for Index = 0, N / 2 - 1 do
			local Pair = buffer.readu32(Poly, Index * 4)
			local V0 = bit32.band(Pair, 0xFFFF)
			local V1 = bit32.rshift(Pair, 16)
			local P0 = V0 * Modulus
			local P1 = V1 * Modulus
			local R0 = bit32.rshift(P0, 5) + bit32.band(bit32.rshift(P0, 4), 1)
			local R1 = bit32.rshift(P1, 5) + bit32.band(bit32.rshift(P1, 4), 1)
			buffer.writeu32(Poly, Index * 4, R0 + bit32.lshift(R1, 16))
		end
	elseif D == 10 then
		for Index = 0, N / 2 - 1 do
			local Pair = buffer.readu32(Poly, Index * 4)
			local V0 = bit32.band(Pair, 0xFFFF)
			local V1 = bit32.rshift(Pair, 16)
			local P0 = V0 * Modulus
			local P1 = V1 * Modulus
			local R0 = bit32.rshift(P0, 10) + bit32.band(bit32.rshift(P0, 9), 1)
			local R1 = bit32.rshift(P1, 10) + bit32.band(bit32.rshift(P1, 9), 1)
			buffer.writeu32(Poly, Index * 4, R0 + bit32.lshift(R1, 16))
		end
	elseif D == 11 then
		for Index = 0, N / 2 - 1 do
			local Pair = buffer.readu32(Poly, Index * 4)
			local V0 = bit32.band(Pair, 0xFFFF)
			local V1 = bit32.rshift(Pair, 16)
			local P0 = V0 * Modulus
			local P1 = V1 * Modulus
			local R0 = bit32.rshift(P0, 11) + bit32.band(bit32.rshift(P0, 10), 1)
			local R1 = bit32.rshift(P1, 11) + bit32.band(bit32.rshift(P1, 10), 1)
			buffer.writeu32(Poly, Index * 4, R0 + bit32.lshift(R1, 16))
		end
	else
		local Decompress = Compression.Decompress
		for Index = 0, N - 1 do
			local Compressed = buffer.readu16(Poly, Index * 2)
			local Decompressed = Decompress(Compressed, D)
			buffer.writeu16(Poly, Index * 2, Decompressed)
		end
	end
end

return Compression