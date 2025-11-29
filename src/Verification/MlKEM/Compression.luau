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
		for Index = 0, N - 1 do
			local Value = buffer.readu16(Poly, Index * 2)
			local Shifted = Value * 2
			local Rounded = Shifted + 1664
			local Quotient = Rounded // Modulus
			buffer.writeu16(Poly, Index * 2, bit32.band(Quotient, 1))
		end
	elseif D == 4 then
		for Index = 0, N - 1 do
			local Value = buffer.readu16(Poly, Index * 2)
			local Shifted = Value * 16
			local Rounded = Shifted + 1664
			local Quotient = Rounded // Modulus
			buffer.writeu16(Poly, Index * 2, bit32.band(Quotient, 15))
		end
	elseif D == 5 then
		for Index = 0, N - 1 do
			local Value = buffer.readu16(Poly, Index * 2)
			local Shifted = Value * 32
			local Rounded = Shifted + 1664
			local Quotient = Rounded // Modulus
			buffer.writeu16(Poly, Index * 2, bit32.band(Quotient, 31))
		end
	elseif D == 10 then
		for Index = 0, N - 1 do
			local Value = buffer.readu16(Poly, Index * 2)
			local Shifted = Value * 1024
			local Rounded = Shifted + 1664
			local Quotient = Rounded // Modulus
			buffer.writeu16(Poly, Index * 2, bit32.band(Quotient, 1023))
		end
	elseif D == 11 then
		for Index = 0, N - 1 do
			local Value = buffer.readu16(Poly, Index * 2)
			local Shifted = Value * 2048
			local Rounded = Shifted + 1664
			local Quotient = Rounded // Modulus
			buffer.writeu16(Poly, Index * 2, bit32.band(Quotient, 2047))
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
		for Index = 0, N - 1 do
			local Compressed = buffer.readu16(Poly, Index * 2)
			local Product = Compressed * Modulus
			local Quotient = bit32.rshift(Product, 1)
			local RoundBit = bit32.band(Product, 1)
			buffer.writeu16(Poly, Index * 2, Quotient + RoundBit)
		end
	elseif D == 4 then
		for Index = 0, N - 1 do
			local Compressed = buffer.readu16(Poly, Index * 2)
			local Product = Compressed * Modulus
			local Quotient = bit32.rshift(Product, 4)
			local RoundBit = bit32.band(bit32.rshift(Product, 3), 1)
			buffer.writeu16(Poly, Index * 2, Quotient + RoundBit)
		end
	elseif D == 5 then
		for Index = 0, N - 1 do
			local Compressed = buffer.readu16(Poly, Index * 2)
			local Product = Compressed * Modulus
			local Quotient = bit32.rshift(Product, 5)
			local RoundBit = bit32.band(bit32.rshift(Product, 4), 1)
			buffer.writeu16(Poly, Index * 2, Quotient + RoundBit)
		end
	elseif D == 10 then
		for Index = 0, N - 1 do
			local Compressed = buffer.readu16(Poly, Index * 2)
			local Product = Compressed * Modulus
			local Quotient = bit32.rshift(Product, 10)
			local RoundBit = bit32.band(bit32.rshift(Product, 9), 1)
			buffer.writeu16(Poly, Index * 2, Quotient + RoundBit)
		end
	elseif D == 11 then
		for Index = 0, N - 1 do
			local Compressed = buffer.readu16(Poly, Index * 2)
			local Product = Compressed * Modulus
			local Quotient = bit32.rshift(Product, 11)
			local RoundBit = bit32.band(bit32.rshift(Product, 10), 1)
			buffer.writeu16(Poly, Index * 2, Quotient + RoundBit)
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