--[=[
	ML-KEM Compression Module
	
	Polynomial coefficient compression and decompression operations for ML-KEM.
		
	Example usage:
		local Compression = require(script.Compression)
		
		local Compressed = Compression.Compress(1234, 4)
		local Decompressed = Compression.Decompress(Compressed, 4)
		
		local Poly = buffer.create(512) -- 256 coefficients * 2 bytes
		Compression.PolyCompress(Poly, 10)
		Compression.PolyDecompress(Poly, 10)
--]=]

--!strict
--!optimize 2
--!native

local Params = require("./Params")

local Q = 13 * 256 + 1
local Q_BIT_WIDTH = 12
local R = math.floor((2^(2 * Q_BIT_WIDTH)) / Q)

local LOG2N = 8
local N = 2^LOG2N

local Compression = {}

function Compression.Compress(X: number, D: number): number
	if not Params.CheckD(D) then
		error("Invalid compression parameter d")
	end

	local Mask = (2^D) - 1
	local Dividend = bit32.lshift(X, D)

	local Quotient0 = math.floor((Dividend * R) / (2^(Q_BIT_WIDTH * 2)))
	local Remainder = Dividend - Quotient0 * Q

	local QHalf = math.floor(Q / 2)
	local Adjustment1 = if (QHalf - Remainder) >= 0 then 0 else 1
	local Adjustment2 = if (Q + QHalf - Remainder) >= 0 then 0 else 1

	local Quotient1 = Quotient0 + Adjustment1
	local Quotient2 = Quotient1 + Adjustment2

	return bit32.band(Quotient2, Mask)
end

function Compression.Decompress(X: number, D: number): number
	if not Params.CheckD(D) then
		error("Invalid compression parameter d")
	end

	local T0 = 2^D
	local T1 = bit32.rshift(T0, 1)
	local T2 = Q * X
	local T3 = T2 + T1
	local T4 = bit32.rshift(T3, D)

	return T4 % Q
end

function Compression.PolyCompress(Poly: buffer, D: number)
	if not Params.CheckD(D) then
		error("Invalid compression parameter d")
	end

	for Index = 0, N - 1 do
		local Coeff = buffer.readu16(Poly, Index * 2)
		local Compressed = Compression.Compress(Coeff, D)
		buffer.writeu16(Poly, Index * 2, Compressed)
	end
end

function Compression.PolyDecompress(Poly: buffer, D: number)
	if not Params.CheckD(D) then
		error("Invalid compression parameter d")
	end

	for Index = 0, N - 1 do
		local Coeff = buffer.readu16(Poly, Index * 2)
		local Decompressed = Compression.Decompress(Coeff, D)
		buffer.writeu16(Poly, Index * 2, Decompressed)
	end
end

function Compression.PolyCompressCopy(Src: buffer, D: number): buffer
	if not Params.CheckD(D) then
		error("Invalid compression parameter d")
	end

	local Result = buffer.create(N * 2)
	buffer.copy(Result, 0, Src, 0, N * 2)
	Compression.PolyCompress(Result, D)

	return Result
end

function Compression.PolyDecompressCopy(Src: buffer, D: number): buffer
	if not Params.CheckD(D) then
		error("Invalid compression parameter d")
	end

	local Result = buffer.create(N * 2)
	buffer.copy(Result, 0, Src, 0, N * 2)
	Compression.PolyDecompress(Result, D)

	return Result
end

function Compression.PolyCompressPacked(Poly: buffer, D: number): buffer
	if not Params.CheckD(D) then
		error("Invalid compression parameter d")
	end

	local TotalBits = D * N
	local PackedSize = math.ceil(TotalBits / 8)
	local Packed = buffer.create(PackedSize)

	local BitOffset = 0

	for Index = 0, N - 1 do
		local Coeff = buffer.readu16(Poly, Index * 2)
		local Compressed = Compression.Compress(Coeff, D)

		local ByteOffset = math.floor(BitOffset / 8)
		local BitInByte = BitOffset % 8

		if BitInByte + D <= 8 then
			local Existing = if ByteOffset < PackedSize then buffer.readu8(Packed, ByteOffset) else 0
			local Shifted = bit32.lshift(Compressed, BitInByte)
			buffer.writeu8(Packed, ByteOffset, bit32.bor(Existing, Shifted))
		else
			local Mask = (2^D) - 1
			local Value = bit32.band(Compressed, Mask)

			if ByteOffset < PackedSize then
				local Existing = buffer.readu8(Packed, ByteOffset)
				local FirstPart = bit32.lshift(Value, BitInByte)
				buffer.writeu8(Packed, ByteOffset, bit32.bor(Existing, FirstPart))
			end

			if ByteOffset + 1 < PackedSize and BitInByte + D > 8 then
				local SecondPart = bit32.rshift(Value, 8 - BitInByte)
				buffer.writeu8(Packed, ByteOffset + 1, SecondPart)
			end
		end

		BitOffset += D
	end

	return Packed
end

function Compression.PolyDecompressPacked(Packed: buffer, D: number): buffer
	if not Params.CheckD(D) then
		error("Invalid compression parameter d")
	end

	local Result = buffer.create(N * 2)
	local BitOffset = 0
	local PackedSize = buffer.len(Packed)

	for Index = 0, N - 1 do
		local ByteOffset = math.floor(BitOffset / 8)
		local BitInByte = BitOffset % 8
		local Compressed = 0

		if ByteOffset < PackedSize then
			if BitInByte + D <= 8 then
				local Byte = buffer.readu8(Packed, ByteOffset)
				Compressed = bit32.band(bit32.rshift(Byte, BitInByte), (2^D) - 1)
			else
				local FirstByte = buffer.readu8(Packed, ByteOffset)
				local FirstPart = bit32.rshift(FirstByte, BitInByte)

				local SecondPart = 0
				if ByteOffset + 1 < PackedSize then
					local SecondByte = buffer.readu8(Packed, ByteOffset + 1)
					SecondPart = bit32.lshift(SecondByte, 8 - BitInByte)
				end

				Compressed = bit32.band(bit32.bor(FirstPart, SecondPart), (2^D) - 1)
			end
		end

		local Decompressed = Compression.Decompress(Compressed, D)
		buffer.writeu16(Result, Index * 2, Decompressed)

		BitOffset += D
	end

	return Result
end

return Compression