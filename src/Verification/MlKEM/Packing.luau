--[=[
	Packing: the byte forms of ML-KEM polynomials (FIPS 203 ByteEncode and ByteDecode), with
	Compress, Decompress and the noise additions done in the same pass. Polynomials are 256 u16
	coefficients and a vector is K of them back to back, so a vector is packed as one long
	polynomial. The encodes take coefficients up to 3q unreduced; compressing masks the excess.
	Decode12 writes every coefficient and reports at the end whether all were below q

	Example usage:
		Packing.Encode12(Vector, K * 256, PublicKey, 0)
		local Valid = Packing.Decode12(PublicKey, 0, K * 256, Vector)
--]=]

--!strict
--!optimize 2
--!native

local Q = 3329

local MESSAGE_PAIRS = buffer.create(16) do
	for Bits = 0, 3 do
		buffer.writeu32(MESSAGE_PAIRS, Bits * 4, bit32.band(Bits, 1) * 1665 + bit32.rshift(Bits, 1) * 1665 * 65536)
	end
end

local function CompressTable(Bits: number): buffer
	local Scale = 2 ^ Bits
	local Table = buffer.create(Q * 6)
	for Value = 0, Q * 3 - 1 do
		buffer.writeu16(Table, Value * 2, bit32.band((Value * Scale + 1664) // Q, Scale - 1))
	end
	return Table
end

local function DecompressTable(Bits: number): buffer
	local Table = buffer.create(2 ^ Bits * 2)
	for Value = 0, 2 ^ Bits - 1 do
		buffer.writeu16(Table, Value * 2, (Value * Q + 2 ^ (Bits - 1)) // 2 ^ Bits)
	end
	return Table
end

local COMPRESS_1 = CompressTable(1)
local COMPRESS_4 = CompressTable(4)
local COMPRESS_5 = CompressTable(5)
local COMPRESS_10 = CompressTable(10)
local COMPRESS_11 = CompressTable(11)
local DECOMPRESS_4 = DecompressTable(4)
local DECOMPRESS_5 = DecompressTable(5)
local DECOMPRESS_10 = DecompressTable(10)
local DECOMPRESS_11 = DecompressTable(11)

local function Encode12(Vector: buffer, Coefficients: number, Output: buffer, OutputOffset: number)
	for In = 0, Coefficients * 2 - 16, 16 do
		local Out = OutputOffset + In * 0.75
		local S0 = buffer.readu32(Vector, In)
		local C0 = bit32.band(S0, 0xffff)
		local C1 = bit32.rshift(S0, 16)
		local S1 = buffer.readu32(Vector, In + 4)
		local C2 = bit32.band(S1, 0xffff)
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 12), bit32.lshift(C2, 24)))
		local C3 = bit32.rshift(S1, 16)
		local S2 = buffer.readu32(Vector, In + 8)
		local C4 = bit32.band(S2, 0xffff)
		local C5 = bit32.rshift(S2, 16)
		buffer.writeu32(Output, Out + 4, bit32.bor(bit32.rshift(C2, 8), bit32.lshift(C3, 4), bit32.lshift(C4, 16), bit32.lshift(C5, 28)))
		local S3 = buffer.readu32(Vector, In + 12)
		local C6 = bit32.band(S3, 0xffff)
		local C7 = bit32.rshift(S3, 16)
		buffer.writeu32(Output, Out + 8, bit32.bor(bit32.rshift(C5, 4), bit32.lshift(C6, 8), bit32.lshift(C7, 20)))
	end
end

local function Decode12(Data: buffer, DataOffset: number, Coefficients: number, Vector: buffer): boolean
	local Invalid = 0
	for Out = 0, Coefficients * 2 - 16, 16 do
		local In = DataOffset + Out * 0.75
		local W0 = buffer.readu32(Data, In)
		local P0 = bit32.bor(bit32.band(W0, 4095), bit32.lshift(bit32.band(bit32.rshift(W0, 12), 4095), 16))
		buffer.writeu32(Vector, Out, P0)
		local W1 = buffer.readu32(Data, In + 4)
		local P1 = bit32.bor(bit32.band(bit32.bor(bit32.rshift(W0, 24), bit32.lshift(W1, 8)), 4095), bit32.lshift(bit32.band(bit32.rshift(W1, 4), 4095), 16))
		buffer.writeu32(Vector, Out + 4, P1)
		local W2 = buffer.readu32(Data, In + 8)
		local P2 = bit32.bor(bit32.band(bit32.rshift(W1, 16), 4095), bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W1, 28), bit32.lshift(W2, 4)), 4095), 16))
		buffer.writeu32(Vector, Out + 8, P2)
		local P3 = bit32.bor(bit32.band(bit32.rshift(W2, 8), 4095), bit32.lshift(bit32.rshift(W2, 20), 16))
		buffer.writeu32(Vector, Out + 12, P3)
		Invalid = bit32.bor(Invalid, P0 + 0x02ff02ff, P1 + 0x02ff02ff, P2 + 0x02ff02ff, P3 + 0x02ff02ff)
	end
	return bit32.band(Invalid, 0x10001000) == 0
end

local function EncodeU10(U: buffer, E1: buffer, Coefficients: number, Output: buffer)
	local Compress = COMPRESS_10
	for In = 0, Coefficients * 2 - 32, 32 do
		local Out = In * 0.625
		local S0 = bit32.bor(buffer.readu32(U, In) + buffer.readu32(E1, In), 0)
		local C0 = buffer.readu16(Compress, bit32.band(bit32.lshift(S0, 1), 0xfffe))
		local C1 = buffer.readu16(Compress, bit32.band(bit32.rshift(S0, 15), 0xfffe))
		local S1 = bit32.bor(buffer.readu32(U, In + 4) + buffer.readu32(E1, In + 4), 0)
		local C2 = buffer.readu16(Compress, bit32.band(bit32.lshift(S1, 1), 0xfffe))
		local C3 = buffer.readu16(Compress, bit32.band(bit32.rshift(S1, 15), 0xfffe))
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 10), bit32.lshift(C2, 20), bit32.lshift(C3, 30)))
		local S2 = bit32.bor(buffer.readu32(U, In + 8) + buffer.readu32(E1, In + 8), 0)
		local C4 = buffer.readu16(Compress, bit32.band(bit32.lshift(S2, 1), 0xfffe))
		local C5 = buffer.readu16(Compress, bit32.band(bit32.rshift(S2, 15), 0xfffe))
		local S3 = bit32.bor(buffer.readu32(U, In + 12) + buffer.readu32(E1, In + 12), 0)
		local C6 = buffer.readu16(Compress, bit32.band(bit32.lshift(S3, 1), 0xfffe))
		buffer.writeu32(Output, Out + 4, bit32.bor(bit32.rshift(C3, 2), bit32.lshift(C4, 8), bit32.lshift(C5, 18), bit32.lshift(C6, 28)))
		local C7 = buffer.readu16(Compress, bit32.band(bit32.rshift(S3, 15), 0xfffe))
		local S4 = bit32.bor(buffer.readu32(U, In + 16) + buffer.readu32(E1, In + 16), 0)
		local C8 = buffer.readu16(Compress, bit32.band(bit32.lshift(S4, 1), 0xfffe))
		local C9 = buffer.readu16(Compress, bit32.band(bit32.rshift(S4, 15), 0xfffe))
		buffer.writeu32(Output, Out + 8, bit32.bor(bit32.rshift(C6, 4), bit32.lshift(C7, 6), bit32.lshift(C8, 16), bit32.lshift(C9, 26)))
		local S5 = bit32.bor(buffer.readu32(U, In + 20) + buffer.readu32(E1, In + 20), 0)
		local C10 = buffer.readu16(Compress, bit32.band(bit32.lshift(S5, 1), 0xfffe))
		local C11 = buffer.readu16(Compress, bit32.band(bit32.rshift(S5, 15), 0xfffe))
		local S6 = bit32.bor(buffer.readu32(U, In + 24) + buffer.readu32(E1, In + 24), 0)
		local C12 = buffer.readu16(Compress, bit32.band(bit32.lshift(S6, 1), 0xfffe))
		buffer.writeu32(Output, Out + 12, bit32.bor(bit32.rshift(C9, 6), bit32.lshift(C10, 4), bit32.lshift(C11, 14), bit32.lshift(C12, 24)))
		local C13 = buffer.readu16(Compress, bit32.band(bit32.rshift(S6, 15), 0xfffe))
		local S7 = bit32.bor(buffer.readu32(U, In + 28) + buffer.readu32(E1, In + 28), 0)
		local C14 = buffer.readu16(Compress, bit32.band(bit32.lshift(S7, 1), 0xfffe))
		local C15 = buffer.readu16(Compress, bit32.band(bit32.rshift(S7, 15), 0xfffe))
		buffer.writeu32(Output, Out + 16, bit32.bor(bit32.rshift(C12, 8), bit32.lshift(C13, 2), bit32.lshift(C14, 12), bit32.lshift(C15, 22)))
	end
end

local function EncodeU11(U: buffer, E1: buffer, Coefficients: number, Output: buffer)
	local Compress = COMPRESS_11
	for In = 0, Coefficients * 2 - 64, 64 do
		local Out = In * 0.6875
		local S0 = bit32.bor(buffer.readu32(U, In) + buffer.readu32(E1, In), 0)
		local C0 = buffer.readu16(Compress, bit32.band(bit32.lshift(S0, 1), 0xfffe))
		local C1 = buffer.readu16(Compress, bit32.band(bit32.rshift(S0, 15), 0xfffe))
		local S1 = bit32.bor(buffer.readu32(U, In + 4) + buffer.readu32(E1, In + 4), 0)
		local C2 = buffer.readu16(Compress, bit32.band(bit32.lshift(S1, 1), 0xfffe))
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 11), bit32.lshift(C2, 22)))
		local C3 = buffer.readu16(Compress, bit32.band(bit32.rshift(S1, 15), 0xfffe))
		local S2 = bit32.bor(buffer.readu32(U, In + 8) + buffer.readu32(E1, In + 8), 0)
		local C4 = buffer.readu16(Compress, bit32.band(bit32.lshift(S2, 1), 0xfffe))
		local C5 = buffer.readu16(Compress, bit32.band(bit32.rshift(S2, 15), 0xfffe))
		buffer.writeu32(Output, Out + 4, bit32.bor(bit32.rshift(C2, 10), bit32.lshift(C3, 1), bit32.lshift(C4, 12), bit32.lshift(C5, 23)))
		local S3 = bit32.bor(buffer.readu32(U, In + 12) + buffer.readu32(E1, In + 12), 0)
		local C6 = buffer.readu16(Compress, bit32.band(bit32.lshift(S3, 1), 0xfffe))
		local C7 = buffer.readu16(Compress, bit32.band(bit32.rshift(S3, 15), 0xfffe))
		local S4 = bit32.bor(buffer.readu32(U, In + 16) + buffer.readu32(E1, In + 16), 0)
		local C8 = buffer.readu16(Compress, bit32.band(bit32.lshift(S4, 1), 0xfffe))
		buffer.writeu32(Output, Out + 8, bit32.bor(bit32.rshift(C5, 9), bit32.lshift(C6, 2), bit32.lshift(C7, 13), bit32.lshift(C8, 24)))
		local C9 = buffer.readu16(Compress, bit32.band(bit32.rshift(S4, 15), 0xfffe))
		local S5 = bit32.bor(buffer.readu32(U, In + 20) + buffer.readu32(E1, In + 20), 0)
		local C10 = buffer.readu16(Compress, bit32.band(bit32.lshift(S5, 1), 0xfffe))
		local C11 = buffer.readu16(Compress, bit32.band(bit32.rshift(S5, 15), 0xfffe))
		buffer.writeu32(Output, Out + 12, bit32.bor(bit32.rshift(C8, 8), bit32.lshift(C9, 3), bit32.lshift(C10, 14), bit32.lshift(C11, 25)))
		local S6 = bit32.bor(buffer.readu32(U, In + 24) + buffer.readu32(E1, In + 24), 0)
		local C12 = buffer.readu16(Compress, bit32.band(bit32.lshift(S6, 1), 0xfffe))
		local C13 = buffer.readu16(Compress, bit32.band(bit32.rshift(S6, 15), 0xfffe))
		local S7 = bit32.bor(buffer.readu32(U, In + 28) + buffer.readu32(E1, In + 28), 0)
		local C14 = buffer.readu16(Compress, bit32.band(bit32.lshift(S7, 1), 0xfffe))
		buffer.writeu32(Output, Out + 16, bit32.bor(bit32.rshift(C11, 7), bit32.lshift(C12, 4), bit32.lshift(C13, 15), bit32.lshift(C14, 26)))
		local C15 = buffer.readu16(Compress, bit32.band(bit32.rshift(S7, 15), 0xfffe))
		local S8 = bit32.bor(buffer.readu32(U, In + 32) + buffer.readu32(E1, In + 32), 0)
		local C16 = buffer.readu16(Compress, bit32.band(bit32.lshift(S8, 1), 0xfffe))
		local C17 = buffer.readu16(Compress, bit32.band(bit32.rshift(S8, 15), 0xfffe))
		buffer.writeu32(Output, Out + 20, bit32.bor(bit32.rshift(C14, 6), bit32.lshift(C15, 5), bit32.lshift(C16, 16), bit32.lshift(C17, 27)))
		local S9 = bit32.bor(buffer.readu32(U, In + 36) + buffer.readu32(E1, In + 36), 0)
		local C18 = buffer.readu16(Compress, bit32.band(bit32.lshift(S9, 1), 0xfffe))
		local C19 = buffer.readu16(Compress, bit32.band(bit32.rshift(S9, 15), 0xfffe))
		local S10 = bit32.bor(buffer.readu32(U, In + 40) + buffer.readu32(E1, In + 40), 0)
		local C20 = buffer.readu16(Compress, bit32.band(bit32.lshift(S10, 1), 0xfffe))
		buffer.writeu32(Output, Out + 24, bit32.bor(bit32.rshift(C17, 5), bit32.lshift(C18, 6), bit32.lshift(C19, 17), bit32.lshift(C20, 28)))
		local C21 = buffer.readu16(Compress, bit32.band(bit32.rshift(S10, 15), 0xfffe))
		local S11 = bit32.bor(buffer.readu32(U, In + 44) + buffer.readu32(E1, In + 44), 0)
		local C22 = buffer.readu16(Compress, bit32.band(bit32.lshift(S11, 1), 0xfffe))
		local C23 = buffer.readu16(Compress, bit32.band(bit32.rshift(S11, 15), 0xfffe))
		buffer.writeu32(Output, Out + 28, bit32.bor(bit32.rshift(C20, 4), bit32.lshift(C21, 7), bit32.lshift(C22, 18), bit32.lshift(C23, 29)))
		local S12 = bit32.bor(buffer.readu32(U, In + 48) + buffer.readu32(E1, In + 48), 0)
		local C24 = buffer.readu16(Compress, bit32.band(bit32.lshift(S12, 1), 0xfffe))
		local C25 = buffer.readu16(Compress, bit32.band(bit32.rshift(S12, 15), 0xfffe))
		local S13 = bit32.bor(buffer.readu32(U, In + 52) + buffer.readu32(E1, In + 52), 0)
		local C26 = buffer.readu16(Compress, bit32.band(bit32.lshift(S13, 1), 0xfffe))
		buffer.writeu32(Output, Out + 32, bit32.bor(bit32.rshift(C23, 3), bit32.lshift(C24, 8), bit32.lshift(C25, 19), bit32.lshift(C26, 30)))
		local C27 = buffer.readu16(Compress, bit32.band(bit32.rshift(S13, 15), 0xfffe))
		local S14 = bit32.bor(buffer.readu32(U, In + 56) + buffer.readu32(E1, In + 56), 0)
		local C28 = buffer.readu16(Compress, bit32.band(bit32.lshift(S14, 1), 0xfffe))
		local C29 = buffer.readu16(Compress, bit32.band(bit32.rshift(S14, 15), 0xfffe))
		buffer.writeu32(Output, Out + 36, bit32.bor(bit32.rshift(C26, 2), bit32.lshift(C27, 9), bit32.lshift(C28, 20), bit32.lshift(C29, 31)))
		local S15 = bit32.bor(buffer.readu32(U, In + 60) + buffer.readu32(E1, In + 60), 0)
		local C30 = buffer.readu16(Compress, bit32.band(bit32.lshift(S15, 1), 0xfffe))
		local C31 = buffer.readu16(Compress, bit32.band(bit32.rshift(S15, 15), 0xfffe))
		buffer.writeu32(Output, Out + 40, bit32.bor(bit32.rshift(C29, 1), bit32.lshift(C30, 10), bit32.lshift(C31, 21)))
	end
end

local function DecodeU10(Data: buffer, Coefficients: number, U: buffer)
	local Decompress = DECOMPRESS_10
	for Out = 0, Coefficients * 2 - 32, 32 do
		local In = Out * 0.625
		local W0 = buffer.readu32(Data, In)
		buffer.writeu32(U, Out, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(W0, 1023), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W0, 10), 1023), 1)), 16)))
		local W1 = buffer.readu32(Data, In + 4)
		buffer.writeu32(U, Out + 4, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W0, 20), 1023), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W0, 30), bit32.lshift(W1, 2)), 1023), 1)), 16)))
		buffer.writeu32(U, Out + 8, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 8), 1023), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 18), 1023), 1)), 16)))
		local W2 = buffer.readu32(Data, In + 8)
		buffer.writeu32(U, Out + 12, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W1, 28), bit32.lshift(W2, 4)), 1023), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 6), 1023), 1)), 16)))
		local W3 = buffer.readu32(Data, In + 12)
		buffer.writeu32(U, Out + 16, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 16), 1023), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W2, 26), bit32.lshift(W3, 6)), 1023), 1)), 16)))
		buffer.writeu32(U, Out + 20, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 4), 1023), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 14), 1023), 1)), 16)))
		local W4 = buffer.readu32(Data, In + 16)
		buffer.writeu32(U, Out + 24, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W3, 24), bit32.lshift(W4, 8)), 1023), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W4, 2), 1023), 1)), 16)))
		buffer.writeu32(U, Out + 28, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W4, 12), 1023), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.rshift(W4, 22), 1)), 16)))
	end
end

local function DecodeU11(Data: buffer, Coefficients: number, U: buffer)
	local Decompress = DECOMPRESS_11
	for Out = 0, Coefficients * 2 - 64, 64 do
		local In = Out * 0.6875
		local W0 = buffer.readu32(Data, In)
		buffer.writeu32(U, Out, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(W0, 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W0, 11), 2047), 1)), 16)))
		local W1 = buffer.readu32(Data, In + 4)
		buffer.writeu32(U, Out + 4, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W0, 22), bit32.lshift(W1, 10)), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 1), 2047), 1)), 16)))
		local W2 = buffer.readu32(Data, In + 8)
		buffer.writeu32(U, Out + 8, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 12), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W1, 23), bit32.lshift(W2, 9)), 2047), 1)), 16)))
		buffer.writeu32(U, Out + 12, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 2), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 13), 2047), 1)), 16)))
		local W3 = buffer.readu32(Data, In + 12)
		buffer.writeu32(U, Out + 16, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W2, 24), bit32.lshift(W3, 8)), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 3), 2047), 1)), 16)))
		local W4 = buffer.readu32(Data, In + 16)
		buffer.writeu32(U, Out + 20, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 14), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W3, 25), bit32.lshift(W4, 7)), 2047), 1)), 16)))
		buffer.writeu32(U, Out + 24, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W4, 4), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W4, 15), 2047), 1)), 16)))
		local W5 = buffer.readu32(Data, In + 20)
		buffer.writeu32(U, Out + 28, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W4, 26), bit32.lshift(W5, 6)), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W5, 5), 2047), 1)), 16)))
		local W6 = buffer.readu32(Data, In + 24)
		buffer.writeu32(U, Out + 32, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W5, 16), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W5, 27), bit32.lshift(W6, 5)), 2047), 1)), 16)))
		buffer.writeu32(U, Out + 36, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W6, 6), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W6, 17), 2047), 1)), 16)))
		local W7 = buffer.readu32(Data, In + 28)
		buffer.writeu32(U, Out + 40, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W6, 28), bit32.lshift(W7, 4)), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W7, 7), 2047), 1)), 16)))
		local W8 = buffer.readu32(Data, In + 32)
		buffer.writeu32(U, Out + 44, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W7, 18), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W7, 29), bit32.lshift(W8, 3)), 2047), 1)), 16)))
		buffer.writeu32(U, Out + 48, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W8, 8), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W8, 19), 2047), 1)), 16)))
		local W9 = buffer.readu32(Data, In + 36)
		buffer.writeu32(U, Out + 52, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W8, 30), bit32.lshift(W9, 2)), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W9, 9), 2047), 1)), 16)))
		local W10 = buffer.readu32(Data, In + 40)
		buffer.writeu32(U, Out + 56, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W9, 20), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W9, 31), bit32.lshift(W10, 1)), 2047), 1)), 16)))
		buffer.writeu32(U, Out + 60, bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W10, 10), 2047), 1)), bit32.lshift(buffer.readu16(Decompress, bit32.lshift(bit32.rshift(W10, 21), 1)), 16)))
	end
end

local function EncodeV4(V: buffer, E2: buffer, Message: buffer, Output: buffer, OutputOffset: number)
	local Compress = COMPRESS_4
	local MessagePairs = MESSAGE_PAIRS
	for In = 0, 448, 64 do
		local Out = OutputOffset + In * 0.25
		local MessageBits = buffer.readu32(Message, In / 16)
		local S0 = bit32.bor(bit32.bor(buffer.readu32(V, In) + buffer.readu32(E2, In), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.lshift(MessageBits, 2), 12)), 0)
		local C0 = buffer.readu16(Compress, bit32.band(bit32.lshift(S0, 1), 0xfffe))
		local C1 = buffer.readu16(Compress, bit32.band(bit32.rshift(S0, 15), 0xfffe))
		local S1 = bit32.bor(bit32.bor(buffer.readu32(V, In + 4) + buffer.readu32(E2, In + 4), 0) + buffer.readu32(MessagePairs, bit32.band(MessageBits, 12)), 0)
		local C2 = buffer.readu16(Compress, bit32.band(bit32.lshift(S1, 1), 0xfffe))
		local C3 = buffer.readu16(Compress, bit32.band(bit32.rshift(S1, 15), 0xfffe))
		local S2 = bit32.bor(bit32.bor(buffer.readu32(V, In + 8) + buffer.readu32(E2, In + 8), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 2), 12)), 0)
		local C4 = buffer.readu16(Compress, bit32.band(bit32.lshift(S2, 1), 0xfffe))
		local C5 = buffer.readu16(Compress, bit32.band(bit32.rshift(S2, 15), 0xfffe))
		local S3 = bit32.bor(bit32.bor(buffer.readu32(V, In + 12) + buffer.readu32(E2, In + 12), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 4), 12)), 0)
		local C6 = buffer.readu16(Compress, bit32.band(bit32.lshift(S3, 1), 0xfffe))
		local C7 = buffer.readu16(Compress, bit32.band(bit32.rshift(S3, 15), 0xfffe))
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 4), bit32.lshift(C2, 8), bit32.lshift(C3, 12), bit32.bor(bit32.lshift(C4, 16), bit32.lshift(C5, 20), bit32.lshift(C6, 24), bit32.lshift(C7, 28))))
		local S4 = bit32.bor(bit32.bor(buffer.readu32(V, In + 16) + buffer.readu32(E2, In + 16), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 6), 12)), 0)
		local C8 = buffer.readu16(Compress, bit32.band(bit32.lshift(S4, 1), 0xfffe))
		local C9 = buffer.readu16(Compress, bit32.band(bit32.rshift(S4, 15), 0xfffe))
		local S5 = bit32.bor(bit32.bor(buffer.readu32(V, In + 20) + buffer.readu32(E2, In + 20), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 8), 12)), 0)
		local C10 = buffer.readu16(Compress, bit32.band(bit32.lshift(S5, 1), 0xfffe))
		local C11 = buffer.readu16(Compress, bit32.band(bit32.rshift(S5, 15), 0xfffe))
		local S6 = bit32.bor(bit32.bor(buffer.readu32(V, In + 24) + buffer.readu32(E2, In + 24), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 10), 12)), 0)
		local C12 = buffer.readu16(Compress, bit32.band(bit32.lshift(S6, 1), 0xfffe))
		local C13 = buffer.readu16(Compress, bit32.band(bit32.rshift(S6, 15), 0xfffe))
		local S7 = bit32.bor(bit32.bor(buffer.readu32(V, In + 28) + buffer.readu32(E2, In + 28), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 12), 12)), 0)
		local C14 = buffer.readu16(Compress, bit32.band(bit32.lshift(S7, 1), 0xfffe))
		local C15 = buffer.readu16(Compress, bit32.band(bit32.rshift(S7, 15), 0xfffe))
		buffer.writeu32(Output, Out + 4, bit32.bor(C8, bit32.lshift(C9, 4), bit32.lshift(C10, 8), bit32.lshift(C11, 12), bit32.bor(bit32.lshift(C12, 16), bit32.lshift(C13, 20), bit32.lshift(C14, 24), bit32.lshift(C15, 28))))
		local S8 = bit32.bor(bit32.bor(buffer.readu32(V, In + 32) + buffer.readu32(E2, In + 32), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 14), 12)), 0)
		local C16 = buffer.readu16(Compress, bit32.band(bit32.lshift(S8, 1), 0xfffe))
		local C17 = buffer.readu16(Compress, bit32.band(bit32.rshift(S8, 15), 0xfffe))
		local S9 = bit32.bor(bit32.bor(buffer.readu32(V, In + 36) + buffer.readu32(E2, In + 36), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 16), 12)), 0)
		local C18 = buffer.readu16(Compress, bit32.band(bit32.lshift(S9, 1), 0xfffe))
		local C19 = buffer.readu16(Compress, bit32.band(bit32.rshift(S9, 15), 0xfffe))
		local S10 = bit32.bor(bit32.bor(buffer.readu32(V, In + 40) + buffer.readu32(E2, In + 40), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 18), 12)), 0)
		local C20 = buffer.readu16(Compress, bit32.band(bit32.lshift(S10, 1), 0xfffe))
		local C21 = buffer.readu16(Compress, bit32.band(bit32.rshift(S10, 15), 0xfffe))
		local S11 = bit32.bor(bit32.bor(buffer.readu32(V, In + 44) + buffer.readu32(E2, In + 44), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 20), 12)), 0)
		local C22 = buffer.readu16(Compress, bit32.band(bit32.lshift(S11, 1), 0xfffe))
		local C23 = buffer.readu16(Compress, bit32.band(bit32.rshift(S11, 15), 0xfffe))
		buffer.writeu32(Output, Out + 8, bit32.bor(C16, bit32.lshift(C17, 4), bit32.lshift(C18, 8), bit32.lshift(C19, 12), bit32.bor(bit32.lshift(C20, 16), bit32.lshift(C21, 20), bit32.lshift(C22, 24), bit32.lshift(C23, 28))))
		local S12 = bit32.bor(bit32.bor(buffer.readu32(V, In + 48) + buffer.readu32(E2, In + 48), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 22), 12)), 0)
		local C24 = buffer.readu16(Compress, bit32.band(bit32.lshift(S12, 1), 0xfffe))
		local C25 = buffer.readu16(Compress, bit32.band(bit32.rshift(S12, 15), 0xfffe))
		local S13 = bit32.bor(bit32.bor(buffer.readu32(V, In + 52) + buffer.readu32(E2, In + 52), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 24), 12)), 0)
		local C26 = buffer.readu16(Compress, bit32.band(bit32.lshift(S13, 1), 0xfffe))
		local C27 = buffer.readu16(Compress, bit32.band(bit32.rshift(S13, 15), 0xfffe))
		local S14 = bit32.bor(bit32.bor(buffer.readu32(V, In + 56) + buffer.readu32(E2, In + 56), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 26), 12)), 0)
		local C28 = buffer.readu16(Compress, bit32.band(bit32.lshift(S14, 1), 0xfffe))
		local C29 = buffer.readu16(Compress, bit32.band(bit32.rshift(S14, 15), 0xfffe))
		local S15 = bit32.bor(bit32.bor(buffer.readu32(V, In + 60) + buffer.readu32(E2, In + 60), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 28), 12)), 0)
		local C30 = buffer.readu16(Compress, bit32.band(bit32.lshift(S15, 1), 0xfffe))
		local C31 = buffer.readu16(Compress, bit32.band(bit32.rshift(S15, 15), 0xfffe))
		buffer.writeu32(Output, Out + 12, bit32.bor(C24, bit32.lshift(C25, 4), bit32.lshift(C26, 8), bit32.lshift(C27, 12), bit32.bor(bit32.lshift(C28, 16), bit32.lshift(C29, 20), bit32.lshift(C30, 24), bit32.lshift(C31, 28))))
	end
end

local function EncodeV5(V: buffer, E2: buffer, Message: buffer, Output: buffer, OutputOffset: number)
	local Compress = COMPRESS_5
	local MessagePairs = MESSAGE_PAIRS
	for In = 0, 448, 64 do
		local Out = OutputOffset + In * 0.3125
		local MessageBits = buffer.readu32(Message, In / 16)
		local S0 = bit32.bor(bit32.bor(buffer.readu32(V, In) + buffer.readu32(E2, In), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.lshift(MessageBits, 2), 12)), 0)
		local C0 = buffer.readu16(Compress, bit32.band(bit32.lshift(S0, 1), 0xfffe))
		local C1 = buffer.readu16(Compress, bit32.band(bit32.rshift(S0, 15), 0xfffe))
		local S1 = bit32.bor(bit32.bor(buffer.readu32(V, In + 4) + buffer.readu32(E2, In + 4), 0) + buffer.readu32(MessagePairs, bit32.band(MessageBits, 12)), 0)
		local C2 = buffer.readu16(Compress, bit32.band(bit32.lshift(S1, 1), 0xfffe))
		local C3 = buffer.readu16(Compress, bit32.band(bit32.rshift(S1, 15), 0xfffe))
		local S2 = bit32.bor(bit32.bor(buffer.readu32(V, In + 8) + buffer.readu32(E2, In + 8), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 2), 12)), 0)
		local C4 = buffer.readu16(Compress, bit32.band(bit32.lshift(S2, 1), 0xfffe))
		local C5 = buffer.readu16(Compress, bit32.band(bit32.rshift(S2, 15), 0xfffe))
		local S3 = bit32.bor(bit32.bor(buffer.readu32(V, In + 12) + buffer.readu32(E2, In + 12), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 4), 12)), 0)
		local C6 = buffer.readu16(Compress, bit32.band(bit32.lshift(S3, 1), 0xfffe))
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 5), bit32.lshift(C2, 10), bit32.lshift(C3, 15), bit32.bor(bit32.lshift(C4, 20), bit32.lshift(C5, 25), bit32.lshift(C6, 30))))
		local C7 = buffer.readu16(Compress, bit32.band(bit32.rshift(S3, 15), 0xfffe))
		local S4 = bit32.bor(bit32.bor(buffer.readu32(V, In + 16) + buffer.readu32(E2, In + 16), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 6), 12)), 0)
		local C8 = buffer.readu16(Compress, bit32.band(bit32.lshift(S4, 1), 0xfffe))
		local C9 = buffer.readu16(Compress, bit32.band(bit32.rshift(S4, 15), 0xfffe))
		local S5 = bit32.bor(bit32.bor(buffer.readu32(V, In + 20) + buffer.readu32(E2, In + 20), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 8), 12)), 0)
		local C10 = buffer.readu16(Compress, bit32.band(bit32.lshift(S5, 1), 0xfffe))
		local C11 = buffer.readu16(Compress, bit32.band(bit32.rshift(S5, 15), 0xfffe))
		local S6 = bit32.bor(bit32.bor(buffer.readu32(V, In + 24) + buffer.readu32(E2, In + 24), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 10), 12)), 0)
		local C12 = buffer.readu16(Compress, bit32.band(bit32.lshift(S6, 1), 0xfffe))
		buffer.writeu32(Output, Out + 4, bit32.bor(bit32.rshift(C6, 2), bit32.lshift(C7, 3), bit32.lshift(C8, 8), bit32.lshift(C9, 13), bit32.bor(bit32.lshift(C10, 18), bit32.lshift(C11, 23), bit32.lshift(C12, 28))))
		local C13 = buffer.readu16(Compress, bit32.band(bit32.rshift(S6, 15), 0xfffe))
		local S7 = bit32.bor(bit32.bor(buffer.readu32(V, In + 28) + buffer.readu32(E2, In + 28), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 12), 12)), 0)
		local C14 = buffer.readu16(Compress, bit32.band(bit32.lshift(S7, 1), 0xfffe))
		local C15 = buffer.readu16(Compress, bit32.band(bit32.rshift(S7, 15), 0xfffe))
		local S8 = bit32.bor(bit32.bor(buffer.readu32(V, In + 32) + buffer.readu32(E2, In + 32), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 14), 12)), 0)
		local C16 = buffer.readu16(Compress, bit32.band(bit32.lshift(S8, 1), 0xfffe))
		local C17 = buffer.readu16(Compress, bit32.band(bit32.rshift(S8, 15), 0xfffe))
		local S9 = bit32.bor(bit32.bor(buffer.readu32(V, In + 36) + buffer.readu32(E2, In + 36), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 16), 12)), 0)
		local C18 = buffer.readu16(Compress, bit32.band(bit32.lshift(S9, 1), 0xfffe))
		local C19 = buffer.readu16(Compress, bit32.band(bit32.rshift(S9, 15), 0xfffe))
		buffer.writeu32(Output, Out + 8, bit32.bor(bit32.rshift(C12, 4), bit32.lshift(C13, 1), bit32.lshift(C14, 6), bit32.lshift(C15, 11), bit32.bor(bit32.lshift(C16, 16), bit32.lshift(C17, 21), bit32.lshift(C18, 26), bit32.lshift(C19, 31))))
		local S10 = bit32.bor(bit32.bor(buffer.readu32(V, In + 40) + buffer.readu32(E2, In + 40), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 18), 12)), 0)
		local C20 = buffer.readu16(Compress, bit32.band(bit32.lshift(S10, 1), 0xfffe))
		local C21 = buffer.readu16(Compress, bit32.band(bit32.rshift(S10, 15), 0xfffe))
		local S11 = bit32.bor(bit32.bor(buffer.readu32(V, In + 44) + buffer.readu32(E2, In + 44), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 20), 12)), 0)
		local C22 = buffer.readu16(Compress, bit32.band(bit32.lshift(S11, 1), 0xfffe))
		local C23 = buffer.readu16(Compress, bit32.band(bit32.rshift(S11, 15), 0xfffe))
		local S12 = bit32.bor(bit32.bor(buffer.readu32(V, In + 48) + buffer.readu32(E2, In + 48), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 22), 12)), 0)
		local C24 = buffer.readu16(Compress, bit32.band(bit32.lshift(S12, 1), 0xfffe))
		local C25 = buffer.readu16(Compress, bit32.band(bit32.rshift(S12, 15), 0xfffe))
		buffer.writeu32(Output, Out + 12, bit32.bor(bit32.rshift(C19, 1), bit32.lshift(C20, 4), bit32.lshift(C21, 9), bit32.lshift(C22, 14), bit32.bor(bit32.lshift(C23, 19), bit32.lshift(C24, 24), bit32.lshift(C25, 29))))
		local S13 = bit32.bor(bit32.bor(buffer.readu32(V, In + 52) + buffer.readu32(E2, In + 52), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 24), 12)), 0)
		local C26 = buffer.readu16(Compress, bit32.band(bit32.lshift(S13, 1), 0xfffe))
		local C27 = buffer.readu16(Compress, bit32.band(bit32.rshift(S13, 15), 0xfffe))
		local S14 = bit32.bor(bit32.bor(buffer.readu32(V, In + 56) + buffer.readu32(E2, In + 56), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 26), 12)), 0)
		local C28 = buffer.readu16(Compress, bit32.band(bit32.lshift(S14, 1), 0xfffe))
		local C29 = buffer.readu16(Compress, bit32.band(bit32.rshift(S14, 15), 0xfffe))
		local S15 = bit32.bor(bit32.bor(buffer.readu32(V, In + 60) + buffer.readu32(E2, In + 60), 0) + buffer.readu32(MessagePairs, bit32.band(bit32.rshift(MessageBits, 28), 12)), 0)
		local C30 = buffer.readu16(Compress, bit32.band(bit32.lshift(S15, 1), 0xfffe))
		local C31 = buffer.readu16(Compress, bit32.band(bit32.rshift(S15, 15), 0xfffe))
		buffer.writeu32(Output, Out + 16, bit32.bor(bit32.rshift(C25, 3), bit32.lshift(C26, 2), bit32.lshift(C27, 7), bit32.lshift(C28, 12), bit32.bor(bit32.lshift(C29, 17), bit32.lshift(C30, 22), bit32.lshift(C31, 27))))
	end
end

local function DecodeMessage4(Data: buffer, DataOffset: number, Product: buffer, Message: buffer)
	local Decompress = DECOMPRESS_4
	local Compress = COMPRESS_1
	for Out = 0, 448, 64 do
		local In = DataOffset + Out * 0.25
		local P0 = buffer.readu32(Product, Out)
		local W0 = buffer.readu32(Data, In)
		local X0 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(W0, 15), 1)) + 3329, 0) - bit32.band(P0, 0xffff), 0)
		local X1 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W0, 4), 15), 1)) + 3329, 0) - bit32.rshift(P0, 16), 0)
		local P1 = buffer.readu32(Product, Out + 4)
		local X2 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W0, 8), 15), 1)) + 3329, 0) - bit32.band(P1, 0xffff), 0)
		local X3 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W0, 12), 15), 1)) + 3329, 0) - bit32.rshift(P1, 16), 0)
		local P2 = buffer.readu32(Product, Out + 8)
		local X4 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W0, 16), 15), 1)) + 3329, 0) - bit32.band(P2, 0xffff), 0)
		local X5 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W0, 20), 15), 1)) + 3329, 0) - bit32.rshift(P2, 16), 0)
		local P3 = buffer.readu32(Product, Out + 12)
		local X6 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W0, 24), 15), 1)) + 3329, 0) - bit32.band(P3, 0xffff), 0)
		local X7 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.rshift(W0, 28), 1)) + 3329, 0) - bit32.rshift(P3, 16), 0)
		local P4 = buffer.readu32(Product, Out + 16)
		local W1 = buffer.readu32(Data, In + 4)
		local X8 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(W1, 15), 1)) + 3329, 0) - bit32.band(P4, 0xffff), 0)
		local X9 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 4), 15), 1)) + 3329, 0) - bit32.rshift(P4, 16), 0)
		local P5 = buffer.readu32(Product, Out + 20)
		local X10 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 8), 15), 1)) + 3329, 0) - bit32.band(P5, 0xffff), 0)
		local X11 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 12), 15), 1)) + 3329, 0) - bit32.rshift(P5, 16), 0)
		local P6 = buffer.readu32(Product, Out + 24)
		local X12 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 16), 15), 1)) + 3329, 0) - bit32.band(P6, 0xffff), 0)
		local X13 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 20), 15), 1)) + 3329, 0) - bit32.rshift(P6, 16), 0)
		local P7 = buffer.readu32(Product, Out + 28)
		local X14 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 24), 15), 1)) + 3329, 0) - bit32.band(P7, 0xffff), 0)
		local X15 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.rshift(W1, 28), 1)) + 3329, 0) - bit32.rshift(P7, 16), 0)
		local P8 = buffer.readu32(Product, Out + 32)
		local W2 = buffer.readu32(Data, In + 8)
		local X16 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(W2, 15), 1)) + 3329, 0) - bit32.band(P8, 0xffff), 0)
		local X17 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 4), 15), 1)) + 3329, 0) - bit32.rshift(P8, 16), 0)
		local P9 = buffer.readu32(Product, Out + 36)
		local X18 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 8), 15), 1)) + 3329, 0) - bit32.band(P9, 0xffff), 0)
		local X19 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 12), 15), 1)) + 3329, 0) - bit32.rshift(P9, 16), 0)
		local P10 = buffer.readu32(Product, Out + 40)
		local X20 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 16), 15), 1)) + 3329, 0) - bit32.band(P10, 0xffff), 0)
		local X21 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 20), 15), 1)) + 3329, 0) - bit32.rshift(P10, 16), 0)
		local P11 = buffer.readu32(Product, Out + 44)
		local X22 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 24), 15), 1)) + 3329, 0) - bit32.band(P11, 0xffff), 0)
		local X23 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.rshift(W2, 28), 1)) + 3329, 0) - bit32.rshift(P11, 16), 0)
		local P12 = buffer.readu32(Product, Out + 48)
		local W3 = buffer.readu32(Data, In + 12)
		local X24 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(W3, 15), 1)) + 3329, 0) - bit32.band(P12, 0xffff), 0)
		local X25 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 4), 15), 1)) + 3329, 0) - bit32.rshift(P12, 16), 0)
		local P13 = buffer.readu32(Product, Out + 52)
		local X26 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 8), 15), 1)) + 3329, 0) - bit32.band(P13, 0xffff), 0)
		local X27 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 12), 15), 1)) + 3329, 0) - bit32.rshift(P13, 16), 0)
		local P14 = buffer.readu32(Product, Out + 56)
		local X28 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 16), 15), 1)) + 3329, 0) - bit32.band(P14, 0xffff), 0)
		local X29 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 20), 15), 1)) + 3329, 0) - bit32.rshift(P14, 16), 0)
		local P15 = buffer.readu32(Product, Out + 60)
		local X30 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 24), 15), 1)) + 3329, 0) - bit32.band(P15, 0xffff), 0)
		local X31 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.rshift(W3, 28), 1)) + 3329, 0) - bit32.rshift(P15, 16), 0)
		buffer.writeu32(Message, Out / 16, bit32.bor(buffer.readu16(Compress, bit32.lshift(X0, 1)), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X1, 1)), 1), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X2, 1)), 2), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X3, 1)), 3), bit32.bor(bit32.lshift(buffer.readu16(Compress, bit32.lshift(X4, 1)), 4), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X5, 1)), 5), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X6, 1)), 6), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X7, 1)), 7), bit32.bor(bit32.lshift(buffer.readu16(Compress, bit32.lshift(X8, 1)), 8), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X9, 1)), 9), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X10, 1)), 10), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X11, 1)), 11), bit32.bor(bit32.lshift(buffer.readu16(Compress, bit32.lshift(X12, 1)), 12), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X13, 1)), 13), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X14, 1)), 14), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X15, 1)), 15), bit32.bor(bit32.lshift(buffer.readu16(Compress, bit32.lshift(X16, 1)), 16), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X17, 1)), 17), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X18, 1)), 18), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X19, 1)), 19), bit32.bor(bit32.lshift(buffer.readu16(Compress, bit32.lshift(X20, 1)), 20), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X21, 1)), 21), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X22, 1)), 22), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X23, 1)), 23), bit32.bor(bit32.lshift(buffer.readu16(Compress, bit32.lshift(X24, 1)), 24), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X25, 1)), 25), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X26, 1)), 26), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X27, 1)), 27), bit32.bor(bit32.lshift(buffer.readu16(Compress, bit32.lshift(X28, 1)), 28), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X29, 1)), 29), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X30, 1)), 30), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X31, 1)), 31))))))))))
	end
end

local function DecodeMessage5(Data: buffer, DataOffset: number, Product: buffer, Message: buffer)
	local Decompress = DECOMPRESS_5
	local Compress = COMPRESS_1
	for Out = 0, 448, 64 do
		local In = DataOffset + Out * 0.3125
		local P0 = buffer.readu32(Product, Out)
		local W0 = buffer.readu32(Data, In)
		local X0 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(W0, 31), 1)) + 3329, 0) - bit32.band(P0, 0xffff), 0)
		local X1 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W0, 5), 31), 1)) + 3329, 0) - bit32.rshift(P0, 16), 0)
		local P1 = buffer.readu32(Product, Out + 4)
		local X2 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W0, 10), 31), 1)) + 3329, 0) - bit32.band(P1, 0xffff), 0)
		local X3 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W0, 15), 31), 1)) + 3329, 0) - bit32.rshift(P1, 16), 0)
		local P2 = buffer.readu32(Product, Out + 8)
		local X4 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W0, 20), 31), 1)) + 3329, 0) - bit32.band(P2, 0xffff), 0)
		local X5 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W0, 25), 31), 1)) + 3329, 0) - bit32.rshift(P2, 16), 0)
		local P3 = buffer.readu32(Product, Out + 12)
		local W1 = buffer.readu32(Data, In + 4)
		local X6 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W0, 30), bit32.lshift(W1, 2)), 31), 1)) + 3329, 0) - bit32.band(P3, 0xffff), 0)
		local X7 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 3), 31), 1)) + 3329, 0) - bit32.rshift(P3, 16), 0)
		local P4 = buffer.readu32(Product, Out + 16)
		local X8 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 8), 31), 1)) + 3329, 0) - bit32.band(P4, 0xffff), 0)
		local X9 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 13), 31), 1)) + 3329, 0) - bit32.rshift(P4, 16), 0)
		local P5 = buffer.readu32(Product, Out + 20)
		local X10 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 18), 31), 1)) + 3329, 0) - bit32.band(P5, 0xffff), 0)
		local X11 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W1, 23), 31), 1)) + 3329, 0) - bit32.rshift(P5, 16), 0)
		local P6 = buffer.readu32(Product, Out + 24)
		local W2 = buffer.readu32(Data, In + 8)
		local X12 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W1, 28), bit32.lshift(W2, 4)), 31), 1)) + 3329, 0) - bit32.band(P6, 0xffff), 0)
		local X13 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 1), 31), 1)) + 3329, 0) - bit32.rshift(P6, 16), 0)
		local P7 = buffer.readu32(Product, Out + 28)
		local X14 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 6), 31), 1)) + 3329, 0) - bit32.band(P7, 0xffff), 0)
		local X15 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 11), 31), 1)) + 3329, 0) - bit32.rshift(P7, 16), 0)
		local P8 = buffer.readu32(Product, Out + 32)
		local X16 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 16), 31), 1)) + 3329, 0) - bit32.band(P8, 0xffff), 0)
		local X17 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 21), 31), 1)) + 3329, 0) - bit32.rshift(P8, 16), 0)
		local P9 = buffer.readu32(Product, Out + 36)
		local X18 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W2, 26), 31), 1)) + 3329, 0) - bit32.band(P9, 0xffff), 0)
		local W3 = buffer.readu32(Data, In + 12)
		local X19 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W2, 31), bit32.lshift(W3, 1)), 31), 1)) + 3329, 0) - bit32.rshift(P9, 16), 0)
		local P10 = buffer.readu32(Product, Out + 40)
		local X20 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 4), 31), 1)) + 3329, 0) - bit32.band(P10, 0xffff), 0)
		local X21 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 9), 31), 1)) + 3329, 0) - bit32.rshift(P10, 16), 0)
		local P11 = buffer.readu32(Product, Out + 44)
		local X22 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 14), 31), 1)) + 3329, 0) - bit32.band(P11, 0xffff), 0)
		local X23 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 19), 31), 1)) + 3329, 0) - bit32.rshift(P11, 16), 0)
		local P12 = buffer.readu32(Product, Out + 48)
		local X24 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W3, 24), 31), 1)) + 3329, 0) - bit32.band(P12, 0xffff), 0)
		local W4 = buffer.readu32(Data, In + 16)
		local X25 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W3, 29), bit32.lshift(W4, 3)), 31), 1)) + 3329, 0) - bit32.rshift(P12, 16), 0)
		local P13 = buffer.readu32(Product, Out + 52)
		local X26 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W4, 2), 31), 1)) + 3329, 0) - bit32.band(P13, 0xffff), 0)
		local X27 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W4, 7), 31), 1)) + 3329, 0) - bit32.rshift(P13, 16), 0)
		local P14 = buffer.readu32(Product, Out + 56)
		local X28 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W4, 12), 31), 1)) + 3329, 0) - bit32.band(P14, 0xffff), 0)
		local X29 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W4, 17), 31), 1)) + 3329, 0) - bit32.rshift(P14, 16), 0)
		local P15 = buffer.readu32(Product, Out + 60)
		local X30 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W4, 22), 31), 1)) + 3329, 0) - bit32.band(P15, 0xffff), 0)
		local X31 = bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.rshift(W4, 27), 1)) + 3329, 0) - bit32.rshift(P15, 16), 0)
		buffer.writeu32(Message, Out / 16, bit32.bor(buffer.readu16(Compress, bit32.lshift(X0, 1)), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X1, 1)), 1), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X2, 1)), 2), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X3, 1)), 3), bit32.bor(bit32.lshift(buffer.readu16(Compress, bit32.lshift(X4, 1)), 4), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X5, 1)), 5), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X6, 1)), 6), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X7, 1)), 7), bit32.bor(bit32.lshift(buffer.readu16(Compress, bit32.lshift(X8, 1)), 8), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X9, 1)), 9), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X10, 1)), 10), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X11, 1)), 11), bit32.bor(bit32.lshift(buffer.readu16(Compress, bit32.lshift(X12, 1)), 12), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X13, 1)), 13), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X14, 1)), 14), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X15, 1)), 15), bit32.bor(bit32.lshift(buffer.readu16(Compress, bit32.lshift(X16, 1)), 16), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X17, 1)), 17), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X18, 1)), 18), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X19, 1)), 19), bit32.bor(bit32.lshift(buffer.readu16(Compress, bit32.lshift(X20, 1)), 20), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X21, 1)), 21), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X22, 1)), 22), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X23, 1)), 23), bit32.bor(bit32.lshift(buffer.readu16(Compress, bit32.lshift(X24, 1)), 24), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X25, 1)), 25), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X26, 1)), 26), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X27, 1)), 27), bit32.bor(bit32.lshift(buffer.readu16(Compress, bit32.lshift(X28, 1)), 28), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X29, 1)), 29), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X30, 1)), 30), bit32.lshift(buffer.readu16(Compress, bit32.lshift(X31, 1)), 31))))))))))
	end
end

local Packing = {
	Encode12 = Encode12,
	Decode12 = Decode12,
}

function Packing.EncodeU(U: buffer, E1: buffer, Coefficients: number, Du: number, Output: buffer)
	if Du == 10 then
		EncodeU10(U, E1, Coefficients, Output)
	else
		EncodeU11(U, E1, Coefficients, Output)
	end
end

function Packing.DecodeU(Data: buffer, Coefficients: number, Du: number, U: buffer)
	if Du == 10 then
		DecodeU10(Data, Coefficients, U)
	else
		DecodeU11(Data, Coefficients, U)
	end
end

function Packing.EncodeV(V: buffer, E2: buffer, Message: buffer, Dv: number, Output: buffer, OutputOffset: number)
	if Dv == 4 then
		EncodeV4(V, E2, Message, Output, OutputOffset)
	else
		EncodeV5(V, E2, Message, Output, OutputOffset)
	end
end

function Packing.DecodeMessage(Data: buffer, DataOffset: number, Dv: number, Product: buffer, Message: buffer)
	if Dv == 4 then
		DecodeMessage4(Data, DataOffset, Product, Message)
	else
		DecodeMessage5(Data, DataOffset, Product, Message)
	end
end

return Packing
