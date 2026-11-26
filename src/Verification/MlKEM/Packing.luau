--[=[
	Packing: the byte forms of ML-KEM polynomials (FIPS 203 ByteEncode and ByteDecode), with
	Compress, Decompress and the noise additions done in the same pass. Polynomials are 256 u16
	coefficients and a vector is K of them back to back, so a vector is packed as one long
	polynomial. The encodes take coefficients up to 3q unreduced; compressing masks the excess.
	Decode12 writes every coefficient and reports at the end whether all were below q. Nothing
	derived from a secret indexes a table, so cache timing does not reveal it

	Example usage:
		Packing.Encode12(Vector, K * 256, PublicKey, 0)
		local Valid = Packing.Decode12(PublicKey, 0, K * 256, Vector)
--]=]

--!strict
--!optimize 2
--!native

local Q = 3329
local BIAS = 1.5e-4
local SCALE_4, OFF_4 = 16 / Q, 1664 / Q + BIAS
local SCALE_5, OFF_5 = 32 / Q, 1664 / Q + BIAS
local SCALE_10, OFF_10 = 1024 / Q, 1664 / Q + BIAS
local SCALE_11, OFF_11 = 2048 / Q, 1664 / Q + BIAS

local function DecompressTable(Bits: number): buffer
	local Table = buffer.create(2 ^ Bits * 2)
	for Value = 0, 2 ^ Bits - 1 do
		buffer.writeu16(Table, Value * 2, (Value * Q + 2 ^ (Bits - 1)) // 2 ^ Bits)
	end
	return Table
end

local DECOMPRESS_4: buffer? = nil
local DECOMPRESS_5: buffer? = nil
local DECOMPRESS_10: buffer? = nil
local DECOMPRESS_11: buffer? = nil

local function Encode12(Vector: buffer, Coefficients: number, Output: buffer, OutputOffset: number): ()
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
	for In = 0, Coefficients * 2 - 32, 32 do
		local Out = In * 0.625
		local S0 = bit32.bor(buffer.readu32(U, In) + buffer.readu32(E1, In), 0)
		local C0 = bit32.band(math.floor(bit32.band(S0, 0xffff) * SCALE_10 + OFF_10), 1023)
		local C1 = bit32.band(math.floor(bit32.rshift(S0, 16) * SCALE_10 + OFF_10), 1023)
		local S1 = bit32.bor(buffer.readu32(U, In + 4) + buffer.readu32(E1, In + 4), 0)
		local C2 = bit32.band(math.floor(bit32.band(S1, 0xffff) * SCALE_10 + OFF_10), 1023)
		local C3 = bit32.band(math.floor(bit32.rshift(S1, 16) * SCALE_10 + OFF_10), 1023)
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 10), bit32.lshift(C2, 20), bit32.lshift(C3, 30)))
		local S2 = bit32.bor(buffer.readu32(U, In + 8) + buffer.readu32(E1, In + 8), 0)
		local C4 = bit32.band(math.floor(bit32.band(S2, 0xffff) * SCALE_10 + OFF_10), 1023)
		local C5 = bit32.band(math.floor(bit32.rshift(S2, 16) * SCALE_10 + OFF_10), 1023)
		local S3 = bit32.bor(buffer.readu32(U, In + 12) + buffer.readu32(E1, In + 12), 0)
		local C6 = bit32.band(math.floor(bit32.band(S3, 0xffff) * SCALE_10 + OFF_10), 1023)
		buffer.writeu32(Output, Out + 4, bit32.bor(bit32.rshift(C3, 2), bit32.lshift(C4, 8), bit32.lshift(C5, 18), bit32.lshift(C6, 28)))
		local C7 = bit32.band(math.floor(bit32.rshift(S3, 16) * SCALE_10 + OFF_10), 1023)
		local S4 = bit32.bor(buffer.readu32(U, In + 16) + buffer.readu32(E1, In + 16), 0)
		local C8 = bit32.band(math.floor(bit32.band(S4, 0xffff) * SCALE_10 + OFF_10), 1023)
		local C9 = bit32.band(math.floor(bit32.rshift(S4, 16) * SCALE_10 + OFF_10), 1023)
		buffer.writeu32(Output, Out + 8, bit32.bor(bit32.rshift(C6, 4), bit32.lshift(C7, 6), bit32.lshift(C8, 16), bit32.lshift(C9, 26)))
		local S5 = bit32.bor(buffer.readu32(U, In + 20) + buffer.readu32(E1, In + 20), 0)
		local C10 = bit32.band(math.floor(bit32.band(S5, 0xffff) * SCALE_10 + OFF_10), 1023)
		local C11 = bit32.band(math.floor(bit32.rshift(S5, 16) * SCALE_10 + OFF_10), 1023)
		local S6 = bit32.bor(buffer.readu32(U, In + 24) + buffer.readu32(E1, In + 24), 0)
		local C12 = bit32.band(math.floor(bit32.band(S6, 0xffff) * SCALE_10 + OFF_10), 1023)
		buffer.writeu32(Output, Out + 12, bit32.bor(bit32.rshift(C9, 6), bit32.lshift(C10, 4), bit32.lshift(C11, 14), bit32.lshift(C12, 24)))
		local C13 = bit32.band(math.floor(bit32.rshift(S6, 16) * SCALE_10 + OFF_10), 1023)
		local S7 = bit32.bor(buffer.readu32(U, In + 28) + buffer.readu32(E1, In + 28), 0)
		local C14 = bit32.band(math.floor(bit32.band(S7, 0xffff) * SCALE_10 + OFF_10), 1023)
		local C15 = bit32.band(math.floor(bit32.rshift(S7, 16) * SCALE_10 + OFF_10), 1023)
		buffer.writeu32(Output, Out + 16, bit32.bor(bit32.rshift(C12, 8), bit32.lshift(C13, 2), bit32.lshift(C14, 12), bit32.lshift(C15, 22)))
	end
end

local function EncodeU11(U: buffer, E1: buffer, Coefficients: number, Output: buffer)
	for In = 0, Coefficients * 2 - 64, 64 do
		local Out = In * 0.6875
		local S0 = bit32.bor(buffer.readu32(U, In) + buffer.readu32(E1, In), 0)
		local C0 = bit32.band(math.floor(bit32.band(S0, 0xffff) * SCALE_11 + OFF_11), 2047)
		local C1 = bit32.band(math.floor(bit32.rshift(S0, 16) * SCALE_11 + OFF_11), 2047)
		local S1 = bit32.bor(buffer.readu32(U, In + 4) + buffer.readu32(E1, In + 4), 0)
		local C2 = bit32.band(math.floor(bit32.band(S1, 0xffff) * SCALE_11 + OFF_11), 2047)
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 11), bit32.lshift(C2, 22)))
		local C3 = bit32.band(math.floor(bit32.rshift(S1, 16) * SCALE_11 + OFF_11), 2047)
		local S2 = bit32.bor(buffer.readu32(U, In + 8) + buffer.readu32(E1, In + 8), 0)
		local C4 = bit32.band(math.floor(bit32.band(S2, 0xffff) * SCALE_11 + OFF_11), 2047)
		local C5 = bit32.band(math.floor(bit32.rshift(S2, 16) * SCALE_11 + OFF_11), 2047)
		buffer.writeu32(Output, Out + 4, bit32.bor(bit32.rshift(C2, 10), bit32.lshift(C3, 1), bit32.lshift(C4, 12), bit32.lshift(C5, 23)))
		local S3 = bit32.bor(buffer.readu32(U, In + 12) + buffer.readu32(E1, In + 12), 0)
		local C6 = bit32.band(math.floor(bit32.band(S3, 0xffff) * SCALE_11 + OFF_11), 2047)
		local C7 = bit32.band(math.floor(bit32.rshift(S3, 16) * SCALE_11 + OFF_11), 2047)
		local S4 = bit32.bor(buffer.readu32(U, In + 16) + buffer.readu32(E1, In + 16), 0)
		local C8 = bit32.band(math.floor(bit32.band(S4, 0xffff) * SCALE_11 + OFF_11), 2047)
		buffer.writeu32(Output, Out + 8, bit32.bor(bit32.rshift(C5, 9), bit32.lshift(C6, 2), bit32.lshift(C7, 13), bit32.lshift(C8, 24)))
		local C9 = bit32.band(math.floor(bit32.rshift(S4, 16) * SCALE_11 + OFF_11), 2047)
		local S5 = bit32.bor(buffer.readu32(U, In + 20) + buffer.readu32(E1, In + 20), 0)
		local C10 = bit32.band(math.floor(bit32.band(S5, 0xffff) * SCALE_11 + OFF_11), 2047)
		local C11 = bit32.band(math.floor(bit32.rshift(S5, 16) * SCALE_11 + OFF_11), 2047)
		buffer.writeu32(Output, Out + 12, bit32.bor(bit32.rshift(C8, 8), bit32.lshift(C9, 3), bit32.lshift(C10, 14), bit32.lshift(C11, 25)))
		local S6 = bit32.bor(buffer.readu32(U, In + 24) + buffer.readu32(E1, In + 24), 0)
		local C12 = bit32.band(math.floor(bit32.band(S6, 0xffff) * SCALE_11 + OFF_11), 2047)
		local C13 = bit32.band(math.floor(bit32.rshift(S6, 16) * SCALE_11 + OFF_11), 2047)
		local S7 = bit32.bor(buffer.readu32(U, In + 28) + buffer.readu32(E1, In + 28), 0)
		local C14 = bit32.band(math.floor(bit32.band(S7, 0xffff) * SCALE_11 + OFF_11), 2047)
		buffer.writeu32(Output, Out + 16, bit32.bor(bit32.rshift(C11, 7), bit32.lshift(C12, 4), bit32.lshift(C13, 15), bit32.lshift(C14, 26)))
		local C15 = bit32.band(math.floor(bit32.rshift(S7, 16) * SCALE_11 + OFF_11), 2047)
		local S8 = bit32.bor(buffer.readu32(U, In + 32) + buffer.readu32(E1, In + 32), 0)
		local C16 = bit32.band(math.floor(bit32.band(S8, 0xffff) * SCALE_11 + OFF_11), 2047)
		local C17 = bit32.band(math.floor(bit32.rshift(S8, 16) * SCALE_11 + OFF_11), 2047)
		buffer.writeu32(Output, Out + 20, bit32.bor(bit32.rshift(C14, 6), bit32.lshift(C15, 5), bit32.lshift(C16, 16), bit32.lshift(C17, 27)))
		local S9 = bit32.bor(buffer.readu32(U, In + 36) + buffer.readu32(E1, In + 36), 0)
		local C18 = bit32.band(math.floor(bit32.band(S9, 0xffff) * SCALE_11 + OFF_11), 2047)
		local C19 = bit32.band(math.floor(bit32.rshift(S9, 16) * SCALE_11 + OFF_11), 2047)
		local S10 = bit32.bor(buffer.readu32(U, In + 40) + buffer.readu32(E1, In + 40), 0)
		local C20 = bit32.band(math.floor(bit32.band(S10, 0xffff) * SCALE_11 + OFF_11), 2047)
		buffer.writeu32(Output, Out + 24, bit32.bor(bit32.rshift(C17, 5), bit32.lshift(C18, 6), bit32.lshift(C19, 17), bit32.lshift(C20, 28)))
		local C21 = bit32.band(math.floor(bit32.rshift(S10, 16) * SCALE_11 + OFF_11), 2047)
		local S11 = bit32.bor(buffer.readu32(U, In + 44) + buffer.readu32(E1, In + 44), 0)
		local C22 = bit32.band(math.floor(bit32.band(S11, 0xffff) * SCALE_11 + OFF_11), 2047)
		local C23 = bit32.band(math.floor(bit32.rshift(S11, 16) * SCALE_11 + OFF_11), 2047)
		buffer.writeu32(Output, Out + 28, bit32.bor(bit32.rshift(C20, 4), bit32.lshift(C21, 7), bit32.lshift(C22, 18), bit32.lshift(C23, 29)))
		local S12 = bit32.bor(buffer.readu32(U, In + 48) + buffer.readu32(E1, In + 48), 0)
		local C24 = bit32.band(math.floor(bit32.band(S12, 0xffff) * SCALE_11 + OFF_11), 2047)
		local C25 = bit32.band(math.floor(bit32.rshift(S12, 16) * SCALE_11 + OFF_11), 2047)
		local S13 = bit32.bor(buffer.readu32(U, In + 52) + buffer.readu32(E1, In + 52), 0)
		local C26 = bit32.band(math.floor(bit32.band(S13, 0xffff) * SCALE_11 + OFF_11), 2047)
		buffer.writeu32(Output, Out + 32, bit32.bor(bit32.rshift(C23, 3), bit32.lshift(C24, 8), bit32.lshift(C25, 19), bit32.lshift(C26, 30)))
		local C27 = bit32.band(math.floor(bit32.rshift(S13, 16) * SCALE_11 + OFF_11), 2047)
		local S14 = bit32.bor(buffer.readu32(U, In + 56) + buffer.readu32(E1, In + 56), 0)
		local C28 = bit32.band(math.floor(bit32.band(S14, 0xffff) * SCALE_11 + OFF_11), 2047)
		local C29 = bit32.band(math.floor(bit32.rshift(S14, 16) * SCALE_11 + OFF_11), 2047)
		buffer.writeu32(Output, Out + 36, bit32.bor(bit32.rshift(C26, 2), bit32.lshift(C27, 9), bit32.lshift(C28, 20), bit32.lshift(C29, 31)))
		local S15 = bit32.bor(buffer.readu32(U, In + 60) + buffer.readu32(E1, In + 60), 0)
		local C30 = bit32.band(math.floor(bit32.band(S15, 0xffff) * SCALE_11 + OFF_11), 2047)
		local C31 = bit32.band(math.floor(bit32.rshift(S15, 16) * SCALE_11 + OFF_11), 2047)
		buffer.writeu32(Output, Out + 40, bit32.bor(bit32.rshift(C29, 1), bit32.lshift(C30, 10), bit32.lshift(C31, 21)))
	end
end

local function DecodeU10(Data: buffer, Coefficients: number, U: buffer)
	local Decompress: buffer
	if DECOMPRESS_10 then
		Decompress = DECOMPRESS_10
	else
		Decompress = DecompressTable(10)
		DECOMPRESS_10 = Decompress
	end
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
	local Decompress: buffer
	if DECOMPRESS_11 then
		Decompress = DECOMPRESS_11
	else
		Decompress = DecompressTable(11)
		DECOMPRESS_11 = Decompress
	end
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
	for In = 0, 480, 32 do
		local Out = OutputOffset + In * 0.25
		local Bits = buffer.readu16(Message, In / 16)
		local S0 = bit32.bor(bit32.bor(buffer.readu32(V, In) + buffer.readu32(E2, In), 0) + bit32.bor(bit32.band(0 - bit32.band(Bits, 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(Bits, 1), 1), 1665), 16)), 0)
		local C0 = bit32.band(math.floor(bit32.band(S0, 0xffff) * SCALE_4 + OFF_4), 15)
		local C1 = bit32.band(math.floor(bit32.rshift(S0, 16) * SCALE_4 + OFF_4), 15)
		local S1 = bit32.bor(bit32.bor(buffer.readu32(V, In + 4) + buffer.readu32(E2, In + 4), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(Bits, 2), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(Bits, 3), 1), 1665), 16)), 0)
		local C2 = bit32.band(math.floor(bit32.band(S1, 0xffff) * SCALE_4 + OFF_4), 15)
		local C3 = bit32.band(math.floor(bit32.rshift(S1, 16) * SCALE_4 + OFF_4), 15)
		local S2 = bit32.bor(bit32.bor(buffer.readu32(V, In + 8) + buffer.readu32(E2, In + 8), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(Bits, 4), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(Bits, 5), 1), 1665), 16)), 0)
		local C4 = bit32.band(math.floor(bit32.band(S2, 0xffff) * SCALE_4 + OFF_4), 15)
		local C5 = bit32.band(math.floor(bit32.rshift(S2, 16) * SCALE_4 + OFF_4), 15)
		local S3 = bit32.bor(bit32.bor(buffer.readu32(V, In + 12) + buffer.readu32(E2, In + 12), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(Bits, 6), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(Bits, 7), 1), 1665), 16)), 0)
		local C6 = bit32.band(math.floor(bit32.band(S3, 0xffff) * SCALE_4 + OFF_4), 15)
		local C7 = bit32.band(math.floor(bit32.rshift(S3, 16) * SCALE_4 + OFF_4), 15)
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 4), bit32.lshift(C2, 8), bit32.lshift(C3, 12), bit32.bor(bit32.lshift(C4, 16), bit32.lshift(C5, 20), bit32.lshift(C6, 24), bit32.lshift(C7, 28))))
		local S4 = bit32.bor(bit32.bor(buffer.readu32(V, In + 16) + buffer.readu32(E2, In + 16), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(Bits, 8), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(Bits, 9), 1), 1665), 16)), 0)
		local C8 = bit32.band(math.floor(bit32.band(S4, 0xffff) * SCALE_4 + OFF_4), 15)
		local C9 = bit32.band(math.floor(bit32.rshift(S4, 16) * SCALE_4 + OFF_4), 15)
		local S5 = bit32.bor(bit32.bor(buffer.readu32(V, In + 20) + buffer.readu32(E2, In + 20), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(Bits, 10), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(Bits, 11), 1), 1665), 16)), 0)
		local C10 = bit32.band(math.floor(bit32.band(S5, 0xffff) * SCALE_4 + OFF_4), 15)
		local C11 = bit32.band(math.floor(bit32.rshift(S5, 16) * SCALE_4 + OFF_4), 15)
		local S6 = bit32.bor(bit32.bor(buffer.readu32(V, In + 24) + buffer.readu32(E2, In + 24), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(Bits, 12), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(Bits, 13), 1), 1665), 16)), 0)
		local C12 = bit32.band(math.floor(bit32.band(S6, 0xffff) * SCALE_4 + OFF_4), 15)
		local C13 = bit32.band(math.floor(bit32.rshift(S6, 16) * SCALE_4 + OFF_4), 15)
		local S7 = bit32.bor(bit32.bor(buffer.readu32(V, In + 28) + buffer.readu32(E2, In + 28), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(Bits, 14), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(Bits, 15), 1), 1665), 16)), 0)
		local C14 = bit32.band(math.floor(bit32.band(S7, 0xffff) * SCALE_4 + OFF_4), 15)
		local C15 = bit32.band(math.floor(bit32.rshift(S7, 16) * SCALE_4 + OFF_4), 15)
		buffer.writeu32(Output, Out + 4, bit32.bor(C8, bit32.lshift(C9, 4), bit32.lshift(C10, 8), bit32.lshift(C11, 12), bit32.bor(bit32.lshift(C12, 16), bit32.lshift(C13, 20), bit32.lshift(C14, 24), bit32.lshift(C15, 28))))
	end
end

local function EncodeV5(V: buffer, E2: buffer, Message: buffer, Output: buffer, OutputOffset: number)
	for In = 0, 448, 64 do
		local Out = OutputOffset + In * 0.3125
		local MessageBits = buffer.readu32(Message, In / 16)
		local S0 = bit32.bor(bit32.bor(buffer.readu32(V, In) + buffer.readu32(E2, In), 0) + bit32.bor(bit32.band(0 - bit32.band(MessageBits, 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 1), 1), 1665), 16)), 0)
		local C0 = bit32.band(math.floor(bit32.band(S0, 0xffff) * SCALE_5 + OFF_5), 31)
		local C1 = bit32.band(math.floor(bit32.rshift(S0, 16) * SCALE_5 + OFF_5), 31)
		local S1 = bit32.bor(bit32.bor(buffer.readu32(V, In + 4) + buffer.readu32(E2, In + 4), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 2), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 3), 1), 1665), 16)), 0)
		local C2 = bit32.band(math.floor(bit32.band(S1, 0xffff) * SCALE_5 + OFF_5), 31)
		local C3 = bit32.band(math.floor(bit32.rshift(S1, 16) * SCALE_5 + OFF_5), 31)
		local S2 = bit32.bor(bit32.bor(buffer.readu32(V, In + 8) + buffer.readu32(E2, In + 8), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 4), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 5), 1), 1665), 16)), 0)
		local C4 = bit32.band(math.floor(bit32.band(S2, 0xffff) * SCALE_5 + OFF_5), 31)
		local C5 = bit32.band(math.floor(bit32.rshift(S2, 16) * SCALE_5 + OFF_5), 31)
		local S3 = bit32.bor(bit32.bor(buffer.readu32(V, In + 12) + buffer.readu32(E2, In + 12), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 6), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 7), 1), 1665), 16)), 0)
		local C6 = bit32.band(math.floor(bit32.band(S3, 0xffff) * SCALE_5 + OFF_5), 31)
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 5), bit32.lshift(C2, 10), bit32.lshift(C3, 15), bit32.bor(bit32.lshift(C4, 20), bit32.lshift(C5, 25), bit32.lshift(C6, 30))))
		local C7 = bit32.band(math.floor(bit32.rshift(S3, 16) * SCALE_5 + OFF_5), 31)
		local S4 = bit32.bor(bit32.bor(buffer.readu32(V, In + 16) + buffer.readu32(E2, In + 16), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 8), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 9), 1), 1665), 16)), 0)
		local C8 = bit32.band(math.floor(bit32.band(S4, 0xffff) * SCALE_5 + OFF_5), 31)
		local C9 = bit32.band(math.floor(bit32.rshift(S4, 16) * SCALE_5 + OFF_5), 31)
		local S5 = bit32.bor(bit32.bor(buffer.readu32(V, In + 20) + buffer.readu32(E2, In + 20), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 10), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 11), 1), 1665), 16)), 0)
		local C10 = bit32.band(math.floor(bit32.band(S5, 0xffff) * SCALE_5 + OFF_5), 31)
		local C11 = bit32.band(math.floor(bit32.rshift(S5, 16) * SCALE_5 + OFF_5), 31)
		local S6 = bit32.bor(bit32.bor(buffer.readu32(V, In + 24) + buffer.readu32(E2, In + 24), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 12), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 13), 1), 1665), 16)), 0)
		local C12 = bit32.band(math.floor(bit32.band(S6, 0xffff) * SCALE_5 + OFF_5), 31)
		buffer.writeu32(Output, Out + 4, bit32.bor(bit32.rshift(C6, 2), bit32.lshift(C7, 3), bit32.lshift(C8, 8), bit32.lshift(C9, 13), bit32.bor(bit32.lshift(C10, 18), bit32.lshift(C11, 23), bit32.lshift(C12, 28))))
		local C13 = bit32.band(math.floor(bit32.rshift(S6, 16) * SCALE_5 + OFF_5), 31)
		local S7 = bit32.bor(bit32.bor(buffer.readu32(V, In + 28) + buffer.readu32(E2, In + 28), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 14), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 15), 1), 1665), 16)), 0)
		local C14 = bit32.band(math.floor(bit32.band(S7, 0xffff) * SCALE_5 + OFF_5), 31)
		local C15 = bit32.band(math.floor(bit32.rshift(S7, 16) * SCALE_5 + OFF_5), 31)
		local S8 = bit32.bor(bit32.bor(buffer.readu32(V, In + 32) + buffer.readu32(E2, In + 32), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 16), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 17), 1), 1665), 16)), 0)
		local C16 = bit32.band(math.floor(bit32.band(S8, 0xffff) * SCALE_5 + OFF_5), 31)
		local C17 = bit32.band(math.floor(bit32.rshift(S8, 16) * SCALE_5 + OFF_5), 31)
		local S9 = bit32.bor(bit32.bor(buffer.readu32(V, In + 36) + buffer.readu32(E2, In + 36), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 18), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 19), 1), 1665), 16)), 0)
		local C18 = bit32.band(math.floor(bit32.band(S9, 0xffff) * SCALE_5 + OFF_5), 31)
		local C19 = bit32.band(math.floor(bit32.rshift(S9, 16) * SCALE_5 + OFF_5), 31)
		buffer.writeu32(Output, Out + 8, bit32.bor(bit32.rshift(C12, 4), bit32.lshift(C13, 1), bit32.lshift(C14, 6), bit32.lshift(C15, 11), bit32.bor(bit32.lshift(C16, 16), bit32.lshift(C17, 21), bit32.lshift(C18, 26), bit32.lshift(C19, 31))))
		local S10 = bit32.bor(bit32.bor(buffer.readu32(V, In + 40) + buffer.readu32(E2, In + 40), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 20), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 21), 1), 1665), 16)), 0)
		local C20 = bit32.band(math.floor(bit32.band(S10, 0xffff) * SCALE_5 + OFF_5), 31)
		local C21 = bit32.band(math.floor(bit32.rshift(S10, 16) * SCALE_5 + OFF_5), 31)
		local S11 = bit32.bor(bit32.bor(buffer.readu32(V, In + 44) + buffer.readu32(E2, In + 44), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 22), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 23), 1), 1665), 16)), 0)
		local C22 = bit32.band(math.floor(bit32.band(S11, 0xffff) * SCALE_5 + OFF_5), 31)
		local C23 = bit32.band(math.floor(bit32.rshift(S11, 16) * SCALE_5 + OFF_5), 31)
		local S12 = bit32.bor(bit32.bor(buffer.readu32(V, In + 48) + buffer.readu32(E2, In + 48), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 24), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 25), 1), 1665), 16)), 0)
		local C24 = bit32.band(math.floor(bit32.band(S12, 0xffff) * SCALE_5 + OFF_5), 31)
		local C25 = bit32.band(math.floor(bit32.rshift(S12, 16) * SCALE_5 + OFF_5), 31)
		buffer.writeu32(Output, Out + 12, bit32.bor(bit32.rshift(C19, 1), bit32.lshift(C20, 4), bit32.lshift(C21, 9), bit32.lshift(C22, 14), bit32.bor(bit32.lshift(C23, 19), bit32.lshift(C24, 24), bit32.lshift(C25, 29))))
		local S13 = bit32.bor(bit32.bor(buffer.readu32(V, In + 52) + buffer.readu32(E2, In + 52), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 26), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 27), 1), 1665), 16)), 0)
		local C26 = bit32.band(math.floor(bit32.band(S13, 0xffff) * SCALE_5 + OFF_5), 31)
		local C27 = bit32.band(math.floor(bit32.rshift(S13, 16) * SCALE_5 + OFF_5), 31)
		local S14 = bit32.bor(bit32.bor(buffer.readu32(V, In + 56) + buffer.readu32(E2, In + 56), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 28), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 29), 1), 1665), 16)), 0)
		local C28 = bit32.band(math.floor(bit32.band(S14, 0xffff) * SCALE_5 + OFF_5), 31)
		local C29 = bit32.band(math.floor(bit32.rshift(S14, 16) * SCALE_5 + OFF_5), 31)
		local S15 = bit32.bor(bit32.bor(buffer.readu32(V, In + 60) + buffer.readu32(E2, In + 60), 0) + bit32.bor(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 30), 1), 1665), bit32.lshift(bit32.band(0 - bit32.band(bit32.rshift(MessageBits, 31), 1), 1665), 16)), 0)
		local C30 = bit32.band(math.floor(bit32.band(S15, 0xffff) * SCALE_5 + OFF_5), 31)
		local C31 = bit32.band(math.floor(bit32.rshift(S15, 16) * SCALE_5 + OFF_5), 31)
		buffer.writeu32(Output, Out + 16, bit32.bor(bit32.rshift(C25, 3), bit32.lshift(C26, 2), bit32.lshift(C27, 7), bit32.lshift(C28, 12), bit32.bor(bit32.lshift(C29, 17), bit32.lshift(C30, 22), bit32.lshift(C31, 27))))
	end
end

local function MsgBit(X: number): number
	local M = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(X - 3329, 31) - 1, 0), 3329), 0)
	return bit32.rshift(bit32.bxor(M - 833, M - 2497), 31)
end

local function DecodeMessage4(Data: buffer, DataOffset: number, Product: buffer, Message: buffer)
	local Decompress: buffer
	if DECOMPRESS_4 then
		Decompress = DECOMPRESS_4
	else
		Decompress = DecompressTable(4)
		DECOMPRESS_4 = Decompress
	end
	for ByteIdx = 0, 31 do
		local Out = ByteIdx * 16
		local W = buffer.readu32(Data, DataOffset + ByteIdx * 4)
		local P0 = buffer.readu32(Product, Out)
		local B0 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(W, 15), 1)) + 3329, 0) - bit32.band(P0, 0xffff), 0))
		local B1 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W, 4), 15), 1)) + 3329, 0) - bit32.rshift(P0, 16), 0))
		local P1 = buffer.readu32(Product, Out + 4)
		local B2 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W, 8), 15), 1)) + 3329, 0) - bit32.band(P1, 0xffff), 0))
		local B3 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W, 12), 15), 1)) + 3329, 0) - bit32.rshift(P1, 16), 0))
		local P2 = buffer.readu32(Product, Out + 8)
		local B4 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W, 16), 15), 1)) + 3329, 0) - bit32.band(P2, 0xffff), 0))
		local B5 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W, 20), 15), 1)) + 3329, 0) - bit32.rshift(P2, 16), 0))
		local P3 = buffer.readu32(Product, Out + 12)
		local B6 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W, 24), 15), 1)) + 3329, 0) - bit32.band(P3, 0xffff), 0))
		local B7 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.rshift(W, 28), 1)) + 3329, 0) - bit32.rshift(P3, 16), 0))
		buffer.writeu8(Message, ByteIdx, bit32.bor(B0, bit32.lshift(B1, 1), bit32.lshift(B2, 2), bit32.lshift(B3, 3), bit32.bor(bit32.lshift(B4, 4), bit32.lshift(B5, 5), bit32.lshift(B6, 6), bit32.lshift(B7, 7))))
	end
end

local function DecodeMessage5(Data: buffer, DataOffset: number, Product: buffer, Message: buffer)
	local Decompress: buffer
	if DECOMPRESS_5 then
		Decompress = DECOMPRESS_5
	else
		Decompress = DecompressTable(5)
		DECOMPRESS_5 = Decompress
	end
	for ByteIdx = 0, 31 do
		local Out = ByteIdx * 16
		local In = DataOffset + ByteIdx * 5
		local W = buffer.readu32(Data, In)
		local Top = buffer.readu8(Data, In + 4)
		local P0 = buffer.readu32(Product, Out)
		local B0 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(W, 31), 1)) + 3329, 0) - bit32.band(P0, 0xffff), 0))
		local B1 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W, 5), 31), 1)) + 3329, 0) - bit32.rshift(P0, 16), 0))
		local P1 = buffer.readu32(Product, Out + 4)
		local B2 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W, 10), 31), 1)) + 3329, 0) - bit32.band(P1, 0xffff), 0))
		local B3 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W, 15), 31), 1)) + 3329, 0) - bit32.rshift(P1, 16), 0))
		local P2 = buffer.readu32(Product, Out + 8)
		local B4 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W, 20), 31), 1)) + 3329, 0) - bit32.band(P2, 0xffff), 0))
		local B5 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.rshift(W, 25), 31), 1)) + 3329, 0) - bit32.rshift(P2, 16), 0))
		local P3 = buffer.readu32(Product, Out + 12)
		local B6 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W, 30), bit32.lshift(Top, 2)), 31), 1)) + 3329, 0) - bit32.band(P3, 0xffff), 0))
		local B7 = MsgBit(bit32.bor(bit32.bor(buffer.readu16(Decompress, bit32.lshift(bit32.rshift(Top, 3), 1)) + 3329, 0) - bit32.rshift(P3, 16), 0))
		buffer.writeu8(Message, ByteIdx, bit32.bor(B0, bit32.lshift(B1, 1), bit32.lshift(B2, 2), bit32.lshift(B3, 3), bit32.bor(bit32.lshift(B4, 4), bit32.lshift(B5, 5), bit32.lshift(B6, 6), bit32.lshift(B7, 7))))
	end
end

local Packing = {
	Encode12 = Encode12,
	Decode12 = Decode12,
}

function Packing.EncodeU(U: buffer, E1: buffer, Coefficients: number, Du: number, Output: buffer): ()
	if Du == 10 then
		EncodeU10(U, E1, Coefficients, Output)
	else
		EncodeU11(U, E1, Coefficients, Output)
	end
end

function Packing.DecodeU(Data: buffer, Coefficients: number, Du: number, U: buffer): ()
	if Du == 10 then
		DecodeU10(Data, Coefficients, U)
	else
		DecodeU11(Data, Coefficients, U)
	end
end

function Packing.EncodeV(V: buffer, E2: buffer, Message: buffer, Dv: number, Output: buffer, OutputOffset: number): ()
	if Dv == 4 then
		EncodeV4(V, E2, Message, Output, OutputOffset)
	else
		EncodeV5(V, E2, Message, Output, OutputOffset)
	end
end

function Packing.DecodeMessage(Data: buffer, DataOffset: number, Dv: number, Product: buffer, Message: buffer): ()
	if Dv == 4 then
		DecodeMessage4(Data, DataOffset, Product, Message)
	else
		DecodeMessage5(Data, DataOffset, Product, Message)
	end
end

return Packing
