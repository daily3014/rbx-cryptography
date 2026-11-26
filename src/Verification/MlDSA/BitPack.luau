--[=[
	BitPack: ML-DSA polynomial vectors packed at a fixed bit width (FIPS 204 SimpleBitPack and
	BitPack). Coefficients are u32 in [0, q). The centered forms store X - c, so a coefficient in
	[X - 2^Bits + 1, X] round trips; t1 decodes already multiplied by 2^13

	Example usage:
		BitPack.EncodeCentered(S1, 0, L * 256, Eta, 3, SecretKey, 128)
		BitPack.DecodeT1(PublicKey, 32, K * 256, T1, 0)
--]=]

--!strict
--!optimize 2
--!native

local Q = 8380417

local function EncodeT1(Vector: buffer, VectorOffset: number, Coefficients: number, Output: buffer, OutputOffset: number): ()
	for Group = 0, Coefficients / 16 - 1 do
		local In = VectorOffset + Group * 64
		local Out = OutputOffset + Group * 20
		local C0 = buffer.readu32(Vector, In)
		local C1 = buffer.readu32(Vector, In + 4)
		local C2 = buffer.readu32(Vector, In + 8)
		local C3 = buffer.readu32(Vector, In + 12)
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 10), bit32.lshift(C2, 20), bit32.lshift(C3, 30)))
		local C4 = buffer.readu32(Vector, In + 16)
		local C5 = buffer.readu32(Vector, In + 20)
		local C6 = buffer.readu32(Vector, In + 24)
		buffer.writeu32(Output, Out + 4, bit32.bor(bit32.rshift(C3, 2), bit32.lshift(C4, 8), bit32.lshift(C5, 18), bit32.lshift(C6, 28)))
		local C7 = buffer.readu32(Vector, In + 28)
		local C8 = buffer.readu32(Vector, In + 32)
		local C9 = buffer.readu32(Vector, In + 36)
		buffer.writeu32(Output, Out + 8, bit32.bor(bit32.rshift(C6, 4), bit32.lshift(C7, 6), bit32.lshift(C8, 16), bit32.lshift(C9, 26)))
		local C10 = buffer.readu32(Vector, In + 40)
		local C11 = buffer.readu32(Vector, In + 44)
		local C12 = buffer.readu32(Vector, In + 48)
		buffer.writeu32(Output, Out + 12, bit32.bor(bit32.rshift(C9, 6), bit32.lshift(C10, 4), bit32.lshift(C11, 14), bit32.lshift(C12, 24)))
		local C13 = buffer.readu32(Vector, In + 52)
		local C14 = buffer.readu32(Vector, In + 56)
		local C15 = buffer.readu32(Vector, In + 60)
		buffer.writeu32(Output, Out + 16, bit32.bor(bit32.rshift(C12, 8), bit32.lshift(C13, 2), bit32.lshift(C14, 12), bit32.lshift(C15, 22)))
	end
end

local function DecodeT1(Data: buffer, DataOffset: number, Coefficients: number, Vector: buffer, VectorOffset: number): ()
	for Group = 0, Coefficients / 16 - 1 do
		local In = DataOffset + Group * 20
		local Out = VectorOffset + Group * 64
		local W0 = buffer.readu32(Data, In)
		buffer.writeu32(Vector, Out, bit32.lshift(bit32.band(W0, 1023), 13))
		buffer.writeu32(Vector, Out + 4, bit32.lshift(bit32.band(bit32.rshift(W0, 10), 1023), 13))
		buffer.writeu32(Vector, Out + 8, bit32.lshift(bit32.band(bit32.rshift(W0, 20), 1023), 13))
		local W1 = buffer.readu32(Data, In + 4)
		buffer.writeu32(Vector, Out + 12, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W0, 30), bit32.lshift(W1, 2)), 1023), 13))
		buffer.writeu32(Vector, Out + 16, bit32.lshift(bit32.band(bit32.rshift(W1, 8), 1023), 13))
		buffer.writeu32(Vector, Out + 20, bit32.lshift(bit32.band(bit32.rshift(W1, 18), 1023), 13))
		local W2 = buffer.readu32(Data, In + 8)
		buffer.writeu32(Vector, Out + 24, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W1, 28), bit32.lshift(W2, 4)), 1023), 13))
		buffer.writeu32(Vector, Out + 28, bit32.lshift(bit32.band(bit32.rshift(W2, 6), 1023), 13))
		buffer.writeu32(Vector, Out + 32, bit32.lshift(bit32.band(bit32.rshift(W2, 16), 1023), 13))
		local W3 = buffer.readu32(Data, In + 12)
		buffer.writeu32(Vector, Out + 36, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W2, 26), bit32.lshift(W3, 6)), 1023), 13))
		buffer.writeu32(Vector, Out + 40, bit32.lshift(bit32.band(bit32.rshift(W3, 4), 1023), 13))
		buffer.writeu32(Vector, Out + 44, bit32.lshift(bit32.band(bit32.rshift(W3, 14), 1023), 13))
		local W4 = buffer.readu32(Data, In + 16)
		buffer.writeu32(Vector, Out + 48, bit32.lshift(bit32.band(bit32.bor(bit32.rshift(W3, 24), bit32.lshift(W4, 8)), 1023), 13))
		buffer.writeu32(Vector, Out + 52, bit32.lshift(bit32.band(bit32.rshift(W4, 2), 1023), 13))
		buffer.writeu32(Vector, Out + 56, bit32.lshift(bit32.band(bit32.rshift(W4, 12), 1023), 13))
		buffer.writeu32(Vector, Out + 60, bit32.lshift(bit32.rshift(W4, 22), 13))
	end
end

local function EncodeCentered3(Vector: buffer, VectorOffset: number, Coefficients: number, X: number, Output: buffer, OutputOffset: number)
	for Group = 0, Coefficients / 32 - 1 do
		local In = VectorOffset + Group * 128
		local Out = OutputOffset + Group * 12
		local D0 = bit32.bor(X - buffer.readu32(Vector, In), 0)
		local C0 = bit32.bor(D0 + bit32.band(Q, bit32.arshift(D0, 31)), 0)
		local D1 = bit32.bor(X - buffer.readu32(Vector, In + 4), 0)
		local C1 = bit32.bor(D1 + bit32.band(Q, bit32.arshift(D1, 31)), 0)
		local D2 = bit32.bor(X - buffer.readu32(Vector, In + 8), 0)
		local C2 = bit32.bor(D2 + bit32.band(Q, bit32.arshift(D2, 31)), 0)
		local D3 = bit32.bor(X - buffer.readu32(Vector, In + 12), 0)
		local C3 = bit32.bor(D3 + bit32.band(Q, bit32.arshift(D3, 31)), 0)
		local D4 = bit32.bor(X - buffer.readu32(Vector, In + 16), 0)
		local C4 = bit32.bor(D4 + bit32.band(Q, bit32.arshift(D4, 31)), 0)
		local D5 = bit32.bor(X - buffer.readu32(Vector, In + 20), 0)
		local C5 = bit32.bor(D5 + bit32.band(Q, bit32.arshift(D5, 31)), 0)
		local D6 = bit32.bor(X - buffer.readu32(Vector, In + 24), 0)
		local C6 = bit32.bor(D6 + bit32.band(Q, bit32.arshift(D6, 31)), 0)
		local D7 = bit32.bor(X - buffer.readu32(Vector, In + 28), 0)
		local C7 = bit32.bor(D7 + bit32.band(Q, bit32.arshift(D7, 31)), 0)
		local D8 = bit32.bor(X - buffer.readu32(Vector, In + 32), 0)
		local C8 = bit32.bor(D8 + bit32.band(Q, bit32.arshift(D8, 31)), 0)
		local D9 = bit32.bor(X - buffer.readu32(Vector, In + 36), 0)
		local C9 = bit32.bor(D9 + bit32.band(Q, bit32.arshift(D9, 31)), 0)
		local D10 = bit32.bor(X - buffer.readu32(Vector, In + 40), 0)
		local C10 = bit32.bor(D10 + bit32.band(Q, bit32.arshift(D10, 31)), 0)
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 3), bit32.lshift(C2, 6), bit32.lshift(C3, 9), bit32.bor(bit32.lshift(C4, 12), bit32.lshift(C5, 15), bit32.lshift(C6, 18), bit32.lshift(C7, 21), bit32.bor(bit32.lshift(C8, 24), bit32.lshift(C9, 27), bit32.lshift(C10, 30)))))
		local D11 = bit32.bor(X - buffer.readu32(Vector, In + 44), 0)
		local C11 = bit32.bor(D11 + bit32.band(Q, bit32.arshift(D11, 31)), 0)
		local D12 = bit32.bor(X - buffer.readu32(Vector, In + 48), 0)
		local C12 = bit32.bor(D12 + bit32.band(Q, bit32.arshift(D12, 31)), 0)
		local D13 = bit32.bor(X - buffer.readu32(Vector, In + 52), 0)
		local C13 = bit32.bor(D13 + bit32.band(Q, bit32.arshift(D13, 31)), 0)
		local D14 = bit32.bor(X - buffer.readu32(Vector, In + 56), 0)
		local C14 = bit32.bor(D14 + bit32.band(Q, bit32.arshift(D14, 31)), 0)
		local D15 = bit32.bor(X - buffer.readu32(Vector, In + 60), 0)
		local C15 = bit32.bor(D15 + bit32.band(Q, bit32.arshift(D15, 31)), 0)
		local D16 = bit32.bor(X - buffer.readu32(Vector, In + 64), 0)
		local C16 = bit32.bor(D16 + bit32.band(Q, bit32.arshift(D16, 31)), 0)
		local D17 = bit32.bor(X - buffer.readu32(Vector, In + 68), 0)
		local C17 = bit32.bor(D17 + bit32.band(Q, bit32.arshift(D17, 31)), 0)
		local D18 = bit32.bor(X - buffer.readu32(Vector, In + 72), 0)
		local C18 = bit32.bor(D18 + bit32.band(Q, bit32.arshift(D18, 31)), 0)
		local D19 = bit32.bor(X - buffer.readu32(Vector, In + 76), 0)
		local C19 = bit32.bor(D19 + bit32.band(Q, bit32.arshift(D19, 31)), 0)
		local D20 = bit32.bor(X - buffer.readu32(Vector, In + 80), 0)
		local C20 = bit32.bor(D20 + bit32.band(Q, bit32.arshift(D20, 31)), 0)
		local D21 = bit32.bor(X - buffer.readu32(Vector, In + 84), 0)
		local C21 = bit32.bor(D21 + bit32.band(Q, bit32.arshift(D21, 31)), 0)
		buffer.writeu32(Output, Out + 4, bit32.bor(bit32.rshift(C10, 2), bit32.lshift(C11, 1), bit32.lshift(C12, 4), bit32.lshift(C13, 7), bit32.bor(bit32.lshift(C14, 10), bit32.lshift(C15, 13), bit32.lshift(C16, 16), bit32.lshift(C17, 19), bit32.bor(bit32.lshift(C18, 22), bit32.lshift(C19, 25), bit32.lshift(C20, 28), bit32.lshift(C21, 31)))))
		local D22 = bit32.bor(X - buffer.readu32(Vector, In + 88), 0)
		local C22 = bit32.bor(D22 + bit32.band(Q, bit32.arshift(D22, 31)), 0)
		local D23 = bit32.bor(X - buffer.readu32(Vector, In + 92), 0)
		local C23 = bit32.bor(D23 + bit32.band(Q, bit32.arshift(D23, 31)), 0)
		local D24 = bit32.bor(X - buffer.readu32(Vector, In + 96), 0)
		local C24 = bit32.bor(D24 + bit32.band(Q, bit32.arshift(D24, 31)), 0)
		local D25 = bit32.bor(X - buffer.readu32(Vector, In + 100), 0)
		local C25 = bit32.bor(D25 + bit32.band(Q, bit32.arshift(D25, 31)), 0)
		local D26 = bit32.bor(X - buffer.readu32(Vector, In + 104), 0)
		local C26 = bit32.bor(D26 + bit32.band(Q, bit32.arshift(D26, 31)), 0)
		local D27 = bit32.bor(X - buffer.readu32(Vector, In + 108), 0)
		local C27 = bit32.bor(D27 + bit32.band(Q, bit32.arshift(D27, 31)), 0)
		local D28 = bit32.bor(X - buffer.readu32(Vector, In + 112), 0)
		local C28 = bit32.bor(D28 + bit32.band(Q, bit32.arshift(D28, 31)), 0)
		local D29 = bit32.bor(X - buffer.readu32(Vector, In + 116), 0)
		local C29 = bit32.bor(D29 + bit32.band(Q, bit32.arshift(D29, 31)), 0)
		local D30 = bit32.bor(X - buffer.readu32(Vector, In + 120), 0)
		local C30 = bit32.bor(D30 + bit32.band(Q, bit32.arshift(D30, 31)), 0)
		local D31 = bit32.bor(X - buffer.readu32(Vector, In + 124), 0)
		local C31 = bit32.bor(D31 + bit32.band(Q, bit32.arshift(D31, 31)), 0)
		buffer.writeu32(Output, Out + 8, bit32.bor(bit32.rshift(C21, 1), bit32.lshift(C22, 2), bit32.lshift(C23, 5), bit32.lshift(C24, 8), bit32.bor(bit32.lshift(C25, 11), bit32.lshift(C26, 14), bit32.lshift(C27, 17), bit32.lshift(C28, 20), bit32.bor(bit32.lshift(C29, 23), bit32.lshift(C30, 26), bit32.lshift(C31, 29)))))
	end
end

local function DecodeCentered3(Data: buffer, DataOffset: number, Coefficients: number, X: number, Vector: buffer, VectorOffset: number)
	for Group = 0, Coefficients / 32 - 1 do
		local In = DataOffset + Group * 12
		local Out = VectorOffset + Group * 128
		local W0 = buffer.readu32(Data, In)
		local D0 = bit32.bor(X - bit32.band(W0, 7), 0)
		buffer.writeu32(Vector, Out, bit32.bor(D0 + bit32.band(Q, bit32.arshift(D0, 31)), 0))
		local D1 = bit32.bor(X - bit32.band(bit32.rshift(W0, 3), 7), 0)
		buffer.writeu32(Vector, Out + 4, bit32.bor(D1 + bit32.band(Q, bit32.arshift(D1, 31)), 0))
		local D2 = bit32.bor(X - bit32.band(bit32.rshift(W0, 6), 7), 0)
		buffer.writeu32(Vector, Out + 8, bit32.bor(D2 + bit32.band(Q, bit32.arshift(D2, 31)), 0))
		local D3 = bit32.bor(X - bit32.band(bit32.rshift(W0, 9), 7), 0)
		buffer.writeu32(Vector, Out + 12, bit32.bor(D3 + bit32.band(Q, bit32.arshift(D3, 31)), 0))
		local D4 = bit32.bor(X - bit32.band(bit32.rshift(W0, 12), 7), 0)
		buffer.writeu32(Vector, Out + 16, bit32.bor(D4 + bit32.band(Q, bit32.arshift(D4, 31)), 0))
		local D5 = bit32.bor(X - bit32.band(bit32.rshift(W0, 15), 7), 0)
		buffer.writeu32(Vector, Out + 20, bit32.bor(D5 + bit32.band(Q, bit32.arshift(D5, 31)), 0))
		local D6 = bit32.bor(X - bit32.band(bit32.rshift(W0, 18), 7), 0)
		buffer.writeu32(Vector, Out + 24, bit32.bor(D6 + bit32.band(Q, bit32.arshift(D6, 31)), 0))
		local D7 = bit32.bor(X - bit32.band(bit32.rshift(W0, 21), 7), 0)
		buffer.writeu32(Vector, Out + 28, bit32.bor(D7 + bit32.band(Q, bit32.arshift(D7, 31)), 0))
		local D8 = bit32.bor(X - bit32.band(bit32.rshift(W0, 24), 7), 0)
		buffer.writeu32(Vector, Out + 32, bit32.bor(D8 + bit32.band(Q, bit32.arshift(D8, 31)), 0))
		local D9 = bit32.bor(X - bit32.band(bit32.rshift(W0, 27), 7), 0)
		buffer.writeu32(Vector, Out + 36, bit32.bor(D9 + bit32.band(Q, bit32.arshift(D9, 31)), 0))
		local W1 = buffer.readu32(Data, In + 4)
		local D10 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W0, 30), bit32.lshift(W1, 2)), 7), 0)
		buffer.writeu32(Vector, Out + 40, bit32.bor(D10 + bit32.band(Q, bit32.arshift(D10, 31)), 0))
		local D11 = bit32.bor(X - bit32.band(bit32.rshift(W1, 1), 7), 0)
		buffer.writeu32(Vector, Out + 44, bit32.bor(D11 + bit32.band(Q, bit32.arshift(D11, 31)), 0))
		local D12 = bit32.bor(X - bit32.band(bit32.rshift(W1, 4), 7), 0)
		buffer.writeu32(Vector, Out + 48, bit32.bor(D12 + bit32.band(Q, bit32.arshift(D12, 31)), 0))
		local D13 = bit32.bor(X - bit32.band(bit32.rshift(W1, 7), 7), 0)
		buffer.writeu32(Vector, Out + 52, bit32.bor(D13 + bit32.band(Q, bit32.arshift(D13, 31)), 0))
		local D14 = bit32.bor(X - bit32.band(bit32.rshift(W1, 10), 7), 0)
		buffer.writeu32(Vector, Out + 56, bit32.bor(D14 + bit32.band(Q, bit32.arshift(D14, 31)), 0))
		local D15 = bit32.bor(X - bit32.band(bit32.rshift(W1, 13), 7), 0)
		buffer.writeu32(Vector, Out + 60, bit32.bor(D15 + bit32.band(Q, bit32.arshift(D15, 31)), 0))
		local D16 = bit32.bor(X - bit32.band(bit32.rshift(W1, 16), 7), 0)
		buffer.writeu32(Vector, Out + 64, bit32.bor(D16 + bit32.band(Q, bit32.arshift(D16, 31)), 0))
		local D17 = bit32.bor(X - bit32.band(bit32.rshift(W1, 19), 7), 0)
		buffer.writeu32(Vector, Out + 68, bit32.bor(D17 + bit32.band(Q, bit32.arshift(D17, 31)), 0))
		local D18 = bit32.bor(X - bit32.band(bit32.rshift(W1, 22), 7), 0)
		buffer.writeu32(Vector, Out + 72, bit32.bor(D18 + bit32.band(Q, bit32.arshift(D18, 31)), 0))
		local D19 = bit32.bor(X - bit32.band(bit32.rshift(W1, 25), 7), 0)
		buffer.writeu32(Vector, Out + 76, bit32.bor(D19 + bit32.band(Q, bit32.arshift(D19, 31)), 0))
		local D20 = bit32.bor(X - bit32.band(bit32.rshift(W1, 28), 7), 0)
		buffer.writeu32(Vector, Out + 80, bit32.bor(D20 + bit32.band(Q, bit32.arshift(D20, 31)), 0))
		local W2 = buffer.readu32(Data, In + 8)
		local D21 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W1, 31), bit32.lshift(W2, 1)), 7), 0)
		buffer.writeu32(Vector, Out + 84, bit32.bor(D21 + bit32.band(Q, bit32.arshift(D21, 31)), 0))
		local D22 = bit32.bor(X - bit32.band(bit32.rshift(W2, 2), 7), 0)
		buffer.writeu32(Vector, Out + 88, bit32.bor(D22 + bit32.band(Q, bit32.arshift(D22, 31)), 0))
		local D23 = bit32.bor(X - bit32.band(bit32.rshift(W2, 5), 7), 0)
		buffer.writeu32(Vector, Out + 92, bit32.bor(D23 + bit32.band(Q, bit32.arshift(D23, 31)), 0))
		local D24 = bit32.bor(X - bit32.band(bit32.rshift(W2, 8), 7), 0)
		buffer.writeu32(Vector, Out + 96, bit32.bor(D24 + bit32.band(Q, bit32.arshift(D24, 31)), 0))
		local D25 = bit32.bor(X - bit32.band(bit32.rshift(W2, 11), 7), 0)
		buffer.writeu32(Vector, Out + 100, bit32.bor(D25 + bit32.band(Q, bit32.arshift(D25, 31)), 0))
		local D26 = bit32.bor(X - bit32.band(bit32.rshift(W2, 14), 7), 0)
		buffer.writeu32(Vector, Out + 104, bit32.bor(D26 + bit32.band(Q, bit32.arshift(D26, 31)), 0))
		local D27 = bit32.bor(X - bit32.band(bit32.rshift(W2, 17), 7), 0)
		buffer.writeu32(Vector, Out + 108, bit32.bor(D27 + bit32.band(Q, bit32.arshift(D27, 31)), 0))
		local D28 = bit32.bor(X - bit32.band(bit32.rshift(W2, 20), 7), 0)
		buffer.writeu32(Vector, Out + 112, bit32.bor(D28 + bit32.band(Q, bit32.arshift(D28, 31)), 0))
		local D29 = bit32.bor(X - bit32.band(bit32.rshift(W2, 23), 7), 0)
		buffer.writeu32(Vector, Out + 116, bit32.bor(D29 + bit32.band(Q, bit32.arshift(D29, 31)), 0))
		local D30 = bit32.bor(X - bit32.band(bit32.rshift(W2, 26), 7), 0)
		buffer.writeu32(Vector, Out + 120, bit32.bor(D30 + bit32.band(Q, bit32.arshift(D30, 31)), 0))
		local D31 = bit32.bor(X - bit32.rshift(W2, 29), 0)
		buffer.writeu32(Vector, Out + 124, bit32.bor(D31 + bit32.band(Q, bit32.arshift(D31, 31)), 0))
	end
end

local function EncodeCentered4(Vector: buffer, VectorOffset: number, Coefficients: number, X: number, Output: buffer, OutputOffset: number)
	for Group = 0, Coefficients / 8 - 1 do
		local In = VectorOffset + Group * 32
		local Out = OutputOffset + Group * 4
		local D0 = bit32.bor(X - buffer.readu32(Vector, In), 0)
		local C0 = bit32.bor(D0 + bit32.band(Q, bit32.arshift(D0, 31)), 0)
		local D1 = bit32.bor(X - buffer.readu32(Vector, In + 4), 0)
		local C1 = bit32.bor(D1 + bit32.band(Q, bit32.arshift(D1, 31)), 0)
		local D2 = bit32.bor(X - buffer.readu32(Vector, In + 8), 0)
		local C2 = bit32.bor(D2 + bit32.band(Q, bit32.arshift(D2, 31)), 0)
		local D3 = bit32.bor(X - buffer.readu32(Vector, In + 12), 0)
		local C3 = bit32.bor(D3 + bit32.band(Q, bit32.arshift(D3, 31)), 0)
		local D4 = bit32.bor(X - buffer.readu32(Vector, In + 16), 0)
		local C4 = bit32.bor(D4 + bit32.band(Q, bit32.arshift(D4, 31)), 0)
		local D5 = bit32.bor(X - buffer.readu32(Vector, In + 20), 0)
		local C5 = bit32.bor(D5 + bit32.band(Q, bit32.arshift(D5, 31)), 0)
		local D6 = bit32.bor(X - buffer.readu32(Vector, In + 24), 0)
		local C6 = bit32.bor(D6 + bit32.band(Q, bit32.arshift(D6, 31)), 0)
		local D7 = bit32.bor(X - buffer.readu32(Vector, In + 28), 0)
		local C7 = bit32.bor(D7 + bit32.band(Q, bit32.arshift(D7, 31)), 0)
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 4), bit32.lshift(C2, 8), bit32.lshift(C3, 12), bit32.bor(bit32.lshift(C4, 16), bit32.lshift(C5, 20), bit32.lshift(C6, 24), bit32.lshift(C7, 28))))
	end
end

local function DecodeCentered4(Data: buffer, DataOffset: number, Coefficients: number, X: number, Vector: buffer, VectorOffset: number)
	for Group = 0, Coefficients / 8 - 1 do
		local In = DataOffset + Group * 4
		local Out = VectorOffset + Group * 32
		local W0 = buffer.readu32(Data, In)
		local D0 = bit32.bor(X - bit32.band(W0, 15), 0)
		buffer.writeu32(Vector, Out, bit32.bor(D0 + bit32.band(Q, bit32.arshift(D0, 31)), 0))
		local D1 = bit32.bor(X - bit32.band(bit32.rshift(W0, 4), 15), 0)
		buffer.writeu32(Vector, Out + 4, bit32.bor(D1 + bit32.band(Q, bit32.arshift(D1, 31)), 0))
		local D2 = bit32.bor(X - bit32.band(bit32.rshift(W0, 8), 15), 0)
		buffer.writeu32(Vector, Out + 8, bit32.bor(D2 + bit32.band(Q, bit32.arshift(D2, 31)), 0))
		local D3 = bit32.bor(X - bit32.band(bit32.rshift(W0, 12), 15), 0)
		buffer.writeu32(Vector, Out + 12, bit32.bor(D3 + bit32.band(Q, bit32.arshift(D3, 31)), 0))
		local D4 = bit32.bor(X - bit32.band(bit32.rshift(W0, 16), 15), 0)
		buffer.writeu32(Vector, Out + 16, bit32.bor(D4 + bit32.band(Q, bit32.arshift(D4, 31)), 0))
		local D5 = bit32.bor(X - bit32.band(bit32.rshift(W0, 20), 15), 0)
		buffer.writeu32(Vector, Out + 20, bit32.bor(D5 + bit32.band(Q, bit32.arshift(D5, 31)), 0))
		local D6 = bit32.bor(X - bit32.band(bit32.rshift(W0, 24), 15), 0)
		buffer.writeu32(Vector, Out + 24, bit32.bor(D6 + bit32.band(Q, bit32.arshift(D6, 31)), 0))
		local D7 = bit32.bor(X - bit32.rshift(W0, 28), 0)
		buffer.writeu32(Vector, Out + 28, bit32.bor(D7 + bit32.band(Q, bit32.arshift(D7, 31)), 0))
	end
end

local function EncodeCentered13(Vector: buffer, VectorOffset: number, Coefficients: number, X: number, Output: buffer, OutputOffset: number)
	for Group = 0, Coefficients / 32 - 1 do
		local In = VectorOffset + Group * 128
		local Out = OutputOffset + Group * 52
		local D0 = bit32.bor(X - buffer.readu32(Vector, In), 0)
		local C0 = bit32.bor(D0 + bit32.band(Q, bit32.arshift(D0, 31)), 0)
		local D1 = bit32.bor(X - buffer.readu32(Vector, In + 4), 0)
		local C1 = bit32.bor(D1 + bit32.band(Q, bit32.arshift(D1, 31)), 0)
		local D2 = bit32.bor(X - buffer.readu32(Vector, In + 8), 0)
		local C2 = bit32.bor(D2 + bit32.band(Q, bit32.arshift(D2, 31)), 0)
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 13), bit32.lshift(C2, 26)))
		local D3 = bit32.bor(X - buffer.readu32(Vector, In + 12), 0)
		local C3 = bit32.bor(D3 + bit32.band(Q, bit32.arshift(D3, 31)), 0)
		local D4 = bit32.bor(X - buffer.readu32(Vector, In + 16), 0)
		local C4 = bit32.bor(D4 + bit32.band(Q, bit32.arshift(D4, 31)), 0)
		buffer.writeu32(Output, Out + 4, bit32.bor(bit32.rshift(C2, 6), bit32.lshift(C3, 7), bit32.lshift(C4, 20)))
		local D5 = bit32.bor(X - buffer.readu32(Vector, In + 20), 0)
		local C5 = bit32.bor(D5 + bit32.band(Q, bit32.arshift(D5, 31)), 0)
		local D6 = bit32.bor(X - buffer.readu32(Vector, In + 24), 0)
		local C6 = bit32.bor(D6 + bit32.band(Q, bit32.arshift(D6, 31)), 0)
		local D7 = bit32.bor(X - buffer.readu32(Vector, In + 28), 0)
		local C7 = bit32.bor(D7 + bit32.band(Q, bit32.arshift(D7, 31)), 0)
		buffer.writeu32(Output, Out + 8, bit32.bor(bit32.rshift(C4, 12), bit32.lshift(C5, 1), bit32.lshift(C6, 14), bit32.lshift(C7, 27)))
		local D8 = bit32.bor(X - buffer.readu32(Vector, In + 32), 0)
		local C8 = bit32.bor(D8 + bit32.band(Q, bit32.arshift(D8, 31)), 0)
		local D9 = bit32.bor(X - buffer.readu32(Vector, In + 36), 0)
		local C9 = bit32.bor(D9 + bit32.band(Q, bit32.arshift(D9, 31)), 0)
		buffer.writeu32(Output, Out + 12, bit32.bor(bit32.rshift(C7, 5), bit32.lshift(C8, 8), bit32.lshift(C9, 21)))
		local D10 = bit32.bor(X - buffer.readu32(Vector, In + 40), 0)
		local C10 = bit32.bor(D10 + bit32.band(Q, bit32.arshift(D10, 31)), 0)
		local D11 = bit32.bor(X - buffer.readu32(Vector, In + 44), 0)
		local C11 = bit32.bor(D11 + bit32.band(Q, bit32.arshift(D11, 31)), 0)
		local D12 = bit32.bor(X - buffer.readu32(Vector, In + 48), 0)
		local C12 = bit32.bor(D12 + bit32.band(Q, bit32.arshift(D12, 31)), 0)
		buffer.writeu32(Output, Out + 16, bit32.bor(bit32.rshift(C9, 11), bit32.lshift(C10, 2), bit32.lshift(C11, 15), bit32.lshift(C12, 28)))
		local D13 = bit32.bor(X - buffer.readu32(Vector, In + 52), 0)
		local C13 = bit32.bor(D13 + bit32.band(Q, bit32.arshift(D13, 31)), 0)
		local D14 = bit32.bor(X - buffer.readu32(Vector, In + 56), 0)
		local C14 = bit32.bor(D14 + bit32.band(Q, bit32.arshift(D14, 31)), 0)
		buffer.writeu32(Output, Out + 20, bit32.bor(bit32.rshift(C12, 4), bit32.lshift(C13, 9), bit32.lshift(C14, 22)))
		local D15 = bit32.bor(X - buffer.readu32(Vector, In + 60), 0)
		local C15 = bit32.bor(D15 + bit32.band(Q, bit32.arshift(D15, 31)), 0)
		local D16 = bit32.bor(X - buffer.readu32(Vector, In + 64), 0)
		local C16 = bit32.bor(D16 + bit32.band(Q, bit32.arshift(D16, 31)), 0)
		local D17 = bit32.bor(X - buffer.readu32(Vector, In + 68), 0)
		local C17 = bit32.bor(D17 + bit32.band(Q, bit32.arshift(D17, 31)), 0)
		buffer.writeu32(Output, Out + 24, bit32.bor(bit32.rshift(C14, 10), bit32.lshift(C15, 3), bit32.lshift(C16, 16), bit32.lshift(C17, 29)))
		local D18 = bit32.bor(X - buffer.readu32(Vector, In + 72), 0)
		local C18 = bit32.bor(D18 + bit32.band(Q, bit32.arshift(D18, 31)), 0)
		local D19 = bit32.bor(X - buffer.readu32(Vector, In + 76), 0)
		local C19 = bit32.bor(D19 + bit32.band(Q, bit32.arshift(D19, 31)), 0)
		buffer.writeu32(Output, Out + 28, bit32.bor(bit32.rshift(C17, 3), bit32.lshift(C18, 10), bit32.lshift(C19, 23)))
		local D20 = bit32.bor(X - buffer.readu32(Vector, In + 80), 0)
		local C20 = bit32.bor(D20 + bit32.band(Q, bit32.arshift(D20, 31)), 0)
		local D21 = bit32.bor(X - buffer.readu32(Vector, In + 84), 0)
		local C21 = bit32.bor(D21 + bit32.band(Q, bit32.arshift(D21, 31)), 0)
		local D22 = bit32.bor(X - buffer.readu32(Vector, In + 88), 0)
		local C22 = bit32.bor(D22 + bit32.band(Q, bit32.arshift(D22, 31)), 0)
		buffer.writeu32(Output, Out + 32, bit32.bor(bit32.rshift(C19, 9), bit32.lshift(C20, 4), bit32.lshift(C21, 17), bit32.lshift(C22, 30)))
		local D23 = bit32.bor(X - buffer.readu32(Vector, In + 92), 0)
		local C23 = bit32.bor(D23 + bit32.band(Q, bit32.arshift(D23, 31)), 0)
		local D24 = bit32.bor(X - buffer.readu32(Vector, In + 96), 0)
		local C24 = bit32.bor(D24 + bit32.band(Q, bit32.arshift(D24, 31)), 0)
		buffer.writeu32(Output, Out + 36, bit32.bor(bit32.rshift(C22, 2), bit32.lshift(C23, 11), bit32.lshift(C24, 24)))
		local D25 = bit32.bor(X - buffer.readu32(Vector, In + 100), 0)
		local C25 = bit32.bor(D25 + bit32.band(Q, bit32.arshift(D25, 31)), 0)
		local D26 = bit32.bor(X - buffer.readu32(Vector, In + 104), 0)
		local C26 = bit32.bor(D26 + bit32.band(Q, bit32.arshift(D26, 31)), 0)
		local D27 = bit32.bor(X - buffer.readu32(Vector, In + 108), 0)
		local C27 = bit32.bor(D27 + bit32.band(Q, bit32.arshift(D27, 31)), 0)
		buffer.writeu32(Output, Out + 40, bit32.bor(bit32.rshift(C24, 8), bit32.lshift(C25, 5), bit32.lshift(C26, 18), bit32.lshift(C27, 31)))
		local D28 = bit32.bor(X - buffer.readu32(Vector, In + 112), 0)
		local C28 = bit32.bor(D28 + bit32.band(Q, bit32.arshift(D28, 31)), 0)
		local D29 = bit32.bor(X - buffer.readu32(Vector, In + 116), 0)
		local C29 = bit32.bor(D29 + bit32.band(Q, bit32.arshift(D29, 31)), 0)
		buffer.writeu32(Output, Out + 44, bit32.bor(bit32.rshift(C27, 1), bit32.lshift(C28, 12), bit32.lshift(C29, 25)))
		local D30 = bit32.bor(X - buffer.readu32(Vector, In + 120), 0)
		local C30 = bit32.bor(D30 + bit32.band(Q, bit32.arshift(D30, 31)), 0)
		local D31 = bit32.bor(X - buffer.readu32(Vector, In + 124), 0)
		local C31 = bit32.bor(D31 + bit32.band(Q, bit32.arshift(D31, 31)), 0)
		buffer.writeu32(Output, Out + 48, bit32.bor(bit32.rshift(C29, 7), bit32.lshift(C30, 6), bit32.lshift(C31, 19)))
	end
end

local function DecodeCentered13(Data: buffer, DataOffset: number, Coefficients: number, X: number, Vector: buffer, VectorOffset: number)
	for Group = 0, Coefficients / 32 - 1 do
		local In = DataOffset + Group * 52
		local Out = VectorOffset + Group * 128
		local W0 = buffer.readu32(Data, In)
		local D0 = bit32.bor(X - bit32.band(W0, 8191), 0)
		buffer.writeu32(Vector, Out, bit32.bor(D0 + bit32.band(Q, bit32.arshift(D0, 31)), 0))
		local D1 = bit32.bor(X - bit32.band(bit32.rshift(W0, 13), 8191), 0)
		buffer.writeu32(Vector, Out + 4, bit32.bor(D1 + bit32.band(Q, bit32.arshift(D1, 31)), 0))
		local W1 = buffer.readu32(Data, In + 4)
		local D2 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W0, 26), bit32.lshift(W1, 6)), 8191), 0)
		buffer.writeu32(Vector, Out + 8, bit32.bor(D2 + bit32.band(Q, bit32.arshift(D2, 31)), 0))
		local D3 = bit32.bor(X - bit32.band(bit32.rshift(W1, 7), 8191), 0)
		buffer.writeu32(Vector, Out + 12, bit32.bor(D3 + bit32.band(Q, bit32.arshift(D3, 31)), 0))
		local W2 = buffer.readu32(Data, In + 8)
		local D4 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W1, 20), bit32.lshift(W2, 12)), 8191), 0)
		buffer.writeu32(Vector, Out + 16, bit32.bor(D4 + bit32.band(Q, bit32.arshift(D4, 31)), 0))
		local D5 = bit32.bor(X - bit32.band(bit32.rshift(W2, 1), 8191), 0)
		buffer.writeu32(Vector, Out + 20, bit32.bor(D5 + bit32.band(Q, bit32.arshift(D5, 31)), 0))
		local D6 = bit32.bor(X - bit32.band(bit32.rshift(W2, 14), 8191), 0)
		buffer.writeu32(Vector, Out + 24, bit32.bor(D6 + bit32.band(Q, bit32.arshift(D6, 31)), 0))
		local W3 = buffer.readu32(Data, In + 12)
		local D7 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W2, 27), bit32.lshift(W3, 5)), 8191), 0)
		buffer.writeu32(Vector, Out + 28, bit32.bor(D7 + bit32.band(Q, bit32.arshift(D7, 31)), 0))
		local D8 = bit32.bor(X - bit32.band(bit32.rshift(W3, 8), 8191), 0)
		buffer.writeu32(Vector, Out + 32, bit32.bor(D8 + bit32.band(Q, bit32.arshift(D8, 31)), 0))
		local W4 = buffer.readu32(Data, In + 16)
		local D9 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W3, 21), bit32.lshift(W4, 11)), 8191), 0)
		buffer.writeu32(Vector, Out + 36, bit32.bor(D9 + bit32.band(Q, bit32.arshift(D9, 31)), 0))
		local D10 = bit32.bor(X - bit32.band(bit32.rshift(W4, 2), 8191), 0)
		buffer.writeu32(Vector, Out + 40, bit32.bor(D10 + bit32.band(Q, bit32.arshift(D10, 31)), 0))
		local D11 = bit32.bor(X - bit32.band(bit32.rshift(W4, 15), 8191), 0)
		buffer.writeu32(Vector, Out + 44, bit32.bor(D11 + bit32.band(Q, bit32.arshift(D11, 31)), 0))
		local W5 = buffer.readu32(Data, In + 20)
		local D12 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W4, 28), bit32.lshift(W5, 4)), 8191), 0)
		buffer.writeu32(Vector, Out + 48, bit32.bor(D12 + bit32.band(Q, bit32.arshift(D12, 31)), 0))
		local D13 = bit32.bor(X - bit32.band(bit32.rshift(W5, 9), 8191), 0)
		buffer.writeu32(Vector, Out + 52, bit32.bor(D13 + bit32.band(Q, bit32.arshift(D13, 31)), 0))
		local W6 = buffer.readu32(Data, In + 24)
		local D14 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W5, 22), bit32.lshift(W6, 10)), 8191), 0)
		buffer.writeu32(Vector, Out + 56, bit32.bor(D14 + bit32.band(Q, bit32.arshift(D14, 31)), 0))
		local D15 = bit32.bor(X - bit32.band(bit32.rshift(W6, 3), 8191), 0)
		buffer.writeu32(Vector, Out + 60, bit32.bor(D15 + bit32.band(Q, bit32.arshift(D15, 31)), 0))
		local D16 = bit32.bor(X - bit32.band(bit32.rshift(W6, 16), 8191), 0)
		buffer.writeu32(Vector, Out + 64, bit32.bor(D16 + bit32.band(Q, bit32.arshift(D16, 31)), 0))
		local W7 = buffer.readu32(Data, In + 28)
		local D17 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W6, 29), bit32.lshift(W7, 3)), 8191), 0)
		buffer.writeu32(Vector, Out + 68, bit32.bor(D17 + bit32.band(Q, bit32.arshift(D17, 31)), 0))
		local D18 = bit32.bor(X - bit32.band(bit32.rshift(W7, 10), 8191), 0)
		buffer.writeu32(Vector, Out + 72, bit32.bor(D18 + bit32.band(Q, bit32.arshift(D18, 31)), 0))
		local W8 = buffer.readu32(Data, In + 32)
		local D19 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W7, 23), bit32.lshift(W8, 9)), 8191), 0)
		buffer.writeu32(Vector, Out + 76, bit32.bor(D19 + bit32.band(Q, bit32.arshift(D19, 31)), 0))
		local D20 = bit32.bor(X - bit32.band(bit32.rshift(W8, 4), 8191), 0)
		buffer.writeu32(Vector, Out + 80, bit32.bor(D20 + bit32.band(Q, bit32.arshift(D20, 31)), 0))
		local D21 = bit32.bor(X - bit32.band(bit32.rshift(W8, 17), 8191), 0)
		buffer.writeu32(Vector, Out + 84, bit32.bor(D21 + bit32.band(Q, bit32.arshift(D21, 31)), 0))
		local W9 = buffer.readu32(Data, In + 36)
		local D22 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W8, 30), bit32.lshift(W9, 2)), 8191), 0)
		buffer.writeu32(Vector, Out + 88, bit32.bor(D22 + bit32.band(Q, bit32.arshift(D22, 31)), 0))
		local D23 = bit32.bor(X - bit32.band(bit32.rshift(W9, 11), 8191), 0)
		buffer.writeu32(Vector, Out + 92, bit32.bor(D23 + bit32.band(Q, bit32.arshift(D23, 31)), 0))
		local W10 = buffer.readu32(Data, In + 40)
		local D24 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W9, 24), bit32.lshift(W10, 8)), 8191), 0)
		buffer.writeu32(Vector, Out + 96, bit32.bor(D24 + bit32.band(Q, bit32.arshift(D24, 31)), 0))
		local D25 = bit32.bor(X - bit32.band(bit32.rshift(W10, 5), 8191), 0)
		buffer.writeu32(Vector, Out + 100, bit32.bor(D25 + bit32.band(Q, bit32.arshift(D25, 31)), 0))
		local D26 = bit32.bor(X - bit32.band(bit32.rshift(W10, 18), 8191), 0)
		buffer.writeu32(Vector, Out + 104, bit32.bor(D26 + bit32.band(Q, bit32.arshift(D26, 31)), 0))
		local W11 = buffer.readu32(Data, In + 44)
		local D27 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W10, 31), bit32.lshift(W11, 1)), 8191), 0)
		buffer.writeu32(Vector, Out + 108, bit32.bor(D27 + bit32.band(Q, bit32.arshift(D27, 31)), 0))
		local D28 = bit32.bor(X - bit32.band(bit32.rshift(W11, 12), 8191), 0)
		buffer.writeu32(Vector, Out + 112, bit32.bor(D28 + bit32.band(Q, bit32.arshift(D28, 31)), 0))
		local W12 = buffer.readu32(Data, In + 48)
		local D29 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W11, 25), bit32.lshift(W12, 7)), 8191), 0)
		buffer.writeu32(Vector, Out + 116, bit32.bor(D29 + bit32.band(Q, bit32.arshift(D29, 31)), 0))
		local D30 = bit32.bor(X - bit32.band(bit32.rshift(W12, 6), 8191), 0)
		buffer.writeu32(Vector, Out + 120, bit32.bor(D30 + bit32.band(Q, bit32.arshift(D30, 31)), 0))
		local D31 = bit32.bor(X - bit32.rshift(W12, 19), 0)
		buffer.writeu32(Vector, Out + 124, bit32.bor(D31 + bit32.band(Q, bit32.arshift(D31, 31)), 0))
	end
end

local function EncodeCentered18(Vector: buffer, VectorOffset: number, Coefficients: number, X: number, Output: buffer, OutputOffset: number)
	for Group = 0, Coefficients / 16 - 1 do
		local In = VectorOffset + Group * 64
		local Out = OutputOffset + Group * 36
		local D0 = bit32.bor(X - buffer.readu32(Vector, In), 0)
		local C0 = bit32.bor(D0 + bit32.band(Q, bit32.arshift(D0, 31)), 0)
		local D1 = bit32.bor(X - buffer.readu32(Vector, In + 4), 0)
		local C1 = bit32.bor(D1 + bit32.band(Q, bit32.arshift(D1, 31)), 0)
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 18)))
		local D2 = bit32.bor(X - buffer.readu32(Vector, In + 8), 0)
		local C2 = bit32.bor(D2 + bit32.band(Q, bit32.arshift(D2, 31)), 0)
		local D3 = bit32.bor(X - buffer.readu32(Vector, In + 12), 0)
		local C3 = bit32.bor(D3 + bit32.band(Q, bit32.arshift(D3, 31)), 0)
		buffer.writeu32(Output, Out + 4, bit32.bor(bit32.rshift(C1, 14), bit32.lshift(C2, 4), bit32.lshift(C3, 22)))
		local D4 = bit32.bor(X - buffer.readu32(Vector, In + 16), 0)
		local C4 = bit32.bor(D4 + bit32.band(Q, bit32.arshift(D4, 31)), 0)
		local D5 = bit32.bor(X - buffer.readu32(Vector, In + 20), 0)
		local C5 = bit32.bor(D5 + bit32.band(Q, bit32.arshift(D5, 31)), 0)
		buffer.writeu32(Output, Out + 8, bit32.bor(bit32.rshift(C3, 10), bit32.lshift(C4, 8), bit32.lshift(C5, 26)))
		local D6 = bit32.bor(X - buffer.readu32(Vector, In + 24), 0)
		local C6 = bit32.bor(D6 + bit32.band(Q, bit32.arshift(D6, 31)), 0)
		local D7 = bit32.bor(X - buffer.readu32(Vector, In + 28), 0)
		local C7 = bit32.bor(D7 + bit32.band(Q, bit32.arshift(D7, 31)), 0)
		buffer.writeu32(Output, Out + 12, bit32.bor(bit32.rshift(C5, 6), bit32.lshift(C6, 12), bit32.lshift(C7, 30)))
		local D8 = bit32.bor(X - buffer.readu32(Vector, In + 32), 0)
		local C8 = bit32.bor(D8 + bit32.band(Q, bit32.arshift(D8, 31)), 0)
		buffer.writeu32(Output, Out + 16, bit32.bor(bit32.rshift(C7, 2), bit32.lshift(C8, 16)))
		local D9 = bit32.bor(X - buffer.readu32(Vector, In + 36), 0)
		local C9 = bit32.bor(D9 + bit32.band(Q, bit32.arshift(D9, 31)), 0)
		local D10 = bit32.bor(X - buffer.readu32(Vector, In + 40), 0)
		local C10 = bit32.bor(D10 + bit32.band(Q, bit32.arshift(D10, 31)), 0)
		buffer.writeu32(Output, Out + 20, bit32.bor(bit32.rshift(C8, 16), bit32.lshift(C9, 2), bit32.lshift(C10, 20)))
		local D11 = bit32.bor(X - buffer.readu32(Vector, In + 44), 0)
		local C11 = bit32.bor(D11 + bit32.band(Q, bit32.arshift(D11, 31)), 0)
		local D12 = bit32.bor(X - buffer.readu32(Vector, In + 48), 0)
		local C12 = bit32.bor(D12 + bit32.band(Q, bit32.arshift(D12, 31)), 0)
		buffer.writeu32(Output, Out + 24, bit32.bor(bit32.rshift(C10, 12), bit32.lshift(C11, 6), bit32.lshift(C12, 24)))
		local D13 = bit32.bor(X - buffer.readu32(Vector, In + 52), 0)
		local C13 = bit32.bor(D13 + bit32.band(Q, bit32.arshift(D13, 31)), 0)
		local D14 = bit32.bor(X - buffer.readu32(Vector, In + 56), 0)
		local C14 = bit32.bor(D14 + bit32.band(Q, bit32.arshift(D14, 31)), 0)
		buffer.writeu32(Output, Out + 28, bit32.bor(bit32.rshift(C12, 8), bit32.lshift(C13, 10), bit32.lshift(C14, 28)))
		local D15 = bit32.bor(X - buffer.readu32(Vector, In + 60), 0)
		local C15 = bit32.bor(D15 + bit32.band(Q, bit32.arshift(D15, 31)), 0)
		buffer.writeu32(Output, Out + 32, bit32.bor(bit32.rshift(C14, 4), bit32.lshift(C15, 14)))
	end
end

local function DecodeCentered18(Data: buffer, DataOffset: number, Coefficients: number, X: number, Vector: buffer, VectorOffset: number)
	for Group = 0, Coefficients / 16 - 1 do
		local In = DataOffset + Group * 36
		local Out = VectorOffset + Group * 64
		local W0 = buffer.readu32(Data, In)
		local D0 = bit32.bor(X - bit32.band(W0, 262143), 0)
		buffer.writeu32(Vector, Out, bit32.bor(D0 + bit32.band(Q, bit32.arshift(D0, 31)), 0))
		local W1 = buffer.readu32(Data, In + 4)
		local D1 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W0, 18), bit32.lshift(W1, 14)), 262143), 0)
		buffer.writeu32(Vector, Out + 4, bit32.bor(D1 + bit32.band(Q, bit32.arshift(D1, 31)), 0))
		local D2 = bit32.bor(X - bit32.band(bit32.rshift(W1, 4), 262143), 0)
		buffer.writeu32(Vector, Out + 8, bit32.bor(D2 + bit32.band(Q, bit32.arshift(D2, 31)), 0))
		local W2 = buffer.readu32(Data, In + 8)
		local D3 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W1, 22), bit32.lshift(W2, 10)), 262143), 0)
		buffer.writeu32(Vector, Out + 12, bit32.bor(D3 + bit32.band(Q, bit32.arshift(D3, 31)), 0))
		local D4 = bit32.bor(X - bit32.band(bit32.rshift(W2, 8), 262143), 0)
		buffer.writeu32(Vector, Out + 16, bit32.bor(D4 + bit32.band(Q, bit32.arshift(D4, 31)), 0))
		local W3 = buffer.readu32(Data, In + 12)
		local D5 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W2, 26), bit32.lshift(W3, 6)), 262143), 0)
		buffer.writeu32(Vector, Out + 20, bit32.bor(D5 + bit32.band(Q, bit32.arshift(D5, 31)), 0))
		local D6 = bit32.bor(X - bit32.band(bit32.rshift(W3, 12), 262143), 0)
		buffer.writeu32(Vector, Out + 24, bit32.bor(D6 + bit32.band(Q, bit32.arshift(D6, 31)), 0))
		local W4 = buffer.readu32(Data, In + 16)
		local D7 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W3, 30), bit32.lshift(W4, 2)), 262143), 0)
		buffer.writeu32(Vector, Out + 28, bit32.bor(D7 + bit32.band(Q, bit32.arshift(D7, 31)), 0))
		local W5 = buffer.readu32(Data, In + 20)
		local D8 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W4, 16), bit32.lshift(W5, 16)), 262143), 0)
		buffer.writeu32(Vector, Out + 32, bit32.bor(D8 + bit32.band(Q, bit32.arshift(D8, 31)), 0))
		local D9 = bit32.bor(X - bit32.band(bit32.rshift(W5, 2), 262143), 0)
		buffer.writeu32(Vector, Out + 36, bit32.bor(D9 + bit32.band(Q, bit32.arshift(D9, 31)), 0))
		local W6 = buffer.readu32(Data, In + 24)
		local D10 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W5, 20), bit32.lshift(W6, 12)), 262143), 0)
		buffer.writeu32(Vector, Out + 40, bit32.bor(D10 + bit32.band(Q, bit32.arshift(D10, 31)), 0))
		local D11 = bit32.bor(X - bit32.band(bit32.rshift(W6, 6), 262143), 0)
		buffer.writeu32(Vector, Out + 44, bit32.bor(D11 + bit32.band(Q, bit32.arshift(D11, 31)), 0))
		local W7 = buffer.readu32(Data, In + 28)
		local D12 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W6, 24), bit32.lshift(W7, 8)), 262143), 0)
		buffer.writeu32(Vector, Out + 48, bit32.bor(D12 + bit32.band(Q, bit32.arshift(D12, 31)), 0))
		local D13 = bit32.bor(X - bit32.band(bit32.rshift(W7, 10), 262143), 0)
		buffer.writeu32(Vector, Out + 52, bit32.bor(D13 + bit32.band(Q, bit32.arshift(D13, 31)), 0))
		local W8 = buffer.readu32(Data, In + 32)
		local D14 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W7, 28), bit32.lshift(W8, 4)), 262143), 0)
		buffer.writeu32(Vector, Out + 56, bit32.bor(D14 + bit32.band(Q, bit32.arshift(D14, 31)), 0))
		local D15 = bit32.bor(X - bit32.rshift(W8, 14), 0)
		buffer.writeu32(Vector, Out + 60, bit32.bor(D15 + bit32.band(Q, bit32.arshift(D15, 31)), 0))
	end
end

local function EncodeCentered20(Vector: buffer, VectorOffset: number, Coefficients: number, X: number, Output: buffer, OutputOffset: number)
	for Group = 0, Coefficients / 8 - 1 do
		local In = VectorOffset + Group * 32
		local Out = OutputOffset + Group * 20
		local D0 = bit32.bor(X - buffer.readu32(Vector, In), 0)
		local C0 = bit32.bor(D0 + bit32.band(Q, bit32.arshift(D0, 31)), 0)
		local D1 = bit32.bor(X - buffer.readu32(Vector, In + 4), 0)
		local C1 = bit32.bor(D1 + bit32.band(Q, bit32.arshift(D1, 31)), 0)
		buffer.writeu32(Output, Out, bit32.bor(C0, bit32.lshift(C1, 20)))
		local D2 = bit32.bor(X - buffer.readu32(Vector, In + 8), 0)
		local C2 = bit32.bor(D2 + bit32.band(Q, bit32.arshift(D2, 31)), 0)
		local D3 = bit32.bor(X - buffer.readu32(Vector, In + 12), 0)
		local C3 = bit32.bor(D3 + bit32.band(Q, bit32.arshift(D3, 31)), 0)
		buffer.writeu32(Output, Out + 4, bit32.bor(bit32.rshift(C1, 12), bit32.lshift(C2, 8), bit32.lshift(C3, 28)))
		local D4 = bit32.bor(X - buffer.readu32(Vector, In + 16), 0)
		local C4 = bit32.bor(D4 + bit32.band(Q, bit32.arshift(D4, 31)), 0)
		buffer.writeu32(Output, Out + 8, bit32.bor(bit32.rshift(C3, 4), bit32.lshift(C4, 16)))
		local D5 = bit32.bor(X - buffer.readu32(Vector, In + 20), 0)
		local C5 = bit32.bor(D5 + bit32.band(Q, bit32.arshift(D5, 31)), 0)
		local D6 = bit32.bor(X - buffer.readu32(Vector, In + 24), 0)
		local C6 = bit32.bor(D6 + bit32.band(Q, bit32.arshift(D6, 31)), 0)
		buffer.writeu32(Output, Out + 12, bit32.bor(bit32.rshift(C4, 16), bit32.lshift(C5, 4), bit32.lshift(C6, 24)))
		local D7 = bit32.bor(X - buffer.readu32(Vector, In + 28), 0)
		local C7 = bit32.bor(D7 + bit32.band(Q, bit32.arshift(D7, 31)), 0)
		buffer.writeu32(Output, Out + 16, bit32.bor(bit32.rshift(C6, 8), bit32.lshift(C7, 12)))
	end
end

local function DecodeCentered20(Data: buffer, DataOffset: number, Coefficients: number, X: number, Vector: buffer, VectorOffset: number)
	for Group = 0, Coefficients / 8 - 1 do
		local In = DataOffset + Group * 20
		local Out = VectorOffset + Group * 32
		local W0 = buffer.readu32(Data, In)
		local D0 = bit32.bor(X - bit32.band(W0, 1048575), 0)
		buffer.writeu32(Vector, Out, bit32.bor(D0 + bit32.band(Q, bit32.arshift(D0, 31)), 0))
		local W1 = buffer.readu32(Data, In + 4)
		local D1 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W0, 20), bit32.lshift(W1, 12)), 1048575), 0)
		buffer.writeu32(Vector, Out + 4, bit32.bor(D1 + bit32.band(Q, bit32.arshift(D1, 31)), 0))
		local D2 = bit32.bor(X - bit32.band(bit32.rshift(W1, 8), 1048575), 0)
		buffer.writeu32(Vector, Out + 8, bit32.bor(D2 + bit32.band(Q, bit32.arshift(D2, 31)), 0))
		local W2 = buffer.readu32(Data, In + 8)
		local D3 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W1, 28), bit32.lshift(W2, 4)), 1048575), 0)
		buffer.writeu32(Vector, Out + 12, bit32.bor(D3 + bit32.band(Q, bit32.arshift(D3, 31)), 0))
		local W3 = buffer.readu32(Data, In + 12)
		local D4 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W2, 16), bit32.lshift(W3, 16)), 1048575), 0)
		buffer.writeu32(Vector, Out + 16, bit32.bor(D4 + bit32.band(Q, bit32.arshift(D4, 31)), 0))
		local D5 = bit32.bor(X - bit32.band(bit32.rshift(W3, 4), 1048575), 0)
		buffer.writeu32(Vector, Out + 20, bit32.bor(D5 + bit32.band(Q, bit32.arshift(D5, 31)), 0))
		local W4 = buffer.readu32(Data, In + 16)
		local D6 = bit32.bor(X - bit32.band(bit32.bor(bit32.rshift(W3, 24), bit32.lshift(W4, 8)), 1048575), 0)
		buffer.writeu32(Vector, Out + 24, bit32.bor(D6 + bit32.band(Q, bit32.arshift(D6, 31)), 0))
		local D7 = bit32.bor(X - bit32.rshift(W4, 12), 0)
		buffer.writeu32(Vector, Out + 28, bit32.bor(D7 + bit32.band(Q, bit32.arshift(D7, 31)), 0))
	end
end

local BitPack = {
	EncodeT1 = EncodeT1,
	DecodeT1 = DecodeT1,
}

function BitPack.EncodeCentered(Vector: buffer, VectorOffset: number, Coefficients: number, X: number, Bits: number, Output: buffer, OutputOffset: number): ()
	if Bits == 3 then
		EncodeCentered3(Vector, VectorOffset, Coefficients, X, Output, OutputOffset)
	elseif Bits == 4 then
		EncodeCentered4(Vector, VectorOffset, Coefficients, X, Output, OutputOffset)
	elseif Bits == 13 then
		EncodeCentered13(Vector, VectorOffset, Coefficients, X, Output, OutputOffset)
	elseif Bits == 18 then
		EncodeCentered18(Vector, VectorOffset, Coefficients, X, Output, OutputOffset)
	elseif Bits == 20 then
		EncodeCentered20(Vector, VectorOffset, Coefficients, X, Output, OutputOffset)
	else
		error(`EncodeCentered has no {Bits} bit form`, 2)
	end
end

function BitPack.DecodeCentered(Data: buffer, DataOffset: number, Coefficients: number, X: number, Bits: number, Vector: buffer, VectorOffset: number): ()
	if Bits == 3 then
		DecodeCentered3(Data, DataOffset, Coefficients, X, Vector, VectorOffset)
	elseif Bits == 4 then
		DecodeCentered4(Data, DataOffset, Coefficients, X, Vector, VectorOffset)
	elseif Bits == 13 then
		DecodeCentered13(Data, DataOffset, Coefficients, X, Vector, VectorOffset)
	elseif Bits == 18 then
		DecodeCentered18(Data, DataOffset, Coefficients, X, Vector, VectorOffset)
	elseif Bits == 20 then
		DecodeCentered20(Data, DataOffset, Coefficients, X, Vector, VectorOffset)
	else
		error(`DecodeCentered has no {Bits} bit form`, 2)
	end
end

function BitPack.EncodeHintBits(H: buffer, Output: buffer, OutputOffset: number, K: number, Omega: number): ()
	buffer.fill(Output, OutputOffset, 0, Omega + K)

	local Idx = 0
	for I = 0, K - 1 do
		local PolyOffset = I * 1024
		for J = 0, 255 do
			if buffer.readu32(H, PolyOffset + J * 4) ~= 0 then
				if Idx >= Omega then
					error(`Hint vector has more than {Omega} set bits`, 2)
				end
				buffer.writeu8(Output, OutputOffset + Idx, J)
				Idx += 1
			end
		end
		buffer.writeu8(Output, OutputOffset + Omega + I, Idx)
	end
end

function BitPack.DecodeHintBits(Data: buffer, DataOffset: number, H: buffer, K: number, Omega: number): boolean
	buffer.fill(H, 0, 0, K * 1024)

	local Idx = 0
	local Failed = false
	for I = 0, K - 1 do
		local PolyOffset = I * 1024
		local Till = buffer.readu8(Data, DataOffset + Omega + I)
		if Till < Idx or Till > Omega then
			Failed = true
		end
		if not Failed then
			local Prev = -1
			for J = Idx, Till - 1 do
				local Position = buffer.readu8(Data, DataOffset + J)
				if Position <= Prev then
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
			if buffer.readu8(Data, DataOffset + I) ~= 0 then
				Failed = true
				break
			end
		end
	end

	return Failed
end

return BitPack
