--[=[
	Vector operations on degree-255 polynomials
	
	Works on vectors of polynomials including matrix multiplication,
	NTT transforms, and encoding/decoding for ML-DSA.

	Example usage:
		local Vec = buffer.create(4 * 256 * 4) -- 4 polynomials
		PolyVec.ForwardNTT(Vec, 4)
		local Norm = PolyVec.InfinityNorm(Vec, 4)
--]=]

--!strict
--!optimize 2
--!native

local NTT = require("./NTT")

local Q = 8380417
local N = 256
local POLY_SIZE = N * 4
local GAMMA2_88 = 95232

local PolyVec = {}

local HINT_WRAP_88 = buffer.create(47) do
	for Index = 0, 46 do
		buffer.writeu8(HINT_WRAP_88, Index, (Index - 1) % 44)
	end
end

local function Unmasked32(R: number): number
	local B = bit32.rshift(R + 127, 7)
	return bit32.rshift(bit32.bor(bit32.bor(bit32.lshift(B, 10) + B, 0) + 2097152, 0), 22)
end

local function Unmasked88(R: number): number
	local B = bit32.rshift(R + 127, 7)
	local Times11 = bit32.bor(bit32.bor(bit32.lshift(B, 3) + bit32.lshift(B, 1), 0) + B, 0)
	return bit32.rshift(bit32.bor(bit32.bor(bit32.lshift(Times11, 10) + Times11, 0) + 8388608, 0), 24)
end

local function Center32(Unmasked: number): number
	return bit32.bor(bit32.lshift(Unmasked, 19) - bit32.lshift(Unmasked, 9), 0)
end

local function Center88(Unmasked: number): number
	local Sum = bit32.bor(bit32.lshift(Unmasked, 17) + bit32.lshift(Unmasked, 15), 0)
	Sum = bit32.bor(Sum + bit32.lshift(Unmasked, 14), 0)
	Sum = bit32.bor(Sum + bit32.lshift(Unmasked, 13), 0)
	return bit32.bor(Sum + bit32.lshift(Unmasked, 11), 0)
end

local function HighBits32(R: number): number
	return bit32.band(Unmasked32(R), 15)
end

local function HighBits88(R: number): number
	local Unmasked = Unmasked88(R)
	return bit32.bxor(Unmasked, bit32.band(bit32.arshift(43 - Unmasked, 31), Unmasked))
end

local function Magnitude(Difference: number): number
	local Negative = bit32.arshift(Difference, 31)
	return bit32.bor(bit32.bxor(Difference, Negative) - Negative, 0)
end

local function CenteredMagnitude(Value: number): number
	local Flip = bit32.arshift(4190208 - Value, 31)
	return bit32.bxor(Value, bit32.band(Flip, bit32.bxor(Value, Q - Value)))
end

local function LowMagnitude32(R: number): number
	local Unmasked = Unmasked32(R)
	return bit32.bor(Magnitude(R - Center32(Unmasked)) + bit32.rshift(Unmasked, 4), 0)
end

local function LowMagnitude88(R: number): number
	local Unmasked = Unmasked88(R)
	return bit32.bor(Magnitude(R - Center88(Unmasked)) + bit32.rshift(43 - Unmasked, 31), 0)
end

local function UseHint32(Hint: number, R: number): number
	local Unmasked = Unmasked32(R)
	local Positive = bit32.rshift(Center32(Unmasked) - R, 31)
	local Up = bit32.band(Hint, Positive)
	local Down = bit32.band(Hint, bit32.bxor(Positive, 1))
	return bit32.band(bit32.bor(bit32.band(Unmasked, 15) + Up, 0) - Down, 15)
end

local function UseHint88(Hint: number, R: number): number
	local Unmasked = Unmasked88(R)
	local Positive = bit32.rshift(Center88(Unmasked) - R, 31)
	local Up = bit32.band(Hint, Positive)
	local Down = bit32.band(Hint, bit32.bxor(Positive, 1))
	return buffer.readu8(HINT_WRAP_88, bit32.bor(bit32.bor(Unmasked + Up, 0) + bit32.bxor(Down, 1), 0))
end

local function AddModQ(A: number, B: number): number
	local Difference = bit32.bor(bit32.bor(A + B, 0) - Q, 0)
	return bit32.bor(Difference + bit32.band(Q, bit32.arshift(Difference, 31)), 0)
end

local function SubtractModQ(A: number, B: number): number
	local Difference = bit32.bor(A - B, 0)
	return bit32.bor(Difference + bit32.band(Q, bit32.arshift(Difference, 31)), 0)
end

function PolyVec.ForwardNTT(Vec: buffer, K: number)
	local Num = N
	for I = 0, K - 1 do
		local Offset = I * Num * 4
		NTT.ForwardNTTWithOffset(Vec, Offset)
	end
end

function PolyVec.InverseNTTProduct(Factor: buffer, Source: buffer, Destination: buffer, K: number)
	local InverseProduct = NTT.InverseNTTProduct
	for I = 0, K - 1 do
		InverseProduct(Factor, Source, I * N * 4, Destination, I * N * 4)
	end
end

function PolyVec.InverseNTT(Vec: buffer, K: number)
	local Inverse = NTT.InverseNTTWithOffset
	for I = 0, K - 1 do
		Inverse(Vec, I * N * 4)
	end
end

local function MatrixMultiply4x4(A: buffer, B: buffer, C: buffer)
	local Modulus = Q
	for E = 0, 1020, 4 do
		local B0 = buffer.readu32(B, E)
		local B1 = buffer.readu32(B, E + 1024)
		local B2 = buffer.readu32(B, E + 2048)
		local B3 = buffer.readu32(B, E + 3072)
		do
			local Acc = buffer.readu32(A, E) * B0
				+ buffer.readu32(A, E + 1024) * B1
				+ buffer.readu32(A, E + 2048) * B2
				+ buffer.readu32(A, E + 3072) * B3
			buffer.writeu32(C, E, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 4096) * B0
				+ buffer.readu32(A, E + 5120) * B1
				+ buffer.readu32(A, E + 6144) * B2
				+ buffer.readu32(A, E + 7168) * B3
			buffer.writeu32(C, E + 1024, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 8192) * B0
				+ buffer.readu32(A, E + 9216) * B1
				+ buffer.readu32(A, E + 10240) * B2
				+ buffer.readu32(A, E + 11264) * B3
			buffer.writeu32(C, E + 2048, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 12288) * B0
				+ buffer.readu32(A, E + 13312) * B1
				+ buffer.readu32(A, E + 14336) * B2
				+ buffer.readu32(A, E + 15360) * B3
			buffer.writeu32(C, E + 3072, Acc % Modulus)
		end
	end
end

local function MatrixMultiply6x5(A: buffer, B: buffer, C: buffer)
	local Modulus = Q
	for E = 0, 1020, 4 do
		local B0 = buffer.readu32(B, E)
		local B1 = buffer.readu32(B, E + 1024)
		local B2 = buffer.readu32(B, E + 2048)
		local B3 = buffer.readu32(B, E + 3072)
		local B4 = buffer.readu32(B, E + 4096)
		do
			local Acc = buffer.readu32(A, E) * B0
				+ buffer.readu32(A, E + 1024) * B1
				+ buffer.readu32(A, E + 2048) * B2
				+ buffer.readu32(A, E + 3072) * B3
				+ buffer.readu32(A, E + 4096) * B4
			buffer.writeu32(C, E, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 5120) * B0
				+ buffer.readu32(A, E + 6144) * B1
				+ buffer.readu32(A, E + 7168) * B2
				+ buffer.readu32(A, E + 8192) * B3
				+ buffer.readu32(A, E + 9216) * B4
			buffer.writeu32(C, E + 1024, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 10240) * B0
				+ buffer.readu32(A, E + 11264) * B1
				+ buffer.readu32(A, E + 12288) * B2
				+ buffer.readu32(A, E + 13312) * B3
				+ buffer.readu32(A, E + 14336) * B4
			buffer.writeu32(C, E + 2048, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 15360) * B0
				+ buffer.readu32(A, E + 16384) * B1
				+ buffer.readu32(A, E + 17408) * B2
				+ buffer.readu32(A, E + 18432) * B3
				+ buffer.readu32(A, E + 19456) * B4
			buffer.writeu32(C, E + 3072, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 20480) * B0
				+ buffer.readu32(A, E + 21504) * B1
				+ buffer.readu32(A, E + 22528) * B2
				+ buffer.readu32(A, E + 23552) * B3
				+ buffer.readu32(A, E + 24576) * B4
			buffer.writeu32(C, E + 4096, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 25600) * B0
				+ buffer.readu32(A, E + 26624) * B1
				+ buffer.readu32(A, E + 27648) * B2
				+ buffer.readu32(A, E + 28672) * B3
				+ buffer.readu32(A, E + 29696) * B4
			buffer.writeu32(C, E + 5120, Acc % Modulus)
		end
	end
end

local function MatrixMultiply8x7(A: buffer, B: buffer, C: buffer)
	local Modulus = Q
	for E = 0, 1020, 4 do
		local B0 = buffer.readu32(B, E)
		local B1 = buffer.readu32(B, E + 1024)
		local B2 = buffer.readu32(B, E + 2048)
		local B3 = buffer.readu32(B, E + 3072)
		local B4 = buffer.readu32(B, E + 4096)
		local B5 = buffer.readu32(B, E + 5120)
		local B6 = buffer.readu32(B, E + 6144)
		do
			local Acc = buffer.readu32(A, E) * B0
				+ buffer.readu32(A, E + 1024) * B1
				+ buffer.readu32(A, E + 2048) * B2
				+ buffer.readu32(A, E + 3072) * B3
				+ buffer.readu32(A, E + 4096) * B4
				+ buffer.readu32(A, E + 5120) * B5
				+ buffer.readu32(A, E + 6144) * B6
			buffer.writeu32(C, E, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 7168) * B0
				+ buffer.readu32(A, E + 8192) * B1
				+ buffer.readu32(A, E + 9216) * B2
				+ buffer.readu32(A, E + 10240) * B3
				+ buffer.readu32(A, E + 11264) * B4
				+ buffer.readu32(A, E + 12288) * B5
				+ buffer.readu32(A, E + 13312) * B6
			buffer.writeu32(C, E + 1024, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 14336) * B0
				+ buffer.readu32(A, E + 15360) * B1
				+ buffer.readu32(A, E + 16384) * B2
				+ buffer.readu32(A, E + 17408) * B3
				+ buffer.readu32(A, E + 18432) * B4
				+ buffer.readu32(A, E + 19456) * B5
				+ buffer.readu32(A, E + 20480) * B6
			buffer.writeu32(C, E + 2048, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 21504) * B0
				+ buffer.readu32(A, E + 22528) * B1
				+ buffer.readu32(A, E + 23552) * B2
				+ buffer.readu32(A, E + 24576) * B3
				+ buffer.readu32(A, E + 25600) * B4
				+ buffer.readu32(A, E + 26624) * B5
				+ buffer.readu32(A, E + 27648) * B6
			buffer.writeu32(C, E + 3072, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 28672) * B0
				+ buffer.readu32(A, E + 29696) * B1
				+ buffer.readu32(A, E + 30720) * B2
				+ buffer.readu32(A, E + 31744) * B3
				+ buffer.readu32(A, E + 32768) * B4
				+ buffer.readu32(A, E + 33792) * B5
				+ buffer.readu32(A, E + 34816) * B6
			buffer.writeu32(C, E + 4096, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 35840) * B0
				+ buffer.readu32(A, E + 36864) * B1
				+ buffer.readu32(A, E + 37888) * B2
				+ buffer.readu32(A, E + 38912) * B3
				+ buffer.readu32(A, E + 39936) * B4
				+ buffer.readu32(A, E + 40960) * B5
				+ buffer.readu32(A, E + 41984) * B6
			buffer.writeu32(C, E + 5120, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 43008) * B0
				+ buffer.readu32(A, E + 44032) * B1
				+ buffer.readu32(A, E + 45056) * B2
				+ buffer.readu32(A, E + 46080) * B3
				+ buffer.readu32(A, E + 47104) * B4
				+ buffer.readu32(A, E + 48128) * B5
				+ buffer.readu32(A, E + 49152) * B6
			buffer.writeu32(C, E + 6144, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 50176) * B0
				+ buffer.readu32(A, E + 51200) * B1
				+ buffer.readu32(A, E + 52224) * B2
				+ buffer.readu32(A, E + 53248) * B3
				+ buffer.readu32(A, E + 54272) * B4
				+ buffer.readu32(A, E + 55296) * B5
				+ buffer.readu32(A, E + 56320) * B6
			buffer.writeu32(C, E + 7168, Acc % Modulus)
		end
	end
end

local function MatrixMultiplySubtract4x4(A: buffer, B: buffer, Challenge: buffer, T1: buffer, C: buffer)
	local Modulus = Q
	for E = 0, 1020, 4 do
		local B0 = buffer.readu32(B, E)
		local B1 = buffer.readu32(B, E + 1024)
		local B2 = buffer.readu32(B, E + 2048)
		local B3 = buffer.readu32(B, E + 3072)
		local Factor = buffer.readu32(Challenge, E)
		do
			local Acc = buffer.readu32(A, E) * B0
				+ buffer.readu32(A, E + 1024) * B1
				+ buffer.readu32(A, E + 2048) * B2
				+ buffer.readu32(A, E + 3072) * B3
				- Factor * buffer.readu32(T1, E)
			buffer.writeu32(C, E, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 4096) * B0
				+ buffer.readu32(A, E + 5120) * B1
				+ buffer.readu32(A, E + 6144) * B2
				+ buffer.readu32(A, E + 7168) * B3
				- Factor * buffer.readu32(T1, E + 1024)
			buffer.writeu32(C, E + 1024, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 8192) * B0
				+ buffer.readu32(A, E + 9216) * B1
				+ buffer.readu32(A, E + 10240) * B2
				+ buffer.readu32(A, E + 11264) * B3
				- Factor * buffer.readu32(T1, E + 2048)
			buffer.writeu32(C, E + 2048, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 12288) * B0
				+ buffer.readu32(A, E + 13312) * B1
				+ buffer.readu32(A, E + 14336) * B2
				+ buffer.readu32(A, E + 15360) * B3
				- Factor * buffer.readu32(T1, E + 3072)
			buffer.writeu32(C, E + 3072, Acc % Modulus)
		end
	end
end

local function MatrixMultiplySubtract6x5(A: buffer, B: buffer, Challenge: buffer, T1: buffer, C: buffer)
	local Modulus = Q
	for E = 0, 1020, 4 do
		local B0 = buffer.readu32(B, E)
		local B1 = buffer.readu32(B, E + 1024)
		local B2 = buffer.readu32(B, E + 2048)
		local B3 = buffer.readu32(B, E + 3072)
		local B4 = buffer.readu32(B, E + 4096)
		local Factor = buffer.readu32(Challenge, E)
		do
			local Acc = buffer.readu32(A, E) * B0
				+ buffer.readu32(A, E + 1024) * B1
				+ buffer.readu32(A, E + 2048) * B2
				+ buffer.readu32(A, E + 3072) * B3
				+ buffer.readu32(A, E + 4096) * B4
				- Factor * buffer.readu32(T1, E)
			buffer.writeu32(C, E, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 5120) * B0
				+ buffer.readu32(A, E + 6144) * B1
				+ buffer.readu32(A, E + 7168) * B2
				+ buffer.readu32(A, E + 8192) * B3
				+ buffer.readu32(A, E + 9216) * B4
				- Factor * buffer.readu32(T1, E + 1024)
			buffer.writeu32(C, E + 1024, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 10240) * B0
				+ buffer.readu32(A, E + 11264) * B1
				+ buffer.readu32(A, E + 12288) * B2
				+ buffer.readu32(A, E + 13312) * B3
				+ buffer.readu32(A, E + 14336) * B4
				- Factor * buffer.readu32(T1, E + 2048)
			buffer.writeu32(C, E + 2048, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 15360) * B0
				+ buffer.readu32(A, E + 16384) * B1
				+ buffer.readu32(A, E + 17408) * B2
				+ buffer.readu32(A, E + 18432) * B3
				+ buffer.readu32(A, E + 19456) * B4
				- Factor * buffer.readu32(T1, E + 3072)
			buffer.writeu32(C, E + 3072, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 20480) * B0
				+ buffer.readu32(A, E + 21504) * B1
				+ buffer.readu32(A, E + 22528) * B2
				+ buffer.readu32(A, E + 23552) * B3
				+ buffer.readu32(A, E + 24576) * B4
				- Factor * buffer.readu32(T1, E + 4096)
			buffer.writeu32(C, E + 4096, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 25600) * B0
				+ buffer.readu32(A, E + 26624) * B1
				+ buffer.readu32(A, E + 27648) * B2
				+ buffer.readu32(A, E + 28672) * B3
				+ buffer.readu32(A, E + 29696) * B4
				- Factor * buffer.readu32(T1, E + 5120)
			buffer.writeu32(C, E + 5120, Acc % Modulus)
		end
	end
end

local function MatrixMultiplySubtract8x7(A: buffer, B: buffer, Challenge: buffer, T1: buffer, C: buffer)
	local Modulus = Q
	for E = 0, 1020, 4 do
		local B0 = buffer.readu32(B, E)
		local B1 = buffer.readu32(B, E + 1024)
		local B2 = buffer.readu32(B, E + 2048)
		local B3 = buffer.readu32(B, E + 3072)
		local B4 = buffer.readu32(B, E + 4096)
		local B5 = buffer.readu32(B, E + 5120)
		local B6 = buffer.readu32(B, E + 6144)
		local Factor = buffer.readu32(Challenge, E)
		do
			local Acc = buffer.readu32(A, E) * B0
				+ buffer.readu32(A, E + 1024) * B1
				+ buffer.readu32(A, E + 2048) * B2
				+ buffer.readu32(A, E + 3072) * B3
				+ buffer.readu32(A, E + 4096) * B4
				+ buffer.readu32(A, E + 5120) * B5
				+ buffer.readu32(A, E + 6144) * B6
				- Factor * buffer.readu32(T1, E)
			buffer.writeu32(C, E, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 7168) * B0
				+ buffer.readu32(A, E + 8192) * B1
				+ buffer.readu32(A, E + 9216) * B2
				+ buffer.readu32(A, E + 10240) * B3
				+ buffer.readu32(A, E + 11264) * B4
				+ buffer.readu32(A, E + 12288) * B5
				+ buffer.readu32(A, E + 13312) * B6
				- Factor * buffer.readu32(T1, E + 1024)
			buffer.writeu32(C, E + 1024, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 14336) * B0
				+ buffer.readu32(A, E + 15360) * B1
				+ buffer.readu32(A, E + 16384) * B2
				+ buffer.readu32(A, E + 17408) * B3
				+ buffer.readu32(A, E + 18432) * B4
				+ buffer.readu32(A, E + 19456) * B5
				+ buffer.readu32(A, E + 20480) * B6
				- Factor * buffer.readu32(T1, E + 2048)
			buffer.writeu32(C, E + 2048, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 21504) * B0
				+ buffer.readu32(A, E + 22528) * B1
				+ buffer.readu32(A, E + 23552) * B2
				+ buffer.readu32(A, E + 24576) * B3
				+ buffer.readu32(A, E + 25600) * B4
				+ buffer.readu32(A, E + 26624) * B5
				+ buffer.readu32(A, E + 27648) * B6
				- Factor * buffer.readu32(T1, E + 3072)
			buffer.writeu32(C, E + 3072, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 28672) * B0
				+ buffer.readu32(A, E + 29696) * B1
				+ buffer.readu32(A, E + 30720) * B2
				+ buffer.readu32(A, E + 31744) * B3
				+ buffer.readu32(A, E + 32768) * B4
				+ buffer.readu32(A, E + 33792) * B5
				+ buffer.readu32(A, E + 34816) * B6
				- Factor * buffer.readu32(T1, E + 4096)
			buffer.writeu32(C, E + 4096, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 35840) * B0
				+ buffer.readu32(A, E + 36864) * B1
				+ buffer.readu32(A, E + 37888) * B2
				+ buffer.readu32(A, E + 38912) * B3
				+ buffer.readu32(A, E + 39936) * B4
				+ buffer.readu32(A, E + 40960) * B5
				+ buffer.readu32(A, E + 41984) * B6
				- Factor * buffer.readu32(T1, E + 5120)
			buffer.writeu32(C, E + 5120, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 43008) * B0
				+ buffer.readu32(A, E + 44032) * B1
				+ buffer.readu32(A, E + 45056) * B2
				+ buffer.readu32(A, E + 46080) * B3
				+ buffer.readu32(A, E + 47104) * B4
				+ buffer.readu32(A, E + 48128) * B5
				+ buffer.readu32(A, E + 49152) * B6
				- Factor * buffer.readu32(T1, E + 6144)
			buffer.writeu32(C, E + 6144, Acc % Modulus)
		end
		do
			local Acc = buffer.readu32(A, E + 50176) * B0
				+ buffer.readu32(A, E + 51200) * B1
				+ buffer.readu32(A, E + 52224) * B2
				+ buffer.readu32(A, E + 53248) * B3
				+ buffer.readu32(A, E + 54272) * B4
				+ buffer.readu32(A, E + 55296) * B5
				+ buffer.readu32(A, E + 56320) * B6
				- Factor * buffer.readu32(T1, E + 7168)
			buffer.writeu32(C, E + 7168, Acc % Modulus)
		end
	end
end

function PolyVec.MatrixMultiply(A: buffer, B: buffer, C: buffer, L: number)
	if L == 4 then
		MatrixMultiply4x4(A, B, C)
	elseif L == 5 then
		MatrixMultiply6x5(A, B, C)
	else
		MatrixMultiply8x7(A, B, C)
	end
end

function PolyVec.MatrixMultiplySubtract(A: buffer, B: buffer, Challenge: buffer, T1: buffer, C: buffer, L: number)
	if L == 4 then
		MatrixMultiplySubtract4x4(A, B, Challenge, T1, C)
	elseif L == 5 then
		MatrixMultiplySubtract6x5(A, B, Challenge, T1, C)
	else
		MatrixMultiplySubtract8x7(A, B, Challenge, T1, C)
	end
end

function PolyVec.Power2RoundSum(T: buffer, S2: buffer, T1: buffer, T0: buffer, K: number)
	for Offset = 0, K * POLY_SIZE - 16, 16 do
		do
			local Sum = AddModQ(buffer.readu32(T, Offset), buffer.readu32(S2, Offset))
			local High = bit32.rshift(Sum + 4095, 13)
			buffer.writeu32(T1, Offset, High)
			buffer.writeu32(T0, Offset, SubtractModQ(Sum, bit32.lshift(High, 13)))
		end
		do
			local Sum = AddModQ(buffer.readu32(T, Offset + 4), buffer.readu32(S2, Offset + 4))
			local High = bit32.rshift(Sum + 4095, 13)
			buffer.writeu32(T1, Offset + 4, High)
			buffer.writeu32(T0, Offset + 4, SubtractModQ(Sum, bit32.lshift(High, 13)))
		end
		do
			local Sum = AddModQ(buffer.readu32(T, Offset + 8), buffer.readu32(S2, Offset + 8))
			local High = bit32.rshift(Sum + 4095, 13)
			buffer.writeu32(T1, Offset + 8, High)
			buffer.writeu32(T0, Offset + 8, SubtractModQ(Sum, bit32.lshift(High, 13)))
		end
		do
			local Sum = AddModQ(buffer.readu32(T, Offset + 12), buffer.readu32(S2, Offset + 12))
			local High = bit32.rshift(Sum + 4095, 13)
			buffer.writeu32(T1, Offset + 12, High)
			buffer.writeu32(T0, Offset + 12, SubtractModQ(Sum, bit32.lshift(High, 13)))
		end
	end
end

function PolyVec.InfinityNorm(Vec: buffer, K: number): number
	local Result = 0
	for Offset = 0, K * POLY_SIZE - 16, 16 do
		Result = math.max(
			Result,
			CenteredMagnitude(buffer.readu32(Vec, Offset)),
			CenteredMagnitude(buffer.readu32(Vec, Offset + 4)),
			CenteredMagnitude(buffer.readu32(Vec, Offset + 8)),
			CenteredMagnitude(buffer.readu32(Vec, Offset + 12))
		)
	end

	return Result
end

function PolyVec.AddExceeds(Y: buffer, Product: buffer, Z: buffer, L: number, Bound: number): boolean
	local Limit = Bound - 1
	local Exceeds = 0
	for Offset = 0, L * POLY_SIZE - 16, 16 do
		local Sum0 = AddModQ(buffer.readu32(Y, Offset), buffer.readu32(Product, Offset))
		buffer.writeu32(Z, Offset, Sum0)
		local Sum1 = AddModQ(buffer.readu32(Y, Offset + 4), buffer.readu32(Product, Offset + 4))
		buffer.writeu32(Z, Offset + 4, Sum1)
		local Sum2 = AddModQ(buffer.readu32(Y, Offset + 8), buffer.readu32(Product, Offset + 8))
		buffer.writeu32(Z, Offset + 8, Sum2)
		local Sum3 = AddModQ(buffer.readu32(Y, Offset + 12), buffer.readu32(Product, Offset + 12))
		buffer.writeu32(Z, Offset + 12, Sum3)
		Exceeds = bit32.bor(Exceeds, bit32.rshift(Limit - math.max(CenteredMagnitude(Sum0), CenteredMagnitude(Sum1), CenteredMagnitude(Sum2), CenteredMagnitude(Sum3)), 31))
	end

	return Exceeds ~= 0
end

function PolyVec.SubtractLowBitsExceeds(W: buffer, Product: buffer, K: number, Gamma2: number, Bound: number): boolean
	local Limit = Bound - 1
	local Exceeds = 0
	if Gamma2 == GAMMA2_88 then
		for Offset = 0, K * POLY_SIZE - 16, 16 do
			local R0 = SubtractModQ(buffer.readu32(W, Offset), buffer.readu32(Product, Offset))
			buffer.writeu32(Product, Offset, R0)
			local R1 = SubtractModQ(buffer.readu32(W, Offset + 4), buffer.readu32(Product, Offset + 4))
			buffer.writeu32(Product, Offset + 4, R1)
			local R2 = SubtractModQ(buffer.readu32(W, Offset + 8), buffer.readu32(Product, Offset + 8))
			buffer.writeu32(Product, Offset + 8, R2)
			local R3 = SubtractModQ(buffer.readu32(W, Offset + 12), buffer.readu32(Product, Offset + 12))
			buffer.writeu32(Product, Offset + 12, R3)
			Exceeds = bit32.bor(Exceeds, bit32.rshift(Limit - math.max(LowMagnitude88(R0), LowMagnitude88(R1), LowMagnitude88(R2), LowMagnitude88(R3)), 31))
		end
	else
		for Offset = 0, K * POLY_SIZE - 16, 16 do
			local R0 = SubtractModQ(buffer.readu32(W, Offset), buffer.readu32(Product, Offset))
			buffer.writeu32(Product, Offset, R0)
			local R1 = SubtractModQ(buffer.readu32(W, Offset + 4), buffer.readu32(Product, Offset + 4))
			buffer.writeu32(Product, Offset + 4, R1)
			local R2 = SubtractModQ(buffer.readu32(W, Offset + 8), buffer.readu32(Product, Offset + 8))
			buffer.writeu32(Product, Offset + 8, R2)
			local R3 = SubtractModQ(buffer.readu32(W, Offset + 12), buffer.readu32(Product, Offset + 12))
			buffer.writeu32(Product, Offset + 12, R3)
			Exceeds = bit32.bor(Exceeds, bit32.rshift(Limit - math.max(LowMagnitude32(R0), LowMagnitude32(R1), LowMagnitude32(R2), LowMagnitude32(R3)), 31))
		end
	end

	return Exceeds ~= 0
end

function PolyVec.MakeHints(R: buffer, Product: buffer, Hints: buffer, K: number, Gamma2: number): (boolean, number)
	local Limit = Gamma2 - 1
	local Exceeds = 0
	local Count = 0
	if Gamma2 == GAMMA2_88 then
		for Offset = 0, K * POLY_SIZE - 16, 16 do
			local Value0 = buffer.readu32(R, Offset)
			local Ct0Value0 = buffer.readu32(Product, Offset)
			local Hint0 = bit32.rshift(0 - bit32.bxor(HighBits88(Value0), HighBits88(AddModQ(Value0, Ct0Value0))), 31)
			buffer.writeu32(Hints, Offset, Hint0)
			local Value1 = buffer.readu32(R, Offset + 4)
			local Ct0Value1 = buffer.readu32(Product, Offset + 4)
			local Hint1 = bit32.rshift(0 - bit32.bxor(HighBits88(Value1), HighBits88(AddModQ(Value1, Ct0Value1))), 31)
			buffer.writeu32(Hints, Offset + 4, Hint1)
			local Value2 = buffer.readu32(R, Offset + 8)
			local Ct0Value2 = buffer.readu32(Product, Offset + 8)
			local Hint2 = bit32.rshift(0 - bit32.bxor(HighBits88(Value2), HighBits88(AddModQ(Value2, Ct0Value2))), 31)
			buffer.writeu32(Hints, Offset + 8, Hint2)
			local Value3 = buffer.readu32(R, Offset + 12)
			local Ct0Value3 = buffer.readu32(Product, Offset + 12)
			local Hint3 = bit32.rshift(0 - bit32.bxor(HighBits88(Value3), HighBits88(AddModQ(Value3, Ct0Value3))), 31)
			buffer.writeu32(Hints, Offset + 12, Hint3)
			Count += bit32.bor(bit32.bor(bit32.bor(Hint0 + Hint1, 0) + Hint2, 0) + Hint3, 0)
			Exceeds = bit32.bor(Exceeds, bit32.rshift(Limit - math.max(CenteredMagnitude(Ct0Value0), CenteredMagnitude(Ct0Value1), CenteredMagnitude(Ct0Value2), CenteredMagnitude(Ct0Value3)), 31))
		end
	else
		for Offset = 0, K * POLY_SIZE - 16, 16 do
			local Value0 = buffer.readu32(R, Offset)
			local Ct0Value0 = buffer.readu32(Product, Offset)
			local Hint0 = bit32.rshift(0 - bit32.bxor(HighBits32(Value0), HighBits32(AddModQ(Value0, Ct0Value0))), 31)
			buffer.writeu32(Hints, Offset, Hint0)
			local Value1 = buffer.readu32(R, Offset + 4)
			local Ct0Value1 = buffer.readu32(Product, Offset + 4)
			local Hint1 = bit32.rshift(0 - bit32.bxor(HighBits32(Value1), HighBits32(AddModQ(Value1, Ct0Value1))), 31)
			buffer.writeu32(Hints, Offset + 4, Hint1)
			local Value2 = buffer.readu32(R, Offset + 8)
			local Ct0Value2 = buffer.readu32(Product, Offset + 8)
			local Hint2 = bit32.rshift(0 - bit32.bxor(HighBits32(Value2), HighBits32(AddModQ(Value2, Ct0Value2))), 31)
			buffer.writeu32(Hints, Offset + 8, Hint2)
			local Value3 = buffer.readu32(R, Offset + 12)
			local Ct0Value3 = buffer.readu32(Product, Offset + 12)
			local Hint3 = bit32.rshift(0 - bit32.bxor(HighBits32(Value3), HighBits32(AddModQ(Value3, Ct0Value3))), 31)
			buffer.writeu32(Hints, Offset + 12, Hint3)
			Count += bit32.bor(bit32.bor(bit32.bor(Hint0 + Hint1, 0) + Hint2, 0) + Hint3, 0)
			Exceeds = bit32.bor(Exceeds, bit32.rshift(Limit - math.max(CenteredMagnitude(Ct0Value0), CenteredMagnitude(Ct0Value1), CenteredMagnitude(Ct0Value2), CenteredMagnitude(Ct0Value3)), 31))
		end
	end

	return Exceeds ~= 0, Count
end

function PolyVec.HighBitsEncode(W: buffer, K: number, Gamma2: number, Output: buffer, OutputOffset: number)
	if Gamma2 == GAMMA2_88 then
		for Group = 0, K * 64 - 1 do
			local In = Group * 16
			local Packed = bit32.bor(
				HighBits88(buffer.readu32(W, In)),
				bit32.lshift(HighBits88(buffer.readu32(W, In + 4)), 6),
				bit32.lshift(HighBits88(buffer.readu32(W, In + 8)), 12),
				bit32.lshift(HighBits88(buffer.readu32(W, In + 12)), 18)
			)
			local Out = OutputOffset + Group * 3
			buffer.writeu16(Output, Out, Packed)
			buffer.writeu8(Output, Out + 2, bit32.rshift(Packed, 16))
		end
	else
		for Group = 0, K * 32 - 1 do
			local In = Group * 32
			local Low = bit32.bor(
				HighBits32(buffer.readu32(W, In)),
				bit32.lshift(HighBits32(buffer.readu32(W, In + 4)), 4),
				bit32.lshift(HighBits32(buffer.readu32(W, In + 8)), 8),
				bit32.lshift(HighBits32(buffer.readu32(W, In + 12)), 12)
			)
			local High = bit32.bor(
				bit32.lshift(HighBits32(buffer.readu32(W, In + 16)), 16),
				bit32.lshift(HighBits32(buffer.readu32(W, In + 20)), 20),
				bit32.lshift(HighBits32(buffer.readu32(W, In + 24)), 24),
				bit32.lshift(HighBits32(buffer.readu32(W, In + 28)), 28)
			)
			buffer.writeu32(Output, OutputOffset + Group * 4, bit32.bor(Low, High))
		end
	end
end

function PolyVec.UseHintEncode(Hints: buffer, R: buffer, K: number, Gamma2: number, Output: buffer, OutputOffset: number)
	if Gamma2 == GAMMA2_88 then
		for Group = 0, K * 64 - 1 do
			local In = Group * 16
			local Packed = bit32.bor(
				UseHint88(buffer.readu32(Hints, In), buffer.readu32(R, In)),
				bit32.lshift(UseHint88(buffer.readu32(Hints, In + 4), buffer.readu32(R, In + 4)), 6),
				bit32.lshift(UseHint88(buffer.readu32(Hints, In + 8), buffer.readu32(R, In + 8)), 12),
				bit32.lshift(UseHint88(buffer.readu32(Hints, In + 12), buffer.readu32(R, In + 12)), 18)
			)
			local Out = OutputOffset + Group * 3
			buffer.writeu16(Output, Out, Packed)
			buffer.writeu8(Output, Out + 2, bit32.rshift(Packed, 16))
		end
	else
		for Group = 0, K * 32 - 1 do
			local In = Group * 32
			local Low = bit32.bor(
				UseHint32(buffer.readu32(Hints, In), buffer.readu32(R, In)),
				bit32.lshift(UseHint32(buffer.readu32(Hints, In + 4), buffer.readu32(R, In + 4)), 4),
				bit32.lshift(UseHint32(buffer.readu32(Hints, In + 8), buffer.readu32(R, In + 8)), 8),
				bit32.lshift(UseHint32(buffer.readu32(Hints, In + 12), buffer.readu32(R, In + 12)), 12)
			)
			local High = bit32.bor(
				bit32.lshift(UseHint32(buffer.readu32(Hints, In + 16), buffer.readu32(R, In + 16)), 16),
				bit32.lshift(UseHint32(buffer.readu32(Hints, In + 20), buffer.readu32(R, In + 20)), 20),
				bit32.lshift(UseHint32(buffer.readu32(Hints, In + 24), buffer.readu32(R, In + 24)), 24),
				bit32.lshift(UseHint32(buffer.readu32(Hints, In + 28), buffer.readu32(R, In + 28)), 28)
			)
			buffer.writeu32(Output, OutputOffset + Group * 4, bit32.bor(Low, High))
		end
	end
end

return PolyVec
