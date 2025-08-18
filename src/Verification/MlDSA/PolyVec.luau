--[=[
	Vector operations on degree-255 polynomials
	
	Works on vectors of polynomials including matrix multiplication,
	NTT transforms, and encoding/decoding for ML-DSA.

	Example usage:
		local PolyVec = require(script)
		
		local Vec = buffer.create(4 * 256 * 4)  -- 4 polynomials
		PolyVec.ForwardNTT(Vec, 4)
		local Norm = PolyVec.InfinityNorm(Vec, 4)
--]=]

--!strict
--!optimize 2
--!native

local Field = require("./Field")
local NTT = require("./NTT")
local BitPacking = require("./Pack")

local LOG2N = 8
local ZETA = 1753
local Q = 8380417

local N = 256
local INV_N = Field.Inverse(N)

local ZETA_EXP, ZETA_NEG_EXP = buffer.create(N * 4), buffer.create(N * 4) do
	for I = 0, N - 1 do
		local Reversed = 0
		local Value = I

		for J = 0, LOG2N - 1 do
			local Bit = bit32.band(bit32.rshift(Value, J), 1)
			Reversed = bit32.bxor(Reversed, bit32.lshift(Bit, LOG2N - 1 - J))
		end

		local ZetaExp = Field.Power(ZETA, Reversed)
		local ZetaNegExp = Field.Negate(ZetaExp)

		buffer.writeu32(ZETA_EXP, I * 4, ZetaExp)
		buffer.writeu32(ZETA_NEG_EXP, I * 4, ZetaNegExp)
	end
end

local PolyVec = {}

function PolyVec.ForwardNTT(Vec: buffer, K: number)
	for I = 0, K - 1 do
		local Offset = I * N * 4
		NTT.ForwardNTTWithOffset(Vec, Offset)
	end
end

function PolyVec.InverseNTT(Vec: buffer, K: number)
	for I = 0, K - 1 do
		local Offset = I * N * 4

		for L = 0, 7 do
			local Len = bit32.lshift(1, L)
			local LenX2 = bit32.lshift(Len, 1)
			local KBeg = bit32.rshift(N, L) - 1

			for Start = 0, N - 1, LenX2 do
				local KNow = KBeg - bit32.rshift(Start, L + 1)
				local NegZetaExpValue = buffer.readu32(ZETA_NEG_EXP, KNow * 4)

				for J = Start, Start + Len - 1 do
					local JOffset = Offset + J * 4
					local JLenOffset = Offset + (J + Len) * 4

					local PolyJ = buffer.readu32(Vec, JOffset)
					local PolyJLen = buffer.readu32(Vec, JLenOffset)

					local Sum = PolyJ + PolyJLen
					Sum = if Sum >= Q then Sum - Q else Sum

					local Diff = if PolyJ >= PolyJLen then PolyJ - PolyJLen else PolyJ - PolyJLen + Q
					local Product = (Diff * NegZetaExpValue) % Q

					buffer.writeu32(Vec, JOffset, Sum)
					buffer.writeu32(Vec, JLenOffset, Product)
				end
			end
		end

		local InvN = INV_N
		for J = 0, N - 1 do
			local JOffset = Offset + J * 4
			local PolyValue = buffer.readu32(Vec, JOffset)
			local Result = (PolyValue * InvN) % Q
			buffer.writeu32(Vec, JOffset, Result)
		end
	end
end

function PolyVec.Power2Round(PolyVec: buffer, PolyHi: buffer, PolyLo: buffer, K: number, D: number)
	local Max = bit32.lshift(1, D - 1)

	for I = 0, K - 1 do
		local Offset = I * N * 4

		for J = 0, N - 1 do
			local JOffset = Offset + J * 4
			local R = buffer.readu32(PolyVec, JOffset)

			local T1 = R + Max - 1
			local T2 = bit32.rshift(T1, D)
			local T3 = bit32.lshift(T2, D)

			local Hi = T2
			local Lo = if R >= T3 then R - T3 else R - T3 + Q

			buffer.writeu32(PolyHi, JOffset, Hi)
			buffer.writeu32(PolyLo, JOffset, Lo)
		end
	end
end

function PolyVec.MatrixMultiply(A: buffer, B: buffer, C: buffer, ARows: number, ACols: number, BRows: number, BCols: number)
	buffer.fill(C, 0, 0, ARows * BCols * N * 4)

	for I = 0, ARows - 1 do
		for J = 0, BCols - 1 do
			local COffset = (I * BCols + J) * N * 4

			for K = 0, ACols - 1 do
				local AOffset = (I * ACols + K) * N * 4
				local BOffset = (K * BCols + J) * N * 4

				for L = 0, N - 1 do
					local ElementOffset = L * 4
					local AValue = buffer.readu32(A, AOffset + ElementOffset)
					local BValue = buffer.readu32(B, BOffset + ElementOffset)

					local Product = (AValue * BValue) % Q

					local CValue = buffer.readu32(C, COffset + ElementOffset)
					local Sum = CValue + Product
					Sum = if Sum >= Q then Sum - Q else Sum

					buffer.writeu32(C, COffset + ElementOffset, Sum)
				end
			end
		end
	end
end

function PolyVec.AddTo(Src: buffer, Dst: buffer, K: number)
	local TotalElements = K * N

	for I = 0, TotalElements - 1 do
		local Offset = I * 4
		local SrcValue = buffer.readu32(Src, Offset)
		local DstValue = buffer.readu32(Dst, Offset)

		local Sum = DstValue + SrcValue
		Sum = if Sum >= Q then Sum - Q else Sum

		buffer.writeu32(Dst, Offset, Sum)
	end
end

function PolyVec.Negate(Vec: buffer, K: number)
	local TotalElements = K * N

	for I = 0, TotalElements - 1 do
		local Offset = I * 4
		local Value = buffer.readu32(Vec, Offset)
		local Negated = if Value == 0 then 0 else Q - Value

		buffer.writeu32(Vec, Offset, Negated)
	end
end

function PolyVec.SubFromX(Vec: buffer, K: number, X: number)
	for I = 0, K - 1 do
		local Offset = I * N * 4

		for J = 0, N - 1 do
			local JOffset = Offset + J * 4
			local PolyValue = buffer.readu32(Vec, JOffset)

			local Result = if X >= PolyValue then X - PolyValue else X - PolyValue + Q

			buffer.writeu32(Vec, JOffset, Result)
		end
	end
end

function PolyVec.Encode(Src: buffer, Dst: buffer, K: number, Sbw: number)
	local PolyByteLength = math.floor((N * Sbw) / 8)

	local PolyBuffer = buffer.create(N * 4)
	local ByteBuffer = buffer.create(PolyByteLength)

	for I = 0, K - 1 do
		local SrcOffset = I * N * 4
		local DstOffset = I * PolyByteLength

		buffer.copy(PolyBuffer, 0, Src, SrcOffset, N * 4)
		BitPacking.Encode(PolyBuffer, ByteBuffer, Sbw)
		buffer.copy(Dst, DstOffset, ByteBuffer, 0, PolyByteLength)
	end
end

function PolyVec.Decode(Src: buffer, Dst: buffer, K: number, Sbw: number)
	local PolyByteLength = math.floor((N * Sbw) / 8)

	local ByteBuffer = buffer.create(PolyByteLength)
	local PolyBuffer = buffer.create(N * 4)

	for I = 0, K - 1 do
		local SrcOffset = I * PolyByteLength
		local DstOffset = I * N * 4

		buffer.copy(ByteBuffer, 0, Src, SrcOffset, PolyByteLength)
		BitPacking.Decode(ByteBuffer, PolyBuffer, Sbw)
		buffer.copy(Dst, DstOffset, PolyBuffer, 0, N * 4)
	end
end

function PolyVec.HighBits(Src: buffer, Dst: buffer, K: number, Alpha: number)
	local T0 = bit32.rshift(Alpha, 1)
	local T1 = Q - 1

	for I = 0, K - 1 do
		local Offset = I * N * 4

		for J = 0, N - 1 do
			local JOffset = Offset + J * 4
			local R = buffer.readu32(Src, JOffset)

			local T2 = R + T0 - 1
			local T3 = math.floor(T2 / Alpha)
			local T4 = T3 * Alpha

			local R0 = if R >= T4 then R - T4 else R - T4 + Q
			local T5 = if R >= R0 then R - R0 else R - R0 + Q

			local Flag = (T5 == T1)
			local R1 = if Flag then 0 else T3

			buffer.writeu32(Dst, JOffset, R1)
		end
	end
end

function PolyVec.LowBits(Src: buffer, Dst: buffer, K: number, Alpha: number)
	local T0 = bit32.rshift(Alpha, 1)
	local T1 = Q - 1

	for I = 0, K - 1 do
		local Offset = I * N * 4

		for J = 0, N - 1 do
			local JOffset = Offset + J * 4
			local R = buffer.readu32(Src, JOffset)

			local T2 = R + T0 - 1
			local T3 = math.floor(T2 / Alpha)
			local T4 = T3 * Alpha

			local R0 = if R >= T4 then R - T4 else R - T4 + Q
			local T5 = if R >= R0 then R - R0 else R - R0 + Q

			local Flag = (T5 == T1)
			local R0_ = if Flag then (if R0 >= 1 then R0 - 1 else R0 - 1 + Q) else R0

			buffer.writeu32(Dst, JOffset, R0_)
		end
	end
end

function PolyVec.MultiplyByPoly(PolyBuffer: buffer, SrcVec: buffer, DstVec: buffer, K: number)
	for I = 0, K - 1 do
		local Offset = I * N * 4

		for J = 0, N - 1 do
			local JOffset = Offset + J * 4
			local PolyValue = buffer.readu32(PolyBuffer, J * 4)
			local SrcValue = buffer.readu32(SrcVec, JOffset)

			local Product = (PolyValue * SrcValue) % Q

			buffer.writeu32(DstVec, JOffset, Product)
		end
	end
end

function PolyVec.InfinityNorm(Vec: buffer, K: number): number
	local Result = 0
	local QBy2 = math.floor(Q / 2)

	for I = 0, K - 1 do
		local Offset = I * N * 4

		for J = 0, N - 1 do
			local JOffset = Offset + J * 4
			local PolyValue = buffer.readu32(Vec, JOffset)

			local CurrentValue = if PolyValue > QBy2 then (if PolyValue == 0 then 0 else Q - PolyValue) else PolyValue
			if CurrentValue > Result then
				Result = CurrentValue
			end
		end
	end

	return Result
end

function PolyVec.MakeHint(PolyA: buffer, PolyB: buffer, PolyC: buffer, K: number, Alpha: number)
	local T0 = bit32.rshift(Alpha, 1)
	local T1 = Q - 1

	for I = 0, K - 1 do
		local Offset = I * N * 4

		for J = 0, N - 1 do
			local JOffset = Offset + J * 4
			local Z = buffer.readu32(PolyA, JOffset)
			local R = buffer.readu32(PolyB, JOffset)

			local T2_R = R + T0 - 1
			local T3_R = math.floor(T2_R / Alpha)
			local T4_R = T3_R * Alpha
			local R0_R = if R >= T4_R then R - T4_R else R - T4_R + Q
			local T5_R = if R >= R0_R then R - R0_R else R - R0_R + Q
			local Flag_R = (T5_R == T1)
			local R1 = if Flag_R then 0 else T3_R

			local Sum = R + Z
			Sum = if Sum >= Q then Sum - Q else Sum

			local T2_V = Sum + T0 - 1
			local T3_V = math.floor(T2_V / Alpha)
			local T4_V = T3_V * Alpha
			local R0_V = if Sum >= T4_V then Sum - T4_V else Sum - T4_V + Q
			local T5_V = if Sum >= R0_V then Sum - R0_V else Sum - R0_V + Q
			local Flag_V = (T5_V == T1)
			local V1 = if Flag_V then 0 else T3_V

			local Hint = if R1 ~= V1 then 1 else 0
			buffer.writeu32(PolyC, JOffset, Hint)
		end
	end
end

function PolyVec.UseHint(PolyH: buffer, PolyR: buffer, PolyRZ: buffer, K: number, Alpha: number)
	local M = math.floor((Q - 1) / Alpha)
	local T0 = bit32.rshift(Alpha, 1)
	local T1 = Q - T0
	local T1_Q = Q - 1

	for I = 0, K - 1 do
		local Offset = I * N * 4

		for J = 0, N - 1 do
			local JOffset = Offset + J * 4
			local H = buffer.readu32(PolyH, JOffset)
			local R = buffer.readu32(PolyR, JOffset)

			local T2 = R + T0 - 1
			local T3 = math.floor(T2 / Alpha)
			local T4 = T3 * Alpha
			local R0 = if R >= T4 then R - T4 else R - T4 + Q
			local T5 = if R >= R0 then R - R0 else R - R0 + Q
			local Flag = (T5 == T1_Q)
			local R1 = if Flag then 0 else T3
			local R0_ = if Flag then (if R0 >= 1 then R0 - 1 else R0 - 1 + Q) else R0

			local Result
			if H == 1 then
				if R0_ > 0 and R0_ < T1 then
					if R1 == (M - 1) then
						Result = 0
					else
						Result = R1 + 1
					end
				elseif R0_ >= T1 then
					if R1 == 0 then
						Result = M - 1
					else
						Result = R1 - 1
					end
				else
					Result = R1
				end
			else
				Result = R1
			end

			buffer.writeu32(PolyRZ, JOffset, Result)
		end
	end
end

function PolyVec.Count1s(Vec: buffer, K: number): number
	local Count = 0

	for I = 0, K * N - 1 do
		local Value = buffer.readu32(Vec, I * 4)
		Count += Value
	end

	return Count
end

function PolyVec.LeftShift(Vec: buffer, K: number, D: number)
	for I = 0, K - 1 do
		local Offset = I * N * 4

		for J = 0, N - 1 do
			local JOffset = Offset + J * 4
			local PolyValue = buffer.readu32(Vec, JOffset)

			local Shifted = bit32.lshift(PolyValue, D)
			local Result = if Shifted >= Q then Shifted % Q else Shifted

			buffer.writeu32(Vec, JOffset, Result)
		end
	end
end

function PolyVec.Copy(Src: buffer, Dst: buffer, K: number)
	buffer.copy(Dst, 0, Src, 0, K * N * 4)
end

function PolyVec.Zero(Vec: buffer, K: number)
	buffer.fill(Vec, 0, 0, K * N * 4)
end

function PolyVec.Equal(VecA: buffer, VecB: buffer, K: number): boolean
	for I = 0, K * N - 1 do
		local AValue = buffer.readu32(VecA, I * 4)
		local BValue = buffer.readu32(VecB, I * 4)

		if AValue ~= BValue then
			return false
		end
	end

	return true
end

return PolyVec