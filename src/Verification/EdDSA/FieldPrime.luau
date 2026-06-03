--[=[
	Cryptography library: Field Prime (Curve25519 Base Field)

	Field elements are stored as 80-byte buffers holding 10 signed 64-bit
	integer limbs in radix 2^25.5 (alternating 26/25 bits). The encoded
	external form is the standard 32-byte little-endian Curve25519 value.

	Return type: varies by function
	Example usage:
		local FieldPrime = require("FieldPrime")

		--------Usage Case 1: Basic arithmetic--------
		local ElementA = FieldPrime.Num(42)
		local ElementB = FieldPrime.Num(17)
		local Sum = FieldPrime.Add(ElementA, ElementB)
		local Product = FieldPrime.Mul(ElementA, ElementB)

		--------Usage Case 2: Encoding/decoding--------
		local Encoded = FieldPrime.Encode(ElementA)
		local Decoded = FieldPrime.Decode(Encoded)
--]=]

--!strict
--!optimize 2
--!native

local SIZE = 80
local M26 = 0x3FFFFFFi
local M25 = 0x1FFFFFFi
local NINETEEN = 19i
local P0 = 0x3FFFFEDi

local FieldPrime = {}

local function ReadLimbs(Element: buffer): (integer, integer, integer, integer, integer, integer, integer, integer, integer, integer)
	return buffer.readinteger(Element, 0), buffer.readinteger(Element, 8),
		buffer.readinteger(Element, 16), buffer.readinteger(Element, 24),
		buffer.readinteger(Element, 32), buffer.readinteger(Element, 40),
		buffer.readinteger(Element, 48), buffer.readinteger(Element, 56),
		buffer.readinteger(Element, 64), buffer.readinteger(Element, 72)
end

local function WriteLimbs(Buf: buffer, L0: integer, L1: integer, L2: integer, L3: integer, L4: integer,
	L5: integer, L6: integer, L7: integer, L8: integer, L9: integer)
	buffer.writeinteger(Buf, 0, L0)
	buffer.writeinteger(Buf, 8, L1)
	buffer.writeinteger(Buf, 16, L2)
	buffer.writeinteger(Buf, 24, L3)
	buffer.writeinteger(Buf, 32, L4)
	buffer.writeinteger(Buf, 40, L5)
	buffer.writeinteger(Buf, 48, L6)
	buffer.writeinteger(Buf, 56, L7)
	buffer.writeinteger(Buf, 64, L8)
	buffer.writeinteger(Buf, 72, L9)
end

function FieldPrime.Num(Number: number): buffer
	local Buf = buffer.create(SIZE)
	local Value = integer.create(Number)
	if Value then
		buffer.writeinteger(Buf, 0, Value)
	end

	return Buf
end

function FieldPrime.Neg(ElementA: buffer): buffer
	local L0, L1, L2, L3, L4, L5, L6, L7, L8, L9 = ReadLimbs(ElementA)
	local Buf = buffer.create(SIZE)
	WriteLimbs(Buf,
		integer.neg(L0), integer.neg(L1), integer.neg(L2), integer.neg(L3), integer.neg(L4),
		integer.neg(L5), integer.neg(L6), integer.neg(L7), integer.neg(L8), integer.neg(L9))

	return Buf
end

function FieldPrime.Add(ElementA: buffer, ElementB: buffer, Storage: buffer?): buffer
	local A0, A1, A2, A3, A4, A5, A6, A7, A8, A9 = ReadLimbs(ElementA)
	local B0, B1, B2, B3, B4, B5, B6, B7, B8, B9 = ReadLimbs(ElementB)

	local Buf = Storage or buffer.create(SIZE)
	WriteLimbs(Buf,
		integer.add(A0, B0), integer.add(A1, B1), integer.add(A2, B2), integer.add(A3, B3), integer.add(A4, B4),
		integer.add(A5, B5), integer.add(A6, B6), integer.add(A7, B7), integer.add(A8, B8), integer.add(A9, B9))

	return Buf
end

function FieldPrime.Sub(ElementA: buffer, ElementB: buffer, Storage: buffer?): buffer
	local A0, A1, A2, A3, A4, A5, A6, A7, A8, A9 = ReadLimbs(ElementA)
	local B0, B1, B2, B3, B4, B5, B6, B7, B8, B9 = ReadLimbs(ElementB)

	local Buf = Storage or buffer.create(SIZE)
	WriteLimbs(Buf,
		integer.sub(A0, B0), integer.sub(A1, B1), integer.sub(A2, B2), integer.sub(A3, B3), integer.sub(A4, B4),
		integer.sub(A5, B5), integer.sub(A6, B6), integer.sub(A7, B7), integer.sub(A8, B8), integer.sub(A9, B9))

	return Buf
end

function FieldPrime.Carry(ElementA: buffer, Storage: buffer?): buffer
	local L0, L1, L2, L3, L4, L5, L6, L7, L8, L9 = ReadLimbs(ElementA)

	local C
	C = integer.arshift(L0, 26i); L1 = integer.add(L1, C); L0 = integer.band(L0, M26)
	C = integer.arshift(L1, 25i); L2 = integer.add(L2, C); L1 = integer.band(L1, M25)
	C = integer.arshift(L2, 26i); L3 = integer.add(L3, C); L2 = integer.band(L2, M26)
	C = integer.arshift(L3, 25i); L4 = integer.add(L4, C); L3 = integer.band(L3, M25)
	C = integer.arshift(L4, 26i); L5 = integer.add(L5, C); L4 = integer.band(L4, M26)
	C = integer.arshift(L5, 25i); L6 = integer.add(L6, C); L5 = integer.band(L5, M25)
	C = integer.arshift(L6, 26i); L7 = integer.add(L7, C); L6 = integer.band(L6, M26)
	C = integer.arshift(L7, 25i); L8 = integer.add(L8, C); L7 = integer.band(L7, M25)
	C = integer.arshift(L8, 26i); L9 = integer.add(L9, C); L8 = integer.band(L8, M26)
	C = integer.arshift(L9, 25i); L0 = integer.add(L0, integer.mul(C, NINETEEN)); L9 = integer.band(L9, M25)
	C = integer.arshift(L0, 26i); L1 = integer.add(L1, C); L0 = integer.band(L0, M26)

	local Buf = Storage or buffer.create(SIZE)
	WriteLimbs(Buf, L0, L1, L2, L3, L4, L5, L6, L7, L8, L9)

	return Buf
end

function FieldPrime.Canonicalize(ElementA: buffer, Storage: buffer?): buffer
	local L0, L1, L2, L3, L4, L5, L6, L7, L8, L9 = ReadLimbs(ElementA)

	local C
	C = integer.arshift(L0, 26i); L1 = integer.add(L1, C); L0 = integer.band(L0, M26)
	C = integer.arshift(L1, 25i); L2 = integer.add(L2, C); L1 = integer.band(L1, M25)
	C = integer.arshift(L2, 26i); L3 = integer.add(L3, C); L2 = integer.band(L2, M26)
	C = integer.arshift(L3, 25i); L4 = integer.add(L4, C); L3 = integer.band(L3, M25)
	C = integer.arshift(L4, 26i); L5 = integer.add(L5, C); L4 = integer.band(L4, M26)
	C = integer.arshift(L5, 25i); L6 = integer.add(L6, C); L5 = integer.band(L5, M25)
	C = integer.arshift(L6, 26i); L7 = integer.add(L7, C); L6 = integer.band(L6, M26)
	C = integer.arshift(L7, 25i); L8 = integer.add(L8, C); L7 = integer.band(L7, M25)
	C = integer.arshift(L8, 26i); L9 = integer.add(L9, C); L8 = integer.band(L8, M26)
	C = integer.arshift(L9, 25i); L0 = integer.add(L0, integer.mul(C, NINETEEN)); L9 = integer.band(L9, M25)
	C = integer.arshift(L0, 26i); L1 = integer.add(L1, C); L0 = integer.band(L0, M26)

	local Buf = Storage or buffer.create(SIZE)

	if L9 == M25 and L8 == M26 and L7 == M25 and L6 == M26 and L5 == M25
		and L4 == M26 and L3 == M25 and L2 == M26 and L1 == M25 and integer.ge(L0, P0) then
		WriteLimbs(Buf, integer.sub(L0, P0), 0i, 0i, 0i, 0i, 0i, 0i, 0i, 0i, 0i)
	else
		WriteLimbs(Buf, L0, L1, L2, L3, L4, L5, L6, L7, L8, L9)
	end

	return Buf
end

function FieldPrime.Eq(ElementA: buffer, ElementB: buffer): boolean
	local Difference = FieldPrime.Canonicalize(FieldPrime.Sub(ElementA, ElementB))
	local L0, L1, L2, L3, L4, L5, L6, L7, L8, L9 = ReadLimbs(Difference)

	return L0 == 0i and L1 == 0i and L2 == 0i and L3 == 0i and L4 == 0i
		and L5 == 0i and L6 == 0i and L7 == 0i and L8 == 0i and L9 == 0i
end

function FieldPrime.Eqz(ElementA: buffer): boolean
	local Canonical = FieldPrime.Canonicalize(ElementA)
	local L0, L1, L2, L3, L4, L5, L6, L7, L8, L9 = ReadLimbs(Canonical)

	return L0 == 0i and L1 == 0i and L2 == 0i and L3 == 0i and L4 == 0i
		and L5 == 0i and L6 == 0i and L7 == 0i and L8 == 0i and L9 == 0i
end

function FieldPrime.Mul(ElementA: buffer, ElementB: buffer, Storage: buffer?): buffer
	local A0, A1, A2, A3, A4, A5, A6, A7, A8, A9 = ReadLimbs(ElementA)
	local B0, B1, B2, B3, B4, B5, B6, B7, B8, B9 = ReadLimbs(ElementB)

	local B1_2 = integer.add(B1, B1)
	local B3_2 = integer.add(B3, B3)
	local B5_2 = integer.add(B5, B5)
	local B7_2 = integer.add(B7, B7)
	local B9_2 = integer.add(B9, B9)

	local B2_19 = integer.mul(B2, NINETEEN)
	local B3_19 = integer.mul(B3, NINETEEN)
	local B4_19 = integer.mul(B4, NINETEEN)
	local B5_19 = integer.mul(B5, NINETEEN)
	local B6_19 = integer.mul(B6, NINETEEN)
	local B7_19 = integer.mul(B7, NINETEEN)
	local B8_19 = integer.mul(B8, NINETEEN)
	local B9_19 = integer.mul(B9, NINETEEN)
	local B1_2_19 = integer.mul(B1_2, NINETEEN)
	local B3_2_19 = integer.mul(B3_2, NINETEEN)
	local B5_2_19 = integer.mul(B5_2, NINETEEN)
	local B7_2_19 = integer.mul(B7_2, NINETEEN)
	local B9_2_19 = integer.mul(B9_2, NINETEEN)

	local T0 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0, B0),
		integer.mul(A1, B9_2_19)),
		integer.mul(A2, B8_19)),
		integer.mul(A3, B7_2_19)),
		integer.mul(A4, B6_19)),
		integer.add(integer.add(integer.add(integer.add(
			integer.mul(A5, B5_2_19),
			integer.mul(A6, B4_19)),
			integer.mul(A7, B3_2_19)),
			integer.mul(A8, B2_19)),
			integer.mul(A9, B1_2_19)))

	local T1 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0, B1),
		integer.mul(A1, B0)),
		integer.mul(A2, B9_19)),
		integer.mul(A3, B8_19)),
		integer.mul(A4, B7_19)),
		integer.add(integer.add(integer.add(integer.add(
			integer.mul(A5, B6_19),
			integer.mul(A6, B5_19)),
			integer.mul(A7, B4_19)),
			integer.mul(A8, B3_19)),
			integer.mul(A9, B2_19)))

	local T2 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0, B2),
		integer.mul(A1, B1_2)),
		integer.mul(A2, B0)),
		integer.mul(A3, B9_2_19)),
		integer.mul(A4, B8_19)),
		integer.add(integer.add(integer.add(integer.add(
			integer.mul(A5, B7_2_19),
			integer.mul(A6, B6_19)),
			integer.mul(A7, B5_2_19)),
			integer.mul(A8, B4_19)),
			integer.mul(A9, B3_2_19)))

	local T3 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0, B3),
		integer.mul(A1, B2)),
		integer.mul(A2, B1)),
		integer.mul(A3, B0)),
		integer.mul(A4, B9_19)),
		integer.add(integer.add(integer.add(integer.add(
			integer.mul(A5, B8_19),
			integer.mul(A6, B7_19)),
			integer.mul(A7, B6_19)),
			integer.mul(A8, B5_19)),
			integer.mul(A9, B4_19)))

	local T4 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0, B4),
		integer.mul(A1, B3_2)),
		integer.mul(A2, B2)),
		integer.mul(A3, B1_2)),
		integer.mul(A4, B0)),
		integer.add(integer.add(integer.add(integer.add(
			integer.mul(A5, B9_2_19),
			integer.mul(A6, B8_19)),
			integer.mul(A7, B7_2_19)),
			integer.mul(A8, B6_19)),
			integer.mul(A9, B5_2_19)))

	local T5 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0, B5),
		integer.mul(A1, B4)),
		integer.mul(A2, B3)),
		integer.mul(A3, B2)),
		integer.mul(A4, B1)),
		integer.add(integer.add(integer.add(integer.add(
			integer.mul(A5, B0),
			integer.mul(A6, B9_19)),
			integer.mul(A7, B8_19)),
			integer.mul(A8, B7_19)),
			integer.mul(A9, B6_19)))

	local T6 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0, B6),
		integer.mul(A1, B5_2)),
		integer.mul(A2, B4)),
		integer.mul(A3, B3_2)),
		integer.mul(A4, B2)),
		integer.add(integer.add(integer.add(integer.add(
			integer.mul(A5, B1_2),
			integer.mul(A6, B0)),
			integer.mul(A7, B9_2_19)),
			integer.mul(A8, B8_19)),
			integer.mul(A9, B7_2_19)))

	local T7 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0, B7),
		integer.mul(A1, B6)),
		integer.mul(A2, B5)),
		integer.mul(A3, B4)),
		integer.mul(A4, B3)),
		integer.add(integer.add(integer.add(integer.add(
			integer.mul(A5, B2),
			integer.mul(A6, B1)),
			integer.mul(A7, B0)),
			integer.mul(A8, B9_19)),
			integer.mul(A9, B8_19)))

	local T8 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0, B8),
		integer.mul(A1, B7_2)),
		integer.mul(A2, B6)),
		integer.mul(A3, B5_2)),
		integer.mul(A4, B4)),
		integer.add(integer.add(integer.add(integer.add(
			integer.mul(A5, B3_2),
			integer.mul(A6, B2)),
			integer.mul(A7, B1_2)),
			integer.mul(A8, B0)),
			integer.mul(A9, B9_2_19)))

	local T9 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0, B9),
		integer.mul(A1, B8)),
		integer.mul(A2, B7)),
		integer.mul(A3, B6)),
		integer.mul(A4, B5)),
		integer.add(integer.add(integer.add(integer.add(
			integer.mul(A5, B4),
			integer.mul(A6, B3)),
			integer.mul(A7, B2)),
			integer.mul(A8, B1)),
			integer.mul(A9, B0)))

	local C
	C = integer.arshift(T0, 26i); T1 = integer.add(T1, C); T0 = integer.band(T0, M26)
	C = integer.arshift(T1, 25i); T2 = integer.add(T2, C); T1 = integer.band(T1, M25)
	C = integer.arshift(T2, 26i); T3 = integer.add(T3, C); T2 = integer.band(T2, M26)
	C = integer.arshift(T3, 25i); T4 = integer.add(T4, C); T3 = integer.band(T3, M25)
	C = integer.arshift(T4, 26i); T5 = integer.add(T5, C); T4 = integer.band(T4, M26)
	C = integer.arshift(T5, 25i); T6 = integer.add(T6, C); T5 = integer.band(T5, M25)
	C = integer.arshift(T6, 26i); T7 = integer.add(T7, C); T6 = integer.band(T6, M26)
	C = integer.arshift(T7, 25i); T8 = integer.add(T8, C); T7 = integer.band(T7, M25)
	C = integer.arshift(T8, 26i); T9 = integer.add(T9, C); T8 = integer.band(T8, M26)
	C = integer.arshift(T9, 25i); T0 = integer.add(T0, integer.mul(C, NINETEEN)); T9 = integer.band(T9, M25)
	C = integer.arshift(T0, 26i); T1 = integer.add(T1, C); T0 = integer.band(T0, M26)

	local Buf = Storage or buffer.create(SIZE)
	WriteLimbs(Buf, T0, T1, T2, T3, T4, T5, T6, T7, T8, T9)

	return Buf
end

function FieldPrime.Square(ElementA: buffer, Storage: buffer?): buffer
	local A0, A1, A2, A3, A4, A5, A6, A7, A8, A9 = ReadLimbs(ElementA)

	local A0_2 = integer.add(A0, A0)
	local A1_2 = integer.add(A1, A1)
	local A2_2 = integer.add(A2, A2)
	local A3_2 = integer.add(A3, A3)
	local A4_2 = integer.add(A4, A4)
	local A5_2 = integer.add(A5, A5)
	local A6_2 = integer.add(A6, A6)
	local A7_2 = integer.add(A7, A7)

	local A5_19 = integer.mul(A5, NINETEEN)
	local A6_19 = integer.mul(A6, NINETEEN)
	local A7_19 = integer.mul(A7, NINETEEN)
	local A8_19 = integer.mul(A8, NINETEEN)
	local A9_19 = integer.mul(A9, NINETEEN)

	local A6_38 = integer.add(A6_19, A6_19)
	local A7_38 = integer.add(A7_19, A7_19)
	local A8_38 = integer.add(A8_19, A8_19)
	local A9_38 = integer.add(A9_19, A9_19)

	local T0 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0, A0),
		integer.mul(A1_2, A9_38)),
		integer.mul(A2_2, A8_19)),
		integer.mul(A3_2, A7_38)),
		integer.mul(A4_2, A6_19)),
		integer.mul(A5_2, A5_19))

	local T1 = integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A1),
		integer.mul(A2, A9_38)),
		integer.mul(A3, A8_38)),
		integer.mul(A4, A7_38)),
		integer.mul(A5, A6_38))

	local T2 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A2),
		integer.mul(A1_2, A1)),
		integer.mul(A3_2, A9_38)),
		integer.mul(A4_2, A8_19)),
		integer.mul(A5_2, A7_38)),
		integer.mul(A6, A6_19))

	local T3 = integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A3),
		integer.mul(A1_2, A2)),
		integer.mul(A4, A9_38)),
		integer.mul(A5, A8_38)),
		integer.mul(A6, A7_38))

	local T4 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A4),
		integer.mul(A1_2, A3_2)),
		integer.mul(A2, A2)),
		integer.mul(A5_2, A9_38)),
		integer.mul(A6_2, A8_19)),
		integer.mul(A7, A7_38))

	local T5 = integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A5),
		integer.mul(A1_2, A4)),
		integer.mul(A2_2, A3)),
		integer.mul(A6, A9_38)),
		integer.mul(A7, A8_38))

	local T6 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A6),
		integer.mul(A1_2, A5_2)),
		integer.mul(A2_2, A4)),
		integer.mul(A3_2, A3)),
		integer.mul(A7_2, A9_38)),
		integer.mul(A8, A8_19))

	local T7 = integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A7),
		integer.mul(A1_2, A6)),
		integer.mul(A2_2, A5)),
		integer.mul(A3_2, A4)),
		integer.mul(A8, A9_38))

	local T8 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A8),
		integer.mul(A1_2, A7_2)),
		integer.mul(A2_2, A6)),
		integer.mul(A3_2, A5_2)),
		integer.mul(A4, A4)),
		integer.mul(A9, A9_38))

	local T9 = integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A9),
		integer.mul(A1_2, A8)),
		integer.mul(A2_2, A7)),
		integer.mul(A3_2, A6)),
		integer.mul(A4_2, A5))

	local C
	C = integer.arshift(T0, 26i); T1 = integer.add(T1, C); T0 = integer.band(T0, M26)
	C = integer.arshift(T1, 25i); T2 = integer.add(T2, C); T1 = integer.band(T1, M25)
	C = integer.arshift(T2, 26i); T3 = integer.add(T3, C); T2 = integer.band(T2, M26)
	C = integer.arshift(T3, 25i); T4 = integer.add(T4, C); T3 = integer.band(T3, M25)
	C = integer.arshift(T4, 26i); T5 = integer.add(T5, C); T4 = integer.band(T4, M26)
	C = integer.arshift(T5, 25i); T6 = integer.add(T6, C); T5 = integer.band(T5, M25)
	C = integer.arshift(T6, 26i); T7 = integer.add(T7, C); T6 = integer.band(T6, M26)
	C = integer.arshift(T7, 25i); T8 = integer.add(T8, C); T7 = integer.band(T7, M25)
	C = integer.arshift(T8, 26i); T9 = integer.add(T9, C); T8 = integer.band(T8, M26)
	C = integer.arshift(T9, 25i); T0 = integer.add(T0, integer.mul(C, NINETEEN)); T9 = integer.band(T9, M25)
	C = integer.arshift(T0, 26i); T1 = integer.add(T1, C); T0 = integer.band(T0, M26)

	local Buf = Storage or buffer.create(SIZE)
	WriteLimbs(Buf, T0, T1, T2, T3, T4, T5, T6, T7, T8, T9)

	return Buf
end

function FieldPrime.KMul(ElementA: buffer, SmallK: number, Storage: buffer?): buffer
	local L0, L1, L2, L3, L4, L5, L6, L7, L8, L9 = ReadLimbs(ElementA)
	local K = integer.create(SmallK) :: integer

	L0 = integer.mul(L0, K); L1 = integer.mul(L1, K); L2 = integer.mul(L2, K); L3 = integer.mul(L3, K); L4 = integer.mul(L4, K)
	L5 = integer.mul(L5, K); L6 = integer.mul(L6, K); L7 = integer.mul(L7, K); L8 = integer.mul(L8, K); L9 = integer.mul(L9, K)

	local C
	C = integer.arshift(L0, 26i); L1 = integer.add(L1, C); L0 = integer.band(L0, M26)
	C = integer.arshift(L1, 25i); L2 = integer.add(L2, C); L1 = integer.band(L1, M25)
	C = integer.arshift(L2, 26i); L3 = integer.add(L3, C); L2 = integer.band(L2, M26)
	C = integer.arshift(L3, 25i); L4 = integer.add(L4, C); L3 = integer.band(L3, M25)
	C = integer.arshift(L4, 26i); L5 = integer.add(L5, C); L4 = integer.band(L4, M26)
	C = integer.arshift(L5, 25i); L6 = integer.add(L6, C); L5 = integer.band(L5, M25)
	C = integer.arshift(L6, 26i); L7 = integer.add(L7, C); L6 = integer.band(L6, M26)
	C = integer.arshift(L7, 25i); L8 = integer.add(L8, C); L7 = integer.band(L7, M25)
	C = integer.arshift(L8, 26i); L9 = integer.add(L9, C); L8 = integer.band(L8, M26)
	C = integer.arshift(L9, 25i); L0 = integer.add(L0, integer.mul(C, NINETEEN)); L9 = integer.band(L9, M25)
	C = integer.arshift(L0, 26i); L1 = integer.add(L1, C); L0 = integer.band(L0, M26)

	local Buf = Storage or buffer.create(SIZE)
	WriteLimbs(Buf, L0, L1, L2, L3, L4, L5, L6, L7, L8, L9)

	return Buf
end

function FieldPrime.NSquare(ElementA: buffer, SquareCount: number, StoreInBuffer: boolean?): buffer
	local A0, A1, A2, A3, A4, A5, A6, A7, A8, A9 = ReadLimbs(ElementA)

	for _ = 1, SquareCount do
	local A0_2 = integer.add(A0, A0)
	local A1_2 = integer.add(A1, A1)
	local A2_2 = integer.add(A2, A2)
	local A3_2 = integer.add(A3, A3)
	local A4_2 = integer.add(A4, A4)
	local A5_2 = integer.add(A5, A5)
	local A6_2 = integer.add(A6, A6)
	local A7_2 = integer.add(A7, A7)

	local A5_19 = integer.mul(A5, NINETEEN)
	local A6_19 = integer.mul(A6, NINETEEN)
	local A7_19 = integer.mul(A7, NINETEEN)
	local A8_19 = integer.mul(A8, NINETEEN)
	local A9_19 = integer.mul(A9, NINETEEN)

	local A6_38 = integer.add(A6_19, A6_19)
	local A7_38 = integer.add(A7_19, A7_19)
	local A8_38 = integer.add(A8_19, A8_19)
	local A9_38 = integer.add(A9_19, A9_19)

	local T0 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0, A0),
		integer.mul(A1_2, A9_38)),
		integer.mul(A2_2, A8_19)),
		integer.mul(A3_2, A7_38)),
		integer.mul(A4_2, A6_19)),
		integer.mul(A5_2, A5_19))

	local T1 = integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A1),
		integer.mul(A2, A9_38)),
		integer.mul(A3, A8_38)),
		integer.mul(A4, A7_38)),
		integer.mul(A5, A6_38))

	local T2 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A2),
		integer.mul(A1_2, A1)),
		integer.mul(A3_2, A9_38)),
		integer.mul(A4_2, A8_19)),
		integer.mul(A5_2, A7_38)),
		integer.mul(A6, A6_19))

	local T3 = integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A3),
		integer.mul(A1_2, A2)),
		integer.mul(A4, A9_38)),
		integer.mul(A5, A8_38)),
		integer.mul(A6, A7_38))

	local T4 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A4),
		integer.mul(A1_2, A3_2)),
		integer.mul(A2, A2)),
		integer.mul(A5_2, A9_38)),
		integer.mul(A6_2, A8_19)),
		integer.mul(A7, A7_38))

	local T5 = integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A5),
		integer.mul(A1_2, A4)),
		integer.mul(A2_2, A3)),
		integer.mul(A6, A9_38)),
		integer.mul(A7, A8_38))

	local T6 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A6),
		integer.mul(A1_2, A5_2)),
		integer.mul(A2_2, A4)),
		integer.mul(A3_2, A3)),
		integer.mul(A7_2, A9_38)),
		integer.mul(A8, A8_19))

	local T7 = integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A7),
		integer.mul(A1_2, A6)),
		integer.mul(A2_2, A5)),
		integer.mul(A3_2, A4)),
		integer.mul(A8, A9_38))

	local T8 = integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A8),
		integer.mul(A1_2, A7_2)),
		integer.mul(A2_2, A6)),
		integer.mul(A3_2, A5_2)),
		integer.mul(A4, A4)),
		integer.mul(A9, A9_38))

	local T9 = integer.add(integer.add(integer.add(integer.add(
		integer.mul(A0_2, A9),
		integer.mul(A1_2, A8)),
		integer.mul(A2_2, A7)),
		integer.mul(A3_2, A6)),
		integer.mul(A4_2, A5))

	local C
	C = integer.arshift(T0, 26i); T1 = integer.add(T1, C); T0 = integer.band(T0, M26)
	C = integer.arshift(T1, 25i); T2 = integer.add(T2, C); T1 = integer.band(T1, M25)
	C = integer.arshift(T2, 26i); T3 = integer.add(T3, C); T2 = integer.band(T2, M26)
	C = integer.arshift(T3, 25i); T4 = integer.add(T4, C); T3 = integer.band(T3, M25)
	C = integer.arshift(T4, 26i); T5 = integer.add(T5, C); T4 = integer.band(T4, M26)
	C = integer.arshift(T5, 25i); T6 = integer.add(T6, C); T5 = integer.band(T5, M25)
	C = integer.arshift(T6, 26i); T7 = integer.add(T7, C); T6 = integer.band(T6, M26)
	C = integer.arshift(T7, 25i); T8 = integer.add(T8, C); T7 = integer.band(T7, M25)
	C = integer.arshift(T8, 26i); T9 = integer.add(T9, C); T8 = integer.band(T8, M26)
	C = integer.arshift(T9, 25i); T0 = integer.add(T0, integer.mul(C, NINETEEN)); T9 = integer.band(T9, M25)
	C = integer.arshift(T0, 26i); T1 = integer.add(T1, C); T0 = integer.band(T0, M26)

		A0, A1, A2, A3, A4, A5, A6, A7, A8, A9 = T0, T1, T2, T3, T4, T5, T6, T7, T8, T9
	end

	local Buf = StoreInBuffer and ElementA or buffer.create(SIZE)
	WriteLimbs(Buf, A0, A1, A2, A3, A4, A5, A6, A7, A8, A9)

	return Buf
end

function FieldPrime.Invert(ElementA: buffer, Storage: buffer?): buffer
	local Mul = FieldPrime.Mul

	local A2 = FieldPrime.Square(ElementA)
	local A9 = Mul(ElementA, FieldPrime.NSquare(A2, 2))
	local A11 = Mul(A9, A2)

	local X5 = Mul(FieldPrime.Square(A11), A9)
	local X10 = Mul(FieldPrime.NSquare(X5, 5), X5)
	local X20 = Mul(FieldPrime.NSquare(X10, 10), X10)
	local X40 = Mul(FieldPrime.NSquare(X20, 20), X20)
	local X50 = Mul(FieldPrime.NSquare(X40, 10), X10)
	local X100 = Mul(FieldPrime.NSquare(X50, 50), X50)
	local X200 = Mul(FieldPrime.NSquare(X100, 100), X100)
	local X250 = Mul(FieldPrime.NSquare(X200, 50), X50)

	return Mul(FieldPrime.NSquare(X250, 5), A11, Storage)
end

local SQRT_M1: buffer

function FieldPrime.SqrtDiv(ElementU: buffer, ElementV: buffer): buffer?
	local Mul = FieldPrime.Mul
	local Square = FieldPrime.Square
	local Carry = FieldPrime.Carry

	Carry(ElementU, ElementU)

	local V2 = Square(ElementV)
	local V3 = Mul(ElementV, V2)
	local UV3 = Mul(ElementU, V3)
	local V4 = Square(V2)
	local UV7 = Mul(UV3, V4)

	local X2 = Mul(Square(UV7), UV7)
	local X4 = Mul(FieldPrime.NSquare(X2, 2), X2)
	local X8 = Mul(FieldPrime.NSquare(X4, 4), X4)
	local X16 = Mul(FieldPrime.NSquare(X8, 8), X8)
	local X18 = Mul(FieldPrime.NSquare(X16, 2), X2)
	local X32 = Mul(FieldPrime.NSquare(X16, 16), X16)
	local X50 = Mul(FieldPrime.NSquare(X32, 18), X18)
	local X100 = Mul(FieldPrime.NSquare(X50, 50), X50)
	local X200 = Mul(FieldPrime.NSquare(X100, 100), X100)
	local X250 = Mul(FieldPrime.NSquare(X200, 50), X50)
	local PowerResult = Mul(FieldPrime.NSquare(X250, 2), UV7)

	local CandidateB = Mul(UV3, PowerResult)
	local B2 = Square(CandidateB)
	local VB2 = Mul(ElementV, B2)

	if not FieldPrime.Eq(VB2, ElementU) then
		CandidateB = Mul(CandidateB, SQRT_M1)
		B2 = Square(CandidateB)
		VB2 = Mul(ElementV, B2)
	end

	if FieldPrime.Eq(VB2, ElementU) then
		return CandidateB
	else
		return nil
	end
end

function FieldPrime.Encode(ElementA: buffer): buffer
	local Canonical = FieldPrime.Canonicalize(ElementA)
	local L0, L1, L2, L3, L4, L5, L6, L7, L8, L9 = ReadLimbs(Canonical)

	local W0 = integer.bor(integer.bor(L0, integer.lshift(L1, 26i)), integer.lshift(L2, 51i))
	local W1 = integer.bor(integer.bor(integer.rshift(L2, 13i), integer.lshift(L3, 13i)), integer.lshift(L4, 38i))
	local W2 = integer.bor(integer.bor(L5, integer.lshift(L6, 25i)), integer.lshift(L7, 51i))
	local W3 = integer.bor(integer.bor(integer.rshift(L7, 13i), integer.lshift(L8, 12i)), integer.lshift(L9, 38i))

	local Buf = buffer.create(32)
	buffer.writeinteger(Buf, 0, W0)
	buffer.writeinteger(Buf, 8, W1)
	buffer.writeinteger(Buf, 16, W2)
	buffer.writeinteger(Buf, 24, W3)

	return Buf
end

function FieldPrime.Decode(EncodedBytes: buffer): buffer
	local W0 = buffer.readinteger(EncodedBytes, 0)
	local W1 = buffer.readinteger(EncodedBytes, 8)
	local W2 = buffer.readinteger(EncodedBytes, 16)
	local W3 = buffer.readinteger(EncodedBytes, 24)

	local L0 = integer.band(W0, M26)
	local L1 = integer.band(integer.rshift(W0, 26i), M25)
	local L2 = integer.band(integer.bor(integer.rshift(W0, 51i), integer.lshift(W1, 13i)), M26)
	local L3 = integer.band(integer.rshift(W1, 13i), M25)
	local L4 = integer.band(integer.rshift(W1, 38i), M26)
	local L5 = integer.band(W2, M25)
	local L6 = integer.band(integer.rshift(W2, 25i), M26)
	local L7 = integer.band(integer.bor(integer.rshift(W2, 51i), integer.lshift(W3, 13i)), M25)
	local L8 = integer.band(integer.rshift(W3, 12i), M26)
	local L9 = integer.band(integer.rshift(W3, 38i), M25)

	local Buf = buffer.create(SIZE)
	WriteLimbs(Buf, L0, L1, L2, L3, L4, L5, L6, L7, L8, L9)

	return Buf
end

SQRT_M1 = FieldPrime.Decode(buffer.fromstring(
	"\xB0\xA0\x0E\x4A\x27\x1B\xEE\xC4" ..
	"\x78\xE4\x2F\xAD\x06\x18\x43\x2F" ..
	"\xA7\xD7\xFB\x3D\x99\x00\x4D\x2B" ..
	"\x0B\xDF\xC1\x4F\x80\x24\x83\x2B"
))

return FieldPrime
