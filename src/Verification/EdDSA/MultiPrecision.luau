--[=[
	Cryptography library: Multi-Precision Arithmetic (264-bit integers)

	Numbers are stored as 96-byte buffers holding 11 signed 64-bit integer
	limbs in radix 2^24, plus an overflow slot at offset 88 used by Carry.

	Return type: varies by function
	Example usage:
		local MultiPrecision = require("MultiPrecision")

		--------Usage Case 1: Basic arithmetic--------
		local NumberA = MultiPrecision.Num(42)
		local NumberB = MultiPrecision.Num(17)
		local Sum = MultiPrecision.Add(NumberA, NumberB)
		local Product = MultiPrecision.Mul(NumberA, NumberB)

		--------Usage Case 2: Carry operations--------
		local LargeSum = MultiPrecision.Add(Sum, Product)
		local Normalized = MultiPrecision.Carry(LargeSum)
--]=]

--!strict
--!optimize 2
--!native

local CARRY = 88
local SIZE = 96
local M24 = 0xFFFFFFi

local MultiPrecision = {}

local function ReadLimbs(Number: buffer): (integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer)
	return buffer.readinteger(Number, 0), buffer.readinteger(Number, 8),
		buffer.readinteger(Number, 16), buffer.readinteger(Number, 24),
		buffer.readinteger(Number, 32), buffer.readinteger(Number, 40),
		buffer.readinteger(Number, 48), buffer.readinteger(Number, 56),
		buffer.readinteger(Number, 64), buffer.readinteger(Number, 72),
		buffer.readinteger(Number, 80)
end

local function WriteLimbs(Buf: buffer, L00: integer, L01: integer, L02: integer, L03: integer,
	L04: integer, L05: integer, L06: integer, L07: integer, L08: integer, L09: integer, L10: integer)
	buffer.writeinteger(Buf, 0, L00)
	buffer.writeinteger(Buf, 8, L01)
	buffer.writeinteger(Buf, 16, L02)
	buffer.writeinteger(Buf, 24, L03)
	buffer.writeinteger(Buf, 32, L04)
	buffer.writeinteger(Buf, 40, L05)
	buffer.writeinteger(Buf, 48, L06)
	buffer.writeinteger(Buf, 56, L07)
	buffer.writeinteger(Buf, 64, L08)
	buffer.writeinteger(Buf, 72, L09)
	buffer.writeinteger(Buf, 80, L10)
end

function MultiPrecision.Carry(LargeNumber: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = ReadLimbs(LargeNumber)

	local Low00 = integer.band(A00, M24); A01 = integer.add(A01, integer.arshift(A00, 24i))
	local Low01 = integer.band(A01, M24); A02 = integer.add(A02, integer.arshift(A01, 24i))
	local Low02 = integer.band(A02, M24); A03 = integer.add(A03, integer.arshift(A02, 24i))
	local Low03 = integer.band(A03, M24); A04 = integer.add(A04, integer.arshift(A03, 24i))
	local Low04 = integer.band(A04, M24); A05 = integer.add(A05, integer.arshift(A04, 24i))
	local Low05 = integer.band(A05, M24); A06 = integer.add(A06, integer.arshift(A05, 24i))
	local Low06 = integer.band(A06, M24); A07 = integer.add(A07, integer.arshift(A06, 24i))
	local Low07 = integer.band(A07, M24); A08 = integer.add(A08, integer.arshift(A07, 24i))
	local Low08 = integer.band(A08, M24); A09 = integer.add(A09, integer.arshift(A08, 24i))
	local Low09 = integer.band(A09, M24); A10 = integer.add(A10, integer.arshift(A09, 24i))
	local Low10 = integer.band(A10, M24)
	local Overflow = integer.arshift(A10, 24i)

	local Buf = Storage or buffer.create(SIZE)
	WriteLimbs(Buf, Low00, Low01, Low02, Low03, Low04, Low05, Low06, Low07, Low08, Low09, Low10)
	buffer.writeinteger(Buf, CARRY, Overflow)

	return Buf
end

function MultiPrecision.CarryWeak(LargeNumber: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = ReadLimbs(LargeNumber)

	local Half = 0x800000i

	local Hi00 = integer.arshift(integer.add(A00, Half), 24i); A01 = integer.add(A01, Hi00)
	local Hi01 = integer.arshift(integer.add(A01, Half), 24i); A02 = integer.add(A02, Hi01)
	local Hi02 = integer.arshift(integer.add(A02, Half), 24i); A03 = integer.add(A03, Hi02)
	local Hi03 = integer.arshift(integer.add(A03, Half), 24i); A04 = integer.add(A04, Hi03)
	local Hi04 = integer.arshift(integer.add(A04, Half), 24i); A05 = integer.add(A05, Hi04)
	local Hi05 = integer.arshift(integer.add(A05, Half), 24i); A06 = integer.add(A06, Hi05)
	local Hi06 = integer.arshift(integer.add(A06, Half), 24i); A07 = integer.add(A07, Hi06)
	local Hi07 = integer.arshift(integer.add(A07, Half), 24i); A08 = integer.add(A08, Hi07)
	local Hi08 = integer.arshift(integer.add(A08, Half), 24i); A09 = integer.add(A09, Hi08)
	local Hi09 = integer.arshift(integer.add(A09, Half), 24i); A10 = integer.add(A10, Hi09)
	local Hi10 = integer.arshift(integer.add(A10, Half), 24i)

	local Buf = Storage or buffer.create(SIZE)
	WriteLimbs(Buf,
		integer.sub(A00, integer.lshift(Hi00, 24i)),
		integer.sub(A01, integer.lshift(Hi01, 24i)),
		integer.sub(A02, integer.lshift(Hi02, 24i)),
		integer.sub(A03, integer.lshift(Hi03, 24i)),
		integer.sub(A04, integer.lshift(Hi04, 24i)),
		integer.sub(A05, integer.lshift(Hi05, 24i)),
		integer.sub(A06, integer.lshift(Hi06, 24i)),
		integer.sub(A07, integer.lshift(Hi07, 24i)),
		integer.sub(A08, integer.lshift(Hi08, 24i)),
		integer.sub(A09, integer.lshift(Hi09, 24i)),
		integer.sub(A10, integer.lshift(Hi10, 24i)))
	buffer.writeinteger(Buf, CARRY, Hi10)

	return Buf
end

function MultiPrecision.Add(NumberA: buffer, NumberB: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = ReadLimbs(NumberA)
	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 = ReadLimbs(NumberB)

	local Buf = Storage or buffer.create(SIZE)
	WriteLimbs(Buf,
		integer.add(A00, B00), integer.add(A01, B01), integer.add(A02, B02),
		integer.add(A03, B03), integer.add(A04, B04), integer.add(A05, B05),
		integer.add(A06, B06), integer.add(A07, B07), integer.add(A08, B08),
		integer.add(A09, B09), integer.add(A10, B10))

	return Buf
end

function MultiPrecision.Sub(NumberA: buffer, NumberB: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = ReadLimbs(NumberA)
	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 = ReadLimbs(NumberB)

	local Buf = Storage or buffer.create(SIZE)
	WriteLimbs(Buf,
		integer.sub(A00, B00), integer.sub(A01, B01), integer.sub(A02, B02),
		integer.sub(A03, B03), integer.sub(A04, B04), integer.sub(A05, B05),
		integer.sub(A06, B06), integer.sub(A07, B07), integer.sub(A08, B08),
		integer.sub(A09, B09), integer.sub(A10, B10))

	return Buf
end

function MultiPrecision.LMul(NumberA: buffer, NumberB: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = ReadLimbs(NumberA)
	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 = ReadLimbs(NumberB)

	local Buf = Storage or buffer.create(SIZE)

	buffer.writeinteger(Buf, 0, integer.mul(A00, B00))
	buffer.writeinteger(Buf, 8, integer.add(integer.mul(A01, B00), integer.mul(A00, B01)))
	buffer.writeinteger(Buf, 16, integer.add(integer.add(integer.mul(A02, B00), integer.mul(A01, B01)), integer.mul(A00, B02)))
	buffer.writeinteger(Buf, 24, integer.add(integer.add(integer.add(integer.mul(A03, B00), integer.mul(A02, B01)), integer.mul(A01, B02)), integer.mul(A00, B03)))
	buffer.writeinteger(Buf, 32, integer.add(integer.add(integer.add(integer.add(integer.mul(A04, B00), integer.mul(A03, B01)), integer.mul(A02, B02)), integer.mul(A01, B03)), integer.mul(A00, B04)))
	buffer.writeinteger(Buf, 40, integer.add(integer.add(integer.add(integer.add(integer.add(integer.mul(A05, B00), integer.mul(A04, B01)), integer.mul(A03, B02)), integer.mul(A02, B03)), integer.mul(A01, B04)), integer.mul(A00, B05)))
	buffer.writeinteger(Buf, 48, integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.mul(A06, B00), integer.mul(A05, B01)), integer.mul(A04, B02)), integer.mul(A03, B03)), integer.mul(A02, B04)), integer.mul(A01, B05)), integer.mul(A00, B06)))
	buffer.writeinteger(Buf, 56, integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.mul(A07, B00), integer.mul(A06, B01)), integer.mul(A05, B02)), integer.mul(A04, B03)), integer.mul(A03, B04)), integer.mul(A02, B05)), integer.mul(A01, B06)), integer.mul(A00, B07)))
	buffer.writeinteger(Buf, 64, integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.mul(A08, B00), integer.mul(A07, B01)), integer.mul(A06, B02)), integer.mul(A05, B03)), integer.mul(A04, B04)), integer.mul(A03, B05)), integer.mul(A02, B06)), integer.mul(A01, B07)), integer.mul(A00, B08)))
	buffer.writeinteger(Buf, 72, integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.mul(A09, B00), integer.mul(A08, B01)), integer.mul(A07, B02)), integer.mul(A06, B03)), integer.mul(A05, B04)), integer.mul(A04, B05)), integer.mul(A03, B06)), integer.mul(A02, B07)), integer.mul(A01, B08)), integer.mul(A00, B09)))
	buffer.writeinteger(Buf, 80, integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.mul(A10, B00), integer.mul(A09, B01)), integer.mul(A08, B02)), integer.mul(A07, B03)), integer.mul(A06, B04)), integer.mul(A05, B05)), integer.mul(A04, B06)), integer.mul(A03, B07)), integer.mul(A02, B08)), integer.mul(A01, B09)), integer.mul(A00, B10)))

	return MultiPrecision.Carry(Buf, Buf)
end

function MultiPrecision.Mul(NumberA: buffer, NumberB: buffer, LowStorage: buffer?, HighStorage: buffer?): (buffer, buffer)
	local LowResult = MultiPrecision.LMul(NumberA, NumberB, LowStorage)
	local Overflow = buffer.readinteger(LowResult, CARRY)

	local _, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = ReadLimbs(NumberA)
	local _, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 = ReadLimbs(NumberB)

	local Buf = HighStorage or buffer.create(SIZE)

	buffer.writeinteger(Buf, 0, integer.add(Overflow, integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A10, B01), integer.mul(A09, B02)), integer.mul(A08, B03)), integer.mul(A07, B04)),
		integer.mul(A06, B05)), integer.mul(A05, B06)), integer.mul(A04, B07)), integer.mul(A03, B08)),
		integer.mul(A02, B09)), integer.mul(A01, B10))))
	buffer.writeinteger(Buf, 8, integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A10, B02), integer.mul(A09, B03)), integer.mul(A08, B04)), integer.mul(A07, B05)),
		integer.mul(A06, B06)), integer.mul(A05, B07)), integer.mul(A04, B08)), integer.mul(A03, B09)),
		integer.mul(A02, B10)))
	buffer.writeinteger(Buf, 16, integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A10, B03), integer.mul(A09, B04)), integer.mul(A08, B05)), integer.mul(A07, B06)),
		integer.mul(A06, B07)), integer.mul(A05, B08)), integer.mul(A04, B09)), integer.mul(A03, B10)))
	buffer.writeinteger(Buf, 24, integer.add(integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A10, B04), integer.mul(A09, B05)), integer.mul(A08, B06)), integer.mul(A07, B07)),
		integer.mul(A06, B08)), integer.mul(A05, B09)), integer.mul(A04, B10)))
	buffer.writeinteger(Buf, 32, integer.add(integer.add(integer.add(integer.add(integer.add(
		integer.mul(A10, B05), integer.mul(A09, B06)), integer.mul(A08, B07)), integer.mul(A07, B08)),
		integer.mul(A06, B09)), integer.mul(A05, B10)))
	buffer.writeinteger(Buf, 40, integer.add(integer.add(integer.add(integer.add(
		integer.mul(A10, B06), integer.mul(A09, B07)), integer.mul(A08, B08)), integer.mul(A07, B09)),
		integer.mul(A06, B10)))
	buffer.writeinteger(Buf, 48, integer.add(integer.add(integer.add(
		integer.mul(A10, B07), integer.mul(A09, B08)), integer.mul(A08, B09)), integer.mul(A07, B10)))
	buffer.writeinteger(Buf, 56, integer.add(integer.add(
		integer.mul(A10, B08), integer.mul(A09, B09)), integer.mul(A08, B10)))
	buffer.writeinteger(Buf, 64, integer.add(integer.mul(A10, B09), integer.mul(A09, B10)))
	buffer.writeinteger(Buf, 72, integer.mul(A10, B10))
	buffer.writeinteger(Buf, 80, 0i)

	return LowResult, MultiPrecision.Carry(Buf, Buf)
end

function MultiPrecision.DWAdd(NumberA0: buffer, NumberA1: buffer, NumberB0: buffer, NumberB1: buffer, LowStorage: buffer?, HighStorage: buffer?): (buffer, buffer, integer)
	local LowSum = MultiPrecision.Carry(MultiPrecision.Add(NumberA0, NumberB0, LowStorage), LowStorage)
	local CarryOut = buffer.readinteger(LowSum, CARRY)

	local HighSum = MultiPrecision.Add(NumberA1, NumberB1, HighStorage)
	buffer.writeinteger(HighSum, 0, integer.add(buffer.readinteger(HighSum, 0), CarryOut))
	local Carried = MultiPrecision.Carry(HighSum, HighSum)

	return LowSum, Carried, buffer.readinteger(Carried, CARRY)
end

function MultiPrecision.Half(NumberA: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = ReadLimbs(NumberA)

	local Buf = Storage or buffer.create(SIZE)
	WriteLimbs(Buf,
		integer.add(integer.arshift(A00, 1i), integer.lshift(A01, 23i)),
		integer.lshift(A02, 23i),
		integer.lshift(A03, 23i),
		integer.lshift(A04, 23i),
		integer.lshift(A05, 23i),
		integer.lshift(A06, 23i),
		integer.lshift(A07, 23i),
		integer.lshift(A08, 23i),
		integer.lshift(A09, 23i),
		integer.lshift(A10, 23i),
		0i)

	return MultiPrecision.CarryWeak(Buf, Buf)
end

function MultiPrecision.Approx(NumberA: buffer): number
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 = ReadLimbs(NumberA)
	return integer.tonumber(A00)
		+ integer.tonumber(A01) * 2 ^ 24
		+ integer.tonumber(A02) * 2 ^ 48
		+ integer.tonumber(A03) * 2 ^ 72
		+ integer.tonumber(A04) * 2 ^ 96
		+ integer.tonumber(A05) * 2 ^ 120
		+ integer.tonumber(A06) * 2 ^ 144
		+ integer.tonumber(A07) * 2 ^ 168
		+ integer.tonumber(A08) * 2 ^ 192
		+ integer.tonumber(A09) * 2 ^ 216
		+ integer.tonumber(A10) * 2 ^ 240
end

function MultiPrecision.Num(RegularNumber: number): buffer
	local Buf = buffer.create(SIZE)
	local Value = integer.create(RegularNumber)
	if Value then
		buffer.writeinteger(Buf, 0, Value)
	end

	return Buf
end

return MultiPrecision
