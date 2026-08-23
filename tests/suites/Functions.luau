--!strict
--!optimize 2
--!native

local Testing = require("../")
local Functions = require("../../src/Utilities/Functions")

local Describe = Testing.Describe
local Test = Testing.Test
local Expect = Testing.Expect

local MASK_ALL = 0xFFFFFFFF
local MASK_NONE = 0x00000000

local EDGE_VALUES = { 0, 1, 2, 0x7FFFFFFE, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFE, 0xFFFFFFFF }

local function Unsigned(Value: number): number
	return Value % 4294967296
end

local function FromBytes(Bytes: { number }): buffer
	local Result = buffer.create(#Bytes)
	for Index, Byte in Bytes do
		buffer.writeu8(Result, Index - 1, Byte)
	end

	return Result
end

local function Filled(Length: number, Byte: number): buffer
	local Result = buffer.create(Length)
	buffer.fill(Result, 0, Byte, Length)
	return Result
end

Describe("Constant Time Utilities", function()
	Describe("CtNonZeroMask", function()
		Test("Returns 0 for zero", function()
			Expect(Unsigned(Functions.CtNonZeroMask(0))).ToBe(MASK_NONE)
		end)

		Test("Returns all ones for every non zero edge value", function()
			for _, Value in EDGE_VALUES do
				if Value == 0 then
					continue
				end

				Expect(Unsigned(Functions.CtNonZeroMask(Value))).ToBe(MASK_ALL)
			end
		end)

		Test("Is the complement of CtIsZeroMask", function()
			for _, Value in EDGE_VALUES do
				local NonZero = Unsigned(Functions.CtNonZeroMask(Value))
				local IsZero = Unsigned(Functions.CtIsZeroMask(Value))
				Expect(Unsigned(bit32.bxor(NonZero, IsZero))).ToBe(MASK_ALL)
			end
		end)
	end)

	Describe("CtIsZeroMask", function()
		Test("Returns all ones only for zero", function()
			for _, Value in EDGE_VALUES do
				local Expected = if Value == 0 then MASK_ALL else MASK_NONE
				Expect(Unsigned(Functions.CtIsZeroMask(Value))).ToBe(Expected)
			end
		end)
	end)

	Describe("CtEqMask", function()
		Test("Matches equality across every edge pair", function()
			for _, A in EDGE_VALUES do
				for _, B in EDGE_VALUES do
					local Expected = if A == B then MASK_ALL else MASK_NONE
					Expect(Unsigned(Functions.CtEqMask(A, B))).ToBe(Expected)
				end
			end
		end)
	end)

	Describe("CtLtMask", function()
		Test("Matches unsigned less than across every edge pair", function()
			for _, A in EDGE_VALUES do
				for _, B in EDGE_VALUES do
					local Expected = if A < B then MASK_ALL else MASK_NONE
					Expect(Unsigned(Functions.CtLtMask(A, B))).ToBe(Expected)
				end
			end
		end)

		Test("Does not treat the high bit as a sign", function()
			Expect(Unsigned(Functions.CtLtMask(0x7FFFFFFF, 0x80000000))).ToBe(MASK_ALL)
			Expect(Unsigned(Functions.CtLtMask(0x80000000, 0x7FFFFFFF))).ToBe(MASK_NONE)
			Expect(Unsigned(Functions.CtLtMask(0, 0xFFFFFFFF))).ToBe(MASK_ALL)
			Expect(Unsigned(Functions.CtLtMask(0xFFFFFFFF, 0))).ToBe(MASK_NONE)
		end)
	end)

	Describe("CtSelect", function()
		Test("Picks A on a full mask and B on an empty one", function()
			Expect(Unsigned(Functions.CtSelect(MASK_ALL, 0xAAAAAAAA, 0x55555555))).ToBe(0xAAAAAAAA)
			Expect(Unsigned(Functions.CtSelect(MASK_NONE, 0xAAAAAAAA, 0x55555555))).ToBe(0x55555555)
		end)

		Test("Composes with CtEqMask", function()
			Expect(Unsigned(Functions.CtSelect(Functions.CtEqMask(7, 7), 111, 222))).ToBe(111)
			Expect(Unsigned(Functions.CtSelect(Functions.CtEqMask(7, 8), 111, 222))).ToBe(222)
		end)
	end)

	Describe("CtSwap", function()
		Test("Swaps on a set bit and holds on a clear one", function()
			local A, B = Functions.CtSwap(1, 0xDEADBEEF, 0xFEEDFACE)
			Expect(Unsigned(A)).ToBe(0xFEEDFACE)
			Expect(Unsigned(B)).ToBe(0xDEADBEEF)

			local C, D = Functions.CtSwap(0, 0xDEADBEEF, 0xFEEDFACE)
			Expect(Unsigned(C)).ToBe(0xDEADBEEF)
			Expect(Unsigned(D)).ToBe(0xFEEDFACE)
		end)

		Test("Accepts a full mask as the condition", function()
			local A, B = Functions.CtSwap(MASK_ALL, 0xDEADBEEF, 0xFEEDFACE)
			Expect(Unsigned(A)).ToBe(0xFEEDFACE)
			Expect(Unsigned(B)).ToBe(0xDEADBEEF)
		end)

		Test("Accepts any non zero condition", function()
			local A, B = Functions.CtSwap(2, 0xDEADBEEF, 0xFEEDFACE)
			Expect(Unsigned(A)).ToBe(0xFEEDFACE)
			Expect(Unsigned(B)).ToBe(0xDEADBEEF)
		end)
	end)

	Describe("CtCompareMask", function()
		Test("Returns all ones for identical content", function()
			for _, Length in { 0, 1, 3, 4, 5, 7, 8, 31, 32, 33, 1088 } do
				local A = Filled(Length, 0xA5)
				local B = Filled(Length, 0xA5)
				Expect(Unsigned(Functions.CtCompareMask(A, B))).ToBe(MASK_ALL)
			end
		end)

		Test("Returns zero for a difference in any single byte", function()
			for _, Length in { 1, 3, 4, 5, 7, 8, 31, 32, 33 } do
				for Index = 0, Length - 1 do
					local A = Filled(Length, 0)
					local B = Filled(Length, 0)
					buffer.writeu8(B, Index, 1)
					Expect(Unsigned(Functions.CtCompareMask(A, B))).ToBe(MASK_NONE)
				end
			end
		end)

		Test("Returns zero on a length mismatch", function()
			Expect(Unsigned(Functions.CtCompareMask(Filled(16, 0), Filled(32, 0)))).ToBe(MASK_NONE)
			Expect(Unsigned(Functions.CtCompareMask(Filled(32, 0), Filled(16, 0)))).ToBe(MASK_NONE)
		end)

		Test("Feeds CtSelectBuffer directly without a boolean", function()
			local Chosen = buffer.create(32)
			local OnEqual = Filled(32, 0x11)
			local OnDiffer = Filled(32, 0x22)

			Functions.CtSelectBuffer(Functions.CtCompareMask(Filled(32, 7), Filled(32, 7)), Chosen, OnEqual, OnDiffer)
			Expect(Testing.BuffersEqual(Chosen, OnEqual)).ToBe(true)

			Functions.CtSelectBuffer(Functions.CtCompareMask(Filled(32, 7), Filled(32, 8)), Chosen, OnEqual, OnDiffer)
			Expect(Testing.BuffersEqual(Chosen, OnDiffer)).ToBe(true)
		end)
	end)

	Describe("CtCompare", function()
		Test("Agrees with CtCompareMask", function()
			Expect(Functions.CtCompare(Filled(32, 3), Filled(32, 3))).ToBe(true)
			Expect(Functions.CtCompare(Filled(32, 3), Filled(32, 4))).ToBe(false)
			Expect(Functions.CtCompare(Filled(16, 0), Filled(32, 0))).ToBe(false)
		end)

		Test("Detects a difference in the unaligned tail", function()
			local A = FromBytes({ 1, 2, 3, 4, 5 })
			local B = FromBytes({ 1, 2, 3, 4, 6 })
			Expect(Functions.CtCompare(A, B)).ToBe(false)
		end)

		Test("Treats empty buffers as equal", function()
			Expect(Functions.CtCompare(buffer.create(0), buffer.create(0))).ToBe(true)
		end)
	end)

	Describe("CtIsAllZero", function()
		Test("Reports true for zeroed buffers of every alignment", function()
			for _, Length in { 0, 1, 3, 4, 5, 7, 8, 33 } do
				Expect(Functions.CtIsAllZero(Filled(Length, 0))).ToBe(true)
			end
		end)

		Test("Reports false for a single set byte at any position", function()
			for _, Length in { 1, 3, 4, 5, 7, 8, 33 } do
				for Index = 0, Length - 1 do
					local Target = Filled(Length, 0)
					buffer.writeu8(Target, Index, 0x80)
					Expect(Functions.CtIsAllZero(Target)).ToBe(false)
				end
			end
		end)
	end)

	Describe("CtSwapBuffers", function()
		Test("Swaps on a set condition and holds on a clear one", function()
			for _, Length in { 1, 3, 4, 5, 7, 8, 33 } do
				local A = Filled(Length, 0xAA)
				local B = Filled(Length, 0x55)

				Functions.CtSwapBuffers(1, A, B)
				Expect(Testing.BuffersEqual(A, Filled(Length, 0x55))).ToBe(true)
				Expect(Testing.BuffersEqual(B, Filled(Length, 0xAA))).ToBe(true)

				Functions.CtSwapBuffers(0, A, B)
				Expect(Testing.BuffersEqual(A, Filled(Length, 0x55))).ToBe(true)
				Expect(Testing.BuffersEqual(B, Filled(Length, 0xAA))).ToBe(true)
			end
		end)

		Test("Is an involution", function()
			local A = FromBytes({ 1, 2, 3, 4, 5, 6, 7, 8, 9 })
			local B = FromBytes({ 9, 8, 7, 6, 5, 4, 3, 2, 1 })
			local OriginalA = FromBytes({ 1, 2, 3, 4, 5, 6, 7, 8, 9 })
			local OriginalB = FromBytes({ 9, 8, 7, 6, 5, 4, 3, 2, 1 })

			Functions.CtSwapBuffers(1, A, B)
			Functions.CtSwapBuffers(1, A, B)
			Expect(Testing.BuffersEqual(A, OriginalA)).ToBe(true)
			Expect(Testing.BuffersEqual(B, OriginalB)).ToBe(true)
		end)

		Test("Accepts a full mask as the condition", function()
			local A = Filled(8, 0xAA)
			local B = Filled(8, 0x55)
			Functions.CtSwapBuffers(MASK_ALL, A, B)
			Expect(Testing.BuffersEqual(A, Filled(8, 0x55))).ToBe(true)
		end)
	end)

	Describe("CtCopyIf", function()
		Test("Copies on a set condition and leaves the destination alone otherwise", function()
			for _, Length in { 1, 3, 4, 5, 7, 8, 33 } do
				local Destination = Filled(Length, 0x11)
				Functions.CtCopyIf(0, Destination, Filled(Length, 0x22))
				Expect(Testing.BuffersEqual(Destination, Filled(Length, 0x11))).ToBe(true)

				Functions.CtCopyIf(1, Destination, Filled(Length, 0x22))
				Expect(Testing.BuffersEqual(Destination, Filled(Length, 0x22))).ToBe(true)
			end
		end)

		Test("Accepts a full mask as the condition", function()
			local Destination = Filled(8, 0x11)
			Functions.CtCopyIf(MASK_ALL, Destination, Filled(8, 0x22))
			Expect(Testing.BuffersEqual(Destination, Filled(8, 0x22))).ToBe(true)
		end)
	end)

	Describe("CtSelectBuffer", function()
		Test("Selects the true source on a set condition", function()
			for _, Length in { 1, 3, 4, 5, 7, 8, 33 } do
				local Destination = buffer.create(Length)
				Functions.CtSelectBuffer(1, Destination, Filled(Length, 0xCC), Filled(Length, 0x33))
				Expect(Testing.BuffersEqual(Destination, Filled(Length, 0xCC))).ToBe(true)

				Functions.CtSelectBuffer(0, Destination, Filled(Length, 0xCC), Filled(Length, 0x33))
				Expect(Testing.BuffersEqual(Destination, Filled(Length, 0x33))).ToBe(true)
			end
		end)

		Test("Selects per byte rather than per buffer", function()
			local Destination = buffer.create(4)
			local TrueSource = FromBytes({ 0xDE, 0xAD, 0xBE, 0xEF })
			local FalseSource = FromBytes({ 0x01, 0x02, 0x03, 0x04 })

			Functions.CtSelectBuffer(1, Destination, TrueSource, FalseSource)
			Expect(Testing.ToHex(Destination)).ToBe("deadbeef")

			Functions.CtSelectBuffer(0, Destination, TrueSource, FalseSource)
			Expect(Testing.ToHex(Destination)).ToBe("01020304")
		end)

		Test("Accepts any non zero condition", function()
			local Destination = buffer.create(8)
			Functions.CtSelectBuffer(2, Destination, Filled(8, 0xCC), Filled(8, 0x33))
			Expect(Testing.BuffersEqual(Destination, Filled(8, 0xCC))).ToBe(true)
		end)
	end)

	Describe("Concatenate", function()
		Test("Joins buffers in order", function()
			local Result = Functions.Concatenate(FromBytes({ 1, 2 }), FromBytes({ 3 }), FromBytes({ 4, 5, 6 }))
			Expect(buffer.len(Result)).ToBe(6)
			Expect(Testing.ToHex(Result)).ToBe("010203040506")
		end)

		Test("Handles empty buffers and no arguments", function()
			Expect(buffer.len(Functions.Concatenate())).ToBe(0)
			Expect(Testing.ToHex(Functions.Concatenate(buffer.create(0), FromBytes({ 7 })))).ToBe("07")
		end)
	end)
end)

Testing.Complete()

return 0
