
--[[
	Proper entropy testing is too expensive
	in luau, done outside by tools like diehard
]]

--!strict
--!optimize 2
--!native

local Testing = require("../")

local Algorithm =  require("../../src/Utilities/CSPRNG")

local function ForceCast<To>(Value: any): To
	return Value :: To
end

Testing.Describe("CSPRNG Algorithm Tests", function()
	Testing.Test("AddEntropy Function", function()
		local Value1 = Algorithm.Random()
		Algorithm.AddEntropy()
		local Value2 = Algorithm.Random()

		Testing.Expect(Value1).Never.ToBe(Value2)

		local CustomEntropy = Algorithm.RandomBytes(64)
		Algorithm.AddEntropy(CustomEntropy)
		local Value3 = Algorithm.Random()
		Testing.Expect(typeof(Value3)).ToBe("number")

		Testing.Expect(function()
			Algorithm.AddEntropy(ForceCast<<buffer>>("not a buffer"))
		end).ToThrow()
	end)

	Testing.Test("RandomInt", function()
		Testing.Expect(function()
			Algorithm.RandomInt(0, -1)
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomInt(0, 0)
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomInt(1, 1)
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomInt(ForceCast<<number>>("test"))
		end).ToThrow()

		for i = 1, 100 do
			local Result = Algorithm.RandomInt(10)
			Testing.Expect(Result).ToBeGreaterThanOrEqual(1)
			Testing.Expect(Result).ToBeLessThanOrEqual(10)
		end

		for i = 1, 1000 do
			local Result = Algorithm.RandomInt(1, 100)
			Testing.Expect(Result).ToBeGreaterThanOrEqual(1)
			Testing.Expect(Result).ToBeLessThanOrEqual(100)
		end

		for i = 1, 100 do
			local Result = Algorithm.RandomInt(2^20, 2^21)
			Testing.Expect(Result).ToBeGreaterThanOrEqual(2^20)
			Testing.Expect(Result).ToBeLessThanOrEqual(2^21)
		end
	end)

	Testing.Test("Random Number", function()
		Testing.Expect(function()
			Algorithm.RandomNumber(0, -1)
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomNumber(0, 0)
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomNumber(1, 1)
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomNumber(ForceCast<<number>>("test"))
		end).ToThrow()

		for i = 1, 100 do
			local Result = Algorithm.RandomNumber(10.5)
			Testing.Expect(Result).ToBeGreaterThanOrEqual(0)
			Testing.Expect(Result).ToBeLessThanOrEqual(10.5)
		end

		for i = 1, 1000 do
			local Result = Algorithm.RandomNumber(1.5, 100.7)
			Testing.Expect(Result).ToBeGreaterThanOrEqual(1.5)
			Testing.Expect(Result).ToBeLessThanOrEqual(100.7)
		end

		for i = 1, 100 do
			local Result = Algorithm.RandomNumber(0.001, 0.002)
			Testing.Expect(Result).ToBeGreaterThanOrEqual(0.001)
			Testing.Expect(Result).ToBeLessThanOrEqual(0.002)
		end
	end)

	Testing.Test("GetBytes", function()
		Testing.Expect(function()
			Algorithm.RandomBytes(0)
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomBytes(1.1)
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomBytes(ForceCast<<number>>("test"))
		end).ToThrow()

		local Buffer1 = Algorithm.RandomBytes(32)
		Testing.Expect(buffer.len(Buffer1)).ToBe(32)
		Testing.Expect(typeof(Buffer1)).ToBe("buffer")

		local Buffer2 = Algorithm.RandomBytes(32)
		Testing.Expect(buffer.len(Buffer2)).ToBe(32)

		local Different = false
		for i = 0, 31 do
			if buffer.readu8(Buffer1, i) ~= buffer.readu8(Buffer2, i) then
				Different = true
				break
			end
		end
		Testing.Expect(Different).ToBeTruthy()

		for Size = 1, 100 do
			local Buffer = Algorithm.RandomBytes(Size)
			Testing.Expect(buffer.len(Buffer)).ToBe(Size)
		end
	end)

	Testing.Test("RandomString", function()
		Testing.Expect(function()
			Algorithm.RandomString(0)
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomString(-1)
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomString(10, ForceCast<<boolean>>(123))
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomString(10, ForceCast<<boolean>>("hello"))
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomString(10.1)
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomString(ForceCast<<number>>("hello"))
		end).ToThrow()

		Testing.Expect(string.len(Algorithm.RandomString(30) :: string)).ToBe(30)
		Testing.Expect(buffer.len(Algorithm.RandomString(30, true) :: buffer)).ToBe(30)

		local String1 = Algorithm.RandomString(10, false) :: string
		Testing.Expect(typeof(String1)).ToBe("string")
		Testing.Expect(#String1).ToBe(10)

		local String2 = Algorithm.RandomString(10, false) :: string
		Testing.Expect(typeof(String2)).ToBe("string")
		Testing.Expect(String1).Never.ToBe(String2)

		local Buffer1 = Algorithm.RandomString(10, true) :: buffer
		Testing.Expect(typeof(Buffer1)).ToBe("buffer")
		Testing.Expect(buffer.len(Buffer1)).ToBe(10)

		for i = 1, 100 do
			local String = Algorithm.RandomString(50, false) :: string
			for j = 1, #String do
				local Byte = string.byte(String, j)
				Testing.Expect(Byte).ToBeGreaterThanOrEqual(36)
				Testing.Expect(Byte).ToBeLessThanOrEqual(122)
			end
		end
	end)

	Testing.Test("RandomHex", function()
		Testing.Expect(function()
			Algorithm.RandomHex(0)
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomHex(-1)
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomHex(10.1)
		end).ToThrow()

		Testing.Expect(function()
			Algorithm.RandomHex(ForceCast<<number>>("hello"))
		end).ToThrow()

		Testing.Expect(string.len(Algorithm.RandomHex(30))).ToBe(30)
		Testing.Expect(function()
			Algorithm.RandomHex(31)
		end).ToThrow()
		Testing.Expect(string.len(Algorithm.RandomHex(32))).ToBe(32)

		for Length = 2, 64, 2 do
			local HexString = Algorithm.RandomHex(Length)
			Testing.Expect(typeof(HexString)).ToBe("string")
			Testing.Expect(#HexString).ToBe(Length)

			for i = 1, #HexString do
				local Char = string.sub(HexString, i, i)
				local IsValidHex = string.match(Char, "[0-9a-fA-F]") ~= nil
				Testing.Expect(IsValidHex).ToBeTruthy()
			end
		end
	end)
end)

Testing.Complete()

return 0
