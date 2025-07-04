--!strict

local Testing = require("./")
type TestVector = {
	Description: string,
	Expected: string
}

type TestVectors = {[string]: TestVector}
local Algorithm = require("../Utilities/CSPRNG") 

Testing.Describe("CSPRNG Algorithm Tests", function()
	Testing.Test("Ed25519 Functions", function()
		local Ed25519Bytes = Algorithm.Ed25519RandomBytes()
		Testing.Expect(typeof(Ed25519Bytes)).ToBe("buffer")
		Testing.Expect(buffer.len(Ed25519Bytes)).ToBe(32)

		Testing.Expect(function()
			Algorithm.Ed25519ClampedBytes("not a buffer" :: any)
		end).ToThrow()

		local TestBuffer = Algorithm.RandomBytes(32)
		local ClampedBytes = Algorithm.Ed25519ClampedBytes(TestBuffer)
		Testing.Expect(typeof(ClampedBytes)).ToBe("buffer")
		Testing.Expect(buffer.len(ClampedBytes)).ToBe(32)

		local FirstByte = buffer.readu8(ClampedBytes, 0)
		local LastByte = buffer.readu8(ClampedBytes, 31)

		Testing.Expect(bit32.band(FirstByte, 0x07)).ToBe(0)
		Testing.Expect(bit32.band(LastByte, 0x80)).ToBe(0)
		Testing.Expect(bit32.band(LastByte, 0x40)).ToBe(0x40)

		local Ed25519Random = Algorithm.Ed25519Random()
		Testing.Expect(typeof(Ed25519Random)).ToBe("buffer")
		Testing.Expect(buffer.len(Ed25519Random)).ToBe(32)

		local FirstByteRandom = buffer.readu8(Ed25519Random, 0)
		local LastByteRandom = buffer.readu8(Ed25519Random, 31)

		Testing.Expect(bit32.band(FirstByteRandom, 0x07)).ToBe(0)
		Testing.Expect(bit32.band(LastByteRandom, 0x80)).ToBe(0)
		Testing.Expect(bit32.band(LastByteRandom, 0x40)).ToBe(0x40)
	end)

	Testing.Test("Reseed Function", function()
		local Value1 = Algorithm.Random()
		Algorithm.Reseed()
		local Value2 = Algorithm.Random()

		Testing.Expect(Value1).Never.ToBe(Value2)

		local CustomEntropy = Algorithm.RandomBytes(64)
		Algorithm.Reseed(CustomEntropy)
		local Value3 = Algorithm.Random()
		Testing.Expect(typeof(Value3)).ToBe("number")

		Testing.Expect(function()
			Algorithm.Reseed("not a buffer" :: any)
		end).ToThrow()
	end)

	Testing.Test("New Instance Creation", function()
		local Instance1 = Algorithm.New()
		local Instance2 = Algorithm.New()

		local Value1 = Instance1:GetFloat()
		local Value2 = Instance2:GetFloat()
		Testing.Expect(Value1).Never.ToBe(Value2)

		Testing.Expect(Instance1:GetUInt32()).ToBe(Testing.Expect.Type("number"))
		Testing.Expect(Instance1:GetIntRange(1, 10)).ToBeGreaterThanOrEqual(1)
		Testing.Expect(Instance1:GetIntRange(1, 10)).ToBeLessThanOrEqual(10)

		local InstanceBytes = Instance1:GetBytes(16)
		Testing.Expect(typeof(InstanceBytes)).ToBe("buffer")
		Testing.Expect(buffer.len(InstanceBytes)).ToBe(16)
	end)
	
	Testing.Test("Chance", function()
		local WeightedChances = {
			Common = 50,
			Rare = 30,
			Legendary = 20,
			Mythic = 1
		}
		
		local TotalWeight = 0
		
		for Name, Weight in WeightedChances do
			TotalWeight += Weight :: any
		end
		
		local function ChooseRandom()
			local Number = Algorithm.RandomInt(1, TotalWeight)
			--local Number = math.random(1, TotalWeight)
			local CurrentWeight = 0

			for Name, Weight in WeightedChances do
				local Name: string = Name :: any
				local Weight: number = Weight :: number

				CurrentWeight += Weight

				if Number <= CurrentWeight then
					return Name
				end
			end

			return "Common"
		end
		
		local ROLLS = 100_000
		local EPSILON = 0.05
		local ITERATIONS = 10

		local Occurences = {
			Common = 0,
			Rare = 0,
			Legendary = 0,
			Mythic = 0,
		}
		
		local function Reset()
			for Name, Count in Occurences do
				Occurences[Name] = 0
			end
		end
		
		local function ExpectedOccurences(Rarity: string)
			return math.ceil((WeightedChances[Rarity] / TotalWeight) * ROLLS)
		end
		
		local Accumlated = table.clone(Occurences)
		for _ = 1, ITERATIONS do
			for _ = 1, ROLLS do
				local ChosenRarity = ChooseRandom()
				Occurences[ChosenRarity] += 1
			end
			
			for Name, Count in Occurences do
				-- For some reason they're "unknown"
				local Name: string = Name :: any
				local Count: number = Count :: number

				local ActualRate = math.abs(1 - (Count / ExpectedOccurences(Name)))
				Accumlated[Name] += ActualRate
			end
			
			Reset()
		end
		
		for Name, Chance in Accumlated do
			-- For some reason they're "unknown"
			local Name: string = Name :: any
			local Chance: number = Chance :: number

			local AverageRate = Chance / ITERATIONS
			Testing.Expect(AverageRate).ToBeLessThan(EPSILON)
		end
	end)

	Testing.Test("Distribution Tests", function()
		local Buckets = {}
		for i = 1, 10 do
			Buckets[i] = 0
		end

		for i = 1, 10000 do
			local Value = Algorithm.RandomInt(1, 10)
			Buckets[Value] += 1
		end

		for i = 1, 10 do
			Testing.Expect(Buckets[i]).ToBeGreaterThan(800)
			Testing.Expect(Buckets[i]).ToBeLessThan(1200)
		end

		local FloatBuckets = {0, 0, 0, 0, 0}
		for i = 1, 10000 do
			local Value = Algorithm.Random()
			local Bucket = math.floor(Value * 5) + 1
			FloatBuckets[Bucket] = FloatBuckets[Bucket] + 1
		end

		for i = 1, 5 do
			Testing.Expect(FloatBuckets[i]).ToBeGreaterThan(1600)
			Testing.Expect(FloatBuckets[i]).ToBeLessThan(2400)
		end
	end)

	Testing.Test("Entropy Quality", function()
		local Values = {}
		for i = 1, 100 do
			local Value = Algorithm.RandomBytes(4)
			local UInt32 = buffer.readu32(Value, 0)
			Values[i] = UInt32
		end

		local Duplicates = 0
		for i = 1, 100 do
			for j = i + 1, 100 do
				if Values[i] == Values[j] then
					Duplicates += 1
				end
			end
		end

		Testing.Expect(Duplicates).ToBeLessThan(2)

		local LargeBuffer = Algorithm.RandomBytes(1000)
		local BitCounts = {0, 0, 0, 0, 0, 0, 0, 0}

		for i = 0, 999 do
			local Byte = buffer.readu8(LargeBuffer, i)
			for Bit = 0, 7 do
				if bit32.band(Byte, bit32.lshift(1, Bit)) ~= 0 then
					BitCounts[Bit + 1] = BitCounts[Bit + 1] + 1
				end
			end
		end

		for i = 1, 8 do
			Testing.Expect(BitCounts[i]).ToBeGreaterThan(450)
			Testing.Expect(BitCounts[i]).ToBeLessThan(550)
		end
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
			Algorithm.RandomInt("test" :: any)
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
			Algorithm.RandomNumber("test" :: any)
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
			Algorithm.RandomBytes("test" :: any)
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
			Algorithm.RandomString(10, 123 :: any)
		end).ToThrow()
		
		Testing.Expect(function()
			Algorithm.RandomString(10, "hello" :: any)
		end).ToThrow()
		
		Testing.Expect(function()
			Algorithm.RandomString(10.1)
		end).ToThrow()
		
		Testing.Expect(function()
			Algorithm.RandomString("test" :: any)
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
			Algorithm.RandomHex("test" :: any)
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