--[=[
   Cryptography library: Field Quadratic (Curve25519 Scalar Field)
   
   Return type: varies by function
   Example usage:
   	local FieldQuadratic = require("FieldQuadratic")
   	
   	--------Usage Case 1: Basic scalar arithmetic--------
   	local ScalarA = FieldQuadratic.Decode(SomeBytes)
   	local ScalarB = FieldQuadratic.Decode(OtherBytes)
   	local Sum = FieldQuadratic.Add(ScalarA, ScalarB)
   	local Product = FieldQuadratic.Mul(ScalarA, ScalarB)
   	
   	--------Usage Case 2: Convert to bits for scalar multiplication--------
   	local ScalarBits = FieldQuadratic.Bits(ScalarA)
   	local EncodedResult = FieldQuadratic.Encode(Product)
--]=]

--!native
--!optimize 2

local MultiPrecision = require(script.Parent.MultiPrecision)

local Unpack = unpack or table.unpack
local PackFieldQuadratic, FormatFieldQuadratic = string.pack, "<I3I3I3I3I3I3I3I3I3I3I2"
local UnpackFieldQuadratic = string.unpack
local UnpackFieldQuadraticLow, FormatFieldQuadraticLow = string.unpack, "<I3I3I3I3I3I3I3I3I3I3I3"
local UnpackFieldQuadraticHigh, FormatFieldQuadraticHigh = string.unpack, "<I3I3I3I3I3I3I3I3I3I3I1"

-- the scalar field's order: q = 2^252 + 27742317777372353535851937790883648493
local FieldOrder = {
	16110573,
	06494812,
	14047250,
	10680220,
	14612958,
	00000020,
	00000000,
	00000000,
	00000000,
	00000000,
	00004096,
}

-- first montgomery precomputed constant: -q^(-1) mod 2^264
local MontgomeryT0 = {
	05537307,
	01942290,
	16765621,
	16628356,
	10618610,
	07072433,
	03735459,
	01369940,
	15276086,
	13038191,
	13409718,
}

-- second montgomery precomputed constant: 2^528 mod q
local MontgomeryT1 = {
	11711996,
	01747860,
	08326961,
	03814718,
	01859974,
	13327461,
	16105061,
	07590423,
	04050668,
	08138906,
	00000283,
}

-- precomputed constant for division by 8
local DivideBy8Constant = {
	5110253,
	3039345,
	2503500,
	11779568,
	15416472,
	16766550,
	16777215,
	16777215,
	16777215,
	16777215,
	4095,
}

local ZeroConstant = MultiPrecision.Num(0)

-- reduce a number modulo q to keep it in the valid range
local function Reduce(LargeNumber)
	local Difference = MultiPrecision.Sub(LargeNumber, FieldOrder)

	-- return carry(a) if a < q
	if MultiPrecision.Approx(Difference) < 0 then
		return MultiPrecision.Carry(LargeNumber)
	end

	-- since q < 2^288, difference < 2q means difference - q < q < 2^288
	-- difference's limbs fit in (-2^26..2^26) since subtraction adds at most one bit
	return MultiPrecision.Carry(Difference) -- carry handles the reduction properly
end

-- add two scalars modulo q
-- works correctly in montgomery form since (2^264 * a) + (2^264 * b) = 2^264 * (a + b) mod q
local function Add(ScalarA, ScalarB)
	return Reduce(MultiPrecision.Add(ScalarA, ScalarB))
end

-- negate a scalar modulo q
local function Neg(ScalarA)
	return Reduce(MultiPrecision.Sub(FieldOrder, ScalarA))
end

-- subtract scalars modulo q
-- works correctly in montgomery form like addition
local function Sub(ScalarA, ScalarB)
	return Add(ScalarA, Neg(ScalarB))
end

-- montgomery multiplication: computes 2^(-264) * a * b mod q
local function Mul(ScalarA, ScalarB)
	local ProductLow, ProductHigh = MultiPrecision.Mul(ScalarA, ScalarB)
	local ReductionLow, ReductionHigh = MultiPrecision.Mul(MultiPrecision.LMul(ProductLow, MontgomeryT0), FieldOrder)
	local _, ResultHigh = MultiPrecision.DWAdd(ProductLow, ProductHigh, ReductionLow, ReductionHigh)
	return Reduce(ResultHigh)
end

-- convert a scalar into montgomery form
local function Montgomery(RegularScalar)
	-- 0 <= a < 2^264 and 0 <= t1 < q
	return Mul(RegularScalar, MontgomeryT1)
end

-- convert a scalar from montgomery form back to regular form
local function Demontgomery(MontgomeryScalar)
	-- it's redc again except b is 1
	local ReductionLow, ReductionHigh =
		MultiPrecision.Mul(MultiPrecision.LMul(MontgomeryScalar, MontgomeryT0), FieldOrder)
	local _, ResultHigh = MultiPrecision.DWAdd(MontgomeryScalar, ZeroConstant, ReductionLow, ReductionHigh)
	return Reduce(ResultHigh)
end

-- turn a scalar into 32 bytes
local function Encode(MontgomeryScalar)
	local DemontResult = Demontgomery(MontgomeryScalar)
	return PackFieldQuadratic(
		FormatFieldQuadratic,
		DemontResult[1],
		DemontResult[2],
		DemontResult[3],
		DemontResult[4],
		DemontResult[5],
		DemontResult[6],
		DemontResult[7],
		DemontResult[8],
		DemontResult[9],
		DemontResult[10],
		DemontResult[11]
	)
end

-- turn 32 bytes into a scalar
local function Decode(EncodedString)
	if #EncodedString ~= 32 then
		error("Decode expects exactly 32 bytes, got " .. #EncodedString)
	end

	local DecodedLimbs = { UnpackFieldQuadratic(FormatFieldQuadratic, EncodedString, 1) }
	DecodedLimbs[12] = nil
	return Montgomery(DecodedLimbs)
end

-- decode a scalar from a "wide" 64-byte string
local function DecodeWide(WideString)
	local LowPart = { UnpackFieldQuadraticLow(FormatFieldQuadraticLow, WideString, 1) }
	LowPart[12] = nil
	local HighPart = { UnpackFieldQuadraticHigh(FormatFieldQuadraticHigh, WideString, 34) }
	HighPart[12] = nil
	return Add(Montgomery(LowPart), Montgomery(Montgomery(HighPart)))
end

-- decode a scalar using x25519/ed25519 bit clamping scheme
local function DecodeClamped(ClampedString)
	-- decode the bytes first
	local WordLimbs = { UnpackFieldQuadratic(FormatFieldQuadratic, ClampedString, 1) }
	WordLimbs[12] = nil

	-- apply the clamping rules
	WordLimbs[1] = bit32.band(WordLimbs[1], 0xfffff8)
	WordLimbs[11] = bit32.band(WordLimbs[11], 0x7fff)
	WordLimbs[11] = bit32.bor(WordLimbs[11], 0x4000)

	return Montgomery(WordLimbs)
end

-- divide a scalar by 8 (multiply by 1/8)
local function Eighth(MontgomeryScalar)
	return Mul(MontgomeryScalar, DivideBy8Constant)
end

-- convert a little-endian array from one power-of-two base to another
local function RebaseLE(InputArray, FromBase, ToBase)
	local OutputArray = {}
	local OutputLength = 1
	local Accumulator = 0
	local Multiplier = 1
	for Index = 1, #InputArray do
		Accumulator = Accumulator + InputArray[Index] * Multiplier
		Multiplier = Multiplier * FromBase
		while Multiplier >= ToBase do
			local Remainder = Accumulator % ToBase
			Accumulator = (Accumulator - Remainder) / ToBase
			Multiplier = Multiplier / ToBase
			OutputArray[OutputLength] = Remainder
			OutputLength = OutputLength + 1
		end
	end
	if Multiplier > 0 then
		OutputArray[OutputLength] = Accumulator
	end
	return OutputArray
end

-- convert a scalar to binary bits for scalar multiplication
local function Bits(MontgomeryScalar)
	local BitOutput = RebaseLE(Demontgomery(MontgomeryScalar), 2 ^ 24, 2)
	for BitIndex = 254, 289 do
		BitOutput[BitIndex] = nil
	end
	return BitOutput
end

-- create a prac ruleset from a pair of scalars (for efficient dual scalar multiplication)
-- see section 3.3 of "speeding up subgroup cryptosystems" by martijn stam
local function MakeRuleset(ScalarA, ScalarB)
	-- convert to raw multiprecision tables
	local DTable = Demontgomery(ScalarA) -- (-2^24..2^24)
	local ETable = Demontgomery(ScalarB) -- (-2^24..2^24)
	local FTable = MultiPrecision.Sub(DTable, ETable) -- (-2^25..2^25)

	-- residue classes modulo 2
	local DMod2 = MultiPrecision.Mod2(DTable)
	local EMod2 = MultiPrecision.Mod2(ETable)

	-- residue classes modulo 3
	local DMod3 = MultiPrecision.Mod3(DTable)
	local EMod3 = MultiPrecision.Mod3(ETable)

	-- floating point approximations
	local EFloat = MultiPrecision.Approx(ETable)
	local FFloat = MultiPrecision.Approx(FTable)

	-- lookup table for inversions and halvings modulo 3
	local Mod3Lut = { [0] = 0, 2, 1 }

	local RuleSequence = {}
	while FFloat ~= 0 do
		if FFloat < 0 then
			-- M0: d < e
			RuleSequence[#RuleSequence + 1] = 0
			-- (d, e) becomes (e, d)
			DTable, ETable = ETable, DTable
			DMod2, EMod2 = EMod2, DMod2
			DMod3, EMod3 = EMod3, DMod3
			EFloat = MultiPrecision.Approx(ETable)
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = -FFloat
		elseif 4 * FFloat < EFloat and DMod3 == Mod3Lut[EMod3] then
			-- M1: e < d <= 5/4 e, d = -e (mod 3)
			RuleSequence[#RuleSequence + 1] = 1
			-- (d, e) becomes ((2d - e)/3, (2e - d)/3)
			DTable, ETable =
				MultiPrecision.Third(MultiPrecision.Add(DTable, FTable)),
				MultiPrecision.Third(MultiPrecision.Sub(ETable, FTable))
			DMod2, EMod2 = EMod2, DMod2
			DMod3, EMod3 = MultiPrecision.Mod3(DTable), MultiPrecision.Mod3(ETable)
			EFloat = MultiPrecision.Approx(ETable)
		elseif 4 * FFloat < EFloat and DMod2 == EMod2 and DMod3 == EMod3 then
			-- M2: e < d <= 5/4 e, d = e (mod 6)
			RuleSequence[#RuleSequence + 1] = 2
			-- (d, e) becomes ((d - e)/2, e)
			DTable = MultiPrecision.Half(FTable)
			DMod2 = MultiPrecision.Mod2(DTable)
			DMod3 = Mod3Lut[(DMod3 - EMod3) % 3]
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		elseif FFloat < 3 * EFloat then
			-- M3: d <= 4e
			RuleSequence[#RuleSequence + 1] = 3
			-- (d, e) becomes (d - e, e)
			DTable = MultiPrecision.CarryWeak(FTable)
			DMod2 = (DMod2 - EMod2) % 2
			DMod3 = (DMod3 - EMod3) % 3
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		elseif DMod2 == EMod2 then
			-- M4: d = e (mod 2)
			RuleSequence[#RuleSequence + 1] = 2
			-- (d, e) becomes ((d - e)/2, e)
			DTable = MultiPrecision.Half(FTable)
			DMod2 = MultiPrecision.Mod2(DTable)
			DMod3 = Mod3Lut[(DMod3 - EMod3) % 3]
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		elseif DMod2 == 0 then
			-- M5: d = 0 (mod 2)
			RuleSequence[#RuleSequence + 1] = 5
			-- (d, e) becomes (d/2, e)
			DTable = MultiPrecision.Half(DTable)
			DMod2 = MultiPrecision.Mod2(DTable)
			DMod3 = Mod3Lut[DMod3]
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		elseif DMod3 == 0 then
			-- M6: d = 0 (mod 3)
			RuleSequence[#RuleSequence + 1] = 6
			-- (d, e) becomes (d/3 - e, e)
			DTable = MultiPrecision.CarryWeak(MultiPrecision.Sub(MultiPrecision.Third(DTable), ETable))
			DMod2 = (DMod2 - EMod2) % 2
			DMod3 = MultiPrecision.Mod3(DTable)
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		elseif DMod3 == Mod3Lut[EMod3] then
			-- M7: d = -e (mod 3)
			RuleSequence[#RuleSequence + 1] = 7
			-- (d, e) becomes ((d - 2e)/3, e)
			DTable = MultiPrecision.Third(MultiPrecision.Sub(FTable, ETable))
			DMod3 = MultiPrecision.Mod3(DTable)
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		elseif DMod3 == EMod3 then
			-- M8: d = e (mod 3)
			RuleSequence[#RuleSequence + 1] = 8
			-- (d, e) becomes ((d - e)/3, e)
			DTable = MultiPrecision.Third(FTable)
			DMod2 = (DMod2 - EMod2) % 2
			DMod3 = MultiPrecision.Mod3(DTable)
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		else
			-- M9: e = 0 (mod 2)
			RuleSequence[#RuleSequence + 1] = 9
			-- (d, e) becomes (d, e/2)
			ETable = MultiPrecision.Half(ETable)
			EMod2 = MultiPrecision.Mod2(ETable)
			EMod3 = Mod3Lut[EMod3]
			EFloat = MultiPrecision.Approx(ETable)
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		end
	end

	local FinalBits = RebaseLE(DTable, 2 ^ 24, 2)
	while FinalBits[#FinalBits] == 0 do
		FinalBits[#FinalBits] = nil
	end

	return { FinalBits, RuleSequence }
end

return {
	Add = Add,
	Sub = Sub,
	Mul = Mul,
	Encode = Encode,
	Decode = Decode,
	DecodeWide = DecodeWide,
	DecodeClamped = DecodeClamped,
	Eighth = Eighth,
	Bits = Bits,
	MakeRuleset = MakeRuleset,
}
