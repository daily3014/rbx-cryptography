--[=[
	Cryptography library: XXHash32
	
	⚠️ WARNING: XXHash32 wasn't designed with cryptographic security in mind!
	Only use for non-security purposes. For security, use SHA256 or higher. ⚠️
	
	Return type: number
	Example usage:
		local Message = buffer.fromstring("Hello World")

		--------Usage Case 1--------
		local Result = XXHash32(Message)
		
		--------Usage Case 2--------
		local Seed = 0xDEADBEEF
		local Result = XXHash32(Message, Seed)
--]=]

--!strict
--!optimize 2
--!native

local function XXH32(Message: buffer, Seed: number?): number
	local PRIME_1, PRIME_1_HIGH, PRIME_1_LOW = 0x9e3779B1, 40503, 31153
	local PRIME_2, PRIME_2_HIGH, PRIME_2_LOW = 0x85ebca77, 34283, 51831
	local _PRIME_3, PRIME_3_HIGH, PRIME_3_LOW = 0xc2b2ae3d, 49842, 44605
	local _PRIME_4, PRIME_4_HIGH, PRIME_4_LOW = 0x27d4eb2f, 10196, 60207
	local PRIME_5, PRIME_5_HIGH, PRIME_5_LOW = 0x165667b1, 5718, 26545

	local UsedSeed = Seed or 0
	local MessageLength = buffer.len(Message)
	local Digest: number
	local CurrentOffset = 0

	if MessageLength >= 16 then
		local Accumulator1 = UsedSeed + PRIME_1 + PRIME_2
		local Accumulator2 = UsedSeed + PRIME_2
		local Accumulator3 = UsedSeed
		local Accumulator4 = UsedSeed - PRIME_1

		while CurrentOffset <= MessageLength - 16 do
			local Word1 = buffer.readu32(Message, CurrentOffset)
			local Word2 = buffer.readu32(Message, CurrentOffset + 4)
			local Word3 = buffer.readu32(Message, CurrentOffset + 8)
			local Word4 = buffer.readu32(Message, CurrentOffset + 12)

			local AHigh1, ALow1 = bit32.rshift(Word1, 16), Word1 % 65536
			local Mult1 = bit32.lshift((AHigh1 * PRIME_2_LOW) + (ALow1 * PRIME_2_HIGH), 16) + (ALow1 * PRIME_2_LOW)

			local Temp1 = bit32.lrotate(Accumulator1 + Mult1, 13)
			local AHigh1_2, ALow1_2 = bit32.rshift(Temp1, 16), Temp1 % 65536
			Accumulator1 = bit32.lshift((AHigh1_2 * PRIME_1_LOW) + (ALow1_2 * PRIME_1_HIGH), 16) + (ALow1_2 * PRIME_1_LOW)

			local AHigh2, ALow2 = bit32.rshift(Word2, 16), Word2 % 65536
			local Mult2 = bit32.lshift((AHigh2 * PRIME_2_LOW) + (ALow2 * PRIME_2_HIGH), 16) + (ALow2 * PRIME_2_LOW)

			local Temp2 = bit32.lrotate(Accumulator2 + Mult2, 13)
			local AHigh2_2, ALow2_2 = bit32.rshift(Temp2, 16), Temp2 % 65536
			Accumulator2 = bit32.lshift((AHigh2_2 * PRIME_1_LOW) + (ALow2_2 * PRIME_1_HIGH), 16) + (ALow2_2 * PRIME_1_LOW)

			local AHigh3, ALow3 = bit32.rshift(Word3, 16), Word3 % 65536
			local Mult3 = bit32.lshift((AHigh3 * PRIME_2_LOW) + (ALow3 * PRIME_2_HIGH), 16) + (ALow3 * PRIME_2_LOW)

			local Temp3 = bit32.lrotate(Accumulator3 + Mult3, 13)
			local AHigh3_2, ALow3_2 = bit32.rshift(Temp3, 16), Temp3 % 65536
			Accumulator3 = bit32.lshift((AHigh3_2 * PRIME_1_LOW) + (ALow3_2 * PRIME_1_HIGH), 16) + (ALow3_2 * PRIME_1_LOW)

			local AHigh4, ALow4 = bit32.rshift(Word4, 16), Word4 % 65536
			local Mult4 = bit32.lshift((AHigh4 * PRIME_2_LOW) + (ALow4 * PRIME_2_HIGH), 16) + (ALow4 * PRIME_2_LOW)

			local Temp4 = bit32.lrotate(Accumulator4 + Mult4, 13)
			local AHigh4_2, ALow4_2 = bit32.rshift(Temp4, 16), Temp4 % 65536
			Accumulator4 = bit32.lshift((AHigh4_2 * PRIME_1_LOW) + (ALow4_2 * PRIME_1_HIGH), 16) + (ALow4_2 * PRIME_1_LOW)

			CurrentOffset += 16
		end

		Digest = bit32.lrotate(Accumulator1, 1) + bit32.lrotate(Accumulator2, 7) + bit32.lrotate(Accumulator3, 12) + bit32.lrotate(Accumulator4, 18)
	else
		Digest = UsedSeed + PRIME_5
	end

	Digest += MessageLength

	while CurrentOffset <= MessageLength - 4 do
		if CurrentOffset + 4 <= buffer.len(Message) then
			local Word = buffer.readu32(Message, CurrentOffset)

			local AHigh_w, ALow_w = bit32.rshift(Word, 16), Word % 65536
			local Mult_w = bit32.lshift((AHigh_w * PRIME_3_LOW) + (ALow_w * PRIME_3_HIGH), 16) + (ALow_w * PRIME_3_LOW)

			Digest += Mult_w

			local Rotated = bit32.lrotate(Digest, 17)
			local AHigh_r, ALow_r = bit32.rshift(Rotated, 16), Rotated % 65536
			Digest = bit32.lshift((AHigh_r * PRIME_4_LOW) + (ALow_r * PRIME_4_HIGH), 16) + (ALow_r * PRIME_4_LOW)
		end
		CurrentOffset += 4
	end

	while CurrentOffset < MessageLength do
		if CurrentOffset < buffer.len(Message) then
			local ByteValue = buffer.readu8(Message, CurrentOffset)

			local AHigh_b, ALow_b = bit32.rshift(ByteValue, 16), ByteValue % 65536
			local Mult_b = bit32.lshift((AHigh_b * PRIME_5_LOW) + (ALow_b * PRIME_5_HIGH), 16) + (ALow_b * PRIME_5_LOW)

			Digest += Mult_b

			local Rotated_b = bit32.lrotate(Digest, 11)
			local AHigh_rb, ALow_rb = bit32.rshift(Rotated_b, 16), Rotated_b % 65536
			Digest = bit32.lshift((AHigh_rb * PRIME_1_LOW) + (ALow_rb * PRIME_1_HIGH), 16) + (ALow_rb * PRIME_1_LOW)
		end
		CurrentOffset += 1
	end

	local XorResult1 = bit32.bxor(Digest, bit32.rshift(Digest, 15))
	local AHigh_f1, ALow_f1 = bit32.rshift(XorResult1, 16), XorResult1 % 65536
	Digest = bit32.lshift((AHigh_f1 * PRIME_2_LOW) + (ALow_f1 * PRIME_2_HIGH), 16) + (ALow_f1 * PRIME_2_LOW)

	local XorResult2 = bit32.bxor(Digest, bit32.rshift(Digest, 13))
	local AHigh_f2, ALow_f2 = bit32.rshift(XorResult2, 16), XorResult2 % 65536
	Digest = bit32.lshift((AHigh_f2 * PRIME_3_LOW) + (ALow_f2 * PRIME_3_HIGH), 16) + (ALow_f2 * PRIME_3_LOW)

	return bit32.bxor(Digest, bit32.rshift(Digest, 16))
end

return XXH32