--!strict
--!native
--!optimize 2

local PRIME_1 = 0x9e3779B1
local PRIME_2 = 0x85ebca77
local PRIME_3 = 0xc2B2ae3d
local PRIME_4 = 0x27d4eb2f
local PRIME_5 = 0x165667b1

--[=[
    Calculates `a * b` mod 32
]=]
local function mult(a: number, b: number): number
	local ah, al = bit32.rshift(a, 16), a % 2 ^ 16
	local bh, bl = bit32.rshift(b, 16), b % 2 ^ 16
	return bit32.lshift((ah * bl) + (al * bh), 16) + (al * bl)
end

--[=[
	Computes the XXH32 hash for `message` and returns it. If specified, `seed`
	is used as a seed for the hash. It defaults to `0`.

	This function returns the 32-bit integer that's the result of the hash.
	
	@param message -- The message to compute the XXHASH32 of
	@param seed -- The seed to use for the hashing algorithm (defaults to `0`) 
]=]
local function xxhash32(message: string, seed: number?): number
	local rSeed = if seed == nil then 0 else bit32.bor(seed, 0)
	local messageLen = #message

	local wordC = 1

	local i = 1
	local digest
	if messageLen >= 16 then
		-- We don't need to worry about overflow for addition here
		local accum1 = rSeed + PRIME_1 + PRIME_2
		local accum2 = rSeed + PRIME_2
		local accum3 = rSeed
		local accum4 = rSeed - PRIME_1
		for _ = 0, messageLen - 16, 16 do
			--stylua: ignore start
			local d1, c1, b1, a1,
				d2, c2, b2, a2,
				d3, c3, b3, a3,
				d4, c4, b4, a4 = string.byte(message, i, i + 15)
			accum1 = mult(bit32.lrotate(accum1 + mult(bit32.bor(bit32.lshift(a1, 24), bit32.lshift(b1, 16), bit32.lshift(c1, 8), d1), PRIME_2), 13), PRIME_1)
			accum2 = mult(bit32.lrotate(accum2 + mult(bit32.bor(bit32.lshift(a2, 24), bit32.lshift(b2, 16), bit32.lshift(c2, 8), d2), PRIME_2), 13), PRIME_1)
			accum3 = mult(bit32.lrotate(accum3 + mult(bit32.bor(bit32.lshift(a3, 24), bit32.lshift(b3, 16), bit32.lshift(c3, 8), d3), PRIME_2), 13), PRIME_1)
			accum4 = mult(bit32.lrotate(accum4 + mult(bit32.bor(bit32.lshift(a4, 24), bit32.lshift(b4, 16), bit32.lshift(c4, 8), d4), PRIME_2), 13), PRIME_1)
			--stylua: ignore end
			wordC += 4
			i += 16
		end
		digest = bit32.lrotate(accum1, 1)
			+ bit32.lrotate(accum2, 7)
			+ bit32.lrotate(accum3, 12)
			+ bit32.lrotate(accum4, 18)
	else
		digest = bit32.bor(rSeed + PRIME_5, 0)
	end
	digest = bit32.bor(digest + messageLen, 0)

	for _ = wordC, messageLen // 4 do
		local d, c, b, a = string.byte(message, i, i + 3)
		--stylua: ignore
		digest += mult(bit32.bor(bit32.lshift(a, 24), bit32.lshift(b, 16), bit32.lshift(c, 8), d), PRIME_3)
		digest = mult(bit32.lrotate(digest, 17), PRIME_4)
		wordC += 1
		i += 4
	end

	for j = -(messageLen % 4), -1 do
		digest += mult(string.byte(message, j), PRIME_5)
		digest = mult(bit32.lrotate(digest, 11), PRIME_1)
	end

	digest = mult(bit32.bxor(digest, bit32.rshift(digest, 15)), PRIME_2)
	digest = mult(bit32.bxor(digest, bit32.rshift(digest, 13)), PRIME_3)
	digest = bit32.bxor(digest, bit32.rshift(digest, 16))

	return digest
end

return xxhash32