--!strict
--!native
--!optimize 2

local BLOCK_FRONT = table.create(80)
local BLOCK_BACK = table.create(80)

--stylua: ignore
local K_FRONT = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 0xca273ece, 
    0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5, 
    0x113f9804, 0x1b710b35, 0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 
    0x431d67c4, 0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c,
}

--stylua: ignore
local K_BACK = {
    0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc, 0xf348b538,
    0xb605d019, 0xaf194f9b, 0xda6d8118, 0xa3030242, 0x45706fbe,
    0x4ee4b28c, 0xd5ffb4e2, 0xf27b896f, 0x3b1696b1, 0x25c71235,
    0xcf692694, 0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65,
    0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5, 0xee66dfab,
    0x2db43210, 0x98fb213f, 0xbeef0ee4, 0x3da88fc2, 0x930aa725,
    0xe003826f, 0x0a0e6e70, 0x46d22ffc, 0x5c26c926, 0x5ac42aed,
    0x9d95b3df, 0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
    0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30, 0xd6ef5218,
    0x5565a910, 0x5771202a, 0x32bbd1b8, 0xb8d2d0c8, 0x5141ab53,
    0xdf8eeb99, 0xe19b48a8, 0xc5c95a63, 0xe3418acb, 0x7763e373,
    0xd6b2b8a3, 0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec,
    0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b, 0xea26619c,
    0x21c0c207, 0xcde0eb1e, 0xee6ed178, 0x72176fba, 0xa2c898a6,
    0xbef90dae, 0x131c471b, 0x23047d84, 0x40c72493, 0x15c9bebc,
    0x9c100d4c, 0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817,
}

--[=[
	The 'little sigma 0' function for the SHA-384 block fill operation.
]=]
local function lil_sig0(front: number, back: number): (number, number)
	-- (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
	-- rrotate(x, n) = (x >> n) | (x << 32 - n)
	-- rshift(x, n) = (x >> n)
	-- sig0(x) = rrotate(x, 1) ^ rrotate(x, 8) ^ rshift(x, 7)
	--         = (x >> 1 | x << 63) ^ (x >> 8 | x << 24) ^ (x >> 7)
	-- since XOR cancels out OR, we can just batch it all:
	--stylua: ignore
	return bit32.bxor(
		bit32.rshift(front, 1), bit32.lshift(back, 31), 
		bit32.rshift(front, 8), bit32.lshift(back, 24),
		bit32.rshift(front, 7)
	), bit32.bxor(
		bit32.rshift(back, 1), bit32.lshift(front, 31), 
		bit32.rshift(back, 8), bit32.lshift(front, 24),
		bit32.rshift(back, 7), bit32.lshift(front, 25)
	)
end

--[=[
	The 'little sigma 1' function for the SHA-384 block fill operation.
]=]
local function lil_sig1(front: number, back: number): (number, number)
	-- (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
	-- rrotate(x, n) = (x >> n) | (x << 32 - n) if x <= 32
	-- rrotate(x, n) = (n >> n % 32) | (n << (32 - n % 32)) if x > 32
	-- sig1(x) = rrotate(x, 19) ^ rrotate(x, 61) ^ rshift(x, 6)
	--         = (x >> 19 | x << 13) ^ (x >> 29 | x << 3) ^ (x >> 6)
	--stylua: ignore
	return bit32.bxor(
		bit32.rshift(front, 19), bit32.lshift(back, 13),
		bit32.lshift(front, 3), bit32.rshift(back, 29), -- Reversed
		bit32.rshift(front, 6)
	), bit32.bxor(
		bit32.rshift(back, 19), bit32.lshift(front, 13),
		bit32.lshift(back, 3), bit32.rshift(front, 29), -- Reversed
		bit32.rshift(back, 6), bit32.lshift(front, 26)
	)
end

--[=[
	The 'big sigma 0' function for the SHA-384 compression rounds.
]=]
local function big_sig0(front: number, back: number): (number, number)
	--(a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
	-- Sig0(x) = (x >> 28) | x >> 4) ^ (x >> 2 | x << 30) ^ (x >> 7 | x << 25)
	--stylua: ignore
	return bit32.bxor(
		bit32.rshift(front, 28), bit32.lshift(back, 4),
		bit32.lshift(front, 30), bit32.rshift(back, 2), -- Reversed
		bit32.lshift(front, 25), bit32.rshift(back, 7) -- Reversed
	), bit32.bxor(
		bit32.rshift(back, 28), bit32.lshift(front, 4),
		bit32.lshift(back, 30), bit32.rshift(front, 2), -- Reversed
		bit32.lshift(back, 25), bit32.rshift(front, 7) -- Reversed
	)
end

--[=[
	The 'big sigma 1' function for the SHA-384 compression rounds.
]=]
local function big_sig1(front: number, back: number): (number, number)
	--(e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
	-- Sig1(x) = (x >> 14 | x << 18) ^ (x >> 18 | x << 14) ^ (x >> 9 | x << 23)
	--stylua: ignore
	return bit32.bxor(
		bit32.rshift(front, 14), bit32.lshift(back, 18),
		bit32.rshift(front, 18), bit32.lshift(back, 14),
		bit32.lshift(front, 23), bit32.rshift(back, 9) -- Reversed
	), bit32.bxor(
		bit32.rshift(back, 14), bit32.lshift(front, 18),
		bit32.rshift(back, 18), bit32.lshift(front, 14),
		bit32.lshift(back, 23), bit32.rshift(front, 9) -- Reversed
	)
end

--[=[
	Proceeses `message` as block of 128 bytes from `start` to `finish`.

	Expects that `(finish - start) % 128 == 0`.
]=]
local function processBlocks(
	digestFront: { number },
	digestBack: { number },
	message: string,
	start: number,
	finish: number
)
	local block_front = BLOCK_FRONT
	local block_back = BLOCK_BACK

	local d1_front, d2_front, d3_front, d4_front = digestFront[1], digestFront[2], digestFront[3], digestFront[4]
	local d5_front, d6_front, d7_front, d8_front = digestFront[5], digestFront[6], digestFront[7], digestFront[8]

	local d1_back, d2_back, d3_back, d4_back = digestBack[1], digestBack[2], digestBack[3], digestBack[4]
	local d5_back, d6_back, d7_back, d8_back = digestBack[5], digestBack[6], digestBack[7], digestBack[8]

	for i = start, finish, 128 do
		for t = 1, 16 do
			local a, b, c, d, e, f, g, h = string.byte(message, i, i + 7)
			block_front[t] = bit32.bor(bit32.lshift(a, 24), bit32.lshift(b, 16), bit32.lshift(c, 8), d)
			block_back[t] = bit32.bor(bit32.lshift(e, 24), bit32.lshift(f, 16), bit32.lshift(g, 8), h)
			i += 8
		end

		for t = 17, 80 do
			local s0_front, s0_back = lil_sig0(block_front[t - 15], block_back[t - 15])
			local s1_front, s1_back = lil_sig1(block_front[t - 2], block_back[t - 2])

			local temp = block_back[t - 16] + s0_back + block_back[t - 7] + s1_back
			-- We are meant to be performing addition here, but are not
			-- properly carrying bits. So, we have to simulate that.
			-- This is the equivalent to temp & 0xFFFF_FFFF, which
			-- truncates the integer for us.
			block_back[t] = bit32.bor(temp, 0)

			block_front[t] = block_front[t - 16]
				+ s0_front
				+ block_front[t - 7]
				+ s1_front
				-- After that, any leftover bits are shifted down until
				-- they can be added safely
				+ temp // 2 ^ 32

			-- block_front[t] %= 2 ^ 32 -- unnecessary but good for debugging
		end

		local a_front, b_front, c_front, d_front = d1_front, d2_front, d3_front, d4_front
		local e_front, f_front, g_front, h_front = d5_front, d6_front, d7_front, d8_front
		local a_back, b_back, c_back, d_back = d1_back, d2_back, d3_back, d4_back
		local e_back, f_back, g_back, h_back = d5_back, d6_back, d7_back, d8_back

		for t = 1, 80 do
			--Ch(e, f, g) = bit32.band(e, f) + bit32.band(-1 - e, g)
			--Maj(a, b, c) = bit32.band(c, b) + bit32.band(a, bit32.bxor(c, b))
			local s0_front, s0_back = big_sig0(a_front, a_back)
			local s1_front, s1_back = big_sig1(e_front, e_back)

			--stylua: ignore start
			-- h + S1 + Ch(e, f, g) + K[t] + W[t]
			local temp1_back = h_back + s1_back + bit32.bor(bit32.band(e_back, f_back), bit32.band(-1 - e_back, g_back), 0) + K_BACK[t] + block_back[t]
			local temp1_front = h_front + s1_front + bit32.bor(bit32.band(e_front, f_front), bit32.band(-1 - e_front, g_front), 0) + K_FRONT[t] + block_front[t] + temp1_back // 2 ^ 32
			temp1_back = bit32.bor(temp1_back, 0)

			-- S0 + Maj
			local temp2_back = s0_back + bit32.band(c_back, b_back) + bit32.band(a_back, bit32.bxor(c_back, b_back))
			local temp2_front = s0_front + bit32.band(c_front, b_front) + bit32.band(a_front, bit32.bxor(c_front, b_front))
			--stylua: ignore end

			h_front, h_back = g_front, g_back
			g_front, g_back = f_front, f_back
			f_front, f_back = e_front, e_back

			e_back = temp1_back + d_back
			e_front = temp1_front + d_front + e_back // 2 ^ 32
			e_back = bit32.bor(e_back, 0)

			d_front, d_back = c_front, c_back
			c_front, c_back = b_front, b_back
			b_front, b_back = a_front, a_back

			a_back = temp1_back + temp2_back
			a_front = temp1_front + temp2_front + a_back // 2 ^ 32
			a_back = bit32.bor(a_back, 0)
		end

		d1_back = d1_back + a_back
		d1_front = bit32.bor(d1_front + a_front + d1_back // 2 ^ 32, 0)
		d1_back = bit32.bor(d1_back, 0)

		d2_back = d2_back + b_back
		d2_front = bit32.bor(d2_front + b_front + d2_back // 2 ^ 32, 0)
		d2_back = bit32.bor(d2_back, 0)

		d3_back = d3_back + c_back
		d3_front = bit32.bor(d3_front + c_front + d3_back // 2 ^ 32, 0)
		d3_back = bit32.bor(d3_back, 0)

		d4_back = d4_back + d_back
		d4_front = bit32.bor(d4_front + d_front + d4_back // 2 ^ 32, 0)
		d4_back = bit32.bor(d4_back, 0)

		d5_back = d5_back + e_back
		d5_front = bit32.bor(d5_front + e_front + d5_back // 2 ^ 32, 0)
		d5_back = bit32.bor(d5_back, 0)

		d6_back = d6_back + f_back
		d6_front = bit32.bor(d6_front + f_front + d6_back // 2 ^ 32, 0)
		d6_back = bit32.bor(d6_back, 0)

		d7_back = d7_back + g_back
		d7_front = bit32.bor(d7_front + g_front + d7_back // 2 ^ 32, 0)
		d7_back = bit32.bor(d7_back, 0)

		d8_back = d8_back + h_back
		d8_front = bit32.bor(d8_front + h_front + d8_back // 2 ^ 32, 0)
		d8_back = bit32.bor(d8_back, 0)
	end

	digestFront[1], digestBack[1] = d1_front, d1_back
	digestFront[2], digestBack[2] = d2_front, d2_back
	digestFront[3], digestBack[3] = d3_front, d3_back
	digestFront[4], digestBack[4] = d4_front, d4_back
	digestFront[5], digestBack[5] = d5_front, d5_back
	digestFront[6], digestBack[6] = d6_front, d6_back
	digestFront[7], digestBack[7] = d7_front, d7_back
	digestFront[8], digestBack[8] = d8_front, d8_back
end

--[=[
	Computes the SHA-384 hash for `message` and returns it.
	This function returns both a hexadecimal encoded string of the hash
	and returns a **read-only** table containing twelve 32-bit integers
	that make up the hash.

	This functions will raise an error if the message passed is over `2^50` bytes
	in length. This is due to a Luau limitation.
	
	@param message -- The payload to compute the SHA-384 hash of
	@return string -- The computed SHA-384 hash as a string of hexadecimal digits
	@return {number} -- The computed SHA-384 hash as an array of 12 integers
]=]
local function sha384(message: string): (string, { number })
	local digest_front =
		{ 0xcbbb9d5d, 0x629a292a, 0x9159015a, 0x152fecd8, 0x67332667, 0x8eb44a87, 0xdb0c2e0d, 0x47b5481d }
	local digest_back =
		{ 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 }

	local messageLen = #message
	-- The max exactly representable value of a double is 2^53
	-- We need to multiply the length of a number by 8 though
	-- So, 2^53 / 8 = 2 ^ 50 = max supported size
	-- In practice, this is almost 26 terabytes of data
	-- Which is technically possible but why would you pass that through
	-- a Luau function?
	if messageLen > 2 ^ 50 then
		error("cannot calculate the SHA-384 hash of a string longer than 2^50 bytes", 2)
	end

	-- SHA-384 has a block size of 1024 bits or 128 bytes
	local leftover = messageLen % 128
	if messageLen >= 128 then
		processBlocks(digest_front, digest_back, message, 1, messageLen - leftover)
	end

	-- Raise `leftover` to next multiple of 128 so that we can calculate
	-- how much padding we need without a branch or loop.
	-- The number here is just masking off the last 6 bits.
	local nextMultipleOf128 = bit32.band(leftover + 64, 0xfffff000)

	local finalMessage = {
		if leftover ~= 0 then string.sub(message, -leftover) else "",
		"\x80",
		string.rep("\0", (nextMultipleOf128 - leftover - 17) % 128),
		string.pack(">L", messageLen * 8 / 2 ^ 32),
		string.pack(">L", bit32.bor(messageLen * 8)),
	}
	local finalBlock = table.concat(finalMessage)
	processBlocks(digest_front, digest_back, finalBlock, 1, #finalBlock)

	local merged = table.create(16)
	for i = 1, 6 do
		merged[2 * i - 1] = digest_front[i]
		merged[2 * i] = digest_back[i]
	end

    --stylua: ignore
	return string.format(
		"%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		digest_front[1], digest_back[1],
		digest_front[2], digest_back[2],
		digest_front[3], digest_back[3],
		digest_front[4], digest_back[4],
		digest_front[5], digest_back[5],
		digest_front[6], digest_back[6]
	), table.freeze(merged)
end

return sha384