--!strict
--!native
--!optimize 2

--- The front half of the initial values used for the hasher state.
local IV_FRONT = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
--- The back half of the initial values used for the hasher state.
local IV_BACK = { 0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1, 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179 }

--- A list of offsets to use for each round in the compression algorithm.
local SIGMA = {
	{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
	{ 15, 11, 5, 9, 10, 16, 14, 7, 2, 13, 1, 3, 12, 8, 6, 4 },
	{ 12, 9, 13, 1, 6, 3, 16, 14, 11, 15, 4, 7, 8, 2, 10, 5 },
	{ 8, 10, 4, 2, 14, 13, 12, 15, 3, 7, 6, 11, 5, 1, 16, 9 },
	{ 10, 1, 6, 8, 3, 5, 11, 16, 15, 2, 12, 13, 7, 9, 4, 14 },
	{ 3, 13, 7, 11, 1, 12, 9, 4, 5, 14, 8, 6, 16, 15, 2, 10 },
	{ 13, 6, 2, 16, 15, 14, 5, 11, 1, 8, 7, 4, 10, 3, 9, 12 },
	{ 14, 12, 8, 15, 13, 2, 4, 10, 6, 1, 16, 5, 9, 7, 3, 11 },
	{ 7, 16, 15, 10, 12, 4, 1, 9, 13, 3, 14, 8, 2, 5, 11, 6 },
	{ 11, 3, 9, 5, 8, 7, 2, 6, 16, 12, 10, 15, 4, 13, 14, 1 },
	-- There are two additional rounds of compression in blake2b
	{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
	{ 15, 11, 5, 9, 10, 16, 14, 7, 2, 13, 1, 3, 12, 8, 6, 4 },
}

--[=[
	The BLAKE2b compression function.

	@param h_front The front half of the internal digest for the algorithm
	@param h_back The back half of the internal digest for the algorithm
	@param m A block of bytes utilized for rounds
	@param t A counter for how many bytes fed into the hasher so far, including this set
	@param f Whether or not this call is the final one
]=]
local function F(
	h_front: { number },
	h_back: { number },
	m_front: { number },
	m_back: { number },
	t: number,
	f: boolean
)
	--stylua: ignore start
	local v_front_1, v_front_2, v_front_3, v_front_4, v_front_5, v_front_6, v_front_7, v_front_8, v_front_9, v_front_10, v_front_11, v_front_12, v_front_13, v_front_14, v_front_15, v_front_16 =
		h_front[1], h_front[2], h_front[3], h_front[4], h_front[5], h_front[6], h_front[7], h_front[8],
		IV_FRONT[1], IV_FRONT[2], IV_FRONT[3], IV_FRONT[4], IV_FRONT[5], IV_FRONT[6], IV_FRONT[7], IV_FRONT[8]
	local v_back_1, v_back_2, v_back_3, v_back_4, v_back_5, v_back_6, v_back_7, v_back_8, v_back_9, v_back_10, v_back_11, v_back_12, v_back_13, v_back_14, v_back_15, v_back_16 =
		h_back[1], h_back[2], h_back[3], h_back[4], h_back[5], h_back[6], h_back[7], h_back[8],
		IV_BACK[1], IV_BACK[2], IV_BACK[3], IV_BACK[4], IV_BACK[5], IV_BACK[6], IV_BACK[7], IV_BACK[8]
	--stylua: ignore end

	v_front_13 = bit32.bxor(v_front_13, t // 2 ^ 32)
	v_back_13 = bit32.bxor(v_back_13, t)
	-- We are never going to handle inputs of greater than 2^50.
	-- So we don't *need* to handle the upper half of the length
	-- It would be `v[14] = v[14] XOR t_upper` though.
	if f then
		v_front_15 = bit32.bnot(v_front_15)
		v_back_15 = bit32.bnot(v_back_15)
	end

	-- Luau's cost function is, unfortunately, rather conservative.
	-- It's a 20-60% uplift in performance to inline these functions so...
	-- I'm sorry that you have to look at this.
	-- I've left them in `do` blocks so that it's easy to hide but here's
	-- 300 lines of mixing.
	local temp = 0
	local x_front, x_back = 0, 0
	local y_front, y_back = 0, 0
	--stylua: ignore
	for _, s in SIGMA do
		-- v_front_1, v_back_1, v_front_5, v_back_5, v_front_9, v_back_9, v_front_13, v_back_13 = G(v_front_1, v_back_1, v_front_5, v_back_5, v_front_9, v_back_9, v_front_13, v_back_13, m_front[s[1]], m_back[s[1]], m_front[s[2]], m_back[s[2]])
		do
			x_front, x_back = m_front[s[1]], m_back[s[1]]
			y_front, y_back = m_front[s[2]], m_back[s[2]]

			temp = v_back_1 + v_back_5 + x_back
			v_front_1 = v_front_1 + v_front_5 + x_front + temp // 2 ^ 32
			v_back_1 = temp % 2 ^ 32
		
			temp = v_front_13
			v_front_13 = bit32.bxor(v_back_13, v_back_1)
			v_back_13 = bit32.bxor(temp, v_front_1)
			
			temp = v_back_9 + v_back_13
			v_front_9 = v_front_9 + v_front_13 + temp // 2 ^ 32
			v_back_9 = temp % 2 ^ 32
		
			temp = v_front_5
			v_front_5 = bit32.bxor(bit32.rshift(v_front_5, 24), bit32.lshift(v_back_5, 8), bit32.rshift(v_front_9, 24), bit32.lshift(v_back_9, 8))
			v_back_5 = bit32.bxor(bit32.rshift(v_back_5, 24), bit32.lshift(temp, 8), bit32.rshift(v_back_9, 24), bit32.lshift(v_front_9, 8))
			
			temp = v_back_1 + v_back_5 + y_back
			v_front_1 = v_front_1 + v_front_5 + y_front + temp // 2 ^ 32
			v_back_1 = temp % 2 ^ 32
		
			temp = v_front_13
			v_front_13 = bit32.bxor(bit32.rshift(v_front_13, 16), bit32.lshift(v_back_13, 16), bit32.rshift(v_front_1, 16), bit32.lshift(v_back_1, 16))
			v_back_13 = bit32.bxor(bit32.rshift(v_back_13, 16), bit32.lshift(temp, 16), bit32.rshift(v_back_1, 16), bit32.lshift(v_front_1, 16))
			
			temp = v_back_9 + v_back_13
			v_front_9 = v_front_9 + v_front_13 + temp // 2 ^ 32
			v_back_9 = temp % 2 ^ 32
		
			temp = v_front_5
			v_front_5 = bit32.bxor(bit32.lshift(v_front_5, 1), bit32.rshift(v_back_5, 31), bit32.lshift(v_front_9, 1), bit32.rshift(v_back_9, 31))
			v_back_5 = bit32.bxor(bit32.lshift(v_back_5, 1), bit32.rshift(temp, 31), bit32.lshift(v_back_9, 1), bit32.rshift(v_front_9, 31))
		end
		
		-- v_front_2, v_back_2, v_front_6, v_back_6, v_front_10, v_back_10, v_front_14, v_back_14 = G(v_front_2, v_back_2, v_front_6, v_back_6, v_front_10, v_back_10, v_front_14, v_back_14, m_front[s[3]], m_back[s[3]], m_front[s[4]], m_back[s[4]])
		do
			x_front, x_back = m_front[s[3]], m_back[s[3]]
			y_front, y_back = m_front[s[4]], m_back[s[4]]
		
			temp = v_back_2 + v_back_6 + x_back
			v_front_2 = v_front_2 + v_front_6 + x_front + temp // 2 ^ 32
			v_back_2 = temp % 2 ^ 32
		
			temp = v_front_14
			v_front_14 = bit32.bxor(v_back_14, v_back_2)
			v_back_14 = bit32.bxor(temp, v_front_2)
			
			temp = v_back_10 + v_back_14
			v_front_10 = v_front_10 + v_front_14 + temp // 2 ^ 32
			v_back_10 = temp % 2 ^ 32
		
			temp = v_front_6
			v_front_6 = bit32.bxor(bit32.rshift(v_front_6, 24), bit32.lshift(v_back_6, 8), bit32.rshift(v_front_10, 24), bit32.lshift(v_back_10, 8))
			v_back_6 = bit32.bxor(bit32.rshift(v_back_6, 24), bit32.lshift(temp, 8), bit32.rshift(v_back_10, 24), bit32.lshift(v_front_10, 8))
			
			temp = v_back_2 + v_back_6 + y_back
			v_front_2 = v_front_2 + v_front_6 + y_front + temp // 2 ^ 32
			v_back_2 = temp % 2 ^ 32
		
			temp = v_front_14
			v_front_14 = bit32.bxor(bit32.rshift(v_front_14, 16), bit32.lshift(v_back_14, 16), bit32.rshift(v_front_2, 16), bit32.lshift(v_back_2, 16))
			v_back_14 = bit32.bxor(bit32.rshift(v_back_14, 16), bit32.lshift(temp, 16), bit32.rshift(v_back_2, 16), bit32.lshift(v_front_2, 16))
			
			temp = v_back_10 + v_back_14
			v_front_10 = v_front_10 + v_front_14 + temp // 2 ^ 32
			v_back_10 = temp % 2 ^ 32
		
			temp = v_front_6
			v_front_6 = bit32.bxor(bit32.lshift(v_front_6, 1), bit32.rshift(v_back_6, 31), bit32.lshift(v_front_10, 1), bit32.rshift(v_back_10, 31))
			v_back_6 = bit32.bxor(bit32.lshift(v_back_6, 1), bit32.rshift(temp, 31), bit32.lshift(v_back_10, 1), bit32.rshift(v_front_10, 31))
		end
		
		-- v_front_3, v_back_3, v_front_7, v_back_7, v_front_11, v_back_11, v_front_15, v_back_15 = G(v_front_3, v_back_3, v_front_7, v_back_7, v_front_11, v_back_11, v_front_15, v_back_15, m_front[s[5]], m_back[s[5]], m_front[s[6]], m_back[s[6]])
		do
			x_front, x_back = m_front[s[5]], m_back[s[5]]
			y_front, y_back = m_front[s[6]], m_back[s[6]]
		
			temp = v_back_3 + v_back_7 + x_back
			v_front_3 = v_front_3 + v_front_7 + x_front + temp // 2 ^ 32
			v_back_3 = temp % 2 ^ 32
		
			temp = v_front_15
			v_front_15 = bit32.bxor(v_back_15, v_back_3)
			v_back_15 = bit32.bxor(temp, v_front_3)
			
			temp = v_back_11 + v_back_15
			v_front_11 = v_front_11 + v_front_15 + temp // 2 ^ 32
			v_back_11 = temp % 2 ^ 32
		
			temp = v_front_7
			v_front_7 = bit32.bxor(bit32.rshift(v_front_7, 24), bit32.lshift(v_back_7, 8), bit32.rshift(v_front_11, 24), bit32.lshift(v_back_11, 8))
			v_back_7 = bit32.bxor(bit32.rshift(v_back_7, 24), bit32.lshift(temp, 8), bit32.rshift(v_back_11, 24), bit32.lshift(v_front_11, 8))
			
			temp = v_back_3 + v_back_7 + y_back
			v_front_3 = v_front_3 + v_front_7 + y_front + temp // 2 ^ 32
			v_back_3 = temp % 2 ^ 32
		
			temp = v_front_15
			v_front_15 = bit32.bxor(bit32.rshift(v_front_15, 16), bit32.lshift(v_back_15, 16), bit32.rshift(v_front_3, 16), bit32.lshift(v_back_3, 16))
			v_back_15 = bit32.bxor(bit32.rshift(v_back_15, 16), bit32.lshift(temp, 16), bit32.rshift(v_back_3, 16), bit32.lshift(v_front_3, 16))
			
			temp = v_back_11 + v_back_15
			v_front_11 = v_front_11 + v_front_15 + temp // 2 ^ 32
			v_back_11 = temp % 2 ^ 32
		
			temp = v_front_7
			v_front_7 = bit32.bxor(bit32.lshift(v_front_7, 1), bit32.rshift(v_back_7, 31), bit32.lshift(v_front_11, 1), bit32.rshift(v_back_11, 31))
			v_back_7 = bit32.bxor(bit32.lshift(v_back_7, 1), bit32.rshift(temp, 31), bit32.lshift(v_back_11, 1), bit32.rshift(v_front_11, 31))
		end
		
		-- v_front_4, v_back_4, v_front_8, v_back_8, v_front_12, v_back_12, v_front_16, v_back_16 = G(v_front_4, v_back_4, v_front_8, v_back_8, v_front_12, v_back_12, v_front_16, v_back_16, m_front[s[7]], m_back[s[7]], m_front[s[8]], m_back[s[8]])
		do
			x_front, x_back = m_front[s[7]], m_back[s[7]]
			y_front, y_back = m_front[s[8]], m_back[s[8]]
		
			temp = v_back_4 + v_back_8 + x_back
			v_front_4 = v_front_4 + v_front_8 + x_front + temp // 2 ^ 32
			v_back_4 = temp % 2 ^ 32
		
			temp = v_front_16
			v_front_16 = bit32.bxor(v_back_16, v_back_4)
			v_back_16 = bit32.bxor(temp, v_front_4)
			
			temp = v_back_12 + v_back_16
			v_front_12 = v_front_12 + v_front_16 + temp // 2 ^ 32
			v_back_12 = temp % 2 ^ 32
		
			temp = v_front_8
			v_front_8 = bit32.bxor(bit32.rshift(v_front_8, 24), bit32.lshift(v_back_8, 8), bit32.rshift(v_front_12, 24), bit32.lshift(v_back_12, 8))
			v_back_8 = bit32.bxor(bit32.rshift(v_back_8, 24), bit32.lshift(temp, 8), bit32.rshift(v_back_12, 24), bit32.lshift(v_front_12, 8))
			
			temp = v_back_4 + v_back_8 + y_back
			v_front_4 = v_front_4 + v_front_8 + y_front + temp // 2 ^ 32
			v_back_4 = temp % 2 ^ 32
		
			temp = v_front_16
			v_front_16 = bit32.bxor(bit32.rshift(v_front_16, 16), bit32.lshift(v_back_16, 16), bit32.rshift(v_front_4, 16), bit32.lshift(v_back_4, 16))
			v_back_16 = bit32.bxor(bit32.rshift(v_back_16, 16), bit32.lshift(temp, 16), bit32.rshift(v_back_4, 16), bit32.lshift(v_front_4, 16))
			
			temp = v_back_12 + v_back_16
			v_front_12 = v_front_12 + v_front_16 + temp // 2 ^ 32
			v_back_12 = temp % 2 ^ 32
		
			temp = v_front_8
			v_front_8 = bit32.bxor(bit32.lshift(v_front_8, 1), bit32.rshift(v_back_8, 31), bit32.lshift(v_front_12, 1), bit32.rshift(v_back_12, 31))
			v_back_8 = bit32.bxor(bit32.lshift(v_back_8, 1), bit32.rshift(temp, 31), bit32.lshift(v_back_12, 1), bit32.rshift(v_front_12, 31))
		end
		
		-- v_front_1, v_back_1, v_front_6, v_back_6, v_front_11, v_back_11, v_front_16, v_back_16 = G(v_front_1, v_back_1, v_front_6, v_back_6, v_front_11, v_back_11, v_front_16, v_back_16, m_front[s[9]], m_back[s[9]], m_front[s[10]], m_back[s[10]])
		do
			x_front, x_back = m_front[s[9]], m_back[s[9]]
			y_front, y_back = m_front[s[10]], m_back[s[10]]
		
			temp = v_back_1 + v_back_6 + x_back
			v_front_1 = v_front_1 + v_front_6 + x_front + temp // 2 ^ 32
			v_back_1 = temp % 2 ^ 32
		
			temp = v_front_16
			v_front_16 = bit32.bxor(v_back_16, v_back_1)
			v_back_16 = bit32.bxor(temp, v_front_1)
			
			temp = v_back_11 + v_back_16
			v_front_11 = v_front_11 + v_front_16 + temp // 2 ^ 32
			v_back_11 = temp % 2 ^ 32
		
			temp = v_front_6
			v_front_6 = bit32.bxor(bit32.rshift(v_front_6, 24), bit32.lshift(v_back_6, 8), bit32.rshift(v_front_11, 24), bit32.lshift(v_back_11, 8))
			v_back_6 = bit32.bxor(bit32.rshift(v_back_6, 24), bit32.lshift(temp, 8), bit32.rshift(v_back_11, 24), bit32.lshift(v_front_11, 8))
			
			temp = v_back_1 + v_back_6 + y_back
			v_front_1 = v_front_1 + v_front_6 + y_front + temp // 2 ^ 32
			v_back_1 = temp % 2 ^ 32
		
			temp = v_front_16
			v_front_16 = bit32.bxor(bit32.rshift(v_front_16, 16), bit32.lshift(v_back_16, 16), bit32.rshift(v_front_1, 16), bit32.lshift(v_back_1, 16))
			v_back_16 = bit32.bxor(bit32.rshift(v_back_16, 16), bit32.lshift(temp, 16), bit32.rshift(v_back_1, 16), bit32.lshift(v_front_1, 16))
			
			temp = v_back_11 + v_back_16
			v_front_11 = v_front_11 + v_front_16 + temp // 2 ^ 32
			v_back_11 = temp % 2 ^ 32
		
			temp = v_front_6
			v_front_6 = bit32.bxor(bit32.lshift(v_front_6, 1), bit32.rshift(v_back_6, 31), bit32.lshift(v_front_11, 1), bit32.rshift(v_back_11, 31))
			v_back_6 = bit32.bxor(bit32.lshift(v_back_6, 1), bit32.rshift(temp, 31), bit32.lshift(v_back_11, 1), bit32.rshift(v_front_11, 31))
		end
		
		-- v_front_2, v_back_2, v_front_7, v_back_7, v_front_12, v_back_12, v_front_13, v_back_13 = G(v_front_2, v_back_2, v_front_7, v_back_7, v_front_12, v_back_12, v_front_13, v_back_13, m_front[s[11]], m_back[s[11]], m_front[s[12]], m_back[s[12]])
		do
			x_front, x_back = m_front[s[11]], m_back[s[11]]
			y_front, y_back = m_front[s[12]], m_back[s[12]]
		
			temp = v_back_2 + v_back_7 + x_back
			v_front_2 = v_front_2 + v_front_7 + x_front + temp // 2 ^ 32
			v_back_2 = temp % 2 ^ 32
		
			temp = v_front_13
			v_front_13 = bit32.bxor(v_back_13, v_back_2)
			v_back_13 = bit32.bxor(temp, v_front_2)
			
			temp = v_back_12 + v_back_13
			v_front_12 = v_front_12 + v_front_13 + temp // 2 ^ 32
			v_back_12 = temp % 2 ^ 32
		
			temp = v_front_7
			v_front_7 = bit32.bxor(bit32.rshift(v_front_7, 24), bit32.lshift(v_back_7, 8), bit32.rshift(v_front_12, 24), bit32.lshift(v_back_12, 8))
			v_back_7 = bit32.bxor(bit32.rshift(v_back_7, 24), bit32.lshift(temp, 8), bit32.rshift(v_back_12, 24), bit32.lshift(v_front_12, 8))
			
			temp = v_back_2 + v_back_7 + y_back
			v_front_2 = v_front_2 + v_front_7 + y_front + temp // 2 ^ 32
			v_back_2 = temp % 2 ^ 32
		
			temp = v_front_13
			v_front_13 = bit32.bxor(bit32.rshift(v_front_13, 16), bit32.lshift(v_back_13, 16), bit32.rshift(v_front_2, 16), bit32.lshift(v_back_2, 16))
			v_back_13 = bit32.bxor(bit32.rshift(v_back_13, 16), bit32.lshift(temp, 16), bit32.rshift(v_back_2, 16), bit32.lshift(v_front_2, 16))
			
			temp = v_back_12 + v_back_13
			v_front_12 = v_front_12 + v_front_13 + temp // 2 ^ 32
			v_back_12 = temp % 2 ^ 32
		
			temp = v_front_7
			v_front_7 = bit32.bxor(bit32.lshift(v_front_7, 1), bit32.rshift(v_back_7, 31), bit32.lshift(v_front_12, 1), bit32.rshift(v_back_12, 31))
			v_back_7 = bit32.bxor(bit32.lshift(v_back_7, 1), bit32.rshift(temp, 31), bit32.lshift(v_back_12, 1), bit32.rshift(v_front_12, 31))
		end
		
		-- v_front_3, v_back_3, v_front_8, v_back_8, v_front_9, v_back_9, v_front_14, v_back_14 = G(v_front_3, v_back_3, v_front_8, v_back_8, v_front_9, v_back_9, v_front_14, v_back_14, m_front[s[13]], m_back[s[13]], m_front[s[14]], m_back[s[14]])
		do
			x_front, x_back = m_front[s[13]], m_back[s[13]]
			y_front, y_back = m_front[s[14]], m_back[s[14]]
		
			temp = v_back_3 + v_back_8 + x_back
			v_front_3 = v_front_3 + v_front_8 + x_front + temp // 2 ^ 32
			v_back_3 = temp % 2 ^ 32
		
			temp = v_front_14
			v_front_14 = bit32.bxor(v_back_14, v_back_3)
			v_back_14 = bit32.bxor(temp, v_front_3)
			
			temp = v_back_9 + v_back_14
			v_front_9 = v_front_9 + v_front_14 + temp // 2 ^ 32
			v_back_9 = temp % 2 ^ 32
		
			temp = v_front_8
			v_front_8 = bit32.bxor(bit32.rshift(v_front_8, 24), bit32.lshift(v_back_8, 8), bit32.rshift(v_front_9, 24), bit32.lshift(v_back_9, 8))
			v_back_8 = bit32.bxor(bit32.rshift(v_back_8, 24), bit32.lshift(temp, 8), bit32.rshift(v_back_9, 24), bit32.lshift(v_front_9, 8))
			
			temp = v_back_3 + v_back_8 + y_back
			v_front_3 = v_front_3 + v_front_8 + y_front + temp // 2 ^ 32
			v_back_3 = temp % 2 ^ 32
		
			temp = v_front_14
			v_front_14 = bit32.bxor(bit32.rshift(v_front_14, 16), bit32.lshift(v_back_14, 16), bit32.rshift(v_front_3, 16), bit32.lshift(v_back_3, 16))
			v_back_14 = bit32.bxor(bit32.rshift(v_back_14, 16), bit32.lshift(temp, 16), bit32.rshift(v_back_3, 16), bit32.lshift(v_front_3, 16))
			
			temp = v_back_9 + v_back_14
			v_front_9 = v_front_9 + v_front_14 + temp // 2 ^ 32
			v_back_9 = temp % 2 ^ 32
		
			temp = v_front_8
			v_front_8 = bit32.bxor(bit32.lshift(v_front_8, 1), bit32.rshift(v_back_8, 31), bit32.lshift(v_front_9, 1), bit32.rshift(v_back_9, 31))
			v_back_8 = bit32.bxor(bit32.lshift(v_back_8, 1), bit32.rshift(temp, 31), bit32.lshift(v_back_9, 1), bit32.rshift(v_front_9, 31))
		end
		
		-- v_front_4, v_back_4, v_front_5, v_back_5, v_front_10, v_back_10, v_front_15, v_back_15 = G(v_front_4, v_back_4, v_front_5, v_back_5, v_front_10, v_back_10, v_front_15, v_back_15, m_front[s[15]], m_back[s[15]], m_front[s[16]], m_back[s[16]])
		do
			x_front, x_back = m_front[s[15]], m_back[s[15]]
			y_front, y_back = m_front[s[16]], m_back[s[16]]
		
			temp = v_back_4 + v_back_5 + x_back
			v_front_4 = v_front_4 + v_front_5 + x_front + temp // 2 ^ 32
			v_back_4 = temp % 2 ^ 32
		
			temp = v_front_15
			v_front_15 = bit32.bxor(v_back_15, v_back_4)
			v_back_15 = bit32.bxor(temp, v_front_4)
			
			temp = v_back_10 + v_back_15
			v_front_10 = v_front_10 + v_front_15 + temp // 2 ^ 32
			v_back_10 = temp % 2 ^ 32
		
			temp = v_front_5
			v_front_5 = bit32.bxor(bit32.rshift(v_front_5, 24), bit32.lshift(v_back_5, 8), bit32.rshift(v_front_10, 24), bit32.lshift(v_back_10, 8))
			v_back_5 = bit32.bxor(bit32.rshift(v_back_5, 24), bit32.lshift(temp, 8), bit32.rshift(v_back_10, 24), bit32.lshift(v_front_10, 8))
			
			temp = v_back_4 + v_back_5 + y_back
			v_front_4 = v_front_4 + v_front_5 + y_front + temp // 2 ^ 32
			v_back_4 = temp % 2 ^ 32
		
			temp = v_front_15
			v_front_15 = bit32.bxor(bit32.rshift(v_front_15, 16), bit32.lshift(v_back_15, 16), bit32.rshift(v_front_4, 16), bit32.lshift(v_back_4, 16))
			v_back_15 = bit32.bxor(bit32.rshift(v_back_15, 16), bit32.lshift(temp, 16), bit32.rshift(v_back_4, 16), bit32.lshift(v_front_4, 16))
			
			temp = v_back_10 + v_back_15
			v_front_10 = v_front_10 + v_front_15 + temp // 2 ^ 32
			v_back_10 = temp % 2 ^ 32
		
			temp = v_front_5
			v_front_5 = bit32.bxor(bit32.lshift(v_front_5, 1), bit32.rshift(v_back_5, 31), bit32.lshift(v_front_10, 1), bit32.rshift(v_back_10, 31))
			v_back_5 = bit32.bxor(bit32.lshift(v_back_5, 1), bit32.rshift(temp, 31), bit32.lshift(v_back_10, 1), bit32.rshift(v_front_10, 31))
		end
	end

	h_front[1] = bit32.bxor(h_front[1], v_front_1, v_front_9)
	h_back[1] = bit32.bxor(h_back[1], v_back_1, v_back_9)

	h_front[2] = bit32.bxor(h_front[2], v_front_2, v_front_10)
	h_back[2] = bit32.bxor(h_back[2], v_back_2, v_back_10)

	h_front[3] = bit32.bxor(h_front[3], v_front_3, v_front_11)
	h_back[3] = bit32.bxor(h_back[3], v_back_3, v_back_11)

	h_front[4] = bit32.bxor(h_front[4], v_front_4, v_front_12)
	h_back[4] = bit32.bxor(h_back[4], v_back_4, v_back_12)

	h_front[5] = bit32.bxor(h_front[5], v_front_5, v_front_13)
	h_back[5] = bit32.bxor(h_back[5], v_back_5, v_back_13)

	h_front[6] = bit32.bxor(h_front[6], v_front_6, v_front_14)
	h_back[6] = bit32.bxor(h_back[6], v_back_6, v_back_14)

	h_front[7] = bit32.bxor(h_front[7], v_front_7, v_front_15)
	h_back[7] = bit32.bxor(h_back[7], v_back_7, v_back_15)

	h_front[8] = bit32.bxor(h_front[8], v_front_8, v_front_16)
	h_back[8] = bit32.bxor(h_back[8], v_back_8, v_back_16)
end

--[=[
	Calculates the BLAKE2b hash of `message` and emits it as a hash of `outSize`
	bytes. If provided, `key` is used as a [pepper][Pepper] for the hash.

	@param message The string to perform the hashing algorithm on
	@param outSize The length of the returned value in bytes. Must be between 1 and 64.
	@param key A pepper to use when performing the hashing algorithm. Must be no longer than 64 bytes.

	@return The computed hash as a hexadecimal string. This string will be `outSize * 2` bytes long.

	[Pepper]: https://en.wikipedia.org/wiki/Pepper_(cryptography)
]=]
local function blake2b(message: string, outSize: number, key: string?): string
	local rKey = if key then key else ""
	local keyLen = #rKey

	assert(math.clamp(outSize, 1, 64) == outSize, "outSize must be in the range [1, 64]")
	assert(math.clamp(keyLen, 0, 64) == keyLen, "key length must be in the range [0, 64]")

	local h_front = table.clone(IV_FRONT)
	local h_back = table.clone(IV_BACK)
	h_back[1] = bit32.bxor(h_back[1], 0x0101_0000, bit32.lshift(keyLen, 8), outSize)

	local block_front = table.create(16)
	local block_back = table.create(16)
	local messageLen = #message
	local t = if keyLen > 0 then 128 else 0

	if keyLen > 0 then
		-- This is technically bad for performance, but I don't really care
		-- since it happens at most once per hash
		rKey ..= string.rep("\0", -keyLen + 128)
		local j = 1
		for i = 1, 16 do
			local h, g, f, e, d, c, b, a = string.byte(rKey, j, j + 7)
			block_front[i] = bit32.bor(bit32.lshift(a, 24), bit32.lshift(b, 16), bit32.lshift(c, 8), d)
			block_back[i] = bit32.bor(bit32.lshift(e, 24), bit32.lshift(f, 16), bit32.lshift(g, 8), h)
			j += 8
		end
		-- Special case: is there even a message?
		F(h_front, h_back, block_front, block_back, t, messageLen == 0)
	end

	local leftover = messageLen % 128
	-- If the message is an even multiple of 128, we need to cut ourselves short
	-- so that we don't skip the final block or process an empty one
	local offset = if leftover == 0 then 128 else leftover
	for i = 1, messageLen - offset, 128 do
		for j = 1, 16 do
			local h, g, f, e, d, c, b, a = string.byte(message, i, i + 7)
			block_front[j] = bit32.bor(bit32.lshift(a, 24), bit32.lshift(b, 16), bit32.lshift(c, 8), d)
			block_back[j] = bit32.bor(bit32.lshift(e, 24), bit32.lshift(f, 16), bit32.lshift(g, 8), h)
			i += 8
		end
		t += 128
		F(h_front, h_back, block_front, block_back, t, false)
	end

	-- We have to push at least one block, regardless of message length
	-- However, if there's a key and the message is empty, we need to skip it
	if keyLen == 0 or messageLen > 0 then
		-- TODO find out if this has a significant performance cost
		local messageSnippet = string.sub(message, -offset)
		local finalMessage = messageSnippet .. string.rep("\0", 128)

		local n = 0
		local i = 1
		for j = 1, 16 do
			n += 1
			local h, g, f, e, d, c, b, a = string.byte(finalMessage, i, i + 7)
			block_front[j] = bit32.bor(bit32.lshift(a, 24), bit32.lshift(b, 16), bit32.lshift(c, 8), d)
			block_back[j] = bit32.bor(bit32.lshift(e, 24), bit32.lshift(f, 16), bit32.lshift(g, 8), h)
			i += 8
		end
		F(h_front, h_back, block_front, block_back, t + #messageSnippet, true)
	end

	local digest = string.format(
		"%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		bit32.byteswap(h_back[1]),
		bit32.byteswap(h_front[1]),
		bit32.byteswap(h_back[2]),
		bit32.byteswap(h_front[2]),
		bit32.byteswap(h_back[3]),
		bit32.byteswap(h_front[3]),
		bit32.byteswap(h_back[4]),
		bit32.byteswap(h_front[4]),
		bit32.byteswap(h_back[5]),
		bit32.byteswap(h_front[5]),
		bit32.byteswap(h_back[6]),
		bit32.byteswap(h_front[6]),
		bit32.byteswap(h_back[7]),
		bit32.byteswap(h_front[7]),
		bit32.byteswap(h_back[8]),
		bit32.byteswap(h_front[8])
	)

	return string.sub(digest, 1, outSize * 2)
end

return blake2b