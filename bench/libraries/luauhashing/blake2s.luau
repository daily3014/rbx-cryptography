--!strict
--!native
--!optimize 2

--- The initial values used for the hasher state.
local IV = { 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 }

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
}

--[=[
	The BLAKE2s compression function.

	@param h The internal digest for the algorithm
	@param m A block of bytes utilized for rounds
	@param t A counter for how many bytes fed into the hasher so far, including this set
	@param f Whether or not this call is the final one
]=]
local function F(h: { number }, m: { number }, t: number, f: boolean)
	-- Conventional wisdom is to use an array here but that's awful for
	-- performance. So, we do it with 16 variables.
	-- Registries suffer but that's a small price to pay.
	local v01, v02, v03, v04, v05, v06, v07, v08 = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
	local v09, v10, v11, v12, v13, v14, v15, v16 = IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7], IV[8]
	v13 = bit32.bxor(v13, t)
	-- this is not using an rshift because `t` might be very big
	v14 = bit32.bxor(v14, t // 2 ^ 32)
	if f then
		v15 = bit32.bnot(v15)
	end

	-- G is a mixer function for the lanes of a block.
	-- It's defined inline here for performance.
	for _, s in SIGMA do
		-- G(v, 1, 5, 9, 13, m[s[1]], m[s[2]])
		v01 += v05 + m[s[1]]
		v13 = bit32.rrotate(bit32.bxor(v13, v01), 16)
		v09 += v13
		v05 = bit32.rrotate(bit32.bxor(v05, v09), 12)
		v01 += v05 + m[s[2]]
		v13 = bit32.rrotate(bit32.bxor(v13, v01), 8)
		v09 += v13
		v05 = bit32.rrotate(bit32.bxor(v05, v09), 7)

		-- G(v, 2, 6, 10, 14, m[s[3]], m[s[4]])
		v02 += v06 + m[s[3]]
		v14 = bit32.rrotate(bit32.bxor(v14, v02), 16)
		v10 += v14
		v06 = bit32.rrotate(bit32.bxor(v06, v10), 12)
		v02 += v06 + m[s[4]]
		v14 = bit32.rrotate(bit32.bxor(v14, v02), 8)
		v10 += v14
		v06 = bit32.rrotate(bit32.bxor(v06, v10), 7)

		-- G(v, 3, 7, 11, 15, m[s[5]], m[s[6]])
		v03 += v07 + m[s[5]]
		v15 = bit32.rrotate(bit32.bxor(v15, v03), 16)
		v11 += v15
		v07 = bit32.rrotate(bit32.bxor(v07, v11), 12)
		v03 += v07 + m[s[6]]
		v15 = bit32.rrotate(bit32.bxor(v15, v03), 8)
		v11 += v15
		v07 = bit32.rrotate(bit32.bxor(v07, v11), 7)

		-- G(v, 4, 8, 12, 16, m[s[7]], m[s[8]])
		v04 += v08 + m[s[7]]
		v16 = bit32.rrotate(bit32.bxor(v16, v04), 16)
		v12 += v16
		v08 = bit32.rrotate(bit32.bxor(v08, v12), 12)
		v04 += v08 + m[s[8]]
		v16 = bit32.rrotate(bit32.bxor(v16, v04), 8)
		v12 += v16
		v08 = bit32.rrotate(bit32.bxor(v08, v12), 7)

		-- G(v, 1, 6, 11, 16, m[s[9]], m[s[10]])
		v01 += v06 + m[s[9]]
		v16 = bit32.rrotate(bit32.bxor(v16, v01), 16)
		v11 += v16
		v06 = bit32.rrotate(bit32.bxor(v06, v11), 12)
		v01 += v06 + m[s[10]]
		v16 = bit32.rrotate(bit32.bxor(v16, v01), 8)
		v11 += v16
		v06 = bit32.rrotate(bit32.bxor(v06, v11), 7)

		-- G(v, 2, 7, 12, 13, m[s[11]], m[s[12]])
		v02 += v07 + m[s[11]]
		v13 = bit32.rrotate(bit32.bxor(v13, v02), 16)
		v12 += v13
		v07 = bit32.rrotate(bit32.bxor(v07, v12), 12)
		v02 += v07 + m[s[12]]
		v13 = bit32.rrotate(bit32.bxor(v13, v02), 8)
		v12 += v13
		v07 = bit32.rrotate(bit32.bxor(v07, v12), 7)

		-- G(v, 3, 8, 9, 14, m[s[13]], m[s[14]])
		v03 += v08 + m[s[13]]
		v14 = bit32.rrotate(bit32.bxor(v14, v03), 16)
		v09 += v14
		v08 = bit32.rrotate(bit32.bxor(v08, v09), 12)
		v03 += v08 + m[s[14]]
		v14 = bit32.rrotate(bit32.bxor(v14, v03), 8)
		v09 += v14
		v08 = bit32.rrotate(bit32.bxor(v08, v09), 7)

		-- G(v, 4, 5, 10, 15, m[s[15]], m[s[16]])
		v04 += v05 + m[s[15]]
		v15 = bit32.rrotate(bit32.bxor(v15, v04), 16)
		v10 += v15
		v05 = bit32.rrotate(bit32.bxor(v05, v10), 12)
		v04 += v05 + m[s[16]]
		v15 = bit32.rrotate(bit32.bxor(v15, v04), 8)
		v10 += v15
		v05 = bit32.rrotate(bit32.bxor(v05, v10), 7)
	end

	h[1] = bit32.bxor(h[1], v01, v09)
	h[2] = bit32.bxor(h[2], v02, v10)
	h[3] = bit32.bxor(h[3], v03, v11)
	h[4] = bit32.bxor(h[4], v04, v12)
	h[5] = bit32.bxor(h[5], v05, v13)
	h[6] = bit32.bxor(h[6], v06, v14)
	h[7] = bit32.bxor(h[7], v07, v15)
	h[8] = bit32.bxor(h[8], v08, v16)
end

--[=[
	Calculates the BLAKE2s hash of `message` and emits it as a hash of `outSize`
	bytes. If provided, `key` is used as a [pepper][Pepper] for the hash.

	@param message The string to perform the hashing algorithm on
	@param outSize The length of the returned value in bytes. Must be between 1 and 32.
	@param key A pepper to use when performing the hashing algorithm. Must be no longer than 32 bytes.

	@return The computed hash as a hexadecimal string. This string will be `outSize * 2` bytes long.

	[Pepper]: https://en.wikipedia.org/wiki/Pepper_(cryptography)
]=]
local function blake2s(message: string, outSize: number, key: string?): string
	local rKey = if key then key else ""
	local keyLen = #rKey

	assert(math.clamp(outSize, 1, 32) == outSize, "outSize must be in the range [1, 32]")
	assert(math.clamp(keyLen, 0, 32) == keyLen, "key length must be in the range [0, 32]")

	local h = table.clone(IV)
	h[1] = bit32.bxor(h[1], 0x0101_0000, bit32.lshift(keyLen, 8), outSize)

	local block = table.create(16)
	local messageLen = #message
	local t = if keyLen > 0 then 64 else 0

	if keyLen > 0 then
		-- This is technically bad for performance, but I don't really care
		-- since it happens at most once per hash
		rKey ..= string.rep("\0", -keyLen + 64)
		local j = 1
		for i = 1, 16 do
			local d, c, b, a = string.byte(rKey, j, j + 3)
			block[i] = bit32.bor(bit32.lshift(a, 24), bit32.lshift(b, 16), bit32.lshift(c, 8), d)
			j += 4
		end
		-- Special case: is there even a message?
		F(h, block, 64, messageLen == 0)
	end

	local leftover = messageLen % 64
	-- If the message is an even multiple of 64, we need to cut ourselves short
	-- so that we don't skip the final block or process an empty one
	local offset = if leftover == 0 then 64 else leftover
	for i = 1, messageLen - offset, 64 do
		for j = 1, 16 do
			local d, c, b, a = string.byte(message, i, i + 3)
			block[j] = bit32.bor(bit32.lshift(a, 24), bit32.lshift(b, 16), bit32.lshift(c, 8), d)
			i += 4
		end
		t += 64
		F(h, block, t, false)
	end

	-- We have to push at least one block, regardless of message length
	-- However, if there's a key and the message is empty, we need to skip it
	if keyLen == 0 or messageLen > 0 then
		-- TODO find out if this has a significant performance cost
		local messageSnippet = string.sub(message, -offset)
		local finalMessage = messageSnippet .. string.rep("\0", 64)

		local i = 1
		for j = 1, 16 do
			local d, c, b, a = string.byte(finalMessage, i, i + 3)
			block[j] = bit32.bor(bit32.lshift(a, 24), bit32.lshift(b, 16), bit32.lshift(c, 8), d)
			i += 4
		end
		F(h, block, t + #messageSnippet, true)
	end

	-- TODO efficiency
	local digest = string.format(
		"%08x%08x%08x%08x%08x%08x%08x%08x",
		bit32.byteswap(h[1]),
		bit32.byteswap(h[2]),
		bit32.byteswap(h[3]),
		bit32.byteswap(h[4]),
		bit32.byteswap(h[5]),
		bit32.byteswap(h[6]),
		bit32.byteswap(h[7]),
		bit32.byteswap(h[8])
	)

	return string.sub(digest, 1, outSize * 2)
end

return blake2s