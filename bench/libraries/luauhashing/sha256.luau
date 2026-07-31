--!strict
--!native
--!optimize 2

--stylua: ignore
local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

--- An allocation that is reused for blocks during hashing
local BLOCK = table.create(64)

--[=[
	Processes `message` from byte `start` to byte `finish` using `digest`.
	It is assumed that `(finish - start) % 64 == 0`.
]=]
local function processBlocks(digest: { number }, message: string, start: number, finish: number)
	local block = BLOCK
	local d1, d2, d3, d4 = digest[1], digest[2], digest[3], digest[4]
	local d5, d6, d7, d8 = digest[5], digest[6], digest[7], digest[8]

	for i = start, finish, 64 do
		-- Fill `block`
		for t = 1, 16 do
			local a, b, c, d = string.byte(message, i, i + 3)
			block[t] = bit32.bor(bit32.lshift(a, 24), bit32.lshift(b, 16), bit32.lshift(c, 8), d)
			i += 4
		end
		for t = 17, 64 do
			local b2 = block[t - 2]
			local b15 = block[t - 15]
			block[t] = bit32.bxor(bit32.rrotate(b2, 17), bit32.rrotate(b2, 19), bit32.rshift(b2, 10))
				+ block[t - 7]
				+ bit32.bxor(bit32.rrotate(b15, 7), bit32.rrotate(b15, 18), bit32.rshift(b15, 3))
				+ block[t - 16]
		end

		local a, b, c, d = d1, d2, d3, d4
		local e, f, g, h = d5, d6, d7, d8
		local temp1, temp2
		for t = 1, 64 do
			-- h + bsig1(e) + ch(e, f, g) + K[t] + block[t]
			-- bsig1(e) = bit32.bxor(bit32.rrotate(e, 6), bit32.rrotate(e, 11), bit32.rrotate(e, 25))
			-- ch(e, f, g) = bit32.band(e, f) + bit32.band(-1 - e, g)
			temp1 = h
				+ bit32.bxor(bit32.rrotate(e, 6), bit32.rrotate(e, 11), bit32.rrotate(e, 25))
				+ bit32.band(e, f)
				+ bit32.band(bit32.bnot(e), g)
				+ K[t]
				+ block[t]
			-- bsig0(a) + maj(a, b, c)
			-- bsig0(a) = bit32.bxor(bit32.rrotate(a, 2), bit32.rrotate(a, 13), bit32.rrotate(a, 22))
			-- maj(a, b, c) = bit32.band(c, b) + bit32.band(a, bit32.bxor(c, b))
			temp2 = bit32.band(c, b)
				+ bit32.band(a, bit32.bxor(c, b))
				+ bit32.bxor(bit32.rrotate(a, 2), bit32.rrotate(a, 13), bit32.rrotate(a, 22))
			h = g
			g = f
			f = e
			e = d + temp1
			d = c
			c = b
			b = a
			a = temp1 + temp2
		end

		d1 = bit32.bor(a + d1, 0)
		d2 = bit32.bor(b + d2, 0)
		d3 = bit32.bor(c + d3, 0)
		d4 = bit32.bor(d + d4, 0)
		d5 = bit32.bor(e + d5, 0)
		d6 = bit32.bor(f + d6, 0)
		d7 = bit32.bor(g + d7, 0)
		d8 = bit32.bor(h + d8, 0)
	end

	digest[1] = d1
	digest[2] = d2
	digest[3] = d3
	digest[4] = d4
	digest[5] = d5
	digest[6] = d6
	digest[7] = d7
	digest[8] = d8
end

--[=[
	Computes the SHA-256 hash for `message` and returns it.
	This function returns both a hexadecimal encoded string of the hash
	and returns a **read-only** table containing the eight 32-bit integers
	that make up the hash.
	
	@param message -- The payload to compute the SHA-256 hash of
	@return string -- The computed SHA-256 hash as a string of hexadecimal digits
	@return {number} -- The computed SHA-256 hash as an array of 8 integers
]=]
local function sha256(message: string): (string, { number })
	local digest = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19,
	}

	local messageLen = #message
	local leftover = messageLen % 64
	if messageLen >= 64 then
		processBlocks(digest, message, 1, messageLen - leftover)
	end

	-- Raise `leftover` to next multiple of 64 so that we can calculate
	-- how much padding we need without a branch or loop.
	-- The number here is just masking off the last 6 bits.
	local nextMultipleOf64 = bit32.band(leftover + 32, 0xffff_ffc0)

	local finalMessage = {
		if leftover ~= 0 then string.sub(message, -leftover) else "",
		"\x80",
		string.rep("\0", (nextMultipleOf64 - leftover - 9) % 64),
		string.pack(">L", messageLen * 8),
	}
	local finalBlock = table.concat(finalMessage)
	processBlocks(digest, finalBlock, 1, #finalBlock)

	return string.format(
		"%08x%08x%08x%08x%08x%08x%08x%08x",
		digest[1],
		digest[2],
		digest[3],
		digest[4],
		digest[5],
		digest[6],
		digest[7],
		digest[8]
	),
		table.freeze(digest)
end

return sha256