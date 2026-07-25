--[=[
	Cryptography library: SHA224

	Sizes:
		Digest: 28 bytes

	Return type: (string, buffer)
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Hash, HashBuffer = SHA224(Message)
--]=]

--!strict
--!optimize 2
--!native

local MASK = 0xFFFFFFFFi

local CONSTANTS = buffer.create(512) do
	local RoundConstants = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	}
	for Index, Constant in ipairs(RoundConstants) do
		buffer.writeinteger(CONSTANTS, (Index - 1) * 8, integer.create(Constant) :: integer)
	end
end

local function PreProcess(Contents: buffer): (buffer, number)
	local ContentLength = buffer.len(Contents)
	local Padding = -(ContentLength + 9) % 64
	local NewContentLength = ContentLength + 1 + Padding + 8
	local NewContent = buffer.create(NewContentLength)
	buffer.copy(NewContent, 0, Contents)
	buffer.writeu8(NewContent, ContentLength, 128)
	local Length8 = ContentLength * 8
	for Index = 7, 0, -1 do
		local Remainder = Length8 % 256
		buffer.writeu8(NewContent, Index + ContentLength + 1 + Padding, Remainder)
		Length8 = (Length8 - Remainder) / 256
	end
	return NewContent, NewContentLength
end

local OFFSETS = buffer.create(512)

local function ProcessSchedule(Offsets: buffer)
	do
		local W15 = buffer.readinteger(Offsets, 8)
		local W2 = buffer.readinteger(Offsets, 112)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 128, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 0), S0), buffer.readinteger(Offsets, 72)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 16)
		local W2 = buffer.readinteger(Offsets, 120)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 136, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 8), S0), buffer.readinteger(Offsets, 80)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 24)
		local W2 = buffer.readinteger(Offsets, 128)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 144, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 16), S0), buffer.readinteger(Offsets, 88)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 32)
		local W2 = buffer.readinteger(Offsets, 136)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 152, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 24), S0), buffer.readinteger(Offsets, 96)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 40)
		local W2 = buffer.readinteger(Offsets, 144)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 160, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 32), S0), buffer.readinteger(Offsets, 104)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 48)
		local W2 = buffer.readinteger(Offsets, 152)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 168, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 40), S0), buffer.readinteger(Offsets, 112)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 56)
		local W2 = buffer.readinteger(Offsets, 160)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 176, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 48), S0), buffer.readinteger(Offsets, 120)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 64)
		local W2 = buffer.readinteger(Offsets, 168)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 184, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 56), S0), buffer.readinteger(Offsets, 128)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 72)
		local W2 = buffer.readinteger(Offsets, 176)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 192, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 64), S0), buffer.readinteger(Offsets, 136)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 80)
		local W2 = buffer.readinteger(Offsets, 184)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 200, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 72), S0), buffer.readinteger(Offsets, 144)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 88)
		local W2 = buffer.readinteger(Offsets, 192)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 208, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 80), S0), buffer.readinteger(Offsets, 152)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 96)
		local W2 = buffer.readinteger(Offsets, 200)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 216, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 88), S0), buffer.readinteger(Offsets, 160)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 104)
		local W2 = buffer.readinteger(Offsets, 208)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 224, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 96), S0), buffer.readinteger(Offsets, 168)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 112)
		local W2 = buffer.readinteger(Offsets, 216)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 232, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 104), S0), buffer.readinteger(Offsets, 176)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 120)
		local W2 = buffer.readinteger(Offsets, 224)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 240, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 112), S0), buffer.readinteger(Offsets, 184)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 128)
		local W2 = buffer.readinteger(Offsets, 232)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 248, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 120), S0), buffer.readinteger(Offsets, 192)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 136)
		local W2 = buffer.readinteger(Offsets, 240)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 256, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 128), S0), buffer.readinteger(Offsets, 200)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 144)
		local W2 = buffer.readinteger(Offsets, 248)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 264, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 136), S0), buffer.readinteger(Offsets, 208)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 152)
		local W2 = buffer.readinteger(Offsets, 256)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 272, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 144), S0), buffer.readinteger(Offsets, 216)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 160)
		local W2 = buffer.readinteger(Offsets, 264)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 280, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 152), S0), buffer.readinteger(Offsets, 224)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 168)
		local W2 = buffer.readinteger(Offsets, 272)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 288, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 160), S0), buffer.readinteger(Offsets, 232)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 176)
		local W2 = buffer.readinteger(Offsets, 280)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 296, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 168), S0), buffer.readinteger(Offsets, 240)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 184)
		local W2 = buffer.readinteger(Offsets, 288)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 304, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 176), S0), buffer.readinteger(Offsets, 248)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 192)
		local W2 = buffer.readinteger(Offsets, 296)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 312, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 184), S0), buffer.readinteger(Offsets, 256)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 200)
		local W2 = buffer.readinteger(Offsets, 304)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 320, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 192), S0), buffer.readinteger(Offsets, 264)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 208)
		local W2 = buffer.readinteger(Offsets, 312)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 328, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 200), S0), buffer.readinteger(Offsets, 272)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 216)
		local W2 = buffer.readinteger(Offsets, 320)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 336, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 208), S0), buffer.readinteger(Offsets, 280)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 224)
		local W2 = buffer.readinteger(Offsets, 328)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 344, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 216), S0), buffer.readinteger(Offsets, 288)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 232)
		local W2 = buffer.readinteger(Offsets, 336)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 352, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 224), S0), buffer.readinteger(Offsets, 296)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 240)
		local W2 = buffer.readinteger(Offsets, 344)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 360, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 232), S0), buffer.readinteger(Offsets, 304)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 248)
		local W2 = buffer.readinteger(Offsets, 352)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 368, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 240), S0), buffer.readinteger(Offsets, 312)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 256)
		local W2 = buffer.readinteger(Offsets, 360)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 376, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 248), S0), buffer.readinteger(Offsets, 320)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 264)
		local W2 = buffer.readinteger(Offsets, 368)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 384, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 256), S0), buffer.readinteger(Offsets, 328)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 272)
		local W2 = buffer.readinteger(Offsets, 376)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 392, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 264), S0), buffer.readinteger(Offsets, 336)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 280)
		local W2 = buffer.readinteger(Offsets, 384)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 400, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 272), S0), buffer.readinteger(Offsets, 344)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 288)
		local W2 = buffer.readinteger(Offsets, 392)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 408, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 280), S0), buffer.readinteger(Offsets, 352)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 296)
		local W2 = buffer.readinteger(Offsets, 400)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 416, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 288), S0), buffer.readinteger(Offsets, 360)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 304)
		local W2 = buffer.readinteger(Offsets, 408)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 424, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 296), S0), buffer.readinteger(Offsets, 368)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 312)
		local W2 = buffer.readinteger(Offsets, 416)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 432, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 304), S0), buffer.readinteger(Offsets, 376)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 320)
		local W2 = buffer.readinteger(Offsets, 424)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 440, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 312), S0), buffer.readinteger(Offsets, 384)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 328)
		local W2 = buffer.readinteger(Offsets, 432)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 448, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 320), S0), buffer.readinteger(Offsets, 392)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 336)
		local W2 = buffer.readinteger(Offsets, 440)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 456, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 328), S0), buffer.readinteger(Offsets, 400)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 344)
		local W2 = buffer.readinteger(Offsets, 448)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 464, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 336), S0), buffer.readinteger(Offsets, 408)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 352)
		local W2 = buffer.readinteger(Offsets, 456)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 472, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 344), S0), buffer.readinteger(Offsets, 416)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 360)
		local W2 = buffer.readinteger(Offsets, 464)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 480, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 352), S0), buffer.readinteger(Offsets, 424)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 368)
		local W2 = buffer.readinteger(Offsets, 472)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 488, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 360), S0), buffer.readinteger(Offsets, 432)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 376)
		local W2 = buffer.readinteger(Offsets, 480)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 496, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 368), S0), buffer.readinteger(Offsets, 440)), S1), MASK))
	end
	do
		local W15 = buffer.readinteger(Offsets, 384)
		local W2 = buffer.readinteger(Offsets, 488)
		local S0 = integer.bxor(integer.bor(integer.rshift(W15, 7i), integer.lshift(W15, 25i)), integer.bor(integer.rshift(W15, 18i), integer.lshift(W15, 14i)), integer.rshift(W15, 3i))
		local S1 = integer.bxor(integer.bor(integer.rshift(W2, 17i), integer.lshift(W2, 15i)), integer.bor(integer.rshift(W2, 19i), integer.lshift(W2, 13i)), integer.rshift(W2, 10i))
		buffer.writeinteger(Offsets, 504, integer.band(integer.add(integer.add(integer.add(buffer.readinteger(Offsets, 376), S0), buffer.readinteger(Offsets, 448)), S1), MASK))
	end
end

local function DigestBlocks(Blocks: buffer, Length: number): (integer, integer, integer, integer, integer, integer, integer)
	local A, B, C, D = 0xc1059ed8i, 0x367cd507i, 0x3070dd17i, 0xf70e5939i
	local E, F, G, H = 0xffc00b31i, 0x68581511i, 0x64f98fa7i, 0xbefa4fa4i

	local Offsets = OFFSETS
	local Constants = CONSTANTS

	for Offset = 0, Length - 1, 64 do
		for WordIndex = 0, 120, 8 do
			buffer.writeinteger(Offsets, WordIndex, integer.create(bit32.byteswap(buffer.readu32(Blocks, Offset + WordIndex // 2))) :: integer)
		end

		ProcessSchedule(Offsets)

		local OldA, OldB, OldC, OldD, OldE, OldF, OldG, OldH = A, B, C, D, E, F, G, H

		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 0)), buffer.readinteger(Offsets, 0))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 8)), buffer.readinteger(Offsets, 8))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 16)), buffer.readinteger(Offsets, 16))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 24)), buffer.readinteger(Offsets, 24))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 32)), buffer.readinteger(Offsets, 32))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 40)), buffer.readinteger(Offsets, 40))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 48)), buffer.readinteger(Offsets, 48))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 56)), buffer.readinteger(Offsets, 56))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 64)), buffer.readinteger(Offsets, 64))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 72)), buffer.readinteger(Offsets, 72))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 80)), buffer.readinteger(Offsets, 80))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 88)), buffer.readinteger(Offsets, 88))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 96)), buffer.readinteger(Offsets, 96))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 104)), buffer.readinteger(Offsets, 104))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 112)), buffer.readinteger(Offsets, 112))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 120)), buffer.readinteger(Offsets, 120))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 128)), buffer.readinteger(Offsets, 128))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 136)), buffer.readinteger(Offsets, 136))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 144)), buffer.readinteger(Offsets, 144))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 152)), buffer.readinteger(Offsets, 152))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 160)), buffer.readinteger(Offsets, 160))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 168)), buffer.readinteger(Offsets, 168))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 176)), buffer.readinteger(Offsets, 176))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 184)), buffer.readinteger(Offsets, 184))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 192)), buffer.readinteger(Offsets, 192))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 200)), buffer.readinteger(Offsets, 200))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 208)), buffer.readinteger(Offsets, 208))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 216)), buffer.readinteger(Offsets, 216))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 224)), buffer.readinteger(Offsets, 224))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 232)), buffer.readinteger(Offsets, 232))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 240)), buffer.readinteger(Offsets, 240))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 248)), buffer.readinteger(Offsets, 248))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 256)), buffer.readinteger(Offsets, 256))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 264)), buffer.readinteger(Offsets, 264))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 272)), buffer.readinteger(Offsets, 272))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 280)), buffer.readinteger(Offsets, 280))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 288)), buffer.readinteger(Offsets, 288))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 296)), buffer.readinteger(Offsets, 296))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 304)), buffer.readinteger(Offsets, 304))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 312)), buffer.readinteger(Offsets, 312))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 320)), buffer.readinteger(Offsets, 320))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 328)), buffer.readinteger(Offsets, 328))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 336)), buffer.readinteger(Offsets, 336))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 344)), buffer.readinteger(Offsets, 344))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 352)), buffer.readinteger(Offsets, 352))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 360)), buffer.readinteger(Offsets, 360))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 368)), buffer.readinteger(Offsets, 368))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 376)), buffer.readinteger(Offsets, 376))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 384)), buffer.readinteger(Offsets, 384))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 392)), buffer.readinteger(Offsets, 392))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 400)), buffer.readinteger(Offsets, 400))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 408)), buffer.readinteger(Offsets, 408))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 416)), buffer.readinteger(Offsets, 416))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 424)), buffer.readinteger(Offsets, 424))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 432)), buffer.readinteger(Offsets, 432))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 440)), buffer.readinteger(Offsets, 440))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 448)), buffer.readinteger(Offsets, 448))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 456)), buffer.readinteger(Offsets, 456))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 464)), buffer.readinteger(Offsets, 464))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 472)), buffer.readinteger(Offsets, 472))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 480)), buffer.readinteger(Offsets, 480))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 488)), buffer.readinteger(Offsets, 488))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 496)), buffer.readinteger(Offsets, 496))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end
		do
			local S1 = integer.bxor(integer.bor(integer.rshift(E, 6i), integer.lshift(E, 26i)), integer.bor(integer.rshift(E, 11i), integer.lshift(E, 21i)), integer.bor(integer.rshift(E, 25i), integer.lshift(E, 7i)))
			local Ch = integer.bxor(integer.band(E, F), integer.band(integer.bnot(E), G))
			local Temp1 = integer.add(integer.add(integer.add(integer.add(H, S1), Ch), buffer.readinteger(Constants, 504)), buffer.readinteger(Offsets, 504))
			local S0 = integer.bxor(integer.bor(integer.rshift(A, 2i), integer.lshift(A, 30i)), integer.bor(integer.rshift(A, 13i), integer.lshift(A, 19i)), integer.bor(integer.rshift(A, 22i), integer.lshift(A, 10i)))
			local Maj = integer.bxor(integer.band(A, B), integer.band(A, C), integer.band(B, C))
			H, G, F, E, D, C, B, A = G, F, E, integer.band(integer.add(D, Temp1), MASK), C, B, A, (integer.band(integer.add(integer.add(Temp1, S0), Maj), MASK))
		end

		A = integer.band(integer.add(A, OldA), MASK)
		B = integer.band(integer.add(B, OldB), MASK)
		C = integer.band(integer.add(C, OldC), MASK)
		D = integer.band(integer.add(D, OldD), MASK)
		E = integer.band(integer.add(E, OldE), MASK)
		F = integer.band(integer.add(F, OldF), MASK)
		G = integer.band(integer.add(G, OldG), MASK)
		H = integer.band(integer.add(H, OldH), MASK)
	end

	return A, B, C, D, E, F, G
end

local function SHA224(Message: buffer): (string, buffer)
	local ProcessedMessage, Length = PreProcess(Message)
	local A, B, C, D, E, F, G = DigestBlocks(ProcessedMessage, Length)

	local Digest = buffer.create(28)
	buffer.writeu32(Digest, 0, bit32.byteswap(integer.tonumber(A)))
	buffer.writeu32(Digest, 4, bit32.byteswap(integer.tonumber(B)))
	buffer.writeu32(Digest, 8, bit32.byteswap(integer.tonumber(C)))
	buffer.writeu32(Digest, 12, bit32.byteswap(integer.tonumber(D)))
	buffer.writeu32(Digest, 16, bit32.byteswap(integer.tonumber(E)))
	buffer.writeu32(Digest, 20, bit32.byteswap(integer.tonumber(F)))
	buffer.writeu32(Digest, 24, bit32.byteswap(integer.tonumber(G)))

	return string.format("%08x%08x%08x%08x%08x%08x%08x",
		A :: any, B :: any, C :: any, D :: any, E :: any, F :: any, G :: any), Digest
end

return SHA224
