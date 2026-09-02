--[=[
	Cryptography library: Keccak/SHA-3
	
	Sizes:
		SHA3-224 Digest: 28 bytes
		SHA3-256 Digest: 32 bytes
		SHA3-384 Digest: 48 bytes
		SHA3-512 Digest: 64 bytes
		SHAKE128 Digest: variable
		SHAKE256 Digest: variable

	Return type: (string, buffer)
	Example usage:
		local Message = buffer.fromstring("Hello World")

		local Hash1, HashBuffer1 = SHA3.SHA3_256(Message)
		local Hash2, HashBuffer2 = SHA3.SHAKE128(Message, 32)
--]=]

--!strict
--!optimize 2
--!native

local Conversions = require("../Utilities/Conversions")
local ToHex = Conversions.ToHex

local SHA3 = {}

local ROUND_CONSTANTS = buffer.create(192) do
	local ShiftRegister = 29
	local function GetNextBit(): number
		local Result = ShiftRegister % 2
		ShiftRegister = bit32.bxor((ShiftRegister - Result) // 2, 142 * Result)
		return Result
	end

	local BitPositions = {0i, 1i, 3i, 7i, 15i, 31i, 63i}
	for Index = 0, 23 do
		local Value = 0i

		for j = 1, 7 do
			if GetNextBit() == 1 then
				Value = integer.bor(Value, integer.lshift(1i, BitPositions[j]))
			end
		end

		buffer.writeinteger(ROUND_CONSTANTS, Index * 8, Value)
	end
end

local LANES = buffer.create(200)
local SQUEEZE_ZERO = buffer.create(168)
local TAIL_BLOCK = buffer.create(200)

local function Keccak(Lanes: buffer, InputBuffer: buffer, Offset: number, Size: number, BlockSizeInBytes: number): ()
	local QuadWordsQuantity = BlockSizeInBytes // 8
	local RC = ROUND_CONSTANTS

	local Lane01, Lane02, Lane03 = buffer.readinteger(Lanes, 0), integer.bnot(buffer.readinteger(Lanes, 8)), integer.bnot(buffer.readinteger(Lanes, 16))
	local Lane04, Lane05, Lane06 = buffer.readinteger(Lanes, 24), buffer.readinteger(Lanes, 32), buffer.readinteger(Lanes, 40)
	local Lane07, Lane08, Lane09 = buffer.readinteger(Lanes, 48), buffer.readinteger(Lanes, 56), integer.bnot(buffer.readinteger(Lanes, 64))
	local Lane10, Lane11, Lane12 = buffer.readinteger(Lanes, 72), buffer.readinteger(Lanes, 80), buffer.readinteger(Lanes, 88)
	local Lane13, Lane14, Lane15 = integer.bnot(buffer.readinteger(Lanes, 96)), buffer.readinteger(Lanes, 104), buffer.readinteger(Lanes, 112)
	local Lane16, Lane17, Lane18 = buffer.readinteger(Lanes, 120), buffer.readinteger(Lanes, 128), integer.bnot(buffer.readinteger(Lanes, 136))
	local Lane19, Lane20, Lane21 = buffer.readinteger(Lanes, 144), buffer.readinteger(Lanes, 152), integer.bnot(buffer.readinteger(Lanes, 160))
	local Lane22, Lane23, Lane24 = buffer.readinteger(Lanes, 168), buffer.readinteger(Lanes, 176), buffer.readinteger(Lanes, 184)
	local Lane25 = buffer.readinteger(Lanes, 192)

	for Position = Offset, Offset + Size - 1, BlockSizeInBytes do
		Lane01 = integer.bxor(Lane01, buffer.readinteger(InputBuffer, Position))
		if QuadWordsQuantity > 1 then
			Lane02 = integer.bxor(Lane02, buffer.readinteger(InputBuffer, Position + 8))
		end
		if QuadWordsQuantity > 2 then
			Lane03 = integer.bxor(Lane03, buffer.readinteger(InputBuffer, Position + 16))
		end
		if QuadWordsQuantity > 3 then
			Lane04 = integer.bxor(Lane04, buffer.readinteger(InputBuffer, Position + 24))
		end
		if QuadWordsQuantity > 4 then
			Lane05 = integer.bxor(Lane05, buffer.readinteger(InputBuffer, Position + 32))
		end
		if QuadWordsQuantity > 5 then
			Lane06 = integer.bxor(Lane06, buffer.readinteger(InputBuffer, Position + 40))
		end
		if QuadWordsQuantity > 6 then
			Lane07 = integer.bxor(Lane07, buffer.readinteger(InputBuffer, Position + 48))
		end
		if QuadWordsQuantity > 7 then
			Lane08 = integer.bxor(Lane08, buffer.readinteger(InputBuffer, Position + 56))
		end
		if QuadWordsQuantity > 8 then
			Lane09 = integer.bxor(Lane09, buffer.readinteger(InputBuffer, Position + 64))
		end
		if QuadWordsQuantity > 9 then
			Lane10 = integer.bxor(Lane10, buffer.readinteger(InputBuffer, Position + 72))
		end
		if QuadWordsQuantity > 10 then
			Lane11 = integer.bxor(Lane11, buffer.readinteger(InputBuffer, Position + 80))
		end
		if QuadWordsQuantity > 11 then
			Lane12 = integer.bxor(Lane12, buffer.readinteger(InputBuffer, Position + 88))
		end
		if QuadWordsQuantity > 12 then
			Lane13 = integer.bxor(Lane13, buffer.readinteger(InputBuffer, Position + 96))
		end
		if QuadWordsQuantity > 13 then
			Lane14 = integer.bxor(Lane14, buffer.readinteger(InputBuffer, Position + 104))
		end
		if QuadWordsQuantity > 14 then
			Lane15 = integer.bxor(Lane15, buffer.readinteger(InputBuffer, Position + 112))
		end
		if QuadWordsQuantity > 15 then
			Lane16 = integer.bxor(Lane16, buffer.readinteger(InputBuffer, Position + 120))
		end
		if QuadWordsQuantity > 16 then
			Lane17 = integer.bxor(Lane17, buffer.readinteger(InputBuffer, Position + 128))
		end
		if QuadWordsQuantity > 17 then
			Lane18 = integer.bxor(Lane18, buffer.readinteger(InputBuffer, Position + 136))
		end
		if QuadWordsQuantity > 18 then
			Lane19 = integer.bxor(Lane19, buffer.readinteger(InputBuffer, Position + 144))
		end
		if QuadWordsQuantity > 19 then
			Lane20 = integer.bxor(Lane20, buffer.readinteger(InputBuffer, Position + 152))
		end
		if QuadWordsQuantity > 20 then
			Lane21 = integer.bxor(Lane21, buffer.readinteger(InputBuffer, Position + 160))
		end
		if QuadWordsQuantity > 21 then
			Lane22 = integer.bxor(Lane22, buffer.readinteger(InputBuffer, Position + 168))
		end
		if QuadWordsQuantity > 22 then
			Lane23 = integer.bxor(Lane23, buffer.readinteger(InputBuffer, Position + 176))
		end
		if QuadWordsQuantity > 23 then
			Lane24 = integer.bxor(Lane24, buffer.readinteger(InputBuffer, Position + 184))
		end
		if QuadWordsQuantity > 24 then
			Lane25 = integer.bxor(Lane25, buffer.readinteger(InputBuffer, Position + 192))
		end

		for RoundIndex = 0, 184, 16 do
			do
				local Column1 = integer.bxor(integer.bxor(integer.bxor(integer.bxor(Lane01, Lane06), Lane11), Lane16), Lane21)
				local Column2 = integer.bxor(integer.bxor(integer.bxor(integer.bxor(Lane02, Lane07), Lane12), Lane17), Lane22)
				local Column3 = integer.bxor(integer.bxor(integer.bxor(integer.bxor(Lane03, Lane08), Lane13), Lane18), Lane23)
				local Column4 = integer.bxor(integer.bxor(integer.bxor(integer.bxor(Lane04, Lane09), Lane14), Lane19), Lane24)
				local Column5 = integer.bxor(integer.bxor(integer.bxor(integer.bxor(Lane05, Lane10), Lane15), Lane20), Lane25)
	
				local Delta = integer.bxor(Column1, integer.lrotate(Column3, 1i))
	
				local Temp0, Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane02), integer.bxor(Delta, Lane07), integer.bxor(Delta, Lane12), integer.bxor(Delta, Lane17), integer.bxor(Delta, Lane22)
				Lane02, Lane07, Lane12, Lane17, Lane22 = integer.rrotate(Temp1, 20i), integer.rrotate(Temp3, 19i), integer.rrotate(Temp0, 63i), integer.rrotate(Temp2, 54i), integer.rrotate(Temp4, 62i)
				Delta = integer.bxor(Column2, integer.rrotate(Column4, 63i))
	
				-- TYPE ERROR: type solver infers Temp4 to be nil after the theta step
				Temp0, Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane03), integer.bxor(Delta, Lane08), integer.bxor(Delta, Lane13), integer.bxor(Delta, Lane18), integer.bxor(Delta, Lane23) :: integer
				Lane03, Lane08, Lane13, Lane18, Lane23 = integer.rrotate(Temp2, 21i), integer.rrotate(Temp4, 3i), integer.rrotate(Temp1, 58i), integer.rrotate(Temp3, 49i), integer.rrotate(Temp0, 2i)
				Delta = integer.bxor(Column3, integer.rrotate(Column5, 63i))
	
				Temp0, Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane04), integer.bxor(Delta, Lane09), integer.bxor(Delta, Lane14), integer.bxor(Delta, Lane19), integer.bxor(Delta, Lane24) :: integer
				Lane04, Lane09, Lane14, Lane19, Lane24 = integer.rrotate(Temp3, 43i), integer.rrotate(Temp0, 36i), integer.rrotate(Temp2, 39i), integer.rrotate(Temp4, 8i), integer.rrotate(Temp1, 9i)
				Delta = integer.bxor(Column4, integer.rrotate(Column1, 63i))
	
				Temp0, Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane05), integer.bxor(Delta, Lane10), integer.bxor(Delta, Lane15), integer.bxor(Delta, Lane20), integer.bxor(Delta, Lane25) :: integer
				Lane05, Lane10, Lane15, Lane20, Lane25 = integer.rrotate(Temp4, 50i), integer.rrotate(Temp1, 44i), integer.rrotate(Temp3, 56i), integer.rrotate(Temp0, 37i), integer.rrotate(Temp2, 25i)
				Delta = integer.bxor(Column5, integer.rrotate(Column2, 63i))
	
				Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane06), integer.bxor(Delta, Lane11), integer.bxor(Delta, Lane16), integer.bxor(Delta, Lane21) :: integer
				Lane06, Lane11, Lane16, Lane21 = integer.rrotate(Temp2, 61i), integer.rrotate(Temp4, 46i), integer.rrotate(Temp1, 28i), integer.rrotate(Temp3, 23i)
				Lane01 = integer.bxor(Delta, Lane01)
	
				Lane01, Lane02, Lane03, Lane04, Lane05 =
					integer.bxor(Lane01, integer.bor(Lane02, Lane03)),
					integer.bxor(Lane02, integer.bor(integer.bnot(Lane03), Lane04)),
					integer.bxor(Lane03, integer.band(Lane04, Lane05)),
					integer.bxor(Lane04, integer.bor(Lane05, Lane01)),
					(integer.bxor(Lane05, integer.band(Lane01, Lane02)))
				
				Lane06, Lane07, Lane08, Lane09, Lane10 =
					integer.bxor(Lane09, integer.bor(Lane10, Lane06)),
					integer.bxor(Lane10, integer.band(Lane06, Lane07)),
					integer.bnot(integer.bxor(Lane06, integer.band(integer.bnot(Lane07), Lane08))),
					integer.bxor(Lane07, integer.bor(Lane08, Lane09)),
					(integer.bxor(Lane08, integer.band(Lane09, Lane10)))
	
				Lane11, Lane12, Lane13, Lane14, Lane15 =
					integer.bxor(Lane12, integer.bor(Lane13, Lane14)),
					integer.bxor(Lane13, integer.band(Lane14, Lane15)),
					integer.bxor(Lane14, integer.band(integer.bnot(Lane15), Lane11)),
					integer.bnot(integer.bxor(Lane15, integer.bor(Lane11, Lane12))),
					(integer.bxor(Lane11, integer.band(Lane12, Lane13)))
	
				Lane16, Lane17, Lane18, Lane19, Lane20 =
					integer.bxor(Lane20, integer.band(Lane16, Lane17)),	
					integer.bxor(Lane16, integer.bor(Lane17, Lane18)),
					integer.bxor(Lane17, integer.bor(integer.bnot(Lane18), Lane19)),
					integer.bnot(integer.bxor(Lane18, integer.band(Lane19, Lane20))),
					(integer.bxor(Lane19, integer.bor(Lane20, Lane16)))
	
				-- TYPE ERROR: type solver infers Lane21-Lane25 to be integer? after this point
				Lane21, Lane22, Lane23, Lane24, Lane25 =
					(Lane21 :: any) :: integer,
					(Lane22 :: any) :: integer,
					(Lane23 :: any) :: integer,
					(Lane24 :: any) :: integer,
					(Lane25 :: any) :: integer
	
				Lane21, Lane22, Lane23, Lane24, Lane25 =
					integer.bxor(Lane23, integer.band(integer.bnot(Lane24), Lane25)),
					integer.bnot(integer.bxor(Lane24, integer.bor(Lane25, Lane21))),
					integer.bxor(Lane25, integer.band(Lane21, Lane22)),
					integer.bxor(Lane21, integer.bor(Lane22, Lane23)),
					(integer.bxor(Lane22, integer.band(Lane23, Lane24)))
	
				Lane01 = integer.bxor(Lane01, buffer.readinteger(RC, RoundIndex))
			end

			do
				local Column1 = integer.bxor(integer.bxor(integer.bxor(integer.bxor(Lane01, Lane06), Lane11), Lane16), Lane21)
				local Column2 = integer.bxor(integer.bxor(integer.bxor(integer.bxor(Lane02, Lane07), Lane12), Lane17), Lane22)
				local Column3 = integer.bxor(integer.bxor(integer.bxor(integer.bxor(Lane03, Lane08), Lane13), Lane18), Lane23)
				local Column4 = integer.bxor(integer.bxor(integer.bxor(integer.bxor(Lane04, Lane09), Lane14), Lane19), Lane24)
				local Column5 = integer.bxor(integer.bxor(integer.bxor(integer.bxor(Lane05, Lane10), Lane15), Lane20), Lane25)
	
				local Delta = integer.bxor(Column1, integer.lrotate(Column3, 1i))
	
				local Temp0, Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane02), integer.bxor(Delta, Lane07), integer.bxor(Delta, Lane12), integer.bxor(Delta, Lane17), integer.bxor(Delta, Lane22)
				Lane02, Lane07, Lane12, Lane17, Lane22 = integer.rrotate(Temp1, 20i), integer.rrotate(Temp3, 19i), integer.rrotate(Temp0, 63i), integer.rrotate(Temp2, 54i), integer.rrotate(Temp4, 62i)
				Delta = integer.bxor(Column2, integer.rrotate(Column4, 63i))
	
				
				-- TYPE ERROR: type solver infers Temp4 to be nil after the theta step
				Temp0, Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane03), integer.bxor(Delta, Lane08), integer.bxor(Delta, Lane13), integer.bxor(Delta, Lane18), integer.bxor(Delta, Lane23) :: integer
				Lane03, Lane08, Lane13, Lane18, Lane23 = integer.rrotate(Temp2, 21i), integer.rrotate(Temp4, 3i), integer.rrotate(Temp1, 58i), integer.rrotate(Temp3, 49i), integer.rrotate(Temp0, 2i)
				Delta = integer.bxor(Column3, integer.rrotate(Column5, 63i))
	
				Temp0, Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane04), integer.bxor(Delta, Lane09), integer.bxor(Delta, Lane14), integer.bxor(Delta, Lane19), integer.bxor(Delta, Lane24) :: integer
				Lane04, Lane09, Lane14, Lane19, Lane24 = integer.rrotate(Temp3, 43i), integer.rrotate(Temp0, 36i), integer.rrotate(Temp2, 39i), integer.rrotate(Temp4, 8i), integer.rrotate(Temp1, 9i)
				Delta = integer.bxor(Column4, integer.rrotate(Column1, 63i))
	
				Temp0, Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane05), integer.bxor(Delta, Lane10), integer.bxor(Delta, Lane15), integer.bxor(Delta, Lane20), integer.bxor(Delta, Lane25) :: integer
				Lane05, Lane10, Lane15, Lane20, Lane25 = integer.rrotate(Temp4, 50i), integer.rrotate(Temp1, 44i), integer.rrotate(Temp3, 56i), integer.rrotate(Temp0, 37i), integer.rrotate(Temp2, 25i)
				Delta = integer.bxor(Column5, integer.rrotate(Column2, 63i))
	
				Temp1, Temp2, Temp3, Temp4 = integer.bxor(Delta, Lane06), integer.bxor(Delta, Lane11), integer.bxor(Delta, Lane16), integer.bxor(Delta, Lane21) :: integer
				Lane06, Lane11, Lane16, Lane21 = integer.rrotate(Temp2, 61i), integer.rrotate(Temp4, 46i), integer.rrotate(Temp1, 28i), integer.rrotate(Temp3, 23i)
				Lane01 = integer.bxor(Delta, Lane01)
	
				Lane01, Lane02, Lane03, Lane04, Lane05 =
					integer.bxor(Lane01, integer.bor(Lane02, Lane03)),
					integer.bxor(Lane02, integer.bor(integer.bnot(Lane03), Lane04)),
					integer.bxor(Lane03, integer.band(Lane04, Lane05)),
					integer.bxor(Lane04, integer.bor(Lane05, Lane01)),
					(integer.bxor(Lane05, integer.band(Lane01, Lane02)))
				
				Lane06, Lane07, Lane08, Lane09, Lane10 =
					integer.bxor(Lane09, integer.bor(Lane10, Lane06)),
					integer.bxor(Lane10, integer.band(Lane06, Lane07)),
					integer.bnot(integer.bxor(Lane06, integer.band(integer.bnot(Lane07), Lane08))),
					integer.bxor(Lane07, integer.bor(Lane08, Lane09)),
					(integer.bxor(Lane08, integer.band(Lane09, Lane10)))
	
				Lane11, Lane12, Lane13, Lane14, Lane15 =
					integer.bxor(Lane12, integer.bor(Lane13, Lane14)),
					integer.bxor(Lane13, integer.band(Lane14, Lane15)),
					integer.bxor(Lane14, integer.band(integer.bnot(Lane15), Lane11)),
					integer.bnot(integer.bxor(Lane15, integer.bor(Lane11, Lane12))),
					(integer.bxor(Lane11, integer.band(Lane12, Lane13)))
	
				Lane16, Lane17, Lane18, Lane19, Lane20 =
					integer.bxor(Lane20, integer.band(Lane16, Lane17)),	
					integer.bxor(Lane16, integer.bor(Lane17, Lane18)),
					integer.bxor(Lane17, integer.bor(integer.bnot(Lane18), Lane19)),
					integer.bnot(integer.bxor(Lane18, integer.band(Lane19, Lane20))),
					(integer.bxor(Lane19, integer.bor(Lane20, Lane16)))
	
				-- TYPE ERROR: type solver infers Lane21-Lane25 to be integer? after this point
				Lane21, Lane22, Lane23, Lane24, Lane25 =
					(Lane21 :: any) :: integer,
					(Lane22 :: any) :: integer,
					(Lane23 :: any) :: integer,
					(Lane24 :: any) :: integer,
					(Lane25 :: any) :: integer
	
				Lane21, Lane22, Lane23, Lane24, Lane25 =
					integer.bxor(Lane23, integer.band(integer.bnot(Lane24), Lane25)),
					integer.bnot(integer.bxor(Lane24, integer.bor(Lane25, Lane21))),
					integer.bxor(Lane25, integer.band(Lane21, Lane22)),
					integer.bxor(Lane21, integer.bor(Lane22, Lane23)),
					(integer.bxor(Lane22, integer.band(Lane23, Lane24)))
	
				Lane01 = integer.bxor(Lane01, buffer.readinteger(RC, RoundIndex + 8))
			end
		end
	end

	buffer.writeinteger(Lanes, 0, Lane01)
	buffer.writeinteger(Lanes, 8, integer.bnot(Lane02))
	buffer.writeinteger(Lanes, 16, integer.bnot(Lane03))
	buffer.writeinteger(Lanes, 24, Lane04)
	buffer.writeinteger(Lanes, 32, Lane05)
	buffer.writeinteger(Lanes, 40, Lane06)
	buffer.writeinteger(Lanes, 48, Lane07)
	buffer.writeinteger(Lanes, 56, Lane08)
	buffer.writeinteger(Lanes, 64, integer.bnot(Lane09))
	buffer.writeinteger(Lanes, 72, Lane10)
	buffer.writeinteger(Lanes, 80, Lane11)
	buffer.writeinteger(Lanes, 88, Lane12)
	buffer.writeinteger(Lanes, 96, integer.bnot(Lane13))
	buffer.writeinteger(Lanes, 104, Lane14)
	buffer.writeinteger(Lanes, 112, Lane15)
	buffer.writeinteger(Lanes, 120, Lane16)
	buffer.writeinteger(Lanes, 128, Lane17)
	buffer.writeinteger(Lanes, 136, integer.bnot(Lane18))
	buffer.writeinteger(Lanes, 144, Lane19)
	buffer.writeinteger(Lanes, 152, Lane20)
	buffer.writeinteger(Lanes, 160, integer.bnot(Lane21))
	buffer.writeinteger(Lanes, 168, Lane22)
	buffer.writeinteger(Lanes, 176, Lane23)
	buffer.writeinteger(Lanes, 184, Lane24)
	buffer.writeinteger(Lanes, 192, Lane25)
end

local function ProcessSponge(Message: buffer, CapacityBits: number, OutputBytes: number, DomainSeparator: number): buffer
	local RateBytes = (1600 - CapacityBits) // 8
	local Lanes = LANES
	buffer.fill(Lanes, 0, 0)

	local MessageLength = buffer.len(Message)
	local TailLength = MessageLength % RateBytes
	local FullBytes = MessageLength - TailLength

	if FullBytes > 0 then
		Keccak(Lanes, Message, 0, FullBytes, RateBytes)
	end

	local Tail = TAIL_BLOCK
	buffer.fill(Tail, 0, 0, RateBytes)
	if TailLength > 0 then
		buffer.copy(Tail, 0, Message, FullBytes, TailLength)
	end
	buffer.writeu8(Tail, TailLength, DomainSeparator)
	buffer.writeu8(Tail, RateBytes - 1, bit32.bor(buffer.readu8(Tail, RateBytes - 1), 0x80))
	Keccak(Lanes, Tail, 0, RateBytes, RateBytes)

	local Output = buffer.create(OutputBytes)
	local OutputOffset = 0

	while OutputOffset < OutputBytes do
		local BytesThisRound = math.min(RateBytes, OutputBytes - OutputOffset)

		buffer.copy(Output, OutputOffset, Lanes, 0, BytesThisRound)
		OutputOffset += BytesThisRound

		if OutputOffset < OutputBytes then
			Keccak(Lanes, SQUEEZE_ZERO, 0, RateBytes, RateBytes)
		end
	end
	
	return Output
end

SHA3.Keccak_Internal = Keccak

function SHA3.SHA3_256_Internal(Message: buffer): buffer
	return ProcessSponge(Message, 512, 32, 0x06)
end

function SHA3.SHA3_512_Internal(Message: buffer): buffer
	return ProcessSponge(Message, 1024, 64, 0x06)
end

function SHA3.SHAKE256_Internal(Message: buffer, OutputBytes: number): buffer
	return ProcessSponge(Message, 512, OutputBytes, 0x1F)
end

function SHA3.SHA3_224(Message: buffer): (string, buffer)
	local Buf = ProcessSponge(Message, 448, 28, 0x06)
	return ToHex(Buf), Buf
end

function SHA3.SHA3_256(Message: buffer): (string, buffer)
	local Buf = ProcessSponge(Message, 512, 32, 0x06)
	return ToHex(Buf), Buf
end

function SHA3.SHA3_384(Message: buffer): (string, buffer)
	local Buf = ProcessSponge(Message, 768, 48, 0x06)
	return ToHex(Buf), Buf
end

function SHA3.SHA3_512(Message: buffer): (string, buffer)
	local Buf = ProcessSponge(Message, 1024, 64, 0x06)
	return ToHex(Buf), Buf
end

function SHA3.SHAKE128(Message: buffer, OutputBytes: number): (string, buffer)
	local Buf = ProcessSponge(Message, 256, OutputBytes, 0x1F)
	return ToHex(Buf), Buf
end

function SHA3.SHAKE256(Message: buffer, OutputBytes: number): (string, buffer)
	local Buf = ProcessSponge(Message, 512, OutputBytes, 0x1F)
	return ToHex(Buf), Buf
end

return SHA3
