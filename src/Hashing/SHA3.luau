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

local Scratch = buffer.create(200)

local function Keccak(Lanes: buffer, InputBuffer: buffer, Offset: number, Size: number, BlockSizeInBytes: number): ()
	local QuadWordsQuantity = BlockSizeInBytes // 8
	local RC = ROUND_CONSTANTS
	local B = Scratch

	for Position = Offset, Offset + Size - 1, BlockSizeInBytes do
		for Index = 0, (QuadWordsQuantity - 1) * 8, 8 do
			buffer.writeinteger(Lanes, Index, integer.bxor(
				buffer.readinteger(Lanes, Index),
				buffer.readinteger(InputBuffer, Position + Index)
			))
		end

		for Round = 0, 184, 8 do
			local C0 = integer.bxor(buffer.readinteger(Lanes, 0), buffer.readinteger(Lanes, 40), buffer.readinteger(Lanes, 80), buffer.readinteger(Lanes, 120), buffer.readinteger(Lanes, 160))
			local C1 = integer.bxor(buffer.readinteger(Lanes, 8), buffer.readinteger(Lanes, 48), buffer.readinteger(Lanes, 88), buffer.readinteger(Lanes, 128), buffer.readinteger(Lanes, 168))
			local C2 = integer.bxor(buffer.readinteger(Lanes, 16), buffer.readinteger(Lanes, 56), buffer.readinteger(Lanes, 96), buffer.readinteger(Lanes, 136), buffer.readinteger(Lanes, 176))
			local C3 = integer.bxor(buffer.readinteger(Lanes, 24), buffer.readinteger(Lanes, 64), buffer.readinteger(Lanes, 104), buffer.readinteger(Lanes, 144), buffer.readinteger(Lanes, 184))
			local C4 = integer.bxor(buffer.readinteger(Lanes, 32), buffer.readinteger(Lanes, 72), buffer.readinteger(Lanes, 112), buffer.readinteger(Lanes, 152), buffer.readinteger(Lanes, 192))
			local D0 = integer.bxor(C4, integer.lrotate(C1, 1i))
			local D1 = integer.bxor(C0, integer.lrotate(C2, 1i))
			local D2 = integer.bxor(C1, integer.lrotate(C3, 1i))
			local D3 = integer.bxor(C2, integer.lrotate(C4, 1i))
			local D4 = integer.bxor(C3, integer.lrotate(C0, 1i))
			buffer.writeinteger(B, 0, integer.bxor(buffer.readinteger(Lanes, 0), D0))
			buffer.writeinteger(B, 80, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 8), D1), 1i))
			buffer.writeinteger(B, 160, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 16), D2), 62i))
			buffer.writeinteger(B, 40, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 24), D3), 28i))
			buffer.writeinteger(B, 120, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 32), D4), 27i))
			buffer.writeinteger(B, 128, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 40), D0), 36i))
			buffer.writeinteger(B, 8, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 48), D1), 44i))
			buffer.writeinteger(B, 88, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 56), D2), 6i))
			buffer.writeinteger(B, 168, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 64), D3), 55i))
			buffer.writeinteger(B, 48, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 72), D4), 20i))
			buffer.writeinteger(B, 56, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 80), D0), 3i))
			buffer.writeinteger(B, 136, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 88), D1), 10i))
			buffer.writeinteger(B, 16, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 96), D2), 43i))
			buffer.writeinteger(B, 96, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 104), D3), 25i))
			buffer.writeinteger(B, 176, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 112), D4), 39i))
			buffer.writeinteger(B, 184, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 120), D0), 41i))
			buffer.writeinteger(B, 64, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 128), D1), 45i))
			buffer.writeinteger(B, 144, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 136), D2), 15i))
			buffer.writeinteger(B, 24, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 144), D3), 21i))
			buffer.writeinteger(B, 104, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 152), D4), 8i))
			buffer.writeinteger(B, 112, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 160), D0), 18i))
			buffer.writeinteger(B, 192, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 168), D1), 2i))
			buffer.writeinteger(B, 72, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 176), D2), 61i))
			buffer.writeinteger(B, 152, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 184), D3), 56i))
			buffer.writeinteger(B, 32, integer.lrotate(integer.bxor(buffer.readinteger(Lanes, 192), D4), 14i))
			buffer.writeinteger(Lanes, 0, integer.bxor(buffer.readinteger(B, 0), integer.band(integer.bnot(buffer.readinteger(B, 8)), buffer.readinteger(B, 16))))
			buffer.writeinteger(Lanes, 8, integer.bxor(buffer.readinteger(B, 8), integer.band(integer.bnot(buffer.readinteger(B, 16)), buffer.readinteger(B, 24))))
			buffer.writeinteger(Lanes, 16, integer.bxor(buffer.readinteger(B, 16), integer.band(integer.bnot(buffer.readinteger(B, 24)), buffer.readinteger(B, 32))))
			buffer.writeinteger(Lanes, 24, integer.bxor(buffer.readinteger(B, 24), integer.band(integer.bnot(buffer.readinteger(B, 32)), buffer.readinteger(B, 0))))
			buffer.writeinteger(Lanes, 32, integer.bxor(buffer.readinteger(B, 32), integer.band(integer.bnot(buffer.readinteger(B, 0)), buffer.readinteger(B, 8))))
			buffer.writeinteger(Lanes, 40, integer.bxor(buffer.readinteger(B, 40), integer.band(integer.bnot(buffer.readinteger(B, 48)), buffer.readinteger(B, 56))))
			buffer.writeinteger(Lanes, 48, integer.bxor(buffer.readinteger(B, 48), integer.band(integer.bnot(buffer.readinteger(B, 56)), buffer.readinteger(B, 64))))
			buffer.writeinteger(Lanes, 56, integer.bxor(buffer.readinteger(B, 56), integer.band(integer.bnot(buffer.readinteger(B, 64)), buffer.readinteger(B, 72))))
			buffer.writeinteger(Lanes, 64, integer.bxor(buffer.readinteger(B, 64), integer.band(integer.bnot(buffer.readinteger(B, 72)), buffer.readinteger(B, 40))))
			buffer.writeinteger(Lanes, 72, integer.bxor(buffer.readinteger(B, 72), integer.band(integer.bnot(buffer.readinteger(B, 40)), buffer.readinteger(B, 48))))
			buffer.writeinteger(Lanes, 80, integer.bxor(buffer.readinteger(B, 80), integer.band(integer.bnot(buffer.readinteger(B, 88)), buffer.readinteger(B, 96))))
			buffer.writeinteger(Lanes, 88, integer.bxor(buffer.readinteger(B, 88), integer.band(integer.bnot(buffer.readinteger(B, 96)), buffer.readinteger(B, 104))))
			buffer.writeinteger(Lanes, 96, integer.bxor(buffer.readinteger(B, 96), integer.band(integer.bnot(buffer.readinteger(B, 104)), buffer.readinteger(B, 112))))
			buffer.writeinteger(Lanes, 104, integer.bxor(buffer.readinteger(B, 104), integer.band(integer.bnot(buffer.readinteger(B, 112)), buffer.readinteger(B, 80))))
			buffer.writeinteger(Lanes, 112, integer.bxor(buffer.readinteger(B, 112), integer.band(integer.bnot(buffer.readinteger(B, 80)), buffer.readinteger(B, 88))))
			buffer.writeinteger(Lanes, 120, integer.bxor(buffer.readinteger(B, 120), integer.band(integer.bnot(buffer.readinteger(B, 128)), buffer.readinteger(B, 136))))
			buffer.writeinteger(Lanes, 128, integer.bxor(buffer.readinteger(B, 128), integer.band(integer.bnot(buffer.readinteger(B, 136)), buffer.readinteger(B, 144))))
			buffer.writeinteger(Lanes, 136, integer.bxor(buffer.readinteger(B, 136), integer.band(integer.bnot(buffer.readinteger(B, 144)), buffer.readinteger(B, 152))))
			buffer.writeinteger(Lanes, 144, integer.bxor(buffer.readinteger(B, 144), integer.band(integer.bnot(buffer.readinteger(B, 152)), buffer.readinteger(B, 120))))
			buffer.writeinteger(Lanes, 152, integer.bxor(buffer.readinteger(B, 152), integer.band(integer.bnot(buffer.readinteger(B, 120)), buffer.readinteger(B, 128))))
			buffer.writeinteger(Lanes, 160, integer.bxor(buffer.readinteger(B, 160), integer.band(integer.bnot(buffer.readinteger(B, 168)), buffer.readinteger(B, 176))))
			buffer.writeinteger(Lanes, 168, integer.bxor(buffer.readinteger(B, 168), integer.band(integer.bnot(buffer.readinteger(B, 176)), buffer.readinteger(B, 184))))
			buffer.writeinteger(Lanes, 176, integer.bxor(buffer.readinteger(B, 176), integer.band(integer.bnot(buffer.readinteger(B, 184)), buffer.readinteger(B, 192))))
			buffer.writeinteger(Lanes, 184, integer.bxor(buffer.readinteger(B, 184), integer.band(integer.bnot(buffer.readinteger(B, 192)), buffer.readinteger(B, 160))))
			buffer.writeinteger(Lanes, 192, integer.bxor(buffer.readinteger(B, 192), integer.band(integer.bnot(buffer.readinteger(B, 160)), buffer.readinteger(B, 168))))
			buffer.writeinteger(Lanes, 0, integer.bxor(buffer.readinteger(Lanes, 0), buffer.readinteger(RC, Round)))
		end
	end
end


local function ProcessSponge(Message: buffer, CapacityBits: number, OutputBytes: number, DomainSeparator: number): buffer
	local RateBytes = (1600 - CapacityBits) // 8
	buffer.fill(LANES, 0, 0)

	local Lanes = LANES

	local MessageLength: number = buffer.len(Message)
	local PaddedLength: number = MessageLength + 1

	local Remainder = PaddedLength % RateBytes
	if Remainder ~= 0 then
		PaddedLength += (RateBytes - Remainder)
	end

	local PaddedMessage = buffer.create(PaddedLength)

	if MessageLength > 0 then
		buffer.copy(PaddedMessage, 0, Message, 0, MessageLength)
	end

	if PaddedLength - MessageLength == 1 then
		buffer.writeu8(PaddedMessage, MessageLength, bit32.bor(DomainSeparator, 0x80))
	else
		buffer.writeu8(PaddedMessage, MessageLength, DomainSeparator)
		if PaddedLength - MessageLength > 2 then
			buffer.fill(PaddedMessage, MessageLength + 1, 0, PaddedLength - MessageLength - 2)
		end
		buffer.writeu8(PaddedMessage, PaddedLength - 1, 0x80)
	end

	Keccak(Lanes, PaddedMessage, 0, PaddedLength, RateBytes)

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
