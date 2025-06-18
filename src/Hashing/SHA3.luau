--[=[
	Cryptography library: Keccak/SHA-3
	
	Return type: string
	Example usage:
		local Message = buffer.fromstring("Hello World")
		
		local Result1 = SHA3_256(Message)
		local Result2 = SHAKE128(Message, 32)
--]=]

--!native
--!optimize 2
--!strict

local RoundConstantsLo = {
	0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001, 0x80008081, 0x00008009,
	0x0000008a, 0x00000088, 0x80008009, 0x8000000a, 0x8000808b, 0x0000008b, 0x00008089, 0x00008003,
	0x00008002, 0x00000080, 0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008
}

local RoundConstantsHi = {
	0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x00000000, 0x00000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x80000000,
	0x80000000, 0x80000000, 0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x00000000, 0x80000000
}

local PiLanes = {
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
}

local RhoOffsets = {
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
}

local SHA3 = {}

local State = buffer.create(200)
local TempState = buffer.create(200)
local OutputBuffer = buffer.create(64)
local HexChars = "0123456789abcdef"

local function RotateLeft64(LoWord: number, HiWord: number, Bits: number): (number, number)
	if Bits == 0 then
		return LoWord, HiWord
	elseif Bits == 32 then
		return HiWord, LoWord
	elseif Bits < 32 then
		return bit32.bor(bit32.lshift(LoWord, Bits), bit32.rshift(HiWord, 32 - Bits)), bit32.bor(bit32.lshift(HiWord, Bits), bit32.rshift(LoWord, 32 - Bits))
	else
		Bits -= 32
		return bit32.bor(bit32.lshift(HiWord, Bits), bit32.rshift(LoWord, 32 - Bits)), bit32.bor(bit32.lshift(LoWord, Bits), bit32.rshift(HiWord, 32 - Bits))
	end
end

local function PreProcessMessage(Message: buffer, RateBytes: number, DomainSeparator: number): buffer
	local MessageLength = buffer.len(Message)
	local PaddedLength = MessageLength + 1

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

	return PaddedMessage
end

local function KeccakF1600()
	local StateBuffer = State
	local TempStateBuffer = TempState

	local RoundConstLo = RoundConstantsLo
	local RoundConstHi = RoundConstantsHi
	local Pi = PiLanes
	local Rho = RhoOffsets

	for Round = 0, 23 do
		local C0Lo = bit32.bxor(buffer.readu32(StateBuffer, 0), buffer.readu32(StateBuffer, 40), buffer.readu32(StateBuffer, 80), buffer.readu32(StateBuffer, 120), buffer.readu32(StateBuffer, 160))
		local C0Hi = bit32.bxor(buffer.readu32(StateBuffer, 4), buffer.readu32(StateBuffer, 44), buffer.readu32(StateBuffer, 84), buffer.readu32(StateBuffer, 124), buffer.readu32(StateBuffer, 164))

		local C1Lo = bit32.bxor(buffer.readu32(StateBuffer, 8), buffer.readu32(StateBuffer, 48), buffer.readu32(StateBuffer, 88), buffer.readu32(StateBuffer, 128), buffer.readu32(StateBuffer, 168))
		local C1Hi = bit32.bxor(buffer.readu32(StateBuffer, 12), buffer.readu32(StateBuffer, 52), buffer.readu32(StateBuffer, 92), buffer.readu32(StateBuffer, 132), buffer.readu32(StateBuffer, 172))

		local C2Lo = bit32.bxor(buffer.readu32(StateBuffer, 16), buffer.readu32(StateBuffer, 56), buffer.readu32(StateBuffer, 96), buffer.readu32(StateBuffer, 136), buffer.readu32(StateBuffer, 176))
		local C2Hi = bit32.bxor(buffer.readu32(StateBuffer, 20), buffer.readu32(StateBuffer, 60), buffer.readu32(StateBuffer, 100), buffer.readu32(StateBuffer, 140), buffer.readu32(StateBuffer, 180))

		local C3Lo = bit32.bxor(buffer.readu32(StateBuffer, 24), buffer.readu32(StateBuffer, 64), buffer.readu32(StateBuffer, 104), buffer.readu32(StateBuffer, 144), buffer.readu32(StateBuffer, 184))
		local C3Hi = bit32.bxor(buffer.readu32(StateBuffer, 28), buffer.readu32(StateBuffer, 68), buffer.readu32(StateBuffer, 108), buffer.readu32(StateBuffer, 148), buffer.readu32(StateBuffer, 188))

		local C4Lo = bit32.bxor(buffer.readu32(StateBuffer, 32), buffer.readu32(StateBuffer, 72), buffer.readu32(StateBuffer, 112), buffer.readu32(StateBuffer, 152), buffer.readu32(StateBuffer, 192))
		local C4Hi = bit32.bxor(buffer.readu32(StateBuffer, 36), buffer.readu32(StateBuffer, 76), buffer.readu32(StateBuffer, 116), buffer.readu32(StateBuffer, 156), buffer.readu32(StateBuffer, 196))

		local D0Lo, D0Hi = RotateLeft64(C1Lo, C1Hi, 1)
		D0Lo = bit32.bxor(C4Lo, D0Lo)
		D0Hi = bit32.bxor(C4Hi, D0Hi)
		buffer.writeu32(StateBuffer, 0, bit32.bxor(buffer.readu32(StateBuffer, 0), D0Lo))
		buffer.writeu32(StateBuffer, 4, bit32.bxor(buffer.readu32(StateBuffer, 4), D0Hi))
		buffer.writeu32(StateBuffer, 40, bit32.bxor(buffer.readu32(StateBuffer, 40), D0Lo))
		buffer.writeu32(StateBuffer, 44, bit32.bxor(buffer.readu32(StateBuffer, 44), D0Hi))
		buffer.writeu32(StateBuffer, 80, bit32.bxor(buffer.readu32(StateBuffer, 80), D0Lo))
		buffer.writeu32(StateBuffer, 84, bit32.bxor(buffer.readu32(StateBuffer, 84), D0Hi))
		buffer.writeu32(StateBuffer, 120, bit32.bxor(buffer.readu32(StateBuffer, 120), D0Lo))
		buffer.writeu32(StateBuffer, 124, bit32.bxor(buffer.readu32(StateBuffer, 124), D0Hi))
		buffer.writeu32(StateBuffer, 160, bit32.bxor(buffer.readu32(StateBuffer, 160), D0Lo))
		buffer.writeu32(StateBuffer, 164, bit32.bxor(buffer.readu32(StateBuffer, 164), D0Hi))

		local D1Lo, D1Hi = RotateLeft64(C2Lo, C2Hi, 1)
		D1Lo = bit32.bxor(C0Lo, D1Lo)
		D1Hi = bit32.bxor(C0Hi, D1Hi)
		local Lane1Lo = bit32.bxor(buffer.readu32(StateBuffer, 8), D1Lo)
		local Lane1Hi = bit32.bxor(buffer.readu32(StateBuffer, 12), D1Hi)
		buffer.writeu32(StateBuffer, 8, Lane1Lo)
		buffer.writeu32(StateBuffer, 12, Lane1Hi)
		buffer.writeu32(StateBuffer, 48, bit32.bxor(buffer.readu32(StateBuffer, 48), D1Lo))
		buffer.writeu32(StateBuffer, 52, bit32.bxor(buffer.readu32(StateBuffer, 52), D1Hi))
		buffer.writeu32(StateBuffer, 88, bit32.bxor(buffer.readu32(StateBuffer, 88), D1Lo))
		buffer.writeu32(StateBuffer, 92, bit32.bxor(buffer.readu32(StateBuffer, 92), D1Hi))
		buffer.writeu32(StateBuffer, 128, bit32.bxor(buffer.readu32(StateBuffer, 128), D1Lo))
		buffer.writeu32(StateBuffer, 132, bit32.bxor(buffer.readu32(StateBuffer, 132), D1Hi))
		buffer.writeu32(StateBuffer, 168, bit32.bxor(buffer.readu32(StateBuffer, 168), D1Lo))
		buffer.writeu32(StateBuffer, 172, bit32.bxor(buffer.readu32(StateBuffer, 172), D1Hi))

		local D2Lo, D2Hi = RotateLeft64(C3Lo, C3Hi, 1)
		D2Lo = bit32.bxor(C1Lo, D2Lo)
		D2Hi = bit32.bxor(C1Hi, D2Hi)
		buffer.writeu32(StateBuffer, 16, bit32.bxor(buffer.readu32(StateBuffer, 16), D2Lo))
		buffer.writeu32(StateBuffer, 20, bit32.bxor(buffer.readu32(StateBuffer, 20), D2Hi))
		buffer.writeu32(StateBuffer, 56, bit32.bxor(buffer.readu32(StateBuffer, 56), D2Lo))
		buffer.writeu32(StateBuffer, 60, bit32.bxor(buffer.readu32(StateBuffer, 60), D2Hi))
		buffer.writeu32(StateBuffer, 96, bit32.bxor(buffer.readu32(StateBuffer, 96), D2Lo))
		buffer.writeu32(StateBuffer, 100, bit32.bxor(buffer.readu32(StateBuffer, 100), D2Hi))
		buffer.writeu32(StateBuffer, 136, bit32.bxor(buffer.readu32(StateBuffer, 136), D2Lo))
		buffer.writeu32(StateBuffer, 140, bit32.bxor(buffer.readu32(StateBuffer, 140), D2Hi))
		buffer.writeu32(StateBuffer, 176, bit32.bxor(buffer.readu32(StateBuffer, 176), D2Lo))
		buffer.writeu32(StateBuffer, 180, bit32.bxor(buffer.readu32(StateBuffer, 180), D2Hi))

		local D3Lo, D3Hi = RotateLeft64(C4Lo, C4Hi, 1)
		D3Lo = bit32.bxor(C2Lo, D3Lo)
		D3Hi = bit32.bxor(C2Hi, D3Hi)
		buffer.writeu32(StateBuffer, 24, bit32.bxor(buffer.readu32(StateBuffer, 24), D3Lo))
		buffer.writeu32(StateBuffer, 28, bit32.bxor(buffer.readu32(StateBuffer, 28), D3Hi))
		buffer.writeu32(StateBuffer, 64, bit32.bxor(buffer.readu32(StateBuffer, 64), D3Lo))
		buffer.writeu32(StateBuffer, 68, bit32.bxor(buffer.readu32(StateBuffer, 68), D3Hi))
		buffer.writeu32(StateBuffer, 104, bit32.bxor(buffer.readu32(StateBuffer, 104), D3Lo))
		buffer.writeu32(StateBuffer, 108, bit32.bxor(buffer.readu32(StateBuffer, 108), D3Hi))
		buffer.writeu32(StateBuffer, 144, bit32.bxor(buffer.readu32(StateBuffer, 144), D3Lo))
		buffer.writeu32(StateBuffer, 148, bit32.bxor(buffer.readu32(StateBuffer, 148), D3Hi))
		buffer.writeu32(StateBuffer, 184, bit32.bxor(buffer.readu32(StateBuffer, 184), D3Lo))
		buffer.writeu32(StateBuffer, 188, bit32.bxor(buffer.readu32(StateBuffer, 188), D3Hi))

		local D4Lo, D4Hi = RotateLeft64(C0Lo, C0Hi, 1)
		D4Lo = bit32.bxor(C3Lo, D4Lo)
		D4Hi = bit32.bxor(C3Hi, D4Hi)
		buffer.writeu32(StateBuffer, 32, bit32.bxor(buffer.readu32(StateBuffer, 32), D4Lo))
		buffer.writeu32(StateBuffer, 36, bit32.bxor(buffer.readu32(StateBuffer, 36), D4Hi))
		buffer.writeu32(StateBuffer, 72, bit32.bxor(buffer.readu32(StateBuffer, 72), D4Lo))
		buffer.writeu32(StateBuffer, 76, bit32.bxor(buffer.readu32(StateBuffer, 76), D4Hi))
		buffer.writeu32(StateBuffer, 112, bit32.bxor(buffer.readu32(StateBuffer, 112), D4Lo))
		buffer.writeu32(StateBuffer, 116, bit32.bxor(buffer.readu32(StateBuffer, 116), D4Hi))
		buffer.writeu32(StateBuffer, 152, bit32.bxor(buffer.readu32(StateBuffer, 152), D4Lo))
		buffer.writeu32(StateBuffer, 156, bit32.bxor(buffer.readu32(StateBuffer, 156), D4Hi))
		buffer.writeu32(StateBuffer, 192, bit32.bxor(buffer.readu32(StateBuffer, 192), D4Lo))
		buffer.writeu32(StateBuffer, 196, bit32.bxor(buffer.readu32(StateBuffer, 196), D4Hi))

		buffer.copy(TempStateBuffer, 0, StateBuffer, 0, 200)

		local TempLo = Lane1Lo
		local TempHi = Lane1Hi

		for Step = 1, 24 do
			local TargetLane = Pi[Step]
			local TargetOffset = TargetLane * 8

			local NextLo = buffer.readu32(TempStateBuffer, TargetOffset)
			local NextHi = buffer.readu32(TempStateBuffer, TargetOffset + 4)

			local RotLo, RotHi = RotateLeft64(TempLo, TempHi, Rho[Step])

			buffer.writeu32(StateBuffer, TargetOffset, RotLo)
			buffer.writeu32(StateBuffer, TargetOffset + 4, RotHi)

			TempLo, TempHi = NextLo, NextHi
		end

		buffer.copy(TempStateBuffer, 0, StateBuffer, 0, 200)
		for Y = 0, 160, 40 do
			for X = 0, 4 do
				local Offset = Y + X * 8
				local X1Offset = Y + ((X + 1) % 5) * 8
				local X2Offset = Y + ((X + 2) % 5) * 8

				local Lo = buffer.readu32(TempStateBuffer, Offset)
				local Hi = buffer.readu32(TempStateBuffer, Offset + 4)
				local Lo1 = buffer.readu32(TempStateBuffer, X1Offset)
				local Hi1 = buffer.readu32(TempStateBuffer, X1Offset + 4)
				local Lo2 = buffer.readu32(TempStateBuffer, X2Offset)
				local Hi2 = buffer.readu32(TempStateBuffer, X2Offset + 4)

				buffer.writeu32(StateBuffer, Offset, bit32.bxor(Lo, bit32.band(bit32.bnot(Lo1), Lo2)))
				buffer.writeu32(StateBuffer, Offset + 4, bit32.bxor(Hi, bit32.band(bit32.bnot(Hi1), Hi2)))
			end
		end

		buffer.writeu32(StateBuffer, 0, bit32.bxor(buffer.readu32(StateBuffer, 0), RoundConstLo[Round + 1]))
		buffer.writeu32(StateBuffer, 4, bit32.bxor(buffer.readu32(StateBuffer, 4), RoundConstHi[Round + 1]))
	end
end

local function ProcessSponge(Message: buffer, CapacityBits: number, OutputBytes: number, DomainSeparator: number): string
	local RateBytes = (1600 - CapacityBits) // 8
	local StateBuffer = State
	local Output_Buffer = OutputBuffer
	local Hex_Chars = HexChars

	buffer.fill(StateBuffer, 0, 0, 200)

	local PaddedMessage = PreProcessMessage(Message, RateBytes, DomainSeparator)
	local PaddedLength = buffer.len(PaddedMessage)

	for Offset = 0, PaddedLength - 1, RateBytes do
		local LanesInBlock = RateBytes // 8
		if LanesInBlock >= 8 then
			local ByteOffset = Offset
			local StateOffset = 0

			for Lane = 0, 7 do
				local Lo = buffer.readu32(PaddedMessage, ByteOffset)
				local Hi = buffer.readu32(PaddedMessage, ByteOffset + 4)

				buffer.writeu32(StateBuffer, StateOffset, bit32.bxor(buffer.readu32(StateBuffer, StateOffset), Lo))
				buffer.writeu32(StateBuffer, StateOffset + 4, bit32.bxor(buffer.readu32(StateBuffer, StateOffset + 4), Hi))

				ByteOffset += 8
				StateOffset += 8
			end

			for Lane = 8, LanesInBlock - 1 do
				local Lo = buffer.readu32(PaddedMessage, ByteOffset)
				local Hi = buffer.readu32(PaddedMessage, ByteOffset + 4)

				buffer.writeu32(StateBuffer, StateOffset, bit32.bxor(buffer.readu32(StateBuffer, StateOffset), Lo))
				buffer.writeu32(StateBuffer, StateOffset + 4, bit32.bxor(buffer.readu32(StateBuffer, StateOffset + 4), Hi))

				ByteOffset += 8
				StateOffset += 8
			end
		else
			for Lane = 0, LanesInBlock - 1 do
				local ByteOffset = Offset + Lane * 8
				local StateOffset = Lane * 8

				local Lo = buffer.readu32(PaddedMessage, ByteOffset)
				local Hi = buffer.readu32(PaddedMessage, ByteOffset + 4)

				buffer.writeu32(StateBuffer, StateOffset, bit32.bxor(buffer.readu32(StateBuffer, StateOffset), Lo))
				buffer.writeu32(StateBuffer, StateOffset + 4, bit32.bxor(buffer.readu32(StateBuffer, StateOffset + 4), Hi))
			end
		end

		KeccakF1600()
	end

	local Output = OutputBytes <= 64 and Output_Buffer or buffer.create(OutputBytes)
	local OutputOffset = 0

	while OutputOffset < OutputBytes do
		local BytesThisRound = math.min(RateBytes, OutputBytes - OutputOffset)

		for ByteIndex = 0, BytesThisRound - 1 do
			local AbsoluteIndex = OutputOffset + ByteIndex
			if AbsoluteIndex < OutputBytes then
				local Lane = ByteIndex // 8
				local ByteInLane = ByteIndex % 8
				local StateOffset = Lane * 8

				local Value
				if ByteInLane < 4 then
					Value = bit32.extract(buffer.readu32(StateBuffer, StateOffset), ByteInLane * 8, 8)
				else
					Value = bit32.extract(buffer.readu32(StateBuffer, StateOffset + 4), (ByteInLane - 4) * 8, 8)
				end
				buffer.writeu8(Output, AbsoluteIndex, Value)
			end
		end

		OutputOffset += BytesThisRound

		if OutputOffset < OutputBytes then
			KeccakF1600()
		end
	end

	local HexParts = {}
	for Index = 0, OutputBytes - 1 do
		local Byte = buffer.readu8(Output, Index)
		local Hi = bit32.rshift(Byte, 4) + 1
		local Lo = bit32.band(Byte, 15) + 1
		HexParts[Index + 1] = string.sub(Hex_Chars, Hi, Hi) .. string.sub(Hex_Chars, Lo, Lo)
	end

	return table.concat(HexParts)
end

function SHA3.SHA3_224(Message: buffer): string
	return ProcessSponge(Message, 448, 28, 0x06)
end

function SHA3.SHA3_256(Message: buffer): string
	return ProcessSponge(Message, 512, 32, 0x06)
end

function SHA3.SHA3_384(Message: buffer): string
	return ProcessSponge(Message, 768, 48, 0x06)
end

function SHA3.SHA3_512(Message: buffer): string
	return ProcessSponge(Message, 1024, 64, 0x06)
end

function SHA3.SHAKE128(Message: buffer, OutputBytes: number): string
	return ProcessSponge(Message, 256, OutputBytes, 0x1F)
end

function SHA3.SHAKE256(Message: buffer, OutputBytes: number): string
	return ProcessSponge(Message, 512, OutputBytes, 0x1F)
end

return SHA3
