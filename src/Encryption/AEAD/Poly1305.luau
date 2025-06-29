--[=[
	Cryptography library: Poly1305
	
	Sizes:
		Key: 32 bytes
		Tag: 16 bytes
	
	Return type: buffer
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Key = buffer.fromstring(string.rep("k", 32))
		
		local Tag = Poly1305(Message, Key)
--]=]

--!strict
--!native
--!optimize 2

local TAG_SIZE = 16
local BLOCK_SIZE = 16
local POLY1305_KEY_SIZE = 32

local function ProcessMessage(Message: buffer, Key: buffer): buffer
	local MessageLength = buffer.len(Message)

	local PaddedMessage = Message
	local ProcessLength = MessageLength

	if MessageLength % BLOCK_SIZE ~= 0 or MessageLength == 0 then
		local PaddingSize = BLOCK_SIZE - (MessageLength % BLOCK_SIZE)
		ProcessLength = MessageLength + PaddingSize
		PaddedMessage = buffer.create(ProcessLength)
		buffer.copy(PaddedMessage, 0, Message, 0, MessageLength)
		buffer.writeu8(PaddedMessage, MessageLength, 1)
	end

	local PartialBlockLength = MessageLength - 15

	local R0 = buffer.readu32(Key, 0) % (2 ^ 28)
	local R1 = bit32.band(buffer.readu32(Key, 4), 0x0FFFFFFC) % (2 ^ 28) * (2 ^ 32)
	local R2 = bit32.band(buffer.readu32(Key, 8), 0x0FFFFFFC) % (2 ^ 28) * (2 ^ 64)
	local R3 = bit32.band(buffer.readu32(Key, 12), 0x0FFFFFFC) % (2 ^ 28) * (2 ^ 96)

	local R0Low = R0 % (2 ^ 18)
	local R0High = R0 - R0Low
	local R1Low = R1 % (2 ^ 50)
	local R1High = R1 - R1Low
	local R2Low = R2 % (2 ^ 82)
	local R2High = R2 - R2Low
	local R3Low = R3 % (2 ^ 112)
	local R3High = R3 - R3Low

	local S1 = 5 / (2 ^ 130) * R1
	local S2 = 5 / (2 ^ 130) * R2
	local S3 = 5 / (2 ^ 130) * R3

	local S1Low = S1 % (2 ^ -80)
	local S1High = S1 - S1Low
	local S2Low = S2 % (2 ^ -48)
	local S2High = S2 - S2Low
	local S3Low = S3 % (2 ^ -16)
	local S3High = S3 - S3Low

	local Accumulator0, Accumulator1, Accumulator2, Accumulator3 = 0, 0, 0, 0
	local Accumulator4, Accumulator5, Accumulator6, Accumulator7 = 0, 0, 0, 0

	for BlockOffset = 0, ProcessLength - 1, BLOCK_SIZE do
		local MessageBlock0 = buffer.readu32(PaddedMessage, BlockOffset)
		local MessageBlock1 = buffer.readu32(PaddedMessage, BlockOffset + 4)
		local MessageBlock2 = buffer.readu32(PaddedMessage, BlockOffset + 8)
		local MessageBlock3 = buffer.readu32(PaddedMessage, BlockOffset + 12)

		local X0 = Accumulator0 + Accumulator1 + MessageBlock0
		local X2 = Accumulator2 + Accumulator3 + MessageBlock1 * (2 ^ 32)
		local X4 = Accumulator4 + Accumulator5 + MessageBlock2 * (2 ^ 64)
		local X6 = Accumulator6 + Accumulator7 + MessageBlock3 * (2 ^ 96)

		if BlockOffset < PartialBlockLength then
			X6 = X6 + (2 ^ 128)
		end

		Accumulator0 = X0 * R0Low + X2 * S3Low + X4 * S2Low + X6 * S1Low
		Accumulator1 = X0 * R0High + X2 * S3High + X4 * S2High + X6 * S1High
		Accumulator2 = X0 * R1Low + X2 * R0Low + X4 * S3Low + X6 * S2Low
		Accumulator3 = X0 * R1High + X2 * R0High + X4 * S3High + X6 * S2High
		Accumulator4 = X0 * R2Low + X2 * R1Low + X4 * R0Low + X6 * S3Low
		Accumulator5 = X0 * R2High + X2 * R1High + X4 * R0High + X6 * S3High
		Accumulator6 = X0 * R3Low + X2 * R2Low + X4 * R1Low + X6 * R0Low
		Accumulator7 = X0 * R3High + X2 * R2High + X4 * R1High + X6 * R0High

		local Y0 = Accumulator0 + 3 * (2 ^ 69) - 3 * (2 ^ 69)
		Accumulator0 -= Y0
		Accumulator1 += Y0

		local Y1 = Accumulator1 + 3 * (2 ^ 83) - 3 * (2 ^ 83)
		Accumulator1 -= Y1
		Accumulator2 += Y1

		local Y2 = Accumulator2 + 3 * (2 ^ 101) - 3 * (2 ^ 101)
		Accumulator2 -= Y2
		Accumulator3 += Y2

		local Y3 = Accumulator3 + 3 * (2 ^ 115) - 3 * (2 ^ 115)
		Accumulator3 -= Y3
		Accumulator4 += Y3

		local Y4 = Accumulator4 + 3 * (2 ^ 133) - 3 * (2 ^ 133)
		Accumulator4 -= Y4
		Accumulator5 += Y4

		local Y5 = Accumulator5 + 3 * (2 ^ 147) - 3 * (2 ^ 147)
		Accumulator5 -= Y5
		Accumulator6 += Y5

		local Y6 = Accumulator6 + 3 * (2 ^ 163) - 3 * (2 ^ 163)
		Accumulator6 -= Y6
		Accumulator7 += Y6

		local Y7 = Accumulator7 + 3 * (2 ^ 181) - 3 * (2 ^ 181)
		Accumulator7 -= Y7

		Accumulator0 += 5 / (2 ^ 130) * Y7
	end

	local Carry0 = Accumulator0 % (2 ^ 16)
	Accumulator1 = Accumulator0 - Carry0 + Accumulator1

	local Carry1 = Accumulator1 % (2 ^ 32)
	Accumulator2 = Accumulator1 - Carry1 + Accumulator2

	local Carry2 = Accumulator2 % (2 ^ 48)
	Accumulator3 = Accumulator2 - Carry2 + Accumulator3

	local Carry3 = Accumulator3 % (2 ^ 64)
	Accumulator4 = Accumulator3 - Carry3 + Accumulator4

	local Carry4 = Accumulator4 % (2 ^ 80)
	Accumulator5 = Accumulator4 - Carry4 + Accumulator5

	local Carry5 = Accumulator5 % (2 ^ 96)
	Accumulator6 = Accumulator5 - Carry5 + Accumulator6

	local Carry6 = Accumulator6 % (2 ^ 112)
	Accumulator7 = Accumulator6 - Carry6 + Accumulator7

	local Carry7 = Accumulator7 % (2 ^ 130)

	Accumulator0 = Carry0 + 5 / (2 ^ 130) * (Accumulator7 - Carry7)
	Carry0 = Accumulator0 % (2 ^ 16)
	Carry1 = Accumulator0 - Carry0 + Carry1

	if Carry7 == 0x3ffff * (2 ^ 112)
		and Carry6 == 0xffff * (2 ^ 96)
		and Carry5 == 0xffff * (2 ^ 80)
		and Carry4 == 0xffff * (2 ^ 64)
		and Carry3 == 0xffff * (2 ^ 48)
		and Carry2 == 0xffff * (2 ^ 32)
		and Carry1 == 0xffff * (2 ^ 16)
		and Carry0 >= 0xfffb
	then
		Carry7, Carry6, Carry5, Carry4 = 0, 0, 0, 0
		Carry3, Carry2, Carry1 = 0, 0, 0
		Carry0 -= 0xfffb
	end

	local S0 = buffer.readu32(Key, 16)
	local S1Val = buffer.readu32(Key, 20)
	local S2Val = buffer.readu32(Key, 24)
	local S3Val = buffer.readu32(Key, 28)

	local Unpacked0 = S0 + Carry0 + Carry1
	local Unpacked1 = Unpacked0 % (2 ^ 32)

	local Unpacked2 = Unpacked0 - Unpacked1 + S1Val * (2 ^ 32) + Carry2 + Carry3
	local Unpacked3 = Unpacked2 % (2 ^ 64)

	local Unpacked4 = Unpacked2 - Unpacked3 + S2Val * (2 ^ 64) + Carry4 + Carry5
	local Unpacked5 = Unpacked4 % (2 ^ 96)

	local Unpacked6 = Unpacked4 - Unpacked5 + S3Val * (2 ^ 96) + Carry6 + Carry7
	local Unpacked7 = Unpacked6 % (2 ^ 128)

	local Output = buffer.create(TAG_SIZE)
	buffer.writeu32(Output, 0, Unpacked1)
	buffer.writeu32(Output, 4, Unpacked3 / (2 ^ 32))
	buffer.writeu32(Output, 8, Unpacked5 / (2 ^ 64))
	buffer.writeu32(Output, 12, Unpacked7 / (2 ^ 96))

	return Output
end

local function Poly1305(Message: buffer, Key: buffer): buffer
	if Message == nil then
		error("Message cannot be nil", 2)
	end

	if typeof(Message) ~= "buffer" then
		error(`Message must be a buffer, got {typeof(Message)}`, 2)
	end

	if Key == nil then
		error("Key cannot be nil", 2)
	end

	if typeof(Key) ~= "buffer" then
		error(`Key must be a buffer, got {typeof(Key)}`, 2)
	end

	local KeyLength = buffer.len(Key)
	if KeyLength ~= POLY1305_KEY_SIZE then
		error(`Key must be exactly {POLY1305_KEY_SIZE} bytes long, got {KeyLength} bytes`, 2)
	end

	return ProcessMessage(Message, Key)
end

return Poly1305
