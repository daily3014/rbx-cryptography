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
--!optimize 2
--!native

local TAG_SIZE = 16
local BLOCK_SIZE = 16
local POLY1305_KEY_SIZE = 32

local M26 = 0x3FFFFFFi
local FIVE = 5i
local HIGH_BIT = 0x1000000i
local P0 = 0x3FFFFFBi

local function ProcessMessage(Message: buffer, Key: buffer): buffer
	local LM26 = M26
	local LFIVE = FIVE
	local LHIGH_BIT = HIGH_BIT
	local LP0 = P0
	local MessageLength = buffer.len(Message)

	local PaddedMessage = Message
	local ProcessLength = MessageLength
	local PartialBlockOffset = -1

	if MessageLength % BLOCK_SIZE ~= 0 or MessageLength == 0 then
		local PaddingSize = BLOCK_SIZE - (MessageLength % BLOCK_SIZE)
		ProcessLength = MessageLength + PaddingSize
		PaddedMessage = buffer.create(ProcessLength)
		buffer.copy(PaddedMessage, 0, Message, 0, MessageLength)
		buffer.writeu8(PaddedMessage, MessageLength, 1)
		PartialBlockOffset = ProcessLength - BLOCK_SIZE
	end

	local KeyLow8 = buffer.readinteger(Key, 0)
	local KeyHigh8 = buffer.readinteger(Key, 8)

	local R0 = integer.band(KeyLow8, 0x3FFFFFFi)
	local R1 = integer.band(integer.rshift(KeyLow8, 26i), 0x3FFFF03i)
	local R2 = integer.band(integer.bor(integer.rshift(KeyLow8, 52i), integer.lshift(KeyHigh8, 12i)), 0x3FFC0FFi)
	local R3 = integer.band(integer.rshift(KeyHigh8, 14i), 0x3F03FFFi)
	local R4 = integer.band(integer.rshift(KeyHigh8, 40i), 0x00FFFFFi)

	local S1 = integer.mul(R1, LFIVE)
	local S2 = integer.mul(R2, LFIVE)
	local S3 = integer.mul(R3, LFIVE)
	local S4 = integer.mul(R4, LFIVE)

	local H0, H1, H2, H3, H4 = 0i, 0i, 0i, 0i, 0i

	for BlockOffset = 0, ProcessLength - 1, BLOCK_SIZE do
		local MLow8 = buffer.readinteger(PaddedMessage, BlockOffset)
		local MHigh8 = buffer.readinteger(PaddedMessage, BlockOffset + 8)

		local M0 = integer.band(MLow8, LM26)
		local M1 = integer.band(integer.rshift(MLow8, 26i), LM26)
		local M2 = integer.band(integer.bor(integer.rshift(MLow8, 52i), integer.lshift(MHigh8, 12i)), LM26)
		local M3 = integer.band(integer.rshift(MHigh8, 14i), LM26)
		local M4 = integer.rshift(MHigh8, 40i)

		if BlockOffset ~= PartialBlockOffset then
			M4 = integer.bor(M4, LHIGH_BIT)
		end

		H0 = integer.add(H0, M0)
		H1 = integer.add(H1, M1)
		H2 = integer.add(H2, M2)
		H3 = integer.add(H3, M3)
		H4 = integer.add(H4, M4)

		local D0 = integer.add(integer.add(integer.add(integer.add(
			integer.mul(H0, R0), integer.mul(H1, S4)),
			integer.mul(H2, S3)), integer.mul(H3, S2)),
			integer.mul(H4, S1))
		local D1 = integer.add(integer.add(integer.add(integer.add(
			integer.mul(H0, R1), integer.mul(H1, R0)),
			integer.mul(H2, S4)), integer.mul(H3, S3)),
			integer.mul(H4, S2))
		local D2 = integer.add(integer.add(integer.add(integer.add(
			integer.mul(H0, R2), integer.mul(H1, R1)),
			integer.mul(H2, R0)), integer.mul(H3, S4)),
			integer.mul(H4, S3))
		local D3 = integer.add(integer.add(integer.add(integer.add(
			integer.mul(H0, R3), integer.mul(H1, R2)),
			integer.mul(H2, R1)), integer.mul(H3, R0)),
			integer.mul(H4, S4))
		local D4 = integer.add(integer.add(integer.add(integer.add(
			integer.mul(H0, R4), integer.mul(H1, R3)),
			integer.mul(H2, R2)), integer.mul(H3, R1)),
			integer.mul(H4, R0))

		local C
		C = integer.arshift(D0, 26i); D1 = integer.add(D1, C); H0 = integer.band(D0, LM26)
		C = integer.arshift(D1, 26i); D2 = integer.add(D2, C); H1 = integer.band(D1, LM26)
		C = integer.arshift(D2, 26i); D3 = integer.add(D3, C); H2 = integer.band(D2, LM26)
		C = integer.arshift(D3, 26i); D4 = integer.add(D4, C); H3 = integer.band(D3, LM26)
		C = integer.arshift(D4, 26i); H0 = integer.add(H0, integer.mul(C, LFIVE)); H4 = integer.band(D4, LM26)
		C = integer.arshift(H0, 26i); H1 = integer.add(H1, C); H0 = integer.band(H0, LM26)
	end

	local C
	C = integer.arshift(H1, 26i); H2 = integer.add(H2, C); H1 = integer.band(H1, LM26)
	C = integer.arshift(H2, 26i); H3 = integer.add(H3, C); H2 = integer.band(H2, LM26)
	C = integer.arshift(H3, 26i); H4 = integer.add(H4, C); H3 = integer.band(H3, LM26)
	C = integer.arshift(H4, 26i); H0 = integer.add(H0, integer.mul(C, LFIVE)); H4 = integer.band(H4, LM26)
	C = integer.arshift(H0, 26i); H1 = integer.add(H1, C); H0 = integer.band(H0, LM26)

	if H4 == LM26 and H3 == LM26 and H2 == LM26 and H1 == LM26 and integer.ge(H0, LP0) then
		H0 = integer.sub(H0, LP0)
		H1, H2, H3, H4 = 0i, 0i, 0i, 0i
	end

	local HLow = integer.bor(integer.bor(H0, integer.lshift(H1, 26i)),
		integer.lshift(integer.band(H2, 0xFFFi), 52i))
	local HHigh = integer.bor(integer.bor(integer.rshift(H2, 12i), integer.lshift(H3, 14i)),
		integer.lshift(H4, 40i))

	local SLow = buffer.readinteger(Key, 16)
	local SHigh = buffer.readinteger(Key, 24)

	local SumLow = integer.add(HLow, SLow)
	local Carry = if integer.ult(SumLow, HLow) then 1i else 0i
	local SumHigh = integer.add(integer.add(HHigh, SHigh), Carry)

	local Output = buffer.create(TAG_SIZE)
	buffer.writeinteger(Output, 0, SumLow)
	buffer.writeinteger(Output, 8, SumHigh)

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
