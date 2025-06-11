--[=[
    Cryptography library: Adler
    
    Note: Although Adler has practically no use, it was
    still fun to implement.

    Return type: number
    Example Usage:
        local Message = buffer.fromstring("Hello World")
        local Hash = Adler(Message)
--]=]

--!native
--!optimize 2
--!strict

local function Adler(Message: buffer)
	-- https://github.com/madler/zlib/blob/5a82f71ed1dfc0bec044d9702463dbdf84ea3b71/adler32.c#L128
	local MOD_ALDER = 65522

	local Sum = bit32.band(bit32.rshift(MOD_ALDER, 16), 0xffff)
	MOD_ALDER = bit32.band(MOD_ALDER, 0xffff)

	local MessageLength = buffer.len(Message)

	if MessageLength == 1 then
		MOD_ALDER += buffer.readu8(Message, 0);
		if MOD_ALDER >= 65521 then
			MOD_ALDER -= 65521
		end

		Sum += MOD_ALDER;
		if Sum >= 65521 then
			Sum -= 65521
		end

		return bit32.bor(MOD_ALDER, bit32.lshift(Sum, 16))
	end

	if MessageLength == 0 then
		return 0x1
	end

	local BufferPointer = 0

	if MessageLength < 16 then
		while MessageLength > 0 do
			local Value = buffer.readu8(Message, BufferPointer)

			MOD_ALDER += Value
			Sum += MOD_ALDER

			BufferPointer += 1
			MessageLength -= 1
		end

		if MOD_ALDER >= 65521 then
			MOD_ALDER -= 65521
		end
		Sum %= 65521

		return bit32.bor(MOD_ALDER, bit32.lshift(Sum, 16)) 
	end

	local NMAX = 5552
	while MessageLength >= NMAX do
		MessageLength -= NMAX

		local Iters = NMAX / 16
		while Iters > 0 do
			Iters -= 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1
		end
	end

	if MessageLength > 0 then
		while MessageLength >= 16 do
			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1

			MessageLength -= 16
		end

		while MessageLength > 0 do
			MOD_ALDER += buffer.readu8(Message, BufferPointer);
			Sum += MOD_ALDER;
			BufferPointer += 1
			MessageLength -= 1
		end

		MOD_ALDER %= 65521
		Sum %= 65521
	end

	return bit32.bor(MOD_ALDER, bit32.lshift(Sum, 16))
end

return Adler