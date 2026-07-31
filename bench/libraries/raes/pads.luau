--!strict
--!optimize 2
--!native
local assert = assert
local error = error

local buffer_copy = 	buffer.copy
local buffer_create = 	buffer.create
local buffer_fill = 	buffer.fill
local buffer_len = 		buffer.len
local buffer_readu8 = 	buffer.readu8
local buffer_writeu8 = 	buffer.writeu8

local math_random = math.random

local table_freeze = table.freeze

local pads = {}
--[[**
	NONE
	No padding is applied.
**]]--
local function nonPad(text)
	return text
end
pads.None = table_freeze({
	Pad = nonPad, Unpad = nonPad,
	Overwrite = false
})
--[[**
	ANSI X9.23
	Last block is padded with bytes and the number of bytes added*
	
	* Unlike the standard implementation, this has no bytes limit and will add zeroes.
**]]--
local function anxPad(text, out, segm)
	local len = buffer_len(text)
	local offs = len - len % segm
	if out then
		assert(buffer_len(out) >= len + segm, "Output buffer out of bounds")
		local offb = segm - len % segm
		buffer_copy(out, 0, text, 0, len)
		buffer_fill(out, len, 0, offb - 1)
		buffer_writeu8(out, offs + segm - 1, offb)
	else
		offs += segm
		out = buffer_create(offs)
		buffer_copy(out, 0, text, 0, len)
		buffer_writeu8(out, offs - 1, segm - len % segm)
	end
	return out
end
local function anxUnpad(text, out, segm)
	local len = buffer_len(text)
	local offs = buffer_readu8(text, len - 1)
	local offb = len - offs
	assert(0 < offs and offs <= segm, "Got unexpected padding")
	for offs = offb, len - 2 do
		if buffer_readu8(text, offs) ~= 0 then
			error("Got unexpected padding")
		end
	end
	if out then
		assert(buffer_len(out) >= offb, "Output buffer out of bounds")
	else
		out = buffer_create(offb)
	end
	buffer_copy(out, 0, text, 0, offb)
	return out
end
--[[**
	IS0 10126
	Last block is padded with random bytes and the number of bytes added.
**]]--
local function i10Pad(text, out, segm)
	local len = buffer_len(text)
	local offs = len - len % segm
	if out then
		assert(buffer_len(out) >= len + segm, "Output buffer out of bounds")
	else
		out = buffer_create(offs + segm)
	end
	buffer_copy(out, 0, text, 0, len)
	for offs = len, offs + segm - 2 do
		buffer_writeu8(out, offs, math_random(0, 255))
	end
	buffer_writeu8(out, offs + segm - 1, segm - len % segm)
	return out
end
local function i10Unpad(text, out, segm)
	local len = buffer_len(text)
	local offs = buffer_readu8(text, len - 1)
	local offb = len - offs
	assert(0 < offs and offs <= segm, "Got unexpected padding")
	if out then
		assert(buffer_len(out) >= offb, "Output buffer out of bounds")
	else
		out = buffer_create(offb)
	end
	buffer_copy(out, 0, text, 0, offb)
	return out
end
--[[**
	PKCS #7
	Last block is added with bytes of the number of bytes added.
**]]--
local function pksPad(text, out, segm)
	local len = buffer_len(text)
	local offs = len - len % segm
	if out then
		assert(buffer_len(out) >= len + segm, "Output buffer out of bounds")
	else
		out = buffer_create(offs + segm)
	end
	local offb = segm - len % segm
	buffer_copy(out, 0, text, 0, len)
	buffer_fill(out, len, offb, offb)
	return out
end
local function pksUnpad(text, out, segm)
	local len = buffer_len(text)
	local offs = buffer_readu8(text, len - 1)
	local offb = len - offs
	assert(0 < offs and offs <= segm, "Got unexpected padding")
	for offb = offb, len - 2 do
		if buffer_readu8(text, offb) ~= offs then
			error("Got unexpected padding")
		end
	end
	if out then
		assert(buffer_len(out) >= offb, "Output buffer out of bounds")
	else
		out = buffer_create(offb)
	end
	buffer_copy(out, 0, text, 0, offb)
	return out
end
--[[**
	ISO/IEC 7816-4
	Last block is byte is padded with 80 byte and zeroes.
**]]--
local function ii7Pad(text, out, segm)
	local len = buffer_len(text)
	if out then
		assert(buffer_len(out) >= len + segm, "Output buffer out of bounds") 
		buffer_fill(out, len + 1, 0, segm - len % segm - 1)
	else
		out = buffer_create(len + segm - len % segm)
	end
	buffer_copy(out, 0, text, 0, len)
	buffer_writeu8(out, len, 128)
	return out
end
local function ii7Unpad(text, out, segm)
	local len = buffer_len(text) - 1
	local byte
	for offs = len, len - segm, - 1 do
		byte = buffer_readu8(text, offs)
		if byte == 128 then
			if out then
				assert(buffer_len(out) >= offs, "Output buffer out of bounds")
			else
				out = buffer_create(offs)
			end
			buffer_copy(out, 0, text, 0, offs)
			return out
		else
			assert(byte == 0, "Got unexpected padding")
		end
	end
	error("Got unexpected padding")
	return buffer_create(0)
end
--[[**
	ZERO
	Last block is padded with zeroes.
**]]--
local function zroPad(text, out, segm)
	local len = buffer_len(text)
	if out then
		assert(buffer_len(out) >= len + segm, "Output buffer out of bounds")
		buffer_fill(out, len, 0, segm - len % segm)
	else
		out = buffer_create(len + segm - len % segm)
	end
	buffer_copy(out, 0, text, 0, len)
	return out
end
local function zroUnpad(text, out, segm)
	local len = buffer_len(text) - 1
	local byte
	for offs = len, len - segm, - 1 do
		byte = buffer_readu8(text, offs)
		if byte == 0 then
			offs += 1
			if out then
				assert(buffer_len(out) >= offs, "Output buffer out of bounds")
			else
				out = buffer_create(offs)
			end
			buffer_copy(out, 0, text, 0, offs)
			return out
		end
	end
	buffer_copy(out, 0, text, 0, len - segm - 1)
	return out
end

local meta = {
	__index = function(_, idx: "AnsiX923" | "Iso10126" | "Pkcs7" | "Iso7816_4" | "Zero"): {}?
		return if idx == "AnsiX923" then {
			Pad = anxPad, Unpad = anxPad,
			Overwrite = nil
		} elseif idx == "Iso10126" then {
				Pad = i10Pad, Unpad = i10Unpad,
				Overwrite = nil
			} elseif idx == "Pkcs7" then {
				Pad = pksPad, Unpad = pksUnpad,
				Overwrite = nil
			} elseif idx == "Iso7816_4" then {
				Pad = ii7Pad, Unpad = ii7Unpad,
				Overwrite = nil
			} elseif idx == "Zero" then {
				Pad = zroPad, Unpad = zroUnpad,
				Overwrite = nil
			} else nil
	end,
	__newindex = function() end
}
setmetatable(pads, meta)
pads.AnsiX923 = 	{} :: {Pad: (buffer, buffer?, number) -> buffer, Unpad: (buffer, buffer?, number) -> buffer, Overwrite: nil | boolean}
pads.Iso10126 = 	{} :: {Pad: (buffer, buffer?, number) -> buffer, Unpad: (buffer, buffer?, number) -> buffer, Overwrite: nil | boolean}
pads.Pkcs7 = 		{} :: {Pad: (buffer, buffer?, number) -> buffer, Unpad: (buffer, buffer?, number) -> buffer, Overwrite: nil | boolean}
pads.Iso7816_4 = 	{} :: {Pad: (buffer, buffer?, number) -> buffer, Unpad: (buffer, buffer?, number) -> buffer, Overwrite: nil | boolean}
pads.Zero = 		{} :: {Pad: (buffer, buffer?, number) -> buffer, Unpad: (buffer, buffer?, number) -> buffer, Overwrite: nil | boolean}
table_freeze(pads)
meta.__metatable = "This metatable is locked"
return pads
;--{ecd34924-4a3c-464d-ab36-70c15a22bb24}