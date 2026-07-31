--!strict
--!native
--!optimize 2
local assert = assert

local bit32_bxor = bit32.bxor

local buffer_copy = 		buffer.copy
local buffer_create = 		buffer.create
local buffer_len = 			buffer.len
local buffer_readu8 = 		buffer.readu8
local buffer_readu32 =		buffer.readu32
local buffer_tostring = 	buffer.tostring
local buffer_writestring = 	buffer.writestring
local buffer_writeu8 = 		buffer.writeu8
local buffer_writeu32 = 	buffer.writeu32

local math_floor = math.floor
local math_random = math.random

local table_freeze = table.freeze

local string_pack = string.pack

-- Empty IV
local ZEROES = buffer_create(16)
-- Counter
local function addByteCtr(ctr: buffer, step: number, offs0: number, offs1: number, le: boolean): ()
	local byte
	if le then
		byte = buffer_readu8(ctr, offs0) + step
		buffer_writeu8(ctr, offs0, byte)
			if byte >= 256 then
			for offs = offs0 + 1, offs1 do
				byte = buffer_readu8(ctr, offs) + 1
				buffer_writeu8(ctr, offs, byte)
				if byte < 256 then
					break
				end
			end
		end
	else
		byte = buffer_readu8(ctr, offs1) + step
		buffer_writeu8(ctr, offs1, byte)
			if byte >= 256 then
			for offs = offs1 - 1, offs0, - 1 do
				byte = buffer_readu8(ctr, offs) + 1
				buffer_writeu8(ctr, offs, byte)
				if byte < 256 then
					break
				end
			end
		end
	end
end

local modes = {}
--[[**
	ELECTRONIC CODEBOOK (ECB)
	Each block is encrypted separately.
	/ Parallelizable
**]]--
modes.ECB = table_freeze({
	FwdMode = function(encp, _, text, out)
		local len = buffer_len(text) - 16
		assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
		for offs = 0, len, 16 do
			encp(text, offs, out, offs)
		end
	end,
	InvMode = function(_, decp, ciph, out)
		local len = buffer_len(ciph) - 16
		assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
		for offs = 0, len, 16 do
			decp(ciph, offs, out, offs)
		end
	end
})
--[[**
	CIPHER BLOCK CHAINING (CBC)
	Each block is XORed with previous ciphertext before being encrypted.
	/ Decryption parallelizable
	/ Expected inputs: IV (buffer, optional)
**]]--
modes.CBC = table_freeze({
	FwdMode = function(encp, _, text, out, _, iv)
		local len = buffer_len(text) - 16
		assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
		iv = iv or ZEROES
		assert(buffer_len(iv) == 16, "Initialization vector must be 16 bytes long")
		buffer_writeu32(out, 0, bit32_bxor(buffer_readu32(text, 0), buffer_readu32(iv, 0)))
		buffer_writeu32(out, 4, bit32_bxor(buffer_readu32(text, 4), buffer_readu32(iv, 4)))
		buffer_writeu32(out, 8, bit32_bxor(buffer_readu32(text, 8), buffer_readu32(iv, 8)))
		buffer_writeu32(out, 12, bit32_bxor(buffer_readu32(text, 12), buffer_readu32(iv, 12)))
		encp(out, 0, out, 0)
		for offs = 16, len, 16 do
			buffer_writeu32(out, offs, bit32_bxor(buffer_readu32(text, offs), buffer_readu32(out, offs - 16)))
			buffer_writeu32(out, offs + 4, bit32_bxor(buffer_readu32(text, offs + 4), buffer_readu32(out, offs - 12)))
			buffer_writeu32(out, offs + 8, bit32_bxor(buffer_readu32(text, offs + 8), buffer_readu32(out, offs - 8)))
			buffer_writeu32(out, offs + 12, bit32_bxor(buffer_readu32(text, offs + 12), buffer_readu32(out, offs - 4)))
			encp(out, offs, out, offs)
		end
	end,
	InvMode = function(_, decp, ciph, out, _, iv)
		local len = buffer_len(ciph) - 16
		assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
		iv = iv or ZEROES
		assert(buffer_len(iv) == 16, "Initialization vector must be 16 bytes long")
		local w0 = buffer_readu32(ciph, 0); local w1 = buffer_readu32(ciph, 4)
		local w2 = buffer_readu32(ciph, 8); local w3 = buffer_readu32(ciph, 12)
		local w4, w5, w6, w7
		decp(ciph, 0, out, 0)
		buffer_writeu32(out, 0, bit32_bxor(buffer_readu32(out, 0), buffer_readu32(iv, 0)))
		buffer_writeu32(out, 4, bit32_bxor(buffer_readu32(out, 4), buffer_readu32(iv, 4)))
		buffer_writeu32(out, 8, bit32_bxor(buffer_readu32(out, 8), buffer_readu32(iv, 8)))
		buffer_writeu32(out, 12, bit32_bxor(buffer_readu32(out, 12), buffer_readu32(iv, 12)))
		for offs = 16, len, 16 do
			w4 = buffer_readu32(ciph, offs)
			w5 = buffer_readu32(ciph, offs + 4)
			w6 = buffer_readu32(ciph, offs + 8)
			w7 = buffer_readu32(ciph, offs + 12)
			decp(ciph, offs, out, offs)
			buffer_writeu32(out, offs, bit32_bxor(buffer_readu32(out, offs), w0))
			buffer_writeu32(out, offs + 4, bit32_bxor(buffer_readu32(out, offs + 4), w1))
			buffer_writeu32(out, offs + 8, bit32_bxor(buffer_readu32(out, offs + 8), w2))
			buffer_writeu32(out, offs + 12, bit32_bxor(buffer_readu32(out, offs + 12), w3))
			w0, w1, w2, w3 = w4, w5, w6, w7
		end
	end
})
--[[**
	PROPAGATING CIPHER BLOCK CHAINING (PCBC)
	Each block is XORed with both previous plaintext and ciphertext before being encrypted.
	\ Not parallelizable
	/ Expected inputs: IV (buffer, optional)
**]]--
modes.PCBC = table_freeze({
	FwdMode = function(encp, _, text, out, _, iv)
		local len = buffer_len(text) - 16
		assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
		iv = iv or ZEROES
		assert(buffer_len(iv) == 16, "Initialization vector must be 16 bytes long")
		local w0 = buffer_readu32(text, 0); local w1 = buffer_readu32(text, 4)
		local w2 = buffer_readu32(text, 8); local w3 = buffer_readu32(text, 12)
		local w4, w5, w6, w7
		buffer_writeu32(out, 0, bit32_bxor(w0, buffer_readu32(iv, 0)))
		buffer_writeu32(out, 4, bit32_bxor(w1, buffer_readu32(iv, 4)))
		buffer_writeu32(out, 8, bit32_bxor(w2, buffer_readu32(iv, 8)))
		buffer_writeu32(out, 12, bit32_bxor(w3, buffer_readu32(iv, 12)))
		encp(out, 0, out, 0)
		for offs = 16, len, 16 do
			w4 = buffer_readu32(text, offs)
			w5 = buffer_readu32(text, offs + 4)
			w6 = buffer_readu32(text, offs + 8)
			w7 = buffer_readu32(text, offs + 12)
			buffer_writeu32(out, offs, bit32_bxor(w0, w4, buffer_readu32(out, offs - 16)))
			buffer_writeu32(out, offs + 4, bit32_bxor(w1, w5, buffer_readu32(out, offs - 12)))
			buffer_writeu32(out, offs + 8, bit32_bxor(w2, w6, buffer_readu32(out, offs - 8)))
			buffer_writeu32(out, offs + 12, bit32_bxor(w3, w7, buffer_readu32(out, offs - 4)))
			encp(out, offs, out, offs)
			w0, w1, w2, w3 = w4, w5, w6, w7
		end
	end,
	InvMode = function(_, decp, ciph, out, _, iv)
		local len = buffer_len(ciph) - 16
		assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
		iv = iv or ZEROES
		assert(buffer_len(iv) == 16, "Initialization vector must be 16 bytes long")
		local w0 = buffer_readu32(ciph, 0); local w1 = buffer_readu32(ciph, 4)
		local w2 = buffer_readu32(ciph, 8); local w3 = buffer_readu32(ciph, 12)
		decp(ciph, 0, out, 0)
		local w4 = bit32_bxor(buffer_readu32(out, 0), buffer_readu32(iv, 0))
		local w5 = bit32_bxor(buffer_readu32(out, 4), buffer_readu32(iv, 4))
		local w6 = bit32_bxor(buffer_readu32(out, 8), buffer_readu32(iv, 8))
		local w7 = bit32_bxor(buffer_readu32(out, 12), buffer_readu32(iv, 12))
		local w8, w9, w10, w11
		buffer_writeu32(out, 0, w4)
		buffer_writeu32(out, 4, w5)
		buffer_writeu32(out, 8, w6)
		buffer_writeu32(out, 12, w7)
		local offp0, offp1, offp2, offp3 = 0, 4, 8, 12
		for offs = 16, len, 16 do
			offp0 += 16; offp1 += 16; offp2 += 16; offp3 += 16
			w8 = buffer_readu32(ciph, offp0)
			w9 = buffer_readu32(ciph, offp1)
			w10 = buffer_readu32(ciph, offp2)
			w11 = buffer_readu32(ciph, offp3)
			decp(ciph, offs, out, offs)
			w4 = bit32_bxor(w0, w4, buffer_readu32(out, offp0))
			w5 = bit32_bxor(w1, w5, buffer_readu32(out, offp1))
			w6 = bit32_bxor(w2, w6, buffer_readu32(out, offp2))
			w7 = bit32_bxor(w3, w7, buffer_readu32(out, offp3))
			w0, w1, w2, w3 = w8, w9, w10, w11
			buffer_writeu32(out, offp0, w4)
			buffer_writeu32(out, offp1, w5)
			buffer_writeu32(out, offp2, w6)
			buffer_writeu32(out, offp3, w7)
		end
	end
})
--[[**
	CIPHER FEEDBACK (CFB)
	Turns a block cipher into a self-sinchronizing stream cipher.
	/ Decryption parallelizable
	/ Symmetric block cipher encryption 
	/ Options:
		- CommonTemp: common temporary buffer shared between CBC calculations
		- SegmentSize: Size of plaintext and ciphertext segments. 0 < s <= 16 (default)
	/ Expected inputs: IV (buffer, optional)
**]]--
local function cfbFwd(encp, _, text, out, options: {CommonTemp: buffer, SegmentSize: number}, iv)
	local segm = options.SegmentSize
	local len = buffer_len(text)
	assert(len % segm == 0, "Input length must be a multiple of segment size")
	iv = iv or ZEROES
	assert(buffer_len(iv) == 16, "Initialization vector must be 16 bytes long")
	local temp = options.CommonTemp or buffer_create(31)
	if len == segm then
		encp(iv, 0, temp, 0)
		for offs = 0, segm - 1 do
			buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(text, offs), buffer_readu8(temp, offs)))
		end
	else
		local last = len - segm; local offb = 16 - segm
		local i
		encp(iv, 0, temp, 0)
		for offs = 0, segm - 1 do
			buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(text, offs), buffer_readu8(temp, offs)))
		end
		buffer_copy(temp, 0, iv, segm, offb)
		buffer_copy(temp, offb, out, 0, segm)
		for offs = segm, last - segm, segm do
			i = 0
			buffer_copy(temp, 16, temp, segm, offb)
			encp(temp, 0, temp, 0)
			for offs = offs, offs + segm - 1 do
				buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(text, offs), buffer_readu8(temp, i)))
				i += 1
			end
			buffer_copy(temp, 0, temp, 16, offb)
			buffer_copy(temp, offb, out, offs, segm)
		end
		encp(temp, 0, temp, 0)
		i = 0
		for offs = last, len - 1 do
			buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(text, offs), buffer_readu8(temp, i)))
			i += 1
		end
	end
end
local function cfbInv(encp, _, ciph, out, options: {CommonTemp: buffer, SegmentSize: number}, iv)
	local len = buffer_len(ciph)
	local segm = options.SegmentSize
	assert(len % segm == 0, "Input length must be a multiple of segment size")
	iv = iv or ZEROES
	assert(buffer_len(iv) == 16, "Initialization vector must be 16 bytes long")
	local temp = options.CommonTemp or buffer_create(31)
	if len == segm then
		encp(iv, 0, temp, 0)
		for offs = 0, segm - 1 do
			buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(ciph, offs), buffer_readu8(temp, offs)))
		end
	else
		local last = len - segm; local offb = 16 - segm
		local i
		encp(iv, 0, temp, 0)
		for offs = 0, segm - 1 do
			buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(ciph, offs), buffer_readu8(temp, offs)))
		end
		buffer_copy(temp, 0, iv, segm, offb)
		buffer_copy(temp, offb, ciph, 0, segm)
		for offs = segm, last - segm, segm do
			i = 0
			buffer_copy(temp, 16, temp, segm, offb)
			encp(temp, 0, temp, 0)
			for offs = offs, offs + segm - 1 do
				buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(ciph, offs), buffer_readu8(temp, i)))
				i += 1
			end
			buffer_copy(temp, 0, temp, 16, offb)
			buffer_copy(temp, offb, ciph, offs, segm)
		end
		encp(temp, 0, temp, 0)
		i = 0
		for offs = last, len - 1 do
			buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(ciph, offs), buffer_readu8(temp, i)))
			i += 1
		end
	end
end
--[[**
	OUTPUT FEEDBACK (OFB)
	Generates keystream blocks which are XORed with plaintext blocks.
	\ Not parallelizable
	/ Symmetric block cipher encryption
	/ Symmetric mode of operation
	/ Expected inputs: IV (buffer, optional)
**]]--
local function ofbMode(encp, _, text: buffer, out: buffer, _, iv: buffer)
	local len = buffer_len(text) - 16
	assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
	iv = iv or ZEROES
	assert(buffer_len(iv) == 16, "Initialization vector must be 16 bytes long")
	local w0 = buffer_readu32(text, 0); local w1 = buffer_readu32(text, 4)
	local w2 = buffer_readu32(text, 8); local w3 = buffer_readu32(text, 12)
	encp(iv, 0, out, 0)
	w0 = bit32_bxor(w0, buffer_readu32(out, 0))
	w1 = bit32_bxor(w1, buffer_readu32(out, 4))
	w2 = bit32_bxor(w2, buffer_readu32(out, 8))
	w3 = bit32_bxor(w3, buffer_readu32(out, 12))
	local w4, w5, w6, w7
	for offs = 16, len, 16 do
		w4 = buffer_readu32(text, offs)
		w5 = buffer_readu32(text, offs + 4)
		w6 = buffer_readu32(text, offs + 8)
		w7 = buffer_readu32(text, offs + 12)
		encp(out, offs - 16, out, offs)
		buffer_writeu32(out, offs - 16, w0)
		buffer_writeu32(out, offs - 12, w1)
		buffer_writeu32(out, offs - 8, w2)
		buffer_writeu32(out, offs - 4, w3)
		w0 = bit32_bxor(w4, buffer_readu32(out, offs))
		w1 = bit32_bxor(w5, buffer_readu32(out, offs + 4))
		w2 = bit32_bxor(w6, buffer_readu32(out, offs + 8))
		w3 = bit32_bxor(w7, buffer_readu32(out, offs + 12))
	end
	buffer_writeu32(out, len, w0)
	buffer_writeu32(out, len + 4, w1)
	buffer_writeu32(out, len + 8, w2)
	buffer_writeu32(out, len + 12, w3)
end
modes.OFB = table_freeze({
	FwdMode = ofbMode, InvMode = ofbMode
})
--[[**
	COUNTER (CTR)
	Generates keystream blocks by encrypting sucessive values of a counter
	/ Parallelizable
	/ Symmetric block cipher encryption
	/ Symmetric mode of operation
	/ Options:
		- CommonTemp: common temporary buffer shared between CTR calculations
		- InitValue: binary string which serves as counter* (generated randomly by default)
		- Prefix: binary string that goes before the counter* (nothing by default)
		- Suffix: binary string that goes after the counter* (nothing by default)
		- Step: Increasing of counter (must be a byte). Used for a parallelization. (default 1)
		- LittleEndian: Boolean indicating if counter increments on the left-most bytes.
	
	* The three strings joined must be 16 bytes long. 
**]]--
local function ctrMode(encp, _, text, out, options: {CommonTemp: buffer, InitValue: string, Prefix: string, Suffix: string,
	Step: number, LittleEndian: boolean})
	local len = buffer_len(text) - 16
	assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
	local temp = options.CommonTemp
	local init = options.InitValue; local pre = options.Prefix
	local suf = options.Suffix; local step = options.Step; local le = options.LittleEndian
	local offs0 = #pre; local offs1 = offs0 + #init - 1
	buffer_writestring(temp, 0, pre)
	buffer_writestring(temp, offs0, init)
	buffer_writestring(temp, offs1 + 1, suf)
	local w0 = buffer_readu32(text, 0); local w1 = buffer_readu32(text, 4)
	local w2 = buffer_readu32(text, 8); local w3 = buffer_readu32(text, 12)
	encp(temp, 0, out, 0)
	buffer_writeu32(out, 0, bit32_bxor(buffer_readu32(out, 0), w0))
	buffer_writeu32(out, 4, bit32_bxor(buffer_readu32(out, 4), w1))
	buffer_writeu32(out, 8, bit32_bxor(buffer_readu32(out, 8), w2))
	buffer_writeu32(out, 12, bit32_bxor(buffer_readu32(out, 12), w3))
	for offs = 16, len, 16 do
		w0 = buffer_readu32(text, offs)
		w1 = buffer_readu32(text, offs + 4)
		w2 = buffer_readu32(text, offs + 8)
		w3 = buffer_readu32(text, offs + 12)
		addByteCtr(temp, step, offs0, offs1, le)
		encp(temp, 0, out, offs)
		buffer_writeu32(out, offs, bit32_bxor(w0, buffer_readu32(out, offs)))
		buffer_writeu32(out, offs + 4, bit32_bxor(w1, buffer_readu32(out, offs + 4)))
		buffer_writeu32(out, offs + 8, bit32_bxor(w2, buffer_readu32(out, offs + 8)))
		buffer_writeu32(out, offs + 12, bit32_bxor(w3, buffer_readu32(out, offs + 12)))
	end
end

local meta = {
	__index = function(_, idx: "CFB" | "CTR"): {}?
		return if idx == "CFB" then {
			FwdMode = cfbFwd, InvMode = cfbInv,
			SegmentSize = 16,
			CommonTemp = buffer_create(31)
			} elseif idx == "CTR" then {
				FwdMode = ctrMode, InvMode = ctrMode,
				InitValue = string_pack("I2I2I2I2I2I2I2I2", math_random(0, 65535), math_random(0, 65535), math_random(0, 65535),
					math_random(0, 65535), math_random(0, 65535), math_random(0, 65535), math_random(0, 65535), math_random(0, 65535)),
				Prefix = "", Suffix = "", Step = 1, LittleEndian = false,
				CommonTemp = buffer_create(16)
			} else nil
	end,
	__newindex = function()
	end
}
setmetatable(modes, meta)
modes.CFB = {} :: {FwdMode: typeof(cfbFwd), InvMode: typeof(cfbInv), CommonTemp: buffer, SegmentSize: number}
modes.CTR = {} :: {FwdMode: typeof(ctrMode), InvMode: typeof(ctrMode), CommonTemp: buffer, InitValue: string, Prefix: string, Suffix: string,
	Step: number, LittleEndian: boolean}
table_freeze(modes)
meta.__metatable = "This metatable is locked"
return modes
;--{8f3b7d65-b403-446a-850c-36c1a1c24379}