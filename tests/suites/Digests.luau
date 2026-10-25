--!strict
--!optimize 2
--!native

local Testing = require("../")

local SHA2 = require("../../src/Hashing/SHA2")
local SHA3 = require("../../src/Hashing/SHA3")
local Blake2b = require("../../src/Hashing/Blake2b")
local Blake3 = require("../../src/Hashing/Blake3")
local MD5 = require("../../src/Hashing/MD5")
local SHA1 = require("../../src/Hashing/SHA1")
local HMAC = require("../../src/Hashing/HMAC")

local Describe = Testing.Describe
local Test = Testing.Test
local Expect = Testing.Expect
local ToHex = Testing.ToHex
local FromHex = Testing.FromHex

type Digester = (Message: buffer, OutputBytes: number) -> (string, buffer)

local Digesters: { { Name: string, Vectors: any, Size: number, Call: Digester } } = {
	{ Name = "MD5", Vectors = require("../tadashi/md5_test"), Size = 16, Call = function(Message) return MD5(Message) end },
	{ Name = "SHA1", Vectors = require("../tadashi/sha1_test"), Size = 20, Call = function(Message) return SHA1(Message) end },
	{ Name = "SHA224", Vectors = require("../tadashi/sha224_test"), Size = 28, Call = function(Message) return SHA2.SHA224(Message) end },
	{ Name = "SHA256", Vectors = require("../tadashi/sha256_test"), Size = 32, Call = function(Message) return SHA2.SHA256(Message) end },
	{ Name = "SHA384", Vectors = require("../tadashi/sha384_test"), Size = 48, Call = function(Message) return SHA2.SHA384(Message) end },
	{ Name = "SHA512", Vectors = require("../tadashi/sha512_test"), Size = 64, Call = function(Message) return SHA2.SHA512(Message) end },
	{ Name = "SHA3-224", Vectors = require("../tadashi/sha3_224_test"), Size = 28, Call = function(Message) return SHA3.SHA3_224(Message) end },
	{ Name = "SHA3-256", Vectors = require("../tadashi/sha3_256_test"), Size = 32, Call = function(Message) return SHA3.SHA3_256(Message) end },
	{ Name = "SHA3-384", Vectors = require("../tadashi/sha3_384_test"), Size = 48, Call = function(Message) return SHA3.SHA3_384(Message) end },
	{ Name = "SHA3-512", Vectors = require("../tadashi/sha3_512_test"), Size = 64, Call = function(Message) return SHA3.SHA3_512(Message) end },
	{ Name = "SHAKE128", Vectors = require("../tadashi/shake128_test"), Size = 0, Call = function(Message, OutputBytes) return SHA3.SHAKE128(Message, OutputBytes) end },
	{ Name = "SHAKE256", Vectors = require("../tadashi/shake256_test"), Size = 0, Call = function(Message, OutputBytes) return SHA3.SHAKE256(Message, OutputBytes) end },
	{ Name = "Blake2b", Vectors = require("../tadashi/blake2b_test"), Size = 0, Call = function(Message, OutputBytes) return Blake2b.Digest(Message, OutputBytes) end },
	{ Name = "Blake3", Vectors = require("../tadashi/blake3_test"), Size = 0, Call = function(Message, OutputBytes) return Blake3.Digest(Message, OutputBytes) end },
}

local Blocks: { [string]: number } = { MD5 = 64, SHA1 = 64, SHA224 = 64, SHA256 = 64, SHA384 = 128, SHA512 = 128 }

local PATTERN_LIMIT = 1048576

local function Message(Case: any): buffer?
	if type(Case.msg) == "string" then
		return FromHex(Case.msg)
	end

	local Pattern = Case.msgPattern
	if type(Pattern) ~= "table" or Pattern.length > PATTERN_LIMIT then
		return nil

	end

	return Testing.ExpandPattern(Pattern.pattern, Pattern.length)
end

local function Plain(Case: any): boolean
	if Case.result ~= "valid" then
		return false
	end
	if type(Case.key) == "string" and #Case.key > 0 then
		return false
	end
	return not (type(Case.context) == "string" and #Case.context > 0)
end

Describe("Digest buffers", function()
	Describe("The buffer holds the published digest", function()
		for _, Entry in Digesters do
			Test(Entry.Name, function()
				local Ran = 0
				for _, Group in Entry.Vectors.testGroups do
					for _, Case in Group.tests do
						if not Plain(Case) then
							continue
						end

						local Input = Message(Case)
						if Input == nil then
							continue
						end

						local Hex, Digest = Entry.Call(Input, #Case.digest // 2)
						Expect(ToHex(Digest)).ToBe(Case.digest)
						Expect(Hex).ToBe(Case.digest)
						Ran += 1
					end
				end

				Expect(Ran).ToBeGreaterThan(0)
			end)
		end
	end)

	Describe("The buffer is the documented length", function()
		for _, Entry in Digesters do
			if Entry.Size == 0 then
				continue
			end

			Test(Entry.Name, function()
				for _, Message in { "", "abc", string.rep("q", 200) } do
					local Hex, Digest = Entry.Call(buffer.fromstring(Message), Entry.Size)
					Expect(buffer.len(Digest)).ToBe(Entry.Size)
					Expect(#Hex).ToBe(Entry.Size * 2)
				end
			end)
		end
	end)

	Describe("Every digester hands HMAC a buffer", function()
		for _, Entry in Digesters do
			Test(Entry.Name, function()
				local _, Digest = Entry.Call(buffer.fromstring("probe"), if Entry.Size > 0 then Entry.Size else 32)
				Expect(typeof(Digest)).ToBe("buffer")
			end)
		end
	end)

	Describe("HMAC forwards a matching buffer", function()
		for _, Entry in Digesters do
			local BlockSize = Blocks[Entry.Name]
			if BlockSize == nil then
				continue
			end

			Test(Entry.Name, function()
				local Key = buffer.fromstring(string.rep("k", 20))
				local Hex, Digest = HMAC(buffer.fromstring("message"), Key, function(Message: buffer) return Entry.Call(Message, Entry.Size) end :: any, BlockSize)
				Expect(ToHex(Digest)).ToBe(Hex)
				Expect(buffer.len(Digest)).ToBe(Entry.Size)
			end)
		end
	end)

	Describe("HMAC depends on the message", function()
		for _, Entry in Digesters do
			local BlockSize = Blocks[Entry.Name]
			if BlockSize == nil then
				continue
			end

			Test(Entry.Name, function()
				local Key = buffer.fromstring(string.rep("k", 20))
				local First = HMAC(buffer.fromstring("one"), Key, function(Message: buffer) return Entry.Call(Message, Entry.Size) end :: any, BlockSize)
				local Second = HMAC(buffer.fromstring("two"), Key, function(Message: buffer) return Entry.Call(Message, Entry.Size) end :: any, BlockSize)
				local Empty = HMAC(buffer.fromstring(""), Key, function(Message: buffer) return Entry.Call(Message, Entry.Size) end :: any, BlockSize)
				Expect(First).Never.ToBe(Second)
				Expect(First).Never.ToBe(Empty)
			end)
		end
	end)
end)

Testing.Complete()

return 0
