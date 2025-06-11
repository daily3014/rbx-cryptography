--!strict

type TestVector = {
	Mode: "Encrypt" | "Decrypt",
	Description: string,
	Expected: string,

	Nonce: buffer?,
	Key: buffer?,
	Counter: number?,
}

type TestVectors = { [string]: TestVector }

local function FromHex(Hex: string): buffer
	local Length = #Hex
	local Buffer = buffer.create(Length / 2)
	for Index = 0, Length - 2, 2 do
		buffer.writeu8(Buffer, Index / 2, tonumber(string.sub(Hex, Index + 1, Index + 2), 16) :: number)
	end

	return Buffer
end

local function ToHex(Buffer: buffer): string
	local Hex = ""
	for Index = 0, buffer.len(Buffer) - 1 do
		Hex ..= string.format("%02x", buffer.readu8(Buffer, Index))
	end

	return Hex
end

local AlgorithmName = script.Parent.Name
local Algorithm = require(script.Parent)

local DefaultKey = buffer.fromstring("0123456789ABCDEF0123456789ABCDEF")
local DefaultNonce = buffer.fromstring("Nonce12Bytes")

local TestVectors: TestVectors = {
	["Hello World!"] = {
		Mode = "Encrypt",
		Description = "Hello World [Encrypt]",
		Expected = "3b66fdac2bf5943d594b1bbb",
	},

	["3b66fdac2bf5943d594b1bbb"] = {
		Mode = "Decrypt",
		Description = "Hello World [Decrypt]",
		Expected = "Hello World!",
	},

	["Hello World"] = {
		Mode = "Encrypt",
		Description = "Hello World with custom counter [Encrypt]",
		Expected = "a55e9f612c550145b40da7",

		Counter = 15,
	},

	["a55e9f612c550145b40da7"] = {
		Mode = "Decrypt",
		Description = "Hello World with custom counter [Decrypt]",
		Expected = "Hello World",

		Counter = 15,
	},

	[string.rep("a", 150)] = {
		Mode = "Encrypt",
		Description = "150 Characters [Encrypt]",
		Expected = "1262f0a125b4a2334a461efb95e26869acc877bde19930e3cbdc404b73709904246201482ce7b5cb0cdc0dbbac79eb5fce3f364d515a7e262c909dda884d77e7dc4f87076265b90fd3cc4cc3cbd5d8482096116d134e4d6153379b5e9ab9df06614981b21f5981d5d97864437de0efeaf8a4470a789f85a43b657cad00992bb644955255e9f9ffb0c68bdfc0adae603d9f93890060ac",
	},

	["1262f0a125b4a2334a461efb95e26869acc877bde19930e3cbdc404b73709904246201482ce7b5cb0cdc0dbbac79eb5fce3f364d515a7e262c909dda884d77e7dc4f87076265b90fd3cc4cc3cbd5d8482096116d134e4d6153379b5e9ab9df06614981b21f5981d5d97864437de0efeaf8a4470a789f85a43b657cad00992bb644955255e9f9ffb0c68bdfc0adae603d9f93890060ac"] = {
		Mode = "Decrypt",
		Description = "150 Characters [Decrypt]",
		Expected = string.rep("a", 150),
	},
}

for TestString, Info in TestVectors do
	local Result
	if Info.Mode == "Encrypt" then
		Result = ToHex(
			Algorithm(buffer.fromstring(TestString), Info.Key or DefaultKey, Info.Nonce or DefaultNonce, Info.Counter)
		)
	elseif Info.Mode == "Decrypt" then
		Result = buffer.tostring(
			Algorithm(FromHex(TestString), Info.Key or DefaultKey, Info.Nonce or DefaultNonce, Info.Counter)
		)
	end

	local ErrorMessage = string.format(
		"%s: Test String '%s' (%s) produced incorrect output. Expected '%s', got '%s'",
		AlgorithmName,
		TestString,
		Info.Description,
		Info.Expected,
		Result
	)

	assert(Result == Info.Expected, ErrorMessage)
	warn(`{AlgorithmName}: Test '{Info.Description}' passed`)
end

print(`[{AlgorithmName}] All test cases passed`)

return 0
