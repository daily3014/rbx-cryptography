--!strict
local Testing = require("./")
type TestVector = {
	Description: string,
	Expected: string
}

type TestVectors = {[string]: TestVector}
local Algorithm = require("../Hashing/SHA1")

local TestVectors: TestVectors = {
	[""] = { Description = "Empty String", Expected = "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
	["The quick brown fox jumps over the lazy dog."] = { Description = "Pangramm Example", Expected = "408d94384216f890ff7a0c3528e8bed1e0b01621" },
	["Привет, мир!"] = { Description = "UTF-8 Example", Expected = "0cb95b7891ff182f0972be8754ec934df65af21c" },
	["\0"] = { Description = "Null Terminator", Expected = "5ba93c9db0cff93f52b521d7420e43f6eda2784f" },
	[string.rep("a", 55)] = { Description = "Block of Characters", Expected = "c1c8bbdc22796e28c0e15163d20899b65621d65a" },
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = { Description = "448 Bit", Expected = "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
	[string.rep("a", 111)] = { Description = "111 Characters", Expected = "ac877859d427d9192054eea8feb3b8a403ef83a5" },
	["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] = { Description = "896 Bits", Expected = "a49b2446a02c645bf419f995b67091253a04a259" },
	[string.rep("a", 119)] = { Description = "119 Characters", Expected = "ee971065aaa017e0632a8ca6c77bb3bf8b1dfc56" },
	[string.rep("a", 239)] = { Description = "239 Characters", Expected = "fdc30857cf7b957f47ebd8288d5e5d7426f44394" },
	[string.rep("a", 1024)] = { Description = "Long String", Expected = "8eca554631df9ead14510e1a70ae48c70f9b9384" },
	[string.rep("a", 199999)] = { Description = "Really Long String", Expected = "b673b36f4398c26070c29ade5193903b4e6455d9" },
	[string.rep("a", 1e6)] = { Description = "Million", Expected = "34aa973cd4c4daa4f61eeb2bdbad27316534016f" },
}

Testing.Describe("SHA1 Algorithm Tests", function()
	for TestString, Info in TestVectors do
		Testing.Test(Info.Description, function()
			local Result = Algorithm(buffer.fromstring(TestString))
			Testing.Expect(Result).ToBe(Info.Expected)
		end)
	end
end)

Testing.Complete()

return 0