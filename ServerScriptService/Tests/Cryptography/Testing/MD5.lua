-- @ScriptType: ModuleScript
--!strict
local Testing = require("./")
type TestVector = {
	Description: string,
	Expected: string
}

type TestVectors = {[string]: TestVector}
local Algorithm = require("../Hashing/MD5")

local TestVectors: TestVectors = {
	[""] = { Description = "Empty String", Expected = "d41d8cd98f00b204e9800998ecf8427e" },
	["The quick brown fox jumps over the lazy dog."] = { Description = "Pangramm Example", Expected = "e4d909c290d0fb1ca068ffaddf22cbd0" },
	["Привет, мир!"] = { Description = "UTF-8 Example", Expected = "c446a2994f35689482651b7c7ba8b56c" },
	["\0"] = { Description = "Null Terminator", Expected = "93b885adfe0da089cdf634904fd59f71" },
	[string.rep("a", 55)] = { Description = "Block of Characters", Expected = "ef1772b6dff9a122358552954ad0df65" },
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = { Description = "448 Bit", Expected = "8215ef0796a20bcaaae116d3876c664a" },
	[string.rep("a", 111)] = { Description = "111 Characters", Expected = "089f243d1e831c5879aa375ee364a06e" },
	["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] = { Description = "896 Bits", Expected = "03dd8807a93175fb062dfb55dc7d359c" },
	[string.rep("a", 119)] = { Description = "119 Characters", Expected = "8a7bd0732ed6a28ce75f6dabc90e1613" },
	[string.rep("a", 239)] = { Description = "239 Characters", Expected = "b7b40d64ffccebd78abcf522376b3aae" },
	[string.rep("a", 1024)] = { Description = "Long String", Expected = "c9a34cfc85d982698c6ac89f76071abd" },
	[string.rep("a", 199999)] = { Description = "Really Long String", Expected = "5b21a86f4bb0f3f703167705e5e673df" },
	[string.rep("a", 1e6)] = { Description = "Million", Expected = "7707d6ae4e027c70eea2a935c2296f21" },
}

Testing.Describe("MD5 Algorithm Tests", function()
	for TestString, Info in TestVectors do
		Testing.Test(Info.Description, function()
			local Result = Algorithm(buffer.fromstring(TestString))
			Testing.Expect(Result).ToBe(Info.Expected)
		end)
	end
end)

Testing.Complete()

return 0