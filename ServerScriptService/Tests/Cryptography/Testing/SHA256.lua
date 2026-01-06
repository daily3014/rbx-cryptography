-- @ScriptType: ModuleScript
--!strict
local Testing = require("./")
type TestVector = {
	Description: string,
	Expected: string
}

type TestVectors = {[string]: TestVector}
local Algorithm = require("../Hashing/SHA2/SHA256")

local TestVectors: TestVectors = {
	[""] = { Description = "Empty String", Expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
	["The quick brown fox jumps over the lazy dog."] = { Description = "Pangramm Example", Expected = "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c" },
	["Привет, мир!"] = { Description = "UTF-8 Example", Expected = "9a0af011605a6ab9022f248fb797064a42782210ac91e834348b3ef089313e5f" },
	["\0"] = { Description = "Null Terminator", Expected = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" },
	[string.rep("a", 55)] = { Description = "Block of Characters", Expected = "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318" },
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = { Description = "448 Bit", Expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
	[string.rep("a", 111)] = { Description = "111 Characters", Expected = "6374f73208854473827f6f6a3f43b1f53eaa3b82c21c1a6d69a2110b2a79baad" },
	["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] = { Description = "896 Bits", Expected = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" },
	[string.rep("a", 119)] = { Description = "119 Characters", Expected = "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb" },
	[string.rep("a", 239)] = { Description = "239 Characters", Expected = "064b3d122abe25c36265f79fc794b0adf28a6c5e4fe8ed3661f2287e8cecadcc" },
	[string.rep("a", 1024)] = { Description = "Long String", Expected = "2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a" },
	[string.rep("a", 199999)] = { Description = "Really Long String", Expected = "6a2540f78c491a847183ac081f68c7f971806fbd346408aaefbf5d4edec3e901" },
	[string.rep("a", 1e6)] = { Description = "Million", Expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" },
}

Testing.Describe("SHA256 Algorithm Tests", function()
	for TestString, Info in TestVectors do
		Testing.Test(Info.Description, function()
			local Result = Algorithm(buffer.fromstring(TestString))
			Testing.Expect(Result).ToBe(Info.Expected)
		end)
	end
end)

Testing.Complete()

return 0