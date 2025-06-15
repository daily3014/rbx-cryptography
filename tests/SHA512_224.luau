--!strict
local Testing = require("./")
type TestVector = {
	Description: string,
	Expected: string
}

type TestVectors = {[string]: TestVector}
local Algorithm = require("../Hashing/SHA2/SHA512_224")

local TestVectors: TestVectors = {
	[""] = { Description = "Empty String", Expected = "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4" },
	["The quick brown fox jumps over the lazy dog."] = { Description = "Pangramm Example", Expected = "6d6a9279495ec4061769752e7ff9c68b6b0b3c5a281b7917ce0572de" },
	["Привет, мир!"] = { Description = "UTF-8 Example", Expected = "2ea5dce818e9db98e1c256580644c9b9b49e2d7fd0c8e499cbfad232" },
	["\0"] = { Description = "Null Terminator", Expected = "283bb59af7081ed08197227d8f65b9591ffe1155be43e9550e57f941" },
	[string.rep("a", 55)] = { Description = "Block of Characters", Expected = "70a40c59a45a82e85038580887f60fb8bb3d3a0562dceac4a909de2e" },
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = { Description = "448 Bit", Expected = "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174" },
	[string.rep("a", 111)] = { Description = "111 Characters", Expected = "3ebe1b48e8c66acb9ae014db95b4bec93de7e9572bff41cf566bd7d0" },
	["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] = { Description = "896 Bits", Expected = "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9" },
	[string.rep("a", 119)] = { Description = "119 Characters", Expected = "3faf8c370047a31f89bd959c5af5a2328928fb13823f15826ce8c225" },
	[string.rep("a", 239)] = { Description = "239 Characters", Expected = "f0d8b2a6b6d937a8232af97907d0e8ab8b7a5d5f0b0b0c9ec2f4d8b0" },
	[string.rep("a", 1024)] = { Description = "Long String", Expected = "804ff477e0a6a6e8728f571147f6aa991354d0305ee611e790cd772c" },
	[string.rep("a", 199999)] = { Description = "Really Long String", Expected = "544e8e61bf9e4fa439cfe6bd0e08923d0da927bb154ebaee2b90ad58" },
	[string.rep("a", 1e6)] = { Description = "Million", Expected = "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287" },
}

Testing.Describe("SHA512_224 Algorithm Tests", function()
	for TestString, Info in TestVectors do
		Testing.Test(Info.Description, function()
			local Result = Algorithm(buffer.fromstring(TestString))
			Testing.Expect(Result).ToBe(Info.Expected)
		end)
	end
end)

Testing.Complete()

return 0