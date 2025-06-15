--!strict
local Testing = require("./")
type TestVector = {
	Description: string,
	Expected: string
}
type TestVectors = {[string]: TestVector}
local Algorithm = require("../Hashing/Blake3")

local TestVectors: TestVectors = {
	[""] = { Description = "Empty String", Expected = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" },
	["The quick brown fox jumps over the lazy dog."] = { Description = "Pangramm Example", Expected = "4c9bd68d7f0baa2e167cef98295eb1ec99a3ec8f0656b33dbae943b387f31d5d" },
	[string.rep("a", 55)] = { Description = "Block of Characters", Expected = "8e0494b8aa1fa7fc245b4de5ecfb343f35550e6cc3c051e1e872c4a0a4105f83" },
	["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = { Description = "448 Bit", Expected = "c19012cc2aaf0dc3d8e5c45a1b79114d2df42abb2a410bf54be09e891af06ff8" },
	[string.rep("a", 111)] = { Description = "111 Characters", Expected = "e7f1ec23cc83137440c010ce04476a7a543e942b2617a1c3aa2f5199edf076ac" },
	["abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"] = { Description = "896 Bits", Expected = "553e1aa2a477cb3166e6ab38c12d59f6c5017f0885aaf079f217da00cfca363f" },
	[string.rep("a", 119)] = { Description = "119 Characters", Expected = "bd2e1189ff4e612ba158590660947d72eb56cf8fc6eed02bb8c429be01ebda77" },
	[string.rep("a", 239)] = { Description = "239 Characters", Expected = "38b9fb732d29456fe598bf54b93ab4bd019b2c5b3fd000227e8956f97cedbf5a" },
	[string.rep("a", 1024)] = { Description = "Long String", Expected = "5a1c9e5d85d9898297037e8e24f69bb0e604a84c91c3b3ef4784a374812900d9" },
	[string.rep("a", 199999)] = { Description = "Really Long String", Expected = "9a8b2510c263d8268e2936ee075307236aacaae95eeff79ea27672469f28dbd7" },
	[string.rep("e", 1e6)] = {Description = "Million e's", Expected = "28c14138dc9ee6fdb54012bea049dc679b2ecd2dac64981220e93453575194b6"}
}

Testing.Describe("Blake3 Algorithm Tests", function()
	for TestString, Info in TestVectors do
		Testing.Test(Info.Description, function()
			local Result = Algorithm.Digest(buffer.fromstring(TestString))
			Testing.Expect(Result).ToBe(Info.Expected)
		end)
	end
end)

Testing.Complete()

return 0