--!strict
local Testing = require("./")
type TestVector = {
	Description: string,
	Expected: string,
	Message: string,
	Key: string,
	Algorithm: (...any) -> (string, buffer)
}

type TestVectors = {[number]: TestVector}
local HMAC = require("../Hashing/HMAC")
local MD5 =  require("../Hashing/MD5")
local SHA256 = require("../Hashing/SHA2/SHA256")
local SHA512 = require("../Hashing/SHA2/SHA512")

local TestVectors: TestVectors = {
	[1] = {
		Description = "HMAC-MD5 Test Case 1",
		Message = "Hi There",
		Key = string.rep("\x0b", 16),
		Expected = "9294727a3638bb1c13f48ef8158bfc9d",
		Algorithm = MD5
	},
	[2] = {
		Description = "HMAC-MD5 Test Case 2", 
		Message = "what do ya want for nothing?",
		Key = "Jefe",
		Expected = "750c783e6ab0b503eaa86e310a5db738",
		Algorithm = MD5
	},
	[3] = {
		Description = "HMAC-MD5 Test Case 3",
		Message = string.rep("\xdd", 50),
		Key = string.rep("\xaa", 16), 
		Expected = "56be34521d144c88dbb8c733f0e8b3f6",
		Algorithm = MD5
	},
	[4] = {
		Description = "HMAC-MD5 Test Case 4",
		Message = string.rep("\xcd", 50),
		Key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", 
		Expected = "697eaf0aca3a3aea3a75164746ffaa79",
		Algorithm = MD5
	},
	[5] = {
		Description = "HMAC-MD5 Test Case 5",
		Message = "Test With Truncation",
		Key = string.rep("\x0c", 16),
		Expected = "56461ef2342edc00f9bab995690efd4c",
		Algorithm = MD5
	},
	[6] = {
		Description = "HMAC-MD5 Test Case 6",
		Message = "Test Using Larger Than Block-Size Key - Hash Key First",
		Key = string.rep("\xaa", 80),
		Expected = "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd", 
		Algorithm = MD5
	},
	[7] = {
		Description = "HMAC-MD5 Test Case 7",
		Message = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
		Key = string.rep("\xaa", 80),
		Expected = "6f630fad67cda0ee1fb1f562db3aa53e",
		Algorithm = MD5
	},

	[8] = {
		Description = "HMAC-SHA-256 Test Case 1",
		Message = "Hi There",
		Key = string.rep("\x0b", 20),
		Expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		Algorithm = SHA256
	},
	[9] = {
		Description = "HMAC-SHA-256 Test Case 2",
		Message = "what do ya want for nothing?",
		Key = "Jefe",
		Expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		Algorithm = SHA256
	},
	[10] = {
		Description = "HMAC-SHA-256 Test Case 3",
		Message = string.rep("\xdd", 50),
		Key = string.rep("\xaa", 20),
		Expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
		Algorithm = SHA256
	},
	[11] = {
		Description = "HMAC-SHA-256 Test Case 4",
		Message = string.rep("\xcd", 50),
		Key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
		Expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
		Algorithm = SHA256
	},
	[12] = {
		Description = "HMAC-SHA-256 Test Case 5 (Truncated)",
		Message = "Test With Truncation",
		Key = string.rep("\x0c", 20),
		Expected = "a3b6167473100ee06e0c796c2955552b", 
		Algorithm = SHA256
	},
	[13] = {
		Description = "HMAC-SHA-256 Test Case 6",
		Message = "Test Using Larger Than Block-Size Key - Hash Key First",
		Key = string.rep("\xaa", 131),
		Expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
		Algorithm = SHA256
	},
	[14] = {
		Description = "HMAC-SHA-256 Test Case 7",
		Message = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
		Key = string.rep("\xaa", 131),
		Expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
		Algorithm = SHA256
	},

	[15] = {
		Description = "HMAC-SHA-512 Test Case 1",
		Message = "Hi There",
		Key = string.rep("\x0b", 20),
		Expected = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
		Algorithm = SHA512
	},
	[16] = {
		Description = "HMAC-SHA-512 Test Case 2",
		Message = "what do ya want for nothing?",
		Key = "Jefe",
		Expected = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
		Algorithm = SHA512
	},
	[17] = {
		Description = "HMAC-SHA-512 Test Case 3",
		Message = string.rep("\xdd", 50),
		Key = string.rep("\xaa", 20),
		Expected = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
		Algorithm = SHA512
	},
	[18] = {
		Description = "HMAC-SHA-512 Test Case 4",
		Message = string.rep("\xcd", 50),
		Key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
		Expected = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
		Algorithm = SHA512
	},
	[19] = {
		Description = "HMAC-SHA-512 Test Case 5 (Truncated)",
		Message = "Test With Truncation",
		Key = string.rep("\x0c", 20),
		Expected = "415fad6271580a531d4179bc891d87a6",
		Algorithm = SHA512
	},
	[20] = {
		Description = "HMAC-SHA-512 Test Case 6",
		Message = "Test Using Larger Than Block-Size Key - Hash Key First",
		Key = string.rep("\xaa", 131),
		Expected = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
		Algorithm = SHA512
	},
	[21] = {
		Description = "HMAC-SHA-512 Test Case 7",
		Message = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
		Key = string.rep("\xaa", 131),
		Expected = "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
		Algorithm = SHA512
	}
}


local BLOCK_SIZES = {
	[MD5] = 64,
	[SHA256] = 64,
	[SHA512] = 128
}

Testing.Describe("HMAC Algorithm Tests", function()
	for Index, TestCase in TestVectors do
		Testing.Test(TestCase.Description, function()
			local MessageBuffer = buffer.fromstring(TestCase.Message)
			local KeyBuffer = buffer.fromstring(TestCase.Key)
			local BlockSize = BLOCK_SIZES[TestCase.Algorithm] or 64
			local HashFunction = TestCase.Algorithm
			local Result = HMAC(MessageBuffer, KeyBuffer, HashFunction, BlockSize)

			local ExpectedResult = TestCase.Expected
			if Index == 12 or Index == 19 then
				Result = string.sub(Result, 1, 32)
			end

			Testing.Expect(Result).ToBe(ExpectedResult)
		end)
	end
end)

Testing.Complete()

return 0