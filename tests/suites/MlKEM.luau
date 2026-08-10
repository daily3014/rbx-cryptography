--[=[
	ML-KEM Tadashi Test Suite

	Test Vector Sources:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/mlkem_512_test.json
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/mlkem_768_test.json
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/mlkem_1024_test.json

	Each file has three test groups: MlKemKeyGen, MlKemEncapsulate, MlKemDecapsulate.
	Tests store seeds (D, Z) so runners regenerate the keys; KeyGen tests publish
	SHA3-256 hashes of the encapsulation/decapsulation keys.
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("../Bridge")
local Testing = require("../")

local MlKem = require("../../src/Verification/MlKEM")
local SHA3 = require("../../src/Hashing/SHA3")
local FromHex = Testing.FromHex
local ToHex = Testing.ToHex

type MlKemTest = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	d: string?,
	z: string?,
	ekSha3_256: string?,
	dkSha3_256: string?,
	msg: string?,
	ekOverride: string?,
	dkOverride: string?,
	ct: string?,
	shared: string?,
	result: string?,
}

type MlKemGroup = {
	type: string,
	tests: {MlKemTest},
}

type MlKemData = {
	algorithm: string,
	numberOfTests: number,
	params: {
		k: number,
		eta1: number,
		eta2: number,
		du: number,
		dv: number,
	},
	testGroups: {MlKemGroup},
}

local MLKEM_VARIANTS = {
	{
		Name = "ML-KEM-512",
		Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/mlkem_512_test.json",
	},
	{
		Name = "ML-KEM-768",
		Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/mlkem_768_test.json",
	},
	{
		Name = "ML-KEM-1024",
		Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/mlkem_1024_test.json",
	},
}

local function FetchTestVectors(Url: string): MlKemData
	local Response = Bridge.Get(Url)
	return Bridge.JSONDecode(Response) :: MlKemData
end

local function Sha3_256Hex(Data: buffer): string
	return (SHA3.SHA3_256(Data))
end

local function RunMlKemTests(Data: MlKemData)
	local K = Data.params.k
	local Eta1 = Data.params.eta1
	local Eta2 = Data.params.eta2
	local Du = Data.params.du
	local Dv = Data.params.dv

	for GroupIndex, Group in ipairs(Data.testGroups) do
		Testing.Describe(`Group_{GroupIndex}: {Data.algorithm} ({Group.type})`, function()
			for _, Test in ipairs(Group.tests) do
				local TestId = Test.tcId
				local Comment = Test.comment or ""

				local TestName = `Test_{TestId}`
				if Comment ~= "" then
					TestName = `Test_{TestId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					if Group.type == "MlKemKeyGen" then
						local D = FromHex(Test.d :: string)
						local Z = FromHex(Test.z :: string)
						local Ek, Dk = MlKem.KeyGen(K, Eta1, D, Z)
						Testing.Expect(Sha3_256Hex(Ek)).ToBe(Test.ekSha3_256 :: string)
						Testing.Expect(Sha3_256Hex(Dk)).ToBe(Test.dkSha3_256 :: string)
					elseif Group.type == "MlKemEncapsulate" then
						local Ek: buffer
						if Test.ekOverride and #Test.ekOverride > 0 then
							Ek = FromHex(Test.ekOverride)
						else
							Ek = (MlKem.KeyGen(K, Eta1, FromHex(Test.d :: string), FromHex(Test.z :: string)))
						end

						local Msg = FromHex(Test.msg :: string)

						if Test.result == "invalid" then
							local Ok = pcall(function()
								return MlKem.Encapsulate(Msg, K, Eta1, Eta2, Du, Dv, Ek)
							end)
							Testing.Expect(Ok).ToBe(false)
						else
							local Ct, Shared = MlKem.Encapsulate(Msg, K, Eta1, Eta2, Du, Dv, Ek)
							Testing.Expect(Ct).ToBeDefined()
							Testing.Expect(Shared).ToBeDefined()
							if Ct and Shared then
								Testing.Expect(ToHex(Ct)).ToBe(Test.ct :: string)
								Testing.Expect(ToHex(Shared)).ToBe(Test.shared :: string)
							end
						end
					elseif Group.type == "MlKemDecapsulate" then
						local Dk: buffer
						if Test.dkOverride and #Test.dkOverride > 0 then
							Dk = FromHex(Test.dkOverride)
						else
							local _, DkFresh = MlKem.KeyGen(K, Eta1, FromHex(Test.d :: string), FromHex(Test.z :: string))
							Dk = DkFresh
						end

						local Ct = FromHex(Test.ct :: string)
						local Shared = MlKem.Decapsulate(Ct, K, Eta1, Eta2, Du, Dv, Dk)
						Testing.Expect(ToHex(Shared)).ToBe(Test.shared :: string)
					end
				end)
			end
		end)
	end
end

for _, Variant in ipairs(MLKEM_VARIANTS) do
	Testing.Describe(`{Variant.Name} Tadashi Tests`, function()
		RunMlKemTests(FetchTestVectors(Variant.Url))
	end)
end

Testing.Complete()

return 0
