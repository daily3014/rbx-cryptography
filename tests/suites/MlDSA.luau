--[=[
	ML-DSA Tadashi Test Suite

	Test Vector Sources:
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/mldsa_44_test.json
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/mldsa_65_test.json
		https://raw.githubusercontent.com/XoifaiI/Tadashi/main/testvectors/mldsa_87_test.json

	Each file has three test groups: MlDsaKeyGen, MlDsaSign, MlDsaVerify. All
	Sign tests use rnd = 0^32 for FIPS-204 deterministic mode (matches both
	rbx-crypto and @noble/post-quantum's extraEntropy=zeros).
--]=]

--!strict
--!optimize 2
--!native

local Bridge = require("../Bridge")
local Testing = require("../")

local MlDsa = require("../../src/Verification/MlDSA")
local SHA3 = require("../../src/Hashing/SHA3")
local FromHex = Testing.FromHex
local ToHex = Testing.ToHex

type MlDsaTest = {
	tcId: number,
	comment: string?,
	targets: {string}?,
	flags: {string}?,
	seed: string?,
	pkSha3_256: string?,
	skSha3_256: string?,
	rnd: string?,
	ctx: string?,
	msg: string?,
	pk: string?,
	sig: string?,
	result: string?,
}

type MlDsaGroup = {
	type: string,
	tests: {MlDsaTest},
}

type MlDsaData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {MlDsaGroup},
}

local MLDSA_VARIANTS = {
	{
		Name = "ML-DSA-44",
		Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/mldsa_44_test.json",
		Params = MlDsa.ML_DSA_44,
	},
	{
		Name = "ML-DSA-65",
		Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/mldsa_65_test.json",
		Params = MlDsa.ML_DSA_65,
	},
	{
		Name = "ML-DSA-87",
		Url = "https://raw.githubusercontent.com/XoifaiI/Tadashi/refs/heads/main/testvectors/mldsa_87_test.json",
		Params = MlDsa.ML_DSA_87,
	},
}

local function FetchTestVectors(Url: string): MlDsaData
	local Response = Bridge.Get(Url)
	return Bridge.JSONDecode(Response) :: MlDsaData
end

local function Sha3_256Hex(Data: buffer): string
	return (SHA3.SHA3_256(Data))
end

local function RunMlDsaTests(Data: MlDsaData, Params: any)
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
					if Group.type == "MlDsaKeyGen" then
						local Seed = FromHex(Test.seed :: string)
						local Pk = buffer.create(Params.PubKeyByteLen)
						local Sk = buffer.create(Params.SecKeyByteLen)
						Params.KeyGen(Seed, Pk, Sk)
						Testing.Expect(Sha3_256Hex(Pk)).ToBe(Test.pkSha3_256 :: string)
						Testing.Expect(Sha3_256Hex(Sk)).ToBe(Test.skSha3_256 :: string)
					elseif Group.type == "MlDsaSign" then
						local Seed = FromHex(Test.seed :: string)
						local Rnd = FromHex(Test.rnd :: string)
						local Ctx = FromHex(Test.ctx :: string)
						local Msg = FromHex(Test.msg :: string)
						local Pk = buffer.create(Params.PubKeyByteLen)
						local Sk = buffer.create(Params.SecKeyByteLen)
						Params.KeyGen(Seed, Pk, Sk)

						local Sig = buffer.create(Params.SigByteLen)
						local SignOk, Ok = pcall(Params.Sign, Msg, Rnd, Sk, Ctx, Sig)
						if Test.result == "invalid" then
							Testing.Expect(SignOk == false or Ok == false).ToBe(true)
						else
							Testing.Expect(SignOk and Ok == true).ToBe(true)
							Testing.Expect(ToHex(Sig)).ToBe(Test.sig :: string)
						end
					elseif Group.type == "MlDsaVerify" then
						local Pk = FromHex(Test.pk :: string)
						local Ctx = FromHex(Test.ctx :: string)
						local Msg = FromHex(Test.msg :: string)
						local Sig = FromHex(Test.sig :: string)
						local Verified = Params.Verify(Msg, Pk, Ctx, Sig)
						Testing.Expect(Verified).ToBe(Test.result == "valid")
					end
				end)
			end
		end)
	end
end

for _, Variant in ipairs(MLDSA_VARIANTS) do
	Testing.Describe(`{Variant.Name} Tadashi Tests`, function()
		RunMlDsaTests(FetchTestVectors(Variant.Url), Variant.Params)
	end)
end

Testing.Complete()

return 0
