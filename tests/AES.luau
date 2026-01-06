--[=[
	AES-GCM Wycheproof Test Suite
	
	Test Vector Source:
		https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/aes_gcm_test.json
	
	Test Categories:
		Ktv - Known test vectors
		Pseudorandom - Various input sizes
		ModifiedTag - Tampered authentication tags
		SmallIv / LongIv / ZeroLengthIv - Non-standard IV sizes
		CounterWrap - Counter overflow edge cases
	
	IV Size Restriction (96-bit only):
		This implementation only supports 96-bit (12-byte) IVs for security reasons.
		Non 96bit IVs require GHASH compression which introduces risks:
		
		1. Authentication key leakage: If the same IV is derived from different
			inputs via GHASH, an attacker can recover the authentication key H.
		
		2. Counter wrap attacks: Long IVs can produce counter values near 2^32,
			enabling attacks that leak information about the GHASH of the IV.
		
		Idk why you would even use a different size nonce.
--]=]

--!strict
--!optimize 2

local Http = game:GetService("HttpService")

local Testing = require("./")
local Cryptography = require("../")

local AES = Cryptography.Encryption.AES
local Conversions = Cryptography.Utilities.Conversions
local FromHex = Conversions.FromHex

type AeadTest = {
	tcId: number,
	comment: string?,
	flags: {string}?,
	key: string,
	iv: string,
	aad: string?,
	msg: string,
	ct: string,
	tag: string,
	result: string,
}

type AeadGroup = {
	type: string,
	keySize: number,
	ivSize: number,
	tagSize: number,
	source: {name: string, version: string}?,
	tests: {AeadTest},
}

type AeadData = {
	algorithm: string,
	numberOfTests: number,
	testGroups: {AeadGroup},
}

local WYCHEPROOF_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/aes_gcm_test.json"

local function BuffersEqual(A: buffer, B: buffer): boolean
	if buffer.len(A) ~= buffer.len(B) then
		return false
	end

	for Index = 0, buffer.len(A) - 1 do
		if buffer.readu8(A, Index) ~= buffer.readu8(B, Index) then
			return false
		end
	end

	return true
end

local function FetchTestVectors(): AeadData
	local Response = Http:GetAsync(WYCHEPROOF_URL)
	return Http:JSONDecode(Response) :: AeadData
end

Testing.Describe("AES-GCM Wycheproof Tests", function()
	local Data = FetchTestVectors()
	local SkippedCount = 0

	for GroupIndex, Group in ipairs(Data.testGroups) do
		local KeySize = Group.keySize
		local IvSize = Group.ivSize
		local TagSize = Group.tagSize

		if IvSize ~= 96 then
			SkippedCount += #Group.tests
			continue
		end

		local SourceName = if Group.source then Group.source.name else "unknown"

		Testing.Describe(`Group_{GroupIndex}: {KeySize}bit_Key_{IvSize}bit_IV_{TagSize}bit_Tag (Source: {SourceName})`, function()
			for _, Test in ipairs(Group.tests) do
				local TestId = Test.tcId
				local Comment = Test.comment or ""
				local ExpectedResult = Test.result

				local TestName = `Test_{TestId}`
				if Comment ~= "" then
					TestName = `Test_{TestId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local Key = FromHex(Test.key)
					local Iv = FromHex(Test.iv)
					local Aad = FromHex(Test.aad or "")
					local Msg = FromHex(Test.msg)
					local ExpectedCt = FromHex(Test.ct)
					local ExpectedTag = FromHex(Test.tag)

					if ExpectedResult == "valid" then
						local EncOk, Ct, Tag = pcall(function()
							return AES.Encrypt(Key, Iv, Msg, Aad)
						end)

						Testing.Expect(EncOk).ToBe(true)
						Testing.Expect(Ct).ToBeDefined()
						Testing.Expect(Tag).ToBeDefined()

						if EncOk and Ct and Tag then
							Testing.Expect(BuffersEqual(Ct, ExpectedCt)).ToBe(true)
							Testing.Expect(BuffersEqual(Tag, ExpectedTag)).ToBe(true)

							local DecOk, DecSuccess, Plaintext = pcall(function()
								return AES.Decrypt(Key, Iv, Ct, Tag, Aad)
							end)

							Testing.Expect(DecOk).ToBe(true)
							Testing.Expect(DecSuccess).ToBe(true)
							Testing.Expect(Plaintext).ToBeDefined()

							if Plaintext then
								Testing.Expect(BuffersEqual(Plaintext, Msg)).ToBe(true)
							end
						end
					elseif ExpectedResult == "invalid" then
						local DecOk, DecSuccess, _ = pcall(function()
							return AES.Decrypt(Key, Iv, ExpectedCt, ExpectedTag, Aad)
						end)

						local DecryptionFailed = not DecOk or not DecSuccess
						Testing.Expect(DecryptionFailed).ToBe(true)
					elseif ExpectedResult == "acceptable" then
						Testing.Expect(true).ToBe(true)
					end
				end)
			end
		end)
	end

	if SkippedCount > 0 then
		print(`[Info] Skipped {SkippedCount} tests with non-96-bit IVs (unsupported for security reasons)`)
	end
end)

Testing.Complete()

return 0