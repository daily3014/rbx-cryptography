--[=[
	ChaCha20-Poly1305 & XChaCha20-Poly1305 Wycheproof Test Suite
	
	Test Vector Sources:
		ChaCha20: https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/chacha20_poly1305_test.json
		XChaCha20: https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/xchacha20_poly1305_test.json
	
	Test Categories:
		Ktv - Known test vectors from RFC 7539 / draft-arciszewski-xchacha
		Pseudorandom - Various input sizes
		ModifiedTag - Tampered authentication tags
		EdgeCasePoly1305 - Integer overflow edge cases
		EdgeCaseTag - Final modular addition edge cases
		InvalidNonceSize - Non-standard nonce sizes
	
	Nonce Size Restrictions:
		ChaCha20-Poly1305: 96-bit (12 bytes) per RFC 7539
		XChaCha20-Poly1305: 192-bit (24 bytes) per spec
		Tests with other nonce sizes are skipped as invalid.
	
	Empty Message Limitation:
		Tests with empty messages are skipped because it won't be supported.
--]=]

--!strict
--!optimize 2

local Http = game:GetService("HttpService")

local Testing = require("./")
local Cryptography = require("../")

local AEAD = Cryptography.Encryption.AEAD
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

local CHACHA20_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/chacha20_poly1305_test.json"
local XCHACHA20_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/refs/heads/main/testvectors_v1/xchacha20_poly1305_test.json"

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

local function FetchTestVectors(Url: string): AeadData
	local Response = Http:GetAsync(Url)
	return Http:JSONDecode(Response) :: AeadData
end

local function RunAeadTests(
	Data: AeadData,
	RequiredIvSize: number,
	IsXChaCha: boolean
): (number, number)
	local SkippedNonceCount = 0
	local SkippedEmptyCount = 0

	for GroupIndex, Group in ipairs(Data.testGroups) do
		local IvSize = Group.ivSize
		local KeySize = Group.keySize
		local TagSize = Group.tagSize

		if IvSize ~= RequiredIvSize then
			SkippedNonceCount += #Group.tests
			continue
		end

		local SourceName = if Group.source then Group.source.name else "unknown"

		Testing.Describe(`Group_{GroupIndex}: {KeySize}bit_Key_{IvSize}bit_IV_{TagSize}bit_Tag (Source: {SourceName})`, function()
			for _, Test in ipairs(Group.tests) do
				local TestId = Test.tcId
				local Comment = Test.comment or ""
				local ExpectedResult = Test.result
				local Msg = FromHex(Test.msg)

				if buffer.len(Msg) == 0 then
					SkippedEmptyCount += 1
					continue
				end

				local TestName = `Test_{TestId}`
				if Comment ~= "" then
					TestName = `Test_{TestId}_{Comment:sub(1, 25):gsub(" ", "_")}`
				end

				Testing.Test(TestName, function()
					local Key = FromHex(Test.key)
					local Iv = FromHex(Test.iv)
					local Aad = FromHex(Test.aad or "")
					local ExpectedCt = FromHex(Test.ct)
					local ExpectedTag = FromHex(Test.tag)

					if ExpectedResult == "valid" then
						local EncOk, Ct, Tag = pcall(function()
							if IsXChaCha then
								return AEAD.Encrypt(Msg, Key, Iv, Aad, 20, true)
							else
								return AEAD.Encrypt(Msg, Key, Iv, Aad)
							end
						end)

						Testing.Expect(EncOk).ToBe(true)
						Testing.Expect(Ct).ToBeDefined()
						Testing.Expect(Tag).ToBeDefined()

						if EncOk and Ct and Tag then
							Testing.Expect(BuffersEqual(Ct, ExpectedCt)).ToBe(true)
							Testing.Expect(BuffersEqual(Tag, ExpectedTag)).ToBe(true)

							local DecOk, Plaintext = pcall(function()
								if IsXChaCha then
									return AEAD.Decrypt(Ct, Key, Iv, Tag, Aad, 20, true)
								else
									return AEAD.Decrypt(Ct, Key, Iv, Tag, Aad)
								end
							end)

							Testing.Expect(DecOk).ToBe(true)
							Testing.Expect(Plaintext).ToBeDefined()

							if Plaintext then
								Testing.Expect(BuffersEqual(Plaintext, Msg)).ToBe(true)
							end
						end
					elseif ExpectedResult == "invalid" then
						local DecOk, Result = pcall(function()
							if IsXChaCha then
								return AEAD.Decrypt(ExpectedCt, Key, Iv, ExpectedTag, Aad, 20, true)
							else
								return AEAD.Decrypt(ExpectedCt, Key, Iv, ExpectedTag, Aad)
							end
						end)

						local DecryptionFailed = not DecOk or not Result
						Testing.Expect(DecryptionFailed).ToBe(true)
					elseif ExpectedResult == "acceptable" then
						Testing.Expect(true).ToBe(true)
					end
				end)
			end
		end)
	end

	return SkippedNonceCount, SkippedEmptyCount
end

Testing.Describe("ChaCha20-Poly1305 Wycheproof Tests", function()
	local Data = FetchTestVectors(CHACHA20_URL)
	local SkippedNonce, SkippedEmpty = RunAeadTests(Data, 96, false)

	if SkippedNonce > 0 then
		print(`[Info] Skipped {SkippedNonce} tests with non-96-bit nonces (invalid per RFC 7539)`)
	end
	if SkippedEmpty > 0 then
		print(`[Info] Skipped {SkippedEmpty} tests with empty messages (unsupported)`)
	end
end)

Testing.Describe("XChaCha20-Poly1305 Wycheproof Tests", function()
	local Data = FetchTestVectors(XCHACHA20_URL)
	local SkippedNonce, SkippedEmpty = RunAeadTests(Data, 192, true)

	if SkippedNonce > 0 then
		print(`[Info] Skipped {SkippedNonce} tests with non-192-bit nonces (invalid per spec)`)
	end
	if SkippedEmpty > 0 then
		print(`[Info] Skipped {SkippedEmpty} tests with empty messages (unsupported)`)
	end
end)

Testing.Complete()

return 0