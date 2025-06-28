--!strict
local Testing = require("./")
type TestVector = {
	Description: string,
	Expected: number
}

type TestVectors = {[string]: TestVector}

local Algorithm = require("../Encryption/AEAD")
local FromHex = require("../Utilities/Conversions").FromHex

Testing.Describe("AEAD Encryption Algorithm Tests", function()
	Testing.Test("Test vector and roundtrip", function()
		local Cipher = FromHex"64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b"

		local Key = FromHex"1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"
		local Nonce = FromHex"000000000102030405060708"

		local AAD = FromHex"f33388860000000000004e91"
		local ReceivedTag = FromHex"eead9d67890cbb22392336fea1851f38"

		local Plain = "Internet-Drafts are draft documents valid for a maximum of six months and may be updated, replaced, or obsoleted by other documents at any time. It is inappropriate to use Internet-Drafts as reference material or to cite them other than as /“work in progress./”"
		do
			local GotCipher, GotTag = Algorithm.Encrypt(buffer.fromstring(Plain), Key, Nonce, AAD)
			
			Testing.Expect(buffer.tostring(GotCipher)).ToBe(buffer.tostring(Cipher))
			Testing.Expect(buffer.tostring(GotTag)).ToBe(buffer.tostring(ReceivedTag))
		end

		local Plaintext = Algorithm.Decrypt(Cipher, Key, Nonce, ReceivedTag, AAD)
		Testing.Expect(buffer.tostring(Plaintext)).ToBe(Plain)
	end)
end)

Testing.Complete()

return 0