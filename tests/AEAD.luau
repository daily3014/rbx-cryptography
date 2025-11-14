--!strict
local Testing = require("./")
type TestVector = {
	Description: string,
	Expected: number
}

type TestVectors = {[string]: TestVector}

local Algorithm = require("../Encryption/AEAD")
local ChaCha20 = require("../Encryption/AEAD/ChaCha").ChaCha20
local XChaCha20 = require("../Encryption/AEAD/ChaCha").XChaCha20
local Poly1305 = require("../Encryption/AEAD/Poly1305")
local FromHex = require("../Utilities/Conversions").FromHex
local ToHex = require("../Utilities/Conversions").ToHex

Testing.Describe("AEAD Encryption Algorithm Tests", function()
	Testing.Test("Full algorithm test #1", function()
		local Cipher = FromHex("64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b")

		local Key = FromHex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
		local Nonce = FromHex("000000000102030405060708")

		local AAD = FromHex("f33388860000000000004e91")
		local ReceivedTag = FromHex("eead9d67890cbb22392336fea1851f38")

		local Plain = "Internet-Drafts are draft documents valid for a maximum of six months and may be updated, replaced, or obsoleted by other documents at any time. It is inappropriate to use Internet-Drafts as reference material or to cite them other than as /“work in progress./”"
		do
			local GotCipher, GotTag = Algorithm.Encrypt(buffer.fromstring(Plain), Key, Nonce, AAD)
			
			Testing.Expect(buffer.tostring(GotCipher)).ToBe(buffer.tostring(Cipher))
			Testing.Expect(buffer.tostring(GotTag)).ToBe(buffer.tostring(ReceivedTag))
		end

		local Plaintext = Algorithm.Decrypt(Cipher, Key, Nonce, ReceivedTag, AAD)
		Testing.Expect.Type("buffer")(Plaintext)
		Testing.Expect(buffer.tostring(Plaintext or buffer.create(0))).ToBe(Plain)
	end)
	
	Testing.Test("Tag #1", function()
		local Plaintext = buffer.create(64)
		local Key = buffer.create(32)
		
		local Tag = Poly1305(Plaintext, Key)
		Testing.Expect(ToHex(Tag)).ToBe("00000000000000000000000000000000")
	end)
	
	Testing.Test("AEAD XChaCha20 Algorithm Tests", function()
		local Key = FromHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
		local Data = FromHex("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
		local AAD = FromHex("50515253c0c1c2c3c4c5c6c7")
		local Nonce = FromHex("404142434445464748494a4b4c4d4e4f5051525354555657")
		
		local CipherText = FromHex("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e")
		local Tag = FromHex("c0875924c1c7987947deafd8780acf49")
		local GotCipher, GotTag = Algorithm.Encrypt(Data, Key, Nonce, AAD, 20, true)
		Testing.Expect(buffer.tostring(GotCipher)).ToBe(buffer.tostring(CipherText))
		Testing.Expect(buffer.tostring(GotTag)).ToBe(buffer.tostring(Tag))
	end)
	
	Testing.Test("XChaCha20 Algorithm Tests", function()
		local Key = FromHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
		local Data = FromHex("5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e")
		local Nonce = FromHex("404142434445464748494a4b4c4d4e4f5051525354555658")

		local CipherText = FromHex("7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee053a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd20112f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63d595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4d0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d316838a9c71f70b5b5907a66f7ea49aadc409")
		local GotCipher = XChaCha20(Data, Key, Nonce)
		Testing.Expect(buffer.tostring(GotCipher)).ToBe(buffer.tostring(CipherText))
	end)
	
	Testing.Test("Tag #2", function()
		local Key = FromHex(
			"00000000000000000000000000000000" ..
			"36e5f6b5c5e06070f0efca96227a863e"
		)
		
		local Data = FromHex(
			"416e79207375626d697373696f6e2074" ..
			"6f20746865204945544620696e74656e" ..
			"6465642062792074686520436f6e7472" ..
			"696275746f7220666f72207075626c69" ..
			"636174696f6e20617320616c6c206f72" ..
			"2070617274206f6620616e2049455446" ..
			"20496e7465726e65742d447261667420" ..
			"6f722052464320616e6420616e792073" ..
			"746174656d656e74206d616465207769" ..
			"7468696e2074686520636f6e74657874" ..
			"206f6620616e20494554462061637469" ..
			"7669747920697320636f6e7369646572" ..
			"656420616e20224945544620436f6e74" ..
			"7269627574696f6e222e205375636820" ..
			"73746174656d656e747320696e636c75" ..
			"6465206f72616c2073746174656d656e" ..
			"747320696e2049455446207365737369" ..
			"6f6e732c2061732077656c6c20617320" ..
			"7772697474656e20616e6420656c6563" ..
			"74726f6e696320636f6d6d756e696361" ..
			"74696f6e73206d61646520617420616e" ..
			"792074696d65206f7220706c6163652c" ..
			"20776869636820617265206164647265" ..
			"7373656420746f"
		)


		local Tag = Poly1305(Data, Key)
		Testing.Expect(ToHex(Tag)).ToBe("36e5f6b5c5e06070f0efca96227a863e")
	end)
	
	Testing.Test("Tag #3", function()
		local Key = FromHex(
			"36e5f6b5c5e06070f0efca96227a863e" ..
			"00000000000000000000000000000000"
		)

		local Data = FromHex(
			"416e79207375626d697373696f6e2074" ..
			"6f20746865204945544620696e74656e" ..
			"6465642062792074686520436f6e7472" ..
			"696275746f7220666f72207075626c69" ..
			"636174696f6e20617320616c6c206f72" ..
			"2070617274206f6620616e2049455446" ..
			"20496e7465726e65742d447261667420" ..
			"6f722052464320616e6420616e792073" ..
			"746174656d656e74206d616465207769" ..
			"7468696e2074686520636f6e74657874" ..
			"206f6620616e20494554462061637469" ..
			"7669747920697320636f6e7369646572" ..
			"656420616e20224945544620436f6e74" ..
			"7269627574696f6e222e205375636820" ..
			"73746174656d656e747320696e636c75" ..
			"6465206f72616c2073746174656d656e" ..
			"747320696e2049455446207365737369" ..
			"6f6e732c2061732077656c6c20617320" ..
			"7772697474656e20616e6420656c6563" ..
			"74726f6e696320636f6d6d756e696361" ..
			"74696f6e73206d61646520617420616e" ..
			"792074696d65206f7220706c6163652c" ..
			"20776869636820617265206164647265" ..
			"7373656420746f"
		)

		local Tag = Poly1305(Data, Key)
		Testing.Expect(ToHex(Tag)).ToBe("f3477e7cd95417af89a6b8794c310cf0")
	end)
	
	Testing.Test("Tag #4", function()
		local Key = FromHex(
			"1c9240a5eb55d38af333888604f6b5f0" ..
			"473917c1402b80099dca5cbc207075c0"
		)

		local Data = FromHex(
			"2754776173206272696c6c69672c2061" ..
			"6e642074686520736c6974687920746f" ..
			"7665730a446964206779726520616e64" ..
			"2067696d626c6520696e207468652077" ..
			"6162653a0a416c6c206d696d73792077" ..
			"6572652074686520626f726f676f7665" ..
			"732c0a416e6420746865206d6f6d6520" ..
			"7261746873206f757467726162652e"
		)

		local Tag = Poly1305(Data, Key)
		Testing.Expect(ToHex(Tag)).ToBe("4541669a7eaaee61e708dc7cbcc5eb62")
	end)
	
	Testing.Test("Tag #5 - 130-bit partial reduction", function()
		local Key = FromHex(
			"02000000000000000000000000000000" ..
			"00000000000000000000000000000000"
		)
		
		local Data = FromHex("ffffffffffffffffffffffffffffffff")
		local Tag = Poly1305(Data, Key)
		Testing.Expect(ToHex(Tag)).ToBe("03000000000000000000000000000000")
	end)
	
	Testing.Test("Tag #6 - addition of S overflow", function()
		local Key = FromHex(
			"02000000000000000000000000000000" ..
			"ffffffffffffffffffffffffffffffff"
		)

		local Data = FromHex("02000000000000000000000000000000")
		local Tag = Poly1305(Data, Key)
		Testing.Expect(ToHex(Tag)).ToBe("03000000000000000000000000000000")
	end)
	
	Testing.Test("Tag #7 - final polynomial = 2^130-5", function()
		local Key = FromHex(
			"01000000000000000000000000000000" ..
			"00000000000000000000000000000000"
		)

		local Data = FromHex(
			"ffffffffffffffffffffffffffffffff" ..
			"fbfefefefefefefefefefefefefefefe" ..
			"01010101010101010101010101010101"
		)
		local Tag = Poly1305(Data, Key)
		Testing.Expect(ToHex(Tag)).ToBe("00000000000000000000000000000000")
	end)
	
	Testing.Test("Tag #8 - final polynomial = 2^130-6", function()
		local Key = FromHex(
			"02000000000000000000000000000000" ..
			"00000000000000000000000000000000"
		)

		local Data = FromHex("fdffffffffffffffffffffffffffffff")
		local Tag = Poly1305(Data, Key)
		
		Testing.Expect(ToHex(Tag)).ToBe("faffffffffffffffffffffffffffffff")
	end)
	
	Testing.Test("Tag #9 - lower limb carry", function()
		local Key = FromHex(
			"01000000000000000000000000000000" ..
			"00000000000000000000000000000000"
		)

		local Data = FromHex(
			"ffffffffffffffffffffffffffffffff" ..
			"f0ffffffffffffffffffffffffffffff" ..
			"11000000000000000000000000000000"
		)
		
		local Tag = Poly1305(Data, Key)
		Testing.Expect(ToHex(Tag)).ToBe("05000000000000000000000000000000")
	end)
	
	Testing.Test("Tag #10 - 5*H+L-type reduction to 131-bit intermediate", function()
		local Key = FromHex(
			"01000000000000000400000000000000" ..
			"00000000000000000000000000000000"
		)

		local Data = FromHex(
			"e33594d7505e43b90000000000000000" ..
			"3394d7505e4379cd0100000000000000" ..
			"00000000000000000000000000000000" ..
			"01000000000000000000000000000000"
		)

		local Tag = Poly1305(Data, Key)
		Testing.Expect(ToHex(Tag)).ToBe("14000000000000005500000000000000")
	end)
	
	Testing.Test("Tag #11 - 5*H+L-type reduction to 131-bit final", function()
		local Key = FromHex(
			"01000000000000000400000000000000" ..
			"00000000000000000000000000000000"
		)

		local Data = FromHex(
			"e33594d7505e43b90000000000000000" ..
			"3394d7505e4379cd0100000000000000" ..
			"00000000000000000000000000000000"
		)

		local Tag = Poly1305(Data, Key)
		Testing.Expect(ToHex(Tag)).ToBe("13000000000000000000000000000000")
	end)
	
	Testing.Test("Auth key #1", function()
		local Key = buffer.create(32)
		local Nonce = buffer.create(12)
		
		local AuthKey = ChaCha20(buffer.create(32), Key, Nonce, 0, 20)
		Testing.Expect(ToHex(AuthKey)).ToBe("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7")
	end)
	
	Testing.Test("Auth key #2", function()
		local Key = buffer.create(32)
		buffer.writeu8(Key, 31, 1)
		local Nonce = buffer.create(12)
		buffer.writeu8(Nonce, 11, 2)

		local AuthKey = ChaCha20(buffer.create(32), Key, Nonce, 0, 20)
		Testing.Expect(ToHex(AuthKey)).ToBe("ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739")
	end)
	
	Testing.Test("Auth key #3", function()
		local Key = FromHex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
		local Nonce = buffer.create(12)
		buffer.writeu8(Nonce, 11, 2)

		local AuthKey = ChaCha20(buffer.create(32), Key, Nonce, 0, 20)
		Testing.Expect(ToHex(AuthKey)).ToBe("965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae")
	end)
end)

Testing.Complete()

return 0