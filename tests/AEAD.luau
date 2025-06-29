--!strict
local Testing = require("./")
type TestVector = {
	Description: string,
	Expected: number
}

type TestVectors = {[string]: TestVector}

local Algorithm = require("../Encryption/AEAD")
local ChaCha20 = require("../Encryption/AEAD/ChaCha20")
local Poly1305 = require("../Encryption/AEAD/Poly1305")
local FromHex = require("../Utilities/Conversions").FromHex
local ToHex = require("../Utilities/Conversions").ToHex

Testing.Describe("AEAD Encryption Algorithm Tests", function()
	Testing.Test("Full algorithm test #1", function()
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
		Testing.Expect.Type("buffer")(Plaintext)
		Testing.Expect(buffer.tostring(Plaintext or buffer.create(0))).ToBe(Plain)
	end)
	
	Testing.Test("Tag #1", function()
		local Plaintext = buffer.create(64)
		local Key = buffer.create(32)
		
		local Tag = Poly1305(Plaintext, Key)
		Testing.Expect(ToHex(Tag)).ToBe("00000000000000000000000000000000")
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