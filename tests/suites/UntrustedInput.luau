--!strict
--!optimize 2

local Testing = require("../")

local EdDSA = require("../../src/Verification/EdDSA")
local X25519 = require("../../src/Verification/EdDSA/X25519")
local MlDSA = require("../../src/Verification/MlDSA")
local MlKEM = require("../../src/Verification/MlKEM")
local AES = require("../../src/Encryption/AES")
local AEAD = require("../../src/Encryption/AEAD")
local Base64 = require("../../src/Utilities/Base64")
local Conversions = require("../../src/Utilities/Conversions")

local function Filled(Length: number, Value: number): buffer
	local Buffer = buffer.create(Length)
	buffer.fill(Buffer, 0, Value)
	return Buffer
end

local function Untyped(Value: any): any
	return Value
end

Testing.Describe("Untrusted input gives false or nil, misuse errors", function()
	Testing.Describe("EdDSA.Verify", function()
		local PublicKey = EdDSA.PublicKey(Filled(32, 7))
		local Message = buffer.fromstring("hello")
		local Signature = EdDSA.Sign(Message, Filled(32, 7), PublicKey)

		Testing.Test("Accepts a valid signature", function()
			Testing.Expect(EdDSA.Verify(Message, PublicKey, Signature)).ToBe(true)
		end)

		Testing.Test("Wrong types give false", function()
			Testing.Expect(EdDSA.Verify(Untyped(nil), PublicKey, Signature)).ToBe(false)
			Testing.Expect(EdDSA.Verify(Message, Untyped("not a key"), Signature)).ToBe(false)
			Testing.Expect(EdDSA.Verify(Message, PublicKey, Untyped({}))).ToBe(false)
		end)

		Testing.Test("Wrong lengths give false", function()
			Testing.Expect(EdDSA.Verify(Message, buffer.create(31), Signature)).ToBe(false)
			Testing.Expect(EdDSA.Verify(Message, PublicKey, buffer.create(63))).ToBe(false)
		end)
	end)

	Testing.Describe("MlDSA.Verify", function()
		local Scheme = MlDSA.ML_DSA_44
		local PublicKey = Scheme.GenerateKeys()
		local Context = buffer.create(0)
		local Message = buffer.fromstring("hello")

		Testing.Test("Wrong types give false", function()
			Testing.Expect(Scheme.Verify(Untyped(nil), PublicKey, Context, buffer.create(10))).ToBe(false)
			Testing.Expect(Scheme.Verify(Message, Untyped("key"), Context, buffer.create(10))).ToBe(false)
			Testing.Expect(Scheme.Verify(Message, PublicKey, Context, Untyped(42))).ToBe(false)
		end)

		Testing.Test("Wrong signature length gives false", function()
			Testing.Expect(Scheme.Verify(Message, PublicKey, Context, buffer.create(10))).ToBe(false)
		end)

		Testing.Test("A context that is not a buffer errors", function()
			Testing.Expect(function()
				Scheme.Verify(Message, PublicKey, Untyped(nil), buffer.create(10))
			end).ToThrow()
		end)
	end)

	Testing.Describe("X25519.Exchange", function()
		local SecretKey = Filled(32, 9)
		local TheirPublicKey = X25519.PublicKey(Filled(32, 3))

		Testing.Test("A valid public key gives a shared secret", function()
			Testing.Expect(X25519.Exchange(SecretKey, TheirPublicKey)).ToBeDefined()
		end)

		Testing.Test("Bad public keys give nil", function()
			Testing.Expect(X25519.Exchange(SecretKey, Untyped(nil))).ToBeNil()
			Testing.Expect(X25519.Exchange(SecretKey, Untyped("abc"))).ToBeNil()
			Testing.Expect(X25519.Exchange(SecretKey, buffer.create(31))).ToBeNil()
			Testing.Expect(X25519.Exchange(SecretKey, buffer.create(32))).ToBeNil()
		end)

		Testing.Test("A bad secret key errors", function()
			Testing.Expect(function()
				X25519.Exchange(buffer.create(31), TheirPublicKey)
			end).ToThrow()
		end)
	end)

	Testing.Describe("MlKEM", function()
		local Scheme = MlKEM.MLKEM_768
		local PublicKey, SecretKey = Scheme.GenerateKeys()
		local Randomness = Filled(32, 5)
		local Ciphertext = Scheme.Encapsulate(Randomness, PublicKey) :: buffer

		Testing.Test("Encapsulate with a bad public key gives nil", function()
			local BadCiphertext, BadShared = Scheme.Encapsulate(Randomness, buffer.create(10))
			Testing.Expect(BadCiphertext).ToBeNil()
			Testing.Expect(BadShared).ToBeNil()
			Testing.Expect((Scheme.Encapsulate(Randomness, Untyped("key")))).ToBeNil()
		end)

		Testing.Test("Encapsulate with bad randomness errors", function()
			Testing.Expect(function()
				Scheme.Encapsulate(buffer.create(31), PublicKey)
			end).ToThrow()
		end)

		Testing.Test("Decapsulate with a bad ciphertext gives nil", function()
			Testing.Expect(Scheme.Decapsulate(buffer.create(10), SecretKey)).ToBeNil()
			Testing.Expect(Scheme.Decapsulate(Untyped({}), SecretKey)).ToBeNil()
			Testing.Expect(Scheme.Decapsulate(Ciphertext, SecretKey)).ToBeDefined()
		end)

		Testing.Test("Decapsulate with a bad secret key errors", function()
			Testing.Expect(function()
				Scheme.Decapsulate(Ciphertext, buffer.create(10))
			end).ToThrow()
		end)
	end)

	Testing.Describe("AES.Decrypt", function()
		local Key = Filled(32, 1)
		local IV = Filled(12, 2)
		local Ciphertext, Tag = AES.Encrypt(buffer.fromstring("secret"), Key, IV)

		Testing.Test("Round trips", function()
			Testing.Expect(AES.Decrypt(Ciphertext, Key, IV, Tag)).ToBeDefined()
		end)

		Testing.Test("Bad received data gives nil", function()
			Testing.Expect(AES.Decrypt(Untyped("text"), Key, IV, Tag)).ToBeNil()
			Testing.Expect(AES.Decrypt(Ciphertext, Key, buffer.create(0), Tag)).ToBeNil()
			Testing.Expect(AES.Decrypt(Ciphertext, Key, Untyped(nil), Tag)).ToBeNil()
			Testing.Expect(AES.Decrypt(Ciphertext, Key, IV, Untyped(5))).ToBeNil()
			Testing.Expect(AES.Decrypt(Ciphertext, Key, IV, buffer.create(15))).ToBeNil()
			Testing.Expect(AES.Decrypt(Ciphertext, Key, IV, Tag, Untyped("aad"))).ToBeNil()
		end)

		Testing.Test("A bad key errors", function()
			Testing.Expect(function()
				AES.Decrypt(Ciphertext, buffer.create(20), IV, Tag)
			end).ToThrow()
		end)
	end)

	Testing.Describe("AEAD.Decrypt", function()
		local Key = Filled(32, 1)
		local Nonce = Filled(12, 2)
		local Ciphertext, Tag = AEAD.Encrypt(buffer.fromstring("secret"), Key, Nonce)

		Testing.Test("Round trips", function()
			Testing.Expect(AEAD.Decrypt(Ciphertext, Key, Nonce, Tag)).ToBeDefined()
		end)

		Testing.Test("Bad received data gives nil", function()
			Testing.Expect(AEAD.Decrypt(Untyped("text"), Key, Nonce, Tag)).ToBeNil()
			Testing.Expect(AEAD.Decrypt(Ciphertext, Key, buffer.create(11), Tag)).ToBeNil()
			Testing.Expect(AEAD.Decrypt(Ciphertext, Key, Untyped(nil), Tag)).ToBeNil()
			Testing.Expect(AEAD.Decrypt(Ciphertext, Key, Nonce, buffer.create(15))).ToBeNil()
			Testing.Expect(AEAD.Decrypt(Ciphertext, Key, Nonce, Tag, Untyped(1))).ToBeNil()
		end)

		Testing.Test("A bad key or options error", function()
			Testing.Expect(function()
				AEAD.Decrypt(Ciphertext, buffer.create(16), Nonce, Tag)
			end).ToThrow()
			Testing.Expect(function()
				AEAD.Decrypt(Ciphertext, Key, Nonce, Tag, nil, 7)
			end).ToThrow()
		end)
	end)

	Testing.Describe("Decoders", function()
		Testing.Test("Base64.Decode gives nil for bad input", function()
			Testing.Expect(Base64.Decode(buffer.fromstring("abc"))).ToBeNil()
			Testing.Expect(Base64.Decode(buffer.fromstring("ab!d"))).ToBeNil()
			Testing.Expect(Base64.Decode(buffer.fromstring("QR=="))).ToBeNil()
			Testing.Expect(Base64.Decode(Untyped("QQ=="))).ToBeNil()
			Testing.Expect(Base64.Decode(buffer.fromstring("QQ=="))).ToBeDefined()
		end)

		Testing.Test("Conversions.FromHex gives nil for bad input", function()
			Testing.Expect(Conversions.FromHex("abc")).ToBeNil()
			Testing.Expect(Conversions.FromHex("zz")).ToBeNil()
			Testing.Expect(Conversions.FromHex(Untyped(12))).ToBeNil()
			Testing.Expect(Conversions.FromHex("0aFF")).ToBeDefined()
		end)
	end)
end)

Testing.Complete()

return 0
