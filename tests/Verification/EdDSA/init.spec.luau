local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Packages = ReplicatedStorage.Packages
local DevPackages = ReplicatedStorage.DevPackages

local JestGlobals = require(DevPackages.JestGlobals)

local describe = JestGlobals.describe
local it = JestGlobals.it
local expect = JestGlobals.expect

local Cryptography = require(Packages.Cryptography)
local EdDSA = Cryptography.Verification.EdDSA

local TestVectors = require(script.Parent.data:WaitForChild("RFC8032.vectors"))
-- Convert hex vectors to bytes for easy comparison in tests
for _, ref in TestVectors do
	ref.secretKey = Cryptography.Utilities.Conversions.HexToBytesStr(ref.secretKey)
	ref.publicKey = Cryptography.Utilities.Conversions.HexToBytesStr(ref.publicKey)
	ref.message = Cryptography.Utilities.Conversions.HexToBytesStr(ref.message)
	ref.signature = Cryptography.Utilities.Conversions.HexToBytesStr(ref.signature)
end

local function generateKeypair(seed)
	if seed then
		return seed, EdDSA.PublicKey(seed)
	else
		local secretKey = Cryptography.Utilities.RandomString(32) -- 32 bytes for EdDSA
		return secretKey, EdDSA.PublicKey(secretKey)
	end
end

describe("EdDSA", function()
	describe("keypair generation", function()
		it("should derive consistent public keys from secret keys", function()
			local a = EdDSA.PublicKey("12345678901234567890123456789012")
			local b = EdDSA.PublicKey("12345678901234567890123456789012")
			local c = EdDSA.PublicKey("11111111111111111111111111111111")

			expect(#a).toBe(32)
			expect(#b).toBe(32)
			expect(#c).toBe(32)

			expect(a).toBe(b)
			expect(a).never.toBe(c)
		end)
	end)

	describe("sign and verify", function()
		it("should sign and verify empty message", function()
			local secretKey, publicKey = generateKeypair()
			local message = ""

			local signature = EdDSA.Sign(secretKey, publicKey, message)
			expect(#signature).toBe(64)

			local isValid = EdDSA.Verify(publicKey, message, signature)
			expect(isValid).toBe(true)
		end)

		it("should sign and verify various messages", function()
			local secretKey, publicKey = generateKeypair()

			local messages = {
				"Hello, World!",
				"The quick brown fox jumps over the lazy dog",
				string.rep("a", 100),
				"DigitalSignaturesRbx is a public-key signature system with several attractive features",
			}

			for _, message in messages do
				local signature = EdDSA.Sign(secretKey, publicKey, message)
				expect(#signature).toBe(64)

				local isValid = EdDSA.Verify(publicKey, message, signature)
				expect(isValid).toBe(true)
			end
		end)

		it("should reject modified signatures", function()
			local secretKey, publicKey = generateKeypair()
			local message = "Test message"
			local signature = EdDSA.Sign(secretKey, publicKey, message)

			-- Modify last byte of signature
			local invalidSig = string.sub(signature, 1, 63) .. string.char((string.byte(signature, 64) + 1) % 256)

			expect(EdDSA.Verify(publicKey, message, invalidSig)).toBe(false)
		end)

		it("should reject signatures with wrong message", function()
			local secretKey, publicKey = generateKeypair()
			local message = "Original message"
			local signature = EdDSA.Sign(secretKey, publicKey, message)

			expect(EdDSA.Verify(publicKey, message .. "x", signature)).toBe(false)
		end)

		it("should reject signatures with wrong public key", function()
			local secretKey1, publicKey1 = generateKeypair()
			local _, publicKey2 = generateKeypair()

			expect(publicKey1).never.toBe(publicKey2)

			local message = "Test message"
			local signature = EdDSA.Sign(secretKey1, publicKey1, message)

			expect(EdDSA.Verify(publicKey2, message, signature)).toBe(false)
		end)
	end)

	describe("invalid inputs", function()
		describe("Sign", function()
			it("should throw with secret key with wrong length", function()
				local secretKey, publicKey = generateKeypair()
				local message = "Test message"

				expect(function()
					EdDSA.Sign(string.sub(secretKey, 1, 31), publicKey, message)
				end).toThrow()
			end)
			it("should throw with public key with wrong length", function()
				local secretKey, publicKey = generateKeypair()
				local message = "Test message"

				expect(function()
					EdDSA.Sign(secretKey, string.sub(publicKey, 1, 31), message)
				end).toThrow()
			end)
		end)
		describe("Verify", function()
			it("should reject signature with wrong length", function()
				local secretKey, publicKey = generateKeypair()
				local message = "Test message"
				local signature = EdDSA.Sign(secretKey, publicKey, message)

				expect(EdDSA.Verify(publicKey, message, string.sub(signature, 1, 63))).toBe(false)
			end)

			it("should reject public key with wrong length", function()
				local secretKey, publicKey = generateKeypair()
				local message = "Test message"
				local signature = EdDSA.Sign(secretKey, publicKey, message)

				expect(EdDSA.Verify(string.sub(publicKey, 1, 31), message, signature)).toBe(false)
			end)

			it("should reject signature with S >= L", function()
				local secretKey, publicKey = generateKeypair()
				local message = "Test message"
				local signature = EdDSA.Sign(secretKey, publicKey, message)

				-- Create invalid signature with S >= L
				local invalidS = string.sub(signature, 1, 32) .. string.rep("\xFF", 32)

				expect(EdDSA.Verify(publicKey, message, invalidS)).toBe(false)
			end)
		end)
		describe("PublicKey", function()
			it("should throw with secret key with wrong length", function()
				expect(function()
					EdDSA.PublicKey("123")
				end).toThrow()
			end)
		end)
	end)

	describe("deterministic signatures", function()
		it("should produce identical signatures for same message and key", function()
			local secretKey, publicKey = generateKeypair()

			local sig1 = EdDSA.Sign(secretKey, publicKey, "Deterministic")
			local sig2 = EdDSA.Sign(secretKey, publicKey, "Deterministic")
			local sig3 = EdDSA.Sign(secretKey, publicKey, "Deterministic")

			expect(sig1).toBe(sig2)
			expect(sig1).toBe(sig3)
		end)

		it("should produce different signatures for different messages", function()
			local secretKey, publicKey = generateKeypair()

			local sig1 = EdDSA.Sign(secretKey, publicKey, "Foo")
			local sig2 = EdDSA.Sign(secretKey, publicKey, "Bar")

			expect(sig1).never.toBe(sig2)
		end)
	end)

	describe("cross-keypair verification", function()
		it("should only verify with matching keypair", function()
			-- Generate multiple keypairs
			local keys = {}
			for i = 1, 3 do
				local secretKey, publicKey = generateKeypair()
				keys[i] = { secret = secretKey, public = publicKey }
			end

			local message = "Cross verification test"

			-- Sign with each key and verify with all public keys
			for i = 1, 3 do
				local signature = EdDSA.Sign(keys[i].secret, keys[i].public, message)

				for j = 1, 3 do
					local shouldVerify = (i == j)
					local doesVerify = EdDSA.Verify(keys[j].public, message, signature)

					expect(doesVerify).toBe(shouldVerify)
				end
			end
		end)
	end)

	describe("RFC-8032 test vectors", function()
		-- Break into multiple smaller tests to avoid timeout issues
		it.each({
			{ start = 1, stop = 128 },
			{ start = 129, stop = 256 },
			{ start = 257, stop = 384 },
			{ start = 385, stop = 512 },
			{ start = 513, stop = 640 },
			{ start = 641, stop = 768 },
			{ start = 769, stop = 896 },
			{ start = 897, stop = 1024 },
		})("should handle test vectors $start through $stop", function(testRange)
			for i = testRange.start, testRange.stop do
				local ref = TestVectors[i]
				local secretKey = ref.secretKey
				local publicKey = EdDSA.PublicKey(secretKey)

				expect(publicKey).toBe(ref.publicKey)

				local message = ref.message
				local signature = EdDSA.Sign(secretKey, publicKey, message)

				-- Verify the signature
				expect(signature).toBe(ref.signature)
				expect(EdDSA.Verify(publicKey, message, signature)).toBe(true)
			end
		end)
	end)
end)
