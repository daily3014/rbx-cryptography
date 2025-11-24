--[[
Cryptography library: Advanced Encryption Standard (Galois/Counter Mode)
	
	Security Limitations:
		Personally don't like AES-GCM because it has a 96 bit nonce 
		which creates birthday bound issues after 2^32 encryptions with the same key, 
		collision probability reaches 2^-32 (NIST's "soft" birthday bound). 
		Which is why I prefer ChaCha20-Poly1305
		
		AES-GCM is also not key committing meaning the same ciphertext can 
		decrypt to different plaintexts under different keys with valid authentication tags. 
		This creates a "Invisible Salamander" attack where an attacker
		makes a message that appears normal to moderators but evil to
		recipients, or vice versa. Affects group messaging and any project with multiple valid keys.
		https://eprint.iacr.org/2019/016.pdf
		
		The Sbox lookup tables are vulnerable to cache timing attacks in
		theory, but constant-time implementations would kill performance
		and isn't really possible in Roblox in the first place.
		https://bearssl.org/constanttime.html
	
	IV Handling:
		- Store IV alongside ciphertext (IVs are not secret)
		- You can send IV with encrypted data
		- Never reuse IV with same key (this breaks the security)
--]]

--!strict
local ReplicatedStorage = game:GetService("ReplicatedStorage")

-- Get the libraries
local Cryptography = require(ReplicatedStorage:WaitForChild("Cryptography"))
local AES = Cryptography.Encryption.AES
local CSPRNG = Cryptography.Utilities.CSPRNG

local Key = CSPRNG.RandomBytes(32)
local IV = CSPRNG.RandomBytes(12)

local Message = "This is a secret message"
local Plaintext = buffer.fromstring(Message)

-- Optional: Additional Authenticated Data (authenticated but not encrypted)
local AAD = buffer.fromstring("user:alice,timestamp:1234567890")
local Ciphertext, Tag = AES.Encrypt(Key, IV, Plaintext, AAD)
print("Encryption successful!")
print("Ciphertext length:", buffer.len(Ciphertext))
print("Tag length:", buffer.len(Tag))

-- Decrypt and verify (returns false on failure, true and buffer on success)
local Success, DecryptedData = AES.Decrypt(Key, IV, Ciphertext, Tag, AAD)
if Success and DecryptedData then
	local DecryptedMessage = buffer.tostring(DecryptedData)
	print("Decryption successful!")
	print("Original message:", Message)
	print("Decrypted message:", DecryptedMessage)
	print("Messages match:", Message == DecryptedMessage)
else
	warn("Decryption failed, data was messed with!")
end