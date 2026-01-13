--[=[
	Cryptography library: EdDSA Batch Verification
	Efficient Verification of Multiple Signatures

	This example shows how u can batch verification of multiple Ed25519 signatures.
	Batch verification is more efficient than verifying signatures individually
	when you need to validate many signatures at once.
--]=]
--!strict

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Cryptography = require(ReplicatedStorage:WaitForChild("Cryptography"))

local EdDSA = Cryptography.Verification.EdDSA
local CSPRNG = Cryptography.Utilities.CSPRNG

-- Generate multiple keypairs (different signers)
local Signer1Private = CSPRNG.Ed25519Random()
local Signer1Public = EdDSA.PublicKey(Signer1Private)

local Signer2Private = CSPRNG.Ed25519Random()
local Signer2Public = EdDSA.PublicKey(Signer2Private)

local Signer3Private = CSPRNG.Ed25519Random()
local Signer3Public = EdDSA.PublicKey(Signer3Private)

-- Create messages and sign them
local Message1 = buffer.fromstring("Transaction: Alice sends 100 to Bob")
local Message2 = buffer.fromstring("Transaction: Bob sends 50 to Charlie")
local Message3 = buffer.fromstring("Transaction: Charlie sends 25 to Dave")

local Signature1 = EdDSA.Sign(Signer1Private, Signer1Public, Message1)
local Signature2 = EdDSA.Sign(Signer2Private, Signer2Public, Message2)
local Signature3 = EdDSA.Sign(Signer3Private, Signer3Public, Message3)

-- Batch verification: verify all signatures at once
local Entries = {
	{ PublicKey = Signer1Public, Message = Message1, Signature = Signature1 },
	{ PublicKey = Signer2Public, Message = Message2, Signature = Signature2 },
	{ PublicKey = Signer3Public, Message = Message3, Signature = Signature3 },
}

-- One of the drawbacks is that you do not know which sgnature failed and have to throw out the whole batch
local AllValid = EdDSA.VerifyBatch(Entries)
if AllValid then
	print("All signatures verified successfully")
else
	print("Batch verification failed at least one signature is invalid")
end

-- Show that batch fails if any signature is tampered
local TamperedSignature = buffer.create(64)
buffer.copy(TamperedSignature, 0, Signature3, 0, 64)
buffer.writeu8(TamperedSignature, 0, bit32.bxor(buffer.readu8(TamperedSignature, 0), 0x01))

local TamperedEntries = {
	{ PublicKey = Signer1Public, Message = Message1, Signature = Signature1 },
	{ PublicKey = Signer2Public, Message = Message2, Signature = Signature2 },
	{ PublicKey = Signer3Public, Message = Message3, Signature = TamperedSignature },
}

local TamperedValid = EdDSA.VerifyBatch(TamperedEntries)
assert(TamperedValid == false, "Tampered batch should fail verification")

print("Batch verification completed")