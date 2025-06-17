# Luau Cryptography
A tested, high performance cryptography library for Roblox built in Luau. 
Has over 30+ cryptographic functions including modern algorithms like SHA-3, BLAKE3, ChaCha20-Poly1305, and EdDSA alongside classic implementations. 
Through alot of optimizations, the implementations are **200-900% faster** than alternatives while having actual readable code.

**Links:**
- [DevForum Documentation](https://devforum.roblox.com/t/fastest-cryptography-library-for-roblox/3680271)
- [Wally Package](https://wally.run/package/daily3014/cryptography)
- [Pesde Package](https://pesde.dev/packages/daily3014/cryptography)

## Features

- **High Performance**: 2x-8.7x faster than alternative implementations
- **Algorithm Support**: 30+ cryptographic functions covering all major use cases
- **Modern Cryptography**: Latest algorithms including SHA-3, BLAKE3, ChaCha20-Poly1305, and EdDSA
- **Easy Integration**: Clean modular API designed for Roblox environments
- **Multiple Package Managers**: Available on both Wally and Pesde
- **Buffer Based**: Efficient buffer usage for everything
- **Fully Testing**: Every algorithm is tested with NIST test vectors
- **Type Safe**: Complete type definitions
- **Well Documented**: Good documentation and examples (website soon) 

### Supported Algorithms

**Hashing Functions (20):**
- **SHA-2 Family**: SHA-224, 256, 384, 512, 512_224, 512_256 (optional salt support)
- **SHA-3 Family**: SHA3-224, 256,3 84, 512, Shake128, Shake256 (latest NIST standard)
- **BLAKE Family**: BLAKE3 (fastest available), BLAKE3-Keyed
- **Authentication**: HMAC (works with any hash function)
- **Fast Hashing**: XXH32 (ultra-fast non-cryptographic)

**Encryption Functions (3):**
- **Stream Cipher**: ChaCha20 (stream cipher)
- **Block Cipher**: AES with multiple modes (CBC, ECB, etc.) and padding schemes
- **Authenticated Encryption**: ChaCha20-Poly1305 AEAD

**Digital Signatures (3):**
- **EdDSA**: Ed25519 key generation, signing, and verification with masking and double key exchange
  
**Utility Functions (10+):**
- **Encoding**: Base64 encode/decode
- **Conversions**: Hex to/from buffer, string utilities
- **Random Generation**: Generates random strings
- **Checksums**: CRC32 (JAM/ISO modes), Adler

---

## Performance
Table would be too large if everything was benched.
Every implementation is faster than all alternatives:

| Algorithm           | Data Size | This Library | HashLib  | Alternative                    | Other Libraries | Improvement                  |
|---------------------|-----------|--------------|----------|--------------------------------|-----------------|------------------------------|
| **SHA512**          | 10k       | **415 μs**   | 2232 μs  | -                              | 641 μs          | **5.6x faster** than HashLib |
| **SHA256**          | 20k       | **370 μs**   | 2058 μs  | 493 μs (old version)           | 596 μs          | **5.5x faster** than HashLib |
| **Keccak/SHA3-512** | 20k       | **6.28 ms**  | 10.60 ms | -                              | -               | **1.7x faster** than HashLib |
| **ChaCha20**        | 20k       | **0.91 ms**  | -        | 7.87 ms (EncryptedNet)         | -               | **8.6x faster**              |
| **AES**             | 20k       | **1.16 ms**  | -        | 5.34 ms (RobloxGamerPro200007) | -               | **4.6x faster**              |
| **CRC32**           | 200k      | **2.58 ms**  | -        | 6.26 ms (DevForum)             | -               | **2.4x faster**              |
| **Adler32**         | 200k      | **0.19 ms**  | -        | 1.65 ms (Naive Approach)       | -               | **8.7x faster**              |

*Benchmarks performed in Roblox Studio on an Intel Core i7-12700*\
*Plugin used: Benchmarker by @boatbomber*

---

## Installation

### Wally
https://wally.run/package/daily3014/cryptography

### Pesde
https://pesde.dev/packages/daily3014/cryptography

### Manual Installation
1. Download the latest release from GitHub
2. Drag the rbxm/rbxmx file into studio
3. Require the module in your scripts

---

## Quick Start

### Basic Setup
```lua
-- Require the library
local Cryptography = require(game:GetService("ReplicatedStorage").Cryptography)

-- Module shortcuts
local Hashing = Cryptography.Hashing
local Encryption = Cryptography.Encryption
local Utilities = Cryptography.Utilities
local Verification = Cryptography.Verification
local Checksums = Cryptography.Checksums
```

### Hash Something Quickly
```lua
-- Hash a message with SHA-256
local MessageBuffer = buffer.fromstring("Hello World!")
local Hash = Hashing.SHA2.SHA256(MessageBuffer)
print("SHA256:", Hash) -- Output is already in hex format
```

### Secure Password Hashing
```lua
-- Hash a password with salt
local function HashPassword(Password, Salt)
    local PasswordBuffer = buffer.fromstring(Password)
    local SaltBuffer = buffer.fromstring(Salt or "defaultsalt")

    return Hashing.SHA2.SHA256(PasswordBuffer, SaltBuffer)
end

-- Example usage
local UserPassword = "MySecurePassword123"
local HashedPassword = HashPassword(UserPassword, "randomsalt")
print("Hashed password:", HashedPassword)

-- Verify password by comparing hashes
local function VerifyPassword(InputPassword, StoredHash, Salt)
    local InputHash = HashPassword(InputPassword, Salt)
    return InputHash == StoredHash
end

local IsValid = VerifyPassword("MySecurePassword123", HashedPassword, "randomsalt")
print("Password is valid:", IsValid)
```

### Authenticated Encryption (AEAD)
```lua
local PlainText = buffer.fromstring("Hello World")
local Key = buffer.fromstring(string.rep("k", 32))
local Nonce = buffer.fromstring(string.rep("n", 12))
local AAD = buffer.fromstring("additional data")

local Ciphertext, Tag = Encryption.AEAD.Encrypt(PlainText, Key, Nonce, AAD)
local DecryptedText = Encryption.AEAD.Decrypt(Ciphertext, Key, Nonce, Tag, AAD)
```
### EdDsa Usage
```lua
local EdDSA = Verification.EdDSA

-- Standard EdDSA usage
local SecretKey = RandomBytes.Random(32) -- You may use any random string generator but it has to be a buffer!
local PublicKey = EdDSA.PublicKey(SecretKey)
local Message = buffer.fromstring("Hello World")
local Signature = EdDSA.Sign(SecretKey, PublicKey, Message)
local IsValid = EdDSA.Verify(PublicKey, Message, Signature)

-- EdDSA with signature masking (enhanced security)
local SecretKey = RandomBytes.Random(32)
local MaskedSignatureKey = EdDSA.MaskedX25519.Mask(SecretKey)
local PublicKey = EdDSA.PublicKey(SecretKey)
local Message = buffer.fromstring("Hello World")
local Signature = EdDSA.Sign(SecretKey, PublicKey, Message)
local IsValid = EdDSA.Verify(PublicKey, Message, Signature)

-- Masked X25519 key exchange via EdDSA module
local AliceSecret = buffer.fromstring(string.rep("a", 32))
local AliceMaskedKey = EdDSA.MaskedX25519.Mask(AliceSecret)
local AlicePublicKey = EdDSA.MaskedX25519.PublicKey(AliceMaskedKey)

local BobSecret = buffer.fromstring(string.rep("b", 32))
local BobMaskedKey = EdDSA.MaskedX25519.Mask(BobSecret)
local BobPublicKey = EdDSA.MaskedX25519.PublicKey(BobMaskedKey)

-- Note that the secrets *shouldn't match!*
local AliceStaticSecret, AliceEphemeralSecret = EdDSA.MaskedX25519.Exchange(AliceMaskedKey, BobPublicKey)
local BobStaticSecret, BobEphemeralSecret = EdDSA.MaskedX25519.Exchange(BobMaskedKey, AlicePublicKey)

-- Refresh masking for ongoing security
local AliceRemaskedKey = EdDSA.MaskedX25519.Remask(AliceMaskedKey)

--- Masked X25519 Examples

-- Generate keypair
local SecretKey = RandomBytes.Random(32)
local PublicKey = EdDSA.PublicKey(SecretKey)

-- Sign message
local Message = buffer.fromstring("Hello World")
local Signature = EdDSA.Sign(SecretKey, PublicKey, Message)

-- Verify signature
local IsValid = EdDSA.Verify(PublicKey, Message, Signature)
assert(IsValid)

-- Alice setup
local AliceSecret = RandomBytes.Random(32)
local AliceMaskedKey = EdDSA.MaskedX25519.Mask(AliceSecret)
local AlicePublicKey = EdDSA.MaskedX25519.PublicKey(AliceMaskedKey)

-- Bob setup  
local BobSecret = RandomBytes.Random(32)
local BobMaskedKey = EdDSA.MaskedX25519.Mask(BobSecret)
local BobPublicKey = EdDSA.MaskedX25519.PublicKey(BobMaskedKey)

-- Key exchange
-- (The secrets themselves won't match, but can derive the same shared key)
local AliceStaticSecret, AliceEphemeralSecret = EdDSA.MaskedX25519.Exchange(AliceMaskedKey, BobPublicKey)
local BobStaticSecret, BobEphemeralSecret = EdDSA.MaskedX25519.Exchange(BobMaskedKey, AlicePublicKey)

-- Refresh masking
local AliceRemasked = EdDSA.MaskedX25519.Remask(AliceMaskedKey)

-- Create masked signing key
local AliceSigningMasked = EdDSA.MaskedX25519.MaskSignature(SecretKey)
local AliceSigningPublic = EdDSA.MaskedX25519.PublicKey(AliceSigningMasked)

-- Get ephemeral key
local EphemeralKey = EdDSA.MaskedX25519.EphemeralSecretKey(AliceMaskedKey)

-- Test that signatures work correctly
local TestMessage = buffer.fromstring("Test validation message")
local TestSignature = EdDSA.Sign(SecretKey, PublicKey, TestMessage)
local TestValid = EdDSA.Verify(PublicKey, TestMessage, TestSignature)
assert(TestValid)

-- Test that wrong signature fails
local WrongMessage = buffer.fromstring("Different message")
local WrongValid = EdDSA.Verify(PublicKey, WrongMessage, TestSignature)
assert(not WrongValid)

-- Test that key exchange produces 32-byte secrets
assert(buffer.len(AliceStaticSecret) == 32, "Alice static secret should be 32 bytes")
assert(buffer.len(AliceEphemeralSecret) == 32, "Alice ephemeral secret should be 32 bytes")
assert(buffer.len(BobStaticSecret) == 32, "Bob static secret should be 32 bytes")
assert(buffer.len(BobEphemeralSecret) == 32, "Bob ephemeral secret should be 32 bytes")

-- Test that public keys are 32 bytes
assert(buffer.len(PublicKey) == 32, "EdDSA public key should be 32 bytes")
assert(buffer.len(AlicePublicKey) == 32, "Alice X25519 public key should be 32 bytes")
assert(buffer.len(BobPublicKey) == 32, "Bob X25519 public key should be 32 bytes")
```

---

## API Reference

### Hashing Functions

**SHA-2 Family:**
```lua
Hashing.SHA2.SHA224(Message: buffer, Salt?: buffer) -> string
Hashing.SHA2.SHA256(Message: buffer, Salt?: buffer) -> string
Hashing.SHA2.SHA384(Message: buffer, Salt?: buffer) -> string
Hashing.SHA2.SHA512(Message: buffer, Salt?: buffer) -> string
Hashing.SHA2.SHA512_224(Message: buffer, Salt?: buffer) -> string
Hashing.SHA2.SHA512_256(Message: buffer, Salt?: buffer) -> string
-- Computes SHA2-xxx hash with optional salt. Most commonly used cryptographic hash function.
```

**SHA-3 Family:**
```lua
Hashing.SHA3.SHA3_224(Message: buffer) -> string
Hashing.SHA3.SHA3_256(Message: buffer) -> string
Hashing.SHA3.SHA3_384(Message: buffer) -> string
Hashing.SHA3.SHA3_512(Message: buffer) -> string
-- Modern SHA3-xxx hash function.

Hashing.SHA3.SHAKE_128(Message: buffer) -> string
Hashing.SHA3.SHAKE_256(Message: buffer) -> string
-- Modern SHAKE-xxx hash function.
```

**BLAKE Family:**
```lua
Hashing.Blake3.Digest(Message: buffer, Length?: number) -> string
-- Fastest cryptographic hash function available. Optimized for performance.
Hashing.Blake3.DigestKeyed(Key: buffer, Message: buffer, Length?: number) -> string
-- Keyed Blake3 hash for authenticated hashing scenarios.

Hashing.Blake2b(InputData: buffer, OutputLength: number?, KeyData: buffer?) -> string
-- Secure cryptographic hash function with optional keying (1-64 byte output, 0-64 byte key).
```

**Authentication:**
```lua
Hashing.HMAC(Message: buffer, Key: buffer, HashFn: function, BlockSize: number) -> string
-- Hash based message authentication code. Works with any underlying hash function.
```

**Fast Hashing:**
```lua
Hashing.XXH32(Message: buffer, Seed?: number) -> number
-- Fast non cryptographic hash function. Perfect for hash tables and checksums.
```

### Encryption Functions

**Stream Cipher:**
```lua
Encryption.AEAD.ChaCha20(Data: buffer, Key: buffer, Nonce: buffer, Counter?: number, Rounds?: number) -> buffer
-- ChaCha20 stream cipher encryption/decryption.
```

**Block Cipher:**
```lua
-- Modes are found in AES.Modes
-- Pads are found in AES.Pads

Encryption.AES.New(Key: buffer, Mode: AESMode, Padding: AESPadding) -> AesCipher
-- Create AES encryption profile with specified mode and padding scheme.

-- Example AES usage:
local AESProfile = Encryption.AES.New(
    buffer.fromstring("A24ByteEncryptionKeyHere"),
    Encryption.AES.Modes.CBC,
    Encryption.AES.Pads.Pkcs7
)

local Message = "Can be a buffer too!"

local Encrypted = AESProfile:Encrypt(Message, nil, InitVector)
local Decrypted = AESProfile:Decrypt(Encrypted, nil, InitVector)
```

**Authenticated Encryption:**
```lua
Encryption.AEAD.Encrypt(Message: buffer, Key: buffer, Nonce: buffer, AAD?: buffer, Rounds?: number) -> (buffer, buffer)
-- ChaCha20-Poly1305 authenticated encryption. Returns ciphertext and authentication tag.

Encryption.AEAD.Decrypt(Ciphertext: buffer, Key: buffer, Nonce: buffer, Tag: buffer, AAD?: buffer, Rounds?: number) -> buffer?
-- ChaCha20-Poly1305 authenticated decryption. Returns plaintext or nil if authentication fails.
```

### Digital Signatures

**EdDSA (Ed25519):**
```lua
Verification.EdDSA.PublicKey(SecretKey: buffer) -> buffer
-- Generate public key from secret key using Ed25519 algorithm.

Verification.EdDSA.Sign(SecretKey: buffer, PublicKey: buffer, Message: buffer) -> buffer
-- Create digital signature for a message using Ed25519.

Verification.EdDSA.Verify(PublicKey: buffer, Message: buffer, Signature: buffer) -> boolean
-- Returns true if signature is valid.

Verification.EdDSA.MaskedX25519.Mask(SecretKey: buffer) -> buffer
-- Creates a 64-byte masked key from a 32-byte secret key for side-channel attack protection.

Verification.EdDSA.MaskedX25519.MaskSignature(SignatureSecretKey: buffer) -> buffer
-- Creates a masked key from an EdDSA signature secret key (applies SHA512 then masking).

Verification.EdDSA.MaskedX25519.Remask(MaskedKey: buffer) -> buffer
-- Refreshes the masking on a 64-byte masked key with new randomness.

Verification.EdDSA.MaskedX25519.PublicKey(MaskedKey: buffer) -> buffer
-- Generates a 32-byte public key from a 64-byte masked key.

Verification.EdDSA.MaskedX25519.Exchange(MaskedSecretKey: buffer, TheirPublicKey: buffer) -> (buffer, buffer)
-- Performs double key exchange returning (StaticSecret, EphemeralSecret).

Verification.EdDSA.MaskedX25519.EphemeralSecretKey(MaskedKey: buffer) -> buffer
-- Extracts the 32-byte ephemeral secret from a 64-byte masked key.
```

### Utility Functions

**Encoding:**
```lua
Utilities.Base64.Encode(Input: buffer) -> string
-- Encode buffer data to Base64 string representation.

Utilities.Base64.Decode(Input: buffer) -> string
-- Decode Base64 string.
```

**Conversions:**
```lua
Utilities.Conversions.ToHex(Buffer: buffer) -> string
-- Convert buffer to hexadecimal string representation.

Utilities.Conversions.FromHex(Hex: string) -> buffer
-- Convert hexadecimal string to buffer.
```

**Random Generation:**
```lua
Utilities.RandomString(Length: number) -> string
-- Generate random string of specified length.
```

### Checksum Functions

```lua
Checksums.CRC32(Message: buffer, Mode: "Jam" | "Iso"?, Hex: boolean?) -> number
-- Calculate CRC32 checksum with optional mode and output format.

Checksums.Adler(Message: buffer) -> number
-- Calculate Adler checksum.
```

## Testing

### Running Tests

To run the complete test suite:
```bash
bash scripts/test.sh
```
This will launch Roblox Studio, execute all tests, and display results in your terminal.

### Development Testing

For continuous testing during development:
```bash
bash scripts/dev.sh
```
This starts a Rojo server. Open Roblox Studio and sync Rojo into a Baseplate. Whenever you run the game server, the test suites will run and results will show in the Output widget.

---

## Contributing

We welcome contributions to improve the library.

### Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/daily3014/rbx-cryptography.git`
3. Install dependencies if needed
4. Start development server: `bash scripts/dev.sh`

### Guidelines

- **Bug Reports**: Use issues with reproduction steps
- **Feature Requests**: Open an issue to discuss before implementing
- **Pull Requests**: 
  - Follow existing code style
  - Add tests for new features
  - Make sure all tests pass

### Adding New Algorithms

When contributing new cryptographic algorithms:
1. Implement the algorithm in the appropriate module (Hashing, Encryption, etc.)
2. Add tests
4. Add performance benchmarks
5. Submit a pull request

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

## Authors

**daily3014** - Developer - [@daily3014](https://github.com/daily3014)  
**xoifail** - Developer - [@xoifail](https://github.com/xoifaii)

### Acknowledgments

- Thanks to those who gave feedback and testing
- Special thanks to all contributors and bug reporters
- AES was originaly made by @RobloxGamerPro200007

---

## FAQ

### Will you add other algorithms?
Maybe! Depends if its possible in Luau without needing really expensive calculations like RSA.

### How is this library faster?
Through many optimizations including buffer operations, algorithm tuning and Luau specific optimizations.

### Which algorithms should I use?
- **Hashing**: SHA-256 for general use, XXHASH32 for speed, SHA3-256 for latest standards
- **Encryption**: ChaCha20-Poly1305 AEAD for secure communication, AES for compatibility
- **Signatures**: Ed25519 for digital signatures and key exchange

---
