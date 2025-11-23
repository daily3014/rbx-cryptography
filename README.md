# Luau Cryptography

<p align="center">
  <a href="https://discord.gg/Fg3sM8qKPp"><img src="https://img.shields.io/badge/Discord-Join%20Server-5865F2?logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://wally.run/package/daily3014/cryptography"><img src="https://img.shields.io/badge/Wally-Package-orange" alt="Wally"></a>
  <a href="https://pesde.dev/packages/daily3014/cryptography"><img src="https://img.shields.io/badge/Pesde-Package-blue" alt="Pesde"></a>
</p>

**Luau Cryptography** is a library of cryptographic algorithims written in Luau. It supports Post-Quantum (PQ), Elliptic Curve Cryptography (ECC), authenticated encryption and CSPRNG with many utilities.

## Authors

**daily3014** - Developer - [@daily3014](https://github.com/daily3014)  
**Xoifail** - Developer - [@xoifail](https://github.com/xoifaii)

### Acknowledgments

- Thanks to those who gave feedback and testing
- Special thanks to all contributors and bug reporters
- AES was originally made by @RobloxGamerPro200007
- XChaCha20 was originally made by @littleBitsman
- Murmur3 hash was originally made by @kohltastrophe

## Disclaimer

While this library has extensive testing, it's always recommended that you do your own tests. Keep in mind that there may be timing vulnerabilities that cannot be fixed due to how Luau compiles functions. **This library is NOT intended for exploitation, harassment, illegal activities, or explicit content.** All security issues should be reported in the Discord server.

## Installation

### Wally

```toml
[dependencies]
cryptography = "daily3014/cryptography@2.6.2"
```

### Pesde

```yaml
pesde add daily3014/cryptography
```

### Manual Installation

Download the latest release from GitHub and place it in your Roblox Studio project.

## List of Algorithms

### Elliptic Curve Cryptography

**Digital Signature Schemes**

- [Ed25519](https://github.com/daily3014/rbx-cryptography/blob/main/src/Verification/EdDSA) signatures with masked operations for side-channel protection

**Key Exchange**

- [X25519](https://github.com/daily3014/rbx-cryptography/blob/main/src/Verification/EdDSA/X25519.luau): Elliptic curve Diffie-Hellman over Curve25519

### Post-Quantum Cryptography

**KEM: Key Encapsulation Methods**

- [ML-KEM](https://github.com/daily3014/rbx-cryptography/tree/main/src/Verification/MlKEM): modes 512, 768, 1024 (Kyber-based, NIST standardized)

**Digital Signature Schemes**

- [ML-DSA](https://github.com/daily3014/rbx-cryptography/tree/main/src/Verification/MlDSA): modes 44, 65, 87 (Dilithium-based, [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204))

### Symmetric Cryptography

**Hash Functions**

- **SHA-2 Family**: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 with optional salt support
- **SHA-3 Family**: SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE-128, SHAKE-256 ([FIPS 202](https://doi.org/10.6028/NIST.FIPS.202))
- **BLAKE Family**: [BLAKE3](https://github.com/daily3014/rbx-cryptography/blob/main/src/Hashing/Blake3.luau) (fastest available), BLAKE3-Keyed, BLAKE3-DeriveKey, [BLAKE2b](https://github.com/daily3014/rbx-cryptography/blob/main/src/Hashing/Blake2b.luau)

**Non-cryptographic Hash Functions**

- [XXH32](https://github.com/daily3014/rbx-cryptography/blob/main/src/Hashing/XXH32.luau): Ultra-fast non-cryptographic hash
- [Murmur3](https://github.com/daily3014/rbx-cryptography/blob/main/src/Hashing/Murmur.luau): Fast non-cryptographic hash

**Message Authentication**

- [HMAC](https://github.com/daily3014/rbx-cryptography/blob/main/src/Hashing/HMAC.luau): Hash-based Message Authentication Code (works with any hash function)

**Authenticated Encryption**

- [ChaCha20-Poly1305](https://github.com/daily3014/rbx-cryptography/blob/main/src/Encryption/AEAD): AEAD construction ([RFC 8439](https://doi.org/10.17487/RFC8439))
- [AES-GCM](https://github.com/daily3014/rbx-cryptography/blob/main/src/Encryption/AES.luau): Galois/Counter Mode

**Stream & Block Ciphers**

- [ChaCha20](https://github.com/daily3014/rbx-cryptography/tree/main/src/Encryption/AEAD): Stream cipher ([RFC 8439](https://doi.org/10.17487/RFC8439))
- [AES-GCM](https://github.com/daily3014/rbx-cryptography/blob/main/src/Encryption/AES.luau): Advanced Encryption Standard
- [Simon](https://github.com/daily3014/rbx-cryptography/blob/main/src/Encryption/Simon.luau): Lightweight block cipher
- [Speck](https://github.com/daily3014/rbx-cryptography/blob/main/src/Encryption/Speck.luau): Lightweight block cipher
- [XOR](https://github.com/daily3014/rbx-cryptography/blob/main/src/Encryption/XOR.luau): Simple additive cipher

**Checksums**

- [CRC32](https://github.com/daily3014/rbx-cryptography/blob/main/src/Checksums/CRC32.luau): Cyclic Redundancy Check (JAM/ISO modes)
- [Adler-32](https://github.com/daily3014/rbx-cryptography/blob/main/src/Checksums/Adler.luau): Checksum algorithm

### Utilities

**Encoding & Conversion**

- [Base64](https://github.com/daily3014/rbx-cryptography/blob/main/src/Utilities/Base64.luau): Encode and decode
- [Hexadecimal](https://github.com/daily3014/rbx-cryptography/blob/main/src/Utilities/Conversions.luau): Buffer to/from hex string conversion

**Random Generation**

- [CSPRNG](https://github.com/daily3014/rbx-cryptography/blob/main/src/Utilities/CSPRNG): Cryptographically Secure Pseudo-Random Number Generator with entropy management
- Random strings and bytes generation

## Performance

Performance benchmarks conducted in Roblox Studio on Intel Core i7-12700 using Benchmarker by @boatbomber.

### Hashing / Checksum

| Algorithm | Data Size | This Library | HashLib | Alternative | Other Libraries | Improvement |
|-----------|-----------|--------------|---------|-------------|-----------------|-------------|
| SHA-256 | 20k | **370 μs** | 2058 μs | 493 μs (Old Version) | 596 μs (Dekkonot) | **5.5x faster** than HashLib |
| SHA-512 | 20k | **766 μs** | 4348 μs | 1066 μs (Dekkonot) | - | **5.7x faster** than HashLib |
| SHA3-512 | 20k | **1.0 ms** | 10.60 ms | - | - | **10.6x faster** than HashLib |
| BLAKE3 | 20k | **168 μs** | - | - | - | - |
| HMAC-BLAKE3 | 20k | **165 μs** | - | - | - | - |
| Adler-32 | 200k | **190 μs** | - | 1.65 ms (Naive Approach) | - | **8.7x faster** |
| CRC32 | 200k | **2.01 ms** | - | 6.26 ms (DevForum) | - | **3.1x faster** |

### Encryption

| Algorithm | Data Size | This Library | Alternative | Other Libraries | Improvement |
|-----------|-----------|--------------|-------------|-----------------|-------------|
| ChaCha20 (Encrypt) | 20k | **266 μs** | 7.87 ms (EncryptedNet) | - | **29.6x faster** |
| ChaCha20 (Roundtrip) | 20k | **538 μs** | ~15 ms (EncryptedNet) | - | **27.9x faster** |
| ChaCha20-Poly1305 (Encrypt) | 20k | **310 μs** | - | - | - |
| ChaCha20-Poly1305 (Roundtrip) | 20k | **642 μs** | - | - | - |
| Simon (Encrypt) | 20k | **395 μs** | - | - | - |
| Simon (Roundtrip) | 20k | **790 μs** | - | - | - |
| Speck (Encrypt) | 20k | **350 μs** | - | - | - |
| Speck (Roundtrip) | 20k | **700 μs** | - | - | - |
| AES-GCM (Encrypt) | 20k | **11.41 ms** | - | - | - |
| AES-GCM (Roundtrip) | 20k | **21.88 ms** | - | - | - |
| XOR (Encrypt) | 1 million | **1.10 ms** | ~49.5 ms (@TwiistedRoyalty) | 4000 ms (daily) | **64.3x faster** |
| XOR (Roundtrip) | 1 million | **2.20 ms** | 98.9 ms (@TwiistedRoyalty) | ~8000 ms (daily) | **64.3x faster** |

### Digital Signatures & Key Exchange

| Algorithm | Operation | Time | Alternative | Improvement |
|-----------|-----------|------|-------------|-------------|
| EdDSA (Roundtrip) | Sign+Verify | **1.4 ms** | - | - |
| ML-DSA-44 (Roundtrip) | Sign+Verify | **9.1 ms** | - | - |
| ML-KEM-512 (Roundtrip) | Encap+Decap | **1.02 ms** | - | - |

### Utilities
| Algorithm | Data Size | Time | Alternative | Improvement |
|-----------|-----------|------|-------------|-------------|
| Base64 (Encode/Decode) | 1 million | **4.62ms** | Lute: 9.11ms<br>Reselim: 12.08ms | **2.0x faster** than Lute<br>**2.6x faster** than Reselim |

*Roundtrip: Complete encrypt/decrypt or sign/verify cycle*

## API Reference

### Hashing Functions

**SHA-2 Family:**
```lua
Hashing.SHA2.SHA224(Message: buffer, Salt?: buffer) -> string
Hashing.SHA2.SHA256(Message: buffer, Salt?: buffer) -> string
Hashing.SHA2.SHA384(Message: buffer, Salt?: buffer) -> string
Hashing.SHA2.SHA512(Message: buffer, Salt?: buffer) -> string
```

**SHA-3 Family:**
```lua
Hashing.SHA3.SHA3_224(Message: buffer) -> string
Hashing.SHA3.SHA3_256(Message: buffer) -> string
Hashing.SHA3.SHA3_384(Message: buffer) -> string
Hashing.SHA3.SHA3_512(Message: buffer) -> string

Hashing.SHA3.SHAKE_128(Message: buffer) -> string
Hashing.SHA3.SHAKE_256(Message: buffer) -> string
```

**BLAKE Family:**
```lua
Hashing.Blake3.Digest(Message: buffer, Length?: number) -> string
Hashing.Blake3.DigestKeyed(Key: buffer, Message: buffer, Length?: number) -> string
Hashing.Blake3.DeriveKey(Context: buffer): (buffer, number?) -> (string, buffer)

Hashing.Blake2b(InputData: buffer, OutputLength: number?, KeyData: buffer?) -> string
```

**Authentication:**
```lua
Hashing.HMAC(Message: buffer, Key: buffer, HashFn: function, BlockSize: number) -> string
```

**Non-Cryptographic Hashing:**
```lua
Hashing.XXH32(Message: buffer, Seed?: number) -> number
Hashing.MurMur(Message: buffer, Seed: number?) -> number
```

### Encryption Functions

**Stream Cipher:**
```lua
Encryption.AEAD.ChaCha20(Data: buffer, Key: buffer, Nonce: buffer, Counter?: number, Rounds?: number) -> buffer
Encryption.AEAD.XChaCha20(Data: buffer, Key: buffer, Nonce: buffer, Counter: number?, Rounds: number?) -> buffer
```

**Authenticated Encryption:**
```lua
Encryption.AEAD.Encrypt(Message: buffer, Key: buffer, Nonce: buffer, AAD?: buffer, Rounds?: number, UseXChaCha20: boolean?) -> (buffer, buffer)
Encryption.AEAD.Decrypt(Ciphertext: buffer, Key: buffer, Nonce: buffer, Tag: buffer, AAD?: buffer, Rounds?: number, UseXChaCha20: boolean?) -> buffer?
```

**Block Ciphers:**
```lua
-- AES-GCM
AES.Encrypt(Key: buffer, IV: buffer, Plaintext: buffer, AAD: buffer?) -> (buffer, buffer)
AES.Decrypt(Key: buffer, IV: buffer, Ciphertext: buffer, Tag: buffer, AAD: buffer?) -> (boolean, buffer?)

-- Simon
Encryption.Simon.Encrypt(PlaintextBuffer: buffer, KeyBuffer: buffer) -> buffer
Encryption.Simon.Decrypt(CipherBuffer: buffer, KeyBuffer: buffer) -> buffer

-- Speck
Encryption.Speck.Encrypt(PlaintextBuffer: buffer, KeyBuffer: buffer) -> buffer
Encryption.Speck.Decrypt(CipherBuffer: buffer, KeyBuffer: buffer) -> buffer
```

**Simple Cipher:**
```lua
Encryption.XOR(Data: buffer, Key: buffer) -> buffer
```

### Digital Signatures

**EdDSA (Ed25519):**
```lua
Verification.EdDSA.PublicKey(SecretKey: buffer) -> buffer
Verification.EdDSA.Sign(SecretKey: buffer, PublicKey: buffer, Message: buffer) -> buffer
Verification.EdDSA.Verify(PublicKey: buffer, Message: buffer, Signature: buffer) -> boolean
```

**Masked X25519:**
```lua
Verification.EdDSA.X25519.Mask(SecretKey: buffer) -> buffer
Verification.EdDSA.X25519.MaskSignature(SignatureSecretKey: buffer) -> buffer
Verification.EdDSA.X25519.Remask(MaskedKey: buffer) -> buffer
Verification.EdDSA.X25519.PublicKey(MaskedKey: buffer) -> buffer
Verification.EdDSA.X25519.Exchange(MaskedSecretKey: buffer, TheirPublicKey: buffer) -> (buffer, buffer)
Verification.EdDSA.X25519.MaskComponent(MaskedKey: buffer) -> buffer
```

**ML-DSA (Post-Quantum):**
```lua
Mldsa.ML_DSA_44.GenerateKeys() -> (PublicKey: buffer, SecretKey: buffer)
Mldsa.ML_DSA_44.Sign(RandomSeed: buffer, SecretKey: buffer, Message: buffer, Context: buffer, Signature: buffer) -> boolean
Mldsa.ML_DSA_44.Verify(PublicKey: buffer, Message: buffer, Context: buffer, Signature: buffer) -> boolean

Mldsa.ML_DSA_65.GenerateKeys() -> (PublicKey: buffer, SecretKey: buffer)
Mldsa.ML_DSA_65.Sign(RandomSeed: buffer, SecretKey: buffer, Message: buffer, Context: buffer, Signature: buffer) -> boolean
Mldsa.ML_DSA_65.Verify(PublicKey: buffer, Message: buffer, Context: buffer, Signature: buffer) -> boolean

Mldsa.ML_DSA_87.GenerateKeys() -> (PublicKey: buffer, SecretKey: buffer)
Mldsa.ML_DSA_87.Sign(RandomSeed: buffer, SecretKey: buffer, Message: buffer, Context: buffer, Signature: buffer) -> boolean
Mldsa.ML_DSA_87.Verify(PublicKey: buffer, Message: buffer, Context: buffer, Signature: buffer) -> boolean
```

### Key Encapsulation

**ML-KEM (Post-Quantum):**
```lua
MlKem.MLKEM_512.GenerateKeys() -> (PublicKey: buffer, SecretKey: buffer)
MlKem.MLKEM_512.KeyGen(D: buffer, Z: buffer) -> (PublicKey: buffer, SecretKey: buffer)
MlKem.MLKEM_512.Encapsulate(PublicKey: buffer, Message: buffer) -> (Ciphertext: buffer?, SharedSecret: buffer?)
MlKem.MLKEM_512.Decapsulate(SecretKey: buffer, Ciphertext: buffer) -> SharedSecret: buffer

MlKem.MLKEM_768.GenerateKeys() -> (PublicKey: buffer, SecretKey: buffer)
MlKem.MLKEM_768.KeyGen(D: buffer, Z: buffer) -> (PublicKey: buffer, SecretKey: buffer)
MlKem.MLKEM_768.Encapsulate(PublicKey: buffer, Message: buffer) -> (Ciphertext: buffer?, SharedSecret: buffer?)
MlKem.MLKEM_768.Decapsulate(SecretKey: buffer, Ciphertext: buffer) -> SharedSecret: buffer

MlKem.MLKEM_1024.GenerateKeys() -> (PublicKey: buffer, SecretKey: buffer)
MlKem.MLKEM_1024.KeyGen(D: buffer, Z: buffer) -> (PublicKey: buffer, SecretKey: buffer)
MlKem.MLKEM_1024.Encapsulate(PublicKey: buffer, Message: buffer) -> (Ciphertext: buffer?, SharedSecret: buffer?)
MlKem.MLKEM_1024.Decapsulate(SecretKey: buffer, Ciphertext: buffer) -> SharedSecret: buffer
```

### Utility Functions

**Encoding:**
```lua
Utilities.Base64.Encode(Input: buffer) -> buffer
Utilities.Base64.Decode(Input: buffer) -> buffer
```

**Conversions:**
```lua
Utilities.Conversions.ToHex(Buffer: buffer) -> string
Utilities.Conversions.FromHex(Hex: string) -> buffer
```

**Random Generation:**
```lua
Utilities.RandomString(Length: number) -> string
```

**CSPRNG:**
```lua
Utilities.CSPRNG.Random() -> number
Utilities.CSPRNG.RandomInt(Min: number, Max: number?) -> number
Utilities.CSPRNG.RandomNumber(Min: number, Max: number?) -> number
Utilities.CSPRNG.RandomBytes(Count: number) -> buffer
Utilities.CSPRNG.RandomHex(Length: number) -> string
Utilities.CSPRNG.RandomString(Length: number, AsBuffer: boolean?) -> buffer | string
Utilities.CSPRNG.Ed25519ClampedBytes(Input: buffer) -> buffer
Utilities.CSPRNG.Ed25519Random() -> buffer
Utilities.CSPRNG.Reseed(CustomEntropy: buffer?)
Utilities.CSPRNG.AddEntropyProvider(ProviderFunction: () -> buffer?)
Utilities.CSPRNG.RemoveEntropyProvider(ProviderFunction: () -> buffer?)
```

### Checksum Functions

```lua
Checksums.CRC32(Message: buffer, Mode: "Jam" | "Iso"?, Hex: boolean?) -> number
Checksums.Adler(Message: buffer) -> number
```

## Testing and Benchmarking

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

## Contributing

To contribute, fork this repository and make your changes, and then make a Pull Request. A Pull Request needs approval.

Please read the [CONTRIBUTING.md file](CONTRIBUTING.md) for detailed guidelines.

## FAQ

### Will you add other algorithms?

Maybe! It depends on whether the algorithm is feasible to implement in Luau without requiring extremely expensive calculations like RSA/Argon.

### How is this library faster?

Through extensive optimizations including efficient buffer operations, algorithm tuning, and Luau-specific optimizations.

### Which algorithms should I use?

- **Hashing**: SHA-256 for general use, XXH32 for speed, BLAKE3 for speed and security, SHA3-256 for latest standards
- **Encryption**: ChaCha20-Poly1305 AEAD for authenticated encryption, AES-GCM for compatibility and security
- **Signatures**: Ed25519 for fast digital signatures and key exchange, ML-DSA for post-quantum security
- **Key Exchange**: ML-KEM for post-quantum key encapsulation, X25519 for compatibility

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---

<div align="center">

[DevForum](https://devforum.roblox.com/t/fastest-cryptography-library-for-roblox/3680271) • [Discord](https://discord.gg/Fg3sM8qKPp) • [Wally](https://wally.run/package/daily3014/cryptography) • [Pesde](https://pesde.dev/packages/daily3014/cryptography)

</div>