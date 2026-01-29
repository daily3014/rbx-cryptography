# Luau Cryptography

<p align="center">
	<a href="https://xoifaii.github.io/"><img src="https://img.shields.io/badge/Docs-xoifaii.github.io-00d4aa" alt="Docs"></a>
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

## Documentation

[![Docs](https://img.shields.io/badge/Docs-Read%20the%20Docs-00d4aa?logo=readthedocs&logoColor=white)](https://xoifaii.github.io/)

## Installation

### Wally

```toml
[dependencies]
cryptography = "daily3014/cryptography@3.0.1"
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

- [KMAC](https://github.com/daily3014/rbx-cryptography/blob/main/src/Hashing/KMAC.luau): Hash-based Message Authentication Code (uses Keccak)

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

Performance benchmarks conducted in Roblox Studio on AMD Ryzen 5 7600X using Benchmarker by @boatbomber.

### Hashing / Checksum

| Algorithm | Data Size | This Library | HashLib | Alternative | Other Libraries | Improvement |
|-----------|-----------|--------------|---------|-------------|-----------------|-------------|
| SHA-256 | 20k | **271 μs** | 2058 μs | 493 μs (Old Version) | 596 μs (Dekkonot) | **7.6x faster** than HashLib |
| SHA-512 | 20k | **421 μs** | 4348 μs | 1066 μs (Dekkonot) | - | **10.3x faster** than HashLib |
| SHA3-512 | 20k | **826 μs** | 10.60 ms | - | - | **12.8x faster** than HashLib |
| BLAKE3 | 20k | **133 μs** | - | - | - | - |
| HMAC-BLAKE3 | 20k | **145 μs** | - | - | - | - |
| KMAC-128 | 20k | **443 μs** | - | - | - | - |
| KMAC-256 | 20k | **501 μs** | - | - | - | - |
| Adler-32 | 200k | **163 μs** | - | 1.65 ms (Naive Approach) | - | **10.1x faster** |
| CRC32 | 200k | **1.43 ms** | - | 6.26 ms (DevForum) | - | **4.4x faster** |

### Encryption

| Algorithm | Data Size | This Library | Alternative | Other Libraries | Improvement |
|-----------|-----------|--------------|-------------|-----------------|-------------|
| ChaCha20 (Encrypt) | 20k | **177 μs** | 7.87 ms (EncryptedNet) | - | **44.5x faster** |
| ChaCha20 (Roundtrip) | 20k | **338 μs** | ~15 ms (EncryptedNet) | - | **44.4x faster** |
| ChaCha20-Poly1305 (Encrypt) | 20k | **232 μs** | - | - | - |
| ChaCha20-Poly1305 (Roundtrip) | 20k | **448 μs** | - | - | - |
| Simon (Encrypt) | 20k | **239 μs** | - | - | - |
| Simon (Roundtrip) | 20k | **466 μs** | - | - | - |
| Speck (Encrypt) | 20k | **193 μs** | - | - | - |
| Speck (Roundtrip) | 20k | **388 μs** | - | - | - |
| AES-GCM (Encrypt) | 20k | **833 μs** | 1.877 ms (RobloxGamerPro200007 AES256-CTR) | - | **2.3x faster** |
| AES-GCM (Roundtrip) | 20k | **1.5 ms** | - | - | - |
| XOR (Encrypt) | 1 million | **1.10 ms** | ~49.5 ms (Devfourm) | ~171000 ms (daily) | **155,454x faster** |
| XOR (Roundtrip) | 1 million | **2.20 ms** | 98.9 ms (Devfourm) | ~342000 ms (daily) | **155,454x faster** |

### Digital Signatures & Key Exchange

| Algorithm | Operation | Time | Alternative | Improvement |
|-----------|-----------|------|-------------|-------------|
| EdDSA (Roundtrip) | Sign+Verify | **691 μs** | - | - |
| ML-DSA-44 (Roundtrip) | Sign+Verify | **3.65 ms** | - | - |
| ML-KEM-512 (Roundtrip) | Encap+Decap | **754 μs** | - | - |

### Utilities

| Algorithm | Data Size | Time | Alternative | Improvement |
|-----------|-----------|------|-------------|-------------|
| Base64 (Roundtrip) | 1 million | **3.77ms** | Lute: 9.11ms<br>Reselim: 12.08ms | **2.4x faster** than Lute<br>**3.2x faster** than Reselim |

*Roundtrip: Complete encrypt/decrypt or sign/verify cycle*

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

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---

<div align="center">

[DevForum](https://devforum.roblox.com/t/fastest-cryptography-library-for-roblox/3680271) • [Discord](https://discord.gg/Fg3sM8qKPp) • [Docs](https://xoifaii.github.io/) • [Wally](https://wally.run/package/daily3014/cryptography) • [Pesde](https://pesde.dev/packages/daily3014/cryptography)


</div>


