# Luau Cryptography

<p align="center">
	<a href="https://xoifaii.github.io/rbx-crypto-docs/"><img src="https://img.shields.io/badge/Docs-xoifaii.github.io-00d4aa" alt="Docs"></a>
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

## Disclaimer

While this library has extensive testing, it's always recommended that you do your own tests. Keep in mind that there may be timing vulnerabilities that cannot be fixed due to how Luau compiles functions. **This library is NOT intended for exploitation, harassment, illegal activities, or explicit content.** All security issues should be reported in the Discord server.

## Documentation

[![Docs](https://img.shields.io/badge/Docs-Read%20the%20Docs-00d4aa?logo=readthedocs&logoColor=white)](https://xoifaii.github.io/)

## Installation

### Wally

```toml
[dependencies]
cryptography = "daily3014/cryptography@4.0.1"
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

- [Ed25519](https://github.com/daily3014/rbx-cryptography/blob/main/src/Verification/EdDSA): Digital signatures over Curve25519 ([RFC 8032](https://doi.org/10.17487/RFC8032))

**Key Exchange**

- [X25519](https://github.com/daily3014/rbx-cryptography/blob/main/src/Verification/EdDSA/X25519.luau): Elliptic curve Diffie-Hellman over Curve25519

### Post-Quantum Cryptography

**KEM: Key Encapsulation Methods**

- [ML-KEM](https://github.com/daily3014/rbx-cryptography/tree/main/src/Verification/MlKEM): modes 512, 768, 1024 (Kyber-based, NIST standardized)

**Digital Signature Schemes**

- [ML-DSA](https://github.com/daily3014/rbx-cryptography/tree/main/src/Verification/MlDSA): modes 44, 65, 87 (Dilithium-based, [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204))

### Symmetric Cryptography

**Hash Functions**

- **SHA-2 Family**: SHA-224, SHA-256, SHA-384, SHA-512
- **SHA-3 Family**: SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE-128, SHAKE-256 ([FIPS 202](https://doi.org/10.6028/NIST.FIPS.202))
- **BLAKE Family**: [BLAKE3](https://github.com/daily3014/rbx-cryptography/blob/main/src/Hashing/Blake3.luau) (fastest available), BLAKE3-Keyed, BLAKE3-DeriveKey, [BLAKE2b](https://github.com/daily3014/rbx-cryptography/blob/main/src/Hashing/Blake2b.luau)

**Message Authentication**

- [HMAC](https://github.com/daily3014/rbx-cryptography/blob/main/src/Hashing/HMAC.luau): Hash-based Message Authentication Code (works with any hash function)

- [KeyedHMAC](https://github.com/daily3014/rbx-cryptography/blob/main/src/Hashing/KeyedHMAC.luau): HMAC with the key prepared once, for many messages under one key (about twice as fast on short messages with SHA-2's Luau path)

- [KMAC](https://github.com/daily3014/rbx-cryptography/blob/main/src/Hashing/KMAC.luau): Hash-based Message Authentication Code (uses Keccak)

**Authenticated Encryption**

- [ChaCha20-Poly1305](https://github.com/daily3014/rbx-cryptography/blob/main/src/Encryption/AEAD): AEAD construction ([RFC 8439](https://doi.org/10.17487/RFC8439))
- [AES-GCM](https://github.com/daily3014/rbx-cryptography/blob/main/src/Encryption/AES.luau): Galois/Counter Mode

**Stream & Block Ciphers**

- [ChaCha20](https://github.com/daily3014/rbx-cryptography/tree/main/src/Encryption/AEAD): Stream cipher ([RFC 8439](https://doi.org/10.17487/RFC8439))
- [AES-GCM](https://github.com/daily3014/rbx-cryptography/blob/main/src/Encryption/AES.luau): Advanced Encryption Standard

### Utilities

**Encoding & Conversion**

- [Base64](https://github.com/daily3014/rbx-cryptography/blob/main/src/Utilities/Base64.luau): Encode and decode
- [Hexadecimal](https://github.com/daily3014/rbx-cryptography/blob/main/src/Utilities/Conversions.luau): Buffer to/from hex string conversion
- [XOR](https://github.com/daily3014/rbx-cryptography/blob/main/src/Utilities/XOR.luau): Simple additive cipher, useful as a one-time pad

**Random Generation**

- [CSPRNG](https://github.com/daily3014/rbx-cryptography/blob/main/src/Utilities/CSPRNG.luau): Cryptographically Secure Pseudo-Random Number Generator with entropy management
- Random strings and bytes generation

## Performance

Performance benchmarks conducted on a RedMagic 11 Pro in the Roblox mobile client with `tests/RunBench.client.luau` (best of five batches), against the other libraries on the same device and inputs.

### Hashing / Checksum

| Algorithm     | Data Size | This Library | Luau Fallback | HashLib | Gamer   | CryptographyService | Improvement |
| ------------- | --------- | ------------ | ------------- | ------- | ------- | ------------------- | ----------- |
| SHA-256       | 50 KB     | **102 μs** | 135 μs | 777 μs | 4.99 ms | 1.24 ms | **7.6x faster** than HashLib<br>**48.8x faster** than Gamer<br>**12.1x faster** than CryptographyService |
| SHA-512       | 50 KB     | **363 μs** | - | 1.17 ms | - | 1.12 ms | **3.2x faster** than HashLib<br>**3.1x faster** than CryptographyService |
| SHA3-512      | 50 KB     | **468 μs** | - | 2.17 ms | - | 14.87 ms | **4.6x faster** than HashLib<br>**31.8x faster** than CryptographyService |
| BLAKE2b       | 50 KB     | **41 μs** | 191 μs | - | - | 2.38 ms | **58.6x faster** than CryptographyService |
| BLAKE3        | 50 KB     | **21 μs** | 52 μs | - | - | - | - |
| HMAC-SHA256   | 50 KB     | **116 μs** | - | 793 μs | 5.06 ms | 1.25 ms | **6.8x faster** than HashLib<br>**43.5x faster** than Gamer<br>**10.8x faster** than CryptographyService |
| HMAC-BLAKE3   | 50 KB     | **33 μs** | - | - | - | - | - |
| KMAC-128      | 50 KB     | **215 μs** | - | - | - | - | - |
| KMAC-256      | 50 KB     | **261 μs** | - | - | - | - | - |

### Encryption

| Algorithm               | Data Size | This Library | Alternative | Improvement |
| ----------------------- | --------- | ------------ | ----------- | ----------- |
| ChaCha20 (Encrypt)      | 50 KB     | **69 μs** | 586 μs (CryptographyService)<br>145 μs (Orbit) | **8.5x faster** than CryptographyService<br>**2.1x faster** than Orbit |
| AES-256-GCM (Encrypt)   | 50 KB     | **350 μs** | - | - |
| XOR (Encrypt)           | 1 MB      | **406 μs** | 12.71 ms (Gamer) | **31.3x faster** than Gamer |

### Digital Signatures & Key Exchange

| Algorithm  | Operation                                 | Time        | Breakdown                                      |
| ---------- | ----------------------------------------- | ----------- | ---------------------------------------------- |
| EdDSA      | Public Key + Sign + Verify                | **227 μs** | Public Key 28 μs, Sign 39 μs, Verify 160 μs |
| ML-DSA-44  | KeyGen + Sign + Verify                    | **291 μs** | KeyGen 79 μs, Sign 145 μs, Verify 67 μs |
| ML-KEM-512 | KeyGen + Encapsulate + Decapsulate        | **118 μs** | KeyGen 31 μs, Encapsulate 36 μs, Decapsulate 52 μs |

### Utilities

| Algorithm          | Data Size | This Library | Alternative | Improvement |
| ------------------ | --------- | ------------ | ----------- | ----------- |
| Base64 (Roundtrip) | 50 KB     | **68 μs** | HashLib: 4.27 ms<br>Gamer: 2.82 ms | **62.4x faster** than HashLib<br>**41.1x faster** than Gamer |

_Roundtrip: Complete encode/decode cycle_

## Testing

### Running Tests

```bash
luau --codegen -O2 tests/runner.luau
```

To suppress verbose output and run silently:

```bash
luau --codegen -O2 tests/runner.luau -a silent
```

## Contributing

To contribute, fork this repository and make your changes, and then make a Pull Request. A Pull Request needs approval.

Please read the [CONTRIBUTING.md file](CONTRIBUTING.md) for detailed guidelines.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---

<div align="center">

[DevForum](https://devforum.roblox.com/t/fastest-cryptography-library-for-roblox/3680271) • [Discord](https://discord.gg/Fg3sM8qKPp) • [Docs](https://xoifaii.github.io/) • [Wally](https://wally.run/package/daily3014/cryptography) • [Pesde](https://pesde.dev/packages/daily3014/cryptography)

</div>
