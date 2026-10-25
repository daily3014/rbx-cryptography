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

Performance benchmarks conducted in Roblox Studio on AMD Ryzen AI 7 PRO 360 using Benchmarker by @boatbomber.

### Hashing / Checksum

| Algorithm     | Data Size | This Library | Luau Fallback | HashLib | Dekkonot | Improvement                                                |
| ------------- | --------- | ------------ | ------------- | ------- | -------- | ---------------------------------------------------------- |
| SHA-256       | 50 KB     | **121 μs**   | 128 μs        | 933 μs  | 916 μs   | **7.7x faster** than HashLib<br>**7.6x faster** than Dekkonot  |
| SHA-512       | 50 KB     | **453 μs**   | -             | 1.39 ms | 2.32 ms  | **3.1x faster** than HashLib<br>**5.1x faster** than Dekkonot  |
| SHA3-512      | 50 KB     | **554 μs**   | -             | 3.46 ms | -        | **6.2x faster** than HashLib                               |
| BLAKE2b       | 50 KB     | **53 μs**    | 283 μs        | -       | 883 μs   | **16.7x faster** than Dekkonot                             |
| BLAKE3        | 50 KB     | **8 μs**     | 75 μs         | -       | -        | -                                                          |
| HMAC-SHA256   | 50 KB     | **142 μs**   | -             | 947 μs  | -        | **6.7x faster** than HashLib                               |
| HMAC-BLAKE3   | 50 KB     | **26 μs**    | -             | -       | -        | -                                                          |
| KMAC-128      | 50 KB     | **258 μs**   | -             | -       | -        | -                                                          |
| KMAC-256      | 50 KB     | **312 μs**   | -             | -       | -        | -                                                          |

### Encryption

| Algorithm               | Data Size | This Library | Alternative                                                       | Improvement                                                       |
| ----------------------- | --------- | ------------ | ----------------------------------------------------------------- | ----------------------------------------------------------------- |
| ChaCha20 (Encrypt)      | 50 KB     | **76 μs**    | 696 μs (MrRoblick)<br>12.01 ms (EncryptedNet)                     | **9.2x faster** than MrRoblick<br>**158x faster** than EncryptedNet |
| AES-256-GCM (Encrypt)   | 50 KB     | **365 μs**   | 926 μs (RobloxGamerPro200007 AES256-CTR, no authentication)       | **2.5x faster**                                                   |
| XOR (Encrypt)           | 1 MB      | **940 μs**   | -                                                                 | -                                                                 |

### Digital Signatures & Key Exchange

| Algorithm  | Operation                                 | Time        | Breakdown                                      |
| ---------- | ----------------------------------------- | ----------- | ---------------------------------------------- |
| EdDSA      | Public Key + Sign + Verify				 | **369 μs**  | Public Key 43 μs, Sign 58 μs, Verify 266 μs    |
| ML-DSA-44  | KeyGen + Sign + Verify                    | **794 μs**  | KeyGen 237 μs, Sign 413 μs, Verify 102 μs      |
| ML-KEM-512 | KeyGen + Encapsulate + Decapsulate        | **201 μs**  | KeyGen 62 μs, Encapsulate 67 μs, Decapsulate 65 μs |

### Utilities

| Algorithm          | Data Size | This Library | Alternative                                    | Improvement                                                 |
| ------------------ | --------- | ------------ | ---------------------------------------------- | ----------------------------------------------------------- |
| Base64 (Roundtrip) | 50 KB     | **128 μs**   | Reselim: 182 μs<br>Lute: 297 μs                | **1.4x faster** than Reselim<br>**2.3x faster** than Lute   |

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
