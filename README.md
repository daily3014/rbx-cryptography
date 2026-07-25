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
cryptography = "daily3014/cryptography@4.0.0"
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

- [Ed25519](./src/Verification/EdDSA) signatures with masked operations for side-channel protection

**Key Exchange**

- [X25519](./src/Verification/EdDSA/X25519.luau): Elliptic curve Diffie-Hellman over Curve25519

### Post-Quantum Cryptography

**KEM: Key Encapsulation Methods**

- [ML-KEM](./src/Verification/MlKEM): modes 512, 768, 1024 (Kyber-based, NIST standardized)

**Digital Signature Schemes**

- [ML-DSA](./src/Verification/MlDSA): modes 44, 65, 87 (Dilithium-based, [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204))

### Symmetric Cryptography

**Hash Functions**

- **SHA-2 Family**: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 with optional salt support
- **SHA-3 Family**: SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE-128, SHAKE-256 ([FIPS 202](https://doi.org/10.6028/NIST.FIPS.202))
- **BLAKE Family**: [BLAKE3](./src/Hashing/Blake3.luau) (fastest available), BLAKE3-Keyed, BLAKE3-DeriveKey, [BLAKE2b](./src/Hashing/Blake2b.luau)

**Password Hashing**

- [Argon2id](./src/Hashing/Argon2id.luau): Memory-hard password hashing function ([RFC 9106](https://doi.org/10.17487/RFC9106)).

**Message Authentication**

- [HMAC](./src/Hashing/HMAC.luau): Hash-based Message Authentication Code (works with any hash function)

- [KMAC](./src/Hashing/KMAC.luau): Hash-based Message Authentication Code (uses Keccak)

**Authenticated Encryption**

- [ChaCha20-Poly1305](./src/Encryption/AEAD): AEAD construction ([RFC 8439](https://doi.org/10.17487/RFC8439))
- [AES-GCM](./src/Encryption/AES.luau): Galois/Counter Mode

**Stream & Block Ciphers**

- [ChaCha20](./src/Encryption/AEAD/ChaCha.luau): Stream cipher ([RFC 8439](https://doi.org/10.17487/RFC8439))
- [AES-GCM](./src/Encryption/AES.luau): Advanced Encryption Standard
- [XOR](./src/Encryption/XOR.luau): Simple additive cipher

### Utilities

**Encoding & Conversion**

- [Base64](./src/Utilities/Base64.luau): Encode and decode
- [Hexadecimal](./src/Utilities/Conversions.luau): Buffer to/from hex string conversion

**Random Generation**

- [CSPRNG](./src/Utilities/CSPRNG.luau): Cryptographically Secure Pseudo-Random Number Generator with entropy management
- Random strings and bytes generation

## Performance

Benchmarks done on an Intel i9-13900K and luau v731

### Data

Data Size: 1 MB\
Key Size (HMAC, KMAC, Encryption): 32 Bytes\
Nonce/IV Size: 12 Bytes

### Hashing

| Algorithm   | rbx-cryptography | Other Libraries                               | Improvement                                                       |
| ----------- | ---------------- | --------------------------------------------- | ----------------------------------------------------------------- |
| SHA-256     | **200.7 MB/s**   | 67.1 MB/s (HashLib)<br>72 MB/s (luau-hashing) | **3x faster** than HashLib<br>**2.8x faster** than luau-hashing   |
| SHA-512     | **438 MB/s**     | 33 MB/s (HashLib)<br>24.2 MB/s (luau-hashing) | **13.3x faster** than HashLib<br>**18x faster** than luau-hashing |
| SHA3-512    | **180 MB/s**     | 14.82 MB/s (HashLib)                          | **12.1x faster** than HashLib                                     |
| BLAKE2B     | **703 MB/s**     | 52 MB/s (luau-hashing)                        | **13.5x faster** than luau-hashing                                |
| BLAKE3      | **336.2 MB/s**   | -                                             | -                                                                 |
| HMAC-BLAKE3 | **314.2 MB/s**   | -                                             | -                                                                 |
| KMAC-128    | **343.1 MB/s**   | -                                             | -                                                                 |
| KMAC-256    | **293.4 MB/s**   | -                                             | -                                                                 |

### Password Hashing (Argon2id)

| Tier        | Parameters         | rbx-cryptography |
| ----------- | ------------------ | ---------------- |
| Interactive | m=8 MiB, t=2, p=1  | **17.3 MB/s**    |
| Default     | m=19 MiB, t=2, p=1 | **12.5 MB/s**    |
| Sensitive   | m=64 MiB, t=3, p=1 | **4.25 MB/s**    |

### Encryption

| Algorithm                   | rbx-cryptography | Other Libraries                             | Improvement       |
| --------------------------- | ---------------- | ------------------------------------------- | ----------------- |
| ChaCha20 (Encrypt)          | **510 MB/s**     | 12 MB/s (EncryptedNet)                      | **45x faster**    |
| ChaCha20-Poly1305 (Encrypt) | **338 MB/s**     | -                                           | -                 |
| AES-GCM (Encrypt)           | **74 MB/s**      | 61.8 MB/s (RobloxGamerPro200007 AES256-CTR) | **1.2x faster**   |
| XOR (Encrypt)               | **1.4 GB/s**     | 19.7 MB/s ms (Devforum)                     | **71.07x faster** |

### Digital Signatures & Key Exchange

| Algorithm               | Time        | Alternative         | Improvement      |
| ----------------------- | ----------- | ------------------- | ---------------- |
| EdDSA (Roundtrip)       | **298 μs**  | -                   | -                |
| ML-DSA-87 (Roundtrip)   | **1.13 ms** | 863 ms (WASM-Luau)  | **761x faster**  |
| X25519 (Exchange)       | **466 μs**  | 628 μs (ccryptolib) | **1.35x faster** |
| ML-KEM-1024 (Roundtrip) | **299 μs**  | 122 ms (WASM-Luau)  | **408x faster**  |

### Utilities

| Algorithm          | Time         | Alternative                         | Improvement                                               |
| ------------------ | ------------ | ----------------------------------- | --------------------------------------------------------- |
| Base64 (Roundtrip) | **600 MB/s** | Lute: 193 MB/s<br>Reselim: 146 MB/s | **3.0x faster** than Lute<br>**4.0x faster** than Reselim |

\*Roundtrip: Complete encrypt/decrypt or sign/verify cycle

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
