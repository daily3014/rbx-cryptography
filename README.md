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

Benchmarks done on an Intel i9-13900K and luau v731\
Algorithms are ran 50 times and measured via the best of N throughput / rate

### Data

Data Size: 1 MB\
Key Size (HMAC, KMAC, Encryption): 32 Bytes\
Nonce/IV Size: 12 Bytes

### Hashing

| Algorithm   | rbx-cryptography | Other Libraries                             | Improvement                                                         |
| ----------- | ---------------- | ------------------------------------------- | ------------------------------------------------------------------- |
| SHA-256     | **234 MB/s**     | 68 MB/s (HashLib)<br>73 MB/s (luau-hashing) | **3.4x faster** than HashLib<br>**3.2x faster** than luau-hashing   |
| SHA-512     | **481 MB/s**     | 35 MB/s (HashLib)<br>25 MB/s (luau-hashing) | **13.7x faster** than HashLib<br>**19.2x faster** than luau-hashing |
| SHA3-512    | **152 MB/s**     | 15 MB/s (HashLib)                           | **10.1x faster** than HashLib                                       |
| BLAKE2B     | **950 MB/s**     | 52 MB/s (luau-hashing)                      | **18.3x faster** than luau-hashing                                  |
| BLAKE3      | **455 MB/s**     | -                                           | -                                                                   |
| HMAC-BLAKE3 | **441 MB/s**     | -                                           | -                                                                   |
| KMAC-128    | **307 MB/s**     | -                                           | -                                                                   |
| KMAC-256    | **253 MB/s**     | -                                           | -                                                                   |

### Password Hashing (Argon2id)

| Tier        | Parameters         | rbx-cryptography   |
| ----------- | ------------------ | ------------------ |
| Interactive | m=8 MiB, t=2, p=1  | **61 op/s - 16ms** |
| Default     | m=19 MiB, t=2, p=1 | **25 op/s - 39ms** |
| Sensitive   | m=64 MiB, t=3, p=1 | **5 op/s - 202ms** |

### Encryption

| Algorithm                   | rbx-cryptography | Other Libraries                           | Improvement       |
| --------------------------- | ---------------- | ----------------------------------------- | ----------------- |
| ChaCha20 (Encrypt)          | **645 MB/s**     | 14 MB/s (EncryptedNet)                    | **46x faster**    |
| ChaCha20-Poly1305 (Encrypt) | **433 MB/s**     | -                                         | -                 |
| AES-GCM (Encrypt)           | **124 MB/s**     | 68 MB/s (RobloxGamerPro200007 AES256-CTR) | **1.8x faster**   |
| XOR (Encrypt)               | **1.4 GB/s**     | 19.7 MB/s (Devforum)                      | **71.07x faster** |

### Digital Signatures & Key Exchange

| Algorithm   | Time                                                                                         | Alternative         | Improvement      |
| ----------- | -------------------------------------------------------------------------------------------- | ------------------- | ---------------- |
| EdDSA       | Roundtrip: **192 μs**<br>Sign: **32 us**<br>Verify: **160us**                                | -                   | -                |
| ML-DSA-87   | Roundtrip: **1.63 ms**<br>KeyGen: **367.5 us**<br>Sign: **831.5 us**<br>Verify: **427.9 us** | 863 ms (WASM-Luau)  | **507x faster**  |
| X25519      | Roundtrip: **465 μs**<br>KeyGen: **280.8 us**<br>Exchange: **184.2 us**                      | 628 μs (ccryptolib) | **1.35x faster** |
| ML-KEM-1024 | Roundtrip: **383 μs**<br>KeyGen: **113.2 us**<br>Encap: **118.6 us**<br>Decap: **151.1 us**  | 122 ms (WASM-Luau)  | **319x faster**  |

### Utilities

| Algorithm            | Time         | Alternative                                             | Improvement                                                                              |
| -------------------- | ------------ | ------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Base64 (Encode)      | **1.5 GB/s** | Lute: 407 MB/s<br>Reselim: 855 MB/s<br>Roblox: 1.3 GB/s | **3.7x faster** than Lute<br>**1.8x faster** than Reselim<br>**1.2x faster** than Roblox |
| Base64 (Decode)      | **1.5 GB/s** | Lute: 562 MB/s<br>Reselim: 882 MB/s<br>Roblox: 2.1 GB/s | **2.7x faster** than Lute<br>**1.7x faster** than Reselim<br>1.4x slower than Roblox     |
| Base64 (Roundtrip)   | **772 MB/s** | Lute: 235 MB/s<br>Reselim: 430 MB/s<br>Roblox: 866 MB/s | **3.3x faster** than Lute<br>**1.8x faster** than Reselim<br>1.1x slower than Roblox     |
| CSPRNG (RandomBytes) | **513 MB/s** | -                                                       | -                                                                                        |

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
