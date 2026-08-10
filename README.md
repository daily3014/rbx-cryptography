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

- [Ed25519](./src/Verification/EdDSA): Digital signatures over Curve25519 ([RFC 8032](https://doi.org/10.17487/RFC8032))

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

| Algorithm   | rbx-cryptography | Alternative                                                         | Improvement                                                                                             |
| ----------- | ---------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| SHA-256     | **230 MB/s**     | 69 MB/s (HashLib)<br>61 MB/s (ccryptolib)<br>73 MB/s (luau-hashing) | **3.3x faster** than HashLib<br>**3.7x faster** than ccryptolib<br>**3.1x faster** than luau-hashing    |
| SHA-512     | **457 MB/s**     | 34 MB/s (HashLib)<br>34 MB/s (ccryptolib)<br>25 MB/s (luau-hashing) | **13.3x faster** than HashLib<br>**13.3x faster** than ccryptolib<br>**18.5x faster** than luau-hashing |
| SHA3-512    | **207 MB/s**     | 15 MB/s (HashLib)                                                   | **13.5x faster** than HashLib                                                                           |
| BLAKE2B     | **1.1 GB/s**     | 53 MB/s (luau-hashing)                                              | **20.6x faster** than luau-hashing                                                                      |
| BLAKE3      | **464 MB/s**     | 120 MB/s (ccryptolib)                                               | **3.9x faster** than ccryptolib                                                                         |
| HMAC-BLAKE3 | **456 MB/s**     | -                                                                   | -                                                                                                       |
| KMAC-128    | **440 MB/s**     | -                                                                   | -                                                                                                       |
| KMAC-256    | **371 MB/s**     | -                                                                   | -                                                                                                       |

### Password Hashing (Argon2id)

| Tier        | Parameters         | rbx-cryptography        |
| ----------- | ------------------ | ----------------------- |
| Interactive | m=8 MiB, t=2, p=1  | **62 op/s - 16.151 ms** |
| Default     | m=19 MiB, t=2, p=1 | **25 op/s - 39.541 ms** |
| Sensitive   | m=64 MiB, t=3, p=1 | **5 op/s - 201.526 ms** |

### Encryption

| Algorithm                   | rbx-cryptography | Alternative                                    | Improvement                                                           |
| --------------------------- | ---------------- | ---------------------------------------------- | --------------------------------------------------------------------- |
| ChaCha20 (Encrypt)          | **735 MB/s**     | 14 MB/s (EncryptedNet)<br>91 MB/s (ccryptolib) | **51.8x faster** than EncryptedNet<br>**8.1x faster** than ccryptolib |
| ChaCha20-Poly1305 (Encrypt) | **506 MB/s**     | 64 MB/s (ccryptolib)                           | **7.9x faster** than ccryptolib                                       |
| AES-GCM (Encrypt)           | **128 MB/s**     | 69 MB/s (RobloxGamerPro200007 AES256-CTR)      | **1.8x faster** than RobloxGamerPro200007 AES256-CTR                  |
| XOR (Encrypt)               | -                | -                                              | -                                                                     |

### Digital Signatures & Key Exchange

| Algorithm   | Time                                                                                          | Alternative           | Improvement       |
| ----------- | --------------------------------------------------------------------------------------------- | --------------------- | ----------------- |
| EdDSA       | Roundtrip: **183.3 us**<br>Sign: **28.9 us**<br>Verify: **154.4 us**                          | 645.0 us (ccryptolib) | **3.5x faster**   |
| ML-DSA-87   | Roundtrip: **1.703 ms**<br>Sign: **1.004 ms**<br>KeyGen: **321.1 us**<br>Verify: **378.1 us** | 470.382 ms (WASM)     | **276.2x faster** |
| X25519      | Roundtrip: **646.6 us**<br>Exchange: **322.7 us**<br>KeyGen: **323.9 us**                     | 1.233 ms (ccryptolib) | **1.9x faster**   |
| ML-KEM-1024 | Roundtrip: **358.2 us**<br>KeyGen: **104.4 us**<br>Decap: **143.2 us**<br>Encap: **110.6 us** | 80.517 ms (WASM)      | **224.8x faster** |

### Utilities

| Algorithm            | rbx-cryptography | Alternative                                                                     | Improvement                                                                                                               |
| -------------------- | ---------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Base64 (Encode)      | **1.5 GB/s**     | 36 MB/s (HashLib)<br>407 MB/s (Lute)<br>849 MB/s (Reselim)<br>1.1 GB/s (Roblox) | **39.9x faster** than HashLib<br>**3.6x faster** than Lute<br>**1.7x faster** than Reselim<br>**1.3x faster** than Roblox |
| Base64 (Decode)      | **1.9 GB/s**     | 568 MB/s (Lute)<br>887 MB/s (Reselim)<br>1.8 GB/s (Roblox)                      | **3.3x faster** than Lute<br>**2.1x faster** than Reselim<br>**1.1x faster** than Roblox                                  |
| Base64 (Roundtrip)   | **872 MB/s**     | 19 MB/s (HashLib)<br>237 MB/s (Lute)<br>434 MB/s (Reselim)<br>684 MB/s (Roblox) | **44.9x faster** than HashLib<br>**3.7x faster** than Lute<br>**2.0x faster** than Reselim<br>**1.3x faster** than Roblox |
| CSPRNG (RandomBytes) | **616 MB/s**     | 287 MB/s (math.random¹)                                                         | **2.1x faster** than math.random                                                                                          |

¹ Unlike CSPRNG, math.random is not suitable for cryptographic use. Finding the seed for a specific sequence of numbers is a trivial task for modern GPUs and CPUs.

\* Generated automatically via the benchmark script at bench/bencher.luau.\
\* Roundtrip: Complete encrypt/decrypt or sign/verify cycle

## Testing and Benchmarking

### Running Tests

```bash
luau --codegen -O2 tests/runner.luau
```

To suppress verbose output and run silently:

```bash
luau --codegen -O2 tests/runner.luau -a silent
```

### Running Benchmarks

```bash
luau --codegen -O2 bench/runner.luau [-a <iterations> <skip_libraries> <baseline>]
```

Arguments

1. iterations (optional, default: 100): Number of benchmark iterations to run.
2. skip_libraries (optional): Comma separated list of libraries to ignore.
3. baseline (optional, default: rbx-cryptography): The primary library to measure all other implementations against.

Example: Run 200 iterations, skipping WASM and HashLib, while benchmarking against ccryptolib as the baseline:

```bash
luau --codegen -O2 bench/runner.luau -a 200 WASM,HashLib ccryptolib
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
