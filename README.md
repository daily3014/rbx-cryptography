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

### Utilities

**Encoding & Conversion**

- [Base64](./src/Utilities/Base64.luau): Encode and decode
- [Hexadecimal](./src/Utilities/Conversions.luau): Buffer to/from hex string conversion
- [XOR](./src/Utilities/XOR.luau): Simple additive cipher, useful as a one-time pad

**Random Generation**

- [CSPRNG](./src/Utilities/CSPRNG.luau): Cryptographically Secure Pseudo-Random Number Generator with entropy management
- Random strings and bytes generation

## Performance

Benchmarks done on an Intel i9-13900K and Luau v735\
Algorithms are ran 1000 times and measured via P0 throughput/rate

### Data

Data Size: 1 MB\
Key Size (HMAC, KMAC, Encryption): 32 Bytes\
Nonce/IV Size: 12 Bytes
Output Size: 64 Bytes

### Hashing

| Algorithm   | rbx-cryptography | Alternative                                                         | Improvement                                                                                             |
| ----------- | ---------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| SHA-256     | **239 MB/s**     | 71 MB/s (HashLib)<br>61 MB/s (ccryptolib)<br>74 MB/s (luau-hashing) | **3.4x faster** than HashLib<br>**3.9x faster** than ccryptolib<br>**3.2x faster** than luau-hashing    |
| SHA-512     | **515 MB/s**     | 36 MB/s (HashLib)<br>36 MB/s (ccryptolib)<br>25 MB/s (luau-hashing) | **14.4x faster** than HashLib<br>**14.3x faster** than ccryptolib<br>**20.4x faster** than luau-hashing |
| SHA3-512    | **210 MB/s**     | 16 MB/s (HashLib)                                                   | **13.5x faster** than HashLib                                                                           |
| BLAKE2B     | **1.1 GB/s**     | 56 MB/s (luau-hashing)                                              | **20.3x faster** than luau-hashing                                                                      |
| BLAKE3      | **489 MB/s**     | 125 MB/s (ccryptolib)                                               | **3.9x faster** than ccryptolib                                                                         |
| HMAC-BLAKE3 | **457 MB/s**     | -                                                                   | -                                                                                                       |
| KMAC-128    | **460 MB/s**     | -                                                                   | -                                                                                                       |
| KMAC-256    | **377 MB/s**     | -                                                                   | -                                                                                                       |

### Password Hashing (Argon2id)

| Tier        | Parameters         | rbx-cryptography        |
| ----------- | ------------------ | ----------------------- |
| Interactive | m=8 MiB, t=2, p=1  | **55 op/s - 18.318 ms** |
| Default     | m=19 MiB, t=2, p=1 | **17 op/s - 57.383 ms** |
| Sensitive   | m=64 MiB, t=3, p=1 | **4 op/s - 237.737 ms** |

### Encryption

| Algorithm                   | rbx-cryptography | Alternative                                    | Improvement                                                           |
| --------------------------- | ---------------- | ---------------------------------------------- | --------------------------------------------------------------------- |
| ChaCha20 (Encrypt)          | **774 MB/s**     | 14 MB/s (EncryptedNet)<br>96 MB/s (ccryptolib) | **53.4x faster** than EncryptedNet<br>**8.1x faster** than ccryptolib |
| ChaCha20-Poly1305 (Encrypt) | **511 MB/s**     | 67 MB/s (ccryptolib)                           | **7.6x faster** than ccryptolib                                       |
| AES-GCM (Encrypt)           | **145 MB/s**     | 73 MB/s (RobloxGamerPro200007 AES256-CTR)      | **2.0x faster** than RobloxGamerPro200007 AES256-CTR                  |

### Digital Signatures & Key Exchange

| Algorithm   | Time                                                                                          | Alternative           | Improvement       |
| ----------- | --------------------------------------------------------------------------------------------- | --------------------- | ----------------- |
| EdDSA       | Roundtrip: **183.1 us**<br>Sign: **29.1 us**<br>Verify: **154.0 us**                          | 643.0 us (ccryptolib) | **3.5x faster**   |
| ML-DSA-87   | Roundtrip: **1.374 ms**<br>Sign: **841.6 us**<br>KeyGen: **325.6 us**<br>Verify: **207.2 us** | 477.676 ms (WASM)     | **347.6x faster** |
| X25519      | Roundtrip: **619.8 us**<br>Exchange: **320.8 us**<br>KeyGen: **299.0 us**                     | 1.171 ms (ccryptolib) | **1.9x faster**   |
| ML-KEM-1024 | Roundtrip: **297.9 us**<br>KeyGen: **107.3 us**<br>Decap: **109.5 us**<br>Encap: **81.1 us**  | 82.845 ms (WASM)      | **278.1x faster** |

### Utilities

| Algorithm            | rbx-cryptography | Alternative                                                                     | Improvement                                                                                                               |
| -------------------- | ---------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Base64 (Encode)      | **1.8 GB/s**     | 40 MB/s (HashLib)<br>430 MB/s (Lute)<br>867 MB/s (Reselim)<br>1.1 GB/s (Roblox) | **46.3x faster** than HashLib<br>**4.3x faster** than Lute<br>**2.1x faster** than Reselim<br>**1.6x faster** than Roblox |
| Base64 (Decode)      | **3.4 GB/s**     | 42 MB/s (HashLib)<br>573 MB/s (Lute)<br>929 MB/s (Reselim)<br>1.8 GB/s (Roblox) | **80.2x faster** than HashLib<br>**5.9x faster** than Lute<br>**3.7x faster** than Reselim<br>**1.9x faster** than Roblox |
| Base64 (Roundtrip)   | **1.2 GB/s**     | 20 MB/s (HashLib)<br>255 MB/s (Lute)<br>450 MB/s (Reselim)<br>684 MB/s (Roblox) | **61.0x faster** than HashLib<br>**4.7x faster** than Lute<br>**2.7x faster** than Reselim<br>**1.8x faster** than Roblox |
| CSPRNG (RandomBytes) | **625 MB/s**     | 302 MB/s (math.random¹)                                                         | **2.1x faster** than math.random                                                                                          |
| XOR                  | **2.7 GB/s**     | 137 KB/s (string.char)<br>16 MB/s (string.gsub)<br>19 MB/s (table.concat)       | **19909.7x faster** than string.char<br>**168.3x faster** than string.gsub<br>**139.6x faster** than table.concat         |

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
