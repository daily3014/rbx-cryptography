# Luau Cryptography

<p align="center">
	<a href="https://xoifaii.github.io/rbx-crypto-docs/"><img src="https://img.shields.io/badge/Docs-xoifaii.github.io-00d4aa?style=for-the-badge" alt="Docs"></a>
	<a href="https://discord.gg/Fg3sM8qKPp"><img src="https://img.shields.io/badge/Discord-Join%20Server-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
	<a href="https://wally.run/package/daily3014/cryptography"><img src="https://img.shields.io/badge/Wally-Package-orange?style=for-the-badge" alt="Wally"></a>
	<a href="https://pesde.dev/packages/daily3014/cryptography"><img src="https://img.shields.io/badge/Pesde-Package-blue?style=for-the-badge" alt="Pesde"></a>
</p>

<p align="center">
	<b>Luau Cryptography</b> is a library of cryptographic algorithms written in Luau.<br>
	It supports Post-Quantum (PQ), Elliptic Curve Cryptography (ECC), authenticated encryption and CSPRNG with many utilities.<br>
	See the <a href="https://xoifaii.github.io/rbx-crypto-docs/docs/benchmarks">benchmarks</a> against other Roblox cryptography libraries.
</p>

## Example

```luau
local Cryptography = require(game:GetService("ReplicatedStorage").Cryptography)
local Hashing, Encryption, Verification = Cryptography.Hashing, Cryptography.Encryption, Cryptography.Verification
local CSPRNG = Cryptography.Utilities.CSPRNG

local Message = buffer.fromstring("Hello World")

-- Hash
local Hex = Hashing.SHA2.SHA256(Message)

-- Encrypt and decrypt with ChaCha20-Poly1305
local Key, Nonce = CSPRNG.RandomBytes(32), CSPRNG.RandomBytes(12)
local Ciphertext, Tag = Encryption.AEAD.Encrypt(Message, Key, Nonce)
local Plaintext = Encryption.AEAD.Decrypt(Ciphertext, Key, Nonce, Tag)

-- Sign and verify with Ed25519
local SecretKey = CSPRNG.RandomBytes(32)
local PublicKey = Verification.EdDSA.PublicKey(SecretKey)
local Signature = Verification.EdDSA.Sign(Message, SecretKey, PublicKey)
local IsValid = Verification.EdDSA.Verify(Message, PublicKey, Signature)
```

## Installation

- **Wally:** `cryptography = "daily3014/cryptography@4.1.0"` under `[dependencies]`
- **Pesde:** `pesde add daily3014/cryptography`
- **Manual:** download the latest release from GitHub and place it in your Roblox Studio project

## Disclaimer

While this library has extensive testing, it's always recommended that you do your own tests. Keep in mind that there may be timing vulnerabilities that cannot be fixed due to how Luau compiles functions. **This library is NOT intended for exploitation, harassment, illegal activities, or explicit content.** All security issues should be reported in the Discord server.

## Authors

**daily3014** ([@daily3014](https://github.com/daily3014)) and **Xoifail** ([@xoifail](https://github.com/xoifaii)). Thanks to everyone who gave feedback, tested, contributed and reported bugs.

## Contributing and License

Fork this repository, make your changes and open a Pull Request, which needs approval. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Licensed under MIT, see [LICENSE](./LICENSE).

---

<div align="center">

[DevForum](https://devforum.roblox.com/t/fastest-cryptography-library-for-roblox/3680271) • [Discord](https://discord.gg/Fg3sM8qKPp) • [Docs](https://xoifaii.github.io/rbx-crypto-docs/) • [Wally](https://wally.run/package/daily3014/cryptography) • [Pesde](https://pesde.dev/packages/daily3014/cryptography)

</div>
