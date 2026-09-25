# 🛡️ cloak

> **Secret operations made simple.**  
> A lightweight, single-binary secret manager combining modern `age` encryption with `sops`-style in-place structured data handling.

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## ✨ Features

- **Single Static Binary**: Fast, standalone executable with zero external runtime dependencies.
- **Modern Cryptography**: Built on **X25519** and **ChaCha20-Poly1305** using audited `age` specifications.
- **Structured In-Place Encryption (SOPS-style)**: Encrypts only sensitive values in **YAML** and **JSON** files while leaving keys and structure visible for clean Git diffs.
- **Config-Driven Operations**: Run a simple two-word command (`cloak encrypt` or `cloak decrypt`) to automatically process all matching files across your workspace based on your `.cloak` rules.
- **Multiple Recipients**: Share encrypted files across entire teams by defining multiple public keys.
- **Full File Encryption**: Encrypts raw binary and plain text files (e.g., `.env`, certificates, archives).
- **Compile-time Metadata**: Full version, Git commit ID, and build timestamp embedded into `--version`.