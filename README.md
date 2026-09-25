# cloak

[![CI Status](https://github.com/ynotnauk/cloak/actions/workflows/ci.yml/badge.svg)](https://github.com/ynotnauk/cloak/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/ynotnauk/cloak?color=blue&logo=github)](https://github.com/ynotnauk/cloak/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ynotnauk/cloak?logo=go)](https://go.dev/)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](LICENSE)

A declarative, in-place secrets encryption tool inspired by SOPS and age, written in Go with near-zero external dependencies.

Cloak encrypts sensitive values inside structured files (.env, .json, .yaml) or entire files while leaving non-sensitive keys, comments, and structure intact.

---

## Features

- Modern Cryptography: X25519 key exchange (crypto/ecdh) and AES-256-GCM symmetric encryption.
- Envelope Encryption: Uses a random 32-byte Data Encryption Key (DEK) wrapped per recipient.
- Declarative Configuration: Define rules and keys once in .cloak.yaml.
- Targeted Key Encryption: Encrypt only specific keys (password, token, etc.) while keeping the rest readable.
- AST-Preserving YAML: Retains formatting, scalar types, and comments.
- Idempotent: Safe to run repeatedly without double-encrypting.
- Multi-Recipient & Rekeying: Add or remove team members with automatic DEK rotation.

---

## Installation

Download pre-built binaries from Releases, or build from source:

```bash
git clone https://github.com/ynotnauk/cloak.git
cd cloak
make build
```

---

## Quick Start

### 1. Generate Your Keypair
Creates an identity keypair stored securely in your user config directory (~/.config/cloak/key.txt):
```bash
cloak keygen
```

### 2. Initialize a Project
Run in the root of your project to create .cloak.yaml:
```bash
cloak init
```

### 3. Encrypt Project Files
Encrypts all matching files in-place according to .cloak.yaml rules:
```bash
cloak encrypt
```

### 4. Decrypt Project Files
Restores all files to plaintext in-place using your local private key:
```bash
cloak decrypt
```

---

## Managing Recipients

```bash
# List active recipients
cloak recipient list

# Add recipient (rotates DEK & rekeys files)
cloak recipient add <public_key_hex>

# Remove recipient (rotates DEK to revoke access)
cloak recipient remove <public_key_hex>

# Rotate data key manually
cloak rekey
```

---

## Configuration Example (.cloak.yaml)

```yaml
recipients:
  - 24e1679ae9ae7a0828bd10afc2a44ce1a4c1a5a8df9382ca4f8756efe8854d07

exclude:
  - .git
  - node_modules
  - bin
  - coverage
  - .cloak.yaml

rules:
  # Encrypt entire file
  - path_regex: .*\.secret$
    type: full

  # Encrypt specific keys in YAML (preserves comments)
  - path_regex: .*\.ya?ml$
    type: yaml
    encrypted_keys:
      - password
      - secret
      - token

  # Encrypt specific keys in JSON
  - path_regex: .*\.json$
    type: json
    encrypted_keys:
      - password
      - secret
      - token

  # Encrypt specific keys in .env files
  - path_regex: .*\.env$
    type: env
    encrypted_keys:
      - PASSWORD
      - SECRET_KEY
```

---

## CLI Reference

| Command | Description |
|---|---|
| ```cloak keygen [-f]``` | Generate local X25519 identity keypair |
| ```cloak init [-f] [-r <key> ...]``` | Create .cloak.yaml configuration |
| ```cloak encrypt``` | Encrypt all matching project files in-place |
| ```cloak decrypt``` | Decrypt all matching project files in-place |
| ```cloak recipient list``` | Display configured project recipients |
| ```cloak recipient add <key>``` | Add recipient public key and rekey files |
| ```cloak recipient remove <key>``` | Remove recipient public key and rekey files |
| ```cloak rekey``` | Rotate data key and re-encrypt files |
| ```cloak version``` | Display binary build and version info |