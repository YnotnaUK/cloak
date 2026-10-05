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

## Prerequisites

### To Install and Run Pre-built Binaries
- Linux or macOS
- `curl` and `bash`

### To Build from Source
- **Go:** 1.20 or newer (requires standard library `crypto/ecdh`)
- **make:** GNU Make
- **git**

---

## Installation

### Via One-Line Install Script (Linux & macOS)
```bash
curl -fsSL https://raw.githubusercontent.com/ynotnauk/cloak/main/install.sh | bash
```

### From Source
```bash
git clone https://github.com/ynotnauk/cloak.git
cd cloak
make install
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
Encrypts all matching files in-place according to .cloak.yaml rules, or only the files you name:
```bash
cloak encrypt
cloak encrypt config/app.yaml
```

### 4. Decrypt
`cloak decrypt` never writes plaintext to disk unless you ask for it with `--in-place`.
```bash
cloak decrypt config/app.yaml                  # print the decrypted file to stdout
cloak decrypt config/app.yaml -e db.password   # print a single value
cloak decrypt -i config/app.yaml               # decrypt one file in-place
cloak decrypt -i                               # decrypt every matching file in-place
```

---

## Using Secrets in Scripts and Ansible

`--extract` (`-e`) prints one decrypted value and nothing else, so it is safe to capture:

```bash
DB_PASSWORD=$(cloak decrypt config/app.yaml -e db.password)
```

```yaml
- name: Read database password
  ansible.builtin.set_fact:
    db_password: "{{ lookup('ansible.builtin.pipe', 'cloak decrypt config/app.yaml -e db.password') }}"
  no_log: true
```

Notes:
- Paths are dot-separated (`db.password`). YAML and JSON arrays use an index (`servers.0.token`). `.env` files use the plain variable name.
- Values that were never encrypted are returned as is.
- Use `-n` (`--no-newline`) to omit the trailing newline.
- Maps and lists cannot be extracted, and `--extract` is not supported for `full` file rules.
- Errors go to stderr with a non-zero exit code, so nothing is printed to stdout on failure.
- The file must be inside the project and match a rule in `.cloak.yaml`. Excluded files are refused.
- Printing a YAML or JSON file to stdout re-serialises it, so blank lines may be dropped. Comments in YAML are kept.
- The private key is resolved as described in [CI/CD and Break-Glass Keys](#cicd-and-break-glass-keys).

---

## Managing Recipients

```bash
# List active recipients
cloak recipient list

# Add a named recipient (rotates DEK & rekeys files)
# kind is one of: user (default), ci, breakglass
cloak recipient add <public_key_hex> --name alice --kind user

# Remove a recipient by name or key (rotates DEK to revoke access)
cloak recipient remove alice

# Rotate data key manually
cloak rekey
```

---

## CI/CD and Break-Glass Keys

`cloak keygen` can create additional identities beyond your personal one. A new key can only decrypt a project once its public key has been added as a recipient.

### Pipeline key
```bash
cloak keygen -o ci.key --name ci-deploy        # -o, --out and --output are equivalent
cloak recipient add <public_key> --name ci-deploy --kind ci
```
Store the contents of `ci.key` in your CI secret store, then delete the local file. Cloak resolves the private key in this order:

1. `CLOAK_KEY` environment variable (the key hex, or the full key file content)
2. `CLOAK_KEY_FILE` environment variable (path to a key file)
3. `~/.config/cloak/key.txt`

GitHub Actions example:
```yaml
- name: Decrypt secrets
  env:
    CLOAK_KEY: ${{ secrets.CLOAK_KEY }}
  run: cloak decrypt -i
```

### Break-glass key
Print the key to stdout instead of writing it to disk. The key goes to stdout and the public key to stderr:
```bash
cloak keygen --stdout --name breakglass > breakglass.key
cloak recipient add <public_key> --name breakglass --kind breakglass
```
Move `breakglass.key` into offline storage (password manager, safe) and delete the local copy. To revoke a leaked key, run `cloak recipient remove <name>`, which rotates the data key.

### keygen options

| Flag | Description |
|---|---|
| `-o`, `--out`, `--output <file>` | Write the key to a custom path (mode 0600) |
| `--stdout` | Print the key instead of writing a file |
| `--name <label>` | Label stored in the key file header |
| `-f`, `--force` | Overwrite an existing key file |

---

## Configuration Example (.cloak.yaml)

```yaml
recipients:
  - name: antony
    key: 24e1679ae9ae7a0828bd10afc2a44ce1a4c1a5a8df9382ca4f8756efe8854d07
    kind: user          # user (default) | ci | breakglass

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
| ```cloak keygen [-f] [-o <file>] [--stdout] [--name <label>]``` | Generate an X25519 identity keypair |
| ```cloak init [-f] [-r <name>=<key> ...]``` | Create .cloak.yaml configuration |
| ```cloak encrypt [file ...]``` | Encrypt files in-place (all matching files if none given) |
| ```cloak decrypt <file>``` | Print the decrypted file to stdout |
| ```cloak decrypt <file> -e <path> [-n]``` | Print a single decrypted value |
| ```cloak decrypt -i [file ...]``` | Decrypt files in-place (all matching files if none given) |
| ```cloak recipient list``` | Display configured project recipients |
| ```cloak recipient add <key> --name <n> [--kind <k>]``` | Add a named recipient and rekey files |
| ```cloak recipient remove <name\|key>``` | Remove a recipient and rekey files |
| ```cloak rekey``` | Rotate data key and re-encrypt files |
| ```cloak version``` | Display binary build and version info |
