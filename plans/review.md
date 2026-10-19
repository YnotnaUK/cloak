# cloak — `release/0.2` Repository Review

**Date:** 05/10/2026
**Branch:** `release/0.2` @ `8777fb1` (9 commits ahead of `origin/main`, 0 behind — fast-forwardable)
**Scope:** All 32 tracked files — Go source, tests, CI/release workflows, install script, Makefile, README, config, demo data.

**Status checked:** 11/10/2026 against `origin/release/0.2` @ `9707514`, using merged commit history and source inspection.
Checked boxes mean the entire item is resolved. Partially resolved items remain unchecked, with completed sub-items checked separately. The baseline results and original findings below are historical, not a fresh tooling or security review.

**Completed:** #1, #2, #3, #6, #13, #20 and #26.
**Fixed locally, not yet merged:** #4 on `fix/rule-validation`; config/engine regression tests, race checks, vet and the full Go suite passed.
**Partially completed:** #7, #8, #11, #18, #19, #22 and documentation/testing.

## Baseline health

| Check | Result |
|---|---|
| `gofmt -s` | ✅ clean |
| `go vet` | ✅ clean |
| `golangci-lint` | ✅ 0 issues |
| `govulncheck` | ✅ no vulnerabilities |
| `go test -race ./...` | ✅ pass |
| Coverage | config 73%, crypto 77%, keys 69%, engine 51%, formats 52%, **cmd 0%, updater 0%** |

The static tooling is clean. Most of the issues below are **behavioural**: problems with how files are handled (data loss or values left in plaintext) that no current test exercises. Each item marked 🔬 was reproduced against a locally built binary.

---

## 🔴 Release blockers

### 1. Multi-document YAML is silently truncated (data loss) 🔬
- [x] Fixed by `2e5a363`: encrypt/decrypt now decode and encode every document; rekey/edit use those formatters. Regression coverage added.

`internal/formats/yaml.go` — `yaml.Unmarshal(content, &root)` decodes only the **first** document. Encrypt, decrypt, rekey and edit then write back just that document, so everything after the first `---` is deleted. Kubernetes manifests are commonly multi-document.

```
a: 1            →   a: 1
password: x         password: CLOAK:v2:...
---                 (rest of file gone)
b: 2
password: y
```
**Fix:** loop with `yaml.NewDecoder(...).Decode(&node)` until `io.EOF` and encode every document with the same encoder.

### 2. JSON secrets inside arrays are never encrypted (plaintext leak) 🔬
- [x] Fixed by `0d38f9d`: nested and top-level arrays are traversed; regression coverage added.

`walkMapEncrypt`/`walkMapDecrypt` (`internal/formats/json.go`) only recurse into `map[string]any`. A value such as `{"servers":[{"password":"plain1"}]}` stays in plaintext while `cloak encrypt` reports `Encrypted: file.json`. JSON documents whose top level is an array are also rejected because the content is unmarshalled into `map[string]any`.
**Fix:** walk `[]any` as well, and unmarshal into `any`.

### 3. JSON non-string values under `encrypted_keys` are corrupted 🔬
- [x] Fixed by `8b42484`: non-string payloads carry JSON type information; null, arrays, numbers and booleans round-trip. Regression coverage added.

The `default:` branch encrypts `fmt.Sprintf("%v", val)`:
- `"token": null` → decrypts to the string `"<nil>"`
- `"secret": ["a","b"]` → decrypts to `"[a b]"`. The original array cannot be recovered.
- numbers and booleans come back as strings.

**Fix:** encrypt the value's JSON encoding (`json.Marshal(val)`) and restore it with `json.Unmarshal` on decrypt. Alternatively, refuse non-scalar values.

### 4. Invalid rule `type` or regex is silently ignored (secrets left in plaintext) 🔬
- [x] Fixed locally on `fix/rule-validation` (not yet merged): `Validate()` checks all rule types using the formatter registry and compiles regexes once. Unsupported types fail explicitly in processing/rekeying; invalid configs fail before key loading or file changes. Config saving validates before truncation.

- `processFile` and `Rekey` return `nil` when `formats.Get` fails. With `type: ful` (a typo), `cloak encrypt s.secret` exits 0 and leaves the file in plaintext.
- `FindRule` discards the `regexp.MatchString` error, so an invalid regex never matches. The regex is also recompiled for every file.
- `Config.Validate()` does not check `rules` at all.

**Fix:** validate rule types and compile the regexes in `Validate()`. Fail loudly on unknown types.

### 5. Recipient add/remove saves the config *before* rekeying, so revocation can fail open 🔬
- [x] Fixed by `59ee952` and `3021009` (merged in #19): recipient changes preflight all matching encrypted files in memory, replace files atomically, and save the config last. File-write or config-save failures trigger rollback, with rollback and temporary-file cleanup errors reported explicitly.

`AddRecipient`/`RemoveRecipient` call `Save()`, and only then does `main.go` call `engine.Rekey()`. If the rekey fails (no private key, an undecryptable file, a parse error), `.cloak.yaml` already says the recipient is gone, but the files are still wrapped for their key. Running `remove` again returns "not found", so the user has no obvious way to recover. Rekey also stops part-way through the walk, which can leave some files rekeyed and others not.
**Fix:** decrypt and re-encrypt everything in memory first. Then write the files atomically, then save the config. At minimum, roll the config back if the rekey fails.

### 6. `VERSION` is still `0.1` on the 0.2 release branch
- [x] Fixed by `4208500`: `VERSION` is `0.2.0`, validated against the release branch; preview tags now use `v0.2.0-preview.<timestamp>`.

The release workflow builds tags from `VERSION`, so this release would be published as `v0.1.<timestamp>` (the latest release is `v0.1.20260928150402`).

### 7. Release pipeline publishes untested, unverified binaries
- [x] Fixed by `303099e` (merged in #20): releases publish `SHA256SUMS`, and both the updater and installer verify the selected binary before replacing an installation. Missing/malformed manifests, missing/duplicate entries, mismatches and failed downloads fail explicitly. Formatting, full lint, tests and build passed before committing.
- [x] Releases depend on lint and tests via the reusable workflow (`4208500`); drafts are published only after all assets upload (`0d00c90`).
- [x] Checksum generation and verification are implemented in the release workflow, `cloak update` and `install.sh`, with regression tests. Signatures/attestations were explicitly deferred; checksums verify integrity, not publisher identity.

**Fix:** run the tests (or `needs:` a test job) in the release workflow, publish `SHA256SUMS` (and ideally a cosign/GitHub attestation), and verify it in both the updater and `install.sh`.

### 8. `install.sh` can install an HTTP error page as the binary
- [x] Fixed by `04352c9` (merged in #21): HTTP, empty-download and checksum failures are handled, and direct/sudo installation uses `install -m 0755`. Regression tests verify exact permissions under `umask 077`, failure reporting and temporary-file cleanup. Formatting, full lint, tests and build passed before committing.
- [x] API/binary requests use `curl -fsSL`, and empty downloads are rejected (`5076ada`).
- [x] Verify checksums (`303099e`).
- [x] Install with mode 0755 (`04352c9`): both installation paths use `install -m 0755`, replacing `chmod +x` and `mv`.

`curl -sL "$DOWNLOAD_URL" -o "$TMP_FILE"` has no `-f`. On a 404 or a pruned release (see #19), the "Not Found" body is made executable and moved to `/usr/local/bin/cloak`. The same applies to the API call on line 25.
**Fix:** use `curl -fsSL`, verify the checksum, and install with `install -m 0755`, not `chmod +x` on a `mktemp` file (mode 0700).

---

## 🟠 High / Medium

### 9. Non-atomic writes of secret files and config
- [x] Fixed on `fix/atomic-file-writes` by `71053e5` (not yet merged): encrypt/decrypt, edit, rekey, config saving and forced initialisation use a shared same-directory temp/write/fsync/rename helper. Existing permissions and symlinks are preserved. Non-forced initialisation atomically publishes a complete config without overwriting a concurrent creator. Tests cover partial-write/rename failures, cleanup, exclusive creation and atomic replacement across engine/config paths; formatting, full lint, all tests, build and focused race tests passed before committing. Per-file atomicity does not imply a project-wide transaction or power-loss durability.

`os.WriteFile` (engine `processFile`, `Rekey`, `Edit`) and `Config.Save` truncate the file and then write it. A crash or a full disk part-way through can destroy secrets or the recipient list.
**Fix:** write to a temp file in the same directory, `fsync`, then `rename`, keeping the original mode.

### 10. Default rules plus "abort on first error" are a footgun 🔬
- [x] Fixed on `fix/continue-processing-file-errors` by `b2ae67d`: `.github` is excluded by default, and explicit/bulk processing collects per-file errors whilst continuing with remaining files.

- The default rule `.*\.json$` matches every JSON file in a repo (`package.json`, lock files, `tsconfig.json`). A single invalid file, such as JSONC with comments, aborts the walk part-way, leaving files already rewritten and the rest untouched.
- The default `init` excludes do **not** include `.github`, even though this repo's own `.cloak.yaml` does. A `token:` in a workflow file would be encrypted.

**Fix:** add `.github` to the defaults. Either collect per-file errors and continue, or validate all files before writing any.

### 11. Every matched file is rewritten even when nothing changes 🔬
- [x] Fixed on `fix/preserve-json-formatting` by `190ba10`: byte-identical output skips the file write and success message. JSON encryption/decryption replaces only changed values, preserving key order, surrounding whitespace, HTML characters and trailing newlines.
- [x] JSON decoding uses `UseNumber()`; large-number precision is covered by tests (`8b42484`).
- [x] Changed JSON strings are encoded without HTML escaping; large JSON numbers retain their original representation.

`processFile` previously rewrote files even when their contents were unchanged. Re-encoding JSON also changed key ordering, HTML escaping and whitespace, while decoding numbers through floating point could lose precision.
**Fix:** skip unchanged writes and replace only changed JSON values, preserving the rest of the document byte-for-byte.

### 12. YAML scalar types are not preserved 🔬
- [x] Fixed on `fix/preserve-yaml-scalar-types` by `ad1da80`: new YAML ciphertext payloads retain the scalar tag, style and value, and decryption restores them. Existing ciphertexts remain readable and decrypt as strings.
- [x] PR review follow-up in `3956f6b`: typed-vs-legacy ciphertext uses an outer `CLOAK:YAML:v1:` envelope prefix, avoiding collisions with legacy plaintext; typed payload fields are strictly validated.

`walkYamlEncrypt` previously set `Tag = "!!str"` without preserving the original tag, so `password: 12345` came back as `password: "12345"`.
**Fix:** store and restore the original scalar metadata in new ciphertexts, retaining backward compatibility for old ciphertexts.

### 13. YAML aliases bypass encryption 🔬
- [x] Fixed on `fix/yaml-alias-encryption`: encryption, decryption, encrypted-value detection and rekeying follow aliases; extraction resolves aliases safely. Regression tests cover scalar and nested mapping aliases, recipient rotation, and recursive alias errors.

`base: &b supersecret` / `password: *b` stays entirely in plaintext because `AliasNode` is neither encrypted nor followed.
**Fix:** resolve aliases when walking, or reject aliased values under encrypted keys.

### 14. `.env` handling gaps 🔬
- [ ] Not fixed: export syntax, spacing, CRLF and long-line handling remain unchanged.

- `export PASSWORD=abc` is not recognised (the key is parsed as `export PASSWORD`), so it stays in plaintext.
- `KEY = value` is normalised to `KEY=…`, CRLF line endings become LF, and `bufio.Scanner`'s 64 KiB line limit can fail on long values.

### 15. Symlinks are followed and written through 🔬
- [ ] Not fixed: explicit-file validation still uses `os.Stat` and lexical path checks.

`resolveFile`'s "outside the project" check is purely lexical. `link.yaml -> /tmp/outside.yaml` was encrypted in place outside the project. The walk does the same for symlinked files.
**Fix:** `Lstat` and skip or refuse symlinks, or check the `EvalSymlinks` result against the project root.

### 16a. Shared envelope validation and plaintext/ciphertext ambiguity
- [x] Implemented: `internal/envelope` strictly parses `CLOAK[v1,iv:…,data:…,wrap:…]` and all formatters use it; malformed reserved-prefix values now error, literal `CLOAK[` plaintext is unsupported (documented), legacy pre-release prefixes are rejected. (Previously deferred; Priority: High / Medium (integrity and potential plaintext exposure); address before wider adoption.)

Formatters currently recognise encrypted values by reserved prefixes rather than validating the complete envelope. YAML now requires `CLOAK:YAML:v1:CLOAK:v1:`, but a plaintext secret beginning with that combined prefix is still skipped by encryption. The existing `CLOAK:v1:` checks in other formats have the same ambiguity. Decryption can subsequently fail on these values, and encryption must not report success whilst leaving a targeted secret unprotected.

**Scope:** introduce a shared, version-aware envelope parser/validator; check segment structure, hex encoding, nonce/ciphertext lengths and recipient wraps before classifying a value as ciphertext. Use consistent recognition in encrypt, decrypt, extract, edit and rekey across YAML, JSON, `.env` and full-file rules. Define an explicit policy for malformed reserved-prefix values (including how users can encrypt literal prefix-shaped secrets), preserve supported legacy envelopes and fail with actionable errors rather than silently skipping secrets.

Structural validation cannot prove authenticity or distinguish a plaintext string that is itself a structurally valid envelope; that remaining ambiguity requires a documented reserved-prefix/escaping policy. Add regression and fuzz tests for prefix-shaped plaintext, malformed/truncated envelopes, supported versions and normal idempotent processing. No implementation is planned as part of task #12.

### 16. Cryptographic design (worth fixing before wider adoption, as it needs a `v3` envelope)
- [ ] Partly fixed with 16a: HKDF-SHA256 (salt = epk‖rpk, info label) and a fixed data/wrap AAD are in. Still outstanding: per-value path/file AAD, file-level MAC and authenticity guidance. `31839fe` only renamed the envelope from `CLOAK:v2:` to `CLOAK:v1:`; a future redesign now needs a new version after v1, not necessarily v3.

- **No AAD.** Ciphertexts are not bound to their file or key path, so someone with write access can swap or copy encrypted values between keys or files undetected. There is no file-level MAC (SOPS has one).
- **KDF.** `wrapKey = SHA-256(sharedSecret)` has no domain separation and does not bind the ephemeral or recipient public keys. Prefer HKDF-SHA256 with `salt = epk || rpk` and an `info` label (as age does).
- Note: as with any public-key scheme, anyone holding the recipient public keys can forge *valid* new values. Document this, or add authorship/MAC.

### 17. `cloak edit` can leave plaintext behind on signals
- [ ] Not fixed: signal handling, editor history caveats and quoted editor paths remain outstanding.

No handling for `SIGINT`/`SIGTERM`/`SIGHUP` (for example, closing the terminal), so the deferred `RemoveAll` does not run. The README covers `kill -9` but not these cases. GUI editors (`code --wait`) also keep their own local history and backups of the plaintext, which is worth a caveat in the README.
`strings.Fields($EDITOR)` also breaks editor paths that contain spaces.

### 18. Updater correctness
- [ ] Partially fixed by `00e6e87`: Windows replacement remains outstanding.
- [x] Versions are compared by major/minor/patch and preview timestamp, with migration handling for legacy stable tags. Development builds are excluded from notices. Explicit updates remain deliberate channel selections, with older targets labelled.
- [x] Background checks maintain one state and no longer overwrite fresh `LastChecked` with stale data.
- [x] Cache directories are created, and cache failures are surfaced instead of silently ignored.
- [x] Binary downloads have a two-minute timeout; explicit release discovery has a 30-second timeout.
- [ ] `os.Rename` over a running `.exe` still fails on Windows.
- [x] `CLOAK_NO_UPDATE_CHECK`, notices and preview/stable update commands are documented.

### 19. Release pruning deletes releases and tags beyond the newest 20
- [ ] Partially fixed by `4208500`: stable tags use SemVer and are not regenerated on every code push, and preview retention is isolated per series. Stable releases/tags beyond the newest 20 are still deleted, so pinned installations and prune races remain concerns.

Every code push to `main` creates a timestamped release, so 20 releases go by quickly. This breaks pinned installs and any `install.sh`/updater run that races a prune. Consider keeping releases and only pruning pre-releases, or moving to proper semver tags.

---

## 🟡 Low / Housekeeping

20. **`.gitignore`** — the `cloak` pattern matches at any depth and ignores `cmd/cloak/` (`git check-ignore` confirms this for new files there). Use `/cloak`.
- [x] Fixed by `00e6e87`: the binary exclusion is `/cloak`; new CLI tests are tracked.

21. **`go.mod`**
    - [ ] `gopkg.in/yaml.v3` is a direct dependency but is marked `// indirect`. Run `go mod tidy`.
    - [ ] The `go 1.27.1` directive contradicts the README's "Go 1.20 or newer".
    - [ ] `gopkg.in/yaml.v3` is archived. Consider the maintained `go.yaml.in/yaml/v3`.
22. **CI**
    - [ ] Default workflow permissions to `contents: read`. Only the release job has explicit permissions.
    - [x] Duplicate feature-branch push/PR checks removed by `4dd4a9c`: pushes are restricted to `main` and `release/**`. A release branch used as a PR source can still have both runs, intentionally retaining post-push checks.
    - [ ] `go-version: stable` instead of `go-version-file: go.mod`.
    - [ ] No `-race` in CI.
    - [ ] Actions are not SHA-pinned.
    - [ ] Release builds lack `-trimpath` and `CGO_ENABLED=0`.
23. **Config**
    - [ ] `.cloak.yaml` is only looked up in the CWD (no upward search from subdirectories).
    - [ ] `Save()` strips any comments from `.cloak.yaml`.
    - [ ] Excludes are exact path-component matches only. Document this, or support globs.
24. **Keys**
    - [ ] `ReadPublicKey` ignores `CLOAK_KEY`/`CLOAK_KEY_FILE` (so `cloak init` does too) and trusts the `# Public Key:` comment instead of deriving the key from the private key.
    - [ ] No warning when the key file permissions are wider than 0600.
    - [ ] The default-path logic is duplicated.
25. **`main.go` / engine**
    - [ ] Usage and error output goes to stdout instead of stderr.
    - [ ] No `help`, `-h` or `--version`.
    - [ ] `recipient add` silently ignores extra positional arguments.
    - [ ] There is a stray `// In internal/engine/engine.go:` comment on `Rekey`, which also lacks a doc comment.
    - [ ] The walk logic is duplicated between `Process` and `Rekey`.
    - [ ] The package-global `cryptoPrivateKeyLoader` panics with a nil pointer if `SetKeyLoader` is not called.
26. **Empty YAML file** is rewritten as `null`.
- [x] Fixed by `2e5a363`: an empty stream yields zero documents and encodes to empty output.

27. **Local `main` is stale** (behind `origin/main`). Fetch or reset it before merging.
- [ ] Still outstanding: local `main` is `a6336d5`, whilst the cached `origin/main` is `18b5990`. No branch reset was performed.

28. **`demo/`** — the plaintext demo secrets match the repo's rules. Running `cloak encrypt` at the repo root encrypts them to the maintainer's key only.
- [ ] Not changed; demo files still match the configured rules.

---

## 📄 Documentation (README)

- [ ] "AST-Preserving YAML: Retains formatting, scalar types" remains inaccurate (see #12): indentation is normalised and types change. Multi-document truncation (#1) is fixed.
- [ ] Fully document JSON re-serialisation: the README mentions stdout re-serialisation, but not key ordering, escaping or number handling.
- [ ] The Go prerequisite says 1.20; `go.mod` requires 1.27.1.
- [x] `cloak update`, `CLOAK_NO_UPDATE_CHECK` and update-check behaviour are documented (`00e6e87`).
- [ ] Document Windows binaries and their self-update limitation.
- [ ] Add `update` to the CLI reference table; it is documented in the separate Updating section.
- [ ] **Important:** state that removing a recipient does not revoke access to values already in git history. The underlying secrets must be rotated.
- [ ] Mention that `make install` uses `sudo`.

---

## 🧪 Suggested test strategy

- **Round-trip regression coverage** (`encrypt → decrypt == original`) per formatter:
  - [x] Multi-document YAML (`2e5a363`).
  - [x] YAML anchors and aliases, including encrypted-value detection and rekeying (`fix/yaml-alias-encryption`).
  - [ ] YAML int/bool/null under encrypted keys.
  - [x] JSON arrays, nested and top-level (`0d38f9d`).
  - [x] JSON null, array and number values under encrypted keys, plus large integers (`8b42484`).
  - [ ] `.env` `export`, spacing, CRLF and long lines.
- **Engine regression coverage** for `Process`/`Rekey`:
  - [x] Invalid rule type and invalid regex (local `fix/rule-validation`): explicit/walk encrypt/decrypt, rekey, stdout decrypt, extract and edit fail without modifying files.
  - [ ] Symlinks.
  - [ ] Partial-failure behaviour.
  - [ ] Recipient removal when rekey fails.
- [ ] **Fuzz tests** (`go test -fuzz`) for `crypto.Decrypt` envelope parsing and each formatter's `Decrypt`/`Extract`.
- [x] **Updater tests** cover comparisons, channel discovery, cache/cooldowns, failures, timeouts and replacement using a mocked HTTP transport instead of `httptest.Server` (`00e6e87`).
- [x] **Installer/release regression tests** cover preview ordering and draft/upload/publication sequencing (`1cc1e5a`).
- [x] **Envelope-version tests** assert v1 output and v2 rejection (`31839fe`).
- [ ] Add `-race` to the CI test job.

---

## Suggested order of work

1. **Data loss / leaks:** #1, #2, #3, #4, #13, #14 (export)
2. **Integrity:** #5, #9, #10, #15, #16a (shared envelope validation; deferred larger work)
3. **Release plumbing:** #6, #7, #8, #19, #20
4. **Correctness and UX:** #11, #12, #17, #18
5. **Crypto v3 envelope (#16):** decide before 1.0, since it is a format change
6. Docs and the low-priority items
