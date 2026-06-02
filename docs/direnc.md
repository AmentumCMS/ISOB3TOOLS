# direnc

Encrypts payload files in a directory in place and injects a bundled `decryptor/` folder, preparing the directory for ISO rebuilding with `xorriso`.

`direnc` handles the encryption step only — you run `xorriso` before and after it yourself. This keeps ISO layout choices (Joliet extensions, volume label, boot records, large-file handling) entirely under your control.

## Build

```bash
cargo build --release --bin direnc
```

Available on Linux and Windows.

## Usage

```
direnc <DIRECTORY> (--password <PW> | --public-key <FILE>) [OPTIONS]
```

| Argument | Type | Required | Description |
|---|---|---|---|
| `DIRECTORY` | path | yes | Directory to process in place |
| `--password <PW>` | string | see note | Encryption password for DBENC001–003. Mutually exclusive with `--public-key`. |
| `--public-key <FILE>` | path | see note | ML-KEM-768 encapsulation key (`.ek`) for DBENC004 (post-quantum). Mutually exclusive with `--password`. |
| `--format <FORMAT>` | string | no | Encryption format. Defaults to `xchacha20` (password) or `pqe-xchacha20` (public key). |
| `--exclude <DIRS>` | string | no | Comma-separated list of subdirectory paths to skip |

One of `--password` or `--public-key` is required.

### `--format`

| Name | Format | Notes |
|---|---|---|
| `argon2id` | DBENC004 Argon2id + XChaCha20-Poly1305 | Default with `--password` |
| `pqe-xchacha20` | DBENC005 ML-KEM-768 + XChaCha20-Poly1305 | Default with `--public-key` |
| `xchacha20` | DBENC003 XChaCha20-Poly1305 + PBKDF2 | |
| `aes-gcm` | DBENC002 AES-256-GCM + PBKDF2 | |
| `legacy-cbc` | DBENC001 AES-256-CBC + HMAC-SHA256 | Compatibility only |

### `--exclude`

Paths are relative to `DIRECTORY` and leading `/` or `./` is stripped before matching. The `decryptor/` subdirectory is always skipped automatically.

SHA-256 manifest files (detected by content, not extension) are always skipped regardless of `--exclude`.

Examples:

```bash
# Password-based encryption (symmetric)
direnc iso-staging --password secret --exclude ./verification/

# PQE encryption with an ML-KEM-768 public key
blake3iso keygen --output release-2026
direnc iso-staging --public-key release-2026.ek

# Override format explicitly
direnc iso-staging --password secret --format aes-gcm
```

## What direnc does

1. Walks all files in `DIRECTORY` recursively.
2. Skips SHA-256 manifest files, the `decryptor/` subtree, and any `--exclude` paths.
3. Encrypts each remaining file in place (writes to a sibling temp file, then atomically replaces the original). Filenames are unchanged.
4. Creates `DIRECTORY/decryptor/` and populates it with:
   - `discdecrypt` — Linux decryptor binary
   - `discdecrypt.exe` — Windows decryptor binary
   - `decrypt.sh` — convenience wrapper script
   - `README.txt` — usage instructions for end users

`direnc` requires `discdecrypt` and `discdecrypt.exe` to be present next to its own executable so it can copy them into the `decryptor/` folder.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `2` | Operational error |

## ISO Prep Workflow

The full workflow for producing an encrypted ISO from a source directory:

```bash
# 1. Build a plaintext ISO from your source tree (or start from an existing ISO)
xorriso -as mkisofs -r -J -V MY_DISC -o plain.iso source-tree/

# 2. Extract the ISO into a staging directory
mkdir -p iso-staging
xorriso -osirrox on -indev plain.iso -extract / iso-staging/

# 3. Encrypt the staging directory
direnc iso-staging/ --password secret --exclude ./verification/

# 4. Rebuild the encrypted ISO
xorriso -as mkisofs -r -J -V MY_DISC -o encrypted.iso iso-staging/

# 5. Implant ISOB3 metadata
blake3iso implant encrypted.iso

# 6. Verify
blake3iso check encrypted.iso
```

## Decrypting the Disc

Recipients use the bundled decryptor inside the disc itself:

```bash
# Linux
chmod +x /media/disc/decryptor/discdecrypt
/media/disc/decryptor/discdecrypt --input /media/disc --output ~/decrypted --password secret

# Or use the convenience wrapper
/media/disc/decryptor/decrypt.sh --output ~/decrypted --password secret
```

On Windows, run `discdecrypt.exe` from the `decryptor\` folder on the disc. If `--output` and `--password` are omitted, the tool prompts for them interactively.

See [discdecrypt.md](discdecrypt.md) for full CLI reference.
