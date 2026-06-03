# ISOB3TOOLS

Rust tools for ISO integrity verification, embedded ISOB3 (BLAKE3) metadata, SHA-256 manifest verification, and per-file encryption.

## Tools

| Binary        | Description                                                                  | Docs                                       |
|---------------|------------------------------------------------------------------------------|--------------------------------------------|
| `ISOB3GUI`    | Desktop app for scanning and verifying removable media and optical discs     | [docs/ISOB3GUI.md](docs/ISOB3GUI.md)       |
| `blake3iso`   | CLI for ISOB3 implant, check, info, and remove                               | [docs/blake3iso.md](docs/blake3iso.md)     |
| `direnc`      | Encrypts a directory in place and injects the decryptor, ready for `xorriso` | [docs/direnc.md](docs/direnc.md)           |
| `discdecrypt` | Decrypts a DBENC disc tree into an output folder (CLI + GUI)                 | [docs/discdecrypt.md](docs/discdecrypt.md) |

## Platforms

- Windows: `ISOB3GUI`, `blake3iso`, `direnc`, `discdecrypt`
- Linux: all four tools

## Quick Start

### Verify a disc or ISO

```bash
cargo build --release --bin blake3iso
blake3iso check release.iso
blake3iso info release.iso
```

### Produce an encrypted ISO

```bash
cargo build --release --bin blake3iso --bin direnc

# Extract source ISO into a staging directory
mkdir -p iso-staging
xorriso -osirrox on -indev plain.iso -extract / iso-staging/

# Encrypt in place and inject decryptor
direnc iso-staging/ --password secret --exclude ./verification/

# Rebuild and implant ISOB3
xorriso -as mkisofs -r -J -o encrypted.iso iso-staging/
blake3iso implant encrypted.iso
blake3iso check encrypted.iso
```

See [docs/direnc.md](docs/direnc.md) for the full workflow and all options.

### Decrypt a disc

```bash
# Using the decryptor bundled on the disc
chmod +x /media/disc/decryptor/discdecrypt
/media/disc/decryptor/discdecrypt \
  --input /media/disc \
  --output ~/decrypted \
  --password secret
```

See [docs/discdecrypt.md](docs/discdecrypt.md) for CLI reference and GUI mode.

## Encryption Formats

| Name            | ID       | Algorithm                                                  |
|-----------------|----------|------------------------------------------------------------|
| `argon2id`      | DBENC004 | Argon2id + XChaCha20-Poly1305 — **default** (password)     |
| `pqe-xchacha20` | DBENC005 | ML-KEM-768 + XChaCha20-Poly1305 — **default** (public key) |
| `xchacha20`     | DBENC003 | XChaCha20-Poly1305 + PBKDF2-HMAC-SHA256                    |
| `aes-gcm`       | DBENC002 | AES-256-GCM + PBKDF2-HMAC-SHA256                           |
| `legacy-cbc`    | DBENC001 | AES-256-CBC + HMAC-SHA256                                  |

## ISOB3 Metadata

Embedded ISOB3 metadata is stored in the ISO9660 Primary Volume Descriptor application data field.

- Offset: `0x8373`
- Size: `512` bytes
- Magic: `ISOB3APP`
- Algorithm: BLAKE3-256

## Exit Codes

| Code | Meaning                               |
|------|---------------------------------------|
| `0`  | Valid / success                       |
| `1`  | Invalid (integrity check failed)      |
| `2`  | Operational error or missing metadata |

## Examples

```bash
bash examples/linux_encrypted_iso_e2e.sh
```

See [examples/README.md](examples/README.md) for what the script does.

## Manual Test Fixtures

Large ISO inputs for local testing belong in `fixtures/manual/` (not tracked in git).

For CI, use the manual workflow in [.github/workflows/large-iso-manual.yml](.github/workflows/large-iso-manual.yml) and supply a download URL.

## Repository Layout

```
.
├── Cargo.toml
├── docs/
│   ├── ISOB3GUI.md
│   ├── blake3iso.md
│   ├── direnc.md
│   └── discdecrypt.md
├── examples/
│   ├── README.md
│   └── linux_encrypted_iso_e2e.sh
├── src/
│   ├── bin/
│   │   ├── blake3iso.rs
│   │   ├── direnc.rs
│   │   └── discdecrypt.rs
│   ├── app.rs          (ISOB3GUI)
│   └── ...
├── tools/
│   ├── checkisomd5
│   └── checkisomd5.exe
└── .github/workflows/
```

## License

CC0 1.0 — public domain.
