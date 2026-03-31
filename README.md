# ISOB3TOOLS

Rust GUI and CLI tools for ISO integrity verification, embedded `ISOB3` metadata, SHA-256 manifest verification, and per-file encryption.

## Overview

This project has two main pieces:

- `ISOB3GUI`: desktop app for scanning removable media and optical discs
- `blake3iso`: CLI for implanting, checking, encrypting, and decrypting files
- `isoenc`: CLI for extracting an input ISO, encrypting payload files in place, and rebuilding a new ISO

The integrity model supports:

- embedded `ISOB3` metadata inside ISO application data
- legacy `isomd5sum` fallback checks
- SHA-256 manifest verification across selected drives
- per-file encrypted payloads with ciphertext attestation plus plaintext verification

Supported platforms:

- Windows
- Linux

## GUI Flow

The GUI verification flow is:

1. Scan disc drives and removable media
2. Select which drives to verify
3. Search selected drives for SHA-256 manifests
4. Verify SHA-256 entries
5. Verify embedded `ISOB3`

Current GUI behavior includes:

- drive selection before verification starts
- live byte-based progress and throughput metrics
- per-drive popup with detailed verification results
- encrypted-file verification with password support
- abort button and close-confirmation while verification is active

On Windows, raw optical devices are verified through paths such as `\\.\CdRom0`.
On Linux, raw optical devices are verified through paths such as `/dev/sr0`.

## CLI Commands

Build the CLI:

```bash
cargo build --release --bin blake3iso
```

Run it during development:

```bash
cargo run --release --bin blake3iso -- <command> ...
```

Available commands:

- `implant`
- `check`
- `remove`
- `info`
- `encrypt`
- `decrypt`

The repository also provides a separate bundler CLI:

```bash
cargo build --release --bin isoenc
```

### ISO Operations

Implant embedded `ISOB3` into an ISO:

```bash
blake3iso implant file.iso
```

Force overwrite if the application data area is already populated:

```bash
blake3iso implant file.iso --force
```

Check an ISO or raw optical device:

```bash
blake3iso check file.iso
```

Show metadata:

```bash
blake3iso info file.iso
```

Remove embedded `ISOB3`:

```bash
blake3iso remove file.iso
```

### Encrypted File Operations

Encrypt a file and generate a ciphertext integrity sidecar:

```bash
blake3iso encrypt payload.iso --password secret
```

The default encryption format is `DBENC003` (`XChaCha20-Poly1305`).

Explicitly choose a format:

```bash
blake3iso encrypt payload.iso --password secret --format xchacha20
blake3iso encrypt payload.iso --password secret --format aes-gcm
blake3iso encrypt payload.iso --password secret --format legacy-cbc
```

You can also use `implant --encrypted` to produce an encrypted file instead of writing embedded ISO metadata:

```bash
blake3iso implant payload.iso --encrypted --password secret
blake3iso implant payload.iso --encrypted --password secret --format aes-gcm
```

Decrypt an encrypted file:

```bash
blake3iso decrypt payload.iso.dbenc --password secret --output payload.iso
```

Check an encrypted file:

```bash
blake3iso check payload.iso.dbenc
```

For encrypted files, `check` validates the ciphertext sidecar. It does not decrypt the file.

### ISO Bundling

`isoenc` is the tool for `input ISO -> encrypted output ISO`.

`isoenc` is currently Linux-only.

Example:

```bash
isoenc bundle input.iso --output encrypted.iso --password secret
```

The bundler:

1. extracts the input ISO into a temporary tree
2. encrypts regular payload files in place while keeping filenames unchanged
3. skips SHA-256 manifest files automatically
4. rebuilds a new ISO from the transformed tree
5. optionally implants `ISOB3` into the rebuilt output

Exclude directories with a comma-separated list:

```bash
isoenc bundle input.iso --output encrypted.iso --password secret --exclude ./verification/,./test/example/
```

Choose an encryption format:

```bash
isoenc bundle input.iso --output encrypted.iso --password secret --format xchacha20
isoenc bundle input.iso --output encrypted.iso --password secret --format aes-gcm
```

### Exit Codes

- `0`: valid / success
- `1`: invalid
- `2`: operational error or missing metadata

## Encryption Formats

The project supports three `DBENC` file formats:

- `DBENC001`: AES-256-CBC + HMAC-SHA256, legacy compatibility format
- `DBENC002`: AES-256-GCM
- `DBENC003`: XChaCha20-Poly1305, default for new encrypted files

For encrypted verification flows:

- ciphertext integrity for standalone encrypted files is attested by the sidecar generated during encryption
- plaintext integrity is verified by decrypting and checking SHA-256 manifests
- embedded `ISOB3` can still be verified for decrypted ISO payloads
- for `isoenc` output, embedded `ISOB3` on the rebuilt ISO attests the encrypted disc image as a whole

## ISOB3 Metadata

Embedded `ISOB3` metadata is stored inside the ISO9660 Primary Volume Descriptor application data field.

- offset: `0x8373`
- size: `512` bytes
- magic: `ISOB3APP`
- digest algorithm: `BLAKE3-256`

## Linux Notes

Linux support currently depends on:

- `lsblk` for removable-media discovery in the GUI
- access permissions for mounted media and raw optical devices like `/dev/sr0`
- the bundled `tools/checkisomd5` binary for legacy `isomd5sum` verification
- `xorriso` for `isoenc bundle`

Current limitation:

- `isoenc bundle` rebuilds a fresh ISO from extracted files. It does not yet preserve original boot metadata or advanced image layout automatically.

## Build And Run

Build everything:

```bash
cargo build --release
```

Run the GUI:

```bash
cargo run --release --bin ISOB3GUI
```

Run the CLI:

```bash
cargo run --release --bin blake3iso -- check file.iso
```

Run the bundler:

```bash
cargo run --release --bin isoenc -- bundle input.iso --output encrypted.iso --password secret
```

## End-To-End Linux Test

This is the simplest manual end-to-end flow for `source ISO -> encrypted ISO -> mounted verification`.

Prerequisites:

- Linux
- `xorriso`
- Rust toolchain
- root or `sudo` access if you want to mount loopback ISOs

### 1. Build the tools

```bash
cargo build --release --bin blake3iso --bin isoenc
```

### 2. Create a source tree with a manifest

```bash
rm -rf demo-root demo-out
mkdir -p demo-root/verification demo-out
printf 'hello from demo\n' > demo-root/README.txt
printf 'build 1\n' > demo-root/BUILD.txt
(
  cd demo-root
  sha256sum README.txt BUILD.txt > verification/SHA256SUMS
)
```

### 3. Build a plaintext source ISO

```bash
xorriso -as mkisofs -r -J -o demo-out/plain.iso demo-root
```

### 4. Bundle an encrypted ISO and implant `ISOB3`

```bash
./target/release/isoenc bundle \
  demo-out/plain.iso \
  --output demo-out/encrypted.iso \
  --password secret \
  --exclude ./verification/ \
  --implant-isob3
```

### 5. Verify the rebuilt encrypted ISO itself

```bash
./target/release/blake3iso check demo-out/encrypted.iso
./target/release/blake3iso info demo-out/encrypted.iso
```

Expected result:

- `check` should report valid `ISOB3`
- this confirms the encrypted ISO image was not modified after bundling

### 6. Extract the rebuilt encrypted ISO and inspect its contents

```bash
rm -rf demo-out/extracted
mkdir -p demo-out/extracted
xorriso -osirrox on -indev demo-out/encrypted.iso -extract / demo-out/extracted
```

Confirm payload files were encrypted in place and the manifest stayed plaintext:

```bash
head -c 8 demo-out/extracted/README.txt
head -c 8 demo-out/extracted/BUILD.txt
head -c 8 demo-out/extracted/verification/SHA256SUMS
```

Expected result:

- `README.txt` starts with `DBENC003` by default
- `BUILD.txt` starts with `DBENC003` by default
- `verification/SHA256SUMS` should not start with `DBENC`

### 7. Decrypt the mounted or extracted payload files

```bash
./target/release/blake3iso decrypt demo-out/extracted/README.txt --password secret --output demo-out/README.dec.txt
./target/release/blake3iso decrypt demo-out/extracted/BUILD.txt --password secret --output demo-out/BUILD.dec.txt
```

### 8. Compare decrypted plaintext to expected content

```bash
printf 'hello from demo\n' > demo-out/README.expected.txt
printf 'build 1\n' > demo-out/BUILD.expected.txt
cmp demo-out/README.dec.txt demo-out/README.expected.txt
cmp demo-out/BUILD.dec.txt demo-out/BUILD.expected.txt
```

### 9. Confirm decrypted plaintext still matches the original manifest

```bash
(
  cd demo-out
  sha256sum README.dec.txt BUILD.dec.txt
)
cat demo-out/extracted/verification/SHA256SUMS
```

The digest values should match.

### 10. Test the same flow from a mounted ISO or burned disc

If you burn `demo-out/encrypted.iso` to optical media, or mount it locally, the verifier flow is the same:

1. scan the mounted disc in `ISOB3GUI`
2. enable encrypted-file support and enter the password
3. verify the SHA-256 manifest entries
4. verify disc-level embedded `ISOB3`

For raw-device verification on Linux, the GUI uses device paths such as `/dev/sr0`.

## Repository Layout

```text
.
|-- Cargo.toml
|-- src
|   |-- app.rs
|   |-- blake3iso_core.rs
|   |-- dbenc.rs
|   |-- encfile.rs
|   |-- isomd5.rs
|   |-- media.rs
|   |-- sha256sum.rs
|   `-- worker.rs
|-- tools
|   |-- checkisomd5
|   `-- checkisomd5.exe
`-- .github/workflows
```

## License

This project is released into the public domain under CC0 1.0.
