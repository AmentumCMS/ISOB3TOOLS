# discdecrypt

Decrypt DBENC files from an extracted or mounted disc into an output folder.

`discdecrypt` ships bundled inside every disc produced by `direnc`. End users run it directly from the disc without needing to install anything separately.

## Build

```bash
cargo build --release --bin discdecrypt
```

Available on Linux and Windows.

## Modes

`discdecrypt` has two modes depending on how it is invoked:

- **CLI mode** — when any argument is passed, runs non-interactively.
- **GUI mode** — when run with no arguments, opens a small desktop window (Windows and Linux).

## CLI Usage

```
discdecrypt [OPTIONS]
```

| Argument | Type | Required | Description |
|---|---|---|---|
| `--input <PATH>` | path | no | Root of the disc or extracted directory (default: current directory `.`) |
| `--output <PATH>` | path | no | Output directory for decrypted files (prompted if omitted) |
| `--password <PASSWORD>` | string | no | Decryption password for DBENC001–003 files (prompted if omitted and `--private-key` not given) |
| `--private-key <FILE>` | path | no | ML-KEM-768 decapsulation key (`.dk`) for DBENC005 (post-quantum) files |

Provide `--password` for password-encrypted discs or `--private-key` for PQE-encrypted discs. If neither is supplied and no `--private-key` is given, the tool prompts for a password interactively.

Per-file format detection: each file's DBENC header is checked independently. A DBENC005 file requires `--private-key`; other DBENC files require `--password`.

Examples:

```bash
# Password-encrypted disc
discdecrypt --input /media/disc --output ~/decrypted --password secret

# PQE-encrypted disc
discdecrypt --input /media/disc --output ~/decrypted --private-key release-2026.dk

# Let the tool prompt for password
discdecrypt --input /media/disc --output ~/decrypted

# Use current directory as input
discdecrypt --output ~/decrypted --password secret
```

Using the convenience script bundled on the disc (input defaults to the disc root automatically):

```bash
chmod +x /media/disc/decryptor/decrypt.sh
/media/disc/decryptor/decrypt.sh --output ~/decrypted --password secret
```

## GUI Mode

Run `discdecrypt` with no arguments to open the GUI.

The GUI provides:

- Input folder field with a Browse button
- Output folder field with a Browse button
- Password field
- Decrypt button with live status output

The Browse button is only implemented on Windows (uses the system folder picker). On Linux, type the path directly.

## Behavior

`discdecrypt` walks the input directory recursively and for each file:

- If the file starts with a `DBENC` header: decrypts it into the output directory at the same relative path.
- Otherwise: copies the file unchanged (manifests and other plaintext files pass through).

The `decryptor/` subdirectory within the input tree is always skipped — the tool does not copy itself into the output.

The output directory must be outside the input tree. If the output path is inside the input, the tool exits with an error before writing anything.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `2` | Operational error (bad path, decryption failure, wrong password, etc.) |
