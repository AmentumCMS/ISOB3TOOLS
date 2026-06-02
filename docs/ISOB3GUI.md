# ISOB3GUI

Desktop application for verifying integrity of optical discs, removable media, and ISO files.

## Build

```bash
cargo build --release --bin ISOB3GUI
```

```bash
cargo run --release --bin ISOB3GUI
```

Available on Windows and Linux.

## Verification Flow

1. **Scan Drives** — discovers removable and optical drives. On Windows, raw optical devices appear as `\\.\CdRom0`. On Linux, they appear as `/dev/sr0` (or similar).
2. **Select drives** — check or uncheck discovered drives before starting.
3. **Verify Selected** — runs all verification checks across selected drives in parallel.

## Checks Performed

For each selected drive, the verifier searches for and runs:

- **SHA-256 manifest** (`SHA256SUMS` or similar) — verifies each listed file against its stored digest.
- **ISOB3** — verifies the embedded BLAKE3 digest in the ISO application data area.
- **ISOMD5** — falls back to `isomd5sum`-style metadata if ISOB3 is absent.

## Encrypted Files

Toggle **Encrypted files** in the toolbar to enable encrypted-payload verification.

When enabled, a password button appears. Click it to enter the shared DBENC password. The verifier will decrypt files in memory during SHA-256 manifest checks rather than comparing ciphertext.

## Controls

| Control | Description |
|---|---|
| **Scan Drives** | Discover removable and optical drives |
| **Verify Selected** | Start verification across checked drives |
| **Abort** | Stop verification in progress (with confirmation) |
| **Max workers** | Number of parallel verification workers (1–16) |
| **Encrypted files** | Enable encrypted-payload mode |
| **Password button** | Set or change the decryption password |
| **Select All / Clear** | Select or deselect all discovered drives |
| Drive name link | Open the per-drive detail window |
| **About** | Show credits and feature summary |

## Results Table

The main results table shows one row per check with:

- Drive name
- Check type (ISOB3 / ISOMD5)
- Subject (filename or device)
- Source (manifest or embedded metadata)
- Pass / Fail status
- Check time in seconds
- Summary line

Click a drive name in the drive list to open a detail window with full per-file results including byte counts and raw detail text.

## Progress

The progress bar and status line show:

- checks complete / total
- data processed and estimated total
- elapsed time, average time per check, and live throughput

## Platform Notes

**Windows** — raw optical devices are accessed through `\\.\CdRom0`, `\\.\CdRom1`, etc.

**Linux** — raw optical devices are accessed through `/dev/sr0`, `/dev/sr1`, etc. The tool uses `lsblk` for removable-media discovery. Access to raw device nodes may require appropriate group membership or `sudo`.
