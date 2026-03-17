# ISOB3TOOLS

Rust tools for verifying, implanting, removing, and benchmarking **ISOB3 integrity metadata** on ISO files.

---

# Overview

ISOB3TOOLS provides both a GUI and CLI for validating ISO integrity using:

- **Modern BLAKE3-based metadata (ISOB3)**
- **Legacy isomd5sum support (fallback compatibility)**

Unlike traditional trailer approaches, ISOB3 stores metadata inside the ISO **Application Data field** (Primary Volume Descriptor), making it far more resilient to burning and copying.

---

# Components

## blake3verifier (GUI)

A desktop application for scanning and verifying media.

Features:
- Detects optical drives and removable media
- Displays friendly names (e.g., `G:` instead of `CdRom0`)
- Recursively scans for `.iso` files
- Verifies using:
    - ISOB3 metadata
    - isomd5sum fallback
- Multi-threaded scanning
- Real-time results display
- About dialog with credits

---

## blake3iso (CLI)

Command-line tool for ISO integrity operations.

Commands:
- `implant`
- `check`
- `remove`
- `info`

Works with:
- Files
- Mounted drives
- Raw devices (`\\.\CdRomX`)

---

## Benchmark Example

Compare hashing performance:

- MD5
- BLAKE3
- BLAKE3 (various chunk sizes)

---

# ISOB3 Metadata Format

Stored inside ISO9660 Primary Volume Descriptor **Application Data (512 bytes)**

Offset: `0x8373`

Structure:

| Field          | Size |
|----------------|------|
| Magic          | 8    |
| Version        | 1    |
| Algorithm      | 1    |
| Digest Length  | 2    |
| Flags          | 4    |
| Digest         | 32   |

Constants:
- Magic: `ISOB3APP`
- Algorithm: BLAKE3-256

---

# Verification Flow

1. Check ISOB3 metadata
2. If missing → check isomd5sum
3. If found → run embedded checker
4. Otherwise → report missing metadata

---

# Requirements

Install Rust:
https://www.rust-lang.org/tools/install

---

# Build

```bash
cargo build --release
```

---

# Run

GUI:
```bash
cargo run --release
```

CLI:
```bash
cargo run --release --bin blake3iso -- <command> <file>
```

---

# CLI Usage

## Implant

```bash
blake3iso implant file.iso
```

Force overwrite:
```bash
blake3iso implant file.iso --force
```

## Check

```bash
blake3iso check file.iso
```

Exit codes:
- 0 = valid
- 1 = invalid
- 2 = error/missing

## Remove

```bash
blake3iso remove file.iso
```

## Info

```bash
blake3iso info file.iso
```

---

# GUI Usage

Click **Scan Media**

The app will:
1. Detect drives
2. Scan for ISOs
3. Verify each
4. Display results

---

# Project Structure

```
ISOB3TOOLS
├── Cargo.toml
├── src
│   ├── main.rs
│   ├── blake3iso_core.rs
│   ├── worker.rs
│   ├── media.rs
│   └── isomd5.rs
├── examples
│   └── benchmark.rs
└── tools
    ├── checkisomd5
    └── checkisomd5.exe
```

---

# Notes

- Metadata survives DVD burns (unlike trailers)
- Payload bytes are never modified
- Verification avoids double-reading unnecessary regions

---

# Credits

- Inspired by isomd5sum
- Windows port inspiration by John Pappas  
  https://github.com/thepappas
- BLAKE3 hashing  
  https://github.com/BLAKE3-team/BLAKE3

---

# License

This project is released into the public domain (CC0 1.0).

Alternatively licensed under:
- Apache 2.0
- Apache 2.0 with LLVM exceptions
