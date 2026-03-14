# ISOB3TOOLS

Rust tools for verifying, implanting, removing, and benchmarking **ISOB3
integrity trailers** on ISO files.

This repository provides:

-   **blake3verifier** --- a GUI application for scanning
    removable/optical media and verifying ISO files
-   **blake3iso** --- a CLI utility for implanting, checking, removing,
    and inspecting ISOB3 trailers
-   **benchmark example** --- a performance comparison tool for MD5 vs
    BLAKE3 hashing

The tools support both modern **BLAKE3 verification** and legacy
**isomd5sum verification**.

------------------------------------------------------------------------

# Overview

ISOB3TOOLS introduces a simple trailer format called **ISOB3** that is
appended to the end of an ISO-like file.

The trailer stores:

-   magic identifier
-   version
-   algorithm identifier
-   digest length
-   original payload size
-   **BLAKE3-256 digest** of the original file contents

This allows verification of the original ISO data **without modifying
the payload bytes**.

The project also supports detecting and validating older **isomd5sum
implanted images** commonly used by some Linux distributions.

------------------------------------------------------------------------

# Components

## blake3verifier (GUI)

The GUI verifier scans mounted media and verifies ISO files
automatically.

Features:

-   Detects removable media and optical drives
-   Recursively scans for `.iso` files
-   Verifies files using:
    -   **ISOB3 trailers**
    -   **isomd5sum implants**
-   Displays verification results in a GUI table
-   Optionally embeds ISOB3 trailers into ISO files that lack integrity
    metadata

### Verification order

Each ISO is processed as follows:

1.  Check for an **ISOB3 trailer**
2.  If none exists, check for an **isomd5sum implant**
3.  If detected, run the embedded `checkisomd5` tool
4.  If neither exists, report the file as missing integrity metadata

------------------------------------------------------------------------

## blake3iso (CLI)

A command-line tool for managing ISOB3 trailers.

Supported commands:

-   implant
-   check
-   remove
-   info

The CLI works with any ISO-like file regardless of extension.

------------------------------------------------------------------------

## Benchmark Example

The benchmark utility compares hashing performance for:

-   MD5
-   BLAKE3
-   BLAKE3 using memory mapping

It reports throughput statistics and identifies the fastest
configuration.

------------------------------------------------------------------------

# ISOB3 Trailer Format

The trailer is appended to the end of the file and is **56 bytes** long.

Field                   Size
  ----------------------- ----------
Magic (`ISOB3TR1`)      8 bytes
Version                 1 byte
Algorithm               1 byte
Digest length           2 bytes
Reserved                4 bytes
Original payload size   8 bytes
BLAKE3 digest           32 bytes

Current constants:

-   Magic: ISOB3TR1
-   Version: 1
-   Algorithm: BLAKE3-256
-   Trailer size: 56 bytes

------------------------------------------------------------------------

# Requirements

You must have Rust installed.

Install Rust from:

https://www.rust-lang.org/tools/install

------------------------------------------------------------------------

# Building

Build the project:

    cargo build --release

------------------------------------------------------------------------

# Running

Run the GUI verifier:

    cargo run --release

Run the CLI tool:

    cargo run --release --bin blake3iso -- <command> <file>

Run the benchmark:

    cargo run --release --example benchmark -- <file> --rounds 3

------------------------------------------------------------------------

# CLI Usage

## Implant a trailer

    cargo run --release --bin blake3iso -- implant example.iso

Force replacement:

    cargo run --release --bin blake3iso -- implant example.iso --force

Operation:

1.  Determine payload size
2.  Compute BLAKE3 hash
3.  Append the 56-byte trailer

------------------------------------------------------------------------

## Verify a trailer

    cargo run --release --bin blake3iso -- check example.iso

Example output:

Payload size : 7459616824 Stored BLAKE3: `<stored hash>`{=html} Actual
BLAKE3: `<computed hash>`{=html} VALID

Exit codes:

-   0 = valid
-   1 = invalid
-   2 = error

------------------------------------------------------------------------

## Remove a trailer

    cargo run --release --bin blake3iso -- remove example.iso

------------------------------------------------------------------------

## Display trailer information

    cargo run --release --bin blake3iso -- info example.iso

------------------------------------------------------------------------

# GUI Behavior

Click **Scan Media**.

The application will:

1.  Enumerate removable and optical media
2.  Recursively search for `.iso` files
3.  Verify each ISO
4.  Display results in the results table

Possible statuses:

-   VALID-ISOB3
-   VALID-ISOMD5
-   INVALID

Possible details:

-   ISOB3 valid (`<hash>`{=html})
-   ISOB3 mismatch
-   ISOMD5 valid (`<hash>`{=html})
-   ISOMD5 invalid
-   No ISOB3 trailer or isomd5sum implant

------------------------------------------------------------------------

# Project Structure

    ISOB3TOOLS
    ├── Cargo.toml
    ├── src
    │   ├── main.rs
    │   └── blake3iso.rs
    ├── examples
    │   └── benchmark.rs
    └── tools
        ├── checkisomd5
        └── checkisomd5.exe

------------------------------------------------------------------------

# Notes

Appending an ISOB3 trailer increases the file size by 56 bytes but does
**not modify the original payload bytes**.

Removing the trailer restores the original file size exactly.

------------------------------------------------------------------------

# Summary

ISOB3TOOLS provides:

-   GUI media verification
-   CLI trailer management
-   compatibility with legacy isomd5sum
-   high-speed BLAKE3 hashing
-   benchmarking tools
