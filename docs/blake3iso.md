# blake3iso

CLI for ISOB3 ISO integrity operations.

## Build

```bash
cargo build --release --bin blake3iso
```

## Subcommands

### implant

Embed ISOB3 (BLAKE3) metadata into an ISO's application data area.

```
blake3iso implant <FILE> [OPTIONS]
```

| Argument | Type | Required | Description |
|---|---|---|---|
| `FILE` | path | yes | ISO file to implant |
| `--force` | flag | no | Overwrite existing ISOB3 metadata if already present |

Examples:

```bash
blake3iso implant release.iso
blake3iso implant release.iso --force
```

---

### check

Verify the integrity of an ISO or raw optical device.

```
blake3iso check <FILE>
```

| Argument | Type | Required | Description |
|---|---|---|---|
| `FILE` | path | yes | ISO file or raw device path (e.g. `/dev/sr0`, `\\.\CdRom0`) |

Behavior:

- Checks embedded ISOB3 metadata.
- If no ISOB3 metadata is found: falls back to ISOMD5 if present.
- If no metadata of any kind is found: exits with code `2`.

Examples:

```bash
blake3iso check release.iso
blake3iso check /dev/sr0
```

---

### info

Display integrity metadata stored in an ISO.

```
blake3iso info <FILE>
```

| Argument | Type | Required | Description |
|---|---|---|---|
| `FILE` | path | yes | ISO file or raw device path |

Shows ISOB3 metadata if present, or ISOMD5 info as a fallback.

Examples:

```bash
blake3iso info release.iso
```

---

### remove

Strip ISOB3 metadata from an ISO.

```
blake3iso remove <FILE>
```

| Argument | Type | Required | Description |
|---|---|---|---|
| `FILE` | path | yes | ISO file to strip |

Zeroes the ISOB3 region in the application data area. Does not modify file contents outside that region.

Examples:

```bash
blake3iso remove release.iso
```

---

### keygen

Generate an ML-KEM-768 keypair for DBENC005 (post-quantum) encryption.

```
blake3iso keygen [--output <PREFIX>]
```

| Argument | Type | Required | Description |
|---|---|---|---|
| `--output` | prefix path | no | Base name for key files (e.g. `mykey` → `mykey.ek` and `mykey.dk`). Defaults to `~/.isob3/default`. |

Output:
- `<PREFIX>.ek` — encapsulation key (public, 1184 bytes). Give this to `direnc --public-key` for DBENC005.
- `<PREFIX>.dk` — decapsulation key (private seed, 64 bytes). Keep this secret; give it to `discdecrypt --private-key`.

If keys are placed at `~/.isob3/default.ek` and `~/.isob3/default.dk`, `direnc` and `discdecrypt` will discover them automatically when no key flag is given.

Examples:

```bash
# Write to default location (~/.isob3/default.ek and .dk)
blake3iso keygen

# Write to an explicit prefix
blake3iso keygen --output release-2026
# Writes release-2026.ek and release-2026.dk
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Valid / success |
| `1` | Invalid (integrity check failed) |
| `2` | Operational error or missing metadata |
