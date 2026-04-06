# Examples

Linux encrypted-ISO end-to-end example:

```bash
bash examples/linux_encrypted_iso_e2e.sh
```

What it does:

1. builds `blake3iso`, `discdecrypt`, and `isoenc`
2. creates a small source tree and SHA-256 manifest
3. builds a plaintext ISO
4. rebuilds it as an encrypted ISO with `ISOB3`
5. verifies the rebuilt ISO
6. extracts it again
7. decrypts payload files with both `blake3iso` and the embedded `discdecrypt`
8. compares decrypted plaintext with the original content

Requirements:

- Linux
- `xorriso`
- Rust toolchain
