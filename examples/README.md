# Examples

Linux encrypted-ISO end-to-end example:

```bash
bash examples/linux_encrypted_iso_e2e.sh
```

What it does:

1. builds `blake3iso`, `discdecrypt`, and `direnc`
2. creates a small source tree and SHA-256 manifest
3. builds a plaintext source ISO
4. extracts it into a staging directory
5. encrypts the staging directory with `direnc` and injects the decryptor
6. rebuilds the encrypted ISO with `xorriso`
7. implants `ISOB3` with `blake3iso`
8. verifies the rebuilt ISO
9. decrypts payload files with both `blake3iso` and the embedded `discdecrypt`
10. compares decrypted plaintext with the original content

Requirements:

- Linux
- `xorriso`
- Rust toolchain
