# Examples

## Password-encrypted ISO (Argon2id / DBENC004)

```bash
bash examples/linux_encrypted_iso_e2e.sh
```

What it does:

1. Builds `blake3iso`, `discdecrypt`, and `direnc`
2. Creates a small source tree and SHA-256 manifest
3. Builds a plaintext source ISO
4. Extracts it into a staging directory
5. Encrypts the staging directory with `direnc --password` and injects the decryptor
6. Rebuilds the encrypted ISO with `xorriso`
7. Implants ISOB3 with `blake3iso`
8. Verifies the rebuilt ISO
9. Decrypts with the embedded `discdecrypt` and compares plaintext

Requirements: Linux, `xorriso`, Rust toolchain

---

## Post-quantum encrypted ISO (ML-KEM-768 / DBENC005)

```bash
bash examples/pqe_encrypted_iso_e2e.sh
```

What it does:

1. Generates an ML-KEM-768 keypair with `blake3iso keygen`
2. Creates a small source tree and SHA-256 manifest
3. Builds a plaintext source ISO
4. Extracts it into a staging directory
5. Encrypts with `direnc --public-key` — only the public key is needed to produce the disc
6. Rebuilds the encrypted ISO with `xorriso`
7. Implants and verifies ISOB3 with `blake3iso`
8. Decrypts with `discdecrypt --private-key` — only the private key can decrypt

Key properties demonstrated:

- The public key (`.ek`) can be safely shared with anyone who produces discs
- The private key (`.dk`) stays with the recipient — it never touches the disc
- Neither key is a password; there is nothing to remember, share over voice, or guess

Requirements: Linux, `xorriso`, Rust toolchain
