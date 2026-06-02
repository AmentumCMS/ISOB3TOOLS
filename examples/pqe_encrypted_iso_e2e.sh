#!/usr/bin/env bash
#
# Post-quantum encrypted ISO end-to-end example.
#
# Demonstrates the full DBENC005 (ML-KEM-768 + XChaCha20-Poly1305) workflow:
#   - Key generation  (blake3iso keygen)
#   - Encryption      (direnc --public-key)
#   - ISO rebuild     (xorriso)
#   - ISOB3 implant   (blake3iso implant / check)
#   - Decryption      (discdecrypt --private-key)
#
# The encryption key (.ek) is the only thing needed to produce the disc.
# The decryption key (.dk) is kept secret by whoever receives the disc.
# Neither key ever needs to be on the disc itself.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_ROOT="$ROOT_DIR/examples/pqe-demo-root"
DEMO_OUT="$ROOT_DIR/examples/pqe-demo-out"
DEMO_STAGING="$DEMO_OUT/iso-staging"
KEY_PREFIX="$DEMO_OUT/release-key"

cd "$ROOT_DIR"

command -v xorriso >/dev/null 2>&1 || {
  echo "xorriso is required for this example." >&2
  exit 1
}

echo "Building blake3iso, discdecrypt, and direnc..."
cargo build --release --bin blake3iso --bin discdecrypt --bin direnc

echo
echo "=== Step 1: Generate ML-KEM-768 keypair ==="
# The .ek (encapsulation / public) key is safe to share with anyone who
# needs to produce encrypted discs.  The .dk (decapsulation / private) key
# is kept by the recipient and never leaves their machine.
rm -rf "$DEMO_OUT"
mkdir -p "$DEMO_OUT"
./target/release/blake3iso keygen --output "$KEY_PREFIX"
echo "  Public  key (safe to share): $KEY_PREFIX.ek  ($(wc -c < "$KEY_PREFIX.ek") bytes)"
echo "  Private key (keep secret):   $KEY_PREFIX.dk  ($(wc -c < "$KEY_PREFIX.dk") bytes)"

echo
echo "=== Step 2: Prepare demo source tree ==="
rm -rf "$DEMO_ROOT"
mkdir -p "$DEMO_ROOT/verification"
printf 'hello from pqe demo\n' > "$DEMO_ROOT/README.txt"
printf 'build 1\n'              > "$DEMO_ROOT/BUILD.txt"
(
  cd "$DEMO_ROOT"
  sha256sum README.txt BUILD.txt > verification/SHA256SUMS
)

echo
echo "=== Step 3: Build plaintext ISO ==="
xorriso -as mkisofs -r -J -V PQE_DEMO -o "$DEMO_OUT/plain.iso" "$DEMO_ROOT"

echo
echo "=== Step 4: Extract ISO into staging directory ==="
mkdir -p "$DEMO_STAGING"
xorriso -osirrox on -indev "$DEMO_OUT/plain.iso" -extract / "$DEMO_STAGING"

echo
echo "=== Step 5: Encrypt staging directory with the public key ==="
# --exclude keeps the SHA-256 manifest in plaintext so recipients can
# verify file integrity after decryption without trusting the encryptor.
./target/release/direnc "$DEMO_STAGING" \
  --public-key "$KEY_PREFIX.ek" \
  --exclude ./verification/

echo
echo "Confirming payload files carry DBENC005 headers..."
printf '  README.txt: '; head -c 8 "$DEMO_STAGING/README.txt"; echo
printf '  BUILD.txt:  '; head -c 8 "$DEMO_STAGING/BUILD.txt";  echo
printf '  verification/SHA256SUMS (plaintext, should NOT be DBENC005): '
head -c 8 "$DEMO_STAGING/verification/SHA256SUMS"; echo
test -f "$DEMO_STAGING/decryptor/discdecrypt"
test -f "$DEMO_STAGING/decryptor/discdecrypt.exe"
echo "  Bundled decryptor: OK"

echo
echo "=== Step 6: Rebuild encrypted ISO ==="
xorriso -as mkisofs -r -J -V PQE_DEMO -o "$DEMO_OUT/encrypted.iso" "$DEMO_STAGING"

echo
echo "=== Step 7: Implant and verify ISOB3 metadata ==="
./target/release/blake3iso implant "$DEMO_OUT/encrypted.iso"
./target/release/blake3iso check   "$DEMO_OUT/encrypted.iso"
./target/release/blake3iso info    "$DEMO_OUT/encrypted.iso"

echo
echo "=== Step 8: Decrypt (simulating the recipient) ==="
# The recipient runs the bundled discdecrypt directly from the disc and
# supplies only their private key — no password, no shared secret over the wire.
chmod +x "$DEMO_STAGING/decryptor/discdecrypt"
"$DEMO_STAGING/decryptor/discdecrypt" \
  --input      "$DEMO_STAGING" \
  --output     "$DEMO_OUT/decrypted-tree" \
  --private-key "$KEY_PREFIX.dk"

echo
echo "=== Step 9: Verify decrypted content ==="
printf 'hello from pqe demo\n' > "$DEMO_OUT/README.expected.txt"
printf 'build 1\n'              > "$DEMO_OUT/BUILD.expected.txt"

cmp "$DEMO_OUT/decrypted-tree/README.txt" "$DEMO_OUT/README.expected.txt"
cmp "$DEMO_OUT/decrypted-tree/BUILD.txt"  "$DEMO_OUT/BUILD.expected.txt"
cmp "$DEMO_OUT/decrypted-tree/verification/SHA256SUMS" "$DEMO_STAGING/verification/SHA256SUMS"
echo "  File content: OK"

(
  cd "$DEMO_OUT/decrypted-tree"
  sha256sum README.txt BUILD.txt > ../../"$DEMO_OUT/decrypted.hashes"
)
manifest_readme="$(awk '/README.txt$/ { print $1 }' "$DEMO_STAGING/verification/SHA256SUMS")"
manifest_build="$(awk '/BUILD.txt$/   { print $1 }' "$DEMO_STAGING/verification/SHA256SUMS")"
actual_readme="$(awk '/README.txt$/   { print $1 }' "$DEMO_OUT/decrypted.hashes")"
actual_build="$(awk '/BUILD.txt$/     { print $1 }' "$DEMO_OUT/decrypted.hashes")"
test "$manifest_readme" = "$actual_readme"
test "$manifest_build"  = "$actual_build"
echo "  SHA-256 manifest: OK"

echo
echo "=== Auto-discovery demo ==="
echo "If you copy the keys to ~/.isob3/default.{ek,dk}:"
echo "  blake3iso keygen              # writes to ~/.isob3/default.ek and .dk"
echo "  direnc iso-staging/           # finds ~/.isob3/default.ek automatically"
echo "  discdecrypt --input /media/disc --output ~/decrypted  # finds ~/.isob3/default.dk"
echo

echo "=== Example completed successfully ==="
echo "Encrypted ISO:    $DEMO_OUT/encrypted.iso"
echo "Decrypted output: $DEMO_OUT/decrypted-tree"
echo "Public key:       $KEY_PREFIX.ek  (share with disc producers)"
echo "Private key:      $KEY_PREFIX.dk  (keep secret, required to decrypt)"
