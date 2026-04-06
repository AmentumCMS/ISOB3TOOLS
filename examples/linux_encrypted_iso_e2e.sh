#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_ROOT="$ROOT_DIR/examples/demo-root"
DEMO_OUT="$ROOT_DIR/examples/demo-out"

cd "$ROOT_DIR"

command -v xorriso >/dev/null 2>&1 || {
  echo "xorriso is required for this example." >&2
  exit 1
}

echo "Building blake3iso, discdecrypt, and isoenc..."
cargo build --release --bin blake3iso --bin discdecrypt --bin isoenc

echo "Preparing demo source tree..."
rm -rf "$DEMO_ROOT" "$DEMO_OUT"
mkdir -p "$DEMO_ROOT/verification" "$DEMO_OUT"
printf 'hello from demo\n' > "$DEMO_ROOT/README.txt"
printf 'build 1\n' > "$DEMO_ROOT/BUILD.txt"
(
  cd "$DEMO_ROOT"
  sha256sum README.txt BUILD.txt > verification/SHA256SUMS
)

echo "Building plaintext source ISO..."
xorriso -as mkisofs -r -J -o "$DEMO_OUT/plain.iso" "$DEMO_ROOT"

echo "Bundling encrypted ISO and implanting ISOB3..."
./target/release/isoenc bundle \
  "$DEMO_OUT/plain.iso" \
  --output "$DEMO_OUT/encrypted.iso" \
  --password secret \
  --exclude ./verification/ \
  --implant-isob3

echo "Checking rebuilt encrypted ISO..."
./target/release/blake3iso check "$DEMO_OUT/encrypted.iso"
./target/release/blake3iso info "$DEMO_OUT/encrypted.iso"

echo "Extracting rebuilt encrypted ISO..."
rm -rf "$DEMO_OUT/extracted"
mkdir -p "$DEMO_OUT/extracted"
xorriso -osirrox on -indev "$DEMO_OUT/encrypted.iso" -extract / "$DEMO_OUT/extracted"

echo "Inspecting encrypted payload headers..."
echo -n "README.txt header: "
head -c 8 "$DEMO_OUT/extracted/README.txt"
echo
echo -n "BUILD.txt header: "
head -c 8 "$DEMO_OUT/extracted/BUILD.txt"
echo
echo -n "verification/SHA256SUMS header: "
head -c 8 "$DEMO_OUT/extracted/verification/SHA256SUMS"
echo
test -f "$DEMO_OUT/extracted/decryptor/discdecrypt"
test -f "$DEMO_OUT/extracted/decryptor/decrypt.sh"

echo "Decrypting payload files..."
./target/release/blake3iso decrypt \
  "$DEMO_OUT/extracted/README.txt" \
  --password secret \
  --output "$DEMO_OUT/README.dec.txt"
./target/release/blake3iso decrypt \
  "$DEMO_OUT/extracted/BUILD.txt" \
  --password secret \
  --output "$DEMO_OUT/BUILD.dec.txt"

echo "Running embedded discdecrypt..."
chmod +x "$DEMO_OUT/extracted/decryptor/discdecrypt"
"$DEMO_OUT/extracted/decryptor/discdecrypt" \
  --input "$DEMO_OUT/extracted" \
  --output "$DEMO_OUT/decrypted-tree" \
  --password secret

printf 'hello from demo\n' > "$DEMO_OUT/README.expected.txt"
printf 'build 1\n' > "$DEMO_OUT/BUILD.expected.txt"

echo "Comparing decrypted plaintext with expected content..."
cmp "$DEMO_OUT/README.dec.txt" "$DEMO_OUT/README.expected.txt"
cmp "$DEMO_OUT/BUILD.dec.txt" "$DEMO_OUT/BUILD.expected.txt"
cmp "$DEMO_OUT/decrypted-tree/README.txt" "$DEMO_OUT/README.expected.txt"
cmp "$DEMO_OUT/decrypted-tree/BUILD.txt" "$DEMO_OUT/BUILD.expected.txt"
cmp "$DEMO_OUT/decrypted-tree/verification/SHA256SUMS" "$DEMO_OUT/extracted/verification/SHA256SUMS"

echo "Computing hashes for decrypted plaintext..."
(
  cd "$DEMO_OUT"
  sha256sum README.dec.txt BUILD.dec.txt > decrypted.hashes
)

echo "Original manifest:"
cat "$DEMO_OUT/extracted/verification/SHA256SUMS"
echo
echo "Decrypted plaintext hashes:"
cat "$DEMO_OUT/decrypted.hashes"

echo
echo "Example completed successfully."
echo "Output directory: $DEMO_OUT"
