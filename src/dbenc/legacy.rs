//! DBENC001 — Legacy AES-256-CBC + PBKDF2-HMAC-SHA256 encryption.
//!
//! ## File layout
//!
//! ```text
//! [0..48]       Header: magic(8) | salt(16) | iv(16) | pbkdf2_rounds_le(4) | padding(4)
//! [48..80]      HMAC-SHA256 over header || ciphertext (covers integrity)
//! [80..]        AES-256-CBC ciphertext with PKCS#7 padding
//! ```
//!
//! PBKDF2 derives a 64-byte key block: bytes 0–31 are the AES-256 key,
//! bytes 32–63 are the HMAC-SHA256 key.
//!
//! This format is retained for backwards compatibility.  New files should use
//! DBENC004 (Argon2id) or DBENC005 (PQE) instead.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit as CipherKeyInit};
use aes::{Aes256, Block};
use hmac::{KeyInit as HmacKeyInit, Mac};
use sha2::{Digest, Sha256};

use super::{
    AEAD_CHUNK_SIZE, AES_BLOCK_SIZE, DecryptedFile, DecryptedTempFile, HmacSha256,
    LEGACY_HEADER_LEN, LEGACY_IV_LEN, LEGACY_MAC_LEN, LEGACY_PBKDF2_ROUNDS, LEGACY_SALT_LEN,
    LegacyHeader, MAGIC_DBENC001, cleanup_temp_file, ensure_parent_dir, hex_digest, make_temp_path,
    pbkdf2_hmac_sha256,
};

// ── Encryption ─────────────────────────────────────────────────────────────────

/// Build a fresh [`LegacyHeader`] with random salt and IV, deriving keys from `password`.
fn build_legacy_header(password: &str) -> Result<LegacyHeader, String> {
    use super::fill_random;
    let mut salt = [0u8; LEGACY_SALT_LEN];
    let mut iv = [0u8; LEGACY_IV_LEN];
    fill_random(&mut salt)?;
    fill_random(&mut iv)?;
    let mut header = [0u8; LEGACY_HEADER_LEN];
    header[..8].copy_from_slice(MAGIC_DBENC001);
    header[8..24].copy_from_slice(&salt);
    header[24..40].copy_from_slice(&iv);
    header[40..44].copy_from_slice(&LEGACY_PBKDF2_ROUNDS.to_le_bytes());
    parse_legacy_header(&header, &[0u8; LEGACY_MAC_LEN], password)
}

/// Encrypt `source_path` → `destination_path` using DBENC001.
///
/// Writes the header, a placeholder MAC, the CBC ciphertext, then seeks
/// back to patch in the real HMAC over header + ciphertext.
pub(super) fn encrypt_legacy_file_to_path(
    source_path: &Path,
    destination_path: &Path,
    password: &str,
) -> Result<u64, String> {
    let mut source = File::open(source_path).map_err(|e| format!("open source failed: {e}"))?;
    let parsed = build_legacy_header(password)?;
    ensure_parent_dir(destination_path)?;
    let mut destination = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(destination_path)
        .map_err(|e| format!("open destination failed: {e}"))?;

    destination
        .write_all(&parsed.header)
        .map_err(|e| format!("write failed: {e}"))?;
    // Write a zero placeholder — will be patched below with the real HMAC.
    destination
        .write_all(&[0u8; LEGACY_MAC_LEN])
        .map_err(|e| format!("write failed: {e}"))?;

    let ciphertext_bytes = encrypt_legacy_stream_to_writer(&mut source, &mut destination, &parsed)?;

    // Compute HMAC over header + ciphertext and patch it in.
    let mut hmac = <HmacSha256 as HmacKeyInit>::new_from_slice(&parsed.mac_key)
        .map_err(|e| format!("hmac init failed: {e}"))?;
    hmac.update(&parsed.header);
    destination
        .flush()
        .map_err(|e| format!("flush failed: {e}"))?;
    let mut encrypted =
        File::open(destination_path).map_err(|e| format!("re-open destination failed: {e}"))?;
    encrypted
        .seek(SeekFrom::Start((LEGACY_HEADER_LEN + LEGACY_MAC_LEN) as u64))
        .map_err(|e| format!("seek failed: {e}"))?;
    let mut buf = vec![0u8; AEAD_CHUNK_SIZE];
    loop {
        let read = encrypted
            .read(&mut buf)
            .map_err(|e| format!("read failed: {e}"))?;
        if read == 0 {
            break;
        }
        hmac.update(&buf[..read]);
    }
    let mac = hmac.finalize().into_bytes();
    destination
        .seek(SeekFrom::Start(LEGACY_HEADER_LEN as u64))
        .map_err(|e| format!("seek failed: {e}"))?;
    destination
        .write_all(&mac)
        .map_err(|e| format!("write failed: {e}"))?;
    destination
        .flush()
        .map_err(|e| format!("flush failed: {e}"))?;
    Ok(ciphertext_bytes)
}

// ── Decryption ─────────────────────────────────────────────────────────────────

/// Parse and validate the DBENC001 header from a file on disk.
fn parse_legacy_header_from_file(path: &Path, password: &str) -> Result<LegacyHeader, String> {
    let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut header = [0u8; LEGACY_HEADER_LEN];
    file.read_exact(&mut header)
        .map_err(|e| format!("read failed: {e}"))?;
    let mut mac = [0u8; LEGACY_MAC_LEN];
    file.read_exact(&mut mac)
        .map_err(|e| format!("read failed: {e}"))?;
    parse_legacy_header(&header, &mac, password)
}

/// Parse and derive keys from a raw DBENC001 header + MAC byte slice.
pub(super) fn parse_legacy_header(
    header: &[u8],
    mac: &[u8],
    password: &str,
) -> Result<LegacyHeader, String> {
    let header: [u8; LEGACY_HEADER_LEN] = header
        .try_into()
        .map_err(|_| "invalid DBENC001 header length".to_string())?;
    let mac: [u8; LEGACY_MAC_LEN] = mac
        .try_into()
        .map_err(|_| "invalid DBENC001 MAC length".to_string())?;
    if &header[..8] != MAGIC_DBENC001 {
        return Err("missing DBENC001 header".to_string());
    }
    let salt = &header[8..24];
    let iv: [u8; LEGACY_IV_LEN] = header[24..40]
        .try_into()
        .map_err(|_| "invalid IV field".to_string())?;
    let iterations = u32::from_le_bytes(
        header[40..44]
            .try_into()
            .map_err(|_| "invalid PBKDF2 rounds field".to_string())?,
    );
    if iterations != LEGACY_PBKDF2_ROUNDS {
        return Err(format!(
            "unsupported PBKDF2 rounds: expected {LEGACY_PBKDF2_ROUNDS}, found {iterations}"
        ));
    }
    let mut key_material = [0u8; 64];
    pbkdf2_hmac_sha256(password.as_bytes(), salt, iterations, &mut key_material);
    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&key_material[..32]);
    let mut mac_key = [0u8; 32];
    mac_key.copy_from_slice(&key_material[32..64]);
    Ok(LegacyHeader {
        header,
        mac,
        enc_key,
        mac_key,
        iv,
    })
}

/// Decrypt an in-memory DBENC001 ciphertext blob, verifying the HMAC first.
pub(super) fn decrypt_legacy_bytes(bytes: &[u8], password: &str) -> Result<DecryptedFile, String> {
    if bytes.len() < LEGACY_HEADER_LEN + LEGACY_MAC_LEN {
        return Err("encrypted file too small".to_string());
    }
    let parsed = parse_legacy_header(
        &bytes[..LEGACY_HEADER_LEN],
        &bytes[LEGACY_HEADER_LEN..LEGACY_HEADER_LEN + LEGACY_MAC_LEN],
        password,
    )?;
    let cipher_bytes = &bytes[LEGACY_HEADER_LEN + LEGACY_MAC_LEN..];
    let mut hmac = <HmacSha256 as HmacKeyInit>::new_from_slice(&parsed.mac_key)
        .map_err(|e| format!("hmac init failed: {e}"))?;
    hmac.update(&parsed.header);
    hmac.update(cipher_bytes);
    hmac.verify_slice(&parsed.mac)
        .map_err(|_| "password incorrect or file integrity check failed".to_string())?;
    let (plaintext, _) = decrypt_legacy_cbc_bytes(cipher_bytes, &parsed.enc_key, &parsed.iv)?;
    Ok(DecryptedFile {
        plaintext,
        cipher_bytes: cipher_bytes.len() as u64,
    })
}

/// Decrypt a DBENC001 file on disk to a temporary file.
pub(super) fn decrypt_legacy_file_to_temp<F, G>(
    path: &Path,
    password: &str,
    progress: &mut F,
    should_abort: &mut G,
) -> Result<DecryptedTempFile, String>
where
    F: FnMut(u64),
    G: FnMut() -> bool,
{
    let parsed = parse_legacy_header_from_file(path, password)?;
    let cipher_bytes = verify_legacy_hmac(path, &parsed, progress, should_abort)?;
    decrypt_legacy_ciphertext_to_temp(path, &parsed, cipher_bytes, progress, should_abort)
}

/// Stream over the ciphertext section to verify the HMAC before decrypting.
///
/// Returns the total number of ciphertext bytes read.
fn verify_legacy_hmac<F, G>(
    path: &Path,
    parsed: &LegacyHeader,
    progress: &mut F,
    should_abort: &mut G,
) -> Result<u64, String>
where
    F: FnMut(u64),
    G: FnMut() -> bool,
{
    let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    file.seek(SeekFrom::Start((LEGACY_HEADER_LEN + LEGACY_MAC_LEN) as u64))
        .map_err(|e| format!("seek failed: {e}"))?;
    let mut hmac = <HmacSha256 as HmacKeyInit>::new_from_slice(&parsed.mac_key)
        .map_err(|e| format!("hmac init failed: {e}"))?;
    hmac.update(&parsed.header);
    let mut total = 0u64;
    let mut buf = vec![0u8; AEAD_CHUNK_SIZE];
    loop {
        if should_abort() {
            return Err("operation aborted".to_string());
        }
        let read = file
            .read(&mut buf)
            .map_err(|e| format!("read failed: {e}"))?;
        if read == 0 {
            break;
        }
        hmac.update(&buf[..read]);
        total += read as u64;
        progress(read as u64);
    }
    hmac.verify_slice(&parsed.mac)
        .map_err(|_| "password incorrect or file integrity check failed".to_string())?;
    Ok(total)
}

/// Allocate the temp file and call the writer.  Cleans up on error.
fn decrypt_legacy_ciphertext_to_temp<F, G>(
    path: &Path,
    parsed: &LegacyHeader,
    cipher_bytes: u64,
    progress: &mut F,
    should_abort: &mut G,
) -> Result<DecryptedTempFile, String>
where
    F: FnMut(u64),
    G: FnMut() -> bool,
{
    if cipher_bytes == 0 || !cipher_bytes.is_multiple_of(AES_BLOCK_SIZE as u64) {
        return Err("ciphertext length is invalid for AES-CBC".to_string());
    }
    let temp_path = make_temp_path("dbenc001-dec", Some(path));
    let result =
        decrypt_legacy_ciphertext_to_writer(path, parsed, &temp_path, progress, should_abort);
    if result.is_err() {
        cleanup_temp_file(&temp_path);
    }
    result
}

/// Stream-decrypt the CBC ciphertext section into `temp_path`, computing a
/// running SHA-256 of the plaintext for later comparison.
fn decrypt_legacy_ciphertext_to_writer<F, G>(
    path: &Path,
    parsed: &LegacyHeader,
    temp_path: &Path,
    progress: &mut F,
    should_abort: &mut G,
) -> Result<DecryptedTempFile, String>
where
    F: FnMut(u64),
    G: FnMut() -> bool,
{
    let mut reader = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    reader
        .seek(SeekFrom::Start((LEGACY_HEADER_LEN + LEGACY_MAC_LEN) as u64))
        .map_err(|e| format!("seek failed: {e}"))?;
    let mut writer = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(temp_path)
        .map_err(|e| format!("failed to create temp file {}: {e}", temp_path.display()))?;
    let cipher = <Aes256 as CipherKeyInit>::new_from_slice(&parsed.enc_key)
        .map_err(|e| format!("cipher init failed: {e}"))?;
    let mut prev_block = parsed.iv;
    let mut pending = Vec::with_capacity(AEAD_CHUNK_SIZE + AES_BLOCK_SIZE);
    let mut buf = vec![0u8; AEAD_CHUNK_SIZE];
    let mut sha = Sha256::new();
    let mut plaintext_bytes = 0u64;

    loop {
        if should_abort() {
            return Err("operation aborted".to_string());
        }
        let read = reader
            .read(&mut buf)
            .map_err(|e| format!("read failed: {e}"))?;
        if read == 0 {
            break;
        }
        pending.extend_from_slice(&buf[..read]);
        // Decrypt all complete blocks, leaving one block in `pending` for
        // PKCS#7 un-padding after the last read.
        while pending.len() > AES_BLOCK_SIZE {
            if should_abort() {
                return Err("operation aborted".to_string());
            }
            let block = pending[..AES_BLOCK_SIZE].to_vec();
            let plaintext_block = decrypt_legacy_cbc_block(&cipher, &block, &prev_block);
            writer
                .write_all(&plaintext_block)
                .map_err(|e| format!("temp write failed: {e}"))?;
            sha.update(plaintext_block);
            plaintext_bytes += plaintext_block.len() as u64;
            progress(plaintext_block.len() as u64);
            prev_block.copy_from_slice(&block);
            pending.drain(..AES_BLOCK_SIZE);
        }
    }

    // Last block — strip PKCS#7 padding.
    if pending.len() != AES_BLOCK_SIZE {
        return Err("ciphertext ended with an incomplete AES block".to_string());
    }
    let final_plaintext = decrypt_legacy_cbc_block(&cipher, &pending, &prev_block);
    let pad_len = *final_plaintext
        .last()
        .ok_or_else(|| "empty final plaintext block".to_string())? as usize;
    if pad_len == 0 || pad_len > AES_BLOCK_SIZE {
        return Err("invalid PKCS7 padding".to_string());
    }
    if !final_plaintext[final_plaintext.len() - pad_len..]
        .iter()
        .all(|&b| b as usize == pad_len)
    {
        return Err("invalid PKCS7 padding".to_string());
    }
    let unpadded = &final_plaintext[..final_plaintext.len() - pad_len];
    if !unpadded.is_empty() {
        writer
            .write_all(unpadded)
            .map_err(|e| format!("temp write failed: {e}"))?;
        sha.update(unpadded);
        plaintext_bytes += unpadded.len() as u64;
        progress(unpadded.len() as u64);
    }
    writer
        .flush()
        .map_err(|e| format!("temp flush failed: {e}"))?;
    Ok(DecryptedTempFile {
        temp_path: temp_path.to_path_buf(),
        plaintext_sha256: hex_digest(&sha.finalize()),
        plaintext_bytes,
        cipher_bytes: legacy_file_cipher_len(path)?,
    })
}

// ── CBC streaming helpers ──────────────────────────────────────────────────────

/// CBC-encrypt all data from `source`, writing to `destination`.
///
/// Appends PKCS#7 padding.  Returns the number of ciphertext bytes written.
pub(super) fn encrypt_legacy_stream_to_writer(
    source: &mut File,
    destination: &mut File,
    parsed: &LegacyHeader,
) -> Result<u64, String> {
    let cipher = <Aes256 as CipherKeyInit>::new_from_slice(&parsed.enc_key)
        .map_err(|e| format!("cipher init failed: {e}"))?;
    let mut prev_block = parsed.iv;
    let mut pending = Vec::with_capacity(AEAD_CHUNK_SIZE + AES_BLOCK_SIZE);
    let mut buf = vec![0u8; AEAD_CHUNK_SIZE];
    let mut total_ciphertext = 0u64;

    loop {
        let read = source
            .read(&mut buf)
            .map_err(|e| format!("read failed: {e}"))?;
        if read == 0 {
            break;
        }
        pending.extend_from_slice(&buf[..read]);
        while pending.len() >= AES_BLOCK_SIZE {
            let block = pending[..AES_BLOCK_SIZE].to_vec();
            let ciphertext_block = encrypt_legacy_cbc_block(&cipher, &block, &prev_block);
            destination
                .write_all(&ciphertext_block)
                .map_err(|e| format!("write failed: {e}"))?;
            prev_block.copy_from_slice(&ciphertext_block);
            pending.drain(..AES_BLOCK_SIZE);
            total_ciphertext += AES_BLOCK_SIZE as u64;
        }
    }

    // Pad remaining bytes to a full block and encrypt.
    let pad_len = AES_BLOCK_SIZE - (pending.len() % AES_BLOCK_SIZE);
    pending.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    for chunk in pending.chunks_exact(AES_BLOCK_SIZE) {
        let ciphertext_block = encrypt_legacy_cbc_block(&cipher, chunk, &prev_block);
        destination
            .write_all(&ciphertext_block)
            .map_err(|e| format!("write failed: {e}"))?;
        prev_block.copy_from_slice(&ciphertext_block);
        total_ciphertext += AES_BLOCK_SIZE as u64;
    }

    Ok(total_ciphertext)
}

/// Decrypt a single 16-byte CBC block.
fn decrypt_legacy_cbc_block(
    cipher: &Aes256,
    block: &[u8],
    prev_block: &[u8; AES_BLOCK_SIZE],
) -> [u8; AES_BLOCK_SIZE] {
    let arr: [u8; AES_BLOCK_SIZE] = block.try_into().expect("block is 16 bytes");
    let mut b = Block::from(arr);
    cipher.decrypt_block(&mut b);
    let mut plaintext = [0u8; AES_BLOCK_SIZE];
    for i in 0..AES_BLOCK_SIZE {
        plaintext[i] = b[i] ^ prev_block[i];
    }
    plaintext
}

/// Encrypt a single 16-byte CBC block.
fn encrypt_legacy_cbc_block(
    cipher: &Aes256,
    block: &[u8],
    prev_block: &[u8; AES_BLOCK_SIZE],
) -> [u8; AES_BLOCK_SIZE] {
    let mut xored = [0u8; AES_BLOCK_SIZE];
    for i in 0..AES_BLOCK_SIZE {
        xored[i] = block[i] ^ prev_block[i];
    }
    let mut b = Block::from(xored);
    cipher.encrypt_block(&mut b);
    let mut ciphertext = [0u8; AES_BLOCK_SIZE];
    ciphertext.copy_from_slice(&b[..]);
    ciphertext
}

/// Decrypt a raw in-memory AES-256-CBC ciphertext blob (no header, no HMAC).
fn decrypt_legacy_cbc_bytes(
    cipher_bytes: &[u8],
    enc_key: &[u8; 32],
    iv: &[u8; LEGACY_IV_LEN],
) -> Result<(Vec<u8>, u64), String> {
    if cipher_bytes.is_empty() || !cipher_bytes.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err("ciphertext length is invalid for AES-CBC".to_string());
    }
    let cipher = <Aes256 as CipherKeyInit>::new_from_slice(enc_key)
        .map_err(|e| format!("cipher init failed: {e}"))?;
    let mut prev_block = *iv;
    let mut plaintext = Vec::with_capacity(cipher_bytes.len());
    for chunk in cipher_bytes.chunks_exact(AES_BLOCK_SIZE) {
        let decrypted = decrypt_legacy_cbc_block(&cipher, chunk, &prev_block);
        plaintext.extend_from_slice(&decrypted);
        prev_block.copy_from_slice(chunk);
    }
    let pad_len = *plaintext
        .last()
        .ok_or_else(|| "empty plaintext".to_string())? as usize;
    if pad_len == 0 || pad_len > AES_BLOCK_SIZE {
        return Err("invalid PKCS7 padding".to_string());
    }
    if !plaintext[plaintext.len() - pad_len..]
        .iter()
        .all(|&b| b as usize == pad_len)
    {
        return Err("invalid PKCS7 padding".to_string());
    }
    plaintext.truncate(plaintext.len() - pad_len);
    Ok((plaintext, cipher_bytes.len() as u64))
}

/// Return the number of ciphertext bytes in a DBENC001 file (file size minus header).
fn legacy_file_cipher_len(path: &Path) -> Result<u64, String> {
    let total = std::fs::metadata(path)
        .map_err(|e| format!("metadata failed: {e}"))?
        .len();
    let overhead = (LEGACY_HEADER_LEN + LEGACY_MAC_LEN) as u64;
    total
        .checked_sub(overhead)
        .ok_or_else(|| "encrypted file too small".to_string())
}
