//! DBENC encrypted-file formats: public API, format dispatch, and shared internals.
//!
//! ## Format overview
//!
//! | Magic     | KDF              | AEAD                   | Notes               |
//! |-----------|------------------|------------------------|---------------------|
//! | `DBENC001`| PBKDF2-HMAC-SHA256| AES-256-CBC + HMAC    | Legacy; avoid for new files |
//! | `DBENC002`| PBKDF2-HMAC-SHA256| AES-256-GCM            |                     |
//! | `DBENC003`| PBKDF2-HMAC-SHA256| XChaCha20-Poly1305     |                     |
//! | `DBENC004`| Argon2id          | XChaCha20-Poly1305     | Recommended password format |
//! | `DBENC005`| ML-KEM-768 (PQE) | XChaCha20-Poly1305     | Post-quantum; no password needed |
//!
//! The public API in this file dispatches to one of four submodules based on
//! the 8-byte magic header detected at the start of the file:
//!
//! - [`legacy`]  — DBENC001
//! - [`aead`]    — DBENC002 / DBENC003
//! - [`argon2`]  — DBENC004
//! - [`pqe`]     — DBENC005

pub mod aead;
pub mod argon2;
pub mod legacy;
pub mod pqe;

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2::Sha256;

// Re-export the PQE public constants and functions so callers only need
// `use crate::dbenc::...` regardless of which submodule owns the symbol.
pub use pqe::{
    PQE_CT_LEN, PQE_DK_LEN, PQE_EK_LEN, decrypt_file_pqe_to_path,
    decrypt_file_pqe_to_temp_with_cancel, encrypt_file_pqe, generate_pqe_keypair,
};

pub(super) type HmacSha256 = Hmac<Sha256>;

// ── Magic bytes ────────────────────────────────────────────────────────────────

pub(super) const MAGIC_DBENC001: &[u8; 8] = b"DBENC001";
pub(super) const MAGIC_DBENC002: &[u8; 8] = b"DBENC002";
pub(super) const MAGIC_DBENC003: &[u8; 8] = b"DBENC003";
pub(super) const MAGIC_DBENC004: &[u8; 8] = b"DBENC004";
pub(super) const MAGIC_DBENC005: &[u8; 8] = b"DBENC005";

// ── Shared constants ───────────────────────────────────────────────────────────

pub(super) const ARGON2_M_COST: u32 = 65536; // 64 MiB
pub(super) const ARGON2_T_COST: u32 = 3;
pub(super) const ARGON2_P_COST: u32 = 4;

pub(super) const LEGACY_HEADER_LEN: usize = 48;
pub(super) const LEGACY_MAC_LEN: usize = 32;
pub(super) const LEGACY_SALT_LEN: usize = 16;
pub(super) const LEGACY_IV_LEN: usize = 16;
pub(super) const LEGACY_PBKDF2_ROUNDS: u32 = 600_000;
pub(super) const AES_BLOCK_SIZE: usize = 16;

pub(super) const AEAD_HEADER_LEN: usize = 64;
pub(super) const AEAD_SALT_LEN: usize = 16;
pub(super) const AEAD_CHUNK_SIZE: usize = 1024 * 1024;
pub(super) const AEAD_AES_GCM_NONCE_LEN: usize = 12;
pub(super) const AEAD_XCHACHA_NONCE_LEN: usize = 24;
pub(super) const AEAD_PBKDF2_ROUNDS: u32 = 600_000;

// ── Public types ───────────────────────────────────────────────────────────────

/// All supported DBENC encryption formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbEncFormat {
    /// Legacy AES-256-CBC + PBKDF2-HMAC-SHA256.  Avoid for new files.
    DbEnc001,
    /// AES-256-GCM + PBKDF2-HMAC-SHA256, chunked.
    DbEnc002,
    /// XChaCha20-Poly1305 + PBKDF2-HMAC-SHA256, chunked.
    DbEnc003,
    /// XChaCha20-Poly1305 + Argon2id KDF, chunked.  Recommended for passwords.
    DbEnc004,
    /// XChaCha20-Poly1305 + ML-KEM-768 key encapsulation (post-quantum).
    DbEnc005,
}

impl DbEncFormat {
    /// The recommended modern password-based format.
    pub fn default_modern() -> Self {
        Self::DbEnc004
    }

    /// Short CLI name used by the `direnc` binary's `--format` flag.
    pub fn cli_name(self) -> &'static str {
        match self {
            Self::DbEnc001 => "legacy-cbc",
            Self::DbEnc002 => "aes-gcm",
            Self::DbEnc003 => "xchacha20",
            Self::DbEnc004 => "argon2id",
            Self::DbEnc005 => "pqe-xchacha20",
        }
    }
}

/// Result of an in-memory decryption (DBENC001 only, or small files).
#[derive(Debug, Clone)]
pub struct DecryptedFile {
    pub plaintext: Vec<u8>,
    /// Number of ciphertext bytes read from disk.
    pub cipher_bytes: u64,
}

/// Result of streaming a decrypted file to a temporary path.
#[derive(Debug, Clone)]
pub struct DecryptedTempFile {
    /// Path to the temporary file containing plaintext.  The caller is
    /// responsible for calling [`cleanup_temp_file`] when done.
    pub temp_path: PathBuf,
    /// Lowercase hex SHA-256 of the plaintext content.
    pub plaintext_sha256: String,
    pub plaintext_bytes: u64,
    /// Number of ciphertext bytes read from disk.
    pub cipher_bytes: u64,
}

// ── Shared internal header structs ────────────────────────────────────────────
//
// These are `pub(super)` so submodules can use them without exposing the raw
// key material to the rest of the codebase.

/// Parsed DBENC001 header and derived key material.
#[derive(Clone)]
pub(super) struct LegacyHeader {
    pub(super) header: [u8; LEGACY_HEADER_LEN],
    pub(super) mac: [u8; LEGACY_MAC_LEN],
    pub(super) enc_key: [u8; 32],
    pub(super) mac_key: [u8; 32],
    pub(super) iv: [u8; LEGACY_IV_LEN],
}

/// Parsed DBENC002/003/004 header and derived key material.
/// (Argon2 and PBKDF2 formats share the same streaming AEAD body layout.)
#[derive(Clone)]
pub(super) struct AeadHeader {
    pub(super) magic: [u8; 8],
    pub(super) header: [u8; AEAD_HEADER_LEN],
    pub(super) key: [u8; 32],
    pub(super) nonce_prefix: [u8; AEAD_XCHACHA_NONCE_LEN],
    pub(super) chunk_size: u32,
}

// ── Public API ─────────────────────────────────────────────────────────────────

/// Parse a format name as typed on the CLI into a [`DbEncFormat`].
pub fn parse_format_name(name: &str) -> Option<DbEncFormat> {
    match name.to_ascii_lowercase().as_str() {
        "legacy-cbc" | "dbenc001" | "cbc" => Some(DbEncFormat::DbEnc001),
        "aes-gcm" | "dbenc002" | "gcm" => Some(DbEncFormat::DbEnc002),
        "xchacha20" | "xchacha20-poly1305" | "dbenc003" => Some(DbEncFormat::DbEnc003),
        "argon2id" | "dbenc004" => Some(DbEncFormat::DbEnc004),
        "pqe-xchacha20" | "pqe" | "dbenc005" => Some(DbEncFormat::DbEnc005),
        _ => None,
    }
}

/// Detect the DBENC format of a file by reading its 8-byte magic header.
///
/// Returns `Ok(None)` for plaintext files (no recognized magic).
pub fn detect_format(path: &Path) -> Result<Option<DbEncFormat>, String> {
    let mut magic = [0u8; 8];
    let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let read = file.read(&mut magic).map_err(|e| format!("read failed: {e}"))?;
    if read < magic.len() {
        return Ok(None);
    }
    Ok(match &magic {
        MAGIC_DBENC001 => Some(DbEncFormat::DbEnc001),
        MAGIC_DBENC002 => Some(DbEncFormat::DbEnc002),
        MAGIC_DBENC003 => Some(DbEncFormat::DbEnc003),
        MAGIC_DBENC004 => Some(DbEncFormat::DbEnc004),
        MAGIC_DBENC005 => Some(DbEncFormat::DbEnc005),
        _ => None,
    })
}

/// Return `true` if the file begins with a recognized DBENC magic header.
pub fn is_encrypted_file(path: &Path) -> Result<bool, String> {
    Ok(detect_format(path)?.is_some())
}

/// Decrypt a password-protected file into memory.
///
/// Only suitable for small files; for large files use
/// [`decrypt_file_to_temp_with_cancel`] instead.
/// DBENC005 is not supported here — use [`decrypt_file_pqe_to_path`].
pub fn decrypt_file(path: &Path, password: &str) -> Result<DecryptedFile, String> {
    match detect_format(path)? {
        Some(DbEncFormat::DbEnc001) => {
            let bytes = std::fs::read(path).map_err(|e| format!("read failed: {e}"))?;
            legacy::decrypt_legacy_bytes(&bytes, password)
        }
        Some(DbEncFormat::DbEnc002) | Some(DbEncFormat::DbEnc003) | Some(DbEncFormat::DbEnc004) => {
            let temp = decrypt_file_to_temp_with_cancel(path, password, |_| {}, || false)?;
            let plaintext =
                std::fs::read(&temp.temp_path).map_err(|e| format!("temp read failed: {e}"))?;
            cleanup_temp_file(&temp.temp_path);
            Ok(DecryptedFile {
                plaintext,
                cipher_bytes: temp.cipher_bytes,
            })
        }
        Some(DbEncFormat::DbEnc005) => {
            Err("DBENC005 requires a private key — use decrypt_file_pqe_to_path".to_string())
        }
        None => Err("missing DBENC header".to_string()),
    }
}

/// Encrypt `source_path` to `destination_path` using the given password and format.
///
/// DBENC005 is not accepted here — use [`encrypt_file_pqe`].
pub fn encrypt_file_to_path(
    source_path: &Path,
    destination_path: &Path,
    password: &str,
    format: DbEncFormat,
) -> Result<u64, String> {
    match format {
        DbEncFormat::DbEnc001 => {
            legacy::encrypt_legacy_file_to_path(source_path, destination_path, password)
        }
        DbEncFormat::DbEnc002 | DbEncFormat::DbEnc003 => {
            aead::encrypt_aead_file_to_path(source_path, destination_path, password, format)
        }
        DbEncFormat::DbEnc004 => {
            argon2::encrypt_argon2id_file_to_path(source_path, destination_path, password)
        }
        DbEncFormat::DbEnc005 => {
            Err("DBENC005 requires a public key — use encrypt_file_pqe".to_string())
        }
    }
}

/// Decrypt a password-protected file to a temporary path, reporting progress.
#[allow(dead_code)]
pub fn decrypt_file_to_temp<F>(
    path: &Path,
    password: &str,
    progress: F,
) -> Result<DecryptedTempFile, String>
where
    F: FnMut(u64),
{
    decrypt_file_to_temp_with_cancel(path, password, progress, || false)
}

/// Decrypt a password-protected file to a temporary path with progress and
/// cancellation support.
///
/// `progress` receives the number of bytes processed on each call.
/// `should_abort` is polled before every chunk; return `true` to cancel.
pub fn decrypt_file_to_temp_with_cancel<F, G>(
    path: &Path,
    password: &str,
    mut progress: F,
    mut should_abort: G,
) -> Result<DecryptedTempFile, String>
where
    F: FnMut(u64),
    G: FnMut() -> bool,
{
    match detect_format(path)? {
        Some(DbEncFormat::DbEnc001) => {
            legacy::decrypt_legacy_file_to_temp(path, password, &mut progress, &mut should_abort)
        }
        Some(DbEncFormat::DbEnc002) | Some(DbEncFormat::DbEnc003) => {
            aead::decrypt_aead_file_to_temp(path, password, &mut progress, &mut should_abort)
        }
        Some(DbEncFormat::DbEnc004) => {
            argon2::decrypt_argon2id_file_to_temp(path, password, &mut progress, &mut should_abort)
        }
        Some(DbEncFormat::DbEnc005) => {
            Err("DBENC005 requires a private key — use decrypt_file_pqe_to_path".to_string())
        }
        None => Err("missing DBENC header".to_string()),
    }
}

/// Decrypt a password-protected file directly to `destination_path`.
pub fn decrypt_file_to_path(
    source_path: &Path,
    destination_path: &Path,
    password: &str,
) -> Result<u64, String> {
    let decrypted = decrypt_file_to_temp_with_cancel(source_path, password, |_| {}, || false)?;
    ensure_parent_dir(destination_path)?;
    std::fs::copy(&decrypted.temp_path, destination_path)
        .map_err(|e| format!("copy failed: {e}"))?;
    cleanup_temp_file(&decrypted.temp_path);
    Ok(decrypted.plaintext_bytes)
}

/// Delete a temporary file, ignoring errors.
pub fn cleanup_temp_file(path: &Path) {
    let _ = std::fs::remove_file(path);
}

// ── Shared internal utilities ─────────────────────────────────────────────────
//
// All `pub(super)` so submodules can import them without re-exporting them to
// crate consumers.

/// Compute a lowercase hex string from a raw digest.
pub(super) fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// PBKDF2-HMAC-SHA256 key derivation.
///
/// Fills `output` with as many derived bytes as it can hold (supports output
/// lengths that are multiples of 32).
pub(super) fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], rounds: u32, output: &mut [u8]) {
    const SHA256_LEN: usize = 32;
    for (block_index, chunk) in output.chunks_mut(SHA256_LEN).enumerate() {
        let mut salt_block = Vec::with_capacity(salt.len() + 4);
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&((block_index + 1) as u32).to_be_bytes());
        let mut u = hmac_sha256(password, &salt_block);
        let mut t = u;
        for _ in 1..rounds {
            u = hmac_sha256(password, &u);
            for (acc, byte) in t.iter_mut().zip(u) {
                *acc ^= byte;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

/// Single-shot HMAC-SHA256.
pub(super) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as HmacKeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Generate a per-chunk AEAD nonce by XOR-ing the chunk index into the
/// random nonce prefix at the format-specific offset.
pub(super) fn make_aead_nonce(
    format: DbEncFormat,
    nonce_prefix: &[u8; AEAD_XCHACHA_NONCE_LEN],
    chunk_index: u64,
) -> [u8; AEAD_XCHACHA_NONCE_LEN] {
    let mut nonce = *nonce_prefix;
    match format {
        // AES-GCM uses a 12-byte nonce; inject index at bytes 4–12.
        DbEncFormat::DbEnc002 => nonce[4..12].copy_from_slice(&chunk_index.to_le_bytes()),
        // XChaCha20 uses a 24-byte nonce; inject index at bytes 16–24.
        DbEncFormat::DbEnc003 => nonce[16..24].copy_from_slice(&chunk_index.to_le_bytes()),
        _ => {}
    }
    nonce
}

/// Build the 16-byte Additional Authenticated Data for one AEAD chunk.
///
/// Layout: `magic[8] | plaintext_len_le[4] | chunk_index_le[4]`
pub(super) fn make_aead_aad(magic: &[u8; 8], chunk_index: u64, plaintext_len: u32) -> [u8; 16] {
    let mut aad = [0u8; 16];
    aad[..8].copy_from_slice(magic);
    aad[8..12].copy_from_slice(&plaintext_len.to_le_bytes());
    aad[12..16].copy_from_slice(&(chunk_index as u32).to_le_bytes());
    aad
}

/// Write one framed AEAD chunk: `plaintext_len_le[4] | ciphertext | tag`.
pub(super) fn write_aead_chunk(
    destination: &mut std::fs::File,
    plaintext_len: u32,
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<(), String> {
    use std::io::Write;
    destination
        .write_all(&plaintext_len.to_le_bytes())
        .map_err(|e| format!("write failed: {e}"))?;
    destination
        .write_all(ciphertext)
        .map_err(|e| format!("write failed: {e}"))?;
    destination
        .write_all(tag)
        .map_err(|e| format!("write failed: {e}"))?;
    Ok(())
}

/// Fill `buf` with cryptographically secure random bytes.
#[cfg(windows)]
pub(super) fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    use windows::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let status = unsafe { BCryptGenRandom(None, buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status.is_ok() {
        Ok(())
    } else {
        Err(format!("random generation failed: {status:?}"))
    }
}

/// Fill `buf` with cryptographically secure random bytes.
#[cfg(not(windows))]
pub(super) fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    let mut file = File::open("/dev/urandom").map_err(|e| format!("random open failed: {e}"))?;
    file.read_exact(buf).map_err(|e| format!("random read failed: {e}"))
}

/// Create all missing parent directories for `path`.
pub(super) fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create directory failed: {e}"))?;
        }
    }
    Ok(())
}

/// Build a unique temporary file path in the system temp directory.
///
/// The name includes the process ID and a nanosecond timestamp to avoid
/// collisions when multiple worker threads are decrypting simultaneously.
/// The source file's extension is preserved so ISOB3 detection still works.
pub(super) fn make_temp_path(prefix: &str, source_path: Option<&Path>) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut name = format!("{prefix}-{pid}-{nanos}");
    if let Some(ext) = source_path
        .and_then(|p| p.extension())
        .and_then(|e| e.to_str())
        .filter(|e| !e.is_empty())
    {
        name.push('.');
        name.push_str(ext);
    } else {
        name.push_str(".tmp");
    }
    std::env::temp_dir().join(name)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypted_temp_file_preserves_source_extension() {
        let root = std::env::temp_dir().join(format!(
            "dbenc-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");

        let source = root.join("payload.iso");
        let encrypted = root.join("payload.iso.enc");
        std::fs::write(&source, b"hello world").expect("write source");

        encrypt_file_to_path(&source, &encrypted, "secret", DbEncFormat::DbEnc003)
            .expect("encrypt source");
        std::fs::rename(&encrypted, &source).expect("replace source with encrypted content");

        let decrypted = decrypt_file_to_temp_with_cancel(&source, "secret", |_| {}, || false)
            .expect("decrypt source");

        assert_eq!(
            decrypted.temp_path.extension().and_then(|ext| ext.to_str()),
            Some("iso")
        );

        cleanup_temp_file(&decrypted.temp_path);
        let _ = std::fs::remove_file(&source);
        let _ = std::fs::remove_dir(&root);
    }
}
