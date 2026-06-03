//! DBENC004 implementation: Argon2id + XChaCha20-Poly1305.
//!
//! DBENC004 uses the same chunked XChaCha20-Poly1305 body format as DBENC003
//! but replaces PBKDF2-HMAC-SHA256 with Argon2id for key derivation, providing
//! better resistance against GPU-based brute-force attacks.
//!
//! ## Header layout (`AEAD_HEADER_LEN` = 64 bytes)
//!
//! | Bytes   | Field        | Notes                          |
//! |---------|--------------|--------------------------------|
//! | 0–7     | magic        | `DBENC004`                     |
//! | 8–23    | salt         | 16 random bytes for Argon2id   |
//! | 24–47   | nonce prefix | 24 random bytes                |
//! | 48–51   | m_cost       | LE u32 (memory in KiB)         |
//! | 52–55   | t_cost       | LE u32 (iterations)            |
//! | 56–59   | p_cost       | LE u32 (parallelism)           |
//! | 60–63   | chunk size   | LE u32                         |
//!
//! ## Body layout (per chunk)
//!
//! `plaintext_len_le[4] | ciphertext[plaintext_len] | tag[16]`

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use aes_gcm::aead::KeyInit as AeadKeyInit;
use sha2::{Digest, Sha256};

use super::{
    AEAD_CHUNK_SIZE, AEAD_HEADER_LEN, AEAD_SALT_LEN, AEAD_XCHACHA_NONCE_LEN, AeadHeader,
    ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, DbEncFormat, DecryptedTempFile,
    MAGIC_DBENC004, cleanup_temp_file, ensure_parent_dir, fill_random, hex_digest,
    make_aead_aad, make_aead_nonce, make_temp_path, write_aead_chunk,
};

/// Derive a 32-byte key from `password` and `salt` using Argon2id.
fn build_argon2id_key(password: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; 32], String> {
    let params = Params::new(m, t, p, Some(32))
        .map_err(|e| format!("argon2 params invalid: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("argon2id key derivation failed: {e}"))?;
    Ok(key)
}

/// Build a new DBENC004 header, generating fresh random salt and nonce prefix
/// and deriving the encryption key via Argon2id.
fn build_argon2id_header(password: &str) -> Result<(AeadHeader, [u8; 32]), String> {
    let mut salt = [0u8; AEAD_SALT_LEN];
    let mut nonce_prefix = [0u8; AEAD_XCHACHA_NONCE_LEN];
    fill_random(&mut salt)?;
    fill_random(&mut nonce_prefix)?;

    let key = build_argon2id_key(password, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)?;

    let mut header = [0u8; AEAD_HEADER_LEN];
    header[..8].copy_from_slice(MAGIC_DBENC004);
    header[8..24].copy_from_slice(&salt);
    header[24..48].copy_from_slice(&nonce_prefix);
    header[48..52].copy_from_slice(&ARGON2_M_COST.to_le_bytes());
    header[52..56].copy_from_slice(&ARGON2_T_COST.to_le_bytes());
    header[56..60].copy_from_slice(&ARGON2_P_COST.to_le_bytes());
    header[60..64].copy_from_slice(&(AEAD_CHUNK_SIZE as u32).to_le_bytes());

    Ok((
        AeadHeader {
            magic: *MAGIC_DBENC004,
            header,
            key,
            nonce_prefix,
            chunk_size: AEAD_CHUNK_SIZE as u32,
        },
        key,
    ))
}

/// Read the DBENC004 header from `path` and derive the decryption key.
fn parse_argon2id_header_from_file(path: &Path, password: &str) -> Result<AeadHeader, String> {
    let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut header = [0u8; AEAD_HEADER_LEN];
    file.read_exact(&mut header).map_err(|e| format!("read failed: {e}"))?;

    if &header[..8] != MAGIC_DBENC004 {
        return Err("missing DBENC004 header".to_string());
    }

    let salt = &header[8..24];
    let mut nonce_prefix = [0u8; AEAD_XCHACHA_NONCE_LEN];
    nonce_prefix.copy_from_slice(&header[24..48]);

    let m = u32::from_le_bytes(header[48..52].try_into().map_err(|_| "invalid m_cost".to_string())?);
    let t = u32::from_le_bytes(header[52..56].try_into().map_err(|_| "invalid t_cost".to_string())?);
    let p = u32::from_le_bytes(header[56..60].try_into().map_err(|_| "invalid p_cost".to_string())?);
    let chunk_size = u32::from_le_bytes(header[60..64].try_into().map_err(|_| "invalid chunk size".to_string())?);

    let key = build_argon2id_key(password, salt, m, t, p)?;

    Ok(AeadHeader {
        magic: *MAGIC_DBENC004,
        header,
        key,
        nonce_prefix,
        chunk_size,
    })
}

/// Encrypt `source_path` to `destination_path` using DBENC004
/// (Argon2id + XChaCha20-Poly1305).
///
/// Returns the number of ciphertext bytes written (excluding the header).
pub(super) fn encrypt_argon2id_file_to_path(
    source_path: &Path,
    destination_path: &Path,
    password: &str,
) -> Result<u64, String> {
    let (parsed, _key) = build_argon2id_header(password)?;
    let mut source = File::open(source_path).map_err(|e| format!("open source failed: {e}"))?;
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

    let mut total_ciphertext = 0u64;
    let mut chunk_index = 0u64;
    let mut buf = vec![0u8; parsed.chunk_size as usize];

    loop {
        let read = source.read(&mut buf).map_err(|e| format!("read failed: {e}"))?;
        if read == 0 {
            break;
        }
        let plaintext = &buf[..read];
        let mut ciphertext = plaintext.to_vec();
        // DBENC004 uses the XChaCha20 nonce width (DbEnc003 variant) for nonce mixing.
        let nonce = make_aead_nonce(DbEncFormat::DbEnc003, &parsed.nonce_prefix, chunk_index);
        let aad = make_aead_aad(&parsed.magic, chunk_index, read as u32);
        let cipher = <XChaCha20Poly1305 as AeadKeyInit>::new_from_slice(&parsed.key)
            .map_err(|e| format!("cipher init failed: {e}"))?;
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(&nonce[..AEAD_XCHACHA_NONCE_LEN]),
                &aad,
                &mut ciphertext,
            )
            .map_err(|_| "XChaCha20-Poly1305 encryption failed".to_string())?
            .to_vec();
        write_aead_chunk(&mut destination, read as u32, &ciphertext, &tag)?;
        total_ciphertext += (ciphertext.len() + tag.len() + 4) as u64;
        chunk_index += 1;
    }

    destination.flush().map_err(|e| format!("flush failed: {e}"))?;
    Ok(total_ciphertext)
}

/// Decrypt a DBENC004 file to a fresh temporary file with progress and
/// cancellation support.
///
/// Returns `Err` and deletes the temp file on failure.
pub(super) fn decrypt_argon2id_file_to_temp<F, G>(
    path: &Path,
    password: &str,
    progress: &mut F,
    should_abort: &mut G,
) -> Result<DecryptedTempFile, String>
where
    F: FnMut(u64),
    G: FnMut() -> bool,
{
    let parsed = parse_argon2id_header_from_file(path, password)?;
    let temp_path = make_temp_path("dbenc-argon2id-dec", Some(path));

    let mut reader = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    reader
        .seek(SeekFrom::Start(AEAD_HEADER_LEN as u64))
        .map_err(|e| format!("seek failed: {e}"))?;
    let mut writer = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&temp_path)
        .map_err(|e| format!("failed to create temp file {}: {e}", temp_path.display()))?;

    let mut sha = Sha256::new();
    let mut plaintext_bytes = 0u64;
    let mut cipher_bytes = 0u64;
    let mut chunk_index = 0u64;

    let result = (|| -> Result<(), String> {
        loop {
            if should_abort() {
                return Err("operation aborted".to_string());
            }

            let mut len_buf = [0u8; 4];
            match reader.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(format!("read failed: {e}")),
            }
            let plaintext_len = u32::from_le_bytes(len_buf) as usize;
            let ciphertext_len = plaintext_len + 16; // 16-byte Poly1305 tag
            let mut ct_buf = vec![0u8; ciphertext_len];
            reader
                .read_exact(&mut ct_buf)
                .map_err(|e| format!("read chunk failed: {e}"))?;
            cipher_bytes += 4 + ciphertext_len as u64;
            progress(4);
            progress(ciphertext_len as u64);

            let nonce = make_aead_nonce(DbEncFormat::DbEnc003, &parsed.nonce_prefix, chunk_index);
            let aad = make_aead_aad(&parsed.magic, chunk_index, plaintext_len as u32);
            let cipher = <XChaCha20Poly1305 as AeadKeyInit>::new_from_slice(&parsed.key)
                .map_err(|e| format!("cipher init failed: {e}"))?;
            cipher
                .decrypt_in_place(
                    XNonce::from_slice(&nonce[..AEAD_XCHACHA_NONCE_LEN]),
                    &aad,
                    &mut ct_buf,
                )
                .map_err(|_| "password incorrect or file integrity check failed".to_string())?;

            writer
                .write_all(&ct_buf)
                .map_err(|e| format!("temp write failed: {e}"))?;
            sha.update(&ct_buf);
            plaintext_bytes += ct_buf.len() as u64;
            progress(ct_buf.len() as u64);
            chunk_index += 1;
        }
        writer.flush().map_err(|e| format!("temp flush failed: {e}"))
    })();

    if result.is_err() {
        cleanup_temp_file(&temp_path);
        return Err(result.unwrap_err());
    }

    Ok(DecryptedTempFile {
        temp_path,
        plaintext_sha256: hex_digest(&sha.finalize()),
        plaintext_bytes,
        cipher_bytes,
    })
}
