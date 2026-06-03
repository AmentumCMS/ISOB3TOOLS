//! DBENC002 (AES-256-GCM) and DBENC003 (XChaCha20-Poly1305) implementations.
//!
//! Both formats share an identical 64-byte header and the same chunked body
//! layout; only the AEAD cipher and the nonce width differ.
//!
//! ## Header layout (`AEAD_HEADER_LEN` = 64 bytes)
//!
//! | Bytes   | Field             | Notes                             |
//! |---------|-------------------|-----------------------------------|
//! | 0–7     | magic             | `DBENC002` or `DBENC003`          |
//! | 8–23    | salt              | 16 random bytes for PBKDF2        |
//! | 24–47   | nonce prefix      | 24 random bytes                   |
//! | 48–51   | PBKDF2 rounds     | LE u32                            |
//! | 52–55   | chunk size        | LE u32                            |
//! | 56      | format tag        | `2` for DBENC002, `3` for DBENC003|
//! | 57–63   | reserved          | zeros                             |
//!
//! ## Body layout (per chunk)
//!
//! `plaintext_len_le[4] | ciphertext[plaintext_len] | tag[16]`

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use aes_gcm::aead::KeyInit as AeadKeyInit;
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};

use super::{
    AEAD_AES_GCM_NONCE_LEN, AEAD_CHUNK_SIZE, AEAD_HEADER_LEN, AEAD_PBKDF2_ROUNDS, AEAD_SALT_LEN,
    AEAD_XCHACHA_NONCE_LEN, AeadHeader, DbEncFormat, DecryptedTempFile, MAGIC_DBENC002,
    MAGIC_DBENC003, cleanup_temp_file, ensure_parent_dir, fill_random, hex_digest, make_aead_aad,
    make_aead_nonce, make_temp_path, pbkdf2_hmac_sha256, write_aead_chunk,
};

/// Build a new AEAD header for DBENC002 or DBENC003, generating fresh random
/// salt and nonce prefix and deriving the encryption key via PBKDF2-HMAC-SHA256.
fn build_aead_header(password: &str, format: DbEncFormat) -> Result<AeadHeader, String> {
    let mut salt = [0u8; AEAD_SALT_LEN];
    let mut nonce_prefix = [0u8; AEAD_XCHACHA_NONCE_LEN];
    fill_random(&mut salt)?;
    fill_random(&mut nonce_prefix)?;

    let magic = match format {
        DbEncFormat::DbEnc002 => *MAGIC_DBENC002,
        DbEncFormat::DbEnc003 => *MAGIC_DBENC003,
        DbEncFormat::DbEnc001 => return Err("DBENC001 does not use AEAD headers".to_string()),
        DbEncFormat::DbEnc004 => return Err("DBENC004 does not use PBKDF2 headers".to_string()),
        DbEncFormat::DbEnc005 => return Err("DBENC005 does not use PBKDF2 headers".to_string()),
    };

    let mut header = [0u8; AEAD_HEADER_LEN];
    header[..8].copy_from_slice(&magic);
    header[8..24].copy_from_slice(&salt);
    header[24..48].copy_from_slice(&nonce_prefix);
    header[48..52].copy_from_slice(&AEAD_PBKDF2_ROUNDS.to_le_bytes());
    header[52..56].copy_from_slice(&(AEAD_CHUNK_SIZE as u32).to_le_bytes());
    header[56] = if format == DbEncFormat::DbEnc002 {
        2
    } else {
        3
    };

    let mut key = [0u8; 32];
    pbkdf2_hmac_sha256(password.as_bytes(), &salt, AEAD_PBKDF2_ROUNDS, &mut key);

    Ok(AeadHeader {
        magic,
        header,
        key,
        nonce_prefix,
        chunk_size: AEAD_CHUNK_SIZE as u32,
    })
}

/// Encrypt `source_path` to `destination_path` using DBENC002 (AES-256-GCM)
/// or DBENC003 (XChaCha20-Poly1305) with PBKDF2-HMAC-SHA256 key derivation.
///
/// Returns the number of ciphertext bytes written (excluding the header).
pub(super) fn encrypt_aead_file_to_path(
    source_path: &Path,
    destination_path: &Path,
    password: &str,
    format: DbEncFormat,
) -> Result<u64, String> {
    let mut source = File::open(source_path).map_err(|e| format!("open source failed: {e}"))?;
    let parsed = build_aead_header(password, format)?;

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
        let read = source
            .read(&mut buf)
            .map_err(|e| format!("read failed: {e}"))?;
        if read == 0 {
            break;
        }
        let plaintext = &buf[..read];
        let mut ciphertext = plaintext.to_vec();
        let nonce = make_aead_nonce(format, &parsed.nonce_prefix, chunk_index);
        let aad = make_aead_aad(&parsed.magic, chunk_index, read as u32);

        let tag_vec = match format {
            DbEncFormat::DbEnc002 => {
                let cipher = <Aes256Gcm as AeadKeyInit>::new_from_slice(&parsed.key)
                    .map_err(|e| format!("cipher init failed: {e}"))?;
                cipher
                    .encrypt_in_place_detached(
                        GcmNonce::from_slice(&nonce[..AEAD_AES_GCM_NONCE_LEN]),
                        &aad,
                        &mut ciphertext,
                    )
                    .map_err(|_| "AES-GCM encryption failed".to_string())?
                    .to_vec()
            }
            DbEncFormat::DbEnc003 => {
                let cipher = <XChaCha20Poly1305 as AeadKeyInit>::new_from_slice(&parsed.key)
                    .map_err(|e| format!("cipher init failed: {e}"))?;
                cipher
                    .encrypt_in_place_detached(
                        XNonce::from_slice(&nonce[..AEAD_XCHACHA_NONCE_LEN]),
                        &aad,
                        &mut ciphertext,
                    )
                    .map_err(|_| "XChaCha20-Poly1305 encryption failed".to_string())?
                    .to_vec()
            }
            DbEncFormat::DbEnc001 | DbEncFormat::DbEnc004 | DbEncFormat::DbEnc005 => unreachable!(),
        };

        write_aead_chunk(&mut destination, read as u32, &ciphertext, &tag_vec)?;
        total_ciphertext += (ciphertext.len() + tag_vec.len() + 4) as u64;
        chunk_index += 1;
    }

    destination
        .flush()
        .map_err(|e| format!("flush failed: {e}"))?;
    Ok(total_ciphertext)
}

/// Read the DBENC002/003 header from `path` and derive the decryption key.
fn parse_aead_header_from_file(path: &Path, password: &str) -> Result<AeadHeader, String> {
    let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut header = [0u8; AEAD_HEADER_LEN];
    file.read_exact(&mut header)
        .map_err(|e| format!("read failed: {e}"))?;
    parse_aead_header(&header, password)
}

/// Parse a raw 64-byte AEAD header and derive the decryption key.
fn parse_aead_header(header: &[u8], password: &str) -> Result<AeadHeader, String> {
    let header: [u8; AEAD_HEADER_LEN] = header
        .try_into()
        .map_err(|_| "invalid AEAD header length".to_string())?;
    let magic: [u8; 8] = header[..8]
        .try_into()
        .map_err(|_| "invalid magic".to_string())?;
    if &magic != MAGIC_DBENC002 && &magic != MAGIC_DBENC003 {
        return Err("missing DBENC002/DBENC003 header".to_string());
    }

    let salt = &header[8..24];
    let mut nonce_prefix = [0u8; AEAD_XCHACHA_NONCE_LEN];
    nonce_prefix.copy_from_slice(&header[24..48]);

    let iterations = u32::from_le_bytes(
        header[48..52]
            .try_into()
            .map_err(|_| "invalid PBKDF2 rounds field".to_string())?,
    );
    if iterations != AEAD_PBKDF2_ROUNDS {
        return Err(format!(
            "unsupported PBKDF2 rounds: expected {AEAD_PBKDF2_ROUNDS}, found {iterations}"
        ));
    }

    let chunk_size = u32::from_le_bytes(
        header[52..56]
            .try_into()
            .map_err(|_| "invalid chunk size field".to_string())?,
    );
    let format_tag = header[56];
    if (&magic == MAGIC_DBENC002 && format_tag != 2)
        || (&magic == MAGIC_DBENC003 && format_tag != 3)
    {
        return Err("encrypted header format tag mismatch".to_string());
    }

    let mut key = [0u8; 32];
    pbkdf2_hmac_sha256(password.as_bytes(), salt, iterations, &mut key);

    Ok(AeadHeader {
        magic,
        header,
        key,
        nonce_prefix,
        chunk_size,
    })
}

/// Decrypt a DBENC002/003 file to a fresh temporary file.
///
/// Returns `Err` and deletes the temp file on failure.
pub(super) fn decrypt_aead_file_to_temp<F, G>(
    path: &Path,
    password: &str,
    progress: &mut F,
    should_abort: &mut G,
) -> Result<DecryptedTempFile, String>
where
    F: FnMut(u64),
    G: FnMut() -> bool,
{
    let parsed = parse_aead_header_from_file(path, password)?;
    let temp_path = make_temp_path("dbenc-aead-dec", Some(path));
    let result = decrypt_aead_stream_to_temp(path, &parsed, &temp_path, progress, should_abort);
    if result.is_err() {
        cleanup_temp_file(&temp_path);
    }
    result
}

/// Stream-decrypt one DBENC002/003 file into `temp_path`, chunk by chunk.
fn decrypt_aead_stream_to_temp<F, G>(
    path: &Path,
    parsed: &AeadHeader,
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
        .seek(SeekFrom::Start(AEAD_HEADER_LEN as u64))
        .map_err(|e| format!("seek failed: {e}"))?;
    let mut writer = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(temp_path)
        .map_err(|e| format!("failed to create temp file {}: {e}", temp_path.display()))?;

    let mut sha = Sha256::new();
    let mut plaintext_bytes = 0u64;
    let mut cipher_bytes = 0u64;
    let mut chunk_index = 0u64;

    loop {
        if should_abort() {
            return Err("operation aborted".to_string());
        }

        // Each chunk is framed: plaintext_len (4 bytes LE) then ciphertext+tag.
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("read failed: {e}")),
        }
        let plaintext_len = u32::from_le_bytes(len_buf) as usize;
        let ciphertext_len = plaintext_len + 16; // 16-byte Poly1305 / GCM tag
        let mut ciphertext_and_tag = vec![0u8; ciphertext_len];
        reader
            .read_exact(&mut ciphertext_and_tag)
            .map_err(|e| format!("read failed: {e}"))?;
        cipher_bytes += 4 + ciphertext_len as u64;
        progress(4);
        progress(ciphertext_len as u64);

        let format = if &parsed.magic == MAGIC_DBENC002 {
            DbEncFormat::DbEnc002
        } else {
            DbEncFormat::DbEnc003
        };
        let nonce = make_aead_nonce(format, &parsed.nonce_prefix, chunk_index);
        let aad = make_aead_aad(&parsed.magic, chunk_index, plaintext_len as u32);
        let mut plaintext = ciphertext_and_tag;

        match &parsed.magic {
            MAGIC_DBENC002 => {
                let cipher = <Aes256Gcm as AeadKeyInit>::new_from_slice(&parsed.key)
                    .map_err(|e| format!("cipher init failed: {e}"))?;
                cipher
                    .decrypt_in_place(
                        GcmNonce::from_slice(&nonce[..AEAD_AES_GCM_NONCE_LEN]),
                        &aad,
                        &mut plaintext,
                    )
                    .map_err(|_| "password incorrect or file integrity check failed".to_string())?;
            }
            MAGIC_DBENC003 => {
                let cipher = <XChaCha20Poly1305 as AeadKeyInit>::new_from_slice(&parsed.key)
                    .map_err(|e| format!("cipher init failed: {e}"))?;
                cipher
                    .decrypt_in_place(
                        XNonce::from_slice(&nonce[..AEAD_XCHACHA_NONCE_LEN]),
                        &aad,
                        &mut plaintext,
                    )
                    .map_err(|_| "password incorrect or file integrity check failed".to_string())?;
            }
            _ => return Err("unsupported AEAD header magic".to_string()),
        }

        writer
            .write_all(&plaintext)
            .map_err(|e| format!("temp write failed: {e}"))?;
        sha.update(&plaintext);
        plaintext_bytes += plaintext.len() as u64;
        progress(plaintext.len() as u64);
        chunk_index += 1;
    }

    writer
        .flush()
        .map_err(|e| format!("temp flush failed: {e}"))?;
    Ok(DecryptedTempFile {
        temp_path: temp_path.to_path_buf(),
        plaintext_sha256: hex_digest(&sha.finalize()),
        plaintext_bytes,
        cipher_bytes,
    })
}
