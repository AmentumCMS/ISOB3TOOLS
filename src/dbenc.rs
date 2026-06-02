use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aes::{Aes256, Block};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as CipherKeyInit};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use aes_gcm::aead::KeyInit as AeadKeyInit;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const MAGIC_DBENC001: &[u8; 8] = b"DBENC001";
const MAGIC_DBENC002: &[u8; 8] = b"DBENC002";
const MAGIC_DBENC003: &[u8; 8] = b"DBENC003";
const LEGACY_HEADER_LEN: usize = 48;
const LEGACY_MAC_LEN: usize = 32;
const LEGACY_SALT_LEN: usize = 16;
const LEGACY_IV_LEN: usize = 16;
const LEGACY_PBKDF2_ROUNDS: u32 = 600_000;
const AES_BLOCK_SIZE: usize = 16;
const AEAD_HEADER_LEN: usize = 64;
const AEAD_SALT_LEN: usize = 16;
const AEAD_CHUNK_SIZE: usize = 1024 * 1024;
const AEAD_AES_GCM_NONCE_LEN: usize = 12;
const AEAD_XCHACHA_NONCE_LEN: usize = 24;
const AEAD_PBKDF2_ROUNDS: u32 = 600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbEncFormat {
    DbEnc001,
    DbEnc002,
    DbEnc003,
}

impl DbEncFormat {
    pub fn default_modern() -> Self {
        Self::DbEnc003
    }

    pub fn cli_name(self) -> &'static str {
        match self {
            Self::DbEnc001 => "legacy-cbc",
            Self::DbEnc002 => "aes-gcm",
            Self::DbEnc003 => "xchacha20",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecryptedFile {
    pub plaintext: Vec<u8>,
    pub cipher_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct DecryptedTempFile {
    pub temp_path: PathBuf,
    pub plaintext_sha256: String,
    pub plaintext_bytes: u64,
    pub cipher_bytes: u64,
}

#[derive(Clone)]
struct LegacyHeader {
    header: [u8; LEGACY_HEADER_LEN],
    mac: [u8; LEGACY_MAC_LEN],
    enc_key: [u8; 32],
    mac_key: [u8; 32],
    iv: [u8; LEGACY_IV_LEN],
}

#[derive(Clone)]
struct AeadHeader {
    magic: [u8; 8],
    header: [u8; AEAD_HEADER_LEN],
    key: [u8; 32],
    nonce_prefix: [u8; AEAD_XCHACHA_NONCE_LEN],
    chunk_size: u32,
}

pub fn parse_format_name(name: &str) -> Option<DbEncFormat> {
    match name.to_ascii_lowercase().as_str() {
        "legacy-cbc" | "dbenc001" | "cbc" => Some(DbEncFormat::DbEnc001),
        "aes-gcm" | "dbenc002" | "gcm" => Some(DbEncFormat::DbEnc002),
        "xchacha20" | "xchacha20-poly1305" | "dbenc003" => Some(DbEncFormat::DbEnc003),
        _ => None,
    }
}

pub fn detect_format(path: &Path) -> Result<Option<DbEncFormat>, String> {
    let mut magic = [0u8; 8];
    let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let read = file
        .read(&mut magic)
        .map_err(|e| format!("read failed: {e}"))?;
    if read < magic.len() {
        return Ok(None);
    }
    Ok(match &magic {
        MAGIC_DBENC001 => Some(DbEncFormat::DbEnc001),
        MAGIC_DBENC002 => Some(DbEncFormat::DbEnc002),
        MAGIC_DBENC003 => Some(DbEncFormat::DbEnc003),
        _ => None,
    })
}

pub fn is_encrypted_file(path: &Path) -> Result<bool, String> {
    Ok(detect_format(path)?.is_some())
}

pub fn decrypt_file(path: &Path, password: &str) -> Result<DecryptedFile, String> {
    match detect_format(path)? {
        Some(DbEncFormat::DbEnc001) => {
            let bytes = std::fs::read(path).map_err(|e| format!("read failed: {e}"))?;
            decrypt_legacy_bytes(&bytes, password)
        }
        Some(DbEncFormat::DbEnc002) | Some(DbEncFormat::DbEnc003) => {
            let temp = decrypt_file_to_temp_with_cancel(path, password, |_| {}, || false)?;
            let plaintext =
                std::fs::read(&temp.temp_path).map_err(|e| format!("temp read failed: {e}"))?;
            cleanup_temp_file(&temp.temp_path);
            Ok(DecryptedFile {
                plaintext,
                cipher_bytes: temp.cipher_bytes,
            })
        }
        None => Err("missing DBENC header".to_string()),
    }
}

pub fn encrypt_file_to_path(
    source_path: &Path,
    destination_path: &Path,
    password: &str,
    format: DbEncFormat,
) -> Result<u64, String> {
    match format {
        DbEncFormat::DbEnc001 => {
            encrypt_legacy_file_to_path(source_path, destination_path, password)
        }
        DbEncFormat::DbEnc002 | DbEncFormat::DbEnc003 => {
            encrypt_aead_file_to_path(source_path, destination_path, password, format)
        }
    }
}

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
            decrypt_legacy_file_to_temp(path, password, &mut progress, &mut should_abort)
        }
        Some(DbEncFormat::DbEnc002) | Some(DbEncFormat::DbEnc003) => {
            decrypt_aead_file_to_temp(path, password, &mut progress, &mut should_abort)
        }
        None => Err("missing DBENC header".to_string()),
    }
}

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

pub fn cleanup_temp_file(path: &Path) {
    let _ = std::fs::remove_file(path);
}

fn build_legacy_header(password: &str) -> Result<LegacyHeader, String> {
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

fn build_aead_header(password: &str, format: DbEncFormat) -> Result<AeadHeader, String> {
    let mut salt = [0u8; AEAD_SALT_LEN];
    let mut nonce_prefix = [0u8; AEAD_XCHACHA_NONCE_LEN];
    fill_random(&mut salt)?;
    fill_random(&mut nonce_prefix)?;
    let magic = match format {
        DbEncFormat::DbEnc002 => *MAGIC_DBENC002,
        DbEncFormat::DbEnc003 => *MAGIC_DBENC003,
        DbEncFormat::DbEnc001 => return Err("DBENC001 does not use AEAD headers".to_string()),
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

fn encrypt_legacy_file_to_path(
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
    destination
        .write_all(&[0u8; LEGACY_MAC_LEN])
        .map_err(|e| format!("write failed: {e}"))?;
    let ciphertext_bytes = encrypt_legacy_stream_to_writer(&mut source, &mut destination, &parsed)?;
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

fn encrypt_aead_file_to_path(
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
            DbEncFormat::DbEnc001 => unreachable!(),
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

fn parse_legacy_header(header: &[u8], mac: &[u8], password: &str) -> Result<LegacyHeader, String> {
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

fn parse_aead_header_from_file(path: &Path, password: &str) -> Result<AeadHeader, String> {
    let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut header = [0u8; AEAD_HEADER_LEN];
    file.read_exact(&mut header)
        .map_err(|e| format!("read failed: {e}"))?;
    parse_aead_header(&header, password)
}

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

fn decrypt_legacy_file_to_temp<F, G>(
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

fn decrypt_aead_file_to_temp<F, G>(
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

fn decrypt_legacy_bytes(bytes: &[u8], password: &str) -> Result<DecryptedFile, String> {
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
    if cipher_bytes == 0 || cipher_bytes % AES_BLOCK_SIZE as u64 != 0 {
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
    let cipher =
        <Aes256 as CipherKeyInit>::new_from_slice(&parsed.enc_key).map_err(|e| format!("cipher init failed: {e}"))?;
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
        while pending.len() > AES_BLOCK_SIZE {
            if should_abort() {
                return Err("operation aborted".to_string());
            }
            let block = pending[..AES_BLOCK_SIZE].to_vec();
            let plaintext_block = decrypt_legacy_cbc_block(&cipher, &block, &prev_block);
            writer
                .write_all(&plaintext_block)
                .map_err(|e| format!("temp write failed: {e}"))?;
            sha.update(&plaintext_block);
            plaintext_bytes += plaintext_block.len() as u64;
            progress(plaintext_block.len() as u64);
            prev_block.copy_from_slice(&block);
            pending.drain(..AES_BLOCK_SIZE);
        }
    }
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

        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("read failed: {e}")),
        }
        let plaintext_len = u32::from_le_bytes(len_buf) as usize;
        let ciphertext_len = plaintext_len + 16;
        let mut ciphertext_and_tag = vec![0u8; ciphertext_len];
        reader
            .read_exact(&mut ciphertext_and_tag)
            .map_err(|e| format!("read failed: {e}"))?;
        cipher_bytes += 4 + ciphertext_len as u64;
        progress(4);
        progress(ciphertext_len as u64);

        let nonce = make_aead_nonce(
            if &parsed.magic == MAGIC_DBENC002 {
                DbEncFormat::DbEnc002
            } else {
                DbEncFormat::DbEnc003
            },
            &parsed.nonce_prefix,
            chunk_index,
        );
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

fn encrypt_legacy_stream_to_writer(
    source: &mut File,
    destination: &mut File,
    parsed: &LegacyHeader,
) -> Result<u64, String> {
    let cipher =
        <Aes256 as CipherKeyInit>::new_from_slice(&parsed.enc_key).map_err(|e| format!("cipher init failed: {e}"))?;
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

fn write_aead_chunk(
    destination: &mut File,
    plaintext_len: u32,
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<(), String> {
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

fn make_aead_nonce(
    format: DbEncFormat,
    nonce_prefix: &[u8; AEAD_XCHACHA_NONCE_LEN],
    chunk_index: u64,
) -> [u8; AEAD_XCHACHA_NONCE_LEN] {
    let mut nonce = *nonce_prefix;
    match format {
        DbEncFormat::DbEnc002 => nonce[4..12].copy_from_slice(&chunk_index.to_le_bytes()),
        DbEncFormat::DbEnc003 => nonce[16..24].copy_from_slice(&chunk_index.to_le_bytes()),
        DbEncFormat::DbEnc001 => {}
    }
    nonce
}

fn make_aead_aad(magic: &[u8; 8], chunk_index: u64, plaintext_len: u32) -> [u8; 16] {
    let mut aad = [0u8; 16];
    aad[..8].copy_from_slice(magic);
    aad[8..12].copy_from_slice(&plaintext_len.to_le_bytes());
    aad[12..16].copy_from_slice(&(chunk_index as u32).to_le_bytes());
    aad
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);

    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }

    out
}

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], rounds: u32, output: &mut [u8]) {
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

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as HmacKeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);

    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

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

fn decrypt_legacy_cbc_bytes(
    cipher_bytes: &[u8],
    enc_key: &[u8; 32],
    iv: &[u8; LEGACY_IV_LEN],
) -> Result<(Vec<u8>, u64), String> {
    if cipher_bytes.is_empty() || cipher_bytes.len() % AES_BLOCK_SIZE != 0 {
        return Err("ciphertext length is invalid for AES-CBC".to_string());
    }
    let cipher = <Aes256 as CipherKeyInit>::new_from_slice(enc_key).map_err(|e| format!("cipher init failed: {e}"))?;
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

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create directory failed: {e}"))?;
        }
    }
    Ok(())
}

fn make_temp_path(prefix: &str, source_path: Option<&Path>) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut name = format!("{prefix}-{pid}-{nanos}");
    if let Some(ext) = source_path
        .and_then(|path| path.extension())
        .and_then(|ext| ext.to_str())
        .filter(|ext| !ext.is_empty())
    {
        name.push('.');
        name.push_str(ext);
    } else {
        name.push_str(".tmp");
    }
    std::env::temp_dir().join(name)
}

fn legacy_file_cipher_len(path: &Path) -> Result<u64, String> {
    let total = std::fs::metadata(path)
        .map_err(|e| format!("metadata failed: {e}"))?
        .len();
    let overhead = (LEGACY_HEADER_LEN + LEGACY_MAC_LEN) as u64;
    total
        .checked_sub(overhead)
        .ok_or_else(|| "encrypted file too small".to_string())
}

#[cfg(windows)]
fn fill_random(buf: &mut [u8]) -> Result<(), String> {
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

#[cfg(not(windows))]
fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    let mut file = File::open("/dev/urandom").map_err(|e| format!("random open failed: {e}"))?;
    file.read_exact(buf)
        .map_err(|e| format!("random read failed: {e}"))
}

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
