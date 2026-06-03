//! DBENC005 implementation: ML-KEM-768 + XChaCha20-Poly1305 (post-quantum encryption).
//!
//! DBENC005 replaces a password-derived key with a key encapsulated via ML-KEM-768
//! (FIPS 203), providing post-quantum security.  A recipient generates a keypair;
//! the 1184-byte encapsulation key (EK) is public and is used to encrypt.  The
//! 64-byte decapsulation key seed (DK) is private and is used to decrypt.
//!
//! ## Header layout (`PQE_HEADER_LEN` = 1124 bytes)
//!
//! | Bytes        | Field          | Notes                             |
//! |--------------|----------------|-----------------------------------|
//! | 0–7          | magic          | `DBENC005`                        |
//! | 8–1095       | ML-KEM-768 CT  | 1088-byte KEM ciphertext          |
//! | 1096–1119    | nonce prefix   | 24 random bytes                   |
//! | 1120–1123    | chunk size     | LE u32                            |
//!
//! ## Body layout (per chunk)
//!
//! `plaintext_len_le[4] | ciphertext[plaintext_len] | tag[16]`
//!
//! The symmetric key is the 32-byte ML-KEM shared secret.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use aes_gcm::aead::KeyInit as AeadKeyInit;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ml_kem::{
    Decapsulate, DecapsulationKey768, Encapsulate, EncapsulationKey768, Kem, KeyExport, MlKem768,
};
use sha2::{Digest, Sha256};

use super::{
    AEAD_CHUNK_SIZE, AEAD_XCHACHA_NONCE_LEN, DbEncFormat, DecryptedTempFile, MAGIC_DBENC005,
    cleanup_temp_file, ensure_parent_dir, fill_random, hex_digest, make_aead_aad,
    make_aead_nonce, make_temp_path, write_aead_chunk,
};

/// Size of the ML-KEM-768 encapsulation key (public key) in bytes.
pub const PQE_EK_LEN: usize = 1184;

/// Size of the ML-KEM-768 decapsulation key seed (private key) in bytes.
///
/// Keys are stored in the compact 64-byte seed format rather than the expanded
/// 2400-byte representation, halving on-disk size and allowing re-derivation.
pub const PQE_DK_LEN: usize = 64;

/// Size of the ML-KEM-768 KEM ciphertext in bytes.
pub const PQE_CT_LEN: usize = 1088;

/// Total header size: magic (8) + KEM CT (1088) + nonce prefix (24) + chunk size (4).
const PQE_HEADER_LEN: usize = 8 + PQE_CT_LEN + AEAD_XCHACHA_NONCE_LEN + 4;

/// Generate a new ML-KEM-768 keypair.
///
/// Returns `(ek, dk)` where:
/// - `ek` is the 1184-byte encapsulation key (public; share with encryptors).
/// - `dk` is the 64-byte decapsulation key seed (private; keep secret).
pub fn generate_pqe_keypair() -> Result<([u8; PQE_EK_LEN], [u8; PQE_DK_LEN]), String> {
    let (dk, ek): (DecapsulationKey768, EncapsulationKey768) = MlKem768::generate_keypair();
    let ek_encoded: ml_kem::array::Array<u8, _> = ek.to_bytes();
    let seed: ml_kem::Seed = dk.to_seed().ok_or("keypair was not generated from seed")?;
    let mut ek_arr = [0u8; PQE_EK_LEN];
    let mut dk_arr = [0u8; PQE_DK_LEN];
    ek_arr.copy_from_slice(ek_encoded.as_ref());
    dk_arr.copy_from_slice(seed.as_ref());
    Ok((ek_arr, dk_arr))
}

/// Encrypt `source_path` to `destination_path` using DBENC005
/// (ML-KEM-768 + XChaCha20-Poly1305).
///
/// `ek_bytes` is the recipient's 1184-byte ML-KEM-768 encapsulation key.
/// Returns the number of ciphertext bytes written (excluding the header).
pub fn encrypt_file_pqe(
    source_path: &Path,
    destination_path: &Path,
    ek_bytes: &[u8; PQE_EK_LEN],
) -> Result<u64, String> {
    // Parse the encapsulation key and perform KEM to derive the symmetric key.
    let ek_encoded: ml_kem::array::Array<u8, _> = ek_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid ML-KEM encapsulation key (wrong size)".to_string())?;
    let ek = EncapsulationKey768::new(&ek_encoded)
        .map_err(|_| "invalid ML-KEM encapsulation key".to_string())?;
    let (ct, ss) = ek.encapsulate();

    let mut ct_arr = [0u8; PQE_CT_LEN];
    ct_arr.copy_from_slice(ct.as_ref());
    let mut key = [0u8; 32];
    key.copy_from_slice(ss.as_ref());

    let mut nonce_prefix = [0u8; AEAD_XCHACHA_NONCE_LEN];
    fill_random(&mut nonce_prefix)?;

    // Build the PQE header.
    let mut header = [0u8; PQE_HEADER_LEN];
    header[..8].copy_from_slice(MAGIC_DBENC005);
    header[8..8 + PQE_CT_LEN].copy_from_slice(&ct_arr);
    header[8 + PQE_CT_LEN..8 + PQE_CT_LEN + AEAD_XCHACHA_NONCE_LEN]
        .copy_from_slice(&nonce_prefix);
    header[8 + PQE_CT_LEN + AEAD_XCHACHA_NONCE_LEN..PQE_HEADER_LEN]
        .copy_from_slice(&(AEAD_CHUNK_SIZE as u32).to_le_bytes());

    let mut source = File::open(source_path).map_err(|e| format!("open source failed: {e}"))?;
    ensure_parent_dir(destination_path)?;
    let mut dest = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(destination_path)
        .map_err(|e| format!("open destination failed: {e}"))?;
    dest.write_all(&header).map_err(|e| format!("write header failed: {e}"))?;

    let mut total = 0u64;
    let mut chunk_index = 0u64;
    let mut buf = vec![0u8; AEAD_CHUNK_SIZE];

    loop {
        let read = source.read(&mut buf).map_err(|e| format!("read failed: {e}"))?;
        if read == 0 {
            break;
        }
        let plaintext = &buf[..read];
        let mut ciphertext = plaintext.to_vec();
        // Use DbEnc003 nonce mixing (XChaCha20's 24-byte width).
        let nonce = make_aead_nonce(DbEncFormat::DbEnc003, &nonce_prefix, chunk_index);
        let aad = make_aead_aad(MAGIC_DBENC005, chunk_index, read as u32);
        let cipher = <XChaCha20Poly1305 as AeadKeyInit>::new_from_slice(&key)
            .map_err(|e| format!("cipher init failed: {e}"))?;
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(&nonce[..AEAD_XCHACHA_NONCE_LEN]),
                &aad,
                &mut ciphertext,
            )
            .map_err(|_| "XChaCha20-Poly1305 encryption failed".to_string())?
            .to_vec();
        write_aead_chunk(&mut dest, read as u32, &ciphertext, &tag)?;
        total += (ciphertext.len() + tag.len() + 4) as u64;
        chunk_index += 1;
    }

    dest.flush().map_err(|e| format!("flush failed: {e}"))?;
    Ok(total)
}

/// Decrypt a DBENC005 file directly to `destination_path`.
///
/// `dk_bytes` is the 64-byte ML-KEM-768 decapsulation key seed.
/// Returns the number of plaintext bytes written.
pub fn decrypt_file_pqe_to_path(
    source_path: &Path,
    destination_path: &Path,
    dk_bytes: &[u8; PQE_DK_LEN],
) -> Result<u64, String> {
    let seed: ml_kem::Seed = dk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid ML-KEM seed (wrong size)".to_string())?;
    let dk = DecapsulationKey768::from_seed(seed);

    let mut file = File::open(source_path).map_err(|e| format!("open failed: {e}"))?;
    let mut header = [0u8; PQE_HEADER_LEN];
    file.read_exact(&mut header)
        .map_err(|e| format!("read header failed: {e}"))?;
    if &header[..8] != MAGIC_DBENC005 {
        return Err("missing DBENC005 header".to_string());
    }

    let ss = dk
        .decapsulate_slice(&header[8..8 + PQE_CT_LEN])
        .map_err(|_| "ML-KEM decapsulation failed (wrong private key or corrupt header)")?;
    let mut key = [0u8; 32];
    key.copy_from_slice(ss.as_ref());

    let mut nonce_prefix = [0u8; AEAD_XCHACHA_NONCE_LEN];
    nonce_prefix.copy_from_slice(&header[8 + PQE_CT_LEN..8 + PQE_CT_LEN + AEAD_XCHACHA_NONCE_LEN]);
    let _chunk_size = u32::from_le_bytes(
        header[8 + PQE_CT_LEN + AEAD_XCHACHA_NONCE_LEN..PQE_HEADER_LEN]
            .try_into()
            .map_err(|_| "invalid chunk size".to_string())?,
    ) as usize;

    ensure_parent_dir(destination_path)?;
    let mut writer = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(destination_path)
        .map_err(|e| format!("open destination failed: {e}"))?;

    let mut chunk_index = 0u64;
    let mut plaintext_bytes = 0u64;

    loop {
        let mut len_buf = [0u8; 4];
        match file.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("read failed: {e}")),
        }
        let plaintext_len = u32::from_le_bytes(len_buf) as usize;
        let ciphertext_len = plaintext_len + 16;
        let mut ct_buf = vec![0u8; ciphertext_len];
        file.read_exact(&mut ct_buf)
            .map_err(|e| format!("read chunk failed: {e}"))?;

        let nonce = make_aead_nonce(DbEncFormat::DbEnc003, &nonce_prefix, chunk_index);
        let aad = make_aead_aad(MAGIC_DBENC005, chunk_index, plaintext_len as u32);
        let cipher = <XChaCha20Poly1305 as AeadKeyInit>::new_from_slice(&key)
            .map_err(|e| format!("cipher init failed: {e}"))?;
        cipher
            .decrypt_in_place(
                XNonce::from_slice(&nonce[..AEAD_XCHACHA_NONCE_LEN]),
                &aad,
                &mut ct_buf,
            )
            .map_err(|_| "decryption failed (wrong key or corrupt data)".to_string())?;

        writer
            .write_all(&ct_buf)
            .map_err(|e| format!("write failed: {e}"))?;
        plaintext_bytes += ct_buf.len() as u64;
        chunk_index += 1;
    }

    writer.flush().map_err(|e| format!("flush failed: {e}"))?;
    Ok(plaintext_bytes)
}

/// Decrypt a DBENC005 file to a temporary path, with progress and cancellation support.
///
/// The caller is responsible for deleting the temp file via [`cleanup_temp_file`]
/// when done.  On failure the temp file is automatically cleaned up.
pub fn decrypt_file_pqe_to_temp_with_cancel<F, G>(
    path: &Path,
    dk_bytes: &[u8; PQE_DK_LEN],
    mut progress: F,
    mut should_abort: G,
) -> Result<DecryptedTempFile, String>
where
    F: FnMut(u64),
    G: FnMut() -> bool,
{
    let seed: ml_kem::Seed = dk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid ML-KEM seed (wrong size)".to_string())?;
    let dk = DecapsulationKey768::from_seed(seed);

    let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut header = [0u8; PQE_HEADER_LEN];
    file.read_exact(&mut header)
        .map_err(|e| format!("read PQE header failed: {e}"))?;
    if &header[..8] != MAGIC_DBENC005 {
        return Err("missing DBENC005 header".to_string());
    }

    let ss = dk
        .decapsulate_slice(&header[8..8 + PQE_CT_LEN])
        .map_err(|_| "ML-KEM decapsulation failed (wrong private key or corrupt header)")?;
    let mut key = [0u8; 32];
    key.copy_from_slice(ss.as_ref());

    let mut nonce_prefix = [0u8; AEAD_XCHACHA_NONCE_LEN];
    nonce_prefix.copy_from_slice(&header[8 + PQE_CT_LEN..8 + PQE_CT_LEN + AEAD_XCHACHA_NONCE_LEN]);

    let temp_path = make_temp_path("pqe", Some(path));
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
            match file.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(format!("read failed: {e}")),
            }
            let plaintext_len = u32::from_le_bytes(len_buf) as usize;
            let ciphertext_len = plaintext_len + 16;
            let mut ct_buf = vec![0u8; ciphertext_len];
            file.read_exact(&mut ct_buf)
                .map_err(|e| format!("read chunk failed: {e}"))?;
            cipher_bytes += 4 + ciphertext_len as u64;
            progress(4);
            progress(ciphertext_len as u64);

            let nonce = make_aead_nonce(DbEncFormat::DbEnc003, &nonce_prefix, chunk_index);
            let aad = make_aead_aad(MAGIC_DBENC005, chunk_index, plaintext_len as u32);
            let cipher = <XChaCha20Poly1305 as AeadKeyInit>::new_from_slice(&key)
                .map_err(|e| format!("cipher init failed: {e}"))?;
            cipher
                .decrypt_in_place(
                    XNonce::from_slice(&nonce[..AEAD_XCHACHA_NONCE_LEN]),
                    &aad,
                    &mut ct_buf,
                )
                .map_err(|_| "decryption failed (wrong private key or corrupt data)".to_string())?;

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

    if let Err(e) = result {
        cleanup_temp_file(&temp_path);
        return Err(e);
    }

    Ok(DecryptedTempFile {
        temp_path,
        plaintext_sha256: hex_digest(&sha.finalize()),
        plaintext_bytes,
        cipher_bytes,
    })
}
