//! Planning phase: manifest discovery, loading, and byte-size estimation.
//!
//! All functions in this module run during the planning pass — before any
//! hashing starts — and feed the job-list and progress-bar totals that
//! [`super::verify_drives_worker`] needs.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;

use walkdir::WalkDir;

use crate::dbenc::{
    DbEncFormat, PQE_DK_LEN, cleanup_temp_file, decrypt_file, decrypt_file_pqe_to_temp_with_cancel,
    detect_format, is_encrypted_file,
};
use crate::sha256sum::{
    ParsedManifest, is_sha256_manifest, parse_sha256_manifest, parse_sha256_manifest_bytes,
};

use super::WorkerEvent;

// ── Manifest discovery ─────────────────────────────────────────────────────────

/// Recursively walk `root` and return every file that looks like a SHA-256
/// manifest, including encrypted files that decrypt to a manifest when a
/// key/password is available.
pub(super) fn find_sha256_manifests(
    root: &Path,
    encryption: &super::EncryptionSettings,
) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| is_sha256_manifest_candidate(path, encryption))
        .collect()
}

/// Return `true` if `path` is (or decrypts to) a SHA-256 manifest.
///
/// Plaintext manifests are identified by filename heuristics.  Encrypted files
/// are tentatively decrypted and parsed — a file is accepted if it yields at
/// least one manifest entry.
pub(super) fn is_sha256_manifest_candidate(
    path: &Path,
    encryption: &super::EncryptionSettings,
) -> bool {
    if is_sha256_manifest(path) {
        return true;
    }

    match detect_format(path) {
        Ok(Some(DbEncFormat::DbEnc005)) => {
            let Some(dk_path) = encryption.private_key_path.as_deref() else {
                return false;
            };
            let Ok(dk_bytes) = load_dk_bytes(dk_path) else {
                return false;
            };
            pqe_manifest_probe(path, &dk_bytes)
                .map(|parsed| !parsed.entries.is_empty())
                .unwrap_or(false)
        }
        Ok(Some(_)) => {
            if !encryption.enabled {
                return false;
            }
            encrypted_manifest_probe(path, &encryption.password)
                .map(|parsed| !parsed.entries.is_empty())
                .unwrap_or(false)
        }
        _ => false,
    }
}

// ── Key loading ────────────────────────────────────────────────────────────────

/// Read a decapsulation-key file and return its bytes as a fixed-size array.
///
/// Fails if the file cannot be read or is the wrong size.
pub(super) fn load_dk_bytes(path: &Path) -> Result<[u8; PQE_DK_LEN], String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read key failed: {e}"))?;
    if bytes.len() != PQE_DK_LEN {
        return Err(format!(
            "invalid key file: expected {} bytes, got {}",
            PQE_DK_LEN,
            bytes.len()
        ));
    }
    let mut arr = [0u8; PQE_DK_LEN];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ── Manifest loading ───────────────────────────────────────────────────────────

/// Fully decrypt (if needed) and parse a manifest file into its entries.
///
/// Dispatches on the detected encryption format:
/// - **DBENC005**: decrypts with the private key from `encryption`
/// - **Other DBENC**: decrypts with the password from `encryption`
/// - **Plaintext**: parsed directly from disk
pub(super) fn load_manifest_entries(
    manifest_path: &Path,
    encryption: &super::EncryptionSettings,
    tx: &Sender<WorkerEvent>,
) -> Result<ParsedManifest, String> {
    match detect_format(manifest_path)? {
        Some(DbEncFormat::DbEnc005) => {
            let dk_path = encryption.private_key_path.as_deref().ok_or_else(|| {
                format!(
                    "Manifest {} is PQE-encrypted (DBENC005). Load a private key (.dk) first.",
                    manifest_path.display()
                )
            })?;
            let dk_bytes = load_dk_bytes(dk_path)?;
            let decrypted =
                decrypt_file_pqe_to_temp_with_cancel(manifest_path, &dk_bytes, |_| {}, || false)?;
            let plaintext = std::fs::read(&decrypted.temp_path)
                .map_err(|e| format!("temp read failed: {e}"))?;
            cleanup_temp_file(&decrypted.temp_path);
            let _ = tx.send(WorkerEvent::Progress {
                bytes_delta: decrypted.cipher_bytes,
            });
            parse_sha256_manifest_bytes(manifest_path, &plaintext)
        }
        Some(_) => {
            if !encryption.enabled {
                return Err(format!(
                    "Manifest {} is encrypted. Enable encrypted-file support first.",
                    manifest_path.display()
                ));
            }
            let decrypted = decrypt_file(manifest_path, &encryption.password)?;
            let _ = tx.send(WorkerEvent::Progress {
                bytes_delta: decrypted.cipher_bytes,
            });
            parse_sha256_manifest_bytes(manifest_path, &decrypted.plaintext)
        }
        None => parse_sha256_manifest(manifest_path),
    }
}

/// Quick-decrypt a password-protected file and try to parse it as a manifest.
///
/// Used during the planning phase to identify encrypted manifests by content.
pub(super) fn encrypted_manifest_probe(
    manifest_path: &Path,
    password: &str,
) -> Result<ParsedManifest, String> {
    let decrypted = decrypt_file(manifest_path, password)?;
    parse_sha256_manifest_bytes(manifest_path, &decrypted.plaintext)
}

/// Quick-decrypt a PQE (DBENC005) file with the given decapsulation key and try
/// to parse it as a manifest.
///
/// Used during planning to detect PQE-encrypted manifests.
pub(super) fn pqe_manifest_probe(
    path: &Path,
    dk_bytes: &[u8; PQE_DK_LEN],
) -> Result<ParsedManifest, String> {
    let decrypted = decrypt_file_pqe_to_temp_with_cancel(path, dk_bytes, |_| {}, || false)?;
    let plaintext =
        std::fs::read(&decrypted.temp_path).map_err(|e| format!("temp read failed: {e}"))?;
    cleanup_temp_file(&decrypted.temp_path);
    parse_sha256_manifest_bytes(path, &plaintext)
}

// ── Byte estimation for progress bar ──────────────────────────────────────────

/// Estimate the bytes that will be processed when loading a manifest file.
///
/// Encrypted manifests are counted twice (once to decrypt, once to parse).
pub(super) fn estimated_manifest_bytes(path: &Path, encryption: &super::EncryptionSettings) -> u64 {
    let file_bytes = file_len(path);
    if encryption.enabled && is_encrypted_file(path).unwrap_or(false) {
        file_bytes.saturating_mul(2)
    } else {
        file_bytes
    }
}

/// Estimate the bytes that will be processed when verifying one manifest target.
///
/// ISO targets cost an extra pass for the ISOB3 check; encrypted files cost an
/// extra pass to decrypt.
pub(super) fn estimated_manifest_target_bytes(
    path: &Path,
    encryption: &super::EncryptionSettings,
) -> u64 {
    let file_bytes = file_len(path);
    if encryption.enabled && is_encrypted_file(path).unwrap_or(false) {
        if super::execute::looks_like_iso_target(path) {
            file_bytes.saturating_mul(3)
        } else {
            file_bytes.saturating_mul(2)
        }
    } else if super::execute::looks_like_iso_target(path) {
        file_bytes.saturating_mul(2)
    } else {
        file_bytes
    }
}

/// Estimate the bytes that will be processed for an embedded-ISOB3 drive check.
pub(super) fn estimated_embedded_bytes(path: &Path) -> u64 {
    super::execute::estimate_verification_source_bytes(path)
}

pub(super) fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbenc::{DbEncFormat, encrypt_file_to_path};
    use crate::worker::EncryptionSettings;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "worker-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    #[test]
    fn discovers_encrypted_manifest_without_manifest_filename() {
        let root = temp_root();
        fs::create_dir_all(&root).expect("create temp root");

        let plaintext_manifest = root.join("manifest.txt");
        fs::write(
            &plaintext_manifest,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef *payload.bin\n",
        )
        .expect("write manifest");

        let encrypted_manifest = root.join("catalog.bin");
        encrypt_file_to_path(
            &plaintext_manifest,
            &encrypted_manifest,
            "secret",
            DbEncFormat::DbEnc003,
        )
        .expect("encrypt manifest");
        fs::remove_file(&plaintext_manifest).expect("remove plaintext manifest");

        let encryption = EncryptionSettings {
            enabled: true,
            password: "secret".to_string(),
            private_key_path: None,
        };
        let manifests = find_sha256_manifests(&root, &encryption);

        assert_eq!(manifests, vec![encrypted_manifest.clone()]);

        let parsed = encrypted_manifest_probe(&encrypted_manifest, &encryption.password)
            .expect("parse encrypted manifest");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].target_display, "payload.bin");

        let _ = fs::remove_file(&encrypted_manifest);
        let _ = fs::remove_dir(&root);
    }
}
