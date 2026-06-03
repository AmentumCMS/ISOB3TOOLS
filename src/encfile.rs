//! Encrypted-file integrity sidecars.
//!
//! When a file is encrypted with a DBENC format, a small JSON sidecar
//! (`<filename>.isob3enc.json`) is written alongside it.  The sidecar stores
//! the BLAKE3 hash of the *ciphertext* so the ciphertext's integrity can be
//! verified before any decryption attempt.
//!
//! This is a belt-and-suspenders check on top of the AEAD tag inside the
//! DBENC container itself.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use blake3::Hasher;
use serde::{Deserialize, Serialize};

/// JSON sidecar that records integrity metadata for one encrypted file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextSidecar {
    /// Format identifier — always `"ISOB3-ENCFILE"`.
    pub magic: String,
    /// Schema version — currently `1`.
    pub version: u32,
    /// Hash algorithm used — currently `"BLAKE3"`.
    pub algorithm: String,
    /// File name of the ciphertext file this sidecar covers.
    pub ciphertext_path: String,
    /// Size of the ciphertext file in bytes at write time.
    pub ciphertext_bytes: u64,
    /// Lowercase hex BLAKE3 digest of the ciphertext file.
    pub digest_hex: String,
}

/// Hash the ciphertext file at `path` and write a `.isob3enc.json` sidecar next to it.
///
/// Returns the path to the newly written sidecar file.
pub fn write_ciphertext_sidecar(path: &Path, ciphertext_bytes: u64) -> Result<PathBuf, String> {
    let digest_hex = compute_blake3_hex(path)?;
    let sidecar = CiphertextSidecar {
        magic: "ISOB3-ENCFILE".to_string(),
        version: 1,
        algorithm: "BLAKE3".to_string(),
        ciphertext_path: path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string(),
        ciphertext_bytes,
        digest_hex,
    };

    let sidecar_path = sidecar_path(path);
    let json = serde_json::to_string_pretty(&sidecar)
        .map_err(|e| format!("sidecar encode failed: {e}"))?;
    std::fs::write(&sidecar_path, json).map_err(|e| format!("sidecar write failed: {e}"))?;
    Ok(sidecar_path)
}

/// Read the sidecar for `path`, re-hash the ciphertext, and compare.
///
/// Returns a human-readable success string on match, or an `Err` on mismatch
/// or if the sidecar is missing / malformed.
pub fn verify_ciphertext_sidecar(path: &Path) -> Result<String, String> {
    let sidecar_path = sidecar_path(path);
    let text =
        std::fs::read_to_string(&sidecar_path).map_err(|e| format!("sidecar read failed: {e}"))?;
    let sidecar: CiphertextSidecar =
        serde_json::from_str(&text).map_err(|e| format!("sidecar parse failed: {e}"))?;

    if sidecar.magic != "ISOB3-ENCFILE" {
        return Err("unsupported encrypted sidecar format".to_string());
    }

    let actual = compute_blake3_hex(path)?;
    if actual != sidecar.digest_hex {
        return Err(format!(
            "Encrypted file integrity mismatch\nExpected: {}\nActual:   {}",
            sidecar.digest_hex, actual
        ));
    }

    Ok(format!(
        "Encrypted file valid ({})\nSidecar: {}",
        actual,
        sidecar_path.display()
    ))
}

pub fn info_ciphertext_sidecar(path: &Path) -> Result<String, String> {
    let sidecar_path = sidecar_path(path);
    let text =
        std::fs::read_to_string(&sidecar_path).map_err(|e| format!("sidecar read failed: {e}"))?;
    let sidecar: CiphertextSidecar =
        serde_json::from_str(&text).map_err(|e| format!("sidecar parse failed: {e}"))?;

    Ok(format!(
        "Encrypted file integrity metadata found\nAlgorithm: {}\nCiphertext bytes: {}\nDigest: {}\nSidecar: {}",
        sidecar.algorithm,
        sidecar.ciphertext_bytes,
        sidecar.digest_hex,
        sidecar_path.display()
    ))
}

/// Return the conventional sidecar path for a given ciphertext file:
/// `<original-name>.isob3enc.json` in the same directory.
pub fn sidecar_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("encrypted");
    path.with_file_name(format!("{file_name}.isob3enc.json"))
}

fn compute_blake3_hex(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut hasher = Hasher::new();
    let mut buf = vec![0u8; 1024 * 1024];

    loop {
        let read = file
            .read(&mut buf)
            .map_err(|e| format!("read failed: {e}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}
