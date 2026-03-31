use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use blake3::Hasher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextSidecar {
    pub magic: String,
    pub version: u32,
    pub algorithm: String,
    pub ciphertext_path: String,
    pub ciphertext_bytes: u64,
    pub digest_hex: String,
}

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
