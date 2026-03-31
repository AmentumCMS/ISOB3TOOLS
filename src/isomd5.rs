#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn read_pvd_text(path: &Path) -> Result<Option<String>, String> {
    const SECTOR_SIZE: u64 = 2048;
    const PVD_SECTOR: u64 = 16;

    let mut f = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    f.seek(SeekFrom::Start(PVD_SECTOR * SECTOR_SIZE))
        .map_err(|e| format!("seek failed: {e}"))?;

    let mut pvd = [0u8; 2048];
    f.read_exact(&mut pvd)
        .map_err(|e| format!("read failed: {e}"))?;

    if pvd[0] != 1 || &pvd[1..6] != b"CD001" {
        return Ok(None);
    }

    Ok(Some(String::from_utf8_lossy(&pvd).into_owned()))
}

fn extract_md5_hex(text: &str) -> Option<String> {
    // `checkisomd5` output is mostly human-readable, so we scrape the digest from the last field.
    for line in text.lines() {
        if let Some((_, rhs)) = line.rsplit_once(':') {
            let candidate = rhs.trim();
            if candidate.len() == 32 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(candidate.to_ascii_lowercase());
            }
        }
    }

    None
}

#[allow(dead_code)]
fn extract_isomd5_from_pvd(text: &str) -> Option<String> {
    let upper = text.to_ascii_uppercase();
    let needle = "ISO MD5SUM = ";
    let start = upper.find(needle)? + needle.len();
    let candidate = text.get(start..start + 32)?;

    if candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(candidate.to_ascii_lowercase())
    } else {
        None
    }
}

#[cfg(windows)]
const CHECKISOMD5_BYTES: &[u8] = include_bytes!("../tools/checkisomd5.exe");

#[cfg(target_os = "linux")]
const CHECKISOMD5_BYTES: &[u8] = include_bytes!("../tools/checkisomd5");

fn materialize_embedded_checkisomd5() -> Result<PathBuf, String> {
    let mut path = std::env::temp_dir();

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("time error: {e}"))?
        .as_millis();

    #[cfg(windows)]
    let file_name = format!("checkisomd5-{ts}.exe");

    #[cfg(target_os = "linux")]
    let file_name = format!("checkisomd5-{ts}");

    #[cfg(not(any(windows, target_os = "linux")))]
    return Err("Unsupported OS for embedded checkisomd5".to_string());

    path.push(file_name);

    // Ship the checker as an embedded asset to avoid an external runtime dependency.
    fs::write(&path, CHECKISOMD5_BYTES).map_err(|e| {
        format!(
            "failed to write embedded checker to {}: {e}",
            path.display()
        )
    })?;

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&path)
            .map_err(|e| format!("failed to stat embedded checker {}: {e}", path.display()))?
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&path, perms).map_err(|e| {
            format!(
                "failed to set execute permissions on embedded checker {}: {e}",
                path.display()
            )
        })?;
    }

    Ok(path)
}

pub fn has_isomd5sum_implant(path: &Path) -> Result<bool, String> {
    let Some(text) = read_pvd_text(path)? else {
        return Ok(false);
    };

    // The legacy implant stores recognizable ASCII markers in the PVD/application area.
    let text = text.to_ascii_uppercase();

    Ok(text.contains("ISO MD5SUM = ")
        || text.contains("FRAGMENT SUMS = ")
        || text.contains("FRAGMENT COUNT = ")
        || text.contains("SKIPSECTORS = ")
        || text.contains("RHLISOSTATUS="))
}

#[allow(dead_code)]
pub fn info_isomd5sum(path: &Path) -> Result<Option<String>, String> {
    let Some(text) = read_pvd_text(path)? else {
        return Ok(None);
    };

    if !has_isomd5sum_implant(path)? {
        return Ok(None);
    }

    let digest = extract_isomd5_from_pvd(&text).unwrap_or_else(|| "unknown".to_string());
    Ok(Some(format!(
        "Legacy ISOMD5 metadata found\nAlgorithm: MD5\nDigest: {digest}"
    )))
}

#[derive(Debug, Clone)]
pub enum IsoMd5CheckOutcome {
    Valid { digest_hex: String },
    Invalid(String),
    ToolMissing,
}

pub fn verify_isomd5sum(path: &Path) -> Result<IsoMd5CheckOutcome, String> {
    let checker_path = match materialize_embedded_checkisomd5() {
        Ok(p) => p,
        Err(_) => return Ok(IsoMd5CheckOutcome::ToolMissing),
    };

    let mut cmd = Command::new(&checker_path);
    cmd.arg("-v").arg(path);

    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let output_result = cmd.output();

    let _ = fs::remove_file(&checker_path);

    let output = output_result.map_err(|e| {
        format!(
            "failed to run embedded checker {}: {e}",
            checker_path.display()
        )
    })?;

    // Normalize stdout/stderr because the bundled tool varies by platform and build.
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    let combined = if stdout.is_empty() {
        stderr.clone()
    } else if stderr.is_empty() {
        stdout.clone()
    } else {
        format!("{stdout}\n{stderr}")
    };

    match output.status.code() {
        Some(0) => {
            let digest_hex = extract_md5_hex(&combined).unwrap_or_else(|| "unknown".to_string());
            Ok(IsoMd5CheckOutcome::Valid { digest_hex })
        }
        Some(1) => Ok(IsoMd5CheckOutcome::Invalid(if combined.is_empty() {
            "isomd5sum verification failed".to_string()
        } else {
            combined
        })),
        Some(2) => Ok(IsoMd5CheckOutcome::Invalid(if combined.is_empty() {
            "isomd5sum verification aborted".to_string()
        } else {
            combined
        })),
        _ => Ok(IsoMd5CheckOutcome::Invalid(if combined.is_empty() {
            "isomd5sum verification returned an unexpected status".to_string()
        } else {
            combined
        })),
    }
}
