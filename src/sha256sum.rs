use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Sha256ManifestEntry {
    pub manifest_path: PathBuf,
    pub target_path: PathBuf,
    pub target_display: String,
    pub expected_hex: String,
}

#[derive(Debug, Clone)]
pub struct ParsedManifest {
    pub entries: Vec<Sha256ManifestEntry>,
    pub skipped_lines: usize,
}

pub fn is_sha256_manifest(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };

    let lower = name.to_ascii_lowercase();

    lower == "sha256sums"
        || lower == "sha256sum.txt"
        || lower.ends_with(".sha256")
        || lower.ends_with(".sha256sum")
        || lower.contains("sha256")
        || lower.contains(".sha")
}

pub fn parse_sha256_manifest(path: &Path) -> Result<ParsedManifest, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read manifest {}: {e}", path.display()))?;
    parse_sha256_manifest_text(path, &text)
}

pub fn parse_sha256_manifest_bytes(path: &Path, bytes: &[u8]) -> Result<ParsedManifest, String> {
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|_| format!("manifest {} is not valid UTF-8", path.display()))?;
    parse_sha256_manifest_text(path, &text)
}

fn parse_sha256_manifest_text(path: &Path, text: &str) -> Result<ParsedManifest, String> {
    let mut entries = Vec::new();
    let mut skipped_lines = 0usize;

    for raw_line in text.lines() {
        let line = raw_line.trim();

        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        let Some((expected_hex, target_display)) = parse_manifest_line(line) else {
            skipped_lines += 1;
            continue;
        };

        let target_path = resolve_manifest_target(path, &target_display);

        entries.push(Sha256ManifestEntry {
            manifest_path: path.to_path_buf(),
            target_path,
            target_display,
            expected_hex,
        });
    }

    Ok(ParsedManifest {
        entries,
        skipped_lines,
    })
}

#[allow(dead_code)]
pub fn compute_sha256(path: &Path) -> Result<String, String> {
    compute_sha256_with_progress(path, |_| {})
}

pub fn compute_sha256_with_progress<F>(path: &Path, progress: F) -> Result<String, String>
where
    F: FnMut(u64),
{
    compute_sha256_with_progress_and_cancel(path, progress, || false)
}

pub fn compute_sha256_with_progress_and_cancel<F, G>(
    path: &Path,
    mut progress: F,
    mut should_abort: G,
) -> Result<String, String>
where
    F: FnMut(u64),
    G: FnMut() -> bool,
{
    let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];

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
        hasher.update(&buf[..read]);
        progress(read as u64);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn parse_manifest_line(line: &str) -> Option<(String, String)> {
    if let Some(parsed) = parse_gnu_line(line) {
        return Some(parsed);
    }

    parse_bsd_line(line)
}

fn parse_gnu_line(line: &str) -> Option<(String, String)> {
    if line.len() < 65 {
        return None;
    }

    let expected_hex = line.get(..64)?;
    if !is_hex_digest(expected_hex) {
        return None;
    }

    let mut remainder = line.get(64..)?.trim_start();
    if remainder.is_empty() {
        return None;
    }

    if let Some(stripped) = remainder.strip_prefix('*') {
        remainder = stripped;
    }

    Some((expected_hex.to_ascii_lowercase(), remainder.to_string()))
}

fn parse_bsd_line(line: &str) -> Option<(String, String)> {
    let prefix = "SHA256 (";
    let rest = line.strip_prefix(prefix)?;
    let close_idx = rest.find(") = ")?;
    let target = rest.get(..close_idx)?;
    let expected_hex = rest.get(close_idx + 4..)?.trim();

    if !is_hex_digest(expected_hex) {
        return None;
    }

    Some((expected_hex.to_ascii_lowercase(), target.to_string()))
}

fn is_hex_digest(candidate: &str) -> bool {
    candidate.len() == 64 && candidate.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn resolve_manifest_target(manifest_path: &Path, target_display: &str) -> PathBuf {
    let candidate = PathBuf::from(target_display);
    if candidate.is_absolute() {
        candidate
    } else {
        manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    }
}
