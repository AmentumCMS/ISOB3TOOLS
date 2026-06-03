//! SHA-256 manifest parsing and file hashing.
//!
//! Supports two manifest line formats:
//! - **GNU** — `<64-hex-digest>  <filename>` (two spaces, or `*` for binary mode)
//! - **BSD** — `SHA256 (<filename>) = <64-hex-digest>`
//!
//! On Windows, large files are read with `FILE_FLAG_NO_BUFFERING |
//! FILE_FLAG_SEQUENTIAL_SCAN` to avoid polluting the system page cache.  A
//! buffered fallback is used if the uncached path fails.

#[cfg(windows)]
use std::alloc::{Layout, alloc, dealloc};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
use std::io::{Seek, SeekFrom};

#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{FILE_FLAG_NO_BUFFERING, FILE_FLAG_SEQUENTIAL_SCAN};

#[cfg(windows)]
const UNCACHED_ALIGNMENT: usize = 4096;
#[cfg(windows)]
const UNCACHED_CHUNK_SIZE: usize = 1024 * 1024;

/// One entry parsed from a SHA-256 manifest file.
#[derive(Debug, Clone)]
pub struct Sha256ManifestEntry {
    /// Path to the manifest file this entry came from.
    pub manifest_path: PathBuf,
    /// Resolved filesystem path of the file to verify.
    pub target_path: PathBuf,
    /// Raw filename string as written in the manifest (used for display and error messages).
    pub target_display: String,
    /// Expected lowercase hex SHA-256 digest.
    pub expected_hex: String,
}

/// Result of parsing a manifest file.
#[derive(Debug, Clone)]
pub struct ParsedManifest {
    pub entries: Vec<Sha256ManifestEntry>,
    /// Number of non-blank, non-comment lines that could not be parsed.
    pub skipped_lines: usize,
}

/// Return `true` if the filename looks like a SHA-256 manifest.
///
/// Matches common conventions: `sha256sums`, `*.sha256`, `*.sha256sum`,
/// and any name containing `sha256` or `.sha`.
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

/// Read and parse a plaintext SHA-256 manifest from disk.
pub fn parse_sha256_manifest(path: &Path) -> Result<ParsedManifest, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read manifest {}: {e}", path.display()))?;
    parse_sha256_manifest_text(path, &text)
}

/// Parse a SHA-256 manifest from an already-loaded byte slice.
///
/// `path` is used only for error messages and to resolve relative target paths.
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

/// Hash a file with SHA-256, reporting progress and supporting cancellation.
///
/// `progress` receives the number of bytes just read on each call.
/// `should_abort` is polled before every chunk — return `true` to cancel
/// (the function will return `Err("operation aborted")`).
pub fn compute_sha256_with_progress_and_cancel<F, G>(
    path: &Path,
    progress: F,
    should_abort: G,
) -> Result<String, String>
where
    F: FnMut(u64),
    G: FnMut() -> bool,
{
    #[cfg(windows)]
    {
        let mut progress = progress;
        let mut should_abort = should_abort;

        compute_sha256_uncached_windows(path, &mut progress, &mut should_abort)
            .or_else(|_| compute_sha256_buffered(path, progress, should_abort))
    }

    #[cfg(not(windows))]
    {
        compute_sha256_buffered(path, progress, should_abort)
    }
}

fn compute_sha256_buffered<F, G>(
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

    Ok(hex_digest(&hasher.finalize()))
}

#[cfg(windows)]
fn compute_sha256_uncached_windows<F, G>(
    path: &Path,
    progress: &mut F,
    should_abort: &mut G,
) -> Result<String, String>
where
    F: FnMut(u64),
    G: FnMut() -> bool,
{
    let file_len = std::fs::metadata(path)
        .map_err(|e| format!("stat failed: {e}"))?
        .len();
    let aligned_len = file_len - (file_len % UNCACHED_ALIGNMENT as u64);

    let mut hasher = Sha256::new();
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN).0)
        .open(path)
        .map_err(|e| format!("uncached open failed: {e}"))?;
    let mut buf = AlignedBuffer::new(UNCACHED_CHUNK_SIZE, UNCACHED_ALIGNMENT)?;
    let mut remaining = aligned_len;

    while remaining > 0 {
        if should_abort() {
            return Err("operation aborted".to_string());
        }

        let to_read = remaining.min(UNCACHED_CHUNK_SIZE as u64) as usize;
        let read = file
            .read(buf.as_mut_slice(to_read))
            .map_err(|e| format!("uncached read failed: {e}"))?;

        if read == 0 {
            return Err("uncached read failed: unexpected EOF".to_string());
        }

        hasher.update(&buf.as_slice()[..read]);
        progress(read as u64);
        remaining -= read as u64;
    }

    if aligned_len < file_len {
        let mut tail_file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
        tail_file
            .seek(SeekFrom::Start(aligned_len))
            .map_err(|e| format!("seek failed: {e}"))?;

        let mut tail = vec![0u8; (file_len - aligned_len) as usize];
        tail_file
            .read_exact(&mut tail)
            .map_err(|e| format!("tail read failed: {e}"))?;
        hasher.update(&tail);
        progress(tail.len() as u64);
    }

    Ok(hex_digest(&hasher.finalize()))
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

/// Heap-allocated buffer with a guaranteed alignment — required for
/// `FILE_FLAG_NO_BUFFERING` reads on Windows, which mandate sector-aligned buffers.
#[cfg(windows)]
struct AlignedBuffer {
    ptr: *mut u8,
    len: usize,
    layout: Layout,
}

#[cfg(windows)]
impl AlignedBuffer {
    fn new(len: usize, alignment: usize) -> Result<Self, String> {
        let layout = Layout::from_size_align(len, alignment)
            .map_err(|_| "invalid aligned buffer layout".to_string())?;
        let ptr = unsafe { alloc(layout) };

        if ptr.is_null() {
            return Err("failed to allocate aligned buffer".to_string());
        }

        Ok(Self { ptr, len, layout })
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn as_mut_slice(&mut self, len: usize) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, len) }
    }
}

#[cfg(windows)]
impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr, self.layout);
        }
    }
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
