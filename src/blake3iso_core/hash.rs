//! BLAKE3 digest computation for ISO9660 images.
//!
//! The ISOB3 digest is computed over the entire image with the application-use
//! area **zeroed** (filled with `0x20` / space) so that the stored digest does
//! not influence its own value.  This normalisation is applied identically
//! during implant, check, and removal.
//!
//! Two code paths are provided:
//!
//! - [`compute_blake3_normalized`] — streaming path for on-disk files, with
//!   optional progress callback and cancellation support.
//! - [`compute_blake3_normalized_bytes`] — in-memory path for files that have
//!   already been decrypted into a `Vec<u8>`.

use std::fs::File;
use std::path::Path;

use blake3::Hasher;

use super::{APPDATA_FILL, APPDATA_OFFSET, APPDATA_SIZE};
use super::io::{read_with_retries};

// ── Streaming (on-disk) ────────────────────────────────────────────────────────

/// Compute the normalised BLAKE3 digest of an ISO image file.
///
/// Equivalent to [`compute_blake3_normalized_with_cancel`] with a no-op abort check.
pub(super) fn compute_blake3_normalized<F>(
    path: &Path,
    chunk_size: usize,
    progress: F,
) -> Result<[u8; 32], String>
where
    F: FnMut(u64),
{
    compute_blake3_normalized_with_cancel(path, chunk_size, progress, || false)
}

/// Compute the normalised BLAKE3 digest of an ISO image file with progress and
/// cancellation support.
///
/// The application-use area (`APPDATA_OFFSET .. APPDATA_OFFSET + APPDATA_SIZE`)
/// is replaced with [`APPDATA_FILL`] bytes in the hash input so the stored
/// digest is self-consistent.
///
/// `progress` is called with the number of bytes fed to the hasher each
/// iteration.  `should_abort` is polled before every chunk; returning `true`
/// causes an early `Err("operation aborted")`.
pub(super) fn compute_blake3_normalized_with_cancel<F, G>(
    path: &Path,
    chunk_size: usize,
    mut progress: F,
    mut should_abort: G,
) -> Result<[u8; 32], String>
where
    F: FnMut(u64),
    G: FnMut() -> bool,
{
    let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut hasher = Hasher::new();
    let mut buf = vec![0u8; chunk_size];
    let mut offset = 0u64;

    let app_start = APPDATA_OFFSET;
    let app_end = APPDATA_OFFSET + APPDATA_SIZE as u64;

    loop {
        if should_abort() {
            return Err("operation aborted".to_string());
        }

        let n = read_with_retries(path, &mut file, &mut buf)?;
        if n == 0 {
            break;
        }

        let chunk = &mut buf[..n];
        let chunk_start = offset;
        let chunk_end = offset + n as u64;

        // Zero out any bytes in this chunk that overlap the application-use area.
        let overlap_start = chunk_start.max(app_start);
        let overlap_end = chunk_end.min(app_end);
        if overlap_start < overlap_end {
            let s = (overlap_start - chunk_start) as usize;
            let e = (overlap_end - chunk_start) as usize;
            chunk[s..e].fill(APPDATA_FILL);
        }

        hasher.update(chunk);
        offset += n as u64;
        progress(n as u64);
    }

    Ok(*hasher.finalize().as_bytes())
}

// ── In-memory ─────────────────────────────────────────────────────────────────

/// Compute the normalised BLAKE3 digest over an in-memory ISO byte slice.
///
/// Clones the slice, blanks the application-use area in the copy, then hashes
/// the whole thing.  Only suitable for files small enough to hold in memory.
pub(super) fn compute_blake3_normalized_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut normalized = bytes.to_vec();
    let start = APPDATA_OFFSET as usize;
    let end = start.saturating_add(APPDATA_SIZE).min(normalized.len());
    if start < end {
        normalized[start..end].fill(APPDATA_FILL);
    }
    *blake3::hash(&normalized).as_bytes()
}

// ── Hex helper ─────────────────────────────────────────────────────────────────

/// Encode `bytes` as a lowercase hex string.
pub(super) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
