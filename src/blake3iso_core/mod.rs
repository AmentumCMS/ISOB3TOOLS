//! ISOB3 metadata implant, check, and removal for ISO9660 images.
//!
//! The ISOB3 record is stored in the 512-byte **application-use area** of the
//! ISO9660 Primary Volume Descriptor (PVD), at byte offset `0x8373`.
//!
//! ## Layout of the application-use area (ISOB3APP, v1)
//!
//! | Offset | Size | Field                              |
//! |--------|------|------------------------------------|
//! | 0      | 8    | Magic `"ISOB3APP"`                 |
//! | 8      | 1    | Version (`0x01`)                   |
//! | 9      | 1    | Algorithm (`0x01` = BLAKE3-256)    |
//! | 10     | 2    | Digest length LE (`32`)            |
//! | 12     | 4    | Flags LE (reserved, `0`)           |
//! | 16     | 32   | BLAKE3-256 digest                  |
//!
//! The digest is computed with the application-use area itself **zeroed** so
//! the stored value does not influence the hash.  This normalisation is applied
//! consistently during implant, check, and removal.
//!
//! ## Module layout
//!
//! | Submodule    | Responsibility                                        |
//! |--------------|-------------------------------------------------------|
//! | [`io`]       | Sector-aligned reads, appdata read/write, retry logic |
//! | [`hash`]     | Normalised BLAKE3 streaming and in-memory hashing     |
//! | (this file)  | Public API, constants, `CheckOutcome`, metadata parse |

pub(crate) mod hash;
pub(crate) mod io;

// ── ISO9660 layout constants ───────────────────────────────────────────────────

pub(super) const ISO_SECTOR_SIZE: u64 = 2048;
const PVD_SECTOR: u64 = 16;
pub(super) const PVD_OFFSET: u64 = PVD_SECTOR * ISO_SECTOR_SIZE;
const PVD_SIZE: usize = 2048;

/// Absolute byte offset of the application-use area inside the PVD.
pub(super) const APPDATA_OFFSET: u64 = 0x8373;
/// Size of the application-use area in bytes.
pub(super) const APPDATA_SIZE: usize = 512;
/// Byte value used to blank the application-use area (`' '` / `0x20`).
pub(super) const APPDATA_FILL: u8 = b' ';

// ── ISOB3APP record constants ──────────────────────────────────────────────────

const MAGIC: &[u8; 8] = b"ISOB3APP";
const VERSION: u8 = 1;
const ALGO_BLAKE3_256: u8 = 1;
const FLAGS: u32 = 0;
const DIGEST_LEN: u16 = 32;

// ── Public types ───────────────────────────────────────────────────────────────

/// Outcome of an ISOB3 integrity check.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum CheckOutcome {
    /// Stored digest matches the computed digest.
    Valid {
        digest_hex: String,
        /// Human-readable summary line (e.g. `"ISOB3 valid (aabbcc…)"`).
        detail: String,
    },
    /// Stored digest does not match the computed digest.
    Invalid {
        expected_hex: String,
        actual_hex: String,
        /// Human-readable mismatch detail.
        detail: String,
    },
    /// No ISOB3 record found in the application-use area.
    Missing,
}

// ── PVD validation ─────────────────────────────────────────────────────────────

/// Return `Ok` if `path` appears to be a valid ISO9660 image by checking the
/// first 7 bytes of the Primary Volume Descriptor.
fn is_probably_iso(path: &Path) -> Result<(), String> {
    let mut pvd = [0u8; 7];
    io::read_exact_at(path, PVD_OFFSET, &mut pvd)?;
    validate_pvd(&pvd)
}

/// Validate the ISO9660 PVD header bytes: type=1, magic `CD001`, version=1.
fn validate_pvd(pvd: &[u8]) -> Result<(), String> {
    if pvd[0] != 1 || &pvd[1..6] != b"CD001" || pvd[6] != 1 {
        return Err("not a recognizable ISO9660 primary volume descriptor".to_string());
    }
    Ok(())
}

// ── Metadata parsing ───────────────────────────────────────────────────────────

/// Read and parse the ISOB3 record from the application-use area of `path`.
///
/// Returns `Ok(Some(digest))` when a valid record is present, `Ok(None)` when
/// the area does not start with the ISOB3 magic, or `Err` on I/O failure.
fn read_metadata(path: &Path) -> Result<Option<[u8; 32]>, String> {
    let buf = io::read_appdata(path)?;
    read_metadata_from_appdata(&buf)
}

/// Parse an ISOB3 record from a raw 512-byte application-use area buffer.
///
/// Silently returns `None` for unknown versions, algorithms, or wrong magic
/// so callers can fall through to ISOMD5 gracefully.
fn read_metadata_from_appdata(buf: &[u8; APPDATA_SIZE]) -> Result<Option<[u8; 32]>, String> {
    if &buf[0..8] != MAGIC {
        return Ok(None);
    }
    if buf[8] != VERSION || buf[9] != ALGO_BLAKE3_256 {
        return Ok(None);
    }
    if u16::from_le_bytes([buf[10], buf[11]]) != DIGEST_LEN {
        return Ok(None);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&buf[16..48]);
    Ok(Some(digest))
}

// ── Public API ─────────────────────────────────────────────────────────────────

use std::path::Path;

/// Verify the ISOB3 record embedded in an ISO image or raw optical device.
///
/// Returns [`CheckOutcome::Missing`] if no record is present, allowing the
/// caller to fall back to ISOMD5 or report "no metadata".
#[allow(dead_code)]
pub fn check_iso(path: &Path) -> Result<CheckOutcome, String> {
    check_iso_with_progress(path, |_| {})
}

/// Like [`check_iso`] but calls `progress(bytes)` after each chunk is hashed.
pub fn check_iso_with_progress<F>(path: &Path, progress: F) -> Result<CheckOutcome, String>
where
    F: FnMut(u64),
{
    check_iso_with_progress_and_cancel(path, progress, || false)
}

/// Verify ISOB3 metadata with per-chunk progress reporting and cancellation support.
///
/// `progress` receives the number of bytes processed per call.  Return `true`
/// from `should_abort` to cancel early with `Err("operation aborted")`.
pub fn check_iso_with_progress_and_cancel<F, G>(
    path: &Path,
    progress: F,
    should_abort: G,
) -> Result<CheckOutcome, String>
where
    F: FnMut(u64),
    G: FnMut() -> bool,
{
    io::ensure_readable(path)?;
    is_probably_iso(path)?;

    let stored = match read_metadata(path)? {
        Some(d) => d,
        None => return Ok(CheckOutcome::Missing),
    };

    let actual = hash::compute_blake3_normalized_with_cancel(
        path,
        1024 * 1024,
        progress,
        should_abort,
    )?;

    let stored_hex = hash::hex(&stored);
    let actual_hex = hash::hex(&actual);

    if stored == actual {
        Ok(CheckOutcome::Valid {
            digest_hex: actual_hex.clone(),
            detail: format!("ISOB3 valid ({actual_hex})"),
        })
    } else {
        Ok(CheckOutcome::Invalid {
            expected_hex: stored_hex.clone(),
            actual_hex: actual_hex.clone(),
            detail: format!("ISOB3 mismatch\nExpected: {stored_hex}\nActual:   {actual_hex}"),
        })
    }
}

/// Verify ISOB3 metadata directly against an in-memory ISO byte slice.
///
/// Used when a file has already been decrypted into memory and the caller
/// wants to avoid writing it back to disk before checking.
pub fn check_iso_bytes(bytes: &[u8]) -> Result<CheckOutcome, String> {
    if bytes.len() < (PVD_OFFSET as usize + 7) {
        return Err("file too small to contain an ISO9660 primary volume descriptor".to_string());
    }
    validate_pvd(&bytes[PVD_OFFSET as usize..PVD_OFFSET as usize + 7])?;

    if bytes.len() < APPDATA_OFFSET as usize + APPDATA_SIZE {
        return Err("file too small to contain ISOB3 metadata".to_string());
    }
    let mut appdata = [0u8; APPDATA_SIZE];
    appdata.copy_from_slice(
        &bytes[APPDATA_OFFSET as usize..APPDATA_OFFSET as usize + APPDATA_SIZE],
    );

    let stored = match read_metadata_from_appdata(&appdata)? {
        Some(d) => d,
        None => return Ok(CheckOutcome::Missing),
    };

    let actual = hash::compute_blake3_normalized_bytes(bytes);
    let stored_hex = hash::hex(&stored);
    let actual_hex = hash::hex(&actual);

    if stored == actual {
        Ok(CheckOutcome::Valid {
            digest_hex: actual_hex.clone(),
            detail: format!("ISOB3 valid ({actual_hex})"),
        })
    } else {
        Ok(CheckOutcome::Invalid {
            expected_hex: stored_hex.clone(),
            actual_hex: actual_hex.clone(),
            detail: format!("ISOB3 mismatch\nExpected: {stored_hex}\nActual:   {actual_hex}"),
        })
    }
}

/// Estimate the total byte size of an ISO image from its PVD volume-space field.
///
/// Returns `sector_count × 2048`.  Used to populate the progress bar before
/// hashing begins; may differ slightly from the actual file size due to trailing
/// padding or raw-device sector overhead.
pub fn estimate_iso_bytes(path: &Path) -> Result<u64, String> {
    let mut pvd = [0u8; PVD_SIZE];
    io::read_exact_at(path, PVD_OFFSET, &mut pvd)?;
    validate_pvd(&pvd[..7])?;

    let sector_count = u32::from_le_bytes(
        pvd[80..84]
            .try_into()
            .map_err(|_| "invalid volume space size in PVD".to_string())?,
    ) as u64;
    Ok(sector_count.saturating_mul(ISO_SECTOR_SIZE))
}

/// Implant ISOB3 (BLAKE3) integrity metadata into an ISO file.
///
/// If the application-use area is already non-blank and `force` is `false`,
/// the operation is rejected to avoid silently overwriting foreign metadata.
#[allow(dead_code)]
pub fn implant_iso(path: &Path, force: bool) -> Result<String, String> {
    io::ensure_writable_file(path)?;
    is_probably_iso(path)?;

    let existing = io::read_appdata(path)?;
    if &existing[0..8] == MAGIC && !force {
        // already ours — fall through and overwrite
    } else if !existing.iter().all(|b| *b == APPDATA_FILL) && !force {
        return Err("appdata not blank; use --force".into());
    }

    // Blank first so the digest does not include itself.
    let blank = [APPDATA_FILL; APPDATA_SIZE];
    io::write_appdata(path, &blank)?;

    let digest = hash::compute_blake3_normalized(path, 1024 * 1024, |_| {})?;

    let mut record = [APPDATA_FILL; APPDATA_SIZE];
    record[0..8].copy_from_slice(MAGIC);
    record[8] = VERSION;
    record[9] = ALGO_BLAKE3_256;
    record[10..12].copy_from_slice(&DIGEST_LEN.to_le_bytes());
    record[12..16].copy_from_slice(&FLAGS.to_le_bytes());
    record[16..48].copy_from_slice(&digest);

    io::write_appdata(path, &record)?;

    Ok(format!(
        "Implanted ISOB3 ({}) into {}",
        hash::hex(&digest),
        path.display()
    ))
}

/// Remove ISOB3 metadata from an ISO file by blanking the application-use area.
#[allow(dead_code)]
pub fn remove_iso(path: &Path) -> Result<String, String> {
    io::ensure_writable_file(path)?;
    is_probably_iso(path)?;
    let blank = [APPDATA_FILL; APPDATA_SIZE];
    io::write_appdata(path, &blank)?;
    Ok(format!("Removed ISOB3 metadata from {}", path.display()))
}

/// Print the ISOB3 metadata embedded in an ISO file without re-verifying content.
///
/// Returns a formatted multi-line string on success, or `"No ISOB3 metadata found."`
/// if the application-use area does not start with the ISOB3 magic.
#[allow(dead_code)]
pub fn info_iso(path: &Path) -> Result<String, String> {
    io::ensure_readable(path)?;
    is_probably_iso(path)?;

    let appdata = io::read_appdata(path)?;
    if &appdata[0..8] != MAGIC {
        return Ok("No ISOB3 metadata found.".to_string());
    }

    let version = appdata[8];
    let algo = appdata[9];
    let digest_len = u16::from_le_bytes([appdata[10], appdata[11]]);
    let flags = u32::from_le_bytes([appdata[12], appdata[13], appdata[14], appdata[15]]);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&appdata[16..48]);

    let algo_name = if algo == ALGO_BLAKE3_256 { "BLAKE3-256" } else { "Unknown" };

    Ok(format!(
        "ISOB3 metadata found\nVersion: {}\nAlgorithm: {}\nDigest len: {}\nFlags: {}\nDigest: {}\nOffset: 0x{:X}",
        version, algo_name, digest_len, flags, hash::hex(&digest), APPDATA_OFFSET
    ))
}
