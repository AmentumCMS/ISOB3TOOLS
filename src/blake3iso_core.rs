//! ISOB3 metadata implant, check, and removal for ISO9660 images.
//!
//! The ISOB3 record is stored in the 512-byte **application-use area** of the
//! ISO9660 Primary Volume Descriptor (PVD), at byte offset `0x8373`.
//!
//! ## Layout of the application-use area (ISOB3APP, v1)
//!
//! | Offset | Size | Field            |
//! |--------|------|-----------------|
//! | 0      | 8    | Magic `"ISOB3APP"` |
//! | 8      | 1    | Version (`0x01`) |
//! | 9      | 1    | Algorithm (`0x01` = BLAKE3-256) |
//! | 10     | 2    | Digest length LE (`32`) |
//! | 12     | 4    | Flags LE (reserved, `0`) |
//! | 16     | 32   | BLAKE3-256 digest |
//!
//! The digest is computed with the application-use area itself **zeroed** so
//! the stored value does not influence the hash.  This is the same normalisation
//! applied during implant, check, and removal so all three operations agree.
//!
//! On Windows raw optical devices (`\\.\CdRomN`) all reads are sector-aligned
//! because the OS driver rejects unaligned requests.  A retry loop with a short
//! delay handles transient `ERROR_SEM_TIMEOUT` (121) errors that can occur on
//! some drives during spin-up.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use blake3::Hasher;

const ISO_SECTOR_SIZE: u64 = 2048;
const PVD_SECTOR: u64 = 16;
const PVD_OFFSET: u64 = PVD_SECTOR * ISO_SECTOR_SIZE;
const PVD_SIZE: usize = 2048;

const APPDATA_OFFSET: u64 = 0x8373;
const APPDATA_SIZE: usize = 512;
const APPDATA_FILL: u8 = b' ';

const MAGIC: &[u8; 8] = b"ISOB3APP";
const VERSION: u8 = 1;
const ALGO_BLAKE3_256: u8 = 1;
const FLAGS: u32 = 0;
const DIGEST_LEN: u16 = 32;
const READ_RETRY_COUNT: usize = 4;
const READ_RETRY_DELAY_MS: u64 = 250;

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

fn is_windows_raw_device(path: &Path) -> bool {
    #[cfg(windows)]
    {
        path.to_string_lossy().starts_with(r"\\.\")
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}

fn ensure_readable(path: &Path) -> Result<(), String> {
    File::open(path)
        .map(|_| ())
        .map_err(|e| format!("open failed: {e}"))
}

#[allow(dead_code)]
fn ensure_writable_file(path: &Path) -> Result<(), String> {
    if is_windows_raw_device(path) {
        return Err("writing to raw devices is not supported".to_string());
    }

    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map(|_| ())
        .map_err(|e| format!("open for write failed: {e}"))
}

fn is_probably_iso(path: &Path) -> Result<(), String> {
    let mut pvd = [0u8; 7];
    read_exact_at(path, PVD_OFFSET, &mut pvd)?;
    validate_pvd(&pvd)
}

fn validate_pvd(pvd: &[u8]) -> Result<(), String> {
    if pvd[0] != 1 || &pvd[1..6] != b"CD001" || pvd[6] != 1 {
        return Err("not a recognizable ISO9660 primary volume descriptor".to_string());
    }
    Ok(())
}

fn read_appdata(path: &Path) -> Result<[u8; APPDATA_SIZE], String> {
    let mut buf = [0u8; APPDATA_SIZE];
    read_exact_at(path, APPDATA_OFFSET, &mut buf)?;
    Ok(buf)
}

#[allow(dead_code)]
fn write_appdata(path: &Path, appdata: &[u8; APPDATA_SIZE]) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("open for write failed: {e}"))?;

    f.seek(SeekFrom::Start(APPDATA_OFFSET))
        .map_err(|e| format!("seek failed: {e}"))?;
    f.write_all(appdata)
        .map_err(|e| format!("write failed: {e}"))?;
    f.flush().map_err(|e| format!("flush failed: {e}"))?;
    Ok(())
}

fn compute_blake3_normalized<F>(
    path: &Path,
    chunk_size: usize,
    progress: F,
) -> Result<[u8; 32], String>
where
    F: FnMut(u64),
{
    compute_blake3_normalized_with_cancel(path, chunk_size, progress, || false)
}

fn compute_blake3_normalized_with_cancel<F, G>(
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

    // Hash as if the application-use area were blank so implant/check/remove all agree.
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

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn read_metadata(path: &Path) -> Result<Option<[u8; 32]>, String> {
    let buf = read_appdata(path)?;
    read_metadata_from_appdata(&buf)
}

fn read_metadata_from_appdata(buf: &[u8; APPDATA_SIZE]) -> Result<Option<[u8; 32]>, String> {
    if &buf[0..8] != MAGIC {
        return Ok(None);
    }
    if buf[8] != VERSION {
        return Ok(None);
    }
    if buf[9] != ALGO_BLAKE3_256 {
        return Ok(None);
    }
    if u16::from_le_bytes([buf[10], buf[11]]) != DIGEST_LEN {
        return Ok(None);
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&buf[16..48]);
    Ok(Some(digest))
}

#[allow(dead_code)]
pub fn check_iso(path: &Path) -> Result<CheckOutcome, String> {
    check_iso_with_progress(path, |_| {})
}

pub fn check_iso_with_progress<F>(path: &Path, progress: F) -> Result<CheckOutcome, String>
where
    F: FnMut(u64),
{
    check_iso_with_progress_and_cancel(path, progress, || false)
}

/// Verify the ISOB3 record embedded in an ISO image or raw optical device.
///
/// Returns [`CheckOutcome::Missing`] if no record is present, so the caller
/// can fall back to ISOMD5 or report "no metadata".
pub fn check_iso_with_progress_and_cancel<F, G>(
    path: &Path,
    progress: F,
    should_abort: G,
) -> Result<CheckOutcome, String>
where
    F: FnMut(u64),
    G: FnMut() -> bool,
{
    ensure_readable(path)?;
    is_probably_iso(path)?;

    let stored = match read_metadata(path)? {
        Some(d) => d,
        None => return Ok(CheckOutcome::Missing),
    };

    let actual = compute_blake3_normalized_with_cancel(path, 1024 * 1024, progress, should_abort)?;

    let stored_hex = hex(&stored);
    let actual_hex = hex(&actual);

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
    appdata
        .copy_from_slice(&bytes[APPDATA_OFFSET as usize..APPDATA_OFFSET as usize + APPDATA_SIZE]);

    let stored = match read_metadata_from_appdata(&appdata)? {
        Some(d) => d,
        None => return Ok(CheckOutcome::Missing),
    };

    let actual = compute_blake3_normalized_bytes(bytes);
    let stored_hex = hex(&stored);
    let actual_hex = hex(&actual);

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
/// Used to populate the progress bar before hashing begins.  The estimate is
/// `sector_count × 2048`; it may differ slightly from the actual file size due
/// to trailing padding or raw-device sector overhead.
pub fn estimate_iso_bytes(path: &Path) -> Result<u64, String> {
    let mut pvd = [0u8; PVD_SIZE];
    read_exact_at(path, PVD_OFFSET, &mut pvd)?;
    validate_pvd(&pvd[..7])?;

    let sector_count = u32::from_le_bytes(
        pvd[80..84]
            .try_into()
            .map_err(|_| "invalid volume space size in PVD".to_string())?,
    ) as u64;

    Ok(sector_count.saturating_mul(ISO_SECTOR_SIZE))
}

#[allow(dead_code)]
pub fn implant_iso(path: &Path, force: bool) -> Result<String, String> {
    ensure_writable_file(path)?;
    is_probably_iso(path)?;

    let existing = read_appdata(path)?;

    if &existing[0..8] == MAGIC && !force {
        // overwrite allowed
    } else if !existing.iter().all(|b| *b == APPDATA_FILL) && !force {
        return Err("appdata not blank; use --force".into());
    }

    // Blank the metadata window before hashing so the stored digest does not include itself.
    let blank = [APPDATA_FILL; APPDATA_SIZE];
    write_appdata(path, &blank)?;

    let digest = compute_blake3_normalized(path, 1024 * 1024, |_| {})?;

    let mut new = [APPDATA_FILL; APPDATA_SIZE];
    new[0..8].copy_from_slice(MAGIC);
    new[8] = VERSION;
    new[9] = ALGO_BLAKE3_256;
    new[10..12].copy_from_slice(&DIGEST_LEN.to_le_bytes());
    new[12..16].copy_from_slice(&FLAGS.to_le_bytes());
    new[16..48].copy_from_slice(&digest);

    write_appdata(path, &new)?;

    Ok(format!(
        "Implanted ISOB3 ({}) into {}",
        hex(&digest),
        path.display()
    ))
}

#[allow(dead_code)]
pub fn remove_iso(path: &Path) -> Result<String, String> {
    ensure_writable_file(path)?;
    is_probably_iso(path)?;

    let blank = [APPDATA_FILL; APPDATA_SIZE];
    write_appdata(path, &blank)?;

    Ok(format!("Removed ISOB3 metadata from {}", path.display()))
}

#[allow(dead_code)]
pub fn info_iso(path: &Path) -> Result<String, String> {
    ensure_readable(path)?;
    is_probably_iso(path)?;

    let appdata = read_appdata(path)?;

    if &appdata[0..8] != MAGIC {
        return Ok("No ISOB3 metadata found.".to_string());
    }

    let version = appdata[8];
    let algo = appdata[9];
    let digest_len = u16::from_le_bytes([appdata[10], appdata[11]]);
    let flags = u32::from_le_bytes([appdata[12], appdata[13], appdata[14], appdata[15]]);

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&appdata[16..48]);

    let algo_name = if algo == ALGO_BLAKE3_256 {
        "BLAKE3-256"
    } else {
        "Unknown"
    };

    Ok(format!(
        "ISOB3 metadata found\nVersion: {}\nAlgorithm: {}\nDigest len: {}\nFlags: {}\nDigest: {}\nOffset: 0x{:X}",
        version,
        algo_name,
        digest_len,
        flags,
        hex(&digest),
        APPDATA_OFFSET
    ))
}

fn read_exact_at(path: &Path, offset: u64, buf: &mut [u8]) -> Result<(), String> {
    if is_windows_raw_device(path) {
        // Windows raw optical devices require sector-aligned reads.
        return read_exact_at_raw(path, offset, buf);
    }

    let mut f = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    f.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("seek failed: {e}"))?;
    read_exact_with_retries(path, &mut f, buf)?;
    Ok(())
}

fn read_exact_at_raw(path: &Path, offset: u64, out: &mut [u8]) -> Result<(), String> {
    let mut f = File::open(path).map_err(|e| format!("open failed: {e}"))?;

    let sector_size = ISO_SECTOR_SIZE as usize;
    let start_sector = offset / ISO_SECTOR_SIZE;
    let end_offset = offset + out.len() as u64;
    let end_sector = (end_offset.saturating_sub(1)) / ISO_SECTOR_SIZE;
    let sector_count = (end_sector - start_sector + 1) as usize;
    let aligned = start_sector * ISO_SECTOR_SIZE;

    // Read the minimal aligned sector range, then slice out the requested bytes.
    let mut buf = vec![0u8; sector_count * sector_size];
    f.seek(SeekFrom::Start(aligned))
        .map_err(|e| format!("seek failed: {e}"))?;
    read_exact_with_retries(path, &mut f, &mut buf)?;

    let local = (offset - aligned) as usize;
    out.copy_from_slice(&buf[local..local + out.len()]);
    Ok(())
}

fn compute_blake3_normalized_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut normalized = bytes.to_vec();
    let start = APPDATA_OFFSET as usize;
    let end = start.saturating_add(APPDATA_SIZE).min(normalized.len());
    if start < end {
        normalized[start..end].fill(APPDATA_FILL);
    }
    *blake3::hash(&normalized).as_bytes()
}

fn read_with_retries(path: &Path, file: &mut File, buf: &mut [u8]) -> Result<usize, String> {
    retry_read(path, || file.read(buf))
}

fn read_exact_with_retries(path: &Path, file: &mut File, buf: &mut [u8]) -> Result<(), String> {
    retry_read(path, || file.read_exact(buf))
}

fn retry_read<T, F>(path: &Path, mut op: F) -> Result<T, String>
where
    F: FnMut() -> io::Result<T>,
{
    let mut last_err = None;

    for attempt in 0..READ_RETRY_COUNT {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) if should_retry_read(path, &err) && attempt + 1 < READ_RETRY_COUNT => {
                last_err = Some(err);
                thread::sleep(Duration::from_millis(READ_RETRY_DELAY_MS));
            }
            Err(err) => return Err(format!("read failed: {err}")),
        }
    }

    Err(format!(
        "read failed: {}",
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown read error".to_string())
    ))
}

fn should_retry_read(path: &Path, err: &io::Error) -> bool {
    is_windows_raw_device(path) && err.raw_os_error() == Some(121)
}
