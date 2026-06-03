//! File I/O helpers for reading and writing ISO9660 image data.
//!
//! ## Windows raw-device support
//!
//! On Windows, optical drives exposed as `\\.\CdRomN` require all reads to be
//! sector-aligned (multiples of 2048 bytes) because the kernel driver rejects
//! unaligned requests.  [`read_exact_at`] detects raw-device paths and delegates
//! to [`read_exact_at_raw`], which rounds the request down to the nearest sector
//! boundary, reads the covering sector range, and slices out the requested bytes.
//!
//! ## Retry logic
//!
//! Optical drives on Windows can return `ERROR_SEM_TIMEOUT` (OS error 121) during
//! spin-up.  [`retry_read`] retries up to [`READ_RETRY_COUNT`] times with a
//! short delay between attempts before propagating the error.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use super::{APPDATA_OFFSET, APPDATA_SIZE, ISO_SECTOR_SIZE};

pub(super) const READ_RETRY_COUNT: usize = 4;
pub(super) const READ_RETRY_DELAY_MS: u64 = 250;

// ── Device-type detection ──────────────────────────────────────────────────────

/// Return `true` if `path` refers to a Windows raw optical device (`\\.\CdRomN`).
pub(super) fn is_windows_raw_device(path: &Path) -> bool {
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

// ── Open guards ────────────────────────────────────────────────────────────────

/// Return `Ok(())` if `path` can be opened for reading, or an error string.
pub(super) fn ensure_readable(path: &Path) -> Result<(), String> {
    File::open(path)
        .map(|_| ())
        .map_err(|e| format!("open failed: {e}"))
}

/// Return `Ok(())` if `path` can be opened for read+write.
///
/// Always returns `Err` for Windows raw device paths since direct sector writes
/// are not supported.
#[allow(dead_code)]
pub(super) fn ensure_writable_file(path: &Path) -> Result<(), String> {
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

// ── Positioned reads and writes ────────────────────────────────────────────────

/// Read exactly `buf.len()` bytes starting at `offset` from `path`.
///
/// For Windows raw-device paths this delegates to [`read_exact_at_raw`] to
/// ensure sector alignment; for regular files a simple seek+read is used.
pub(super) fn read_exact_at(path: &Path, offset: u64, buf: &mut [u8]) -> Result<(), String> {
    if is_windows_raw_device(path) {
        return read_exact_at_raw(path, offset, buf);
    }
    let mut f = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    f.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("seek failed: {e}"))?;
    read_exact_with_retries(path, &mut f, buf)?;
    Ok(())
}

/// Sector-aligned positioned read for Windows raw optical devices.
///
/// Rounds `offset` down to the nearest sector boundary, reads the minimal
/// covering sector range, then copies the requested slice out of the buffer.
fn read_exact_at_raw(path: &Path, offset: u64, out: &mut [u8]) -> Result<(), String> {
    let mut f = File::open(path).map_err(|e| format!("open failed: {e}"))?;

    let sector_size = ISO_SECTOR_SIZE as usize;
    let start_sector = offset / ISO_SECTOR_SIZE;
    let end_offset = offset + out.len() as u64;
    let end_sector = (end_offset.saturating_sub(1)) / ISO_SECTOR_SIZE;
    let sector_count = (end_sector - start_sector + 1) as usize;
    let aligned = start_sector * ISO_SECTOR_SIZE;

    let mut buf = vec![0u8; sector_count * sector_size];
    f.seek(SeekFrom::Start(aligned))
        .map_err(|e| format!("seek failed: {e}"))?;
    read_exact_with_retries(path, &mut f, &mut buf)?;

    let local = (offset - aligned) as usize;
    out.copy_from_slice(&buf[local..local + out.len()]);
    Ok(())
}

/// Read the 512-byte ISOB3 application-use area from an ISO image.
pub(super) fn read_appdata(path: &Path) -> Result<[u8; APPDATA_SIZE], String> {
    let mut buf = [0u8; APPDATA_SIZE];
    read_exact_at(path, APPDATA_OFFSET, &mut buf)?;
    Ok(buf)
}

/// Overwrite the 512-byte application-use area of an ISO file at its fixed offset.
#[allow(dead_code)]
pub(super) fn write_appdata(path: &Path, appdata: &[u8; APPDATA_SIZE]) -> Result<(), String> {
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

// ── Retry wrappers ─────────────────────────────────────────────────────────────

/// Wrapper around `file.read(buf)` with optical-drive spin-up retry.
pub(super) fn read_with_retries(
    path: &Path,
    file: &mut File,
    buf: &mut [u8],
) -> Result<usize, String> {
    retry_read(path, || file.read(buf))
}

/// Wrapper around `file.read_exact(buf)` with optical-drive spin-up retry.
pub(super) fn read_exact_with_retries(
    path: &Path,
    file: &mut File,
    buf: &mut [u8],
) -> Result<(), String> {
    retry_read(path, || file.read_exact(buf))
}

/// Run `op` up to [`READ_RETRY_COUNT`] times, sleeping between attempts when the
/// error looks like a transient optical-drive timeout.
pub(super) fn retry_read<T, F>(path: &Path, mut op: F) -> Result<T, String>
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

/// Return `true` if the error is `ERROR_SEM_TIMEOUT` (OS error 121) on a
/// Windows raw device — a known transient spin-up condition.
fn should_retry_read(path: &Path, err: &io::Error) -> bool {
    is_windows_raw_device(path) && err.raw_os_error() == Some(121)
}
