use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use blake3::Hasher;

const ISO_SECTOR_SIZE: u64 = 2048;
const PVD_SECTOR: u64 = 16;
const PVD_OFFSET: u64 = PVD_SECTOR * ISO_SECTOR_SIZE;

const APPDATA_OFFSET: u64 = 0x8373;
const APPDATA_SIZE: usize = 512;
const APPDATA_FILL: u8 = b' ';

const MAGIC: &[u8; 8] = b"ISOB3APP";
const VERSION: u8 = 1;
const ALGO_BLAKE3_256: u8 = 1;
const FLAGS: u32 = 0;
const DIGEST_LEN: u16 = 32;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum CheckOutcome {
    Valid {
        digest_hex: String,
        detail: String,
    },
    Invalid {
        expected_hex: String,
        actual_hex: String,
        detail: String,
    },
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

fn compute_blake3_normalized(path: &Path, chunk_size: usize) -> Result<[u8; 32], String> {
    let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut hasher = Hasher::new();
    let mut buf = vec![0u8; chunk_size];
    let mut offset = 0u64;

    let app_start = APPDATA_OFFSET;
    let app_end = APPDATA_OFFSET + APPDATA_SIZE as u64;

    loop {
        let n = file.read(&mut buf).map_err(|e| format!("read failed: {e}"))?;
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

pub fn check_iso(path: &Path) -> Result<CheckOutcome, String> {
    ensure_readable(path)?;
    is_probably_iso(path)?;

    let stored = match read_metadata(path)? {
        Some(d) => d,
        None => return Ok(CheckOutcome::Missing),
    };

    let actual = compute_blake3_normalized(path, 1024 * 1024)?;

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
            detail: format!(
                "ISOB3 mismatch\nExpected: {stored_hex}\nActual:   {actual_hex}"
            ),
        })
    }
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

    let blank = [APPDATA_FILL; APPDATA_SIZE];
    write_appdata(path, &blank)?;

    let digest = compute_blake3_normalized(path, 1024 * 1024)?;

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
        return read_exact_at_raw(path, offset, buf);
    }

    let mut f = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    f.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("seek failed: {e}"))?;
    f.read_exact(buf)
        .map_err(|e| format!("read failed: {e}"))?;
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

    let mut buf = vec![0u8; sector_count * sector_size];
    f.seek(SeekFrom::Start(aligned))
        .map_err(|e| format!("seek failed: {e}"))?;
    f.read_exact(&mut buf)
        .map_err(|e| format!("read failed: {e}"))?;

    let local = (offset - aligned) as usize;
    out.copy_from_slice(&buf[local..local + out.len()]);
    Ok(())
}