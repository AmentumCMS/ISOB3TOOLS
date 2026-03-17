use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use blake3::Hasher;

/// Fixed marker written at the end of a file to identify an ISOB3 trailer.
pub const MAGIC: &[u8; 8] = b"ISOB3TR1";

/// Trailer format version.
pub const VERSION: u8 = 1;

/// Algorithm identifier for BLAKE3-256.
pub const ALGO_BLAKE3_256: u8 = 1;

/// Serialized trailer size in bytes.
///
/// Layout:
/// - 8  bytes: magic
/// - 1  byte : version
/// - 1  byte : algorithm id
/// - 2  bytes: digest length
/// - 4  bytes: reserved
/// - 8  bytes: payload size
/// - 32 bytes: BLAKE3 digest
pub const TRAILER_SIZE: usize = 8 + 1 + 1 + 2 + 4 + 8 + 32;

/// Parsed ISOB3 trailer contents.
#[derive(Debug, Clone)]
pub struct Trailer {
    pub payload_size: u64,
    pub digest: [u8; 32],
}

/// Convert bytes to lowercase hexadecimal.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(windows)]
use std::os::windows::fs::FileExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::GetFileSizeEx;
#[cfg(windows)]
use windows::Win32::System::IO::DeviceIoControl;

#[cfg(windows)]
const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007405c;

#[cfg(windows)]
#[repr(C)]
struct GetLengthInformation {
    length: i64,
}

/// Read and validate an ISOB3 trailer from the end of a file.
///
/// Returns:
/// - `Ok(Some(Trailer))` if a valid trailer exists
/// - `Ok(None)` if the file does not contain a valid ISOB3 trailer
/// - `Err(...)` for actual I/O failures
pub fn read_trailer(path: &Path) -> Result<Option<Trailer>, String> {
    #[cfg(windows)]
    {
        if is_windows_cdrom_device(path) {
            return read_trailer_streaming_windows_cdrom(path);
        }
    }

    let file_size = get_path_len(path)?;

    if file_size < TRAILER_SIZE as u64 {
        return Ok(None);
    }

    let trailer_offset = file_size - TRAILER_SIZE as u64;
    let mut raw = [0u8; TRAILER_SIZE];

    #[cfg(windows)]
    {
        // Non-CdRom Windows paths can still use aligned positional reads.
        let sector_size = get_windows_read_alignment(path).unwrap_or(2048);
        let trailer_bytes = read_exact_at_aligned(path, trailer_offset, TRAILER_SIZE, sector_size)?;
        raw.copy_from_slice(&trailer_bytes);
    }

    #[cfg(not(windows))]
    {
        let mut f = File::open(path).map_err(|e| format!("open failed: {e}"))?;
        f.seek(SeekFrom::Start(trailer_offset))
            .map_err(|e| format!("seek failed: {e}"))?;
        f.read_exact(&mut raw)
            .map_err(|e| format!("read trailer failed: {e}"))?;
    }

    parse_trailer_bytes(&raw, file_size)
}

fn parse_trailer_bytes(raw: &[u8; TRAILER_SIZE], file_size: u64) -> Result<Option<Trailer>, String> {
    let magic = &raw[0..8];
    let version = raw[8];
    let algo = raw[9];
    let digest_len = u16::from_le_bytes([raw[10], raw[11]]);
    let _reserved = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
    let payload_size = u64::from_le_bytes([
        raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
    ]);

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&raw[24..56]);

    if magic != MAGIC {
        return Ok(None);
    }
    if version != VERSION {
        return Ok(None);
    }
    if algo != ALGO_BLAKE3_256 {
        return Ok(None);
    }
    if digest_len != 32 {
        return Ok(None);
    }
    if payload_size > file_size.saturating_sub(TRAILER_SIZE as u64) {
        return Ok(None);
    }

    Ok(Some(Trailer {
        payload_size,
        digest,
    }))
}

/// Compute a BLAKE3 digest over the first `size` bytes of a file.
///
/// This is used both for verifying an existing trailer and for creating a new one.
/// `chunk_size` controls the read buffer size, not the digest format.
pub fn compute_blake3(path: &Path, size: u64, chunk_size: usize) -> Result<[u8; 32], String> {
    #[cfg(windows)]
    {
        if is_windows_cdrom_device(path) {
            return compute_blake3_streaming_windows_cdrom(path, size);
        }

        let sector_size = get_windows_read_alignment(path).unwrap_or(2048);
        return compute_blake3_windows_aligned(path, size, chunk_size, sector_size);
    }

    #[cfg(not(windows))]
    {
        let mut f = File::open(path).map_err(|e| format!("open failed: {e}"))?;
        let mut hasher = Hasher::new();

        let mut remaining = size;
        let mut buffer = vec![0u8; chunk_size];

        while remaining > 0 {
            let to_read = remaining.min(chunk_size as u64) as usize;
            let n = f
                .read(&mut buffer[..to_read])
                .map_err(|e| format!("read failed: {e}"))?;

            if n == 0 {
                return Err(format!("unexpected EOF while hashing {}", path.display()));
            }

            hasher.update(&buffer[..n]);
            remaining -= n as u64;
        }

        Ok(*hasher.finalize().as_bytes())
    }
}

/// Result of checking a file for ISOB3 validity.
#[derive(Debug, Clone)]
pub enum VerifyOutcome {
    Valid { digest_hex: String },
    MissingTrailer,
    Mismatch { expected: String, actual: String },
}

/// Verify a file against its ISOB3 trailer, if present.
pub fn verify_isoblake3(path: &Path) -> Result<VerifyOutcome, String> {
    let trailer = match read_trailer(path)? {
        Some(t) => t,
        None => return Ok(VerifyOutcome::MissingTrailer),
    };

    // Only hash the original payload, not the appended trailer.
    let actual_digest = compute_blake3(path, trailer.payload_size, 4 * 1024 * 1024)?;
    let expected_digest = trailer.digest;

    if actual_digest == expected_digest {
        Ok(VerifyOutcome::Valid {
            digest_hex: hex_encode(&expected_digest),
        })
    } else {
        Ok(VerifyOutcome::Mismatch {
            expected: hex_encode(&expected_digest),
            actual: hex_encode(&actual_digest),
        })
    }
}

/// Build the raw serialized trailer bytes for appending to a file.
pub fn build_trailer_bytes(payload_size: u64, digest: [u8; 32]) -> [u8; TRAILER_SIZE] {
    let mut raw = [0u8; TRAILER_SIZE];

    raw[0..8].copy_from_slice(MAGIC);
    raw[8] = VERSION;
    raw[9] = ALGO_BLAKE3_256;
    raw[10..12].copy_from_slice(&32u16.to_le_bytes());
    raw[12..16].copy_from_slice(&0u32.to_le_bytes());
    raw[16..24].copy_from_slice(&payload_size.to_le_bytes());
    raw[24..56].copy_from_slice(&digest);

    raw
}

/// Compute and append an ISOB3 trailer to a file.
///
/// This modifies the file by writing a trailer to the end.
/// The returned string is the payload digest in hex.
pub fn embed_isob3_trailer(path: &Path) -> Result<String, String> {
    // Prevent double-embedding.
    if read_trailer(path)?.is_some() {
        return Err("ISO already has an ISOB3 trailer".to_string());
    }

    let payload_size = get_path_len(path)?;
    let digest = compute_blake3(path, payload_size, 4 * 1024 * 1024)?;
    let trailer = build_trailer_bytes(payload_size, digest);

    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|e| format!("open for append failed: {e}"))?;

    f.write_all(&trailer)
        .map_err(|e| format!("write trailer failed: {e}"))?;

    Ok(hex_encode(&digest))
}

fn get_path_len(path: &Path) -> Result<u64, String> {
    let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;

    // Normal files usually work here.
    if let Ok(len) = file.seek(SeekFrom::End(0)) {
        return Ok(len);
    }

    #[cfg(windows)]
    {
        let handle = HANDLE(file.as_raw_handle());

        // Fallback 1: GetFileSizeEx
        let mut size: i64 = 0;
        unsafe {
            if GetFileSizeEx(handle, &mut size).is_ok() && size >= 0 {
                return Ok(size as u64);
            }
        }

        // Fallback 2: IOCTL_DISK_GET_LENGTH_INFO
        let mut out = GetLengthInformation { length: 0 };
        let mut bytes_returned = 0u32;

        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_LENGTH_INFO,
                None,
                0,
                Some((&mut out as *mut GetLengthInformation).cast()),
                std::mem::size_of::<GetLengthInformation>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        if ok.is_ok() && out.length >= 0 {
            return Ok(out.length as u64);
        }

        return Err(format!(
            "{} opened successfully, but Windows would not report its length via standard file APIs or device IOCTLs.",
            path.display()
        ));
    }

    #[cfg(not(windows))]
    {
        Err(format!("seek-to-end failed: {}", path.display()))
    }
}

#[cfg(windows)]
fn is_windows_cdrom_device(path: &Path) -> bool {
    let s = path.to_string_lossy().to_ascii_lowercase();
    s.starts_with(r"\\.\cdrom")
}

#[cfg(windows)]
fn get_windows_read_alignment(_path: &Path) -> Result<u64, String> {
    // For finalized optical ISO-style media, 2048-byte sectors are the practical default.
    Ok(2048)
}

#[cfg(windows)]
fn read_exact_at_aligned(
    path: &Path,
    offset: u64,
    len: usize,
    sector_size: u64,
) -> Result<Vec<u8>, String> {
    let file_size = get_path_len(path)?;
    let f = File::open(path).map_err(|e| format!("open failed: {e}"))?;

    if offset > file_size {
        return Err(format!(
            "aligned read offset {} is beyond end of {} (size {})",
            offset,
            path.display(),
            file_size
        ));
    }

    let end = offset
        .checked_add(len as u64)
        .ok_or_else(|| "offset overflow while reading aligned region".to_string())?;

    if end > file_size {
        return Err(format!(
            "requested region [{}..{}) exceeds end of {} (size {})",
            offset,
            end,
            path.display(),
            file_size
        ));
    }

    let aligned_start = (offset / sector_size) * sector_size;
    let offset_in_buffer = (offset - aligned_start) as usize;
    let needed = offset_in_buffer + len;

    let desired_aligned_len =
        needed.div_ceil(sector_size as usize) * sector_size as usize;

    let max_readable = (file_size - aligned_start) as usize;
    let actual_read_len = desired_aligned_len.min(max_readable);

    if offset_in_buffer + len > actual_read_len {
        return Err(format!(
            "internal aligned read window too small for {}: need {}, have {}",
            path.display(),
            offset_in_buffer + len,
            actual_read_len
        ));
    }

    let mut buf = vec![0u8; actual_read_len];
    let mut read_total = 0usize;

    while read_total < actual_read_len {
        let n = f
            .seek_read(
                &mut buf[read_total..actual_read_len],
                aligned_start + read_total as u64,
            )
            .map_err(|e| format!("aligned read failed: {e}"))?;

        if n == 0 {
            return Err(format!(
                "unexpected EOF while reading aligned region from {} (start={}, requested={}, got={})",
                path.display(),
                aligned_start,
                actual_read_len,
                read_total
            ));
        }

        read_total += n;
    }

    Ok(buf[offset_in_buffer..offset_in_buffer + len].to_vec())
}

#[cfg(windows)]
fn compute_blake3_windows_aligned(
    path: &Path,
    size: u64,
    chunk_size: usize,
    sector_size: u64,
) -> Result<[u8; 32], String> {
    let file_size = get_path_len(path)?;
    if size > file_size {
        return Err(format!(
            "requested hash size {} exceeds media size {} for {}",
            size,
            file_size,
            path.display()
        ));
    }

    let f = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut hasher = Hasher::new();

    let aligned_chunk =
        chunk_size.div_ceil(sector_size as usize) * sector_size as usize;

    let mut offset = 0u64;
    let mut buffer = vec![0u8; aligned_chunk];

    while offset < size {
        let remaining = (size - offset) as usize;
        let to_take = remaining.min(chunk_size);

        let desired_aligned_take =
            to_take.div_ceil(sector_size as usize) * sector_size as usize;

        let max_readable = (size - offset) as usize;
        let actual_read_len = desired_aligned_take.min(max_readable);

        let mut read_total = 0usize;
        while read_total < actual_read_len {
            let n = f
                .seek_read(
                    &mut buffer[read_total..actual_read_len],
                    offset + read_total as u64,
                )
                .map_err(|e| format!("read failed: {e}"))?;

            if n == 0 {
                return Err(format!(
                    "unexpected EOF while hashing {} at offset {}",
                    path.display(),
                    offset + read_total as u64
                ));
            }

            read_total += n;
        }

        hasher.update(&buffer[..to_take]);
        offset += to_take as u64;
    }

    Ok(*hasher.finalize().as_bytes())
}

#[cfg(windows)]
fn read_trailer_streaming_windows_cdrom(path: &Path) -> Result<Option<Trailer>, String> {
    let file_size = get_path_len(path)?;
    if file_size < TRAILER_SIZE as u64 {
        return Ok(None);
    }

    let mut f = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut tail = Vec::<u8>::new();
    let mut total_read = 0u64;

    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("stream read failed: {e}"))?;

        if n == 0 {
            break;
        }

        total_read += n as u64;
        tail.extend_from_slice(&buf[..n]);

        if tail.len() > TRAILER_SIZE {
            let keep_from = tail.len() - TRAILER_SIZE;
            tail.drain(..keep_from);
        }
    }

    if total_read == 0 {
        return Err(format!("no data could be read from {}", path.display()));
    }

    if tail.len() < TRAILER_SIZE {
        return Ok(None);
    }

    let raw: [u8; TRAILER_SIZE] = tail
        .as_slice()
        .try_into()
        .map_err(|_| "failed to extract trailer bytes".to_string())?;

    parse_trailer_bytes(&raw, file_size)
}

#[cfg(windows)]
fn compute_blake3_streaming_windows_cdrom(path: &Path, size: u64) -> Result<[u8; 32], String> {
    let mut f = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut hasher = Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut remaining = size;

    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        let n = f
            .read(&mut buf[..to_read])
            .map_err(|e| format!("stream read failed: {e}"))?;

        if n == 0 {
            return Err(format!(
                "unexpected EOF while hashing {} ({} bytes remaining)",
                path.display(),
                remaining
            ));
        }

        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }

    Ok(*hasher.finalize().as_bytes())
}