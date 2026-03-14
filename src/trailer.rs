use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
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

/// Read and validate an ISOB3 trailer from the end of a file.
///
/// Returns:
/// - `Ok(Some(Trailer))` if a valid trailer exists
/// - `Ok(None)` if the file does not contain a valid ISOB3 trailer
/// - `Err(...)` for actual I/O failures
pub fn read_trailer(path: &Path) -> Result<Option<Trailer>, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("stat failed: {e}"))?;
    let file_size = metadata.len();

    // Too small to possibly contain a trailer.
    if file_size < TRAILER_SIZE as u64 {
        return Ok(None);
    }

    let mut f = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    f.seek(SeekFrom::Start(file_size - TRAILER_SIZE as u64))
        .map_err(|e| format!("seek failed: {e}"))?;

    let mut raw = [0u8; TRAILER_SIZE];
    f.read_exact(&mut raw)
        .map_err(|e| format!("read trailer failed: {e}"))?;

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

    // Validate trailer fields. If any do not match expectations, treat the file
    // as not containing a valid ISOB3 trailer rather than as a hard failure.
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

    // Payload must fit within the file before the trailer begins.
    if payload_size > file_size - TRAILER_SIZE as u64 {
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

    let payload_size = fs::metadata(path)
        .map_err(|e| format!("stat failed: {e}"))?
        .len();

    let digest = compute_blake3(path, payload_size, 4 * 1024 * 1024)?;
    let trailer = build_trailer_bytes(payload_size, digest);

    let mut f = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|e| format!("open for append failed: {e}"))?;

    f.write_all(&trailer)
        .map_err(|e| format!("write trailer failed: {e}"))?;

    Ok(hex_encode(&digest))
}
