// cargo run --release --bin blake3iso -- implant .\Atlassian-Group.iso
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use blake3::Hasher;
use clap::{Parser, Subcommand};

const MAGIC: &[u8; 8] = b"ISOB3TR1";
const VERSION: u8 = 1;
const ALGO_BLAKE3_256: u8 = 1;
const RESERVED: u32 = 0;

// Trailer layout:
// magic        8s
// version      B
// algo         B
// digest_len   H
// reserved     I
// file_size    Q   -> original file size without trailer
// digest       32s
//
// Total = 8 + 1 + 1 + 2 + 4 + 8 + 32 = 56 bytes
const TRAILER_SIZE: usize = 56;

#[derive(Debug, Clone)]
struct Trailer {
    magic: [u8; 8],
    version: u8,
    algo: u8,
    digest_len: u16,
    reserved: u32,
    file_size: u64,
    digest: [u8; 32],
}

impl Trailer {
    fn pack(&self) -> [u8; TRAILER_SIZE] {
        let mut out = [0u8; TRAILER_SIZE];

        out[0..8].copy_from_slice(&self.magic);
        out[8] = self.version;
        out[9] = self.algo;
        out[10..12].copy_from_slice(&self.digest_len.to_le_bytes());
        out[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        out[16..24].copy_from_slice(&self.file_size.to_le_bytes());
        out[24..56].copy_from_slice(&self.digest);

        out
    }

    fn unpack(data: &[u8]) -> Result<Self, String> {
        if data.len() != TRAILER_SIZE {
            return Err(format!("Expected {TRAILER_SIZE} bytes, got {}", data.len()));
        }

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&data[0..8]);

        let version = data[8];
        let algo = data[9];
        let digest_len = u16::from_le_bytes([data[10], data[11]]);
        let reserved = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let file_size = u64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);

        let mut digest = [0u8; 32];
        digest.copy_from_slice(&data[24..56]);

        Ok(Self {
            magic,
            version,
            algo,
            digest_len,
            reserved,
            file_size,
            digest,
        })
    }
}

fn read_trailer(path: &Path) -> Result<Option<Trailer>, String> {
    let file_size = fs::metadata(path)
        .map_err(|e| format!("stat failed: {e}"))?
        .len();

    if file_size < TRAILER_SIZE as u64 {
        return Ok(None);
    }

    let mut f = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    f.seek(SeekFrom::Start(file_size - TRAILER_SIZE as u64))
        .map_err(|e| format!("seek failed: {e}"))?;

    let mut raw = [0u8; TRAILER_SIZE];
    f.read_exact(&mut raw)
        .map_err(|e| format!("read trailer failed: {e}"))?;

    let trailer = match Trailer::unpack(&raw) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };

    if &trailer.magic != MAGIC {
        return Ok(None);
    }
    if trailer.version != VERSION {
        return Ok(None);
    }
    if trailer.algo != ALGO_BLAKE3_256 {
        return Ok(None);
    }
    if trailer.digest_len != 32 {
        return Ok(None);
    }
    if trailer.file_size > file_size - TRAILER_SIZE as u64 {
        return Ok(None);
    }

    Ok(Some(trailer))
}

fn payload_size(path: &Path) -> Result<u64, String> {
    match read_trailer(path)? {
        Some(trailer) => Ok(trailer.file_size),
        None => Ok(fs::metadata(path)
            .map_err(|e| format!("stat failed: {e}"))?
            .len()),
    }
}

fn compute_blake3(path: &Path, size: u64, chunk_size: usize) -> Result<[u8; 32], String> {
    let mut hasher = Hasher::new();
    let mut remaining = size;
    let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut buf = vec![0u8; chunk_size];

    while remaining > 0 {
        let to_read = remaining.min(chunk_size as u64) as usize;
        let n = file
            .read(&mut buf[..to_read])
            .map_err(|e| format!("read failed: {e}"))?;

        if n == 0 {
            return Err("Unexpected EOF while hashing".to_string());
        }

        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }

    Ok(*hasher.finalize().as_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn atomic_replace_bytes(
    path: &Path,
    new_payload: Option<&[u8]>,
    copy_from_size: Option<u64>,
    append: &[u8],
) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file");

    let tmp_path = unique_temp_path(parent, file_name);

    let write_result = (|| -> Result<(), String> {
        let mut out = File::create(&tmp_path).map_err(|e| format!("create temp failed: {e}"))?;

        if let Some(payload) = new_payload {
            out.write_all(payload)
                .map_err(|e| format!("write temp failed: {e}"))?;
        } else if let Some(copy_size) = copy_from_size {
            let mut src = File::open(path).map_err(|e| format!("open source failed: {e}"))?;
            let mut remaining = copy_size;
            let mut buf = vec![0u8; 1024 * 1024];

            while remaining > 0 {
                let to_read = remaining.min(buf.len() as u64) as usize;
                let n = src
                    .read(&mut buf[..to_read])
                    .map_err(|e| format!("copy read failed: {e}"))?;

                if n == 0 {
                    return Err("Unexpected EOF while copying".to_string());
                }

                out.write_all(&buf[..n])
                    .map_err(|e| format!("copy write failed: {e}"))?;
                remaining -= n as u64;
            }
        } else {
            return Err("Either new_payload or copy_from_size must be provided".to_string());
        }

        if !append.is_empty() {
            out.write_all(append)
                .map_err(|e| format!("append write failed: {e}"))?;
        }

        out.flush().map_err(|e| format!("flush failed: {e}"))?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp_path);
        return write_result;
    }

    fs::rename(&tmp_path, path).or_else(|_| {
        fs::remove_file(path).ok();
        fs::rename(&tmp_path, path)
    })
        .map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            format!("replace failed: {e}")
        })?;

    Ok(())
}

fn unique_temp_path(parent: &Path, file_name: &str) -> PathBuf {
    for i in 0..10_000u32 {
        let candidate = parent.join(format!("{file_name}.{i}.tmp"));
        if !candidate.exists() {
            return candidate;
        }
    }
    parent.join(format!("{file_name}.fallback.tmp"))
}

fn implant(path: &Path, force: bool) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("File not found: {}", path.display()));
    }

    let existing = read_trailer(path)?;
    let base_size = payload_size(path)?;
    let digest = compute_blake3(path, base_size, 1024 * 1024)?;

    let new_trailer = Trailer {
        magic: *MAGIC,
        version: VERSION,
        algo: ALGO_BLAKE3_256,
        digest_len: 32,
        reserved: RESERVED,
        file_size: base_size,
        digest,
    };

    if existing.is_some() && !force {
        println!("Existing BLAKE3 trailer found; replacing it.");
    }

    atomic_replace_bytes(path, None, Some(base_size), &new_trailer.pack())?;

    println!("Implanted BLAKE3 trailer into: {}", path.display());
    println!("Payload size : {base_size}");
    println!("BLAKE3       : {}", hex_encode(&digest));
    Ok(())
}

fn check(path: &Path) -> Result<i32, String> {
    if !path.exists() {
        return Err(format!("File not found: {}", path.display()));
    }

    let trailer = match read_trailer(path)? {
        Some(t) => t,
        None => {
            println!("No valid ISOB3 trailer found.");
            return Ok(2);
        }
    };

    let actual_size = fs::metadata(path)
        .map_err(|e| format!("stat failed: {e}"))?
        .len();
    let expected_total = trailer.file_size + TRAILER_SIZE as u64;

    if actual_size != expected_total {
        println!("WARNING: File size does not match implanted trailer metadata.");
        println!("Expected total size: {expected_total}");
        println!("Actual total size  : {actual_size}");
    }

    let digest = compute_blake3(path, trailer.file_size, 1024 * 1024)?;

    println!("Payload size : {}", trailer.file_size);
    println!("Stored BLAKE3: {}", hex_encode(&trailer.digest));
    println!("Actual BLAKE3: {}", hex_encode(&digest));

    if digest == trailer.digest {
        println!("VALID");
        Ok(0)
    } else {
        println!("INVALID");
        Ok(1)
    }
}

fn remove_trailer(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("File not found: {}", path.display()));
    }

    let trailer = match read_trailer(path)? {
        Some(t) => t,
        None => {
            println!("No ISOB3 trailer found; nothing to remove.");
            return Ok(());
        }
    };

    atomic_replace_bytes(path, None, Some(trailer.file_size), &[])?;

    println!("Removed BLAKE3 trailer from: {}", path.display());
    println!("Restored payload size: {}", trailer.file_size);
    Ok(())
}

fn info(path: &Path) -> Result<i32, String> {
    if !path.exists() {
        return Err(format!("File not found: {}", path.display()));
    }

    let trailer = match read_trailer(path)? {
        Some(t) => t,
        None => {
            let raw_size = fs::metadata(path)
                .map_err(|e| format!("stat failed: {e}"))?
                .len();
            println!("No valid ISOB3 trailer found.");
            println!("Raw file size: {raw_size}");
            return Ok(1);
        }
    };

    let total_size = fs::metadata(path)
        .map_err(|e| format!("stat failed: {e}"))?
        .len();

    println!("ISOB3 trailer found:");
    println!("  Version      : {}", trailer.version);
    println!("  Algorithm    : BLAKE3-256");
    println!("  Payload size : {}", trailer.file_size);
    println!("  Digest len   : {}", trailer.digest_len);
    println!("  Digest       : {}", hex_encode(&trailer.digest));
    println!("  Total size   : {}", total_size);

    Ok(0)
}

#[derive(Parser)]
#[command(name = "isoblake3")]
#[command(about = "Implant/check a BLAKE3 trailer in an ISO-like file.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Embed or replace the BLAKE3 trailer
    Implant {
        file: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Verify the embedded BLAKE3 trailer
    Check {
        file: PathBuf,
    },
    /// Remove the embedded BLAKE3 trailer
    Remove {
        file: PathBuf,
    },
    /// Show embedded trailer metadata
    Info {
        file: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    let code = match cli.command {
        Commands::Implant { file, force } => match implant(&file, force) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("ERROR: {e}");
                2
            }
        },
        Commands::Check { file } => match check(&file) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("ERROR: {e}");
                2
            }
        },
        Commands::Remove { file } => match remove_trailer(&file) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("ERROR: {e}");
                2
            }
        },
        Commands::Info { file } => match info(&file) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("ERROR: {e}");
                2
            }
        },
    };

    std::process::exit(code);
}