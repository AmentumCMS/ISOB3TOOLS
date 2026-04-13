// to run: cargo run --release --example benchmark

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use md5::{Digest, Md5};

const CHUNK_SIZES: [usize; 1] = [
    1 * 1024 * 1024, // 1 MiB
                     // 2 * 1024 * 1024,       // 2 MiB
                     // 3 * 1024 * 1024,       // 3 MiB
                     // 4 * 1024 * 1024,       // 4 MiB
                     // 8 * 1024 * 1024,       // 8 MiB
                     // 16 * 1024 * 1024,      // 16 MiB
                     // 32 * 1024 * 1024,      // 32 MiB
                     // 64 * 1024 * 1024,      // 64 MiB
                     // 128 * 1024 * 1024,     // 128 MiB
                     // 256 * 1024 * 1024,     // 256 MiB
                     // 512 * 1024 * 1024,     // 512 MiB
                     // 1024 * 1024 * 1024,    // 1 GiB
];

#[derive(Parser, Debug)]
#[command(about = "Benchmark MD5 vs BLAKE3 across multiple chunk sizes")]
struct Args {
    file: PathBuf,

    #[arg(long, default_value_t = 3)]
    rounds: usize,
}

#[derive(Debug, Clone)]
struct ResultRow {
    chunk_size: usize,
    digest: String,
    seconds: f64,
    bps: f64,
}

fn human_bytes(num_bytes: usize) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = num_bytes as f64;

    for unit in units {
        if value < 1024.0 || unit == "TiB" {
            return format!("{value:.2} {unit}");
        }
        value /= 1024.0;
    }

    format!("{num_bytes} B")
}

fn benchmark_md5(
    file_path: &PathBuf,
    chunk_size: usize,
    rounds: usize,
) -> anyhow::Result<ResultRow> {
    let file_size = std::fs::metadata(file_path)?.len() as f64;
    let mut best_time = f64::INFINITY;
    let mut best_digest = String::new();

    for _ in 0..rounds {
        let mut file = File::open(file_path)?;
        let mut hasher = Md5::new();
        let mut buf = vec![0u8; chunk_size];

        let start = Instant::now();

        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        let elapsed = start.elapsed().as_secs_f64();
        let digest = hex_digest(&hasher.finalize());

        if elapsed < best_time {
            best_time = elapsed;
            best_digest = digest;
        }
    }

    Ok(ResultRow {
        chunk_size,
        digest: best_digest,
        seconds: best_time,
        bps: file_size / best_time,
    })
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

fn benchmark_blake3(
    file_path: &PathBuf,
    chunk_size: usize,
    rounds: usize,
) -> anyhow::Result<ResultRow> {
    let file_size = std::fs::metadata(file_path)?.len() as f64;
    let mut best_time = f64::INFINITY;
    let mut best_digest = String::new();

    for _ in 0..rounds {
        let mut file = File::open(file_path)?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; chunk_size];

        let start = Instant::now();

        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        let elapsed = start.elapsed().as_secs_f64();
        let digest = hasher.finalize().to_hex().to_string();

        if elapsed < best_time {
            best_time = elapsed;
            best_digest = digest;
        }
    }

    Ok(ResultRow {
        chunk_size,
        digest: best_digest,
        seconds: best_time,
        bps: file_size / best_time,
    })
}
fn benchmark_blake3_mmap(file_path: &PathBuf, rounds: usize) -> anyhow::Result<ResultRow> {
    let file_size = std::fs::metadata(file_path)?.len() as f64;
    let mut best_time = f64::INFINITY;
    let mut best_digest = String::new();

    for _ in 0..rounds {
        let file = File::open(file_path)?;
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };

        let start = Instant::now();
        let digest = blake3::hash(&mmap).to_hex().to_string();
        let elapsed = start.elapsed().as_secs_f64();

        if elapsed < best_time {
            best_time = elapsed;
            best_digest = digest;
        }
    }

    Ok(ResultRow {
        chunk_size: 0,
        digest: best_digest,
        seconds: best_time,
        bps: file_size / best_time,
    })
}
fn print_mmap_result(label: &str, result: &ResultRow) {
    let mib_s = result.bps / (1024.0 * 1024.0);
    let gib_s = mib_s / 1024.0;

    println!("{label}:");
    println!("  Mode       : mmap()");
    println!("  Time       : {:.4} s", result.seconds);
    println!("  Throughput : {:.2} MiB/s ({:.2} GiB/s)", mib_s, gib_s);
    println!("  Digest     : {}", result.digest);
    println!();
}
fn print_algo_results(algo_name: &str, results: &[ResultRow]) {
    println!("{algo_name}:");
    println!(
        "{:>10}  {:>10}  {:>12}  {:>10}",
        "Chunk", "Time (s)", "MiB/s", "GiB/s"
    );
    println!("{}", "-".repeat(50));

    for row in results {
        let mib_s = row.bps / (1024.0 * 1024.0);
        let gib_s = mib_s / 1024.0;
        println!(
            "{:>10}  {:>10.4}  {:>12.2}  {:>10.2}",
            human_bytes(row.chunk_size),
            row.seconds,
            mib_s,
            gib_s
        );
    }

    let best = results
        .iter()
        .max_by(|a, b| a.bps.partial_cmp(&b.bps).unwrap())
        .unwrap();

    println!();
    println!("Best chunk size : {}", human_bytes(best.chunk_size));
    println!("Best time       : {:.4} s", best.seconds);
    println!(
        "Best throughput : {:.2} MiB/s",
        best.bps / (1024.0 * 1024.0)
    );
    println!("Digest          : {}", best.digest);
    println!();
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if !args.file.exists() {
        anyhow::bail!("File not found: {}", args.file.display());
    }
    if !args.file.is_file() {
        anyhow::bail!("Not a regular file: {}", args.file.display());
    }

    let file_size = std::fs::metadata(&args.file)?.len() as usize;

    println!("File   : {}", args.file.display());
    println!("Size   : {} ({file_size} bytes)", human_bytes(file_size));
    println!("Rounds : {}", args.rounds);
    println!(
        "Chunks : {}",
        CHUNK_SIZES
            .iter()
            .map(|&s| human_bytes(s))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!();

    let mut md5_results = Vec::new();
    let mut blake3_results = Vec::new();

    for &chunk_size in &CHUNK_SIZES {
        md5_results.push(benchmark_md5(&args.file, chunk_size, args.rounds)?);
        blake3_results.push(benchmark_blake3(&args.file, chunk_size, args.rounds)?);
    }

    print_algo_results("MD5", &md5_results);
    print_algo_results("BLAKE3", &blake3_results);

    let mmap_result = benchmark_blake3_mmap(&args.file, args.rounds)?;
    print_mmap_result("BLAKE3 (mmap)", &mmap_result);

    let best_md5 = md5_results
        .iter()
        .max_by(|a, b| a.bps.partial_cmp(&b.bps).unwrap())
        .unwrap();

    let best_blake3 = blake3_results
        .iter()
        .max_by(|a, b| a.bps.partial_cmp(&b.bps).unwrap())
        .unwrap();

    let speedup = best_md5.seconds / best_blake3.seconds;
    let winner = if best_blake3.seconds < best_md5.seconds {
        "BLAKE3"
    } else {
        "MD5"
    };

    println!("Overall best comparison:");
    println!(
        "  MD5 best    : {} at {:.2} MiB/s",
        human_bytes(best_md5.chunk_size),
        best_md5.bps / (1024.0 * 1024.0)
    );
    println!(
        "  BLAKE3 best : {} at {:.2} MiB/s",
        human_bytes(best_blake3.chunk_size),
        best_blake3.bps / (1024.0 * 1024.0)
    );
    println!("  Winner      : {winner}");
    println!(
        "  Speedup     : {:.2}x (MD5 best time / BLAKE3 best time)",
        speedup
    );

    Ok(())
}
