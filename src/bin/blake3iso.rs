//! `blake3iso` — CLI for ISOB3 metadata and ML-KEM-768 keypair management.
//!
//! ## Subcommands
//!
//! | Subcommand | Description                                                       |
//! |------------|-------------------------------------------------------------------|
//! | `implant`  | Write ISOB3 (BLAKE3) integrity metadata into an ISO file          |
//! | `check`    | Verify ISOB3 metadata; falls back to ISOMD5 if absent            |
//! | `remove`   | Strip ISOB3 metadata from an ISO file                             |
//! | `info`     | Print embedded metadata without verifying                         |
//! | `keygen`   | Generate an ML-KEM-768 keypair for DBENC005 (PQE) encryption     |
//!
//! Exit codes: `0` = success/valid, `1` = check failed, `2` = error.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use isob3_tools::blake3iso_core::{CheckOutcome, check_iso, implant_iso, info_iso, remove_iso};
use isob3_tools::dbenc::{PQE_DK_LEN, PQE_EK_LEN, generate_pqe_keypair};
use isob3_tools::isomd5::{
    IsoMd5CheckOutcome, has_isomd5sum_implant, info_isomd5sum, verify_isomd5sum,
};

#[derive(Parser)]
#[command(name = "blake3iso", about = "ISOB3 ISO integrity tool and ML-KEM-768 key manager.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Write ISOB3 (BLAKE3) integrity metadata into an ISO file.
    ///
    /// The metadata is embedded in the ISO9660 application-use area of the
    /// Primary Volume Descriptor so it survives raw optical duplication.
    Implant {
        /// Path to the ISO file to implant.
        file: PathBuf,
        /// Overwrite existing ISOB3 metadata if already present.
        #[arg(long)]
        force: bool,
    },
    /// Verify the ISOB3 metadata embedded in an ISO file.
    ///
    /// Falls back to ISOMD5 verification if no ISOB3 metadata is found.
    /// Exit code 0 = valid, 1 = invalid, 2 = error.
    Check {
        /// Path to the ISO file to check.
        file: PathBuf,
    },
    /// Strip ISOB3 metadata from an ISO file, leaving it unmodified otherwise.
    Remove {
        /// Path to the ISO file to clear.
        file: PathBuf,
    },
    /// Print embedded ISOB3 or ISOMD5 metadata without re-verifying the content.
    Info {
        /// Path to the ISO file to inspect.
        file: PathBuf,
    },
    /// Generate an ML-KEM-768 keypair for DBENC005 (PQE) encryption.
    ///
    /// Writes `<output>.ek` (encapsulation / public key, 1184 bytes) and
    /// `<output>.dk` (decapsulation / private key seed, 64 bytes).
    /// Defaults to `~/.isob3/default` when `--output` is omitted.
    Keygen {
        /// File-system path prefix for the key files (no extension).
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

/// Return the default keypair prefix `~/.isob3/default`, or `None` if the
/// home directory cannot be read from environment variables.
fn default_key_prefix() -> Option<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var("USERPROFILE").ok()?;
    #[cfg(not(windows))]
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".isob3").join("default"))
}

/// Generate an ML-KEM-768 keypair and write `<prefix>.ek` and `<prefix>.dk`.
///
/// Returns a human-readable summary of what was written, or an error string.
fn run_keygen(output: Option<&PathBuf>) -> Result<String, String> {
    let prefix = match output {
        Some(p) => p.clone(),
        None => default_key_prefix()
            .ok_or_else(|| "cannot determine home directory; use --output".to_string())?,
    };
    if let Some(parent) = prefix.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create directory {} failed: {e}", parent.display()))?;
        }
    }
    let (ek, dk) = generate_pqe_keypair()?;
    let ek_path = prefix.with_extension("ek");
    let dk_path = prefix.with_extension("dk");
    std::fs::write(&ek_path, &ek[..PQE_EK_LEN])
        .map_err(|e| format!("write {} failed: {e}", ek_path.display()))?;
    std::fs::write(&dk_path, &dk[..PQE_DK_LEN])
        .map_err(|e| format!("write {} failed: {e}", dk_path.display()))?;
    Ok(format!(
        "Encapsulation key (public):  {}\nDecapsulation key (private): {}\nKeep the .dk file secret.\n\
         direnc and discdecrypt will auto-discover these keys if placed at ~/.isob3/default.{{ek,dk}}.",
        ek_path.display(),
        dk_path.display()
    ))
}

/// Run integrity verification on `file`, trying ISOB3 first and ISOMD5 as fallback.
///
/// Returns `(exit_code, message)` where exit code 0 = valid, 1 = invalid, 2 = error.
fn run_check(file: &PathBuf) -> (i32, String) {
    match check_iso(file) {
        Ok(CheckOutcome::Valid { detail, .. }) => (0, detail),
        Ok(CheckOutcome::Invalid { detail, .. }) => (1, detail),
        Ok(CheckOutcome::Missing) => match has_isomd5sum_implant(file) {
            Ok(true) => match verify_isomd5sum(file) {
                Ok(IsoMd5CheckOutcome::Valid { digest_hex }) => {
                    (0, format!("ISOMD5 valid ({digest_hex})"))
                }
                Ok(IsoMd5CheckOutcome::Invalid(detail)) => {
                    (1, format!("ISOMD5 invalid\n{detail}"))
                }
                Ok(IsoMd5CheckOutcome::ToolMissing) => {
                    (0, "ISOMD5 present (tool missing)".to_string())
                }
                Err(e) => (2, format!("ISOMD5 error: {e}")),
            },
            Ok(false) => (2, "No ISOB3 or ISOMD5 metadata".to_string()),
            Err(e) => (2, format!("ISOMD5 probe error: {e}")),
        },
        Err(e) => (2, e),
    }
}

/// Print embedded metadata from `file` without re-hashing the content.
///
/// Returns `(exit_code, message)` where exit code 0 = info found, 2 = error.
fn run_info(file: &PathBuf) -> (i32, String) {
    match info_iso(file) {
        Ok(msg) if msg != "No ISOB3 metadata found." => (0, msg),
        Ok(_) => match info_isomd5sum(file) {
            Ok(Some(msg)) => (0, msg),
            Ok(None) => (0, "No ISOB3 or ISOMD5 metadata found.".to_string()),
            Err(e) => (2, format!("ISOMD5 probe error: {e}")),
        },
        Err(e) => (2, e),
    }
}

fn main() {
    let cli = Cli::parse();

    let code = match cli.command {
        Commands::Implant { file, force } => match implant_iso(&file, force) {
            Ok(msg) => {
                println!("{msg}");
                0
            }
            Err(e) => {
                eprintln!("{e}");
                2
            }
        },
        Commands::Check { file } => {
            let (code, detail) = run_check(&file);
            if code == 2 {
                eprintln!("{detail}");
            } else {
                println!("{detail}");
            }
            code
        }
        Commands::Remove { file } => match remove_iso(&file) {
            Ok(msg) => {
                println!("{msg}");
                0
            }
            Err(e) => {
                eprintln!("{e}");
                2
            }
        },
        Commands::Info { file } => {
            let (code, detail) = run_info(&file);
            if code == 2 {
                eprintln!("{detail}");
            } else {
                println!("{detail}");
            }
            code
        }
        Commands::Keygen { output } => match run_keygen(output.as_ref()) {
            Ok(msg) => {
                println!("{msg}");
                0
            }
            Err(e) => {
                eprintln!("{e}");
                2
            }
        },
    };

    std::process::exit(code);
}
