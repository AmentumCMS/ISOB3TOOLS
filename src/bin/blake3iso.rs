use std::path::PathBuf;

use clap::{Parser, Subcommand};

use isob3_tools::blake3iso_core::{CheckOutcome, check_iso, implant_iso, info_iso, remove_iso};
use isob3_tools::isomd5::{
    IsoMd5CheckOutcome, has_isomd5sum_implant, info_isomd5sum, verify_isomd5sum,
};

#[derive(Parser)]
/// CLI for ISOB3 ISO integrity operations.
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Implant {
        file: PathBuf,
        #[arg(long)]
        force: bool,
    },
    Check {
        file: PathBuf,
    },
    Remove {
        file: PathBuf,
    },
    Info {
        file: PathBuf,
    },
}

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
    };

    std::process::exit(code);
}
