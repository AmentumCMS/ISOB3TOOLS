use std::path::PathBuf;

use clap::{Parser, Subcommand};

use isob3_tools::blake3iso_core::{
    check_iso, implant_iso, info_iso, remove_iso, CheckOutcome,
};

#[derive(Parser)]
/// Minimal CLI wrapper around the ISOB3 core operations.
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Implant { file: PathBuf, #[arg(long)] force: bool },
    Check { file: PathBuf },
    Remove { file: PathBuf },
    Info { file: PathBuf },
}

fn main() {
    let cli = Cli::parse();

    // Exit codes mirror the verification result so the tool is script-friendly.
    let code = match cli.command {
        Commands::Implant { file, force } => match implant_iso(&file, force) {
            Ok(msg) => { println!("{msg}"); 0 }
            Err(e) => { eprintln!("{e}"); 2 }
        },
        Commands::Check { file } => match check_iso(&file) {
            Ok(CheckOutcome::Valid { detail, .. }) => { println!("{detail}"); 0 }
            Ok(CheckOutcome::Invalid { detail, .. }) => { println!("{detail}"); 1 }
            Ok(CheckOutcome::Missing) => { println!("No metadata"); 2 }
            Err(e) => { eprintln!("{e}"); 2 }
        },
        Commands::Remove { file } => match remove_iso(&file) {
            Ok(msg) => { println!("{msg}"); 0 }
            Err(e) => { eprintln!("{e}"); 2 }
        },
        Commands::Info { file } => match info_iso(&file) {
            Ok(msg) => { println!("{msg}"); 0 }
            Err(e) => { eprintln!("{e}"); 2 }
        },
    };

    std::process::exit(code);
}
