use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use isob3_tools::blake3iso_core::{CheckOutcome, check_iso, implant_iso, info_iso, remove_iso};
use isob3_tools::dbenc::{
    DbEncFormat, decrypt_file_to_path, encrypt_file_to_path, is_encrypted_file, parse_format_name,
};
use isob3_tools::encfile::{
    info_ciphertext_sidecar, verify_ciphertext_sidecar, write_ciphertext_sidecar,
};
use isob3_tools::isomd5::{
    IsoMd5CheckOutcome, has_isomd5sum_implant, info_isomd5sum, verify_isomd5sum,
};

#[derive(Parser)]
/// CLI wrapper around ISOB3 ISO operations and DBENC file encryption.
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
        #[arg(long)]
        encrypted: bool,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        format: Option<String>,
    },
    Encrypt {
        file: PathBuf,
        #[arg(long)]
        password: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        format: Option<String>,
    },
    Decrypt {
        file: PathBuf,
        #[arg(long)]
        password: String,
        #[arg(long)]
        output: PathBuf,
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
    match is_encrypted_file(file) {
        Ok(true) => match verify_ciphertext_sidecar(file) {
            Ok(msg) => (0, msg),
            Err(err) => (1, err),
        },
        Ok(false) => match check_iso(file) {
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
                Ok(false) => (
                    2,
                    "No ISOB3, encrypted sidecar, or ISOMD5 metadata".to_string(),
                ),
                Err(e) => (2, format!("ISOMD5 probe error: {e}")),
            },
            Err(e) => (2, e),
        },
        Err(err) => (2, format!("Encryption probe failed: {err}")),
    }
}

fn run_info(file: &PathBuf) -> (i32, String) {
    match is_encrypted_file(file) {
        Ok(true) => match info_ciphertext_sidecar(file) {
            Ok(msg) => (0, msg),
            Err(err) => (2, err),
        },
        Ok(false) => match info_iso(file) {
            Ok(msg) if msg != "No ISOB3 metadata found." => (0, msg),
            Ok(_) => match info_isomd5sum(file) {
                Ok(Some(msg)) => (0, msg),
                Ok(None) => (
                    0,
                    "No ISOB3, encrypted sidecar, or ISOMD5 metadata found.".to_string(),
                ),
                Err(e) => (2, format!("ISOMD5 probe error: {e}")),
            },
            Err(e) => (2, e),
        },
        Err(err) => (2, format!("Encryption probe failed: {err}")),
    }
}

fn resolve_encryption_format(format: Option<&str>) -> Result<DbEncFormat, String> {
    match format {
        Some(name) => {
            parse_format_name(name).ok_or_else(|| format!("unsupported encryption format: {name}"))
        }
        None => Ok(DbEncFormat::default_modern()),
    }
}

fn run_encrypt(
    file: &Path,
    output: Option<PathBuf>,
    password: &str,
    format: Option<&str>,
) -> Result<String, String> {
    let format = resolve_encryption_format(format)?;
    let output = output.unwrap_or_else(|| default_encrypted_output(file));
    let ciphertext_bytes = encrypt_file_to_path(file, &output, password, format)?;
    let sidecar = write_ciphertext_sidecar(&output, ciphertext_bytes)?;

    Ok(format!(
        "Encrypted {} -> {} ({})\nCiphertext integrity sidecar: {}",
        file.display(),
        output.display(),
        format.cli_name(),
        sidecar.display()
    ))
}

fn default_encrypted_output(file: &Path) -> PathBuf {
    let file_name = file
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("encrypted");
    file.with_file_name(format!("{file_name}.dbenc"))
}

fn main() {
    let cli = Cli::parse();

    let code = match cli.command {
        Commands::Implant {
            file,
            force,
            encrypted,
            password,
            output,
            format,
        } => {
            if encrypted {
                match password {
                    Some(password) => {
                        match run_encrypt(&file, output, &password, format.as_deref()) {
                            Ok(msg) => {
                                println!("{msg}");
                                0
                            }
                            Err(err) => {
                                eprintln!("{err}");
                                2
                            }
                        }
                    }
                    None => {
                        eprintln!("--password is required with --encrypted");
                        2
                    }
                }
            } else {
                if output.is_some() {
                    eprintln!("--output is only supported with --encrypted");
                    2
                } else if format.is_some() {
                    eprintln!("--format is only supported with --encrypted");
                    2
                } else if password.is_some() {
                    eprintln!("--password is only supported with --encrypted");
                    2
                } else {
                    match implant_iso(&file, force) {
                        Ok(msg) => {
                            println!("{msg}");
                            0
                        }
                        Err(e) => {
                            eprintln!("{e}");
                            2
                        }
                    }
                }
            }
        }
        Commands::Encrypt {
            file,
            password,
            output,
            format,
        } => match run_encrypt(&file, output, &password, format.as_deref()) {
            Ok(msg) => {
                println!("{msg}");
                0
            }
            Err(err) => {
                eprintln!("{err}");
                2
            }
        },
        Commands::Decrypt {
            file,
            password,
            output,
        } => match decrypt_file_to_path(&file, &output, &password) {
            Ok(bytes) => {
                println!(
                    "Decrypted {} -> {} ({bytes} bytes)",
                    file.display(),
                    output.display()
                );
                0
            }
            Err(err) => {
                eprintln!("{err}");
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
