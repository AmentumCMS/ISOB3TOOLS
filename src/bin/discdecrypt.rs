use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use walkdir::WalkDir;

use isob3_tools::dbenc::{decrypt_file_to_path, is_encrypted_file};

#[derive(Parser)]
#[command(name = "discdecrypt")]
#[command(about = "Decrypt DBENC files from an extracted or mounted disc into an output folder.")]
struct Cli {
    #[arg(long, default_value = ".")]
    input: PathBuf,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    password: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    let output = match cli.output {
        Some(path) => path,
        None => match prompt("Output directory") {
            Ok(value) if !value.is_empty() => PathBuf::from(value),
            Ok(_) => {
                eprintln!("output directory is required");
                std::process::exit(2);
            }
            Err(err) => {
                eprintln!("failed to read output directory: {err}");
                std::process::exit(2);
            }
        },
    };
    let password = match cli.password {
        Some(value) => value,
        None => match prompt("Password") {
            Ok(value) if !value.is_empty() => value,
            Ok(_) => {
                eprintln!("password is required");
                std::process::exit(2);
            }
            Err(err) => {
                eprintln!("failed to read password: {err}");
                std::process::exit(2);
            }
        },
    };

    match run(&cli.input, &output, &password) {
        Ok(summary) => println!("{summary}"),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    }
}

fn run(input_root: &Path, output_root: &Path, password: &str) -> Result<String, String> {
    if !input_root.is_dir() {
        return Err(format!(
            "input directory not found: {}",
            input_root.display()
        ));
    }

    let input_root = input_root
        .canonicalize()
        .map_err(|e| format!("failed to resolve input directory: {e}"))?;

    if output_root.exists() && !output_root.is_dir() {
        return Err(format!(
            "output path is not a directory: {}",
            output_root.display()
        ));
    }

    ensure_output_outside_input(&input_root, output_root)?;
    fs::create_dir_all(output_root).map_err(|e| {
        format!(
            "failed to create output directory {}: {e}",
            output_root.display()
        )
    })?;

    let mut decrypted = 0usize;
    let mut copied = 0usize;

    for entry in WalkDir::new(&input_root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        let relative = path.strip_prefix(&input_root).unwrap_or(path);
        if should_skip(relative) {
            continue;
        }
        let destination = output_root.join(relative);

        if entry.file_type().is_dir() {
            fs::create_dir_all(&destination).map_err(|e| {
                format!(
                    "failed to create output directory {}: {e}",
                    destination.display()
                )
            })?;
            continue;
        }

        if is_encrypted_file(path)? {
            decrypt_file_to_path(path, &destination, password)
                .map_err(|e| format!("decrypt failed for {}: {e}", path.display()))?;
            decrypted += 1;
        } else {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "failed to create output directory {}: {e}",
                        parent.display()
                    )
                })?;
            }
            fs::copy(path, &destination).map_err(|e| {
                format!(
                    "copy failed from {} to {}: {e}",
                    path.display(),
                    destination.display()
                )
            })?;
            copied += 1;
        }
    }

    Ok(format!(
        "Wrote decrypted disc contents to {}\nDecrypted {} file(s); copied {} plaintext file(s)",
        output_root.display(),
        decrypted,
        copied
    ))
}

fn prompt(label: &str) -> io::Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_string())
}

fn ensure_output_outside_input(input_root: &Path, output_root: &Path) -> Result<(), String> {
    let candidate = if output_root.exists() {
        output_root
            .canonicalize()
            .map_err(|e| format!("failed to resolve output directory: {e}"))?
    } else if output_root.is_absolute() {
        output_root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("failed to resolve current directory: {e}"))?
            .join(output_root)
    };

    if candidate.starts_with(input_root) {
        return Err(format!(
            "output directory must be outside the input tree: {}",
            candidate.display()
        ));
    }

    Ok(())
}

fn should_skip(relative: &Path) -> bool {
    relative
        .components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
        == Some("decryptor")
}
