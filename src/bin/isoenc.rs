#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use walkdir::WalkDir;

use isob3_tools::blake3iso_core::implant_iso;
use isob3_tools::dbenc::{DbEncFormat, encrypt_file_to_path, parse_format_name};
use isob3_tools::sha256sum::is_sha256_manifest;

#[derive(Parser)]
#[command(name = "isoenc")]
#[command(about = "Extract an ISO, encrypt its payload files in place, and rebuild a new ISO.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Bundle {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        password: String,
        #[arg(long)]
        format: Option<String>,
        #[arg(long)]
        exclude: Option<String>,
        #[arg(long)]
        implant_isob3: bool,
        #[arg(long)]
        xorriso: Option<PathBuf>,
    },
}

#[derive(Clone, Debug)]
struct BundleOptions {
    input: PathBuf,
    output: PathBuf,
    password: String,
    format: DbEncFormat,
    exclude_dirs: Vec<PathBuf>,
    implant_isob3: bool,
    xorriso: Option<PathBuf>,
}

#[derive(Clone, Debug)]
enum Backend {
    LinuxXorriso { xorriso: PathBuf },
}

fn main() {
    #[cfg(not(target_os = "linux"))]
    {
        unsupported_main();
        return;
    }

    #[cfg(target_os = "linux")]
    {
        linux_main();
    }
}

#[cfg(not(target_os = "linux"))]
fn unsupported_main() {
    eprintln!("isoenc is currently supported on Linux only.");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn linux_main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Bundle {
            input,
            output,
            password,
            format,
            exclude,
            implant_isob3,
            xorriso,
        } => {
            let resolved_format = match resolve_encryption_format(format.as_deref()) {
                Ok(value) => value,
                Err(err) => {
                    eprintln!("{err}");
                    std::process::exit(2);
                }
            };

            let options = BundleOptions {
                input,
                output,
                password,
                format: resolved_format,
                exclude_dirs: parse_exclude_dirs(exclude.as_deref()),
                implant_isob3,
                xorriso,
            };

            match run_bundle(&options) {
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
    };

    std::process::exit(code);
}

fn run_bundle(options: &BundleOptions) -> Result<String, String> {
    if !options.input.is_file() {
        return Err(format!("input ISO not found: {}", options.input.display()));
    }

    let backend = resolve_backend(options)?;
    let temp_root = make_temp_dir("isoenc-bundle")?;
    let extract_dir = temp_root.join("extract");
    fs::create_dir_all(&extract_dir).map_err(|e| format!("create temp directory failed: {e}"))?;

    let result = (|| {
        extract_iso(&backend, &options.input, &extract_dir)?;
        let encrypted_files = encrypt_tree_in_place(
            &extract_dir,
            &options.password,
            options.format,
            &options.exclude_dirs,
        )?;
        rebuild_iso(&backend, &extract_dir, &options.output)?;
        if options.implant_isob3 {
            implant_iso(&options.output, true)?;
        }

        Ok(format!(
            "Bundled {} -> {} ({})\nEncrypted {} file(s) in place{}\nExcluded: {}",
            options.input.display(),
            options.output.display(),
            options.format_name(),
            encrypted_files,
            if options.implant_isob3 {
                "\nImplanted ISOB3 into rebuilt ISO"
            } else {
                ""
            },
            format_excludes(&options.exclude_dirs)
        ))
    })();

    let _ = fs::remove_dir_all(&temp_root);
    result
}

impl BundleOptions {
    fn format_name(&self) -> &'static str {
        self.format.cli_name()
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

fn parse_exclude_dirs(raw: Option<&str>) -> Vec<PathBuf> {
    raw.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_exclude_path)
        .collect()
}

fn normalize_exclude_path(raw: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for component in Path::new(raw).components() {
        match component {
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            Component::ParentDir => out.push(".."),
            Component::Normal(value) => out.push(value),
        }
    }
    out
}

fn format_excludes(excludes: &[PathBuf]) -> String {
    if excludes.is_empty() {
        "none".to_string()
    } else {
        excludes
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn resolve_backend(options: &BundleOptions) -> Result<Backend, String> {
    #[cfg(target_os = "linux")]
    {
        let xorriso = resolve_tool(options.xorriso.as_deref(), "xorriso")?;
        return Ok(Backend::LinuxXorriso { xorriso });
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err("isoenc is currently supported on Linux only".to_string())
    }
}

fn resolve_tool(explicit: Option<&Path>, fallback: &str) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        return Err(format!("tool not found: {}", path.display()));
    }

    if let Some(path) = find_on_path(fallback) {
        return Ok(path);
    }

    Err(format!(
        "required tool not found on PATH: {fallback}. Pass an explicit path with the matching CLI flag."
    ))
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let mut candidates = std::env::split_paths(&path_var).flat_map(|dir| {
        candidate_names(name)
            .into_iter()
            .map(move |candidate| dir.join(candidate))
    });
    candidates.find(|path| path.is_file())
}

fn candidate_names(name: &str) -> Vec<OsString> {
    #[cfg(windows)]
    {
        let path = Path::new(name);
        if path.extension().is_some() {
            vec![OsString::from(name)]
        } else {
            vec![
                OsString::from(name),
                OsString::from(format!("{name}.exe")),
                OsString::from(format!("{name}.cmd")),
                OsString::from(format!("{name}.bat")),
            ]
        }
    }

    #[cfg(not(windows))]
    {
        vec![OsString::from(name)]
    }
}

fn extract_iso(backend: &Backend, input: &Path, output_dir: &Path) -> Result<(), String> {
    match backend {
        Backend::LinuxXorriso { xorriso } => run_command(
            Command::new(xorriso).args([
                "-osirrox",
                "on",
                "-indev",
                &input.display().to_string(),
                "-extract",
                "/",
                &output_dir.display().to_string(),
            ]),
            "xorriso extract",
        ),
    }
}

fn rebuild_iso(backend: &Backend, source_dir: &Path, output: &Path) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create output directory failed: {e}"))?;
        }
    }

    match backend {
        Backend::LinuxXorriso { xorriso } => run_command(
            Command::new(xorriso).args([
                "-as",
                "mkisofs",
                "-r",
                "-J",
                "-o",
                &output.display().to_string(),
                &source_dir.display().to_string(),
            ]),
            "xorriso build",
        ),
    }
}

fn encrypt_tree_in_place(
    root: &Path,
    password: &str,
    format: DbEncFormat,
    exclude_dirs: &[PathBuf],
) -> Result<usize, String> {
    let mut encrypted_files = 0usize;

    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if entry.file_type().is_dir() {
            continue;
        }

        let relative = path.strip_prefix(root).unwrap_or(path);
        if should_skip(relative, path, exclude_dirs) {
            continue;
        }

        let temp_output = sibling_temp_path(path);
        let result = encrypt_file_to_path(path, &temp_output, password, format);
        match result {
            Ok(_) => {
                fs::rename(&temp_output, path)
                    .map_err(|e| format!("replace failed for {}: {e}", path.display()))?;
                encrypted_files += 1;
            }
            Err(err) => {
                let _ = fs::remove_file(&temp_output);
                return Err(format!("encrypt failed for {}: {err}", path.display()));
            }
        }
    }

    Ok(encrypted_files)
}

fn should_skip(relative: &Path, full_path: &Path, exclude_dirs: &[PathBuf]) -> bool {
    if is_sha256_manifest(full_path) {
        return true;
    }

    exclude_dirs
        .iter()
        .any(|excluded| !excluded.as_os_str().is_empty() && relative.starts_with(excluded))
}

fn sibling_temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("tmpfile");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    path.with_file_name(format!("{file_name}.isoenc-tmp-{stamp}"))
}

fn make_temp_dir(prefix: &str) -> Result<PathBuf, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .map_err(|e| format!("time error: {e}"))?;
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{stamp}", std::process::id()));
    fs::create_dir_all(&dir).map_err(|e| format!("create temp directory failed: {e}"))?;
    Ok(dir)
}

fn run_command(command: &mut Command, label: &str) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|e| format!("{label} failed to start: {e}"))?;
    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let detail = if stdout.is_empty() {
        stderr
    } else if stderr.is_empty() {
        stdout
    } else {
        format!("{stdout}\n{stderr}")
    };

    Err(if detail.is_empty() {
        format!("{label} failed with status {}", output.status)
    } else {
        format!("{label} failed with status {}\n{detail}", output.status)
    })
}
