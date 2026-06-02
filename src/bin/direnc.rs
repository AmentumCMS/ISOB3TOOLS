use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use walkdir::WalkDir;

use isob3_tools::dbenc::{DbEncFormat, encrypt_file_to_path, parse_format_name};
use isob3_tools::sha256sum::is_sha256_manifest;

#[derive(Parser)]
#[command(name = "direnc")]
#[command(
    about = "Encrypt payload files in a directory in place and inject the decryptor.\n\
             Run xorriso yourself before (to extract) and after (to rebuild the ISO)."
)]
struct Cli {
    directory: PathBuf,
    #[arg(long)]
    password: String,
    #[arg(long)]
    format: Option<String>,
    #[arg(long)]
    exclude: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    let format = match resolve_format(cli.format.as_deref()) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let exclude_dirs = parse_exclude_dirs(cli.exclude.as_deref());

    match run(&cli.directory, &cli.password, format, &exclude_dirs) {
        Ok(msg) => println!("{msg}"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    }
}

fn run(
    dir: &Path,
    password: &str,
    format: DbEncFormat,
    exclude_dirs: &[PathBuf],
) -> Result<String, String> {
    if !dir.is_dir() {
        return Err(format!("directory not found: {}", dir.display()));
    }

    let encrypted = encrypt_tree_in_place(dir, password, format, exclude_dirs)?;
    inject_decryptor(dir)?;

    Ok(format!(
        "Prepared {}\nEncrypted {} file(s) in place ({})\nExcluded: {}",
        dir.display(),
        encrypted,
        format.cli_name(),
        format_excludes(exclude_dirs)
    ))
}

fn resolve_format(name: Option<&str>) -> Result<DbEncFormat, String> {
    match name {
        Some(n) => {
            parse_format_name(n).ok_or_else(|| format!("unsupported encryption format: {n}"))
        }
        None => Ok(DbEncFormat::default_modern()),
    }
}

fn parse_exclude_dirs(raw: Option<&str>) -> Vec<PathBuf> {
    raw.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(normalize_exclude_path)
        .collect()
}

fn normalize_exclude_path(raw: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for component in Path::new(raw).components() {
        match component {
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            Component::ParentDir => out.push(".."),
            Component::Normal(v) => out.push(v),
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
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn encrypt_tree_in_place(
    root: &Path,
    password: &str,
    format: DbEncFormat,
    exclude_dirs: &[PathBuf],
) -> Result<usize, String> {
    let mut count = 0usize;

    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if entry.file_type().is_dir() {
            continue;
        }

        let relative = path.strip_prefix(root).unwrap_or(path);
        if should_skip(relative, path, exclude_dirs) {
            continue;
        }

        let temp = sibling_temp_path(path);
        match encrypt_file_to_path(path, &temp, password, format) {
            Ok(_) => {
                fs::rename(&temp, path)
                    .map_err(|e| format!("replace failed for {}: {e}", path.display()))?;
                count += 1;
            }
            Err(e) => {
                let _ = fs::remove_file(&temp);
                return Err(format!("encrypt failed for {}: {e}", path.display()));
            }
        }
    }

    Ok(count)
}

fn inject_decryptor(root: &Path) -> Result<(), String> {
    let current_exe = std::env::current_exe().map_err(|e| format!("current_exe failed: {e}"))?;
    let exe_dir = current_exe
        .parent()
        .ok_or_else(|| "failed to resolve direnc executable directory".to_string())?;

    let linux_dec = resolve_linux_decryptor(&current_exe, exe_dir)?;
    let windows_dec = resolve_windows_decryptor(exe_dir)?;

    let target_dir = root.join("decryptor");
    fs::create_dir_all(&target_dir).map_err(|e| {
        format!(
            "create decryptor directory failed for {}: {e}",
            target_dir.display()
        )
    })?;

    fs::copy(&linux_dec, target_dir.join("discdecrypt")).map_err(|e| {
        format!(
            "copy decryptor failed from {}: {e}",
            linux_dec.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            target_dir.join("discdecrypt"),
            fs::Permissions::from_mode(0o755),
        )
        .map_err(|e| format!("set discdecrypt permissions failed: {e}"))?;
    }

    fs::copy(&windows_dec, target_dir.join("discdecrypt.exe")).map_err(|e| {
        format!(
            "copy Windows decryptor failed from {}: {e}",
            windows_dec.display()
        )
    })?;

    fs::write(
        target_dir.join("README.txt"),
        "Linux: run ./discdecrypt --input .. --output <folder>\n\
         Windows: run discdecrypt.exe and choose this disc as the input folder.\n\
         If --password is omitted, the tool will prompt for it.\n\
         Encrypted files are detected by DBENC header, not by file extension.\n\
         Plaintext files and manifests are copied through unchanged.\n",
    )
    .map_err(|e| format!("write decryptor README failed: {e}"))?;

    fs::write(
        target_dir.join("decrypt.sh"),
        "#!/usr/bin/env sh\nset -eu\n\
         DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n\
         exec \"$DIR/discdecrypt\" --input \"$DIR/..\" \"$@\"\n",
    )
    .map_err(|e| format!("write decrypt.sh failed: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            target_dir.join("decrypt.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .map_err(|e| format!("set decrypt.sh permissions failed: {e}"))?;
    }

    Ok(())
}

fn resolve_linux_decryptor(current_exe: &Path, exe_dir: &Path) -> Result<PathBuf, String> {
    let mut candidates = vec![exe_dir.join("discdecrypt")];
    if let Some(name) = current_exe.file_name().and_then(|n| n.to_str()) {
        candidates.push(exe_dir.join(name.replacen("direnc", "discdecrypt", 1)));
    }

    if let Some(path) = candidates.into_iter().find(|p| p.is_file()) {
        return Ok(path);
    }

    find_in_dir(exe_dir, |name| {
        name.starts_with("discdecrypt") && !name.ends_with(".exe")
    })
    .ok_or_else(|| {
        format!(
            "discdecrypt binary not found next to direnc in {}",
            exe_dir.display()
        )
    })
}

fn resolve_windows_decryptor(exe_dir: &Path) -> Result<PathBuf, String> {
    let direct = exe_dir.join("discdecrypt.exe");
    if direct.is_file() {
        return Ok(direct);
    }

    find_in_dir(exe_dir, |name| {
        name.starts_with("discdecrypt") && name.ends_with(".exe") && name.contains("windows")
    })
    .ok_or_else(|| {
        format!(
            "Windows discdecrypt.exe not found next to direnc in {}",
            exe_dir.display()
        )
    })
}

fn find_in_dir(dir: &Path, pred: impl Fn(&str) -> bool) -> Option<PathBuf> {
    fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(&pred)
                .unwrap_or(false)
                && p.is_file()
        })
}

fn should_skip(relative: &Path, full_path: &Path, exclude_dirs: &[PathBuf]) -> bool {
    if is_sha256_manifest(full_path) {
        return true;
    }

    if relative
        .components()
        .next()
        .and_then(|c| c.as_os_str().to_str())
        == Some("decryptor")
    {
        return true;
    }

    exclude_dirs
        .iter()
        .any(|ex| !ex.as_os_str().is_empty() && relative.starts_with(ex))
}

fn sibling_temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("tmpfile");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.with_file_name(format!("{name}.direnc-tmp-{stamp}"))
}
