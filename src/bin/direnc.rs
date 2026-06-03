//! `direnc` — in-place directory encryptor for disc mastering.
//!
//! This tool walks a directory tree that has been extracted from an ISO (e.g.
//! via `xorriso -osirrox`) and encrypts every payload file in-place using one
//! of the DBENC formats.  It then injects the `discdecrypt` binary and helper
//! scripts into a `decryptor/` subdirectory so that end-users can decrypt the
//! disc after optical read-back without installing additional software.
//!
//! ## Typical workflow
//!
//! ```text
//! 1. xorriso -osirrox on:in image.iso -extract / iso-root/
//! 2. direnc iso-root/ [--public-key key.ek | --password secret] [--format argon2id]
//! 3. xorriso ... -outdev encrypted.iso
//! ```
//!
//! ## Credential priority
//!
//! 1. `--public-key <path>` — ML-KEM-768 encapsulation key (DBENC005 / PQE)
//! 2. `--password <secret>` — symmetric password (DBENC001–004)
//! 3. `~/.isob3/default.ek` — auto-discovered public key (no flag needed)
//! 4. Prompted interactively if none of the above are present

use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use walkdir::WalkDir;

use isob3_tools::dbenc::{
    DbEncFormat, PQE_EK_LEN, encrypt_file_pqe, encrypt_file_to_path, parse_format_name,
};
use isob3_tools::sha256sum::is_sha256_manifest;

#[derive(Parser)]
#[command(name = "direnc")]
#[command(
    about = "Encrypt payload files in a directory in place and inject the decryptor.\n\
             Run xorriso yourself before (to extract) and after (to rebuild the ISO)."
)]
struct Cli {
    /// Directory tree to encrypt in-place (e.g. the xorriso extraction root).
    directory: PathBuf,
    /// Password for DBENC001–004 (symmetric). Mutually exclusive with --public-key.
    /// If neither --password nor --public-key is given, looks for ~/.isob3/default.ek first.
    #[arg(long, conflicts_with = "public_key")]
    password: Option<String>,
    /// Path to ML-KEM-768 encapsulation key (.ek) for DBENC005 (PQE).
    /// Mutually exclusive with --password.
    #[arg(long, conflicts_with = "password")]
    public_key: Option<PathBuf>,
    /// DBENC format name (e.g. `argon2id`, `xchacha20`, `pqe-xchacha20`).
    /// Defaults to `argon2id` for passwords or `pqe-xchacha20` for public keys.
    #[arg(long)]
    format: Option<String>,
    /// Comma-separated list of subdirectory names to skip (e.g. `extras,efi`).
    #[arg(long)]
    exclude: Option<String>,
}

/// Resolved encryption credential — either a password string or a raw ML-KEM-768
/// encapsulation key loaded from a `.ek` file.
enum EncKey {
    Password(String),
    PublicKey([u8; PQE_EK_LEN]),
}

fn main() {
    let cli = Cli::parse();

    let enc_key = match resolve_enc_key(cli.password, cli.public_key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let format = match resolve_format(cli.format.as_deref(), &enc_key) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let exclude_dirs = parse_exclude_dirs(cli.exclude.as_deref());

    match run(&cli.directory, &enc_key, format, &exclude_dirs) {
        Ok(msg) => println!("{msg}"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    }
}

/// Return the platform-appropriate `~/.isob3` key directory, or `None` if the
/// home directory cannot be determined from environment variables.
fn default_key_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var("USERPROFILE").ok()?;
    #[cfg(not(windows))]
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".isob3"))
}

/// Resolve which encryption credential to use, following the priority order:
/// explicit `--public-key`, explicit `--password`, auto-discovered `.ek`,
/// then interactive password prompt.
fn resolve_enc_key(password: Option<String>, public_key: Option<PathBuf>) -> Result<EncKey, String> {
    if let Some(pk_path) = public_key {
        return Ok(EncKey::PublicKey(load_public_key(&pk_path)?));
    }
    if let Some(pw) = password {
        return Ok(EncKey::Password(pw));
    }
    if let Some(default_ek) = default_key_dir().map(|d| d.join("default.ek")) {
        if default_ek.is_file() {
            eprintln!("Using default encapsulation key: {}", default_ek.display());
            return Ok(EncKey::PublicKey(load_public_key(&default_ek)?));
        }
    }
    // Fall back to password prompt
    match prompt("Password") {
        Ok(pw) if !pw.is_empty() => Ok(EncKey::Password(pw)),
        Ok(_) => Err("password is required (or provide --public-key, or place a key at ~/.isob3/default.ek)".to_string()),
        Err(e) => Err(format!("failed to read password: {e}")),
    }
}

/// Print `label: ` to stdout and read one line from stdin, returning it trimmed.
fn prompt(label: &str) -> io::Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_string())
}

/// Read a ML-KEM-768 encapsulation key from `path`, returning the raw 1184-byte array.
fn load_public_key(path: &PathBuf) -> Result<[u8; PQE_EK_LEN], String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {} failed: {e}", path.display()))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{} is not a valid ML-KEM-768 encapsulation key (expected {PQE_EK_LEN} bytes)", path.display()))
}

/// Encrypt every payload file in `dir` in-place and inject the decryptor bundle.
///
/// Returns a human-readable summary on success, or an error description on failure.
fn run(
    dir: &Path,
    enc_key: &EncKey,
    format: DbEncFormat,
    exclude_dirs: &[PathBuf],
) -> Result<String, String> {
    if !dir.is_dir() {
        return Err(format!("directory not found: {}", dir.display()));
    }

    let encrypted = encrypt_tree_in_place(dir, enc_key, format, exclude_dirs)?;
    inject_decryptor(dir)?;

    Ok(format!(
        "Prepared {}\nEncrypted {} file(s) in place ({})\nExcluded: {}",
        dir.display(),
        encrypted,
        format.cli_name(),
        format_excludes(exclude_dirs)
    ))
}

/// Parse an optional format name, defaulting to DBENC005 for public-key credentials
/// and DBENC004 (Argon2id) for passwords.
fn resolve_format(name: Option<&str>, key: &EncKey) -> Result<DbEncFormat, String> {
    match name {
        Some(n) => {
            parse_format_name(n).ok_or_else(|| format!("unsupported encryption format: {n}"))
        }
        None => match key {
            EncKey::PublicKey(_) => Ok(DbEncFormat::DbEnc005),
            EncKey::Password(_) => Ok(DbEncFormat::default_modern()),
        },
    }
}

/// Split the `--exclude` comma-separated list into normalized relative paths.
fn parse_exclude_dirs(raw: Option<&str>) -> Vec<PathBuf> {
    raw.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(normalize_exclude_path)
        .collect()
}

/// Strip leading root components (`.`, `/`, drive letters) from an exclude path
/// so it can be compared against `path.strip_prefix(root)` relative paths.
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

/// Format the exclude list as a human-readable comma-separated string, or `"none"`.
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

/// Walk `root` and encrypt every non-excluded, non-manifest file in-place.
///
/// Each file is encrypted to a sibling temp path first; on success it replaces
/// the original.  This avoids leaving a partially-encrypted file if the process
/// is interrupted.  Returns the number of files encrypted.
fn encrypt_tree_in_place(
    root: &Path,
    enc_key: &EncKey,
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
        let result = match enc_key {
            EncKey::Password(pw) => encrypt_file_to_path(path, &temp, pw, format),
            EncKey::PublicKey(ek) => encrypt_file_pqe(path, &temp, ek),
        };
        match result {
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

/// Copy the `discdecrypt` (Linux) and `discdecrypt.exe` (Windows) binaries into
/// `root/decryptor/`, along with a `README.txt` and a `decrypt.sh` convenience
/// wrapper, so end-users can decrypt without installing additional tools.
///
/// The decryptor binaries are located relative to the currently-running `direnc`
/// executable, which is how the CI build places them.
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

/// Find the Linux `discdecrypt` binary relative to the running executable.
///
/// Checks a fixed `discdecrypt` sibling first, then falls back to scanning the
/// directory for any non-`.exe` file whose name starts with `discdecrypt`.
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

/// Find the Windows `discdecrypt.exe` binary relative to the running executable.
///
/// Checks a fixed `discdecrypt.exe` sibling first, then scans for any `.exe`
/// whose name starts with `discdecrypt` and contains `windows` (cross-compiled
/// artifact naming convention).
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

/// Return the first regular file in `dir` whose name satisfies `pred`, or `None`.
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

/// Return `true` if a file should be skipped during encryption.
///
/// Skipped files:
/// - SHA-256 manifests (so checksums stay verifiable after decryption)
/// - Anything under `decryptor/` (the injected tools themselves)
/// - Any path whose first component matches an entry in `exclude_dirs`
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

/// Build a unique temporary file path in the same directory as `path`.
///
/// Using a sibling temp ensures the rename-to-replace is atomic on most
/// file systems (same volume as the target).
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
