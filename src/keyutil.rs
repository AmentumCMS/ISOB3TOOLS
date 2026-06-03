//! Shared key-file path helpers and ML-KEM-768 keypair generation.
//!
//! Used by the GUI (`app/keys.rs`) and both CLI binaries (`blake3iso`, `direnc`).

use std::path::{Path, PathBuf};

use crate::dbenc::{PQE_DK_LEN, PQE_EK_LEN, generate_pqe_keypair};

// ── Default path helpers ───────────────────────────────────────────────────────

/// Platform-appropriate `~/.isob3` key directory.
pub fn default_key_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var("USERPROFILE").ok()?;
    #[cfg(not(windows))]
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".isob3"))
}

/// Default keypair file prefix: `~/.isob3/default`
pub fn default_key_prefix() -> Option<PathBuf> {
    Some(default_key_dir()?.join("default"))
}

/// Default private-key path: `~/.isob3/default.dk`
pub fn default_dk_path() -> Option<PathBuf> {
    Some(default_key_prefix()?.with_extension("dk"))
}

/// Resolve a private-key path from a text-field string.
///
/// Non-empty input is used verbatim; empty input falls back to [`default_dk_path`].
pub fn resolve_private_key_path(input: &str) -> Option<PathBuf> {
    if !input.trim().is_empty() {
        return Some(PathBuf::from(input.trim()));
    }
    default_dk_path()
}

// ── Keypair generation ─────────────────────────────────────────────────────────

/// Generate an ML-KEM-768 keypair and write `<prefix>.ek` and `<prefix>.dk`.
///
/// Parent directories are created automatically.
/// Returns a human-readable success message or an error description.
pub fn run_keygen(prefix: &Path) -> Result<String, String> {
    if let Some(parent) = prefix.parent()
        && !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create directory failed: {e}"))?;
        }

    let (ek_bytes, dk_bytes) = generate_pqe_keypair()?;

    let ek_path = prefix.with_extension("ek");
    let dk_path = prefix.with_extension("dk");

    std::fs::write(&ek_path, ek_bytes)
        .map_err(|e| format!("write {}: {e}", ek_path.display()))?;
    std::fs::write(&dk_path, dk_bytes)
        .map_err(|e| format!("write {}: {e}", dk_path.display()))?;

    Ok(format!(
        "✔ Keypair written.\n  Public  (.ek): {}  [{} bytes]\n  Private (.dk): {}  [{} bytes]",
        ek_path.display(),
        PQE_EK_LEN,
        dk_path.display(),
        PQE_DK_LEN,
    ))
}
