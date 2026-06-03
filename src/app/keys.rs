//! Key-file path helpers, keypair generation, and the OS file-picker.
//!
//! Keypair generation writes two files:
//!   - `{prefix}.ek`  — encapsulation key (public, 1184 bytes); share with disc producers
//!   - `{prefix}.dk`  — decapsulation key (private, 64-byte seed); keep secret

use std::path::PathBuf;

use crate::dbenc::{PQE_DK_LEN, PQE_EK_LEN, generate_pqe_keypair};

// ── Default path helpers ───────────────────────────────────────────────────────

/// Platform-appropriate `~/.isob3` directory.
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

/// Resolve a private-key path from user input.
///
/// If `input` is non-empty, use it verbatim.
/// Otherwise fall back to [`default_dk_path`].
/// Returns `None` only if neither produces a path.
pub fn resolve_private_key_path(input: &str) -> Option<PathBuf> {
    if !input.trim().is_empty() {
        return Some(PathBuf::from(input.trim()));
    }
    default_dk_path()
}

// ── Keypair generation ─────────────────────────────────────────────────────────

/// Generate an ML-KEM-768 keypair and write the two key files.
///
/// `prefix` is a file-system path without an extension.  The `.ek` and `.dk`
/// files are written alongside each other.  Parent directories are created
/// automatically.
///
/// Returns a human-readable success message or an error description.
pub fn run_keygen(prefix: &str) -> Result<String, String> {
    let prefix = prefix.trim();
    if prefix.is_empty() {
        return Err("Output prefix must not be empty.".to_string());
    }

    let ek_path = PathBuf::from(format!("{prefix}.ek"));
    let dk_path = PathBuf::from(format!("{prefix}.dk"));

    // Ensure the parent directory exists.
    if let Some(parent) = ek_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create directory failed: {e}"))?;
        }
    }

    let (ek_bytes, dk_bytes) = generate_pqe_keypair()?;

    std::fs::write(&ek_path, &ek_bytes)
        .map_err(|e| format!("write {}: {e}", ek_path.display()))?;
    std::fs::write(&dk_path, &dk_bytes)
        .map_err(|e| format!("write {}: {e}", dk_path.display()))?;

    Ok(format!(
        "✔ Keypair written.\n  Public  (.ek): {}  [{} bytes]\n  Private (.dk): {}  [{} bytes]",
        ek_path.display(),
        PQE_EK_LEN,
        dk_path.display(),
        PQE_DK_LEN,
    ))
}

// ── Native file picker ─────────────────────────────────────────────────────────

/// Open a native file-picker dialog for `.dk` files and return the chosen path.
///
/// On Windows this invokes PowerShell's `OpenFileDialog` (via `-STA`).
/// On other platforms the feature is not yet implemented and returns `None`.
pub fn browse_dk_file() -> Option<String> {
    #[cfg(windows)]
    {
        browse_dk_file_windows()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(windows)]
fn browse_dk_file_windows() -> Option<String> {
    // PowerShell must run in STA mode to host the Windows Forms dialog.
    let script = r#"
Add-Type -AssemblyName System.Windows.Forms
$d = New-Object System.Windows.Forms.OpenFileDialog
$d.Title  = 'Select decapsulation key (.dk)'
$d.Filter = 'Decapsulation Key (*.dk)|*.dk|All Files (*.*)|*.*'
$d.Multiselect = $false
if ($d.ShowDialog() -eq 'OK') { Write-Output $d.FileName }
"#;

    let output = std::process::Command::new("powershell")
        .args(["-NonInteractive", "-STA", "-Command", script])
        .output()
        .ok()?;

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() { None } else { Some(path) }
}
