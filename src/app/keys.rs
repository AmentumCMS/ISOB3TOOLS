//! Key-file path helpers, keypair generation, and the OS file-picker.
//!
//! Path helpers and keypair generation are thin wrappers around [`crate::keyutil`].
//! This module adds the GUI-specific `browse_dk_file` helper.

use std::path::PathBuf;

pub use crate::keyutil::{default_dk_path, default_key_dir, default_key_prefix};

// ── Re-exported helpers ────────────────────────────────────────────────────────

/// Resolve a private-key path from user input.
///
/// If `input` is non-empty, use it verbatim.
/// Otherwise fall back to [`default_dk_path`].
/// Returns `None` only if neither produces a path.
pub fn resolve_private_key_path(input: &str) -> Option<PathBuf> {
    crate::keyutil::resolve_private_key_path(input)
}

// ── Keypair generation ─────────────────────────────────────────────────────────

/// Generate an ML-KEM-768 keypair and write the two key files.
///
/// `prefix` is a file-system path without an extension.
/// Returns a human-readable success message or an error description.
pub fn run_keygen(prefix: &str) -> Result<String, String> {
    let prefix = prefix.trim();
    if prefix.is_empty() {
        return Err("Output prefix must not be empty.".to_string());
    }
    crate::keyutil::run_keygen(std::path::Path::new(prefix))
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
