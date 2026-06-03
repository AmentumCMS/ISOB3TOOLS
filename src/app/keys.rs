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

/// Spawn the native `.dk` file-picker on a background thread and return a
/// one-shot receiver.  The receiver yields `Some(path)` when the user confirms
/// a selection, or `None` when they cancel.
///
/// **Must not be called on the render thread directly** — the dialog blocks
/// until the user dismisses it, which would freeze the GUI.
///
/// On non-Windows platforms the spawned thread immediately sends `None`.
pub fn browse_dk_file_async() -> std::sync::mpsc::Receiver<Option<String>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = browse_dk_file_impl();
        let _ = tx.send(result);
    });
    rx
}

/// Blocking implementation — runs on the background thread.
fn browse_dk_file_impl() -> Option<String> {
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
    use std::os::windows::process::CommandExt;
    // CREATE_NO_WINDOW (0x0800_0000) prevents Windows from opening a console
    // window when spawning powershell.exe from a GUI process.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    // PowerShell must run in STA apartment mode to host Windows Forms dialogs.
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
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() { None } else { Some(path) }
}
