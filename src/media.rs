//! Drive discovery: enumerates removable and optical media on Windows and Linux.
//!
//! The public surface is a single function, [`get_media_roots`], which returns
//! a [`Vec<MediaRoot>`] describing every candidate drive.  The implementation
//! is platform-specific — Windows uses `GetDriveTypeW` and `QueryDosDeviceW`;
//! Linux parses `lsblk -J` output.

use std::path::PathBuf;

#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
use serde::Deserialize;

/// One discovered removable or optical drive.
#[derive(Debug, Clone)]
pub struct MediaRoot {
    /// Directory to walk when looking for SHA-256 manifests (the mount point).
    pub search_root: PathBuf,
    /// Short human-readable label shown in the GUI (e.g. `"D:"` or `/media/cdrom`).
    pub display_name: String,
    /// Raw device path for optical drives, used for the embedded ISOB3 check
    /// (e.g. `\\.\CdRom0` on Windows, `/dev/sr0` on Linux).  `None` for USB drives.
    pub embedded_target: Option<PathBuf>,
}

// ── Windows ───────────────────────────────────────────────────────────────────

/// Resolve a drive letter to its underlying `\\.\CdRomN` device path so the
/// ISOB3 checker can read raw optical sectors.  Returns `None` for non-optical
/// devices or if the query fails.
#[cfg(windows)]
fn drive_letter_to_cdrom_device(letter: char) -> Option<String> {
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
    use windows::core::PCWSTR;

    let drive = format!("{}:", letter);
    let drive_w: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();

    let mut buf = vec![0u16; 1024];

    let len = unsafe { QueryDosDeviceW(PCWSTR(drive_w.as_ptr()), Some(buf.as_mut_slice())) };
    if len == 0 {
        return None;
    }

    let first_nul = buf.iter().position(|&c| c == 0)?;
    let target = String::from_utf16_lossy(&buf[..first_nul]);
    let lower = target.to_ascii_lowercase();

    if let Some(idx) = lower.find(r"\device\cdrom") {
        let suffix = &target[idx + r"\Device\".len()..];
        return Some(format!(r"\\.\{}", suffix));
    }

    None
}

/// Enumerate every drive letter that is removable (`DRIVE_REMOVABLE`) or
/// optical (`DRIVE_CDROM`) and build a [`MediaRoot`] for each.
#[cfg(windows)]
fn get_windows_media_roots() -> Vec<MediaRoot> {
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;
    use windows::core::PCWSTR;

    let mut roots = Vec::new();

    for letter in b'A'..=b'Z' {
        let drive_letter = format!("{}:", letter as char);
        let mount_root = format!(r"{}\", drive_letter);
        let search_root = PathBuf::from(&mount_root);
        if !search_root.exists() {
            continue;
        }

        let wide: Vec<u16> = mount_root
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let drive_type = unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) };

        const DRIVE_REMOVABLE: u32 = 2;
        const DRIVE_CDROM: u32 = 5;

        if drive_type == DRIVE_REMOVABLE || drive_type == DRIVE_CDROM {
            roots.push(MediaRoot {
                search_root,
                display_name: drive_letter.clone(),
                embedded_target: if drive_type == DRIVE_CDROM {
                    drive_letter_to_cdrom_device(letter as char).map(PathBuf::from)
                } else {
                    None
                },
            });
        }
    }

    dedup_media_roots(roots)
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<LsblkDevice>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
struct LsblkDevice {
    path: Option<String>,
    #[serde(rename = "type")]
    dev_type: Option<String>,
    rm: Option<u8>,
    tran: Option<String>,
    mountpoint: Option<String>,
    children: Option<Vec<LsblkDevice>>,
}

// ── Linux ─────────────────────────────────────────────────────────────────────

/// Enumerate removable USB and optical drives via `lsblk -J`.
///
/// Returns an empty list (rather than an error) if `lsblk` is unavailable or
/// fails, so the GUI degrades gracefully on unusual Linux configurations.
#[cfg(target_os = "linux")]
fn get_linux_media_roots() -> Vec<MediaRoot> {
    let mut roots = Vec::new();

    let lsblk_result = Command::new("lsblk")
        .args(["-J", "-o", "PATH,TYPE,RM,TRAN,MOUNTPOINT"])
        .output();

    match lsblk_result {
        Ok(output) if output.status.success() => {
            if let Ok(parsed) = serde_json::from_slice::<LsblkOutput>(&output.stdout) {
                fn walk(dev: &LsblkDevice, roots: &mut Vec<MediaRoot>) {
                    let dev_type = dev.dev_type.as_deref().unwrap_or("");
                    let rm = dev.rm.unwrap_or(0);
                    let path = dev.path.as_deref();
                    let mountpoint = dev.mountpoint.as_deref();

                    let is_optical = dev_type == "rom"
                        || path.map(|p| p.starts_with("/dev/sr")).unwrap_or(false);
                    let is_usb = rm == 1 && dev.tran.as_deref() == Some("usb");

                    if is_optical {
                        if let Some(mp) = mountpoint {
                            roots.push(MediaRoot {
                                search_root: PathBuf::from(mp),
                                display_name: mp.to_string(),
                                embedded_target: path.map(PathBuf::from),
                            });
                        }
                    } else if is_usb {
                        if let Some(mp) = mountpoint {
                            roots.push(MediaRoot {
                                search_root: PathBuf::from(mp),
                                display_name: mp.to_string(),
                                embedded_target: None,
                            });
                        }
                    }

                    if let Some(children) = &dev.children {
                        for child in children {
                            walk(child, roots);
                        }
                    }
                }

                for dev in &parsed.blockdevices {
                    walk(dev, &mut roots);
                }
            }
        }
        _ => {}
    }

    dedup_media_roots(roots)
}

// ── Shared utilities ──────────────────────────────────────────────────────────

/// Remove duplicate drives that resolve to the same canonical path.
///
/// This can happen on Linux when a device has multiple symlinks.
#[cfg(any(windows, target_os = "linux"))]
fn dedup_media_roots(roots: Vec<MediaRoot>) -> Vec<MediaRoot> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();

    for root in roots {
        let key = root
            .search_root
            .canonicalize()
            .unwrap_or_else(|_| root.search_root.clone())
            .to_string_lossy()
            .to_string();

        if seen.insert(key) {
            out.push(root);
        }
    }

    out
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Return all removable and optical drives visible on this machine.
///
/// The result is platform-specific:
/// - **Windows** — scans drive letters A–Z via `GetDriveTypeW`
/// - **Linux** — parses `lsblk -J`
/// - **Other** — returns `Err`
#[cfg(windows)]
pub fn get_media_roots() -> Result<Vec<MediaRoot>, String> {
    Ok(get_windows_media_roots())
}

/// See [`get_media_roots`] above.
#[cfg(target_os = "linux")]
pub fn get_media_roots() -> Result<Vec<MediaRoot>, String> {
    Ok(get_linux_media_roots())
}

/// See [`get_media_roots`] above.
#[cfg(not(any(windows, target_os = "linux")))]
pub fn get_media_roots() -> Result<Vec<MediaRoot>, String> {
    Err("Unsupported OS".to_string())
}
