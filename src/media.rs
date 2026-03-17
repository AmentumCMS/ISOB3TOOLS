use std::path::PathBuf;

#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
use serde::Deserialize;

#[derive(Debug, Clone)]
pub enum MediaKind {
    /// Read directly from a device node or raw optical drive handle.
    RawDevice,
    /// Walk a mounted filesystem and look for `.iso` files.
    ScanRoot,
}

#[derive(Debug, Clone)]
pub struct MediaRoot {
    pub path: PathBuf,
    pub kind: MediaKind,
    pub display_name: String,
}

#[cfg(windows)]
fn drive_letter_to_cdrom_device(letter: char) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

    let drive = format!("{}:", letter);
    let drive_w: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();

    let mut buf = vec![0u16; 1024];

    let len = unsafe { QueryDosDeviceW(PCWSTR(drive_w.as_ptr()), Some(buf.as_mut_slice())) };
    if len == 0 {
        return None;
    }

    let first_nul = buf.iter().position(|&c| c == 0)?;
    let target = String::from_utf16_lossy(&buf[..first_nul]);

    // Translate the DOS device mapping into a raw `\\.\CdRomN` path when possible.
    let lower = target.to_ascii_lowercase();
    if let Some(idx) = lower.find(r"\device\cdrom") {
        let suffix = &target[idx + r"\Device\".len()..];
        return Some(format!(r"\\.\{}", suffix));
    }

    None
}

#[cfg(windows)]
fn get_windows_media_roots() -> Vec<MediaRoot> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;

    let mut roots = Vec::new();

    for letter in b'A'..=b'Z' {
        let drive_letter = format!("{}:", letter as char);
        let mount_root = format!(r"{}\", drive_letter);
        let path = PathBuf::from(&mount_root);
        if !path.exists() {
            continue;
        }

        let wide: Vec<u16> = mount_root.encode_utf16().chain(std::iter::once(0)).collect();
        let drive_type = unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) };

        const DRIVE_REMOVABLE: u32 = 2;
        const DRIVE_CDROM: u32 = 5;

        if drive_type == DRIVE_CDROM {
            // Prefer raw device access for optical media so verification works even when the
            // mounted filesystem view is incomplete or absent.
            if let Some(cdrom_path) = drive_letter_to_cdrom_device(letter as char) {
                roots.push(MediaRoot {
                    path: PathBuf::from(cdrom_path),
                    kind: MediaKind::RawDevice,
                    display_name: drive_letter.clone(),
                });
            } else {
                roots.push(MediaRoot {
                    path: PathBuf::from(mount_root),
                    kind: MediaKind::ScanRoot,
                    display_name: drive_letter.clone(),
                });
            }
        } else if drive_type == DRIVE_REMOVABLE {
            roots.push(MediaRoot {
                path: PathBuf::from(mount_root),
                kind: MediaKind::ScanRoot,
                display_name: drive_letter.clone(),
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

#[cfg(target_os = "linux")]
fn get_linux_media_roots() -> Vec<MediaRoot> {
    let mut roots = Vec::new();

    // `lsblk` gives us enough information to separate optical devices from removable USB mounts.
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

                    let is_optical =
                        dev_type == "rom" || path.map(|p| p.starts_with("/dev/sr")).unwrap_or(false);

                    let is_usb = rm == 1 && dev.tran.as_deref() == Some("usb");

                    if is_optical {
                        if let Some(device_path) = path {
                            roots.push(MediaRoot {
                                path: PathBuf::from(device_path),
                                kind: MediaKind::RawDevice,
                                display_name: device_path.to_string(),
                            });
                        }
                    } else if is_usb {
                        // For removable storage we scan the mounted tree for ISO files instead of
                        // hashing the block device directly.
                        if let Some(mp) = mountpoint {
                            roots.push(MediaRoot {
                                path: PathBuf::from(mp),
                                kind: MediaKind::ScanRoot,
                                display_name: mp.to_string(),
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
        _ => {
            // Fall back to a few common optical device names when `lsblk` is unavailable.
            for candidate in ["/dev/sr0", "/dev/sr1", "/dev/sr2", "/dev/cdrom", "/dev/dvd"] {
                let path = PathBuf::from(candidate);
                if path.exists() {
                    roots.push(MediaRoot {
                        path,
                        kind: MediaKind::RawDevice,
                        display_name: candidate.to_string(),
                    });
                }
            }
        }
    }

    dedup_media_roots(roots)
}

#[cfg(any(windows, target_os = "linux"))]
fn dedup_media_roots(roots: Vec<MediaRoot>) -> Vec<MediaRoot> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();

    for root in roots {
        let key = root
            .path
            .canonicalize()
            .unwrap_or_else(|_| root.path.clone())
            .to_string_lossy()
            .to_string();

        // Keep raw-device and scan-root entries distinct even if they resolve to the same path.
        if seen.insert((key, matches!(root.kind, MediaKind::RawDevice))) {
            out.push(root);
        }
    }

    out
}

#[cfg(windows)]
pub fn get_media_roots() -> Result<Vec<MediaRoot>, String> {
    Ok(get_windows_media_roots())
}

#[cfg(target_os = "linux")]
pub fn get_media_roots() -> Result<Vec<MediaRoot>, String> {
    Ok(get_linux_media_roots())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn get_media_roots() -> Result<Vec<MediaRoot>, String> {
    Err("Unsupported OS".to_string())
}
