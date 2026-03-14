use std::path::{PathBuf};

#[cfg(target_os = "linux")]
use serde::Deserialize;

#[cfg(windows)]
fn get_windows_media_roots() -> Vec<PathBuf> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;

    let mut roots = Vec::new();

    for letter in b'A'..=b'Z' {
        let root = format!("{}:\\", letter as char);
        let path = PathBuf::from(&root);
        if !path.exists() {
            continue;
        }

        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        let drive_type = unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) };

        const DRIVE_REMOVABLE: u32 = 2;
        const DRIVE_CDROM: u32 = 5;

        if drive_type == DRIVE_REMOVABLE || drive_type == DRIVE_CDROM {
            roots.push(path);
        }
    }

    roots
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
fn get_linux_media_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    let lsblk_result = Command::new("lsblk")
        .args(["-J", "-o", "PATH,TYPE,RM,TRAN,MOUNTPOINT"])
        .output();

    match lsblk_result {
        Ok(output) if output.status.success() => {
            if let Ok(parsed) = serde_json::from_slice::<LsblkOutput>(&output.stdout) {
                fn walk(dev: &LsblkDevice, roots: &mut Vec<PathBuf>) {
                    let dev_type = dev.dev_type.as_deref().unwrap_or("");
                    let rm = dev.rm.unwrap_or(0);
                    let mountpoint = dev.mountpoint.as_deref();
                    let path = dev.path.as_deref();

                    if let Some(mp) = mountpoint {
                        if dev_type == "rom"
                            || rm == 1
                            || path.map(|p| p.starts_with("/dev/sr")).unwrap_or(false)
                            || dev.tran.as_deref() == Some("usb")
                        {
                            roots.push(PathBuf::from(mp));
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
            for base in ["/media", "/run/media", "/mnt"] {
                let p = Path::new(base);
                if p.exists() {
                    if let Ok(entries) = std::fs::read_dir(p) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.is_dir() {
                                roots.push(path);
                            }
                        }
                    }
                }
            }
        }
    }

    dedup_paths(roots)
}

#[cfg(target_os = "linux")]
fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();

    for p in paths {
        let key = p
            .canonicalize()
            .unwrap_or_else(|_| p.clone())
            .to_string_lossy()
            .to_string();

        if seen.insert(key) {
            out.push(p);
        }
    }

    out
}

#[cfg(windows)]
pub fn get_media_roots() -> Result<Vec<PathBuf>, String> {
    Ok(get_windows_media_roots())
}

#[cfg(target_os = "linux")]
pub fn get_media_roots() -> Result<Vec<PathBuf>, String> {
    Ok(get_linux_media_roots())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn get_media_roots() -> Result<Vec<PathBuf>, String> {
    Err("Unsupported OS".to_string())
}
