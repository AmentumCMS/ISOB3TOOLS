use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Instant;

use crossbeam_channel::unbounded;
use walkdir::WalkDir;

use crate::blake3iso_core::{
    CheckOutcome, check_iso_bytes, check_iso_with_progress_and_cancel, estimate_iso_bytes,
};
use crate::dbenc::{
    cleanup_temp_file, decrypt_file, decrypt_file_to_temp_with_cancel, is_encrypted_file,
};
use crate::media::{MediaRoot, get_media_roots};
use crate::sha256sum::{
    ParsedManifest, compute_sha256_with_progress_and_cancel, is_sha256_manifest,
    parse_sha256_manifest, parse_sha256_manifest_bytes,
};

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub drive_name: String,
    pub check_name: String,
    pub subject: String,
    pub source: String,
    pub ok: bool,
    pub detail: String,
    pub elapsed_secs: f64,
    pub processed_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct EncryptionSettings {
    pub enabled: bool,
    pub password: String,
}

#[derive(Debug)]
pub enum WorkerEvent {
    DrivesFound(Vec<MediaRoot>),
    JobsReady {
        count: usize,
        workers: usize,
        total_bytes: u64,
    },
    Progress {
        bytes_delta: u64,
    },
    VerificationResult(VerificationResult),
    Aborted,
    Log(String),
    Fatal(String),
}

#[derive(Debug, Clone)]
enum WorkerJob {
    VerifyManifestEntry {
        media: MediaRoot,
        manifest_path: PathBuf,
        target_path: PathBuf,
        target_display: String,
        expected_sha256: String,
        encryption: EncryptionSettings,
    },
    VerifyEmbeddedDrive {
        media: MediaRoot,
        target_path: PathBuf,
    },
}

struct VerificationInput {
    actual_sha256: String,
    decrypted_path: Option<PathBuf>,
    processed_bytes: u64,
}

#[derive(Default)]
struct PlanningTotals {
    manifest_bytes: u64,
    target_bytes: u64,
    embedded_bytes: u64,
}

enum JobOutcome {
    Completed(VerificationResult),
    Aborted,
}

pub fn discover_drives_worker(tx: Sender<WorkerEvent>) -> Result<(), String> {
    let drives = get_media_roots()?;
    tx.send(WorkerEvent::DrivesFound(drives))
        .map_err(|e| e.to_string())
}

pub fn verify_drives_worker(
    tx: Sender<WorkerEvent>,
    selected_drives: Vec<MediaRoot>,
    max_workers: usize,
    encryption: EncryptionSettings,
    cancel: Arc<AtomicBool>,
) -> Result<(), String> {
    let mut jobs = Vec::new();
    let mut totals = PlanningTotals::default();

    for drive in selected_drives {
        if cancel.load(Ordering::Relaxed) {
            let _ = tx.send(WorkerEvent::Aborted);
            return Ok(());
        }

        tx.send(WorkerEvent::Log(format!(
            "Searching {} for SHA-256 manifests...",
            drive.display_name
        )))
        .map_err(|e| e.to_string())?;

        let manifests = find_sha256_manifests(&drive.search_root);
        tx.send(WorkerEvent::Log(format!(
            "Found {} SHA-256 manifest(s) on {}.",
            manifests.len(),
            drive.display_name
        )))
        .map_err(|e| e.to_string())?;

        for manifest_path in manifests {
            if cancel.load(Ordering::Relaxed) {
                let _ = tx.send(WorkerEvent::Aborted);
                return Ok(());
            }

            totals.manifest_bytes = totals
                .manifest_bytes
                .saturating_add(estimated_manifest_bytes(&manifest_path, &encryption));

            match load_manifest_entries(&manifest_path, &encryption, &tx) {
                Ok(parsed) => {
                    tx.send(WorkerEvent::Log(format!(
                        "Parsed {} entrie(s) from {}{}",
                        parsed.entries.len(),
                        manifest_path.display(),
                        if parsed.skipped_lines > 0 {
                            format!(" (skipped {} line(s))", parsed.skipped_lines)
                        } else {
                            String::new()
                        }
                    )))
                    .map_err(|e| e.to_string())?;

                    for entry in parsed.entries {
                        totals.target_bytes =
                            totals
                                .target_bytes
                                .saturating_add(estimated_manifest_target_bytes(
                                    &entry.target_path,
                                    &encryption,
                                ));

                        jobs.push(WorkerJob::VerifyManifestEntry {
                            media: drive.clone(),
                            manifest_path: entry.manifest_path,
                            target_path: entry.target_path,
                            target_display: entry.target_display,
                            expected_sha256: entry.expected_hex,
                            encryption: encryption.clone(),
                        });
                    }
                }
                Err(err) => {
                    tx.send(WorkerEvent::VerificationResult(VerificationResult {
                        drive_name: drive.display_name.clone(),
                        check_name: "SHA256-MANIFEST".to_string(),
                        subject: manifest_path.display().to_string(),
                        source: manifest_path.display().to_string(),
                        ok: false,
                        detail: err,
                        elapsed_secs: 0.0,
                        processed_bytes: 0,
                    }))
                    .map_err(|e| e.to_string())?;
                }
            }
        }

        if let Some(target_path) = &drive.embedded_target {
            totals.embedded_bytes = totals
                .embedded_bytes
                .saturating_add(estimated_embedded_bytes(target_path));

            jobs.push(WorkerJob::VerifyEmbeddedDrive {
                media: drive.clone(),
                target_path: target_path.clone(),
            });
        }
    }

    let total_bytes = totals
        .manifest_bytes
        .saturating_add(totals.target_bytes)
        .saturating_add(totals.embedded_bytes);
    let workers = max_workers.min(jobs.len().max(1));
    tx.send(WorkerEvent::Log(format!(
        "Planned bytes | manifests: {} | sha targets: {} | embedded ISOB3: {} | total: {}",
        totals.manifest_bytes, totals.target_bytes, totals.embedded_bytes, total_bytes
    )))
    .map_err(|e| e.to_string())?;
    tx.send(WorkerEvent::JobsReady {
        count: jobs.len(),
        workers,
        total_bytes,
    })
    .map_err(|e| e.to_string())?;

    if jobs.is_empty() {
        return Ok(());
    }

    let (job_tx, job_rx) = unbounded();

    for _ in 0..workers {
        let rx = job_rx.clone();
        let tx_clone = tx.clone();
        let cancel_clone = cancel.clone();

        thread::spawn(move || {
            while let Ok(job) = rx.recv() {
                if cancel_clone.load(Ordering::Relaxed) {
                    let _ = tx_clone.send(WorkerEvent::Aborted);
                    break;
                }

                match run_job(job, &tx_clone, &cancel_clone) {
                    JobOutcome::Completed(result) => {
                        let _ = tx_clone.send(WorkerEvent::VerificationResult(result));
                    }
                    JobOutcome::Aborted => {
                        let _ = tx_clone.send(WorkerEvent::Aborted);
                        break;
                    }
                }
            }
        });
    }

    for job in jobs {
        if cancel.load(Ordering::Relaxed) {
            let _ = tx.send(WorkerEvent::Aborted);
            return Ok(());
        }
        job_tx.send(job).map_err(|e| e.to_string())?;
    }

    Ok(())
}

fn find_sha256_manifests(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| is_sha256_manifest(path))
        .collect()
}

fn load_manifest_entries(
    manifest_path: &Path,
    encryption: &EncryptionSettings,
    tx: &Sender<WorkerEvent>,
) -> Result<ParsedManifest, String> {
    if is_encrypted_file(manifest_path)? {
        if !encryption.enabled {
            return Err(format!(
                "Manifest {} is encrypted. Enable encrypted-file support first.",
                manifest_path.display()
            ));
        }

        let decrypted = decrypt_file(manifest_path, &encryption.password)?;
        let _ = tx.send(WorkerEvent::Progress {
            bytes_delta: decrypted.cipher_bytes,
        });
        parse_sha256_manifest_bytes(manifest_path, &decrypted.plaintext)
    } else {
        parse_sha256_manifest(manifest_path)
    }
}

fn run_job(job: WorkerJob, tx: &Sender<WorkerEvent>, cancel: &Arc<AtomicBool>) -> JobOutcome {
    match job {
        WorkerJob::VerifyManifestEntry {
            media,
            manifest_path,
            target_path,
            target_display,
            expected_sha256,
            encryption,
        } => verify_manifest_entry(
            &media,
            &manifest_path,
            &target_path,
            &target_display,
            &expected_sha256,
            &encryption,
            tx,
            cancel,
        ),
        WorkerJob::VerifyEmbeddedDrive { media, target_path } => {
            verify_embedded_drive(&media, &target_path, tx, cancel)
        }
    }
}

fn verify_manifest_entry(
    media: &MediaRoot,
    manifest_path: &Path,
    target_path: &Path,
    target_display: &str,
    expected_sha256: &str,
    encryption: &EncryptionSettings,
    tx: &Sender<WorkerEvent>,
    cancel: &Arc<AtomicBool>,
) -> JobOutcome {
    let start = Instant::now();

    if !target_path.exists() {
        return JobOutcome::Completed(VerificationResult {
            drive_name: media.display_name.clone(),
            check_name: "SHA256".to_string(),
            subject: target_display.to_string(),
            source: manifest_path.display().to_string(),
            ok: false,
            detail: format!("Referenced file not found: {}", target_path.display()),
            elapsed_secs: 0.0,
            processed_bytes: 0,
        });
    }

    let verification_input = match build_verification_input(target_path, encryption, tx, cancel) {
        Ok(input) => input,
        Err(err) if is_abort_error(&err) => return JobOutcome::Aborted,
        Err(err) => {
            return JobOutcome::Completed(VerificationResult {
                drive_name: media.display_name.clone(),
                check_name: "SHA256".to_string(),
                subject: target_display.to_string(),
                source: manifest_path.display().to_string(),
                ok: false,
                detail: err,
                elapsed_secs: start.elapsed().as_secs_f64(),
                processed_bytes: 0,
            });
        }
    };

    if verification_input.actual_sha256 != expected_sha256 {
        return JobOutcome::Completed(VerificationResult {
            drive_name: media.display_name.clone(),
            check_name: "SHA256".to_string(),
            subject: target_display.to_string(),
            source: manifest_path.display().to_string(),
            ok: false,
            detail: format!(
                "SHA-256 mismatch\nExpected: {expected_sha256}\nActual:   {}",
                verification_input.actual_sha256
            ),
            elapsed_secs: start.elapsed().as_secs_f64(),
            processed_bytes: verification_input.processed_bytes,
        });
    }

    let iso_target = verification_input
        .decrypted_path
        .as_deref()
        .unwrap_or(target_path);
    let iso_detail = match verify_isob3_target(iso_target, None, tx, cancel) {
        Ok(detail) => detail,
        Err(err) if is_abort_error(&err) => {
            if let Some(temp_path) = &verification_input.decrypted_path {
                cleanup_temp_file(temp_path);
            }
            return JobOutcome::Aborted;
        }
        Err(err) => IsoVerification::Invalid(err),
    };
    let elapsed_secs = start.elapsed().as_secs_f64();

    let result = match iso_detail {
        IsoVerification::Valid(detail) => VerificationResult {
            drive_name: media.display_name.clone(),
            check_name: "SHA256 + ISOB3".to_string(),
            subject: target_display.to_string(),
            source: manifest_path.display().to_string(),
            ok: true,
            detail: format!("SHA-256 valid\n{detail}"),
            elapsed_secs,
            processed_bytes: verification_input.processed_bytes,
        },
        IsoVerification::Missing(detail) => VerificationResult {
            drive_name: media.display_name.clone(),
            check_name: "SHA256 + ISOB3".to_string(),
            subject: target_display.to_string(),
            source: manifest_path.display().to_string(),
            ok: false,
            detail: format!("SHA-256 valid\n{detail}"),
            elapsed_secs,
            processed_bytes: verification_input.processed_bytes,
        },
        IsoVerification::Invalid(detail) => VerificationResult {
            drive_name: media.display_name.clone(),
            check_name: "SHA256 + ISOB3".to_string(),
            subject: target_display.to_string(),
            source: manifest_path.display().to_string(),
            ok: false,
            detail: format!("SHA-256 valid\n{detail}"),
            elapsed_secs,
            processed_bytes: verification_input.processed_bytes,
        },
        IsoVerification::Skipped(detail) => VerificationResult {
            drive_name: media.display_name.clone(),
            check_name: "SHA256".to_string(),
            subject: target_display.to_string(),
            source: manifest_path.display().to_string(),
            ok: true,
            detail: format!("SHA-256 valid\n{detail}"),
            elapsed_secs,
            processed_bytes: verification_input.processed_bytes,
        },
    };

    if let Some(temp_path) = &verification_input.decrypted_path {
        cleanup_temp_file(temp_path);
    }

    JobOutcome::Completed(result)
}

fn build_verification_input(
    target_path: &Path,
    encryption: &EncryptionSettings,
    tx: &Sender<WorkerEvent>,
    cancel: &Arc<AtomicBool>,
) -> Result<VerificationInput, String> {
    if is_encrypted_file(target_path)? {
        if !encryption.enabled {
            return Err(format!(
                "Target {} is encrypted. Enable encrypted-file support first.",
                target_path.display()
            ));
        }

        let decrypted = decrypt_file_to_temp_with_cancel(
            target_path,
            &encryption.password,
            |bytes_delta| {
                let _ = tx.send(WorkerEvent::Progress { bytes_delta });
            },
            || cancel.load(Ordering::Relaxed),
        )?;

        Ok(VerificationInput {
            actual_sha256: decrypted.plaintext_sha256,
            processed_bytes: decrypted.cipher_bytes + decrypted.plaintext_bytes,
            decrypted_path: Some(decrypted.temp_path),
        })
    } else {
        let processed_bytes = file_len(target_path);
        let actual_sha256 = compute_sha256_with_progress_and_cancel(
            target_path,
            |bytes_delta| {
                let _ = tx.send(WorkerEvent::Progress { bytes_delta });
            },
            || cancel.load(Ordering::Relaxed),
        )
        .map_err(|err| format!("SHA-256 error: {err}"))?;

        Ok(VerificationInput {
            actual_sha256,
            processed_bytes,
            decrypted_path: None,
        })
    }
}

fn verify_embedded_drive(
    media: &MediaRoot,
    target_path: &Path,
    tx: &Sender<WorkerEvent>,
    cancel: &Arc<AtomicBool>,
) -> JobOutcome {
    let start = Instant::now();
    let detail = match verify_isob3_target(target_path, None, tx, cancel) {
        Ok(detail) => detail,
        Err(err) if is_abort_error(&err) => return JobOutcome::Aborted,
        Err(err) => IsoVerification::Invalid(err),
    };
    let processed_bytes = estimate_verification_source_bytes(target_path);

    JobOutcome::Completed(match detail {
        IsoVerification::Valid(detail) => VerificationResult {
            drive_name: media.display_name.clone(),
            check_name: "EMBEDDED-ISOB3".to_string(),
            subject: target_path.display().to_string(),
            source: media.search_root.display().to_string(),
            ok: true,
            detail,
            elapsed_secs: start.elapsed().as_secs_f64(),
            processed_bytes,
        },
        IsoVerification::Missing(detail)
        | IsoVerification::Invalid(detail)
        | IsoVerification::Skipped(detail) => VerificationResult {
            drive_name: media.display_name.clone(),
            check_name: "EMBEDDED-ISOB3".to_string(),
            subject: target_path.display().to_string(),
            source: media.search_root.display().to_string(),
            ok: false,
            detail,
            elapsed_secs: start.elapsed().as_secs_f64(),
            processed_bytes,
        },
    })
}

enum IsoVerification {
    Valid(String),
    Missing(String),
    Invalid(String),
    Skipped(String),
}

fn verify_isob3_target(
    path: &Path,
    decrypted_bytes: Option<&[u8]>,
    tx: &Sender<WorkerEvent>,
    cancel: &Arc<AtomicBool>,
) -> Result<IsoVerification, String> {
    if let Some(bytes) = decrypted_bytes {
        if !looks_like_iso_bytes(bytes) {
            return Ok(IsoVerification::Skipped(
                "Skipped ISOB3 check (decrypted content is not an ISO).".to_string(),
            ));
        }

        let _ = tx.send(WorkerEvent::Progress {
            bytes_delta: bytes.len() as u64,
        });

        return Ok(map_check_outcome(check_iso_bytes(bytes)));
    }

    if !looks_like_iso_target(path) {
        return Ok(IsoVerification::Skipped(
            "Skipped ISOB3 check (not an ISO target).".to_string(),
        ));
    }

    Ok(map_check_outcome(check_iso_with_progress_and_cancel(
        path,
        |bytes_delta| {
            let _ = tx.send(WorkerEvent::Progress { bytes_delta });
        },
        || cancel.load(Ordering::Relaxed),
    )))
}

fn map_check_outcome(result: Result<CheckOutcome, String>) -> IsoVerification {
    match result {
        Ok(CheckOutcome::Valid { detail, .. }) => IsoVerification::Valid(detail),
        Ok(CheckOutcome::Invalid { detail, .. }) => IsoVerification::Invalid(detail),
        Ok(CheckOutcome::Missing) => {
            IsoVerification::Missing("ISOB3 metadata missing.".to_string())
        }
        Err(err) => IsoVerification::Invalid(format!("ISOB3 error: {err}")),
    }
}

fn looks_like_iso_target(path: &Path) -> bool {
    if is_raw_iso_device(path) {
        return true;
    }

    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("iso"))
        .unwrap_or(false)
}

fn is_raw_iso_device(path: &Path) -> bool {
    #[cfg(windows)]
    {
        if path.to_string_lossy().starts_with(r"\\.\") {
            return true;
        }
    }

    #[cfg(target_os = "linux")]
    {
        let raw = path.to_string_lossy();
        if raw.starts_with("/dev/sr")
            || raw.starts_with("/dev/scd")
            || raw == "/dev/cdrom"
            || raw == "/dev/dvd"
        {
            return true;
        }
    }

    false
}

fn looks_like_iso_bytes(bytes: &[u8]) -> bool {
    const PVD_OFFSET: usize = 16 * 2048;
    bytes.len() >= PVD_OFFSET + 7
        && bytes[PVD_OFFSET] == 1
        && &bytes[PVD_OFFSET + 1..PVD_OFFSET + 6] == b"CD001"
        && bytes[PVD_OFFSET + 6] == 1
}

fn estimated_manifest_bytes(path: &Path, encryption: &EncryptionSettings) -> u64 {
    let file_bytes = file_len(path);
    if encryption.enabled && is_encrypted_file(path).unwrap_or(false) {
        file_bytes.saturating_mul(2)
    } else {
        file_bytes
    }
}

fn estimated_manifest_target_bytes(path: &Path, encryption: &EncryptionSettings) -> u64 {
    let file_bytes = file_len(path);
    if encryption.enabled && is_encrypted_file(path).unwrap_or(false) {
        if looks_like_iso_target(path) {
            file_bytes.saturating_mul(3)
        } else {
            file_bytes.saturating_mul(2)
        }
    } else if looks_like_iso_target(path) {
        file_bytes.saturating_mul(2)
    } else {
        file_bytes
    }
}

fn estimated_embedded_bytes(path: &Path) -> u64 {
    estimate_verification_source_bytes(path)
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}

fn estimate_verification_source_bytes(path: &Path) -> u64 {
    let file_bytes = file_len(path);
    if file_bytes > 0 {
        file_bytes
    } else {
        estimate_iso_bytes(path).unwrap_or(0)
    }
}

fn is_abort_error(err: &str) -> bool {
    err.contains("operation aborted")
}
