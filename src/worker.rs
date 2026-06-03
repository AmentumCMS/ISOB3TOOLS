//! Background worker threads: drive discovery and multi-drive verification.
//!
//! Verification runs in two phases:
//!
//! 1. **Planning** — each selected drive is walked to find SHA-256 manifests and
//!    detect embedded ISOB3 targets.  All planned work is reported via
//!    [`WorkerEvent::JobsReady`] before any hashing starts.
//!
//! 2. **Execution** — SHA-256 manifest jobs run first (concurrent across drives),
//!    then embedded-ISOB3 drive jobs.  Each phase uses [`run_drive_phase`] with a
//!    bounded worker pool.  Results flow back through an [`mpsc::Sender<WorkerEvent>`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Instant;

use crossbeam_channel::unbounded;
use walkdir::WalkDir;

use crate::blake3iso_core::{
    CheckOutcome, check_iso_bytes, check_iso_with_progress_and_cancel, estimate_iso_bytes,
};
use crate::dbenc::{
    DbEncFormat, PQE_DK_LEN, cleanup_temp_file, decrypt_file, detect_format,
    decrypt_file_to_temp_with_cancel, decrypt_file_pqe_to_temp_with_cancel, is_encrypted_file,
};
use crate::media::{MediaRoot, get_media_roots};
use crate::sha256sum::{
    ParsedManifest, compute_sha256_with_progress_and_cancel, is_sha256_manifest,
    parse_sha256_manifest, parse_sha256_manifest_bytes,
};

/// Outcome of one file-level verification check, sent back to the GUI via the worker channel.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Human-readable name of the drive this result belongs to (e.g. `"D:"`).
    pub drive_name: String,
    /// What kind of check was performed (e.g. `"SHA256 + ISOB3"`, `"EMBEDDED-ISOB3"`).
    pub check_name: String,
    /// Display path of the file that was verified.
    pub subject: String,
    /// Manifest or drive path that named this check.
    pub source: String,
    /// `true` if the check passed.
    pub ok: bool,
    /// Multi-line human-readable detail (digest values, error descriptions, etc.).
    pub detail: String,
    /// Wall-clock seconds consumed by this check.
    pub elapsed_secs: f64,
    /// Bytes read/processed during this check (used for throughput stats).
    pub processed_bytes: u64,
}

/// Credentials and flags needed to handle encrypted disc files during verification.
#[derive(Debug, Clone)]
pub struct EncryptionSettings {
    /// Whether encrypted-file support is active at all.
    pub enabled: bool,
    /// Password for DBENC001–DBENC004 symmetric encryption.
    pub password: String,
    /// Path to a DBENC005 (ML-KEM-768) decapsulation-key file (`.dk`, 64-byte seed).
    /// When set, PQE-encrypted files are decrypted automatically without a password.
    pub private_key_path: Option<PathBuf>,
}

impl Default for EncryptionSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            password: String::new(),
            private_key_path: None,
        }
    }
}

/// Events sent from background worker threads to the GUI event loop.
#[derive(Debug)]
pub enum WorkerEvent {
    /// Drive discovery finished; contains every discovered removable / optical drive.
    DrivesFound(Vec<MediaRoot>),
    /// All jobs have been planned; GUI can show the total expected work.
    JobsReady {
        count: usize,
        workers: usize,
        total_bytes: u64,
    },
    /// A chunk of bytes was hashed; used to advance the progress bar.
    Progress {
        bytes_delta: u64,
    },
    /// One file-level check completed.
    VerificationResult(VerificationResult),
    /// The run was cancelled via the abort flag.
    Aborted,
    /// Informational log message.
    Log(String),
    /// Unrecoverable worker error (planning or channel failure).
    Fatal(String),
}

// ── Internal job types ─────────────────────────────────────────────────────────

/// A single unit of verification work dispatched to a worker thread.
#[derive(Debug, Clone)]
enum WorkerJob {
    /// Verify one entry from a SHA-256 manifest file.
    VerifyManifestEntry {
        media: MediaRoot,
        manifest_path: PathBuf,
        target_path: PathBuf,
        target_display: String,
        expected_sha256: String,
        encryption: EncryptionSettings,
    },
    /// Verify an ISO/device target that carries embedded ISOB3 metadata.
    VerifyEmbeddedDrive {
        media: MediaRoot,
        target_path: PathBuf,
    },
}

/// All jobs planned for one drive, split into two ordered phases.
#[derive(Debug, Clone)]
struct DriveJobs {
    /// SHA-256 manifest checks (run first, concurrently across drives).
    sha_jobs: Vec<WorkerJob>,
    /// Embedded ISOB3 drive checks (run second, after all SHA jobs finish).
    embedded_jobs: Vec<WorkerJob>,
}

/// Intermediate result of decrypting/hashing a target file before comparing
/// it against the manifest's expected digest.
struct VerificationInput {
    /// Lowercase hex SHA-256 of the plaintext content.
    actual_sha256: String,
    /// Path to a temporary decrypted file, if the source was encrypted.
    /// Must be cleaned up after the check completes.
    decrypted_path: Option<PathBuf>,
    /// Total bytes read during this step (ciphertext + plaintext for encrypted files).
    processed_bytes: u64,
}

/// Byte-count accumulators built during the planning phase for the progress-bar estimate.
#[derive(Default)]
struct PlanningTotals {
    manifest_bytes: u64,
    target_bytes: u64,
    embedded_bytes: u64,
}

/// What a single [`WorkerJob`] execution produced.
enum JobOutcome {
    Completed(VerificationResult),
    Aborted,
}

// ── Public entry points ────────────────────────────────────────────────────────

/// Discover removable and optical drives on the current machine.
///
/// Sends a single [`WorkerEvent::DrivesFound`] and returns.  Intended to run
/// in a dedicated thread spawned by the GUI.
pub fn discover_drives_worker(tx: Sender<WorkerEvent>) -> Result<(), String> {
    let drives = get_media_roots()?;
    tx.send(WorkerEvent::DrivesFound(drives))
        .map_err(|e| e.to_string())
}

/// Run all verification work across the given drives.
///
/// Sends a stream of [`WorkerEvent`] values (progress, results, logs) and
/// returns `Ok(())` when finished or when aborted via `cancel`.  Any channel
/// send failure is treated as fatal and propagated as `Err`.
pub fn verify_drives_worker(
    tx: Sender<WorkerEvent>,
    selected_drives: Vec<MediaRoot>,
    max_workers: usize,
    encryption: EncryptionSettings,
    cancel: Arc<AtomicBool>,
) -> Result<(), String> {
    let mut drive_jobs = Vec::new();
    let mut totals = PlanningTotals::default();

    for drive in selected_drives {
        let mut sha_jobs = Vec::new();
        let mut embedded_jobs = Vec::new();

        if cancel.load(Ordering::Relaxed) {
            let _ = tx.send(WorkerEvent::Aborted);
            return Ok(());
        }

        tx.send(WorkerEvent::Log(format!(
            "Searching {} for SHA-256 manifests...",
            drive.display_name
        )))
        .map_err(|e| e.to_string())?;

        let manifests = find_sha256_manifests(&drive.search_root, &encryption);
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

                        sha_jobs.push(WorkerJob::VerifyManifestEntry {
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

            embedded_jobs.push(WorkerJob::VerifyEmbeddedDrive {
                media: drive.clone(),
                target_path: target_path.clone(),
            });
        }

        if !sha_jobs.is_empty() || !embedded_jobs.is_empty() {
            drive_jobs.push(DriveJobs {
                sha_jobs,
                embedded_jobs,
            });
        }
    }

    let total_bytes = totals
        .manifest_bytes
        .saturating_add(totals.target_bytes)
        .saturating_add(totals.embedded_bytes);
    tx.send(WorkerEvent::Log(format!(
        "Planned bytes | manifests: {} | sha targets: {} | embedded ISOB3: {} | total: {}",
        totals.manifest_bytes, totals.target_bytes, totals.embedded_bytes, total_bytes
    )))
    .map_err(|e| e.to_string())?;
    let total_jobs: usize = drive_jobs
        .iter()
        .map(|batch| batch.sha_jobs.len() + batch.embedded_jobs.len())
        .sum();
    tx.send(WorkerEvent::JobsReady {
        count: total_jobs,
        workers: max_workers.min(drive_jobs.len().max(1)),
        total_bytes,
    })
    .map_err(|e| e.to_string())?;

    if drive_jobs.is_empty() {
        return Ok(());
    }

    run_drive_phase(
        &tx,
        &cancel,
        max_workers,
        drive_jobs
            .iter()
            .filter(|batch| !batch.sha_jobs.is_empty())
            .map(|batch| batch.sha_jobs.clone())
            .collect(),
    )?;

    if cancel.load(Ordering::Relaxed) {
        let _ = tx.send(WorkerEvent::Aborted);
        return Ok(());
    }

    run_drive_phase(
        &tx,
        &cancel,
        max_workers,
        drive_jobs
            .into_iter()
            .filter(|batch| !batch.embedded_jobs.is_empty())
            .map(|batch| batch.embedded_jobs)
            .collect(),
    )?;

    Ok(())
}

// ── Execution engine ──────────────────────────────────────────────────────────

/// Run one phase of work (either SHA or embedded ISOB3 jobs) across all drives.
///
/// Each element of `drive_batches` is the full job list for one drive.  Jobs
/// within a batch run sequentially (so one drive uses at most one worker at a
/// time), but up to `max_workers` drives are processed concurrently.
fn run_drive_phase(
    tx: &Sender<WorkerEvent>,
    cancel: &Arc<AtomicBool>,
    max_workers: usize,
    drive_batches: Vec<Vec<WorkerJob>>,
) -> Result<(), String> {
    if drive_batches.is_empty() {
        return Ok(());
    }

    let workers = max_workers.min(drive_batches.len().max(1));
    let (job_tx, job_rx) = unbounded::<Vec<WorkerJob>>();
    let (done_tx, done_rx) = mpsc::channel();

    for _ in 0..workers {
        let rx = job_rx.clone();
        let tx_clone = tx.clone();
        let cancel_clone = cancel.clone();
        let done_tx_clone = done_tx.clone();

        thread::spawn(move || {
            while let Ok(drive_batch) = rx.recv() {
                if cancel_clone.load(Ordering::Relaxed) {
                    let _ = tx_clone.send(WorkerEvent::Aborted);
                    break;
                }

                for job in drive_batch {
                    if cancel_clone.load(Ordering::Relaxed) {
                        let _ = tx_clone.send(WorkerEvent::Aborted);
                        return;
                    }

                    match run_job(job, &tx_clone, &cancel_clone) {
                        JobOutcome::Completed(result) => {
                            let _ = tx_clone.send(WorkerEvent::VerificationResult(result));
                        }
                        JobOutcome::Aborted => {
                            let _ = tx_clone.send(WorkerEvent::Aborted);
                            return;
                        }
                    }
                }
            }

            let _ = done_tx_clone.send(());
        });
    }

    drop(done_tx);

    for drive_batch in drive_batches {
        if cancel.load(Ordering::Relaxed) {
            let _ = tx.send(WorkerEvent::Aborted);
            return Ok(());
        }
        job_tx.send(drive_batch).map_err(|e| e.to_string())?;
    }

    drop(job_tx);

    for _ in 0..workers {
        done_rx.recv().map_err(|e| e.to_string())?;
    }

    Ok(())
}

// ── Planning helpers ──────────────────────────────────────────────────────────

/// Recursively walk `root` and return every file that looks like a SHA-256 manifest,
/// including encrypted files that decrypt to a manifest when a key/password is available.
fn find_sha256_manifests(root: &Path, encryption: &EncryptionSettings) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| is_sha256_manifest_candidate(path, encryption))
        .collect()
}

/// Read a decapsulation-key file and return its bytes as a fixed-size array.
///
/// Fails if the file cannot be read or is the wrong size.
fn load_dk_bytes(path: &Path) -> Result<[u8; PQE_DK_LEN], String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read key failed: {e}"))?;
    if bytes.len() != PQE_DK_LEN {
        return Err(format!(
            "invalid key file: expected {} bytes, got {}",
            PQE_DK_LEN,
            bytes.len()
        ));
    }
    let mut arr = [0u8; PQE_DK_LEN];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Return `true` if `path` is (or decrypts to) a SHA-256 manifest.
///
/// Plaintext manifests are identified by filename heuristics.  Encrypted files
/// are tentatively decrypted and parsed — a file is accepted if it yields at
/// least one manifest entry.
fn is_sha256_manifest_candidate(path: &Path, encryption: &EncryptionSettings) -> bool {
    if is_sha256_manifest(path) {
        return true;
    }

    match detect_format(path) {
        Ok(Some(DbEncFormat::DbEnc005)) => {
            let Some(dk_path) = encryption.private_key_path.as_deref() else {
                return false;
            };
            let Ok(dk_bytes) = load_dk_bytes(dk_path) else {
                return false;
            };
            pqe_manifest_probe(path, &dk_bytes)
                .map(|parsed| !parsed.entries.is_empty())
                .unwrap_or(false)
        }
        Ok(Some(_)) => {
            if !encryption.enabled {
                return false;
            }
            encrypted_manifest_probe(path, &encryption.password)
                .map(|parsed| !parsed.entries.is_empty())
                .unwrap_or(false)
        }
        _ => false,
    }
}

/// Fully decrypt (if needed) and parse a manifest file into its entries.
///
/// Dispatches on the detected encryption format:
/// - **DBENC005**: decrypts with the private key from `encryption`
/// - **Other DBENC**: decrypts with the password from `encryption`
/// - **Plaintext**: parsed directly from disk
fn load_manifest_entries(
    manifest_path: &Path,
    encryption: &EncryptionSettings,
    tx: &Sender<WorkerEvent>,
) -> Result<ParsedManifest, String> {
    match detect_format(manifest_path)? {
        Some(DbEncFormat::DbEnc005) => {
            let dk_path = encryption.private_key_path.as_deref().ok_or_else(|| {
                format!(
                    "Manifest {} is PQE-encrypted (DBENC005). Load a private key (.dk) first.",
                    manifest_path.display()
                )
            })?;
            let dk_bytes = load_dk_bytes(dk_path)?;
            let decrypted =
                decrypt_file_pqe_to_temp_with_cancel(manifest_path, &dk_bytes, |_| {}, || false)?;
            let plaintext = std::fs::read(&decrypted.temp_path)
                .map_err(|e| format!("temp read failed: {e}"))?;
            cleanup_temp_file(&decrypted.temp_path);
            let _ = tx.send(WorkerEvent::Progress {
                bytes_delta: decrypted.cipher_bytes,
            });
            parse_sha256_manifest_bytes(manifest_path, &plaintext)
        }
        Some(_) => {
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
        }
        None => parse_sha256_manifest(manifest_path),
    }
}

/// Quick-decrypt a password-protected file and try to parse it as a manifest.
/// Used during the planning phase to identify encrypted manifests by content.
fn encrypted_manifest_probe(manifest_path: &Path, password: &str) -> Result<ParsedManifest, String> {
    let decrypted = decrypt_file(manifest_path, password)?;
    parse_sha256_manifest_bytes(manifest_path, &decrypted.plaintext)
}

/// Quick-decrypt a PQE (DBENC005) file with the given decapsulation key and try
/// to parse it as a manifest.  Used during planning to detect PQE-encrypted manifests.
fn pqe_manifest_probe(path: &Path, dk_bytes: &[u8; PQE_DK_LEN]) -> Result<ParsedManifest, String> {
    let decrypted = decrypt_file_pqe_to_temp_with_cancel(path, dk_bytes, |_| {}, || false)?;
    let plaintext =
        std::fs::read(&decrypted.temp_path).map_err(|e| format!("temp read failed: {e}"))?;
    cleanup_temp_file(&decrypted.temp_path);
    parse_sha256_manifest_bytes(path, &plaintext)
}

// ── Job dispatch ──────────────────────────────────────────────────────────────

/// Dispatch a single job to the appropriate verification handler.
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

/// Verify one SHA-256 manifest entry end-to-end:
///
/// 1. Confirm the target file exists.
/// 2. Decrypt it (if encrypted) and compute its SHA-256.
/// 3. Compare against the expected digest from the manifest.
/// 4. If the digest matches and the file looks like an ISO, also run an ISOB3 check.
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
            detail: if detail.is_empty() {
                "SHA-256 valid".to_string()
            } else {
                "SHA-256 valid".to_string()
            },
            elapsed_secs,
            processed_bytes: verification_input.processed_bytes,
        },
    };

    if let Some(temp_path) = &verification_input.decrypted_path {
        cleanup_temp_file(temp_path);
    }

    JobOutcome::Completed(result)
}

/// Decrypt (if necessary) a target file and compute its plaintext SHA-256.
///
/// Returns a [`VerificationInput`] containing the hash, byte counts, and
/// optionally the path to a temporary decrypted file that must be cleaned up
/// by the caller once the ISOB3 check is also done.
fn build_verification_input(
    target_path: &Path,
    encryption: &EncryptionSettings,
    tx: &Sender<WorkerEvent>,
    cancel: &Arc<AtomicBool>,
) -> Result<VerificationInput, String> {
    match detect_format(target_path)? {
        Some(DbEncFormat::DbEnc005) => {
            let dk_path = encryption.private_key_path.as_deref().ok_or_else(|| {
                format!(
                    "Target {} is PQE-encrypted (DBENC005). Load a private key (.dk) first.",
                    target_path.display()
                )
            })?;
            let dk_bytes = load_dk_bytes(dk_path)?;
            let decrypted = decrypt_file_pqe_to_temp_with_cancel(
                target_path,
                &dk_bytes,
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
        }
        Some(_) => {
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
        }
        None => {
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
}

/// Verify the ISOB3 metadata embedded in a raw disc device or ISO image.
///
/// No manifest is involved — the target is inspected directly for its embedded
/// ISOB3 application-use-area record.
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

/// Outcome of an ISOB3 check against an ISO file or decrypted ISO bytes.
enum IsoVerification {
    /// ISOB3 metadata found and digest matched.
    Valid(String),
    /// ISOB3 metadata not present in the application-use area.
    Missing(String),
    /// ISOB3 metadata found but digest did not match.
    Invalid(String),
    /// File was not an ISO; ISOB3 check skipped.
    Skipped(String),
}

// ── ISOB3 helpers ─────────────────────────────────────────────────────────────

/// Run an ISOB3 check against either an already-decrypted byte slice or a
/// file/device path.  Skips the check if the target doesn't look like an ISO.
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

// ── File-type detection ───────────────────────────────────────────────────────

/// Return `true` if `path` is likely an ISO image or raw optical device.
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

/// Return `true` if `bytes` begins with a valid ISO9660 Primary Volume Descriptor.
fn looks_like_iso_bytes(bytes: &[u8]) -> bool {
    const PVD_OFFSET: usize = 16 * 2048;
    bytes.len() >= PVD_OFFSET + 7
        && bytes[PVD_OFFSET] == 1
        && &bytes[PVD_OFFSET + 1..PVD_OFFSET + 6] == b"CD001"
        && bytes[PVD_OFFSET + 6] == 1
}

// ── Byte estimation for progress bar ─────────────────────────────────────────

/// Estimate the bytes that will be processed when loading a manifest file.
///
/// Encrypted manifests are counted twice (once to decrypt, once to parse).
fn estimated_manifest_bytes(path: &Path, encryption: &EncryptionSettings) -> u64 {
    let file_bytes = file_len(path);
    if encryption.enabled && is_encrypted_file(path).unwrap_or(false) {
        file_bytes.saturating_mul(2)
    } else {
        file_bytes
    }
}

/// Estimate the bytes that will be processed when verifying one manifest target.
///
/// ISO targets cost an extra pass for the ISOB3 check; encrypted files cost an
/// extra pass to decrypt.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbenc::{DbEncFormat, encrypt_file_to_path};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "worker-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    #[test]
    fn discovers_encrypted_manifest_without_manifest_filename() {
        let root = temp_root();
        fs::create_dir_all(&root).expect("create temp root");

        let plaintext_manifest = root.join("manifest.txt");
        fs::write(
            &plaintext_manifest,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef *payload.bin\n",
        )
        .expect("write manifest");

        let encrypted_manifest = root.join("catalog.bin");
        encrypt_file_to_path(
            &plaintext_manifest,
            &encrypted_manifest,
            "secret",
            DbEncFormat::DbEnc003,
        )
        .expect("encrypt manifest");
        fs::remove_file(&plaintext_manifest).expect("remove plaintext manifest");

        let encryption = EncryptionSettings {
            enabled: true,
            password: "secret".to_string(),
            private_key_path: None,
        };
        let manifests = find_sha256_manifests(&root, &encryption);

        assert_eq!(manifests, vec![encrypted_manifest.clone()]);

        let parsed = encrypted_manifest_probe(&encrypted_manifest, &encryption.password)
            .expect("parse encrypted manifest");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].target_display, "payload.bin");

        let _ = fs::remove_file(&encrypted_manifest);
        let _ = fs::remove_dir(&root);
    }
}
