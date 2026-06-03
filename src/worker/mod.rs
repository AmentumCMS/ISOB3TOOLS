//! Background worker threads: drive discovery and multi-drive verification.
//!
//! Verification runs in two phases:
//!
//! 1. **Planning** — each selected drive is walked to find SHA-256 manifests and
//!    detect embedded ISOB3 targets.  All planned work is reported via
//!    [`WorkerEvent::JobsReady`] before any hashing starts.
//!
//! 2. **Execution** — SHA-256 manifest jobs run first (concurrent across drives),
//!    then embedded-ISOB3 drive jobs.  Each phase uses [`execute::run_drive_phase`]
//!    with a bounded worker pool.  Results flow back through an
//!    [`mpsc::Sender<WorkerEvent>`].
//!
//! ## Module layout
//!
//! | Submodule       | Responsibility                                            |
//! |-----------------|-----------------------------------------------------------|
//! | [`plan`]        | Manifest discovery, loading, byte-estimation helpers      |
//! | [`execute`]     | Thread-pool engine, job dispatch, SHA/ISOB3 verification  |
//! | (this file)     | Public types, `discover_drives_worker`, `verify_drives_worker` |

pub(crate) mod execute;
pub(crate) mod plan;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;

use crate::media::{MediaRoot, get_media_roots};

// ── Public types ───────────────────────────────────────────────────────────────

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
    /// The run was canceled via the abort flag.
    Aborted,
    /// Informational log message.
    Log(String),
    /// Unrecoverable worker error (planning or channel failure).
    Fatal(String),
}

// ── Internal job types ─────────────────────────────────────────────────────────

/// A single unit of verification work dispatched to a worker thread.
#[derive(Debug, Clone)]
pub(super) enum WorkerJob {
    /// Verify one entry from an SHA-256 manifest file.
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

/// Byte-count accumulators built during the planning phase for the progress-bar estimate.
#[derive(Default)]
struct PlanningTotals {
    manifest_bytes: u64,
    target_bytes: u64,
    embedded_bytes: u64,
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

        let manifests = plan::find_sha256_manifests(&drive.search_root, &encryption);
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
                .saturating_add(plan::estimated_manifest_bytes(&manifest_path, &encryption));

            match plan::load_manifest_entries(&manifest_path, &encryption, &tx) {
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
                                .saturating_add(plan::estimated_manifest_target_bytes(
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
                .saturating_add(plan::estimated_embedded_bytes(target_path));

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

    execute::run_drive_phase(
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

    execute::run_drive_phase(
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
