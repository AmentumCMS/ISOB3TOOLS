//! Execution engine: thread-pool dispatch, job runners, and ISOB3 verification.
//!
//! [`run_drive_phase`] is the bounded worker-pool that drives both SHA-256 and
//! embedded-ISOB3 phases.  Individual jobs are routed by [`run_job`] to
//! [`verify_manifest_entry`] or [`verify_embedded_drive`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Instant;

use crossbeam_channel::unbounded;

use crate::blake3iso_core::{
    CheckOutcome, check_iso_bytes, check_iso_with_progress_and_cancel, estimate_iso_bytes,
};
use crate::dbenc::{
    DbEncFormat, cleanup_temp_file, decrypt_file_pqe_to_temp_with_cancel,
    decrypt_file_to_temp_with_cancel, detect_format,
};
use crate::sha256sum::compute_sha256_with_progress_and_cancel;

use super::plan::{file_len, load_dk_bytes};
use super::{EncryptionSettings, VerificationResult, WorkerEvent, WorkerJob};

// ── Internal types ─────────────────────────────────────────────────────────────

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

/// What a single [`WorkerJob`] execution produced.
pub(super) enum JobOutcome {
    Completed(VerificationResult),
    Aborted,
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

// ── Execution engine ───────────────────────────────────────────────────────────

/// Run one phase of work (either SHA or embedded ISOB3 jobs) across all drives.
///
/// Each element of `drive_batches` is the full job list for one drive.  Jobs
/// within a batch run sequentially (so one drive uses at most one worker at a
/// time), but up to `max_workers` drives are processed concurrently.
pub(super) fn run_drive_phase(
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

// ── Job dispatch ───────────────────────────────────────────────────────────────

/// Dispatch a single job to the appropriate verification handler.
pub(super) fn run_job(
    job: WorkerJob,
    tx: &Sender<WorkerEvent>,
    cancel: &Arc<AtomicBool>,
) -> JobOutcome {
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

// ── SHA-256 manifest entry verification ───────────────────────────────────────

/// Verify one SHA-256 manifest entry end-to-end:
///
/// 1. Confirm the target file exists.
/// 2. Decrypt it (if encrypted) and compute its SHA-256.
/// 3. Compare against the expected digest from the manifest.
/// 4. If the digest matches and the file looks like an ISO, also run an ISOB3 check.
#[allow(clippy::too_many_arguments)]
fn verify_manifest_entry(
    media: &crate::media::MediaRoot,
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
        IsoVerification::Skipped(_) => VerificationResult {
            drive_name: media.display_name.clone(),
            check_name: "SHA256".to_string(),
            subject: target_display.to_string(),
            source: manifest_path.display().to_string(),
            ok: true,
            detail: "SHA-256 valid".to_string(),
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

// ── Embedded-ISOB3 drive verification ─────────────────────────────────────────

/// Verify the ISOB3 metadata embedded in a raw disc device or ISO image.
///
/// No manifest is involved — the target is inspected directly for its embedded
/// ISOB3 application-use-area record.
fn verify_embedded_drive(
    media: &crate::media::MediaRoot,
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

// ── ISOB3 helpers ──────────────────────────────────────────────────────────────

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

// ── File-type detection ────────────────────────────────────────────────────────

/// Return `true` if `path` is likely an ISO image or raw optical device.
pub(super) fn looks_like_iso_target(path: &Path) -> bool {
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

// ── Byte estimation ────────────────────────────────────────────────────────────

/// Estimate the total bytes that will be read when verifying a drive source.
///
/// Falls back to [`estimate_iso_bytes`] for raw optical devices where
/// `metadata().len()` returns zero.
pub(super) fn estimate_verification_source_bytes(path: &Path) -> u64 {
    let file_bytes = file_len(path);
    if file_bytes > 0 {
        file_bytes
    } else {
        estimate_iso_bytes(path).unwrap_or(0)
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Return `true` if `err` is the sentinel string used by cancellable operations.
pub(super) fn is_abort_error(err: &str) -> bool {
    err.contains("operation aborted")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_abort_error ────────────────────────────────────────────────────────

    #[test]
    fn abort_error_matches_sentinel() {
        assert!(is_abort_error("operation aborted"));
        assert!(is_abort_error("read failed: operation aborted"));
        assert!(is_abort_error("wrapped: operation aborted by user"));
    }

    #[test]
    fn abort_error_does_not_match_other_errors() {
        assert!(!is_abort_error(""));
        assert!(!is_abort_error("some other error"));
        assert!(!is_abort_error("OPERATION ABORTED")); // case-sensitive
    }

    // ── looks_like_iso_bytes ──────────────────────────────────────────────────

    #[test]
    fn iso_bytes_too_short_returns_false() {
        assert!(!looks_like_iso_bytes(&[]));
        assert!(!looks_like_iso_bytes(&[0u8; 16 * 2048])); // one byte short
        assert!(!looks_like_iso_bytes(&[0u8; 16 * 2048 + 6]));
    }

    #[test]
    fn iso_bytes_valid_pvd_returns_true() {
        let pvd_offset = 16 * 2048;
        let mut data = vec![0u8; pvd_offset + 7];
        data[pvd_offset] = 1;
        data[pvd_offset + 1..pvd_offset + 6].copy_from_slice(b"CD001");
        data[pvd_offset + 6] = 1;
        assert!(looks_like_iso_bytes(&data));
    }

    #[test]
    fn iso_bytes_wrong_magic_returns_false() {
        let pvd_offset = 16 * 2048;
        let mut data = vec![0u8; pvd_offset + 7];
        data[pvd_offset] = 1;
        data[pvd_offset + 1..pvd_offset + 6].copy_from_slice(b"XXXXX");
        data[pvd_offset + 6] = 1;
        assert!(!looks_like_iso_bytes(&data));
    }

    // ── looks_like_iso_target ─────────────────────────────────────────────────

    #[test]
    fn iso_extension_matches() {
        assert!(looks_like_iso_target(Path::new("disc.iso")));
        assert!(looks_like_iso_target(Path::new("disc.ISO")));
        assert!(looks_like_iso_target(Path::new("path/to/image.Iso")));
    }

    #[test]
    fn non_iso_extension_does_not_match() {
        assert!(!looks_like_iso_target(Path::new("archive.zip")));
        assert!(!looks_like_iso_target(Path::new("file.bin")));
        assert!(!looks_like_iso_target(Path::new("noextension")));
    }
}
