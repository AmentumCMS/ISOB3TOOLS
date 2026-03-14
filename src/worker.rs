use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Instant;

use crossbeam_channel::unbounded;

use crate::isomd5::{has_isomd5sum_implant, verify_isomd5sum, IsoMd5CheckOutcome};
use crate::iso_scan::find_iso_files;
use crate::media::get_media_roots;
use crate::trailer::{verify_isoblake3, VerifyOutcome};

#[derive(Debug)]
pub enum WorkerEvent {
    MediaFound(Vec<PathBuf>),
    MediaScanned {
        media: PathBuf,
        count: usize,
    },
    JobsReady {
        count: usize,
        workers: usize,
    },
    FileResult {
        media: PathBuf,
        file: PathBuf,
        ok: bool,
        had_embedded_trailer: bool,
        detail: String,
        elapsed_secs: f64,
    },
    Fatal(String),
}

pub fn verify_one_file(media_root: &Path, iso: &Path) -> WorkerEvent {
    let started = Instant::now();

    let mut event = match verify_isoblake3(iso) {
        Ok(VerifyOutcome::Valid { digest_hex }) => WorkerEvent::FileResult {
            media: media_root.to_path_buf(),
            file: iso.to_path_buf(),
            ok: true,
            had_embedded_trailer: true,
            detail: format!("ISOB3 valid ({digest_hex})"),
            elapsed_secs: 0.0,
        },
        Ok(VerifyOutcome::Mismatch { expected, actual }) => WorkerEvent::FileResult {
            media: media_root.to_path_buf(),
            file: iso.to_path_buf(),
            ok: false,
            had_embedded_trailer: true,
            detail: format!("ISOB3 mismatch\nExpected: {expected}\nActual:   {actual}"),
            elapsed_secs: 0.0,
        },
        Ok(VerifyOutcome::MissingTrailer) => match has_isomd5sum_implant(iso) {
            Ok(true) => match verify_isomd5sum(iso) {
                Ok(IsoMd5CheckOutcome::Valid { digest_hex }) => WorkerEvent::FileResult {
                    media: media_root.to_path_buf(),
                    file: iso.to_path_buf(),
                    ok: true,
                    had_embedded_trailer: false,
                    detail: format!("ISOMD5 valid ({digest_hex})"),
                    elapsed_secs: 0.0,
                },
                Ok(IsoMd5CheckOutcome::Invalid(msg)) => WorkerEvent::FileResult {
                    media: media_root.to_path_buf(),
                    file: iso.to_path_buf(),
                    ok: false,
                    had_embedded_trailer: false,
                    detail: format!("ISOMD5 invalid\n{msg}"),
                    elapsed_secs: 0.0,
                },
                Ok(IsoMd5CheckOutcome::ToolMissing) => WorkerEvent::FileResult {
                    media: media_root.to_path_buf(),
                    file: iso.to_path_buf(),
                    ok: true,
                    had_embedded_trailer: false,
                    detail:
                    "ISOMD5 implant present (checkisomd5.exe not found, not fully verified)"
                        .to_string(),
                    elapsed_secs: 0.0,
                },
                Err(e) => WorkerEvent::FileResult {
                    media: media_root.to_path_buf(),
                    file: iso.to_path_buf(),
                    ok: false,
                    had_embedded_trailer: false,
                    detail: format!("Error checking isomd5sum: {e}"),
                    elapsed_secs: 0.0,
                },
            },
            Ok(false) => WorkerEvent::FileResult {
                media: media_root.to_path_buf(),
                file: iso.to_path_buf(),
                ok: false,
                had_embedded_trailer: false,
                detail: "No ISOB3 trailer or isomd5sum implant".to_string(),
                elapsed_secs: 0.0,
            },
            Err(e) => WorkerEvent::FileResult {
                media: media_root.to_path_buf(),
                file: iso.to_path_buf(),
                ok: false,
                had_embedded_trailer: false,
                detail: format!("Error checking isomd5sum presence: {e}"),
                elapsed_secs: 0.0,
            },
        },
        Err(e) => WorkerEvent::FileResult {
            media: media_root.to_path_buf(),
            file: iso.to_path_buf(),
            ok: false,
            had_embedded_trailer: false,
            detail: format!("Error: {e}"),
            elapsed_secs: 0.0,
        },
    };

    let elapsed_secs = started.elapsed().as_secs_f64();

    if let WorkerEvent::FileResult { elapsed_secs: e, .. } = &mut event {
        *e = elapsed_secs;
    }

    event
}

pub fn scan_worker(tx: Sender<WorkerEvent>, max_workers: usize) -> Result<(), String> {
    let media_roots = get_media_roots()?;
    tx.send(WorkerEvent::MediaFound(media_roots.clone()))
        .map_err(|e| e.to_string())?;

    let mut media_jobs = Vec::<(PathBuf, Vec<PathBuf>)>::new();
    let mut total_jobs = 0usize;

    for media_root in &media_roots {
        let iso_files = find_iso_files(media_root);

        tx.send(WorkerEvent::MediaScanned {
            media: media_root.clone(),
            count: iso_files.len(),
        })
            .map_err(|e| e.to_string())?;

        if !iso_files.is_empty() {
            total_jobs += iso_files.len();
            media_jobs.push((media_root.clone(), iso_files));
        }
    }

    if media_jobs.is_empty() {
        tx.send(WorkerEvent::JobsReady {
            count: 0,
            workers: 0,
        })
            .map_err(|e| e.to_string())?;
        return Ok(());
    }

    let desired_workers = max_workers.max(1);
    let effective_workers = desired_workers.min(media_jobs.len());

    tx.send(WorkerEvent::JobsReady {
        count: total_jobs,
        workers: effective_workers,
    })
        .map_err(|e| e.to_string())?;

    let (group_tx, group_rx) = unbounded::<(PathBuf, Vec<PathBuf>)>();
    let mut handles = Vec::new();

    for _ in 0..effective_workers {
        let group_rx = group_rx.clone();
        let tx_clone = tx.clone();

        let handle = thread::spawn(move || {
            while let Ok((media_root, iso_files)) = group_rx.recv() {
                for iso in iso_files {
                    let result = verify_one_file(&media_root, &iso);
                    let _ = tx_clone.send(result);
                }
            }
        });

        handles.push(handle);
    }

    for group in media_jobs {
        group_tx.send(group).map_err(|e| e.to_string())?;
    }
    drop(group_tx);

    for handle in handles {
        let _ = handle.join();
    }

    Ok(())
}
