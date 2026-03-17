use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Instant;

use crossbeam_channel::unbounded;
use walkdir::WalkDir;

use crate::blake3iso_core::{check_iso, CheckOutcome};
use crate::isomd5::{has_isomd5sum_implant, verify_isomd5sum, IsoMd5CheckOutcome};
use crate::media::{get_media_roots, MediaKind, MediaRoot};

#[derive(Debug)]
pub enum WorkerEvent {
    MediaFound(Vec<(String, PathBuf)>),
    JobsReady {
        count: usize,
        workers: usize,
    },
    FileResult {
        media_name: String,
        file: PathBuf,
        ok: bool,
        had_embedded_trailer: bool,
        detail: String,
        elapsed_secs: f64,
    },
    Fatal(String),
}

#[derive(Debug, Clone)]
enum WorkerJob {
    Verify { media: MediaRoot, file: PathBuf },
    NoIsoFound { media: MediaRoot },
}

fn find_iso_files(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("iso"))
                .unwrap_or(false)
        })
        .map(|e| e.path().to_path_buf())
        .collect()
}

fn verify_one_target(media: &MediaRoot, file: &Path) -> WorkerEvent {
    let start = Instant::now();

    let result = match check_iso(file) {
        Ok(CheckOutcome::Valid { detail, .. }) => (true, true, detail),
        Ok(CheckOutcome::Invalid { detail, .. }) => (false, true, detail),
        Ok(CheckOutcome::Missing) => match has_isomd5sum_implant(file) {
            Ok(true) => match verify_isomd5sum(file) {
                Ok(IsoMd5CheckOutcome::Valid { digest_hex }) => {
                    (true, false, format!("ISOMD5 valid ({digest_hex})"))
                }
                Ok(IsoMd5CheckOutcome::Invalid(msg)) => {
                    (false, false, format!("ISOMD5 invalid\n{msg}"))
                }
                Ok(IsoMd5CheckOutcome::ToolMissing) => {
                    (true, false, "ISOMD5 present (tool missing)".to_string())
                }
                Err(e) => (false, false, format!("ISOMD5 error: {e}")),
            },
            _ => (false, false, "No ISOB3 or ISOMD5 metadata".to_string()),
        },
        Err(e) => (false, false, format!("Error: {e}")),
    };

    WorkerEvent::FileResult {
        media_name: media.display_name.clone(),
        file: file.to_path_buf(),
        ok: result.0,
        had_embedded_trailer: result.1,
        detail: result.2,
        elapsed_secs: start.elapsed().as_secs_f64(),
    }
}

fn run_job(job: WorkerJob) -> WorkerEvent {
    match job {
        WorkerJob::Verify { media, file } => verify_one_target(&media, &file),
        WorkerJob::NoIsoFound { media } => WorkerEvent::FileResult {
            media_name: media.display_name.clone(),
            file: media.path.clone(),
            ok: false,
            had_embedded_trailer: false,
            detail: "No ISO files found.".to_string(),
            elapsed_secs: 0.0,
        },
    }
}

pub fn scan_worker(tx: Sender<WorkerEvent>, max_workers: usize) -> Result<(), String> {
    let media = get_media_roots()?;

    tx.send(WorkerEvent::MediaFound(
        media.iter()
            .map(|m| (m.display_name.clone(), m.path.clone()))
            .collect(),
    ))
        .map_err(|e| e.to_string())?;

    let mut jobs = Vec::new();

    for m in &media {
        match m.kind {
            MediaKind::RawDevice => jobs.push(WorkerJob::Verify {
                media: m.clone(),
                file: m.path.clone(),
            }),
            MediaKind::ScanRoot => {
                let files = find_iso_files(&m.path);
                if files.is_empty() {
                    jobs.push(WorkerJob::NoIsoFound { media: m.clone() });
                } else {
                    for f in files {
                        jobs.push(WorkerJob::Verify {
                            media: m.clone(),
                            file: f,
                        });
                    }
                }
            }
        }
    }

    let workers = max_workers.min(jobs.len().max(1));

    tx.send(WorkerEvent::JobsReady {
        count: jobs.len(),
        workers,
    })
        .map_err(|e| e.to_string())?;

    let (job_tx, job_rx) = unbounded();

    for _ in 0..workers {
        let rx = job_rx.clone();
        let tx_clone = tx.clone();

        thread::spawn(move || {
            while let Ok(job) = rx.recv() {
                let _ = tx_clone.send(run_job(job));
            }
        });
    }

    for j in jobs {
        job_tx.send(j).map_err(|e| e.to_string())?;
    }

    Ok(())
}