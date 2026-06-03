//! Background-worker event processing.
//!
//! The worker threads send [`WorkerEvent`] messages through an `mpsc` channel.
//! [`App::process_events`] drains that channel every frame and updates the
//! application state accordingly.

use std::time::Instant;

use super::{App, DriveSelection};
use crate::worker::WorkerEvent;

impl App {
    /// Drain all pending worker events and update state.
    ///
    /// Called once per egui frame before any rendering happens.
    pub(in crate::app) fn process_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                // ── Drive discovery ───────────────────────────────────────────
                WorkerEvent::DrivesFound(drives) => {
                    self.discovering = false;

                    // All newly-discovered drives start selected.
                    self.drives = drives
                        .into_iter()
                        .map(|media| DriveSelection {
                            media,
                            selected: true,
                        })
                        .collect();

                    if self.drives.is_empty() {
                        self.log_line("No removable or optical drives were found.");
                    } else {
                        self.log_line("Discovered drives:");
                        // Collect first to avoid borrowing `self` while iterating.
                        let lines: Vec<String> = self
                            .drives
                            .iter()
                            .map(|d| {
                                format!(
                                    "  - {} [{}]",
                                    d.media.display_name,
                                    d.media.search_root.display()
                                )
                            })
                            .collect();
                        for line in lines {
                            self.log_line(line);
                        }
                    }
                }

                // ── Jobs queued ───────────────────────────────────────────────
                WorkerEvent::JobsReady {
                    count,
                    workers,
                    total_bytes,
                } => {
                    self.total = count;
                    self.effective_workers = workers;
                    self.planned_bytes = total_bytes;
                    self.log_line(format!("Queued {count} verification job(s)."));
                    self.log_line(format!("Using {workers} worker(s)."));

                    if count == 0 {
                        self.verifying = false;
                        self.verification_finished_at = Some(Instant::now());
                        self.log_line("No SHA-256 work was found on the selected drives.");
                    }
                }

                // ── Per-chunk byte progress ───────────────────────────────────
                WorkerEvent::Progress { bytes_delta } => {
                    self.processed_bytes = self.processed_bytes.saturating_add(bytes_delta);
                }

                // ── One file verified ─────────────────────────────────────────
                WorkerEvent::VerificationResult(result) => {
                    self.done += 1;
                    if result.ok {
                        self.valid += 1;
                    } else {
                        self.invalid += 1;
                    }

                    self.log_line(format!(
                        "{} | {} | {}",
                        result.drive_name, result.check_name, result.subject
                    ));

                    self.results.push(result);

                    // Mark the run finished when the last result arrives.
                    if self.total > 0 && self.done >= self.total {
                        self.verifying = false;
                        self.verification_finished_at = Some(Instant::now());
                    }
                }

                // ── Worker aborted ────────────────────────────────────────────
                WorkerEvent::Aborted => {
                    self.verifying = false;
                    self.verification_finished_at = Some(Instant::now());
                    self.log_line("Verification aborted.");
                }

                // ── Log line from worker ──────────────────────────────────────
                WorkerEvent::Log(line) => self.log_line(line),

                // ── Fatal worker error ────────────────────────────────────────
                WorkerEvent::Fatal(err) => {
                    self.discovering = false;
                    self.verifying = false;
                    self.verification_finished_at = Some(Instant::now());
                    self.log_line(format!("ERROR: {err}"));
                }
            }
        }
    }
}
