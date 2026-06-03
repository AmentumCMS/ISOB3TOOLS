//! User-initiated operations: drive scan, verification, abort, and helpers.

use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;

use super::App;
use crate::media::MediaRoot;
use crate::worker::{EncryptionSettings, WorkerEvent, discover_drives_worker,
                   verify_drives_worker};

use super::keys::resolve_private_key_path;

impl App {
    // ── Channel management ────────────────────────────────────────────────────

    /// Replace the worker channel with a fresh pair.
    ///
    /// Called after an abort so that leftover messages from the old worker
    /// thread are discarded rather than processed by the next run.
    pub(in crate::app) fn reset_event_channel(&mut self) {
        let (tx, rx) = mpsc::channel();
        self.tx = tx;
        self.rx = rx;
    }

    // ── Counter / state reset ─────────────────────────────────────────────────

    /// Clear all verification counters and result state.
    ///
    /// Called before starting a new scan or verification run so the UI shows
    /// fresh progress from zero.
    pub(in crate::app) fn reset_results(&mut self) {
        self.total = 0;
        self.done = 0;
        self.valid = 0;
        self.invalid = 0;
        self.processed_bytes = 0;
        self.planned_bytes = 0;
        self.effective_workers = 0;
        self.results.clear();
        self.logs.clear();
        self.abort_requested.store(false, Ordering::Relaxed);
        self.verification_started_at = None;
        self.verification_finished_at = None;
    }

    // ── Log ───────────────────────────────────────────────────────────────────

    /// Append one line to the log and request a scroll-to-bottom on next frame.
    pub(in crate::app) fn log_line(&mut self, text: impl Into<String>) {
        self.logs.push(text.into());
        self.scroll_log_to_bottom = true;
    }

    // ── Drive helpers ─────────────────────────────────────────────────────────

    /// Returns the drives the user currently has ticked.
    pub(in crate::app) fn selected_drives(&self) -> Vec<MediaRoot> {
        self.drives
            .iter()
            .filter(|d| d.selected)
            .map(|d| d.media.clone())
            .collect()
    }

    /// How many drives are currently ticked.
    pub(in crate::app) fn selected_count(&self) -> usize {
        self.drives.iter().filter(|d| d.selected).count()
    }

    // ── Scan ──────────────────────────────────────────────────────────────────

    /// Begin a background drive-discovery pass.
    ///
    /// Ignored if a scan or verification is already in progress.
    pub(in crate::app) fn start_drive_scan(&mut self) {
        if self.discovering || self.verifying {
            return;
        }

        self.discovering = true;
        self.drives.clear();
        self.reset_results();
        self.log_line("Scanning drives...");

        let tx = self.tx.clone();
        thread::spawn(move || {
            if let Err(err) = discover_drives_worker(tx.clone()) {
                let _ = tx.send(WorkerEvent::Fatal(err));
            }
        });
    }

    // ── Verification ─────────────────────────────────────────────────────────

    /// Begin a background verification run across all selected drives.
    ///
    /// If encrypted mode is on and neither a private key path nor a password
    /// has been provided, opens the password prompt dialog instead.
    pub(in crate::app) fn start_verification(&mut self) {
        if self.discovering || self.verifying {
            return;
        }

        let selected = self.selected_drives();
        if selected.is_empty() {
            self.log_line("Select at least one drive before starting verification.");
            return;
        }

        // Resolve which credential we have available.
        let resolved_key = resolve_private_key_path(&self.private_key_input)
            .filter(|p| p.exists());
        let has_key = resolved_key.is_some();

        // When encrypted mode is active, we need either a private key or a password.
        if self.encrypted_mode && !has_key && self.password_input.is_empty() {
            self.password_prompt_open = true;
            return;
        }

        self.verifying = true;
        self.reset_results();
        self.verification_started_at = Some(std::time::Instant::now());
        self.verification_finished_at = None;
        self.log_line(format!(
            "Starting verification across {} selected drive(s)...",
            selected.len()
        ));

        let tx = self.tx.clone();
        let max_workers = self.worker_count;
        let private_key_path = resolved_key;
        let encryption = EncryptionSettings {
            enabled: self.encrypted_mode,
            password: self.password_input.clone(),
            private_key_path,
        };
        let cancel = self.abort_requested.clone();

        thread::spawn(move || {
            if let Err(err) =
                verify_drives_worker(tx.clone(), selected, max_workers, encryption, cancel)
            {
                let _ = tx.send(WorkerEvent::Fatal(err));
            }
        });
    }

    // ── Abort ─────────────────────────────────────────────────────────────────

    /// Signal the running workers to stop and mark verification as finished.
    ///
    /// `close_after_abort`: if `true`, the process exits once the abort is
    /// acknowledged (used when the user closes the window mid-run).
    pub(in crate::app) fn request_abort(&mut self, close_after_abort: bool) {
        if !self.verifying {
            return;
        }

        self.abort_requested.store(true, Ordering::Relaxed);
        self.close_after_abort = close_after_abort;
        self.verifying = false;
        self.effective_workers = 0;
        self.verification_finished_at = Some(std::time::Instant::now());
        // Drop the old channel so leftover worker messages are discarded.
        self.reset_event_channel();
        self.log_line("Verification aborted.");
    }

}
