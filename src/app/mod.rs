//! ISOB3 Media Verifier — GUI application root.
//!
//! The `App` struct holds all GUI state. Its implementation is split across
//! several submodules to keep each file focused:
//!
//! - [`actions`]  — user-initiated operations (scan, verify, abort)
//! - [`events`]   — background-worker event processing
//! - [`format`]   — text/number formatting helpers
//! - [`keys`]     — key-file path helpers and keypair generation
//! - [`ui`]       — all egui rendering code

pub mod actions;
pub mod events;
pub mod format;
pub mod keys;
pub mod ui;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Instant;

use eframe::egui;

use crate::media::MediaRoot;
use crate::worker::{VerificationResult, WorkerEvent};

// ── Internal drive-selection model ────────────────────────────────────────────

/// One discovered drive plus whether the user has it ticked for verification.
#[derive(Clone)]
pub(in crate::app) struct DriveSelection {
    pub(in crate::app) media: MediaRoot,
    pub(in crate::app) selected: bool,
}

// ── Application state ─────────────────────────────────────────────────────────

/// Root application state.
///
/// All fields are `pub(in crate::app)` so that the `actions`, `events`,
/// `format`, `keys`, and `ui` submodules can access them directly without
/// needing public getters for every field.
pub struct App {
    // ── Worker channel ────────────────────────────────────────────────────────
    pub(in crate::app) tx: Sender<WorkerEvent>,
    pub(in crate::app) rx: Receiver<WorkerEvent>,

    // ── Operation state ───────────────────────────────────────────────────────
    pub(in crate::app) discovering: bool,
    pub(in crate::app) verifying: bool,
    /// Number of parallel workers selected in the UI.
    pub(in crate::app) worker_count: usize,
    /// Actual worker count reported by the worker thread.
    pub(in crate::app) effective_workers: usize,

    // ── Verification counters ─────────────────────────────────────────────────
    pub(in crate::app) total: usize,
    pub(in crate::app) done: usize,
    pub(in crate::app) valid: usize,
    pub(in crate::app) invalid: usize,
    pub(in crate::app) processed_bytes: u64,
    pub(in crate::app) planned_bytes: u64,

    // ── Data ──────────────────────────────────────────────────────────────────
    pub(in crate::app) drives: Vec<DriveSelection>,
    pub(in crate::app) results: Vec<VerificationResult>,

    // ── Log panel ─────────────────────────────────────────────────────────────
    pub(in crate::app) logs: Vec<String>,
    pub(in crate::app) log_autoscroll: bool,
    /// Set to `true` whenever a new log line is pushed; cleared by the log renderer.
    pub(in crate::app) scroll_log_to_bottom: bool,

    // ── Dialog / window flags ─────────────────────────────────────────────────
    pub(in crate::app) show_about: bool,
    pub(in crate::app) drive_details_open: bool,
    pub(in crate::app) drive_details_target: Option<String>,

    // ── Encryption / password ─────────────────────────────────────────────────
    /// Whether the user has ticked "Encrypted files".
    pub(in crate::app) encrypted_mode: bool,
    pub(in crate::app) password_prompt_open: bool,
    pub(in crate::app) password_input: String,

    // ── Abort / lifecycle ─────────────────────────────────────────────────────
    pub(in crate::app) abort_requested: Arc<AtomicBool>,
    pub(in crate::app) abort_confirm_open: bool,
    /// If true, exit the process once the abort completes.
    pub(in crate::app) close_after_abort: bool,
    pub(in crate::app) verification_started_at: Option<Instant>,
    pub(in crate::app) verification_finished_at: Option<Instant>,

    // ── Key management ────────────────────────────────────────────────────────
    /// Path to the `.dk` (decapsulation key) file — typed or auto-discovered.
    pub(in crate::app) private_key_input: String,
    /// Whether the "Generate Keypair" dialog is open.
    pub(in crate::app) keygen_open: bool,
    /// Output-prefix field inside the keygen dialog.
    pub(in crate::app) keygen_prefix_input: String,
    /// Last result from key generation (`Ok(message)` or `Err(message)`).
    pub(in crate::app) keygen_status: Option<Result<String, String>>,
}

// ── Constructor ────────────────────────────────────────────────────────────────

impl App {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();

        // Pre-fill the private key path if `~/.isob3/default.dk` already exists.
        let private_key_input = keys::default_dk_path()
            .filter(|p| p.exists())
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        // Pre-fill the keygen prefix with the default location.
        let keygen_prefix_input = keys::default_key_prefix()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~/.isob3/default".to_string());

        Self {
            tx,
            rx,
            discovering: false,
            verifying: false,
            worker_count: 8,
            effective_workers: 0,
            total: 0,
            done: 0,
            valid: 0,
            invalid: 0,
            processed_bytes: 0,
            planned_bytes: 0,
            drives: Vec::new(),
            results: Vec::new(),
            logs: vec!["Ready.".to_string()],
            log_autoscroll: true,
            scroll_log_to_bottom: true,
            show_about: false,
            drive_details_open: false,
            drive_details_target: None,
            encrypted_mode: false,
            password_prompt_open: false,
            password_input: String::new(),
            abort_requested: Arc::new(AtomicBool::new(false)),
            abort_confirm_open: false,
            close_after_abort: false,
            verification_started_at: None,
            verification_finished_at: None,
            private_key_input,
            keygen_open: false,
            keygen_prefix_input,
            keygen_status: None,
        }
    }
}

// ── eframe integration ────────────────────────────────────────────────────────

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        ui::render(self, ui, frame);
    }
}
