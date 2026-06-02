use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};
use std::{collections::HashMap, iter};

use eframe::egui;

use crate::media::MediaRoot;
use crate::dbenc::{PQE_DK_LEN, PQE_EK_LEN, generate_pqe_keypair};
use crate::worker::{
    EncryptionSettings, VerificationResult, WorkerEvent, discover_drives_worker,
    verify_drives_worker,
};

#[derive(Clone)]
struct DriveSelection {
    media: MediaRoot,
    selected: bool,
}

pub struct App {
    tx: Sender<WorkerEvent>,
    rx: Receiver<WorkerEvent>,

    discovering: bool,
    verifying: bool,
    worker_count: usize,
    effective_workers: usize,

    total: usize,
    done: usize,
    valid: usize,
    invalid: usize,
    processed_bytes: u64,
    planned_bytes: u64,

    drives: Vec<DriveSelection>,
    results: Vec<VerificationResult>,
    logs: Vec<String>,
    log_autoscroll: bool,
    scroll_log_to_bottom: bool,

    show_about: bool,
    drive_details_open: bool,
    drive_details_target: Option<String>,
    encrypted_mode: bool,
    password_prompt_open: bool,
    password_input: String,
    abort_requested: Arc<AtomicBool>,
    abort_confirm_open: bool,
    close_after_abort: bool,
    verification_started_at: Option<Instant>,
    verification_finished_at: Option<Instant>,

    // Key management
    private_key_input: String,      // path to .dk file (typed or auto-discovered)
    keygen_open: bool,
    keygen_prefix_input: String,
    keygen_status: Option<Result<String, String>>,
}

impl App {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();

        // Pre-fill private key path if the default key exists on disk.
        let private_key_input = default_dk_path()
            .filter(|p| p.exists())
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        let keygen_prefix_input = default_key_prefix()
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

    fn reset_event_channel(&mut self) {
        let (tx, rx) = mpsc::channel();
        self.tx = tx;
        self.rx = rx;
    }

    fn reset_results(&mut self) {
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

    fn log_line(&mut self, text: impl Into<String>) {
        self.logs.push(text.into());
        self.scroll_log_to_bottom = true;
    }

    fn selected_drives(&self) -> Vec<MediaRoot> {
        self.drives
            .iter()
            .filter(|drive| drive.selected)
            .map(|drive| drive.media.clone())
            .collect()
    }

    fn selected_count(&self) -> usize {
        self.drives.iter().filter(|drive| drive.selected).count()
    }

    fn summary_text(&self) -> String {
        if self.discovering {
            "Scanning drives...".to_string()
        } else if self.verifying {
            format!(
                "Verifying {}/{} checks | Data: {} / {} est. | Passed: {} | Failed: {} | Workers: {}",
                self.done,
                self.total,
                human_bytes(self.processed_bytes),
                human_bytes(self.planned_bytes),
                self.valid,
                self.invalid,
                self.effective_workers
            )
        } else if self.total > 0 {
            format!(
                "Done. {}/{} checks | Data: {} | Passed: {} | Failed: {}",
                self.done,
                self.total,
                human_bytes(self.processed_bytes),
                self.valid,
                self.invalid
            )
        } else if self.drives.is_empty() {
            "No drives discovered.".to_string()
        } else {
            format!(
                "{} drive(s) discovered, {} selected.",
                self.drives.len(),
                self.selected_count()
            )
        }
    }

    fn start_drive_scan(&mut self) {
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

    fn start_verification(&mut self) {
        if self.discovering || self.verifying {
            return;
        }

        let selected = self.selected_drives();
        if selected.is_empty() {
            self.log_line("Select at least one drive before starting verification.");
            return;
        }

        if self.encrypted_mode && self.password_input.is_empty() {
            self.password_prompt_open = true;
            return;
        }

        self.verifying = true;
        self.reset_results();
        self.verification_started_at = Some(Instant::now());
        self.verification_finished_at = None;
        self.log_line(format!(
            "Starting verification across {} selected drive(s)...",
            selected.len()
        ));

        let tx = self.tx.clone();
        let max_workers = self.worker_count;
        let private_key_path = resolve_private_key_path(&self.private_key_input);
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

    fn request_abort(&mut self, close_after_abort: bool) {
        if !self.verifying {
            return;
        }

        self.abort_requested.store(true, Ordering::Relaxed);
        self.close_after_abort = close_after_abort;
        self.verifying = false;
        self.effective_workers = 0;
        self.verification_finished_at = Some(Instant::now());
        self.reset_event_channel();
        self.log_line("Verification aborted.");
    }

    fn process_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                WorkerEvent::DrivesFound(drives) => {
                    self.discovering = false;
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
                        let mut discovered = Vec::new();
                        for drive in &self.drives {
                            discovered.push(format!(
                                "  - {} [{}]",
                                drive.media.display_name,
                                drive.media.search_root.display()
                            ));
                        }
                        for line in discovered {
                            self.log_line(line);
                        }
                    }
                }
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
                WorkerEvent::Progress { bytes_delta } => {
                    self.processed_bytes = self.processed_bytes.saturating_add(bytes_delta);
                }
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

                    if self.total > 0 && self.done >= self.total {
                        self.verifying = false;
                        self.verification_finished_at = Some(Instant::now());
                    }
                }
                WorkerEvent::Aborted => {
                    self.verifying = false;
                    self.verification_finished_at = Some(Instant::now());
                    self.log_line("Verification aborted.");
                }
                WorkerEvent::Log(line) => self.log_line(line),
                WorkerEvent::Fatal(err) => {
                    self.discovering = false;
                    self.verifying = false;
                    self.verification_finished_at = Some(Instant::now());
                    self.log_line(format!("ERROR: {err}"));
                }
            }
        }
    }

    fn total_elapsed(&self) -> Option<Duration> {
        let started = self.verification_started_at?;
        let end = self.verification_finished_at.unwrap_or_else(Instant::now);
        Some(end.saturating_duration_since(started))
    }

    fn progress_text(&self) -> String {
        let total_result_secs = self.results.iter().map(|row| row.elapsed_secs).sum::<f64>();
        let avg_secs = if self.done > 0 {
            total_result_secs / self.done as f64
        } else {
            0.0
        };

        let total_elapsed_secs = self
            .total_elapsed()
            .map(|elapsed| elapsed.as_secs_f64())
            .unwrap_or(0.0);

        let live_throughput = if total_elapsed_secs > 0.0 {
            self.processed_bytes as f64 / total_elapsed_secs
        } else {
            0.0
        };

        let completed_throughput = if total_result_secs > 0.0 {
            self.processed_bytes as f64 / total_result_secs
        } else {
            0.0
        };

        if self.verifying {
            format!(
                "{} of {} checks complete | {} of {} est. processed | Total elapsed {:.1}s | Avg/check {:.2}s | Throughput {}/s",
                self.done,
                self.total,
                human_bytes(self.processed_bytes),
                human_bytes(self.planned_bytes),
                total_elapsed_secs,
                avg_secs,
                human_bytes(live_throughput as u64)
            )
        } else if self.total > 0 {
            format!(
                "{} checks complete | {} processed | Total elapsed {:.1}s | Avg/check {:.2}s | Throughput {}/s",
                self.done,
                human_bytes(self.processed_bytes),
                total_elapsed_secs,
                avg_secs,
                human_bytes(completed_throughput as u64)
            )
        } else {
            "No verification in progress.".to_string()
        }
    }

    fn drive_result_counts(&self, drive_name: &str) -> (usize, usize) {
        let mut passed = 0usize;
        let mut failed = 0usize;

        for result in self
            .results
            .iter()
            .filter(|row| row.drive_name == drive_name)
        {
            if result.ok {
                passed += 1;
            } else {
                failed += 1;
            }
        }

        (passed, failed)
    }

    fn main_result_summary(detail: &str) -> &str {
        let first_line = detail.lines().next().unwrap_or(detail);

        if first_line.starts_with("SHA-256 valid") {
            "SHA-256 valid"
        } else if first_line.starts_with("SHA-256 mismatch") {
            "SHA-256 mismatch"
        } else if first_line.starts_with("ISOB3 valid") {
            "ISOB3 valid"
        } else if first_line.starts_with("ISOB3 mismatch") {
            "ISOB3 mismatch"
        } else {
            first_line
        }
    }

    fn main_result_check_name(check_name: &str) -> Option<&str> {
        if check_name.contains("ISOMD5") {
            Some("ISOMD5")
        } else if check_name.contains("ISOB3") {
            Some("ISOB3")
        } else {
            None
        }
    }

    fn main_result_detail(detail: &str) -> &str {
        for line in detail.lines() {
            if line.starts_with("ISOB3 ") || line.starts_with("ISOMD5 ") {
                return Self::main_result_summary(line);
            }
        }

        Self::main_result_summary(detail)
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if ctx.input(|i| i.viewport().close_requested()) && self.verifying {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.abort_confirm_open = true;
            self.close_after_abort = true;
        }

        self.process_events();

        if self.close_after_abort && !self.verifying {
            std::process::exit(0);
        }

        egui::Panel::top("top_panel").show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !self.discovering && !self.verifying,
                        egui::Button::new("1. Scan Drives"),
                    )
                    .clicked()
                {
                    self.start_drive_scan();
                }

                if ui
                    .add_enabled(
                        !self.discovering && !self.verifying && self.selected_count() > 0,
                        egui::Button::new("2. Verify Selected"),
                    )
                    .clicked()
                {
                    self.start_verification();
                }

                if ui
                    .add_enabled(self.verifying, egui::Button::new("Abort"))
                    .clicked()
                {
                    self.abort_confirm_open = true;
                    self.close_after_abort = false;
                }

                ui.label("Max workers:");
                egui::ComboBox::from_id_salt("worker_count")
                    .selected_text(self.worker_count.to_string())
                    .show_ui(ui, |ui| {
                        for n in [1, 2, 3, 4, 6, 8, 12, 16] {
                            ui.selectable_value(&mut self.worker_count, n, n.to_string());
                        }
                    });

                ui.separator();
                ui.checkbox(&mut self.encrypted_mode, "Encrypted files");
                if self.encrypted_mode {
                    let masked = if self.password_input.is_empty() {
                        "No password set".to_string()
                    } else {
                        format!(
                            "Password set ({} chars)",
                            self.password_input.chars().count()
                        )
                    };
                    if ui.button(masked).clicked() {
                        self.password_prompt_open = true;
                    }
                }

                ui.separator();
                ui.label(self.summary_text());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("About").clicked() {
                        self.show_about = true;
                    }
                });
            });

            // Key management row
            ui.horizontal(|ui| {
                ui.label("🔑 Private key (.dk):");
                let key_hint = if self.private_key_input.is_empty() {
                    "path/to/key.dk (or leave blank to auto-discover ~/.isob3/default.dk)"
                } else {
                    ""
                };
                ui.add(
                    egui::TextEdit::singleline(&mut self.private_key_input)
                        .hint_text(key_hint)
                        .desired_width(340.0),
                );

                // Show whether the path resolves to an existing file
                if let Some(dk) = resolve_private_key_path(&self.private_key_input) {
                    if dk.exists() {
                        ui.colored_label(egui::Color32::GREEN, "✔ key found");
                    } else {
                        ui.colored_label(egui::Color32::RED, "✘ not found");
                    }
                } else {
                    ui.colored_label(egui::Color32::GRAY, "(none)");
                }

                ui.separator();
                if ui.button("Generate Keypair…").clicked() {
                    self.keygen_status = None;
                    self.keygen_open = true;
                }
            });

            let progress = if self.total == 0 {
                0.0
            } else if self.verifying && self.planned_bytes > 0 {
                (self.processed_bytes as f32 / self.planned_bytes as f32).clamp(0.0, 1.0)
            } else {
                self.done as f32 / self.total as f32
            };
            ui.add(egui::ProgressBar::new(progress).show_percentage());
            ui.label(self.progress_text());
        });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.heading("Drive Selection");
            ui.separator();

            if self.drives.is_empty() {
                ui.label("Run `Scan Drives` to discover removable and optical drives.");
            } else {
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !self.discovering && !self.verifying,
                            egui::Button::new("Select All"),
                        )
                        .clicked()
                    {
                        for drive in &mut self.drives {
                            drive.selected = true;
                        }
                    }

                    if ui
                        .add_enabled(
                            !self.discovering && !self.verifying,
                            egui::Button::new("Clear"),
                        )
                        .clicked()
                    {
                        for drive in &mut self.drives {
                            drive.selected = false;
                        }
                    }
                });

                egui::Grid::new("drive_grid")
                    .striped(true)
                    .min_col_width(120.0)
                    .show(ui, |ui| {
                        let drive_counts: HashMap<String, (usize, usize)> = self
                            .drives
                            .iter()
                            .map(|drive| {
                                (
                                    drive.media.display_name.clone(),
                                    self.drive_result_counts(&drive.media.display_name),
                                )
                            })
                            .chain(iter::empty())
                            .collect();

                        ui.strong("Use");
                        ui.strong("Drive");
                        ui.strong("Search Root");
                        ui.strong("Embedded ISOB3");
                        ui.strong("Checks");
                        ui.end_row();

                        for drive in &mut self.drives {
                            ui.add_enabled(
                                !self.discovering && !self.verifying,
                                egui::Checkbox::without_text(&mut drive.selected),
                            );
                            let (passed, failed) = drive_counts
                                .get(&drive.media.display_name)
                                .copied()
                                .unwrap_or((0, 0));
                            if ui.link(&drive.media.display_name).clicked() {
                                self.drive_details_target = Some(drive.media.display_name.clone());
                                self.drive_details_open = true;
                            }
                            ui.label(drive.media.search_root.display().to_string());
                            ui.label(
                                drive
                                    .media
                                    .embedded_target
                                    .as_ref()
                                    .map(|path| path.display().to_string())
                                    .unwrap_or_else(|| "n/a".to_string()),
                            );
                            ui.label(format!("{} pass / {} fail", passed, failed));
                            ui.end_row();
                        }
                    });
            }

            ui.add_space(10.0);
            ui.heading("Verification Results");
            ui.separator();

            egui::ScrollArea::vertical()
                .max_height(300.0)
                .show(ui, |ui| {
                    egui::Grid::new("results_grid")
                        .striped(true)
                        .min_col_width(80.0)
                        .show(ui, |ui| {
                            ui.strong("Drive");
                            ui.strong("Check");
                            ui.strong("Subject");
                            ui.strong("Source");
                            ui.strong("Status");
                            ui.strong("Check Time");
                            ui.strong("Summary");
                            ui.end_row();

                            for row in &self.results {
                                let Some(main_check_name) =
                                    Self::main_result_check_name(&row.check_name)
                                else {
                                    continue;
                                };

                                ui.label(&row.drive_name);
                                ui.label(main_check_name);
                                ui.label(&row.subject);
                                ui.label(&row.source);

                                let color = if row.ok {
                                    egui::Color32::GREEN
                                } else {
                                    egui::Color32::RED
                                };
                                ui.colored_label(color, if row.ok { "PASS" } else { "FAIL" });

                                ui.label(format!("{:.2}s", row.elapsed_secs));
                                ui.label(Self::main_result_detail(&row.detail));
                                ui.end_row();
                            }
                        });
                });

            ui.separator();
            ui.horizontal(|ui| {
                ui.heading("Log");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.checkbox(&mut self.log_autoscroll, "Autoscroll");
                });
            });
            let should_scroll_log = self.log_autoscroll && self.scroll_log_to_bottom;
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.logs {
                        ui.label(line);
                    }
                    if should_scroll_log {
                        ui.scroll_to_cursor(Some(egui::Align::BOTTOM));
                    }
                });
            if self.log_autoscroll {
                self.scroll_log_to_bottom = false;
            }
        });

        if self.show_about {
            egui::Window::new("About ISOB3 Media Verifier")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(&ctx, |ui| {
                    ui.heading("ISOB3 Media Verifier");
                    ui.separator();

                    ui.label("A desktop tool for verifying ISO media using embedded ISOB3 (BLAKE3) metadata, with SHA-256 manifest validation and ISOMD5 fallback support.");

                    ui.add_space(8.0);

                    ui.label("Features:");
                    ui.label("Verifies raw optical media and discovered ISO files");
                    ui.label("Validates SHA-256 manifests found on selected drives");
                    ui.label("Supports ISOB3 metadata in the ISO9660 application area");
                    ui.label("Falls back to ISOMD5 when ISOB3 metadata is not present");
                    ui.label("Runs verification across drives with one active worker per drive");

                    ui.add_space(10.0);
                    ui.separator();

                    ui.heading("Credits");

                    ui.add_space(6.0);

                    ui.label("ISOMD5 concept & tooling:");
                    ui.horizontal(|ui| {
                        ui.label("Inspiration from isomd5sum");
                        ui.hyperlink_to("GitHub", "https://github.com/rhinstaller/isomd5sum");
                    });

                    ui.add_space(4.0);

                    ui.label("Windows port of isomd5sum:");
                    ui.horizontal(|ui| {
                        ui.label("John Pappas");
                        ui.hyperlink_to("GitHub", "https://github.com/thepappas");
                    });

                    ui.add_space(4.0);

                    ui.label("Hashing algorithm:");
                    ui.horizontal(|ui| {
                        ui.label("BLAKE3");
                        ui.hyperlink_to("Project", "https://github.com/BLAKE3-team/BLAKE3");
                    });

                    ui.add_space(10.0);
                    ui.separator();

                    ui.horizontal(|ui| {
                        ui.label("Created by William Kronfeld");
                        ui.hyperlink_to("LinkedIn", "https://www.linkedin.com/in/william-kronfeld/");
                    });

                    ui.add_space(12.0);

                    if ui.button("Close").clicked() {
                        self.show_about = false;
                    }
                });
        }

        if self.drive_details_open {
            let mut is_open = self.drive_details_open;
            egui::Window::new("Drive Verification Details")
                .open(&mut is_open)
                .resizable(true)
                .default_size([980.0, 420.0])
                .show(&ctx, |ui| {
                    let Some(drive_name) = self.drive_details_target.as_deref() else {
                        ui.label("No drive selected.");
                        return;
                    };

                    ui.heading(drive_name);
                    ui.separator();

                    let matching_results: Vec<&VerificationResult> = self
                        .results
                        .iter()
                        .filter(|row| row.drive_name == drive_name)
                        .collect();

                    if matching_results.is_empty() {
                        ui.label("No verification results for this drive yet.");
                        return;
                    }

                    egui::ScrollArea::vertical().show(ui, |ui| {
                        egui::Grid::new("drive_detail_grid")
                            .striped(true)
                            .min_col_width(90.0)
                            .show(ui, |ui| {
                                ui.strong("Check");
                                ui.strong("Subject");
                                ui.strong("Source");
                                ui.strong("Status");
                                ui.strong("Bytes");
                                ui.strong("Check Time");
                                ui.strong("Detail");
                                ui.end_row();

                                for row in matching_results {
                                    ui.label(&row.check_name);
                                    ui.label(&row.subject);
                                    ui.label(&row.source);
                                    ui.colored_label(
                                        if row.ok {
                                            egui::Color32::GREEN
                                        } else {
                                            egui::Color32::RED
                                        },
                                        if row.ok { "PASS" } else { "FAIL" },
                                    );
                                    ui.label(human_bytes(row.processed_bytes));
                                    ui.label(format!("{:.2}s", row.elapsed_secs));
                                    ui.label(&row.detail);
                                    ui.end_row();
                                }
                            });
                    });
                });
            self.drive_details_open = is_open;
            if !self.drive_details_open {
                self.drive_details_target = None;
            }
        }

        if self.password_prompt_open {
            let mut is_open = self.password_prompt_open;
            egui::Window::new("Encrypted File Password")
                .open(&mut is_open)
                .collapsible(false)
                .resizable(false)
                .default_width(420.0)
                .show(&ctx, |ui| {
                    ui.label(
                        "Enter the password used to decrypt DBENC001–DBENC004 encrypted files.",
                    );
                    ui.add_space(8.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.password_input)
                            .password(true)
                            .desired_width(360.0),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Use Password").clicked() {
                            self.password_prompt_open = false;
                        }
                        if ui.button("Clear").clicked() {
                            self.password_input.clear();
                        }
                    });
                });
            self.password_prompt_open = is_open;
        }

        if self.abort_confirm_open {
            let mut is_open = self.abort_confirm_open;
            let mut abort_clicked = false;
            let mut continue_clicked = false;
            egui::Window::new("Abort Verification")
                .open(&mut is_open)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(&ctx, |ui| {
                    ui.label("Verification is still running.");
                    ui.label("Abort verification and close the application?");
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Abort").clicked() {
                            abort_clicked = true;
                        }
                        if ui.button("Continue").clicked() {
                            continue_clicked = true;
                        }
                    });
                });

            if abort_clicked {
                let close_after_abort = self.close_after_abort;
                is_open = false;
                self.request_abort(close_after_abort);
            }

            if continue_clicked {
                is_open = false;
                self.close_after_abort = false;
            }

            self.abort_confirm_open = is_open;
        }

        if self.keygen_open {
            let mut generate_clicked = false;
            let mut close_clicked = false;
            egui::Window::new("Generate ML-KEM-768 Keypair")
                .collapsible(false)
                .resizable(false)
                .default_width(480.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(&ctx, |ui| {
                    ui.label("Generates a post-quantum (ML-KEM-768) keypair:");
                    ui.label("  • .ek — encapsulation key (public, 1184 bytes) — share with disc producers");
                    ui.label("  • .dk — decapsulation key (private, 64 bytes)  — keep secret, needed to verify");
                    ui.add_space(8.0);

                    ui.horizontal(|ui| {
                        ui.label("Output prefix:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.keygen_prefix_input)
                                .desired_width(300.0),
                        );
                    });
                    ui.label(
                        egui::RichText::new(format!(
                            "Will write: {}.ek  and  {}.dk",
                            self.keygen_prefix_input, self.keygen_prefix_input
                        ))
                        .weak(),
                    );

                    ui.add_space(8.0);

                    if let Some(ref status) = self.keygen_status {
                        match status {
                            Ok(msg) => {
                                ui.colored_label(egui::Color32::GREEN, msg);
                            }
                            Err(msg) => {
                                ui.colored_label(egui::Color32::RED, format!("Error: {msg}"));
                            }
                        }
                        ui.add_space(4.0);
                    }

                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                !self.keygen_prefix_input.is_empty(),
                                egui::Button::new("Generate"),
                            )
                            .clicked()
                        {
                            generate_clicked = true;
                        }
                        if ui.button("Close").clicked() {
                            close_clicked = true;
                        }
                    });
                });

            if generate_clicked {
                self.keygen_status = Some(run_keygen_gui(&self.keygen_prefix_input));
                // Auto-load the new .dk if no key is set yet
                if let Some(Ok(_)) = &self.keygen_status {
                    if self.private_key_input.is_empty() {
                        self.private_key_input = format!("{}.dk", self.keygen_prefix_input);
                    }
                }
            }

            if close_clicked {
                self.keygen_open = false;
            }
        }

        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

/// Returns the default `~/.isob3` directory for the current platform.
fn default_key_dir() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    let home = std::env::var("USERPROFILE").ok()?;
    #[cfg(not(windows))]
    let home = std::env::var("HOME").ok()?;
    Some(std::path::PathBuf::from(home).join(".isob3"))
}

/// Default key prefix: `~/.isob3/default`
fn default_key_prefix() -> Option<std::path::PathBuf> {
    Some(default_key_dir()?.join("default"))
}

/// Default private key path: `~/.isob3/default.dk`
fn default_dk_path() -> Option<std::path::PathBuf> {
    Some(default_key_prefix()?.with_extension("dk"))
}

/// Resolve the private key path from user input, falling back to the default.
/// Returns `None` if neither the input nor the default produces a usable path.
fn resolve_private_key_path(input: &str) -> Option<std::path::PathBuf> {
    if !input.trim().is_empty() {
        return Some(std::path::PathBuf::from(input.trim()));
    }
    default_dk_path()
}

/// Run keygen synchronously (ML-KEM key generation is fast — microseconds).
/// Writes `{prefix}.ek` and `{prefix}.dk`, returns a human-readable status message.
fn run_keygen_gui(prefix: &str) -> Result<String, String> {
    let prefix = prefix.trim();
    if prefix.is_empty() {
        return Err("Output prefix must not be empty.".to_string());
    }

    let ek_path = std::path::PathBuf::from(format!("{prefix}.ek"));
    let dk_path = std::path::PathBuf::from(format!("{prefix}.dk"));

    // Create parent directory if needed
    if let Some(parent) = ek_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create directory failed: {e}"))?;
        }
    }

    let (ek_bytes, dk_bytes) = generate_pqe_keypair()?;

    std::fs::write(&ek_path, &ek_bytes)
        .map_err(|e| format!("write {}: {e}", ek_path.display()))?;
    std::fs::write(&dk_path, &dk_bytes)
        .map_err(|e| format!("write {}: {e}", dk_path.display()))?;

    Ok(format!(
        "✔ Keypair written.\n  Public  (.ek): {}  [{} bytes]\n  Private (.dk): {}  [{} bytes]",
        ek_path.display(),
        PQE_EK_LEN,
        dk_path.display(),
        PQE_DK_LEN,
    ))
}

fn human_bytes(num_bytes: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = num_bytes as f64;

    for unit in units {
        if value < 1024.0 || unit == "TiB" {
            return format!("{value:.2} {unit}");
        }
        value /= 1024.0;
    }

    format!("{num_bytes} B")
}
