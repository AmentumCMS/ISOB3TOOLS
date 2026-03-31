use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::{collections::HashMap, iter};

use eframe::egui;

use crate::media::MediaRoot;
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

    show_about: bool,
    drive_details_open: bool,
    drive_details_target: Option<String>,
    encrypted_mode: bool,
    password_prompt_open: bool,
    password_input: String,
    abort_requested: Arc<AtomicBool>,
    abort_confirm_open: bool,
    close_after_abort: bool,
}

impl App {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();

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
            show_about: false,
            drive_details_open: false,
            drive_details_target: None,
            encrypted_mode: false,
            password_prompt_open: false,
            password_input: String::new(),
            abort_requested: Arc::new(AtomicBool::new(false)),
            abort_confirm_open: false,
            close_after_abort: false,
        }
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
    }

    fn log_line(&mut self, text: impl Into<String>) {
        self.logs.push(text.into());
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
        self.log_line(format!(
            "Starting verification across {} selected drive(s)...",
            selected.len()
        ));

        let tx = self.tx.clone();
        let max_workers = self.worker_count;
        let encryption = EncryptionSettings {
            enabled: self.encrypted_mode,
            password: self.password_input.clone(),
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
        self.log_line("Abort requested. Stopping verification...");
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
                    }
                }
                WorkerEvent::Aborted => {
                    self.verifying = false;
                    self.log_line("Verification aborted.");
                }
                WorkerEvent::Log(line) => self.log_line(line),
                WorkerEvent::Fatal(err) => {
                    self.discovering = false;
                    self.verifying = false;
                    self.log_line(format!("ERROR: {err}"));
                }
            }
        }
    }

    fn progress_text(&self) -> String {
        let avg_secs = if self.done > 0 {
            self.results.iter().map(|row| row.elapsed_secs).sum::<f64>() / self.done as f64
        } else {
            0.0
        };

        let throughput = if self.results.is_empty() {
            0.0
        } else {
            let total_secs = self.results.iter().map(|row| row.elapsed_secs).sum::<f64>();
            if total_secs > 0.0 {
                self.processed_bytes as f64 / total_secs
            } else {
                0.0
            }
        };

        if self.verifying {
            format!(
                "{} of {} checks complete | {} of {} est. processed | Avg/check {:.2}s | Throughput {}/s",
                self.done,
                self.total,
                human_bytes(self.processed_bytes),
                human_bytes(self.planned_bytes),
                avg_secs,
                human_bytes(throughput as u64)
            )
        } else if self.total > 0 {
            format!(
                "{} checks complete | {} processed | Avg/check {:.2}s | Throughput {}/s",
                self.done,
                human_bytes(self.processed_bytes),
                avg_secs,
                human_bytes(throughput as u64)
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
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.input(|i| i.viewport().close_requested()) && self.verifying {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.abort_confirm_open = true;
            self.close_after_abort = true;
        }

        self.process_events();

        if self.close_after_abort && !self.verifying {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
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

        egui::CentralPanel::default().show(ctx, |ui| {
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
                            ui.strong("Time");
                            ui.strong("Detail");
                            ui.end_row();

                            for row in &self.results {
                                ui.label(&row.drive_name);
                                ui.label(&row.check_name);
                                ui.label(&row.subject);
                                ui.label(&row.source);

                                let color = if row.ok {
                                    egui::Color32::GREEN
                                } else {
                                    egui::Color32::RED
                                };
                                ui.colored_label(color, if row.ok { "PASS" } else { "FAIL" });

                                ui.label(format!("{:.2}s", row.elapsed_secs));
                                ui.label(&row.detail);
                                ui.end_row();
                            }
                        });
                });

            ui.separator();
            ui.heading("Log");
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.logs {
                        ui.label(line);
                    }
                });
        });

        if self.show_about {
            egui::Window::new("About Drive Integrity Verifier")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.heading("Drive Integrity Verifier");
                    ui.separator();
                    ui.label("A desktop tool for scanning drives, discovering SHA-256 manifests, validating referenced files, and checking embedded ISOB3 metadata on ISO media.");
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
                .show(ctx, |ui| {
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
                                ui.strong("Time");
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
                .show(ctx, |ui| {
                    ui.label(
                        "Enter the shared password used for DBENC001 AES-256 encrypted files.",
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
            egui::Window::new("Abort Verification")
                .open(&mut is_open)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Verification is still running.");
                    ui.label("Abort verification and close the application?");
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Abort").clicked() {
                            let close_after_abort = self.close_after_abort;
                            self.abort_confirm_open = false;
                            self.request_abort(close_after_abort);
                        }
                        if ui.button("Continue").clicked() {
                            self.abort_confirm_open = false;
                            self.close_after_abort = false;
                        }
                    });
                });
            self.abort_confirm_open = is_open;
        }

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
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
