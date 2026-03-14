use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use eframe::egui;

use crate::trailer::embed_isob3_trailer;
use crate::worker::{scan_worker, WorkerEvent};

/// One row in the on-screen results table.
#[derive(Clone)]
struct ResultRow {
    media: String,
    file: String,
    status: String,
    elapsed: String,
    detail: String,
    ok: bool,
}

/// Main GUI application state.
///
/// This owns:
/// - the worker communication channel
/// - scan/progress counters
/// - the results grid data
/// - the log output
/// - the "embed missing trailers" prompt state
pub struct App {
    tx: Sender<WorkerEvent>,
    rx: Receiver<WorkerEvent>,

    scanning: bool,
    worker_count: usize,
    effective_workers: usize,

    total: usize,
    done: usize,
    valid: usize,
    invalid: usize,
    embedded_count: usize,

    results: Vec<ResultRow>,
    logs: Vec<String>,

    missing_trailer_files: Vec<PathBuf>,
    show_embed_prompt: bool,
    embedding_now: bool,
}

impl App {
    /// Create a new application instance and its worker event channel.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();

        Self {
            tx,
            rx,
            scanning: false,
            worker_count: 8,
            effective_workers: 0,
            total: 0,
            done: 0,
            valid: 0,
            invalid: 0,
            embedded_count: 0,
            results: Vec::new(),
            logs: vec!["Ready.".to_string()],
            missing_trailer_files: Vec::new(),
            show_embed_prompt: false,
            embedding_now: false,
        }
    }

    /// Clear all scan-related state before starting a new scan.
    fn reset_results(&mut self) {
        self.total = 0;
        self.done = 0;
        self.valid = 0;
        self.invalid = 0;
        self.embedded_count = 0;
        self.effective_workers = 0;
        self.missing_trailer_files.clear();
        self.show_embed_prompt = false;
        self.embedding_now = false;
        self.results.clear();
        self.logs.clear();
        self.logs.push("Scanning...".to_string());
    }

    /// Append a line to the log panel.
    fn log_line(&mut self, text: impl Into<String>) {
        self.logs.push(text.into());
    }

    /// Human-readable summary shown in the top status bar.
    fn summary_text(&self) -> String {
        if self.scanning && self.total == 0 {
            "Scanning...".to_string()
        } else if self.total == 0 {
            "No ISO files found.".to_string()
        } else if self.scanning {
            format!(
                "Checked {}/{} | Valid: {} | Invalid: {} | Active workers: {}",
                self.done, self.total, self.valid, self.invalid, self.effective_workers
            )
        } else {
            format!(
                "Done. Checked {}/{} | Valid: {} | Invalid: {} | Workers used: {}",
                self.done, self.total, self.valid, self.invalid, self.effective_workers
            )
        }
    }

    /// Start a background scan thread if one is not already running.
    ///
    /// The actual work is done in `scan_worker`, which sends events back
    /// to this UI thread through the channel.
    fn start_scan(&mut self) {
        if self.scanning {
            return;
        }

        self.scanning = true;
        self.reset_results();

        let tx = self.tx.clone();
        let max_workers = self.worker_count;

        thread::spawn(move || {
            if let Err(e) = scan_worker(tx.clone(), max_workers) {
                let _ = tx.send(WorkerEvent::Fatal(e));
            }
        });
    }

    /// Drain all pending worker events and update UI state.
    ///
    /// This keeps the GUI responsive while background verification runs.
    fn process_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                WorkerEvent::MediaFound(roots) => {
                    if roots.is_empty() {
                        self.log_line("No mounted removable or optical media found.");
                    } else {
                        self.log_line("Detected media:");
                        for r in roots {
                            self.log_line(format!("  - {}", r.display()));
                        }
                    }
                }
                WorkerEvent::MediaScanned { media, count } => {
                    self.log_line(format!("Scanned {} -> found {} ISO(s)", media.display(), count));
                }
                WorkerEvent::JobsReady { count, workers } => {
                    self.total = count;
                    self.effective_workers = workers;
                    self.log_line(format!("Found {count} ISO file(s)."));
                    self.log_line(format!("Using {workers} worker(s)."));

                    if count == 0 {
                        self.scanning = false;
                    }
                }
                WorkerEvent::FileResult {
                    media,
                    file,
                    ok,
                    had_embedded_trailer,
                    detail,
                    elapsed_secs,
                } => {
                    self.done += 1;

                    // Keep track of how many files already had ISOB3 embedded.
                    if had_embedded_trailer {
                        self.embedded_count += 1;
                    // If the file has neither ISOB3 nor isomd5sum, queue it for
                    // the optional "embed trailer now" prompt at the end.
                    } else if detail == "No ISOB3 trailer or isomd5sum implant" {
                        self.missing_trailer_files.push(file.clone());
                    }

                    if ok {
                        self.valid += 1;
                    } else {
                        self.invalid += 1;
                    }

                    // Pick a more specific status label for the results grid.
                    let status = if ok {
                        if detail.starts_with("ISOB3 valid") {
                            "VALID-ISOB3".to_string()
                        } else if detail.starts_with("ISOMD5 valid") {
                            "VALID-ISOMD5".to_string()
                        } else {
                            "VALID".to_string()
                        }
                    } else {
                        "INVALID".to_string()
                    };

                    self.log_line(format!(
                        "Verified {} in {:.2}s -> {}",
                        file.display(),
                        elapsed_secs,
                        status
                    ));

                    self.results.push(ResultRow {
                        media: media.display().to_string(),
                        file: file.display().to_string(),
                        status,
                        elapsed: format!("{elapsed_secs:.2}s"),
                        detail,
                        ok,
                    });

                    // When all files are done, stop scanning and optionally show
                    // the prompt for embedding missing trailers.
                    if self.total > 0 && self.done == self.total {
                        self.scanning = false;

                        if !self.missing_trailer_files.is_empty() {
                            self.show_embed_prompt = true;
                        }
                    }
                }
                WorkerEvent::Fatal(err) => {
                    self.scanning = false;
                    self.log_line(format!("ERROR: {err}"));
                }
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Pull in any new background worker messages each frame.
        self.process_events();

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                // Prevent starting a second scan while one is already running.
                if ui
                    .add_enabled(!self.scanning, egui::Button::new("Scan Media"))
                    .clicked()
                {
                    self.start_scan();
                }

                // This is a cap, not a guarantee. The worker layer decides the
                // actual number used based on how many media roots have ISOs.
                ui.label("Max workers:");
                egui::ComboBox::from_id_salt("worker_count")
                    .selected_text(self.worker_count.to_string())
                    .show_ui(ui, |ui| {
                        for n in [1, 2, 3, 4, 6, 8, 12, 16] {
                            ui.selectable_value(&mut self.worker_count, n, n.to_string());
                        }
                    });

                ui.separator();
                ui.label(self.summary_text());
            });

            let progress = if self.total == 0 {
                0.0
            } else {
                self.done as f32 / self.total as f32
            };
            ui.add(egui::ProgressBar::new(progress).show_percentage());
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Results");
            ui.separator();

            // Results grid showing one row per verified ISO.
            egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                egui::Grid::new("results_grid")
                    .striped(true)
                    .min_col_width(80.0)
                    .show(ui, |ui| {
                        ui.strong("Media");
                        ui.strong("ISO File");
                        ui.strong("Status");
                        ui.strong("Time");
                        ui.strong("Detail");
                        ui.end_row();

                        for row in &self.results {
                            ui.label(&row.media);
                            ui.label(&row.file);

                            let color = if row.ok {
                                egui::Color32::GREEN
                            } else {
                                egui::Color32::RED
                            };
                            ui.colored_label(color, &row.status);

                            ui.label(&row.elapsed);
                            ui.label(&row.detail);
                            ui.end_row();
                        }
                    });
            });

            ui.separator();
            ui.heading("Log");

            // Log area sticks to the bottom so the most recent entries remain visible.
            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                for line in &self.logs {
                    ui.label(line);
                }
            });
        });

        // Post-scan prompt for adding ISOB3 trailers to files that had neither
        // an ISOB3 trailer nor an isomd5sum implant.
        if self.show_embed_prompt {
            egui::Window::new("Some ISO files are missing BLAKE3 trailers")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("One or more scanned ISO files do not contain an ISOB3 BLAKE3 trailer.");
                    ui.label("These files also do not appear to contain an isomd5sum implant.");
                    ui.label("Do you want to embed BLAKE3 trailers into those ISO files now?");
                    ui.label("Warning: this will modify those ISO files by appending an ISOB3 trailer.");
                    ui.add_space(8.0);

                    if self.embedding_now {
                        ui.label("Embedding trailers...");
                    } else {
                        ui.horizontal(|ui| {
                            if ui.button("Yes, embed").clicked() {
                                self.embedding_now = true;

                                let files = self.missing_trailer_files.clone();

                                for path in files {
                                    match embed_isob3_trailer(&path) {
                                        Ok(digest) => {
                                            self.log_line(format!(
                                                "Embedded ISOB3 trailer into {} ({})",
                                                path.display(),
                                                digest
                                            ));
                                        }
                                        Err(e) => {
                                            self.log_line(format!(
                                                "Failed to embed trailer into {}: {}",
                                                path.display(),
                                                e
                                            ));
                                        }
                                    }
                                }

                                self.log_line(
                                    "Embedding complete. Re-scan to verify the newly embedded trailers.",
                                );

                                self.embedding_now = false;
                                self.show_embed_prompt = false;
                            }

                            if ui.button("No").clicked() {
                                self.show_embed_prompt = false;
                            }
                        });
                    }
                });
        }

        // Keep repainting while background work is active and to keep the log/progress fresh.
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}
