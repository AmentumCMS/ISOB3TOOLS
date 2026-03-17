use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use eframe::egui;

use crate::worker::{scan_worker, WorkerEvent};

#[derive(Clone)]
struct ResultRow {
    media: String,
    file: String,
    status: String,
    elapsed: String,
    detail: String,
    ok: bool,
}

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

    show_about: bool,
}

impl App {
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
            show_about: false,
        }
    }

    fn reset_results(&mut self) {
        self.total = 0;
        self.done = 0;
        self.valid = 0;
        self.invalid = 0;
        self.embedded_count = 0;
        self.effective_workers = 0;
        self.results.clear();
        self.logs.clear();
        self.logs.push("Scanning media devices...".to_string());
    }

    fn log_line(&mut self, text: impl Into<String>) {
        self.logs.push(text.into());
    }

    fn active_workers(&self) -> usize {
        if !self.scanning || self.total == 0 {
            0
        } else {
            let remaining = self.total.saturating_sub(self.done);
            remaining.min(self.effective_workers)
        }
    }

    fn summary_text(&self) -> String {
        if self.scanning && self.total == 0 {
            "Scanning media devices...".to_string()
        } else if self.total == 0 {
            "No media devices found.".to_string()
        } else if self.scanning {
            format!(
                "Checked {}/{} | Valid: {} | Invalid: {} | Active workers: {}",
                self.done,
                self.total,
                self.valid,
                self.invalid,
                self.active_workers()
            )
        } else {
            format!(
                "Done. Checked {}/{} | Valid: {} | Invalid: {} | Workers used: {}",
                self.done, self.total, self.valid, self.invalid, self.effective_workers
            )
        }
    }

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

    fn process_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                WorkerEvent::MediaFound(media_items) => {
                    if media_items.is_empty() {
                        self.log_line("No mounted removable or optical media found.");
                    } else {
                        self.log_line("Detected media devices:");
                        for (display_name, path) in media_items {
                            self.log_line(format!("  - {} [{}]", display_name, path.display()));
                        }
                    }
                }
                WorkerEvent::JobsReady { count, workers } => {
                    self.total = count;
                    self.effective_workers = workers;
                    self.log_line(format!("Queued {count} target(s) for verification."));
                    self.log_line(format!("Using {workers} worker(s)."));

                    if count == 0 {
                        self.scanning = false;
                    }
                }
                WorkerEvent::FileResult {
                    media_name,
                    file,
                    ok,
                    had_embedded_trailer,
                    detail,
                    elapsed_secs,
                } => {
                    self.done += 1;

                    if had_embedded_trailer {
                        self.embedded_count += 1;
                    }

                    if ok {
                        self.valid += 1;
                    } else {
                        self.invalid += 1;
                    }

                    let status = if ok {
                        if detail.starts_with("ISOMD5 valid") {
                            "VALID-ISOMD5".to_string()
                        } else if detail.contains("ISOB3") || detail.contains("BLAKE3") {
                            "VALID-ISOB3".to_string()
                        } else {
                            "VALID".to_string()
                        }
                    } else if detail.starts_with("ISOMD5 invalid") {
                        "INVALID-ISOMD5".to_string()
                    } else if detail.contains("ISOB3") || detail.contains("BLAKE3") {
                        "INVALID-ISOB3".to_string()
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
                        media: media_name,
                        file: file.display().to_string(),
                        status,
                        elapsed: format!("{elapsed_secs:.2}s"),
                        detail,
                        ok,
                    });

                    if self.total > 0 && self.done == self.total {
                        self.scanning = false;
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
        self.process_events();

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.scanning, egui::Button::new("Scan Media"))
                    .clicked()
                {
                    self.start_scan();
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
                ui.label(self.summary_text());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("About").clicked() {
                        self.show_about = true;
                    }
                });
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

            egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                egui::Grid::new("results_grid")
                    .striped(true)
                    .min_col_width(80.0)
                    .show(ui, |ui| {
                        ui.strong("Media");
                        ui.strong("Path");
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

            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                for line in &self.logs {
                    ui.label(line);
                }
            });
        });

        if self.show_about {
            egui::Window::new("About ISOB3 Media Verifier")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.heading("ISOB3 Media Verifier");
                    ui.separator();

                    ui.label("A desktop tool for verifying ISO media using embedded ISOB3 (BLAKE3) metadata, with ISOMD5 fallback support.");

                    ui.add_space(8.0);

                    ui.label("Features:");
                    ui.label("• Verifies raw optical media and discovered ISO files");
                    ui.label("• Supports ISOB3 metadata in the ISO9660 application area");
                    ui.label("• Falls back to ISOMD5 when ISOB3 metadata is not present");
                    ui.label("• Multi-worker scanning for fast verification");

                    ui.add_space(10.0);
                    ui.separator();

                    ui.heading("Credits");

                    ui.add_space(6.0);

                    ui.label("• ISOMD5 concept & tooling:");
                    ui.horizontal(|ui| {
                        ui.label("  Inspiration from isomd5sum");
                        ui.hyperlink_to("GitHub", "https://github.com/rhinstaller/isomd5sum");
                    });

                    ui.add_space(4.0);

                    ui.label("• Windows port of isomd5sum:");
                    ui.horizontal(|ui| {
                        ui.label("  John Pappas");
                        ui.hyperlink_to("GitHub", "https://github.com/thepappas");
                    });

                    ui.add_space(4.0);

                    ui.label("• Hashing algorithm:");
                    ui.horizontal(|ui| {
                        ui.label("  BLAKE3");
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

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}