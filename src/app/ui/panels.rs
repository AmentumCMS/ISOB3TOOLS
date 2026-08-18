//! Central-area panels: drive selection, verification results, and log.

use std::collections::HashMap;

use eframe::egui;

use crate::app::{App, format::human_bytes};

/// Scroll behaviour for panels: scrollbar + mouse-wheel, but NOT drag.
///
/// Drag-to-scroll is disabled so a ScrollArea touching a panel boundary does
/// not swallow the drag event meant for the panel's resize handle. (Desktop
/// users scroll with the wheel or scrollbar, so this costs nothing.)
fn no_drag_scroll() -> egui::scroll_area::ScrollSource {
    egui::scroll_area::ScrollSource {
        scroll_bar: true,
        drag: egui::scroll_area::DragScroll::Never,
        mouse_wheel: true,
    }
}

// ── Drive-selection panel ──────────────────────────────────────────────────────

/// Render the drive-selection grid (fills the remaining central area).
pub fn show_drives(app: &mut App, ui: &mut egui::Ui) {
    ui.heading("Drive Selection");
    ui.separator();

    if app.drives.is_empty() {
        ui.label("Run `Scan Drives` to discover removable and optical drives.");
        // Fill the rest of the panel so the resizable panel keeps its height
        // instead of collapsing to this short message (which would pin its
        // stored size to min_size — even after drives are later scanned).
        ui.allocate_space(ui.available_size());
        return;
    }

    // Select All / Clear buttons
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                !app.discovering && !app.verifying,
                egui::Button::new("Select All"),
            )
            .clicked()
        {
            for drive in &mut app.drives {
                drive.selected = true;
            }
        }

        if ui
            .add_enabled(
                !app.discovering && !app.verifying,
                egui::Button::new("Clear"),
            )
            .clicked()
        {
            for drive in &mut app.drives {
                drive.selected = false;
            }
        }
    });

    // Pre-compute pass/fail counts so the grid loop can borrow `app.drives` mutably.
    let drive_counts: HashMap<String, (usize, usize)> = app
        .drives
        .iter()
        .map(|d| {
            (
                d.media.display_name.clone(),
                app.drive_result_counts(&d.media.display_name),
            )
        })
        .collect();

    egui::ScrollArea::vertical()
        .id_salt("drives_scroll")
        .scroll_source(no_drag_scroll())
        // Fill the panel's full height so the resizable panel keeps its size
        // instead of collapsing to its content height (which pins it to min_size).
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("drive_grid")
                .striped(true)
                .min_col_width(120.0)
                .show(ui, |ui| {
                    // Header row
                    ui.strong("Use");
                    ui.strong("Drive");
                    ui.strong("Search Root");
                    ui.strong("Embedded ISOB3");
                    ui.strong("Checks");
                    ui.end_row();

                    for drive in &mut app.drives {
                        // Tick-box
                        ui.add_enabled(
                            !app.discovering && !app.verifying,
                            egui::Checkbox::without_text(&mut drive.selected),
                        );

                        // Drive name — click to open the details window
                        let (passed, failed) = drive_counts
                            .get(&drive.media.display_name)
                            .copied()
                            .unwrap_or((0, 0));

                        if ui.link(&drive.media.display_name).clicked() {
                            app.drive_details_target = Some(drive.media.display_name.clone());
                            app.drive_details_open = true;
                        }

                        ui.label(drive.media.search_root.display().to_string());

                        // Show embedded-target path or "n/a"
                        ui.label(
                            drive
                                .media
                                .embedded_target
                                .as_ref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "n/a".to_string()),
                        );

                        ui.label(format!("{passed} pass / {failed} fail"));
                        ui.end_row();
                    }
                });
        });
}

// ── Verification results panel ─────────────────────────────────────────────────

/// Render the verification-results grid.
pub fn show_results(app: &mut App, ui: &mut egui::Ui) {
    ui.heading("Verification Results");
    ui.separator();

    egui::ScrollArea::vertical()
        .id_salt("results_scroll")
        .scroll_source(no_drag_scroll())
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("results_grid")
                .striped(true)
                .min_col_width(80.0)
                .show(ui, |ui| {
                    // Header row
                    ui.strong("Drive");
                    ui.strong("Check");
                    ui.strong("Subject");
                    ui.strong("Source");
                    ui.strong("Status");
                    ui.strong("Check Time");
                    ui.strong("Summary");
                    ui.end_row();

                    for row in &app.results {
                        // Skip sub-checks that don't map to a top-level check name.
                        let Some(main_check_name) = App::main_result_check_name(&row.check_name)
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
                        ui.label(App::main_result_detail(&row.detail));
                        ui.end_row();
                    }
                });
        });
}

// ── Log panel ──────────────────────────────────────────────────────────────────

/// Render the log panel with optional auto-scroll.
pub fn show_log(app: &mut App, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.heading("Log");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.checkbox(&mut app.log_autoscroll, "Autoscroll");
        });
    });

    egui::ScrollArea::vertical()
        .id_salt("log_scroll")
        .scroll_source(no_drag_scroll())
        .auto_shrink([false, false])
        .stick_to_bottom(app.log_autoscroll)
        .show(ui, |ui| {
            for line in &app.logs {
                ui.label(line);
            }
        });

    // Clear the "please scroll to bottom" flag after rendering.
    app.scroll_log_to_bottom = false;
}

// ── Drive-detail popup ─────────────────────────────────────────────────────────

/// Render the drive-detail window (launched when a drive name is clicked).
pub fn show_drive_details(app: &mut App, ctx: &egui::Context) {
    if !app.drive_details_open {
        return;
    }

    let mut is_open = app.drive_details_open;
    let screen = ctx.content_rect();

    egui::Window::new("Drive Verification Details")
        .open(&mut is_open)
        .resizable(true)
        .default_size([screen.width() * 0.8, screen.height() * 0.6])
        .min_size([360.0, 220.0])
        .max_size([screen.width(), screen.height()])
        .show(ctx, |ui| {
            let Some(drive_name) = app.drive_details_target.as_deref() else {
                ui.label("No drive selected.");
                return;
            };

            ui.heading(drive_name);
            ui.separator();

            let matching: Vec<_> = app
                .results
                .iter()
                .filter(|r| r.drive_name == drive_name)
                .collect();

            if matching.is_empty() {
                ui.label("No verification results for this drive yet.");
                return;
            }

            // `both()` + `auto_shrink(false)` lets the scroll area fill the
            // window so it can actually be resized. A Window can never shrink
            // below its content's min size, and a default ScrollArea reports its
            // full content as that min size — so the window grows to fit the
            // grid instead of scrolling, and can't be made smaller. Filling the
            // window bounds the scroll viewport: the window now resizes freely
            // and wide/tall content scrolls within it.
            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .show(ui, |ui| {
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

                            for row in matching {
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

    app.drive_details_open = is_open;
    if !app.drive_details_open {
        app.drive_details_target = None;
    }
}
