//! egui rendering — entry point.
//!
//! [`render`] is called once per frame from the [`eframe::App`] impl in
//! `super::mod.rs`.  It delegates to the three submodules:
//!
//! - [`toolbar`]  — top panel: action buttons, encryption options, key row
//! - [`panels`]   — central panel: drives list, results table, log
//! - [`dialogs`]  — floating windows: about, drive details, password, keygen, abort

pub mod dialogs;
pub mod panels;
pub mod toolbar;

use eframe::egui;

use crate::app::App;

/// Top-level render function — called once per egui frame.
pub fn render(app: &mut App, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
    let ctx = ui.ctx().clone();

    // ── Close-while-verifying guard ──────────────────────────────────────────
    // If the user tries to close the window while verification is running,
    // cancel the close and open the abort-confirmation dialog instead.
    if ctx.input(|i| i.viewport().close_requested()) && app.verifying {
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        app.abort_confirm_open = true;
        app.close_after_abort = true;
    }

    // Drain the worker channel before any rendering.
    app.process_events();

    // Exit after a confirmed abort-and-close.
    if app.close_after_abort && !app.verifying {
        std::process::exit(0);
    }

    // ── Layout ────────────────────────────────────────────────────────────────
    // 1. Top toolbar (fixed height, contains buttons + progress).
    // 2. Inside the remaining area: bottom panels (log, results) are declared
    //    first so egui allocates them before the central drive-list panel.

    // Toolbar — fixed height at the top.
    egui::Panel::top("top_panel").show_inside(ui, |ui| {
        toolbar::show(app, ui);
    });

    // Drive list — sits just below the toolbar; starts at ~5-row height, resizable.
    egui::Panel::top("drives_panel")
        .resizable(true)
        .min_size(60.0)
        .default_size(200.0)
        .show_inside(ui, |ui| {
            panels::show_drives(app, ui);
        });

    // Log — anchored to the very bottom, resizable upward.
    egui::Panel::bottom("log_panel")
        .resizable(true)
        .min_size(60.0)
        .default_size(180.0)
        .show_inside(ui, |ui| {
            panels::show_log(app, ui);
        });

    // Results — fills exactly the space between drives and log; no gap possible.
    egui::CentralPanel::default().show_inside(ui, |ui| {
        panels::show_results(app, ui);
    });

    // ── Floating dialogs ──────────────────────────────────────────────────────
    dialogs::show_all(app, &ctx);

    // Redraw at ~10 fps while idle, faster when a run is in progress.
    ctx.request_repaint_after(std::time::Duration::from_millis(100));
}
