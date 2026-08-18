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
pub fn render(app: &mut App, ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();

    // ── Close-while-verifying guard ──────────────────────────────────────────
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
    // We render every panel with show(ui) on the Ui that eframe hands us
    // (eframe's `App::ui` gives us a top-level Ui; nesting panels inside it
    // with show(ui) is the supported pattern).
    //
    // Two requirements make the resizable panels behave (see panels.rs):
    //   1. Each panel's content must FILL the panel's height. egui stores a
    //      resizable panel's size from its *content* rect, so content shorter
    //      than the panel collapses its stored size down to `min_size` — and a
    //      drag then "snaps back" on release. The inner ScrollAreas use
    //      `auto_shrink([false, false])` (and the empty drive list fills the
    //      leftover space) so the panels keep their height.
    //   2. The inner ScrollAreas must NOT sense drag, or they swallow the drag
    //      meant for the panel's resize handle at the boundary. They pass a
    //      `scroll_source` with drag disabled for this.
    //
    // Declaration order matters: bottom panels before the CentralPanel.

    egui::Panel::top("top_panel").show(ui, |ui| {
        toolbar::show(app, ui);
    });

    egui::Panel::top("drives_panel_v2")
        .resizable(true)
        .min_size(60.0)
        .default_size(160.0)
        .show(ui, |ui| {
            panels::show_drives(app, ui);
        });

    egui::Panel::bottom("log_panel_v2")
        .resizable(true)
        .min_size(60.0)
        .default_size(280.0)
        .show(ui, |ui| {
            panels::show_log(app, ui);
        });

    // Results fills exactly the space between drives and log.
    egui::CentralPanel::default().show(ui, |ui| {
        panels::show_results(app, ui);
    });

    // ── Floating dialogs ──────────────────────────────────────────────────────
    dialogs::show_all(app, &ctx);

    // Redraw at ~10 fps while idle, faster when a run is in progress.
    ctx.request_repaint_after(std::time::Duration::from_millis(100));
}
