//! Top toolbar: action buttons, worker selector, encryption settings, key row,
//! progress bar, and status label.

use eframe::egui;

use crate::app::{App, keys};

/// Render the full toolbar inside the already-allocated top-panel `ui`.
pub fn show(app: &mut App, ui: &mut egui::Ui) {
    // ── Row 1: action buttons + encryption controls ───────────────────────────
    ui.horizontal(|ui| {
        // Scan drives button
        if ui
            .add_enabled(
                !app.discovering && !app.verifying,
                egui::Button::new("1. Scan Drives"),
            )
            .clicked()
        {
            app.start_drive_scan();
        }

        // Verify selected button
        if ui
            .add_enabled(
                !app.discovering && !app.verifying && app.selected_count() > 0,
                egui::Button::new("2. Verify Selected"),
            )
            .clicked()
        {
            app.start_verification();
        }

        // Abort button — only enabled while a run is active
        if ui
            .add_enabled(app.verifying, egui::Button::new("Abort"))
            .clicked()
        {
            app.abort_confirm_open = true;
            app.close_after_abort = false;
        }

        ui.label("Max workers:");
        egui::ComboBox::from_id_salt("worker_count")
            .selected_text(app.worker_count.to_string())
            .show_ui(ui, |ui| {
                for n in [1, 2, 3, 4, 6, 8, 12, 16] {
                    ui.selectable_value(&mut app.worker_count, n, n.to_string());
                }
            });

        ui.separator();

        // "Encrypted files" checkbox — controls whether the key row is shown
        // and whether a credential is required before verification starts.
        ui.checkbox(&mut app.encrypted_mode, "Encrypted files");

        if app.encrypted_mode {
            // Show a password-set indicator / button to open the password dialog.
            let masked = if app.password_input.is_empty() {
                "No password set".to_string()
            } else {
                format!("Password set ({} chars)", app.password_input.chars().count())
            };
            if ui.button(masked).clicked() {
                app.password_prompt_open = true;
            }
        }

        ui.separator();
        ui.label(app.summary_text());

        // "About" button — right-aligned
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("About").clicked() {
                app.show_about = true;
            }
        });
    });

    // ── Row 2: private-key row (only visible when encrypted mode is on) ───────
    if app.encrypted_mode {
        show_key_row(app, ui);
    }

    // ── Row 3: progress bar + timing label ────────────────────────────────────
    let progress = if app.total == 0 {
        0.0_f32
    } else if app.verifying && app.planned_bytes > 0 {
        (app.processed_bytes as f32 / app.planned_bytes as f32).clamp(0.0, 1.0)
    } else {
        app.done as f32 / app.total as f32
    };
    ui.add(egui::ProgressBar::new(progress).show_percentage());
    ui.label(app.progress_text());
}

// ── Private-key row ────────────────────────────────────────────────────────────

/// Render the private-key path input, existence indicator, Browse button,
/// and "Generate Keypair" button.
fn show_key_row(app: &mut App, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.label("🔑 Private key (.dk):");

        // On Windows we show a Browse button; elsewhere the user types the path.
        #[cfg(windows)]
        let browse_width = 90.0_f32;
        #[cfg(not(windows))]
        let browse_width = 0.0_f32;

        // Reserve space for: indicator (~90px) + separator + Generate button (~160px) + Browse
        let key_input_width = (ui.available_width() - 260.0 - browse_width).max(100.0);

        let hint = if app.private_key_input.is_empty() {
            "path/to/key.dk  (or leave blank — auto-discovers ~/.isob3/default.dk)"
        } else {
            ""
        };

        ui.add(
            egui::TextEdit::singleline(&mut app.private_key_input)
                .hint_text(hint)
                .desired_width(key_input_width),
        );

        // Native file picker (Windows only)
        #[cfg(windows)]
        if ui.button("Browse…").clicked() {
            if let Some(path) = keys::browse_dk_file() {
                app.private_key_input = path;
            }
        }

        // Show whether the resolved path points to an existing file
        match keys::resolve_private_key_path(&app.private_key_input) {
            Some(p) if p.exists() => {
                ui.colored_label(egui::Color32::GREEN, "✔ key found");
            }
            Some(_) => {
                ui.colored_label(egui::Color32::RED, "✘ not found");
            }
            None => {
                ui.colored_label(egui::Color32::GRAY, "(none)");
            }
        }

        ui.separator();

        if ui.button("Generate Keypair…").clicked() {
            app.keygen_status = None;
            app.keygen_open = true;
        }
    });
}
