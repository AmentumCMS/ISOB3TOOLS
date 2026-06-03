//! Floating dialog windows: About, Drive Details, Password, Abort Confirm,
//! and the ML-KEM-768 Keypair Generator.

use eframe::egui;

use crate::app::{App, keys};
use super::panels;

/// Render every dialog that might be open this frame.
///
/// Each dialog checks its own `*_open` flag and does nothing when false.
pub fn show_all(app: &mut App, ctx: &egui::Context) {
    show_about(app, ctx);
    panels::show_drive_details(app, ctx);
    show_password(app, ctx);
    show_abort_confirm(app, ctx);
    show_keygen(app, ctx);
}

// ── About ──────────────────────────────────────────────────────────────────────

fn show_about(app: &mut App, ctx: &egui::Context) {
    if !app.show_about {
        return;
    }

    egui::Window::new("About ISOB3 Media Verifier")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.heading("ISOB3 Media Verifier");
            ui.separator();
            ui.label(
                "A desktop tool for verifying ISO media using embedded ISOB3 (BLAKE3) \
                 metadata, with SHA-256 manifest validation and ISOMD5 fallback support.",
            );

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
                ui.hyperlink_to(
                    "LinkedIn",
                    "https://www.linkedin.com/in/william-kronfeld/",
                );
            });

            ui.add_space(12.0);
            if ui.button("Close").clicked() {
                app.show_about = false;
            }
        });
}

// ── Password prompt ────────────────────────────────────────────────────────────

fn show_password(app: &mut App, ctx: &egui::Context) {
    if !app.password_prompt_open {
        return;
    }

    let mut is_open = app.password_prompt_open;
    let pw_width = (ctx.content_rect().width() * 0.38).clamp(320.0, 520.0);

    egui::Window::new("Encrypted File Password")
        .open(&mut is_open)
        .collapsible(false)
        .resizable(false)
        .default_width(pw_width)
        .show(ctx, |ui| {
            ui.label(
                "Enter the password used to decrypt DBENC001–DBENC004 encrypted files.",
            );
            ui.add_space(8.0);
            ui.add(
                egui::TextEdit::singleline(&mut app.password_input)
                    .password(true)
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Use Password").clicked() {
                    app.password_prompt_open = false;
                }
                if ui.button("Clear").clicked() {
                    app.password_input.clear();
                }
            });
        });

    app.password_prompt_open = is_open;
}

// ── Abort confirmation ─────────────────────────────────────────────────────────

fn show_abort_confirm(app: &mut App, ctx: &egui::Context) {
    if !app.abort_confirm_open {
        return;
    }

    let mut is_open = app.abort_confirm_open;
    let mut abort_clicked = false;
    let mut continue_clicked = false;

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
                    abort_clicked = true;
                }
                if ui.button("Continue").clicked() {
                    continue_clicked = true;
                }
            });
        });

    if abort_clicked {
        let close_after = app.close_after_abort;
        is_open = false;
        app.request_abort(close_after);
    }

    if continue_clicked {
        is_open = false;
        app.close_after_abort = false;
    }

    app.abort_confirm_open = is_open;
}

// ── ML-KEM-768 Keypair Generator ───────────────────────────────────────────────

fn show_keygen(app: &mut App, ctx: &egui::Context) {
    if !app.keygen_open {
        return;
    }

    let mut generate_clicked = false;
    let mut close_clicked = false;
    let keygen_width = (ctx.content_rect().width() * 0.42).clamp(360.0, 560.0);

    egui::Window::new("Generate ML-KEM-768 Keypair")
        .collapsible(false)
        .resizable(false)
        .default_width(keygen_width)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.label("Generates a post-quantum (ML-KEM-768) keypair:");
            ui.label("  • .ek — encapsulation key (public, 1184 bytes) — share with disc producers");
            ui.label("  • .dk — decapsulation key (private, 64 bytes)  — keep secret, needed to verify");
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label("Output prefix:");
                ui.add(
                    egui::TextEdit::singleline(&mut app.keygen_prefix_input)
                        .desired_width(300.0),
                );
            });

            ui.label(
                egui::RichText::new(format!(
                    "Will write: {}.ek  and  {}.dk",
                    app.keygen_prefix_input, app.keygen_prefix_input
                ))
                .weak(),
            );

            ui.add_space(8.0);

            // Show last result (success or error)
            if let Some(ref status) = app.keygen_status {
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
                        !app.keygen_prefix_input.is_empty(),
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
        app.keygen_status = Some(keys::run_keygen(&app.keygen_prefix_input));

        // Autoload the new .dk into the key field if nothing is set yet.
        if let Some(Ok(_)) = &app.keygen_status
            && app.private_key_input.is_empty() {
                app.private_key_input = format!("{}.dk", app.keygen_prefix_input);
            }
    }

    if close_clicked {
        app.keygen_open = false;
    }
}
