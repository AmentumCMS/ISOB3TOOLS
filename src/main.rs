#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod app;
mod blake3iso_core;
mod dbenc;
mod encfile;
#[allow(dead_code)]
mod isomd5;
mod media;
mod sha256sum;
mod worker;

use eframe::egui;

fn main() -> eframe::Result<()> {
    // Start the desktop UI with a roomy default size for the result grid and log pane.
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1200.0, 700.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Drive Integrity Verifier",
        options,
        Box::new(|_cc| Ok(Box::new(app::App::new()))),
    )
}
