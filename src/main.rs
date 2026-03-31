#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use eframe::egui;
use isob3_tools::app;

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
