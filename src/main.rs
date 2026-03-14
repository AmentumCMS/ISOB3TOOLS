mod app;
mod isomd5;
mod media;
mod iso_scan;
mod trailer;
mod worker;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1200.0, 700.0]),
        ..Default::default()
    };

    eframe::run_native(
        "ISOB3 Media Verifier",
        options,
        Box::new(|_cc| Ok(Box::new(app::App::new()))),
    )
}
