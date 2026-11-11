// Hide the console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod ciphers;
mod envelope;
mod theme;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("cipherterm")
            .with_inner_size([1200.0, 780.0])
            .with_min_inner_size([820.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native(
        "cipherterm",
        options,
        Box::new(|cc| Ok(Box::new(app::CipherApp::new(cc)))),
    )
}
