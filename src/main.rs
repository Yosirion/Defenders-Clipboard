#![windows_subsystem = "windows"]

use std::sync::mpsc;
use eframe::egui;

use defenders_clipboard::app::ClipboardApp;
use defenders_clipboard::clipboard_listener::{start_clipboard_listener, WINDOW_VISIBLE};
use defenders_clipboard::events::{AppEvent, ListenerCommand};

fn main() -> eframe::Result<()> {
    // Create channels for bidirectional communication between GUI and Background threads
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let (cmd_tx, cmd_rx) = mpsc::channel::<ListenerCommand>();

    // Spawn the Win32 message loop daemon
    start_clipboard_listener(tx.clone(), cmd_rx);

    // Setup native window options for Egui
    let mut native_options = eframe::NativeOptions::default();
    native_options.follow_system_theme = true;
// --- HIGH-DPI & GRAPHICS QUALITY IMPROVEMENTS ---
    native_options.multisampling = 4;

    // In eframe 0.27, you apply properties by calling the builder methods!
    native_options.viewport = egui::ViewportBuilder::default()
        .with_active(false)
        .with_window_level(egui::WindowLevel::AlwaysOnTop)
        .with_decorations(false)
        .with_transparent(true)
        .with_resizable(false)
        .with_inner_size(egui::vec2(360.0, 380.0));

    // Embed and load the custom icon for the taskbar
    let icon_data = include_bytes!("../icon.ico");
    if let Ok(image) = image::load_from_memory(icon_data) {
        let rgba = image.into_rgba8();
        let (width, height) = rgba.dimensions();
        native_options.viewport.icon = Some(std::sync::Arc::new(egui::IconData {
            rgba: rgba.into_raw(),
            width,
            height,
        }));
    }

    // Signal the background listener that the UI is initializing as visible
    WINDOW_VISIBLE.store(true, std::sync::atomic::Ordering::SeqCst);

    // Run the main GUI event loop
    eframe::run_native(
        "Defenders Clipboard",
        native_options,
        Box::new(|cc| {
            // Force Crisp Rendering across the entire UI
            let mut style = (*cc.egui_ctx.style()).clone();

            // This ensures that fonts are snapped to actual physical pixels, avoiding blurriness
            style.spacing.interact_size = egui::vec2(40.0, 18.0);
            cc.egui_ctx.set_style(style);

            Box::new(ClipboardApp::new(tx, rx, cmd_tx))
        }),
    )
}
