use std::collections::{HashMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use arboard::{Clipboard, ImageData};
use eframe::egui;
use image::{DynamicImage, RgbaImage, imageops::FilterType};
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
use winreg::RegKey;
use serde::{Deserialize, Serialize};

use crate::clipboard_listener::{GUI_CONTEXT, OPEN_AT_CURSOR, WINDOW_VISIBLE};
use crate::events::{AppEvent, ClipboardImage, HotkeyConfig, ListenerCommand};
use crate::transformers::TransformationManager;
use crate::api::{classify_indicator, IndicatorType, VtStatus, AbuseStatus};

const REGISTRY_RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const APP_REGISTRY_NAME: &str = "DefendersClipboard";

use std::path::PathBuf;
use base64::Engine;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HLOCAL, LocalFree}; 
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN
};

/// Returns the absolute path to a file located in the same directory as the executable.
/// This guarantees we always read/write the correct configuration file, even when the 
/// application is launched with a different Working Directory (e.g., via Windows Registry 
/// Autostart, Scheduled Tasks, or System32 contexts).
pub fn get_app_dir_file(filename: &str) -> PathBuf {
    if let Ok(mut path) = std::env::current_exe() {
        path.pop(); // Remove the executable name (defenders_clipboard.exe) to get the parent folder
        path.push(filename); // Append the target filename
        path
    } else {
        // Ultimate fallback if the OS somehow fails to provide the current executable path
        PathBuf::from(filename)
    }
}

/// Encrypts a string using Windows DPAPI and returns it as a Base64 string.
/// The encryption is tied to the current Windows user profile.
pub fn encrypt_secret(plain: &str) -> String {
    if plain.trim().is_empty() { return String::new(); }
    
    // Convert text to a Windows Data Blob
    let data_in = CRYPT_INTEGER_BLOB {
        cbData: plain.len() as u32,
        pbData: plain.as_ptr() as *mut u8, // Cast safe because Windows only reads this input
    };
    
    // Empty output blob to be filled by Windows
    let mut data_out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    
    unsafe {
        // Call the OS Native Encryption
        if CryptProtectData(&data_in, PCWSTR::null(), None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut data_out).is_ok() {
            // Convert the raw encrypted bytes to a Rust slice
            let encrypted_slice = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
            // Encode to Base64 so it can be saved in YAML safely
            let b64 = base64::engine::general_purpose::STANDARD.encode(encrypted_slice);
            
            // VERY IMPORTANT: Free the memory allocated by Windows!
            let _ = LocalFree(HLOCAL(data_out.pbData as _));
            
            return b64;
        }
    }
    String::new() // Fallback if encryption fails
}

/// Decrypts a Base64 string encrypted via Windows DPAPI back to a plain text string.
pub fn decrypt_secret(base64_cipher: &str) -> String {
    if base64_cipher.trim().is_empty() { return String::new(); }

    if let Ok(mut encrypted_bytes) = base64::engine::general_purpose::STANDARD.decode(base64_cipher.trim()) {
        let data_in = CRYPT_INTEGER_BLOB {
            cbData: encrypted_bytes.len() as u32,
            pbData: encrypted_bytes.as_mut_ptr(),
        };
        
        let mut data_out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        
        unsafe {
            // Call the OS Native Decryption
            if CryptUnprotectData(&data_in, None, None, None, None, 0, &mut data_out).is_ok() {
                let decrypted_slice = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
                
                // Convert back to a Rust UTF-8 String
                let plain_text = String::from_utf8_lossy(decrypted_slice).to_string();
                
                // FREE MEMORY!
                let _ = LocalFree(HLOCAL(data_out.pbData as _));
                
                return plain_text;
            }
        }
    }
    String::new()
}

/// State for each individual transformer tool in the settings menu
#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransformerState {
    is_active: bool,
}

impl Default for TransformerState {
    fn default() -> Self {
        Self { is_active: true }
    }
}

/// Structure representing the entire config.yml file mapped for Serde
#[derive(Debug, Serialize, Deserialize)]
struct AppConfig {
    #[serde(default)]
    vt_api_key: String,
    
    #[serde(default)]
    abuse_api_key: String,
    
    #[serde(default)]
    hotkey: HotkeyConfig,
    
    #[serde(default)]
    transformers: HashMap<String, TransformerState>,

    #[serde(default = "default_window_width")]
    window_width: f32,

    #[serde(default = "default_window_height")]
    window_height: f32,

    #[serde(default = "default_history_limit")]
    history_limit: usize,

    #[serde(default = "default_open_at_cursor")]
    open_at_cursor: bool,
}

// Default fallbacks used by Serde if fields are missing from the YAML file
fn default_window_width() -> f32 { 360.0 }
fn default_window_height() -> f32 { 380.0 }
fn default_history_limit() -> usize { 10 }
fn default_open_at_cursor() -> bool { true }

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            vt_api_key: String::new(),
            abuse_api_key: String::new(),
            hotkey: HotkeyConfig::default(),
            transformers: HashMap::new(),
            window_width: default_window_width(),
            window_height: default_window_height(),
            history_limit: default_history_limit(),
            open_at_cursor: default_open_at_cursor(),
        }
    }
}

/// Encapsulates the actual content of a clipboard item (Text or Image)
#[derive(Clone)]
enum HistoryPayload {
    Text(String),
    Image {
        width: usize,
        height: usize,
        rgba_bytes: Vec<u8>,
        egui_texture: Option<egui::TextureHandle>, // Lazy-loaded VRAM texture for performance
        qr_decode_result: Option<String>,
    },
}

#[derive(Clone)]
struct HistoryItem {
    payload: HistoryPayload,
    indicator_type: IndicatorType,
    vt_status: Option<VtStatus>,
    abuse_status: Option<AbuseStatus>, 
    is_pinned: bool,
    unique_hash: u64, // Used to uniquely identify and prevent duplicate entries
}

pub struct ClipboardApp {
    history: Vec<HistoryItem>,
    selected_index: Option<usize>,
    
    event_rx: Receiver<AppEvent>,
    event_tx: Sender<AppEvent>,
    cmd_tx: Sender<ListenerCommand>, 
    
    clipboard: Clipboard,
    last_action: Option<(String, bool)>, // (Message, Is Error)
    last_action_time: Option<Instant>,
    last_copied_hash: Option<u64>, // Prevents feedback loops when the app itself modifies the clipboard
    
    transformer_manager: TransformationManager,
    transformer_states: HashMap<String, TransformerState>, 
    
    show_settings: bool,
    vt_api_key_input: String,
    abuse_api_key_input: String,
    
    hotkey_config: HotkeyConfig, 
    search_query: String, // Search bar filter text
    start_with_windows: bool, // Tracks the registry autostart state
    just_opened: bool, // Forces focus onto the search bar when the UI awakens
    
    window_width: f32,
    window_height: f32,
    history_limit: usize,
    open_at_cursor: bool,
    focus_search_next_frame: bool,
    wake_up_time: Option<Instant>, 
}

impl ClipboardApp {
    pub fn new(event_tx: Sender<AppEvent>, event_rx: Receiver<AppEvent>, cmd_tx: Sender<ListenerCommand>) -> Self {
            let clipboard = Clipboard::new().expect("Failed to initialize clipboard");
            let transformer_manager = TransformationManager::new();

            // 1. Initialize a baseline configuration with safe defaults
            let mut config = AppConfig::default();

            // 2. Resolve the absolute path to the configuration file
            let config_path = get_app_dir_file("config.yml");
            
            // 3. --- LOAD SETTINGS FROM YAML ---
            let mut key_decrypt_failed = false;
            if let Ok(data) = std::fs::read_to_string(&config_path) {
                if let Ok(parsed_yaml) = serde_yaml::from_str::<AppConfig>(&data) {
                    // YAML successfully parsed! Overwrite the default config.
                    config = parsed_yaml;

                    // DECRYPT SECRETS ON THE FLY!
                    // The YAML contains DPAPI-encrypted Base64 blobs. We decrypt them here
                    // so the application logic and UI can work with plain text strings.
                    // DPAPI ties the ciphertext to this Windows user profile: if the file
                    // was copied to another machine/user, decryption silently yields "".
                    let vt_was_set = !config.vt_api_key.trim().is_empty();
                    let abuse_was_set = !config.abuse_api_key.trim().is_empty();

                    config.vt_api_key = decrypt_secret(&config.vt_api_key);
                    config.abuse_api_key = decrypt_secret(&config.abuse_api_key);

                    key_decrypt_failed = (vt_was_set && config.vt_api_key.is_empty())
                        || (abuse_was_set && config.abuse_api_key.is_empty());
                }
            }

            // Enable all tools by default on first run if they are missing from the config file
            // (Ensures newly added Transformer updates don't disappear from the user's UI)
            for t in &transformer_manager.transformers {
                config.transformers.entry(t.name().to_string()).or_insert_with(TransformerState::default);
            }

            // Apply the loaded hotkey immediately by broadcasting a command to the Win32 Listener
            let _ = cmd_tx.send(ListenerCommand::UpdateHotkey(config.hotkey.clone()));

            // Tell the Win32 listener where the window should open
            OPEN_AT_CURSOR.store(config.open_at_cursor, std::sync::atomic::Ordering::SeqCst);

            // --- LOAD AUTOSTART STATE FROM REGISTRY ---
            let start_with_windows = Self::is_autostart_enabled();

            // Surface a startup toast if the saved API keys couldn't be decrypted,
            // instead of silently dropping them (see key_decrypt_failed above).
            let (last_action, last_action_time) = if key_decrypt_failed {
                (
                    Some(("Could not decrypt saved API keys (different Windows profile?). Please re-enter them in Settings.".to_string(), true)),
                    Some(Instant::now()),
                )
            } else {
                (None, None)
            };

            Self {
                history: Vec::new(),
                selected_index: None,
                event_rx,
                event_tx,
                cmd_tx,
                clipboard,
                last_action,
                last_action_time,
                last_copied_hash: None,
                transformer_manager,
                transformer_states: config.transformers, 
                show_settings: false,
                
                // Inject the decrypted plain-text keys directly into the UI text fields
                vt_api_key_input: config.vt_api_key,     
                abuse_api_key_input: config.abuse_api_key, 
                
                hotkey_config: config.hotkey,
                search_query: String::new(),
                start_with_windows,
                just_opened: true,
                focus_search_next_frame: false,
                wake_up_time: None,
                window_width: config.window_width,
                window_height: config.window_height,
                history_limit: config.history_limit,
                open_at_cursor: config.open_at_cursor,
            }
        }


    // --- AUTOSTART REGISTRY LOGIC ---
    fn is_autostart_enabled() -> bool {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(run_key) = hkcu.open_subkey_with_flags(REGISTRY_RUN_KEY, KEY_READ) {
            let val: Result<String, _> = run_key.get_value(APP_REGISTRY_NAME);
            return val.is_ok();
        }
        false
    }

    fn toggle_autostart(&mut self, enable: bool) {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(run_key) = hkcu.open_subkey_with_flags(REGISTRY_RUN_KEY, KEY_WRITE) {
            if enable {
                if let Ok(exe_path) = std::env::current_exe() {
                    let path_str = format!("\"{}\"", exe_path.to_string_lossy()); 
                    let _ = run_key.set_value(APP_REGISTRY_NAME, &path_str);
                    self.start_with_windows = true;
                }
            } else {
                let _ = run_key.delete_value(APP_REGISTRY_NAME);
                self.start_with_windows = false;
            }
        }
    }

    // --- CONFIGURATION SAVE ---
     fn save_settings(&self) {
        // --- SAVE TO YAML ---
        // Reconstruct the AppConfig struct using the current RAM state
        let config = AppConfig {
            vt_api_key: encrypt_secret(self.vt_api_key_input.trim()),
            abuse_api_key: encrypt_secret(self.abuse_api_key_input.trim()),
            hotkey: self.hotkey_config.clone(),
            transformers: self.transformer_states.clone(),
            window_width: self.window_width,
            window_height: self.window_height,
            history_limit: self.history_limit,
            open_at_cursor: self.open_at_cursor,
        };

        // Serialize to YAML and write securely to the absolute path
        let config_path = get_app_dir_file("config.yml");
        if let Ok(yaml_string) = serde_yaml::to_string(&config) {
            let _ = std::fs::write(&config_path, yaml_string);
        }
        
        // Notify Win32 Listener that the hotkey might have changed
        let _ = self.cmd_tx.send(ListenerCommand::UpdateHotkey(self.hotkey_config.clone()));
    }

    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    // --- CORE HISTORY LOGIC ---
    fn insert_history_item(&mut self, new_item: HistoryItem) {
        // Prevent feedback loop: If we just copied this exact item, ignore the broadcast
        if Some(new_item.unique_hash) == self.last_copied_hash {
            self.last_copied_hash = None;
            return;
        }

        // Remove older duplicates but keep their pinned/API status intact
        let mut existing_pin = false;
        let mut existing_vt = None;
        let mut existing_abuse = None;
        
        if let Some(pos) = self.history.iter().position(|t| t.unique_hash == new_item.unique_hash) {
            let removed = self.history.remove(pos);
            existing_pin = removed.is_pinned;
            existing_vt = removed.vt_status;
            existing_abuse = removed.abuse_status;
        }

        let mut final_item = new_item;
        final_item.is_pinned = existing_pin;
        final_item.vt_status = existing_vt;
        final_item.abuse_status = existing_abuse;

        // Pinned items stay at the absolute top
        if final_item.is_pinned {
            self.history.insert(0, final_item);
        } else {
            let insert_idx = self.history.iter().take_while(|item| item.is_pinned).count();
            self.history.insert(insert_idx, final_item);
        }

        // Enforce the history limit ONLY on unpinned items to avoid erasing saved elements
        let unpinned_count = self.history.iter().filter(|i| !i.is_pinned).count();
        if unpinned_count > self.history_limit {
            if let Some(pos) = self.history.iter().rposition(|i| !i.is_pinned) {
                self.history.remove(pos);
            }
        }
    }

    fn update_history_from_text(&mut self, text: String) {
        let trimmed = text.trim();
        if trimmed.is_empty() { return; }

        let unique_hash = Self::calculate_hash(&trimmed);
        
        let item = HistoryItem {
            payload: HistoryPayload::Text(trimmed.to_owned()),
            indicator_type: classify_indicator(trimmed),
            vt_status: None,
            abuse_status: None,
            is_pinned: false,
            unique_hash,
        };
        self.insert_history_item(item);
    }

    fn update_history_from_image(&mut self, img: ClipboardImage) {
        let unique_hash = Self::calculate_hash(&img.bytes);

        // Soft thumbnail generation: resize massive 4K screenshots to prevent RAM exhaustion
        let final_img = if img.width > 800 || img.height > 800 {
            if let Some(raw_img) = RgbaImage::from_raw(img.width as u32, img.height as u32, img.bytes.clone()) {
                let dynamic = DynamicImage::ImageRgba8(raw_img);
                let thumbnail = dynamic.resize(800, 800, FilterType::Triangle);
                let thumb_rgba = thumbnail.to_rgba8();
                let (w, h) = thumb_rgba.dimensions();
                ClipboardImage { width: w as usize, height: h as usize, bytes: thumb_rgba.into_raw() }
            } else { img }
        } else { img };

        let item = HistoryItem {
            payload: HistoryPayload::Image {
                width: final_img.width,
                height: final_img.height,
                rgba_bytes: final_img.bytes,
                egui_texture: None, 
                qr_decode_result: None,
            },
            indicator_type: IndicatorType::Unknown,
            vt_status: None,
            abuse_status: None,
            is_pinned: false,
            unique_hash,
        };
        self.insert_history_item(item);
    }

    /// Hides the window (same state changes as after clicking an entry to paste it).
    fn hide_window(&mut self, ctx: &egui::Context) {
        WINDOW_VISIBLE.store(false, std::sync::atomic::Ordering::SeqCst);
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        self.search_query.clear();
    }

    // --- FEEDBACK TOAST HANDLERS ---
    fn set_feedback_success(&mut self, msg: String) {
        self.last_action = Some((msg, false));
        self.last_action_time = Some(Instant::now());
    }

    fn set_feedback_error(&mut self, msg: String) {
        self.last_action = Some((msg, true));
        self.last_action_time = Some(Instant::now());
    }
}

impl eframe::App for ClipboardApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Store context globally so the Win32 listener can wake up the UI from sleep
        let _ = GUI_CONTEXT.set(ctx.clone());

        // Setup crisp font sizing
        {
            let mut style = (*ctx.style()).clone();
            if let Some(body) = style.text_styles.get_mut(&egui::TextStyle::Body) {
                if body.size < 15.0 { body.size = 15.0; }
            }
            ctx.set_style(style);
        }

        // Apply dynamic window sizing set by the user in the Preferences
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
            self.window_width, 
            self.window_height
        )));

        // --- ASYNC EVENT HANDLING LOOP ---
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AppEvent::ClipboardUpdatedText(text) => self.update_history_from_text(text),
                AppEvent::ClipboardUpdatedImage(img) => self.update_history_from_image(img),
                
                AppEvent::ClipboardUpdatedFileHash(file_name, hash) => {
                    self.update_history_from_text(hash);
                    self.set_feedback_success(format!("SHA-256 computed for: {}", file_name));
                }
                
                AppEvent::VtResult(value, result) => {
                    match result {
                        Ok(status) => {
                            if let Some(item) = self.history.iter_mut().find(|it| {
                                if let HistoryPayload::Text(ref t) = it.payload { t == &value } else { false }
                            }) {
                                item.vt_status = Some(status);
                                // NON COPIAMO NULLA! Lasciamo solo che l'interfaccia si colori.
                            }
                        }
                        Err(err_msg) => self.set_feedback_error(format!("VT Error: {err_msg}")),
                    }
                }

                AppEvent::AbuseResult(value, result) => {
                    match result {
                        Ok(status) => {
                            if let Some(item) = self.history.iter_mut().find(|it| {
                                if let HistoryPayload::Text(ref t) = it.payload { t == &value } else { false }
                            }) {
                                item.abuse_status = Some(status);
                                // NON COPIAMO NULLA! Lasciamo solo che l'interfaccia mostri il punteggio.
                            }
                        }
                        Err(err_msg) => self.set_feedback_error(format!("AbuseIPDB Error: {err_msg}")),
                    }
                }
                AppEvent::Notification(msg, is_err) => {
                    if is_err { self.set_feedback_error(msg) } else { self.set_feedback_success(msg) }
                },
                
                // Handle results generated asynchronously by Transformer plugins
                AppEvent::TransformerResultText(action_name, result_text, idx) => {
                    if action_name == "QR Decode" {
                        if let Some(item) = self.history.get_mut(idx) {
                            if let HistoryPayload::Image { qr_decode_result, .. } = &mut item.payload {
                                *qr_decode_result = Some(result_text.clone());
                            }
                        }
                        self.set_feedback_success("QR Code Decoded!".to_string());
                        
                    } else if action_name == "Extract IOCs" {
                        // Extract IOCs splits the result into single items instead of pasting a massive block
                        let lines: Vec<&str> = result_text.lines().collect();
                        let count = lines.len();
                        
                        for line in lines.into_iter().rev() {
                            self.update_history_from_text(line.to_string());
                        }
                        
                        self.last_copied_hash = Some(Self::calculate_hash(&result_text)); 
                        let _ = self.clipboard.set_text(result_text);
                        self.set_feedback_success(format!("Extracted {} IOCs!", count));
                        
                    } else {
                        // Standard Transformers: Copy to OS Clipboard
                        self.last_copied_hash = Some(Self::calculate_hash(&result_text)); 
                        if self.clipboard.set_text(result_text).is_ok() {
                            self.set_feedback_success(format!("Copied ({action_name})!"));
                            // The result is already in the clipboard: get out of the way
                            self.hide_window(ctx);
                        } else {
                            self.set_feedback_error("Error during copy.".to_string());
                        }
                    }
                },
                
                AppEvent::TransformerResultBrowser(action_name, url) => {
                    if open::that(&url).is_ok() {
                        self.set_feedback_success(format!("Opened {} in Browser!", action_name));
                        // The browser takes over: hide the clipboard like after a paste
                        self.hide_window(ctx);
                    } else {
                        self.set_feedback_error("Failed to open browser.".to_string());
                    }
                },

                AppEvent::OpenSettings => {
                    self.show_settings = true;
                    WINDOW_VISIBLE.store(true, std::sync::atomic::Ordering::SeqCst);
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(egui::WindowLevel::AlwaysOnTop));
                }

                // Global shortcut triggered: ensure the app requests focus on the search bar
                AppEvent::AppWokeUp => {
                    self.just_opened = true;
                    self.search_query.clear();
                    self.wake_up_time = Some(Instant::now());
                }
            }
        }

        // Clear feedback toasts after a few seconds
        if let Some(t) = self.last_action_time {
            if t.elapsed() > Duration::from_secs(4) {
                self.last_action = None;
                self.last_action_time = None;
            }
        }

        // --- GLOBAL APP SHORTCUTS ---
        // "Escape" hides the application instantly
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            WINDOW_VISIBLE.store(false, std::sync::atomic::Ordering::SeqCst);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.search_query.clear();
        }

        let main_frame = egui::Frame {
            fill: ctx.style().visuals.window_fill,
            rounding: egui::Rounding::same(8.0),
            stroke: egui::Stroke::new(1.0, egui::Color32::from_gray(150)),
            inner_margin: egui::Margin::ZERO,
            ..Default::default()
        };

        egui::CentralPanel::default().frame(main_frame).show(ctx, |ui| {
            
            // =====================================
            // --- DRAGGABLE HEADER ---
            // =====================================
            let header_height = 35.0; 
            let header_width = ui.available_width();
            
            let header_rect = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(header_width, header_height));
            ui.painter().rect_filled(
                header_rect,
                egui::Rounding { nw: 8.0, ne: 8.0, sw: 0.0, se: 0.0 },
                egui::Color32::from_rgb(40, 45, 55),
            );

            ui.allocate_ui_with_layout(
                egui::vec2(header_width, header_height),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    let drag_area_width = header_width - 40.0;
                    let drag_response = ui.allocate_response(egui::vec2(drag_area_width, header_height), egui::Sense::drag());
                    
                    if drag_response.dragged() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                    }

                    ui.painter().text(
                        drag_response.rect.left_center() + egui::vec2(12.0, 0.0),
                        egui::Align2::LEFT_CENTER, "Defenders Clipboard", egui::FontId::proportional(16.0), egui::Color32::WHITE,
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        let close_btn = egui::Button::new(egui::RichText::new("X").color(egui::Color32::WHITE).strong().size(15.0)).fill(egui::Color32::TRANSPARENT).frame(false);
                        if ui.add_sized(egui::vec2(24.0, 24.0), close_btn).on_hover_text("Hide").clicked() {
                            WINDOW_VISIBLE.store(false, std::sync::atomic::Ordering::SeqCst);
                            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                            self.search_query.clear();
                        }
                    });
                }
            );

            egui::Frame::none().inner_margin(egui::Margin::same(12.0)).show(ui, |ui| {
                
                // =====================================
                // --- SETTINGS VIEW ---
                // =====================================
                if self.show_settings {
                    egui::ScrollArea::vertical()
                        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                        .show(ui, |ui| {
                        
                        ui.heading("Settings");
                        ui.add_space(10.0);
                        
                        // --- SYSTEM STARTUP SETTINGS ---
                        ui.horizontal(|ui| {
                            let mut autostart = self.start_with_windows;
                            if ui.checkbox(&mut autostart, "Start with Windows")
                                 .on_hover_text("Automatically launches the app when you log in")
                                 .changed() 
                            {
                                self.toggle_autostart(autostart);
                            }
                        });
                        ui.add_space(15.0);
                        
                        // --- API KEYS ---
                        ui.label("VirusTotal API Key:");
                        ui.add(egui::TextEdit::singleline(&mut self.vt_api_key_input).desired_width(ui.available_width()));
                        ui.add_space(10.0);

                        ui.label("AbuseIPDB API Key:");
                        ui.add(egui::TextEdit::singleline(&mut self.abuse_api_key_input).desired_width(ui.available_width()));
                        ui.add_space(15.0);

                        // --- HOTKEY SETTINGS ---
                        ui.label(egui::RichText::new("Global Hotkey:").strong());
                        ui.horizontal(|ui| {
                            let mut settings_changed = false;
                            
                            if ui.checkbox(&mut self.hotkey_config.ctrl, "Ctrl").changed() { settings_changed = true; }
                            if ui.checkbox(&mut self.hotkey_config.alt, "Alt").changed() { settings_changed = true; }
                            if ui.checkbox(&mut self.hotkey_config.shift, "Shift").changed() { settings_changed = true; }
                            if ui.checkbox(&mut self.hotkey_config.win, "Win").changed() { settings_changed = true; }
                            
                            ui.label("+");
                            
                            egui::ComboBox::from_id_source("hotkey_combo")
                                .selected_text(self.hotkey_config.key.clone())
                                .width(80.0) 
                                .show_ui(ui, |ui| {
                                    
                                    let mut supported_keys: Vec<String> = (b'A'..=b'Z').map(|c| (c as char).to_string()).collect();
                                    for n in 0..=9 { supported_keys.push(n.to_string()); }
                                    
                                    let extra_keys = vec![
                                        "SPACE", "ENTER", "TAB", "ESC", "BACKSPACE", 
                                        "UP", "DOWN", "LEFT", "RIGHT",
                                        "F1", "F2", "F3", "F4", "F5", "F6", 
                                        "F7", "F8", "F9", "F10", "F11", "F12",
                                        "è", "à", "ò", "ù", "ì", "+", "-", ",", ".", "<"
                                    ];
                                    for k in extra_keys { supported_keys.push(k.to_string()); }

                                    for key_str in supported_keys {
                                        if ui.selectable_value(&mut self.hotkey_config.key, key_str.clone(), key_str).changed() {
                                            settings_changed = true;
                                        }
                                    }
                                });
                                
                            if settings_changed {
                                self.save_settings(); 
                            }
                        });
                        ui.add_space(15.0);

                        // --- UI PREFERENCES ---
                        ui.label(egui::RichText::new("Interface Preferences:").strong());
                        ui.add_space(5.0);

                        let mut settings_changed = false;

                        ui.horizontal(|ui| {
                            ui.label("History Capacity:");
                            if ui.add(egui::Slider::new(&mut self.history_limit, 5..=50).text("items")).on_hover_text("Maximum unpinned items to keep in memory").changed() {
                                settings_changed = true;
                                
                                let mut unpinned_count = self.history.iter().filter(|i| !i.is_pinned).count();
                                while unpinned_count > self.history_limit {
                                    if let Some(pos) = self.history.iter().rposition(|i| !i.is_pinned) {
                                        self.history.remove(pos);
                                        unpinned_count -= 1;
                                    }
                                }
                            }
                        });

                        ui.horizontal(|ui| {
                            ui.label("Window Width:");
                            if ui.add(egui::Slider::new(&mut self.window_width, 300.0..=800.0).text("px")).changed() {
                                settings_changed = true;
                            }
                        });

                        ui.horizontal(|ui| {
                            ui.label("Window Height:");
                            if ui.add(egui::Slider::new(&mut self.window_height, 200.0..=1000.0).text("px")).changed() {
                                settings_changed = true;
                            }
                        });

                        if ui.checkbox(&mut self.open_at_cursor, "Open under the mouse pointer")
                             .on_hover_text("Opens on the monitor where the pointer is. When off, it opens centered on the primary monitor.")
                             .changed()
                        {
                            OPEN_AT_CURSOR.store(self.open_at_cursor, std::sync::atomic::Ordering::SeqCst);
                            settings_changed = true;
                        }

                        if settings_changed {
                            self.save_settings(); 
                        }
                        ui.add_space(15.0);

                        // --- ACTIVE TOOLS ---
                        ui.label(egui::RichText::new("Active Tools:").strong());
                        ui.add_space(5.0);
                        
                        for transformer in &self.transformer_manager.transformers {
                            let name = transformer.name();
                            let mut is_active = (*self.transformer_states.get(name).unwrap_or(&TransformerState::default())).is_active;
                            
                            if ui.checkbox(&mut is_active, name).changed() {
                                self.transformer_states.insert(name.to_string(), TransformerState { is_active });
                                settings_changed = true;
                            }
                        }

                        ui.add_space(20.0);
                        ui.horizontal(|ui| {
                            if ui.button("Save & Exit").clicked() {
                                self.save_settings();
                                self.show_settings = false;
                                self.set_feedback_success("Settings saved!".to_string());
                            }
                        });

                        if settings_changed {
                            self.save_settings();
                        }
                    });

                } else {
                    // =====================================
                    // --- CLIPBOARD HISTORY VIEW ---
                    // =====================================
                    
                    // 1. TOP ROW: Search Bar and Clear Button
                    ui.horizontal(|ui| {
                        
                        let search_bg_color = if ctx.style().visuals.dark_mode {
                            egui::Color32::from_rgb(50, 50, 50)
                        } else {
                            egui::Color32::from_rgb(240, 240, 240)
                        };

                        let frame = egui::Frame::none()
                            .fill(search_bg_color)
                            .rounding(4.0)
                            .inner_margin(egui::Margin::symmetric(8.0, 4.0));
                        
// We assign a strict ID to the search bar to manually handle its focus states
                        let search_id = ui.id().with("search_bar");

                        frame.show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("🔍").color(egui::Color32::GRAY));
                                
                                // Check if we are within the 200ms "quarantine" window after the app wakes up
                                let in_quarantine = match self.wake_up_time {
                                    Some(time) => time.elapsed() < Duration::from_millis(200),
                                    None => false,
                                };
                                
                                let search_input = egui::TextEdit::singleline(&mut self.search_query)
                                    .id(search_id)
                                    .desired_width(170.0)
                                    .hint_text("Search...")
                                    .frame(false);
                                
                                let resp = ui.add(search_input);

                                // --- 1. QUARANTINE (Absolute Anti-Key Bleeding) ---
                                // Continuously clears any incoming text (e.g., the leftover hotkey press) 
                                // and forces Egui to repaint until the quarantine timer expires.
                                if in_quarantine {
                                    self.search_query.clear();
                                    ui.ctx().request_repaint();
                                }

                                // --- 2. DYNAMIC FOCUS MANAGEMENT ---
                                // Grab focus when the app wakes up OR when navigating back up from the history list
                                if self.just_opened || self.focus_search_next_frame {
                                    resp.request_focus();
                                    self.focus_search_next_frame = false;
                                    
                                    // Hardcore mitigation: if the app just opened, clear the Egui event buffer entirely 
                                    // to destroy any floating 'KeyUp' events from the global OS hotkey.
                                    if self.just_opened {
                                        ui.ctx().input_mut(|i| i.events.clear()); 
                                        self.search_query.clear();
                                        self.just_opened = false;
                                    }
                                }

                                // --- 3. MANUAL CLEAR TRIGGERS ---
                                // "Delete" clears the search query and keeps focus
                                if ui.input(|i| i.key_pressed(egui::Key::Delete)) {
                                    self.search_query.clear();
                                    resp.request_focus();
                                }
                                
                                // Draw the "X" button to manually clear the search via mouse
                                if !self.search_query.is_empty() {
                                    if ui.add(egui::Label::new(egui::RichText::new("x").color(egui::Color32::GRAY)).sense(egui::Sense::click()))
                                         .on_hover_cursor(egui::CursorIcon::PointingHand)
                                         .clicked() 
                                    {
                                        self.search_query.clear();
                                        resp.request_focus();
                                    }
                                }
                            });
                        });
                        
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("🗑 Clear").on_hover_text("Remove all unpinned items").clicked() {
                                self.history.retain(|item| item.is_pinned);
                                self.set_feedback_success("Clipboard cleared (Pinned items kept).".to_string());
                                self.search_query.clear(); 
                            }
                        });
                    });
                    
                    ui.add_space(4.0);

                    // 2. FEEDBACK TOAST ROW
                    if let Some((ref msg, is_error)) = self.last_action {
                        let color = if is_error { egui::Color32::from_rgb(200, 0, 0) } else { egui::Color32::DARK_GREEN };
                        ui.label(egui::RichText::new(msg).color(color).size(13.0).strong());
                        ui.add_space(4.0);
                    }

                    let mut delete_idx: Option<usize> = None;
                    let mut pin_toggled_idx: Option<usize> = None;
                    let mut text_to_copy: Option<(String, String)> = None; 
                    let mut image_to_copy: Option<(String, usize)> = None; 

                    // Normalize search query (lowercase, removes newlines/tabs) for resilient matching
                    let normalize_for_search = |s: &str| {
                        s.to_lowercase().split_whitespace().collect::<Vec<&str>>().join(" ")
                    };
                    let search_clean = normalize_for_search(&self.search_query);

                    // --- KEYBOARD NAVIGATION LOGIC ---
                    // Compute the list of currently visible/filtered items based on the search query
                    let mut visible_indices = Vec::new();
                    for (idx, item) in self.history.iter().enumerate() {
                        if !search_clean.is_empty() {
                            match &item.payload {
                                HistoryPayload::Text(text_val) => {
                                    let text_clean = normalize_for_search(text_val);
                                    if !text_clean.contains(&search_clean) { continue; }
                                },
                                HistoryPayload::Image { qr_decode_result, .. } => {
                                    let mut matches_qr = false;
                                    if let Some(qr_text) = qr_decode_result {
                                        let qr_clean = normalize_for_search(qr_text);
                                        if qr_clean.contains(&search_clean) { matches_qr = true; }
                                    }
                                    if !matches_qr { continue; }
                                }
                            }
                        }
                        visible_indices.push(idx);
                    }

                    let mut keyboard_navigated = false;

                    // Detect if the search bar currently has focus.
                    let search_id = ui.id().with("search_bar");
                    let search_has_focus = ui.ctx().memory(|mem| mem.has_focus(search_id));

                    // --- CLEAR HIGHLIGHT IF SEARCHING ---
                    // If the user is typing in the search bar, remove the blue highlight from the list
                    if search_has_focus {
                        self.selected_index = None;
                    }

                    if visible_indices.is_empty() {
                        self.selected_index = None;
                    } else {
                        // Activate history navigation ONLY when the search bar is inactive
                        if !search_has_focus {
                            
                            // Start selection on the first element if arriving from the search bar
                            if self.selected_index.is_none() || !visible_indices.contains(&self.selected_index.unwrap()) {
                                self.selected_index = Some(visible_indices[0]);
                            }

                            // Arrow Down Navigation
                            if ui.input(|i| i.key_pressed(egui::Key::ArrowDown)) {
                                if let Some(current) = self.selected_index {
                                    if let Some(pos) = visible_indices.iter().position(|&i| i == current) {
                                        if pos + 1 < visible_indices.len() {
                                            self.selected_index = Some(visible_indices[pos + 1]);
                                            keyboard_navigated = true;
                                        }
                                    }
                                }
                            }
                            
                            // Arrow Up Navigation
                            if ui.input(|i| i.key_pressed(egui::Key::ArrowUp)) {
                                if let Some(current) = self.selected_index {
                                    if let Some(pos) = visible_indices.iter().position(|&i| i == current) {
                                        if pos > 0 {
                                            // Move selection up
                                            self.selected_index = Some(visible_indices[pos - 1]);
                                            keyboard_navigated = true;
                                        } else {
                                            // WE HIT THE TOP!
                        
                                            self.selected_index = None;
                                            self.focus_search_next_frame = true;
                                            ui.ctx().request_repaint();
                                        }
                                    }
                                }
                            }

                            // "Enter" to trigger Auto-Paste
                            if ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                if let Some(current_idx) = self.selected_index {
                                    if let Some(item) = self.history.get(current_idx) {
                                        match &item.payload {
                                            HistoryPayload::Text(text_val) => {
                                                text_to_copy = Some(("Text copied".to_string(), text_val.clone()));
                                            },
                                            HistoryPayload::Image { .. } => {
                                                image_to_copy = Some(("Image copied".to_string(), current_idx));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // 3. SCROLLABLE HISTORY CARDS
                    egui::ScrollArea::vertical()
                        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                        .show(ui, |ui| {
                        
                        for (idx, item) in self.history.iter_mut().enumerate() {
                            
                            if !visible_indices.contains(&idx) {
                                continue; 
                            }

                            let selected = self.selected_index == Some(idx);
                            let is_dark_mode = ctx.style().visuals.dark_mode;

                            // Dynamic Background Colors based on VT/AbuseIPDB and Theme
                            // Dynamic Background Colors based on VT/AbuseIPDB and Theme
                            let mut bg_color = if is_dark_mode {
                                match item.vt_status {
                                    Some(VtStatus::Malicious(_, _)) => egui::Color32::from_rgb(90, 20, 20),     
                                    Some(VtStatus::Suspicious(_, _)) => egui::Color32::from_rgb(100, 70, 10),   
                                    Some(VtStatus::Clean(_, _)) => egui::Color32::from_rgb(20, 60, 20),         
                                    _ => match item.abuse_status {
                                        Some(AbuseStatus::Malicious(_)) => egui::Color32::from_rgb(90, 20, 20),
                                        Some(AbuseStatus::Suspicious(_)) => egui::Color32::from_rgb(100, 70, 10),
                                        Some(AbuseStatus::Clean(_)) => egui::Color32::from_rgb(20, 60, 20),
                                        _ => egui::Color32::from_rgb(45, 45, 45), 
                                    }
                                }
                            } else {
                                match item.vt_status {
                                    Some(VtStatus::Malicious(_, _)) => egui::Color32::from_rgb(255, 210, 210),   
                                    Some(VtStatus::Suspicious(_, _)) => egui::Color32::from_rgb(255, 240, 180),  
                                    Some(VtStatus::Clean(_, _)) => egui::Color32::from_rgb(220, 255, 220),       
                                    _ => match item.abuse_status {
                                        Some(AbuseStatus::Malicious(_)) => egui::Color32::from_rgb(255, 210, 210),
                                        Some(AbuseStatus::Suspicious(_)) => egui::Color32::from_rgb(255, 240, 180),
                                        Some(AbuseStatus::Clean(_)) => egui::Color32::from_rgb(220, 255, 220),
                                        _ => egui::Color32::from_rgb(245, 245, 245), 
                                    }
                                }
                            };

                            // Selection Highlight Effect
                            if selected {
                                if is_dark_mode {
                                    bg_color = egui::Color32::from_rgb(
                                        bg_color.r().saturating_add(30), 
                                        bg_color.g().saturating_add(30), 
                                        bg_color.b().saturating_add(30)
                                    );
                                } else {
                                    bg_color = egui::Color32::from_rgb(
                                        bg_color.r().saturating_sub(20), 
                                        bg_color.g().saturating_sub(20), 
                                        bg_color.b().saturating_sub(20)
                                    );
                                }
                            }

                            // Pin Highlight Effect
                            let stroke = if item.is_pinned {
                                egui::Stroke::new(2.0, egui::Color32::from_rgb(255, 165, 0))
                            } else {
                                egui::Stroke::new(1.0, if is_dark_mode { egui::Color32::from_gray(60) } else { egui::Color32::from_gray(210) })
                            };

                            let text_color = if is_dark_mode { egui::Color32::LIGHT_GRAY } else { egui::Color32::BLACK };

                            let frame = egui::Frame::none()
                                .fill(bg_color)
                                .stroke(stroke)
                                .rounding(6.0)
                                .inner_margin(egui::Margin::same(10.0));

                            let frame_response = frame.show(ui, |ui| {
                                ui.set_width(ui.available_width());

                                ui.vertical(|ui| {
                                    
                                    ui.horizontal(|ui| {
                                        // PIN BUTTON
                                        let star_text = if item.is_pinned { "★" } else { "☆" };
                                        let star_color = if item.is_pinned { egui::Color32::from_rgb(255, 165, 0) } else { egui::Color32::GRAY };
                                        let star_btn = egui::Button::new(egui::RichText::new(star_text).color(star_color).size(18.0)).frame(false);
                                        
                                        if ui.add(star_btn).on_hover_text("Pin / Unpin item").clicked() {
                                            pin_toggled_idx = Some(idx);
                                        }

                                        // PAYLOAD (TEXT / IMAGE)
                                        match &mut item.payload {
                                            HistoryPayload::Text(text_val) => {
                                                let text_rich = egui::RichText::new(text_val.clone()).size(15.0).color(text_color);
                                                if ui.add(egui::Label::new(text_rich).truncate(true).sense(egui::Sense::click()))
                                                     .on_hover_cursor(egui::CursorIcon::PointingHand)
                                                     .on_hover_text("Click to copy")
                                                     .clicked() 
                                                { 
                                                    self.selected_index = Some(idx);
                                                    text_to_copy = Some(("Text copied".to_string(), text_val.clone()));
                                                }
                                            }
                                            HistoryPayload::Image { width, height, rgba_bytes, egui_texture, qr_decode_result } => {
                                                ui.horizontal(|ui| {
                                                    let texture = egui_texture.get_or_insert_with(|| {
                                                        let image_data = egui::ColorImage::from_rgba_unmultiplied([*width, *height], rgba_bytes);
                                                        ctx.load_texture("clipboard_img", image_data, egui::TextureOptions::LINEAR)
                                                    });
                                                    
                                                    let aspect = *width as f32 / *height as f32;
                                                    let max_h = 80.0_f32;
                                                    let thumb_size = egui::vec2(max_h * aspect, max_h);

                                                    if ui.add(egui::Image::new(&*texture).fit_to_exact_size(thumb_size).sense(egui::Sense::click()))
                                                         .on_hover_cursor(egui::CursorIcon::PointingHand)
                                                         .on_hover_text("Click to copy image")
                                                         .clicked() 
                                                    { 
                                                        self.selected_index = Some(idx);
                                                        image_to_copy = Some(("Image copied".to_string(), idx));
                                                    }
                                                    
                                                    if let Some(qr_text) = qr_decode_result {
                                                        ui.add_space(10.0);
                                                        ui.with_layout(egui::Layout::top_down(egui::Align::LEFT), |ui| {
                                                            ui.label(egui::RichText::new("QR Code:").color(egui::Color32::DARK_GREEN).strong().size(12.0));
                                                            let text_rich = egui::RichText::new(qr_text.clone()).size(14.0).color(text_color);
                                                            let label = egui::Label::new(text_rich).wrap(true).sense(egui::Sense::click());
                                                            if ui.add(label)
                                                                 .on_hover_cursor(egui::CursorIcon::PointingHand)
                                                                 .on_hover_text("Click to copy QR text")
                                                                 .clicked() 
                                                            { 
                                                                text_to_copy = Some(("QR text copied".to_string(), qr_text.clone()));
                                                            }
                                                        });
                                                    }
                                                });
                                            }
                                        }

                                        // DELETE BUTTON (Pushed to the far right)
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            let delete_btn = egui::Button::new(
                                                egui::RichText::new("🗑").color(egui::Color32::from_rgb(180, 50, 50)).size(14.0)
                                            ).fill(egui::Color32::TRANSPARENT).frame(false);
                                            
                                            if ui.add(delete_btn).on_hover_text("Delete this item").clicked() {
                                                delete_idx = Some(idx);
                                            }
                                        });

                                    });

                                    // --- OSINT RESULTS (VT & AbuseIPDB) ---
                                    if item.vt_status.is_some() || item.abuse_status.is_some() {
                                        ui.add_space(6.0);
                                        ui.horizontal(|ui| {
                                            
                                            // VirusTotal Clickable Result
                                            if let Some(status) = &item.vt_status {
                                                let (status_text, status_color) = match status {
                                                    VtStatus::Malicious(m, t) => (format!("VT: Malicious 🚨 [{}/{}]", m, t), egui::Color32::from_rgb(200, 0, 0)),
                                                    VtStatus::Suspicious(s, t) => (format!("VT: Suspicious ⚠️ [{}/{}]", s, t), egui::Color32::from_rgb(200, 100, 0)),
                                                    VtStatus::Clean(c, t) => (format!("VT: Clean ✅ [{}/{}]", c, t), egui::Color32::DARK_GREEN),
                                                    VtStatus::Unknown => ("VT: Unknown ❓".to_string(), egui::Color32::GRAY),
                                                };
                                                
                                                if ui.add(egui::Label::new(egui::RichText::new(status_text).color(status_color).strong().size(13.0)).sense(egui::Sense::click()))
                                                     .on_hover_cursor(egui::CursorIcon::PointingHand)
                                                     .on_hover_text("Click to copy VT Report")
                                                     .clicked() 
                                                {
                                                    if let HistoryPayload::Text(text_val) = &item.payload {
                                                        let defanged_ioc = crate::transformers::SmartFangTransformer::force_defang(text_val);
                                                        let report = match status {
                                                            VtStatus::Malicious(m, t) => format!("IOC: {} - VirusTotal: Malicious [{}/{}]", defanged_ioc, m, t),
                                                            VtStatus::Suspicious(s, t) => format!("IOC: {} - VirusTotal: Suspicious [{}/{}]", defanged_ioc, s, t),
                                                            VtStatus::Clean(c, t) => format!("IOC: {} - VirusTotal: Clean [{}/{}]", defanged_ioc, c, t),
                                                            VtStatus::Unknown => format!("IOC: {} - VirusTotal: Unknown", defanged_ioc),
                                                        };
                                                        text_to_copy = Some(("VT Report copied".to_string(), report));
                                                    }
                                                }
                                                ui.add_space(8.0);
                                            }

                                            // AbuseIPDB Clickable Result
                                            if let Some(status) = &item.abuse_status {
                                                let (text, color) = match status {
                                                    AbuseStatus::Malicious(score) => (format!("Abuse: {}% 🚨", score), egui::Color32::from_rgb(200, 0, 0)),
                                                    AbuseStatus::Suspicious(score) => (format!("Abuse: {}% ⚠️", score), egui::Color32::from_rgb(200, 100, 0)),
                                                    AbuseStatus::Clean(score) => (format!("Abuse: {}% ✅", score), egui::Color32::DARK_GREEN),
                                                };
                                                
                                                if ui.add(egui::Label::new(egui::RichText::new(text).color(color).strong().size(13.0)).sense(egui::Sense::click()))
                                                     .on_hover_cursor(egui::CursorIcon::PointingHand)
                                                     .on_hover_text("Click to copy AbuseIPDB Report")
                                                     .clicked() 
                                                {
                                                    if let HistoryPayload::Text(text_val) = &item.payload {
                                                        let defanged_ioc = crate::transformers::SmartFangTransformer::force_defang(text_val);
                                                        let report = match status {
                                                            AbuseStatus::Malicious(s) => format!("IOC: {} - AbuseIPDB: Malicious ({}%)", defanged_ioc, s),
                                                            AbuseStatus::Suspicious(s) => format!("IOC: {} - AbuseIPDB: Suspicious ({}%)", defanged_ioc, s),
                                                            AbuseStatus::Clean(s) => format!("IOC: {} - AbuseIPDB: Clean ({}%)", defanged_ioc, s),
                                                        };
                                                        text_to_copy = Some(("Abuse Report copied".to_string(), report));
                                                    }
                                                }
                                            }
                                        });
                                    }

                                    ui.add_space(6.0); 

                                    ui.horizontal_wrapped(|ui| {
                                        
                                        // 1. Internal IP badge (hardcoded, not a transformer)
                                        if let HistoryPayload::Text(_) = &item.payload {
                                            if item.indicator_type == IndicatorType::InternalIp {
                                                let internal_ip_btn = egui::Button::new(egui::RichText::new("INTERNAL").color(egui::Color32::DARK_RED).strong().size(11.0)).fill(egui::Color32::from_rgb(255, 200, 200));
                                                ui.add_sized(egui::vec2(70.0, 22.0), internal_ip_btn).on_hover_text("Private IP — no public threat intel available for this address.");
                                            }
                                        }

                                        // 2. Render Active Transformer Plugins dynamically
                                        for transformer in &self.transformer_manager.transformers {
                                            let label = transformer.name();
                                            
                                            // Check if user enabled it in settings
                                            if (*self.transformer_states.get(label).unwrap_or(&TransformerState::default())).is_active {
                                                
                                                // Ask the transformer if it supports Text/Image payloads
                                                let is_supported_payload = match &item.payload {
                                                    HistoryPayload::Text(_) => transformer.supports_text(),
                                                    HistoryPayload::Image { .. } => transformer.supports_image(),
                                                };

                                                if is_supported_payload {
                                                    
                                                    // DYNAMIC UI LOGIC: Let the Transformer dictate its visibility rules!
                                                    let mut show_btn = true;
                                                    
                                                    if let HistoryPayload::Text(text) = &item.payload {
                                                        // No point showing a public-lookup tool for a private/internal IP
                                                        if item.indicator_type == IndicatorType::InternalIp && transformer.requires_external_lookup() {
                                                            show_btn = false;
                                                        }
                                                        // Hide tools that don't support this specific indicator type (e.g. Abuse on Domains)
                                                        else if !transformer.is_supported_indicator(&item.indicator_type) {
                                                            show_btn = false;
                                                        }
                                                        // Hide tools that have nothing to do on this specific text (e.g. Unwrap without a safe link)
                                                        else if !transformer.is_applicable_to_text(text) {
                                                            show_btn = false;
                                                        }
                                                    }

                                                    if show_btn {
                                                        // The label may depend on the content (Fang -> Defang / Refang)
                                                        let short = match &item.payload {
                                                            HistoryPayload::Text(text) => transformer.short_name_for_text(text),
                                                            HistoryPayload::Image { .. } => std::borrow::Cow::Borrowed(transformer.short_name()),
                                                        };
                                                        // Ask the transformer for its preferred button width
                                                        let btn_size = egui::vec2(transformer.button_width(), 22.0);

                                                        if ui.add_sized(btn_size, egui::Button::new(short.as_ref())).on_hover_text(label).clicked() {
                                                            
                                                            let tx = self.event_tx.clone();
                                                            let action_name = label.to_string();
                                                            let ui_ctx = ctx.clone();
                                                            let original_text = match &item.payload { HistoryPayload::Text(t) => t.clone(), _ => "".to_string() };
                                                            
                                                            let (payload_text, img_w, img_h, img_bytes) = match &item.payload {
                                                                HistoryPayload::Text(t) => (Some(t.clone()), 0, 0, Vec::new()),
                                                                HistoryPayload::Image { width, height, rgba_bytes, .. } => (None, *width, *height, rgba_bytes.clone()),
                                                            };

                                                            let vt_key = if self.vt_api_key_input.trim().is_empty() { None } else { Some(self.vt_api_key_input.trim().to_string()) };
                                                            let abuse_key = if self.abuse_api_key_input.trim().is_empty() { None } else { Some(self.abuse_api_key_input.trim().to_string()) };
                                                            // Spawn background thread to process the action
                                                            std::thread::spawn(move || {
                                                                let transformer_mgr = TransformationManager::new();
                                                                if let Some(t) = transformer_mgr.transformers.iter().find(|t| t.name() == action_name) {
                                                                    let vk = vt_key.as_deref();
                                                                    let ak = abuse_key.as_deref();
                                                                    let result = if let Some(text) = payload_text {
                                                                        t.transform_text(&text,vk,ak)
                                                                    } else {
                                                                        t.transform_image(img_w, img_h, &img_bytes,vk,ak)
                                                                    };

                                                                    // Dispatch the outcome back to the GUI
                                                                    match result {
                                                                        Some(crate::transformers::TransformerResult::Text(transformed)) => {
                                                                            let _ = tx.send(AppEvent::TransformerResultText(action_name, transformed, idx));
                                                                            ui_ctx.request_repaint();
                                                                        }
                                                                        Some(crate::transformers::TransformerResult::OpenBrowser(url)) => {
                                                                            let _ = tx.send(AppEvent::TransformerResultBrowser(action_name, url));
                                                                            ui_ctx.request_repaint();
                                                                        }
                                                                        Some(crate::transformers::TransformerResult::ApiVtResult(status)) => {
                                                                            let _ = tx.send(AppEvent::VtResult(original_text, Ok(status)));
                                                                            ui_ctx.request_repaint();
                                                                        }
                                                                        Some(crate::transformers::TransformerResult::ApiAbuseResult(status)) => {
                                                                            let _ = tx.send(AppEvent::AbuseResult(original_text, Ok(status)));
                                                                            ui_ctx.request_repaint();
                                                                        }
                                                                        Some(crate::transformers::TransformerResult::ApiError(err_msg)) => {
                                                                            let _ = tx.send(AppEvent::Notification(format!("API Error: {err_msg}"), true));
                                                                            ui_ctx.request_repaint();
                                                                        }
                                                                        None => {
                                                                            let _ = tx.send(AppEvent::Notification("Operation skipped or no data.".to_string(), true));
                                                                            ui_ctx.request_repaint();
                                                                        }
                                                                    }
                                                                }
                                                            });
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    });
                                });
                            }); 
                            
                            // --- SMART AUTO-SCROLL ---
                            // Only trigger scroll if the user actually navigated using keyboard arrows
                            if selected && keyboard_navigated {
                                frame_response.response.scroll_to_me(Some(egui::Align::Center));
                            }
                            
                            ui.add_space(8.0); 
                        } // End of For Loop
                    }); // End ScrollArea

                    // --- END OF FRAME ACTIONS ---
                    
                    // 1. DELETE ITEM
                    if let Some(idx) = delete_idx {
                        self.history.remove(idx);
                        self.set_feedback_success("Item deleted.".to_string());
                        
                        // Reset selection if deleted items
                        if self.selected_index == Some(idx) {
                            self.selected_index = None;
                        } else if let Some(sel) = self.selected_index {
                            // Move selection to previous item
                            if idx < sel {
                                self.selected_index = Some(sel - 1);
                            }
                        }
                    }

                    // 2. TOGGLE PIN
                    if let Some(idx) = pin_toggled_idx {
                        let is_currently_pinned = self.history[idx].is_pinned;
                        let current_pins = self.history.iter().filter(|i| i.is_pinned).count();

                        let should_pin = if is_currently_pinned {
                            false
                        } else if current_pins < 3 {
                            true
                        } else {
                            self.set_feedback_error("Max 3 pinned items allowed!".to_string());
                            false
                        };

                        if is_currently_pinned != should_pin {
                            self.history[idx].is_pinned = should_pin;
                            self.history.sort_by_key(|item| !item.is_pinned);
                        }
                    }

                    // 3. COPY TEXT & DETERMINISTIC AUTO-PASTE
                    if let Some((label, text)) = text_to_copy {
                        self.last_copied_hash = Some(Self::calculate_hash(&text));
                        if self.clipboard.set_text(text).is_ok() {
                            self.set_feedback_success(format!("{label}!"));
                            
                            // Hide the Clipboard UI completely
                            crate::clipboard_listener::WINDOW_VISIBLE.store(false, std::sync::atomic::Ordering::SeqCst);
                            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                            
                            self.search_query.clear();

                            // We need to find our own HWND to tell the listener what to wait for
                            let title: Vec<u16> = "Defenders Clipboard\0".encode_utf16().collect();
                            let my_hwnd = unsafe { windows::Win32::UI::WindowsAndMessaging::FindWindowW(None, windows::core::PCWSTR(title.as_ptr())).unwrap_or_default() };
                            let my_hwnd_val = my_hwnd.0 as isize;

                            // Send the Paste command to the background listener
                            let _ = self.cmd_tx.send(ListenerCommand::PasteCommand(my_hwnd_val));

                        } else {
                            self.set_feedback_error("Error during copy.".to_string());
                        }
                    }

                    // 4. COPY IMAGE & DETERMINISTIC AUTO-PASTE
                    if let Some((label, idx)) = image_to_copy {
                        if let HistoryPayload::Image { width, height, rgba_bytes, .. } = &self.history[idx].payload {
                            self.last_copied_hash = Some(Self::calculate_hash(&rgba_bytes));
                            
                            let img_data = ImageData {
                                width: *width,
                                height: *height,
                                bytes: std::borrow::Cow::Borrowed(rgba_bytes)
                            };
                            
                            if self.clipboard.set_image(img_data).is_ok() {
                                self.set_feedback_success(format!("{label}!"));
                                
                                crate::clipboard_listener::WINDOW_VISIBLE.store(false, std::sync::atomic::Ordering::SeqCst);
                                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));

                                self.search_query.clear();

                                let title: Vec<u16> = "Defenders Clipboard\0".encode_utf16().collect();
                                let my_hwnd = unsafe { windows::Win32::UI::WindowsAndMessaging::FindWindowW(None, windows::core::PCWSTR(title.as_ptr())).unwrap_or_default() };
                                let my_hwnd_val = my_hwnd.0 as isize;
                                
                                let _ = self.cmd_tx.send(ListenerCommand::PasteCommand(my_hwnd_val));
                                
                            } else {
                                self.set_feedback_error("Failed to copy image.".to_string());
                            }
                        }
                    }
                }
            });
        });
    }
}