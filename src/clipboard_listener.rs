use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::os::windows::ffi::OsStringExt;

use sha2::{Sha256, Digest};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM, POINT, RECT};
use windows::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MonitorFromPoint, MONITORINFO, MONITOR_DEFAULTTONEAREST, MONITOR_DEFAULTTOPRIMARY,
};
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, RemoveClipboardFormatListener,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN, MOD_NOREPEAT, UnregisterHotKey, RegisterHotKey,
    VK_SPACE, VK_RETURN, VK_TAB, VK_ESCAPE, VK_BACK, VK_UP, VK_DOWN, VK_LEFT, VK_RIGHT,
    VK_F1, VK_F2, VK_F3, VK_F4, VK_F5, VK_F6, VK_F7, VK_F8, VK_F9, VK_F10, VK_F11, VK_F12,
    VkKeyScanW, SendInput, INPUT, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, VK_CONTROL, VK_V
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, RegisterClassW,
    TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, HWND_MESSAGE, MSG, WNDCLASSW,
    WM_CREATE, WM_DESTROY, WM_HOTKEY, WS_OVERLAPPEDWINDOW, WM_CLIPBOARDUPDATE,
    FindWindowW, ShowWindow, SW_HIDE, SW_SHOW, 
    GetCursorPos, GetWindowRect, SetWindowPos, HWND_TOPMOST, SWP_NOSIZE,
    WM_APP, WM_COMMAND, WM_RBUTTONUP, WM_LBUTTONUP, WM_QUIT,
    CreatePopupMenu, AppendMenuW, TrackPopupMenu, DestroyMenu,
    MF_STRING, TPM_RIGHTBUTTON, TPM_BOTTOMALIGN, TPM_LEFTALIGN,
    LoadIconW, IDI_APPLICATION,
    SetWindowLongW, GetWindowLongW, GWL_EXSTYLE, WS_EX_NOACTIVATE,
    PostQuitMessage, GetForegroundWindow
};
use windows::Win32::UI::Shell::{
    NOTIFYICONDATAW, Shell_NotifyIconW, NIM_ADD, NIM_DELETE, NIF_ICON, NIF_MESSAGE, NIF_TIP,
    DragQueryFileW, HDROP
};

use arboard::Clipboard;
use crate::events::{AppEvent, ClipboardImage, HotkeyConfig, ListenerCommand};

const HOTKEY_ID: i32 = 1;
const WM_APP_TRAYMSG: u32 = WM_APP + 1;
const ID_TRAY_SETTINGS: usize = 2001;
const ID_TRAY_EXIT: usize = 2002;

static APP_EVENT_SENDER: OnceLock<Mutex<Sender<AppEvent>>> = OnceLock::new();
static LISTENER_COMMAND_RX: OnceLock<Mutex<Receiver<ListenerCommand>>> = OnceLock::new();
pub static GUI_CONTEXT: OnceLock<eframe::egui::Context> = OnceLock::new();

// Keeps track of the logical visibility of the UI window
pub static WINDOW_VISIBLE: AtomicBool = AtomicBool::new(true);

// Where the window opens: next to the mouse pointer (true) or centered on the primary monitor.
// Kept in sync with the "open at cursor" setting by the GUI.
pub static OPEN_AT_CURSOR: AtomicBool = AtomicBool::new(true);

static CLIPBOARD_READER: OnceLock<Mutex<Clipboard>> = OnceLock::new();

pub fn start_clipboard_listener(sender: Sender<AppEvent>, cmd_rx: Receiver<ListenerCommand>) {
    let _ = APP_EVENT_SENDER.set(Mutex::new(sender));
    let _ = LISTENER_COMMAND_RX.set(Mutex::new(cmd_rx));
    let _ = CLIPBOARD_READER.set(Mutex::new(Clipboard::new().expect("Failed to initialize clipboard reader")));
    
    // Spawn the primary Win32 Message Loop
    thread::spawn(|| unsafe { run_message_loop(); });

    // --- WINDOW HUNTER THREAD ---
    // eframe creates the window asynchronously. This thread waits for the window to spawn
    // and immediately injects the WS_EX_NOACTIVATE style to prevent keyboard focus stealing.
    thread::spawn(|| unsafe {
        let title: Vec<u16> = "Defenders Clipboard\0".encode_utf16().collect();
        loop {
            if let Ok(egui_hwnd) = FindWindowW(None, PCWSTR(title.as_ptr())) {
                if !egui_hwnd.0.is_null() {
                    let current_ex_style = GetWindowLongW(egui_hwnd, GWL_EXSTYLE);
                    let _ = SetWindowLongW(
                        egui_hwnd, 
                        GWL_EXSTYLE, 
                        current_ex_style | (WS_EX_NOACTIVATE.0 as i32)
                    );
                    break; 
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
}

fn wake_up_gui() {
    if let Some(ctx) = GUI_CONTEXT.get() { ctx.request_repaint(); }
}

/// Converts a string representation of a key (e.g., "V", "SPACE", "è") into a Windows Virtual Key Code.
/// It uses the OS mapping to perfectly match special characters on any keyboard layout!
fn get_vk_code(key: &str) -> u32 {
    
    // 1. Explicit mapping for non-printable or system keys (we uppercase them to easily match "SPACE", "space", etc.)
    let upper_key = key.to_uppercase();
    match upper_key.as_str() {
        "SPACE" => return VK_SPACE.0 as u32,
        "ENTER" => return VK_RETURN.0 as u32,
        "TAB" => return VK_TAB.0 as u32,
        "ESC" => return VK_ESCAPE.0 as u32,
        "BACKSPACE" => return VK_BACK.0 as u32,
        "UP" => return VK_UP.0 as u32,
        "DOWN" => return VK_DOWN.0 as u32,
        "LEFT" => return VK_LEFT.0 as u32,
        "RIGHT" => return VK_RIGHT.0 as u32,
        "F1" => return VK_F1.0 as u32,
        "F2" => return VK_F2.0 as u32,
        "F3" => return VK_F3.0 as u32,
        "F4" => return VK_F4.0 as u32,
        "F5" => return VK_F5.0 as u32,
        "F6" => return VK_F6.0 as u32,
        "F7" => return VK_F7.0 as u32,
        "F8" => return VK_F8.0 as u32,
        "F9" => return VK_F9.0 as u32,
        "F10" => return VK_F10.0 as u32,
        "F11" => return VK_F11.0 as u32,
        "F12" => return VK_F12.0 as u32,
        _ => {}
    }

    // 2. Mapping for single characters (A-Z, 0-9, and Special chars like 'è', '+', '-')
    // We use the ORIGINAL exact character (case-sensitive) without uppercasing it.
    // This is crucial for accented letters, as 'è' and 'È' are different states for VkKeyScanW!
    if let Some(ch) = key.chars().next() {
        unsafe {
            // Encode the character to UTF-16 for the Windows API
            let mut utf16_char = [0; 2];
            let encoded = ch.encode_utf16(&mut utf16_char);
            
            if !encoded.is_empty() {
                let vk_result = VkKeyScanW(encoded[0]);
                
                // If the key is valid (not -1), the lower byte contains the exact Virtual Key Code!
                if vk_result != -1 {
                    let vk = (vk_result & 0xFF) as u32;
                    return vk;
                }
            }
        }
    }

    // Fallback if everything fails
    0x56 // 'V'
}
unsafe fn apply_hotkey(hwnd: HWND, config: &HotkeyConfig) {
    let _ = UnregisterHotKey(hwnd, HOTKEY_ID);
    
    let mut modifiers = MOD_NOREPEAT;
    if config.ctrl { modifiers |= MOD_CONTROL; }
    if config.alt { modifiers |= MOD_ALT; }
    if config.shift { modifiers |= MOD_SHIFT; }
    if config.win { modifiers |= MOD_WIN; }
    
    let vk_code = get_vk_code(&config.key);
    let _ = RegisterHotKey(hwnd, HOTKEY_ID, modifiers, vk_code);
}

/// Simulates a physical keyboard pressing 'Ctrl + V'
pub fn simulate_paste() {
    unsafe {
        let input_ctrl_down = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
                ki: KEYBDINPUT { wVk: VK_CONTROL, wScan: 0, dwFlags: windows::Win32::UI::Input::KeyboardAndMouse::KEYBD_EVENT_FLAGS(0), time: 0, dwExtraInfo: 0 },
            },
        };

        let input_v_down = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
                ki: KEYBDINPUT { wVk: VK_V, wScan: 0, dwFlags: windows::Win32::UI::Input::KeyboardAndMouse::KEYBD_EVENT_FLAGS(0), time: 0, dwExtraInfo: 0 },
            },
        };

        let input_v_up = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
                ki: KEYBDINPUT { wVk: VK_V, wScan: 0, dwFlags: KEYEVENTF_KEYUP, time: 0, dwExtraInfo: 0 },
            },
        };

        let input_ctrl_up = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
                ki: KEYBDINPUT { wVk: VK_CONTROL, wScan: 0, dwFlags: KEYEVENTF_KEYUP, time: 0, dwExtraInfo: 0 },
            },
        };

        let inputs = [input_ctrl_down, input_v_down, input_v_up, input_ctrl_up];
        let _ = SendInput(&inputs, std::mem::size_of::<INPUT>() as i32);
    }
}


/// Moves the window where it should open: just below the mouse pointer on whichever
/// monitor the pointer is (default), or centered on the primary monitor. Either way it
/// is kept inside the monitor's work area (so never under the taskbar or off-screen),
/// and the window's real size is used rather than a hardcoded one.
unsafe fn place_window(hwnd: HWND) {
    let at_cursor = OPEN_AT_CURSOR.load(Ordering::SeqCst);

    let mut cursor = POINT::default();
    let _ = GetCursorPos(&mut cursor);

    let (anchor, flags) = if at_cursor {
        (cursor, MONITOR_DEFAULTTONEAREST)
    } else {
        (POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY)
    };
    let monitor = MonitorFromPoint(anchor, flags);
    let mut info = MONITORINFO { cbSize: std::mem::size_of::<MONITORINFO>() as u32, ..Default::default() };
    if !GetMonitorInfoW(monitor, &mut info).as_bool() { return; }
    let work = info.rcWork;

    // Moving to a monitor with a different DPI rescales the window, so the size is
    // measured again after the first move and the position fixed up if it changed.
    let mut last_size = (0, 0);
    for _ in 0..2 {
        let mut rect = RECT::default();
        if GetWindowRect(hwnd, &mut rect).is_err() { return; }
        let (w, h) = (rect.right - rect.left, rect.bottom - rect.top);
        if (w, h) == last_size { break; }
        last_size = (w, h);

        let (x, y) = compute_position(
            (work.left, work.top, work.right, work.bottom),
            (cursor.x, cursor.y),
            (w, h),
            at_cursor,
        );
        let _ = SetWindowPos(hwnd, HWND_TOPMOST, x, y, 0, 0, SWP_NOSIZE);
    }
}

/// Pure placement math (no Win32), so it can be unit-tested.
/// `work` is (left, top, right, bottom) of the monitor's work area, `size` the window's (w, h).
/// Returns the top-left corner: at the pointer (flipped above it when there's no room
/// below) or centered, and in both cases kept fully inside `work` (the left/top edge wins
/// if the window is bigger than the area).
fn compute_position(
    work: (i32, i32, i32, i32),
    cursor: (i32, i32),
    size: (i32, i32),
    at_cursor: bool,
) -> (i32, i32) {
    let (left, top, right, bottom) = work;
    let (w, h) = size;

    let (x, y) = if at_cursor {
        let y = if cursor.1 + h > bottom { cursor.1 - h } else { cursor.1 };
        (cursor.0, y)
    } else {
        (left + (right - left - w) / 2, top + (bottom - top - h) / 2)
    };

    (x.min(right - w).max(left), y.min(bottom - h).max(top))
}

#[cfg(test)]
mod tests;

unsafe fn run_message_loop() {
    let class_name: Vec<u16> = "DefendersClipboardListener\0".encode_utf16().collect();
    let module = GetModuleHandleW(None).unwrap_or_default();
    let h_instance = HINSTANCE(module.0);

    let wnd_class = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(window_proc),
        hInstance: h_instance,
        lpszClassName: PCWSTR(class_name.as_ptr()),
        ..Default::default()
    };

    if RegisterClassW(&wnd_class) == 0 { return; }

    let hwnd = CreateWindowExW(
        Default::default(), PCWSTR(class_name.as_ptr()), PCWSTR(class_name.as_ptr()),
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        HWND_MESSAGE, None, h_instance, None,
    ).expect("CreateWindowExW failed");

    let _ = AddClipboardFormatListener(hwnd);
    
    // Register the default hotkey initially. Will be overridden by config file instantly.
    apply_hotkey(hwnd, &HotkeyConfig::default());

    // --- SYSTEM TRAY ICON SETUP ---
    let mut nid = NOTIFYICONDATAW::default();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_APP_TRAYMSG;
    
    // Load the custom icon embedded by build.rs (Resource ID 1)
    let resource_id = PCWSTR(1_usize as *const u16);
    let h_icon_embedded = LoadIconW(h_instance, resource_id);

    if let Ok(handle) = h_icon_embedded {
        nid.hIcon = handle;
    } else {
        // Fallback to the stock system icon; if even that fails, leave hIcon at its
        // zeroed default rather than panicking (panic = "abort" would kill the whole app).
        nid.hIcon = LoadIconW(None, IDI_APPLICATION).unwrap_or_default();
    }

    let tip_text = "Defenders Clipboard\0".encode_utf16().collect::<Vec<u16>>();
    for (i, &c) in tip_text.iter().enumerate() {
        if i < nid.szTip.len() { nid.szTip[i] = c; }
    }
    let _ = Shell_NotifyIconW(NIM_ADD, &nid);

    let mut msg = MSG::default();
    loop {
        // PeekMessageW prevents blocking the thread, allowing us to read the MPSC channel too
        while windows::Win32::UI::WindowsAndMessaging::PeekMessageW(&mut msg, None, 0, 0, windows::Win32::UI::WindowsAndMessaging::PM_REMOVE).into() {
            if msg.message == WM_QUIT {
                return;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        // Listen for internal commands sent by the Main GUI Thread
        if let Some(mutex) = LISTENER_COMMAND_RX.get() {
            if let Ok(rx) = mutex.lock() {
                if let Ok(cmd) = rx.try_recv() {
                    match cmd {
                        ListenerCommand::UpdateHotkey(config) => {
                            apply_hotkey(hwnd, &config);
                        }
                        ListenerCommand::PasteCommand(my_hwnd_val) => {
                            // Spawn a background thread so we don't block the main message loop
                            std::thread::spawn(move || {
                                unsafe {
                                    // DETERMINISTIC FOCUS WAITING
                                    // We actively poll the OS to see which window is currently in the foreground.
                                    // We wait until OUR window (my_hwnd_val) is NO LONGER the active one.
                                    // This guarantees that the target application has fully regained focus.
                                    
                                    let mut attempts = 0;
                                    loop {
                                        let current_fg = GetForegroundWindow().0 as isize;
                                        
                                        // If the foreground window has changed, we are ready to paste!
                                        if current_fg != my_hwnd_val {
                                            // Tiny micro-sleep just to let the target app UI settle 
                                            // (sometimes focus changes but the text caret needs 10ms to blink)
                                            std::thread::sleep(std::time::Duration::from_millis(15));
                                            simulate_paste();
                                            break;
                                        }
                                        
                                        attempts += 1;
                                        // Safety timeout: If after 1 second (100 * 10ms) we still have focus, 
                                        // abort to prevent an infinite loop.
                                        if attempts > 100 {
                                            break;
                                        }
                                        
                                        std::thread::sleep(std::time::Duration::from_millis(10));
                                    }
                                }
                            });
                        }
                    }
                    }
                }
            }
        }
    }

extern "system" fn window_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_CREATE => LRESULT(0),
            
            // --- SYSTEM TRAY CONTEXT MENU ---
            WM_APP_TRAYMSG => {
                let event = lparam.0 as u32;
                if event == WM_RBUTTONUP || event == WM_LBUTTONUP {
                    let mut pt = POINT::default();
                    let _ = GetCursorPos(&mut pt);

                    // If menu creation fails (rare OS resource exhaustion), skip showing the
                    // context menu instead of unwrapping and aborting the whole application.
                    if let Ok(hmenu) = CreatePopupMenu() {
                        let text_settings: Vec<u16> = "Settings\0".encode_utf16().collect();
                        let text_exit: Vec<u16> = "Exit\0".encode_utf16().collect();

                        let _ = AppendMenuW(hmenu, MF_STRING, ID_TRAY_SETTINGS, PCWSTR(text_settings.as_ptr()));
                        let _ = AppendMenuW(hmenu, MF_STRING, ID_TRAY_EXIT, PCWSTR(text_exit.as_ptr()));

                        // Force foreground to allow the menu to close if clicked outside
                        let _ = windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow(hwnd);

                        let _ = TrackPopupMenu(
                            hmenu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, None,
                        );
                        let _ = DestroyMenu(hmenu);
                    }
                }
                LRESULT(0)
            }
            
            // --- TRAY MENU ACTIONS ---
            WM_COMMAND => {
                let menu_id = (wparam.0 & 0xFFFF) as usize;
                if let Some(mutex) = APP_EVENT_SENDER.get() {
                    if let Ok(sender) = mutex.lock() {
                        match menu_id {
                            ID_TRAY_SETTINGS => {
                                let _ = sender.send(AppEvent::OpenSettings);
                                WINDOW_VISIBLE.store(true, std::sync::atomic::Ordering::SeqCst);
                                let title: Vec<u16> = "Defenders Clipboard\0".encode_utf16().collect();
                                
                                if let Ok(egui_hwnd) = FindWindowW(None, PCWSTR(title.as_ptr())) {
                                    place_window(egui_hwnd);
                                    let _ = ShowWindow(egui_hwnd, SW_SHOW);
                                }
                            }
                            ID_TRAY_EXIT => {
                                // Gracefully remove the Tray icon before hard exiting
                                let mut nid = NOTIFYICONDATAW::default();
                                nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
                                nid.hWnd = hwnd;
                                nid.uID = 1;
                                let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
                                std::process::exit(0);
                            }
                            _ => {}
                        }
                    }
                }
                LRESULT(0)
            }

            WM_CLIPBOARDUPDATE => {
                if let Some(event) = read_clipboard_smart() {
                    if let Some(mutex) = APP_EVENT_SENDER.get() {
                        if let Ok(sender) = mutex.lock() {
                            let _ = sender.send(event);
                            wake_up_gui();
                        }
                    }
                }
                LRESULT(0)
            }
            
            // --- GLOBAL HOTKEY TRIGGER ---
            WM_HOTKEY => {
                let was_visible = WINDOW_VISIBLE.fetch_xor(true, std::sync::atomic::Ordering::SeqCst);
                let new_state = !was_visible;

                let title: Vec<u16> = "Defenders Clipboard\0".encode_utf16().collect();
                if let Ok(egui_hwnd) = FindWindowW(None, PCWSTR(title.as_ptr())) {
                    if new_state {
                        
                         if let Some(mutex) = APP_EVENT_SENDER.get() {
                            if let Ok(sender) = mutex.lock() {
                                let _ = sender.send(AppEvent::AppWokeUp);
                            }
                        }
                        
                        if let Some(ctx) = GUI_CONTEXT.get() {
                            ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Visible(true));
                            ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Focus); 
                        }

                        place_window(egui_hwnd);

                        let _ = ShowWindow(egui_hwnd, windows::Win32::UI::WindowsAndMessaging::SW_SHOW);
                        let _ = windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow(egui_hwnd);
                    } else {
                        if let Some(ctx) = GUI_CONTEXT.get() {
                            ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Visible(false));
                        }
                        let _ = ShowWindow(egui_hwnd, SW_HIDE);
                    }
                }
                LRESULT(0)
            }
            
            WM_DESTROY => {
                let mut nid = NOTIFYICONDATAW::default();
                nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
                nid.hWnd = hwnd;
                nid.uID = 1;
                let _ = Shell_NotifyIconW(NIM_DELETE, &nid);

                let _ = RemoveClipboardFormatListener(hwnd);
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

/// Safely polls the OS Clipboard to extract Files, Images, or Text
fn read_clipboard_smart() -> Option<AppEvent> {
    if let Some(mutex) = CLIPBOARD_READER.get() {
        if let Ok(mut clipboard) = mutex.lock() {
            
            // 50ms delay to allow other apps (like Chrome/Explorer) to release the clipboard lock
            std::thread::sleep(std::time::Duration::from_millis(50));

            // 1. TRY PHYSICAL FILE (CF_HDROP)
            unsafe {
                if windows::Win32::System::DataExchange::OpenClipboard(HWND(std::ptr::null_mut())).is_ok() {
                    let hdrop_format = 15; 
                    if let Ok(handle) = windows::Win32::System::DataExchange::GetClipboardData(hdrop_format) {
                        let hdrop = HDROP(handle.0 as _);
                        let file_count = DragQueryFileW(hdrop, 0xFFFFFFFF, None);
                        
                        // Process only single file copies to prevent application freezes
                        if file_count == 1 {
                            let mut buffer = [0u16; 1024]; 
                            let len = DragQueryFileW(hdrop, 0, Some(&mut buffer));
                            
                            if len > 0 {
                                let path_string = std::ffi::OsString::from_wide(&buffer[..len as usize]);
                                if let Some(path_str) = path_string.to_str() {
                                    
                                    let file_path = std::path::Path::new(path_str);
                                    let file_name = file_path.file_name().unwrap_or_default().to_string_lossy().to_string();
                                    
                                    if file_path.is_file() {
                                        if let Ok(mut file) = std::fs::File::open(file_path) {
                                            use std::io::Read;
                                            let mut hasher = Sha256::new();
                                            let mut read_buffer = [0u8; 8192];
                                            
                                            // Soft Limit: Skip computing hash for files > 100MB
                                            if let Ok(meta) = file.metadata() {
                                                if meta.len() < 100_000_000 {
                                                    while let Ok(bytes_read) = file.read(&mut read_buffer) {
                                                        if bytes_read == 0 { break; }
                                                        hasher.update(&read_buffer[..bytes_read]);
                                                    }
                                                    
                                                    let hash_result = hasher.finalize();
                                                    let hex_string: String = hash_result.iter().map(|b| format!("{:02x}", b)).collect();

                                                    let _ = windows::Win32::System::DataExchange::CloseClipboard();
                                                    return Some(AppEvent::ClipboardUpdatedFileHash(file_name, hex_string));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    let _ = windows::Win32::System::DataExchange::CloseClipboard();
                }
            }

            // 2. TRY PLAIN TEXT FIRST!
            // Programs like Excel put BOTH text and an image of the cell into the clipboard.
            // By requesting text first, we get the actual data instead of a useless screenshot.
            if let Ok(text) = clipboard.get_text() {
                if !text.trim().is_empty() {
                    return Some(AppEvent::ClipboardUpdatedText(text));
                }
            }

            // 3. TRY IMAGE FALLBACK
            // Only capture images if there is absolutely no text available (e.g. Snipping Tool)
            if let Ok(img) = clipboard.get_image() {
                let bytes = img.bytes.into_owned();
                if !bytes.is_empty() {
                    return Some(AppEvent::ClipboardUpdatedImage(ClipboardImage {
                        width: img.width,
                        height: img.height,
                        bytes,
                    }));
                }
            }
        }
    }
    None
}