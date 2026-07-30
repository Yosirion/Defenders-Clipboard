use crate::api::{VtStatus, AbuseStatus};
use serde::{Deserialize, Serialize};

/// Commands sent from the GUI to the Win32 Listener
#[derive(Clone, Debug)]
pub enum ListenerCommand {
    /// Update the global hotkey registered in Windows
    UpdateHotkey(HotkeyConfig),
    
    /// Trigger the deterministic Auto-Paste.
    /// Passes the HWND (as isize) of our application so the listener knows 
    /// what to wait for before firing the Ctrl+V keystroke.
    PasteCommand(isize), 
}


/// Represents an image copied to the Windows clipboard.
#[derive(Clone, Debug)]
pub struct ClipboardImage {
    pub width: usize,
    pub height: usize,
    pub bytes: Vec<u8>, // Raw RGBA pixel format
}

/// Stores the configuration for the global shortcut used to summon the app.
#[derive(Clone, Debug, PartialEq,  Serialize, Deserialize)]
pub struct HotkeyConfig {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub win: bool,
    pub key: String, 
}

impl Default for HotkeyConfig {
    fn default() -> Self {
        Self {
            ctrl: true,
            alt: true,
            shift: false,
            win: false,
            key: "V".to_string(), // Default hotkey: Ctrl + Alt + V
        }
    }
}

/// Events sent from the background worker threads to the main GUI thread.
#[derive(Clone, Debug)]
pub enum AppEvent {
    /// A new text string was copied to the clipboard.
    ClipboardUpdatedText(String),
    
    /// A new image (screenshot) was copied to the clipboard.
    ClipboardUpdatedImage(ClipboardImage),
    
    /// A physical file was copied. Contains (File Name, Computed SHA-256 Hash).
    ClipboardUpdatedFileHash(String, String),
    
    /// An asynchronous VirusTotal API lookup finished.
    VtResult(String, Result<VtStatus, String>),
    
    /// An asynchronous AbuseIPDB API lookup finished.
    AbuseResult(String, Result<AbuseStatus, String>),
    
    /// A UI notification payload. Tuple is (Message, Is_Error).
    Notification(String, bool),
    
    /// Command to open the Settings panel from the System Tray.
    OpenSettings,
    //  App wake app
    AppWokeUp,
    /// Result from a background Transformer task returning modified text.
    /// (Action Name, Resulting Text, History Index)
    TransformerResultText(String, String, usize),
    
    /// Result from a background Transformer task requesting to open a URL.
    /// (Action Name, Target URL)
    TransformerResultBrowser(String, String),
}

