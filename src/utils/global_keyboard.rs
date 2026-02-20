//! Global keyboard listener using rdev.
//!
//! This module provides cross-platform global keyboard event capture
//! that works even when the application is not in focus.

use rdev::{Event, EventType, Key};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// A captured keyboard event.
#[derive(Debug, Clone)]
pub struct CapturedKey {
    /// The key that was pressed or released.
    pub key: String,
    /// Whether the key was pressed (true) or released (false).
    pub is_press: bool,
}

/// Global keyboard listener that captures all keyboard events.
pub struct GlobalKeyboardListener {
    /// Channel to send captured key events.
    tx: mpsc::UnboundedSender<CapturedKey>,
    /// Flag to stop the listener.
    running: Arc<AtomicBool>,
    /// Whether the listener is currently enabled.
    enabled: Arc<AtomicBool>,
}

impl GlobalKeyboardListener {
    /// Create a new global keyboard listener.
    pub fn new() -> (Self, mpsc::UnboundedReceiver<CapturedKey>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let running = Arc::new(AtomicBool::new(false));
        let enabled = Arc::new(AtomicBool::new(false));
        
        (Self { tx, running, enabled }, rx)
    }

    /// Start listening for global keyboard events.
    /// This spawns a background thread that captures all keyboard events.
    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            // Already running
            return;
        }

        let tx = self.tx.clone();
        let running = self.running.clone();
        let enabled = self.enabled.clone();

        info!(event = "global_keyboard_start", "Starting global keyboard listener");

        std::thread::spawn(move || {
            let callback = move |event: Event| {
                if !running.load(Ordering::SeqCst) {
                    return;
                }

                if !enabled.load(Ordering::SeqCst) {
                    return;
                }

                let (key, is_press) = match event.event_type {
                    EventType::KeyPress(k) => (key_to_string(k), true),
                    EventType::KeyRelease(k) => (key_to_string(k), false),
                    _ => return,
                };

                if key.is_empty() {
                    return;
                }

                // Only send key press events (not releases)
                if is_press {
                    if tx.send(CapturedKey { key, is_press }).is_err() {
                        debug!("Global keyboard listener channel closed");
                    }
                }
            };

            if let Err(e) = rdev::listen(callback) {
                error!(event = "global_keyboard_error", error = %format!("{:?}", e), "Global keyboard listener error");
            }
        });
    }

    /// Stop listening for global keyboard events.
    pub fn stop(&self) {
        info!(event = "global_keyboard_stop", "Stopping global keyboard listener");
        self.running.store(false, Ordering::SeqCst);
    }

    /// Enable or disable capturing keyboard events.
    /// When disabled, the listener still runs but doesn't send events.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
        debug!(
            event = "global_keyboard_enabled",
            enabled = enabled,
            "Global keyboard listener enabled state changed"
        );
    }

    /// Check if the listener is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Check if the listener is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

impl Drop for GlobalKeyboardListener {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Convert an rdev Key to a string representation.
fn key_to_string(key: Key) -> String {
    match key {
        // Letters
        Key::KeyA => "a",
        Key::KeyB => "b",
        Key::KeyC => "c",
        Key::KeyD => "d",
        Key::KeyE => "e",
        Key::KeyF => "f",
        Key::KeyG => "g",
        Key::KeyH => "h",
        Key::KeyI => "i",
        Key::KeyJ => "j",
        Key::KeyK => "k",
        Key::KeyL => "l",
        Key::KeyM => "m",
        Key::KeyN => "n",
        Key::KeyO => "o",
        Key::KeyP => "p",
        Key::KeyQ => "q",
        Key::KeyR => "r",
        Key::KeyS => "s",
        Key::KeyT => "t",
        Key::KeyU => "u",
        Key::KeyV => "v",
        Key::KeyW => "w",
        Key::KeyX => "x",
        Key::KeyY => "y",
        Key::KeyZ => "z",
        
        // Numbers
        Key::Num0 => "0",
        Key::Num1 => "1",
        Key::Num2 => "2",
        Key::Num3 => "3",
        Key::Num4 => "4",
        Key::Num5 => "5",
        Key::Num6 => "6",
        Key::Num7 => "7",
        Key::Num8 => "8",
        Key::Num9 => "9",
        
        // Function keys (F1-F12 are supported by rdev)
        Key::F1 => "F1",
        Key::F2 => "F2",
        Key::F3 => "F3",
        Key::F4 => "F4",
        Key::F5 => "F5",
        Key::F6 => "F6",
        Key::F7 => "F7",
        Key::F8 => "F8",
        Key::F9 => "F9",
        Key::F10 => "F10",
        Key::F11 => "F11",
        Key::F12 => "F12",
        
        // Special keys
        Key::Return => "Enter",
        Key::Escape => "Esc",
        Key::Backspace => "Backspace",
        Key::Tab => "Tab",
        Key::Space => "Space",
        Key::Delete => "Delete",
        Key::Insert => "Insert",
        Key::Home => "Home",
        Key::End => "End",
        Key::PageUp => "PageUp",
        Key::PageDown => "PageDown",
        
        // Arrow keys
        Key::UpArrow => "Up",
        Key::DownArrow => "Down",
        Key::LeftArrow => "Left",
        Key::RightArrow => "Right",
        
        // Symbols
        Key::Minus => "-",
        Key::Equal => "=",
        Key::LeftBracket => "[",
        Key::RightBracket => "]",
        Key::BackSlash => "\\",
        Key::SemiColon => ";",
        Key::Quote => "'",
        Key::Comma => ",",
        Key::Dot => ".",
        Key::Slash => "/",
        
        // Modifiers (we still capture these but they're special)
        Key::ShiftLeft | Key::ShiftRight => "Shift",
        Key::ControlLeft | Key::ControlRight => "Ctrl",
        Key::Alt => "Alt",
        Key::AltGr => "AltGr",
        Key::MetaLeft | Key::MetaRight => "Meta",
        Key::CapsLock => "CapsLock",
        Key::NumLock => "NumLock",
        Key::ScrollLock => "ScrollLock",
        
        // Other keys
        Key::PrintScreen => "PrintScreen",
        Key::Pause => "Pause",
        
        // Unknown
        _ => "",
    }.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_listener_creation() {
        let (listener, _rx) = GlobalKeyboardListener::new();
        assert!(!listener.is_running());
        assert!(!listener.is_enabled());
    }

    #[test]
    fn test_enable_disable() {
        let (listener, _rx) = GlobalKeyboardListener::new();
        listener.set_enabled(true);
        assert!(listener.is_enabled());
        listener.set_enabled(false);
        assert!(!listener.is_enabled());
    }
}
