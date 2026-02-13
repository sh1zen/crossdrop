//! User-facing notification system for the TUI status bar.
//!
//! Provides concise, level-aware notifications with auto-expiry.
//! All user-visible messages MUST go through this module — verbose
//! details belong in `tracing` logs, not in the status bar.
//!
//! Design:
//! - Notifications auto-expire based on severity (info: 5s, error: 10s).
//! - Only one notification is active at a time (newest wins).
//! - Rendering picks color from the level.
//! - If no notification is active, the UI falls back to help text.

use ratatui::style::Color;
use std::time::{Duration, Instant};

// ── Notification Level ───────────────────────────────────────────────────────

/// Severity of a user-facing notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyLevel {
    /// Neutral informational message (e.g. "Downloading…").
    Info,
    /// Positive outcome (e.g. "Connected", "Transfer complete").
    Success,
    /// Non-critical issue (e.g. "Cancelled", "Peer offline").
    Warning,
    /// Actionable error (e.g. "Transfer failed").
    Error,
}

impl NotifyLevel {
    /// Terminal color for the notification text.
    pub fn color(self) -> Color {
        match self {
            NotifyLevel::Info => Color::Cyan,
            NotifyLevel::Success => Color::Green,
            NotifyLevel::Warning => Color::Yellow,
            NotifyLevel::Error => Color::Red,
        }
    }

    /// How long the notification stays visible before auto-expiring.
    fn ttl(self) -> Duration {
        match self {
            NotifyLevel::Info => Duration::from_secs(5),
            NotifyLevel::Success => Duration::from_secs(5),
            NotifyLevel::Warning => Duration::from_secs(8),
            NotifyLevel::Error => Duration::from_secs(10),
        }
    }

    /// Single-char prefix for the notification (for quick visual scan).
    pub fn icon(self) -> &'static str {
        match self {
            NotifyLevel::Info => "(i)",
            NotifyLevel::Success => "",
            NotifyLevel::Warning => "(x)",
            NotifyLevel::Error => "(!)",
        }
    }
}

// ── Notification ─────────────────────────────────────────────────────────────

/// A single user-facing notification.
#[derive(Debug, Clone)]
pub struct Notification {
    pub level: NotifyLevel,
    pub message: String,
    created_at: Instant,
    ttl: Duration,
}

impl Notification {
    fn new(level: NotifyLevel, message: impl Into<String>) -> Self {
        Self {
            ttl: level.ttl(),
            level,
            message: message.into(),
            created_at: Instant::now(),
        }
    }

    /// Whether this notification has expired and should no longer be shown.
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.ttl
    }
}

// ── Notify Manager ───────────────────────────────────────────────────────────

/// Manages the single active user-facing notification.
///
/// Only the most recent notification is kept. Expired notifications
/// are automatically hidden — the UI falls back to help text.
pub struct NotifyManager {
    current: Option<Notification>,
}

impl NotifyManager {
    pub fn new() -> Self {
        Self { current: None }
    }

    // ── Push helpers (one per level) ─────────────────────────────────────

    /// Show an informational message (auto-expires in 5s).
    pub fn info(&mut self, message: impl Into<String>) {
        self.current = Some(Notification::new(NotifyLevel::Info, message));
    }

    /// Show a success message (auto-expires in 5s).
    pub fn success(&mut self, message: impl Into<String>) {
        self.current = Some(Notification::new(NotifyLevel::Success, message));
    }

    /// Show a warning message (auto-expires in 8s).
    pub fn warn(&mut self, message: impl Into<String>) {
        self.current = Some(Notification::new(NotifyLevel::Warning, message));
    }

    /// Show an error message (auto-expires in 10s).
    pub fn error(&mut self, message: impl Into<String>) {
        self.current = Some(Notification::new(NotifyLevel::Error, message));
    }

    // ── Queries ──────────────────────────────────────────────────────────

    /// Returns the active notification, or `None` if expired / absent.
    pub fn current(&self) -> Option<&Notification> {
        self.current.as_ref().filter(|n| !n.is_expired())
    }

    /// Explicitly dismiss the current notification.
    pub fn clear(&mut self) {
        self.current = None;
    }
}

impl Default for NotifyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info_notification() {
        let mut mgr = NotifyManager::new();
        mgr.info("test");
        let n = mgr.current().unwrap();
        assert_eq!(n.level, NotifyLevel::Info);
        assert_eq!(n.message, "test");
    }

    #[test]
    fn test_success_notification() {
        let mut mgr = NotifyManager::new();
        mgr.success("done");
        let n = mgr.current().unwrap();
        assert_eq!(n.level, NotifyLevel::Success);
    }

    #[test]
    fn test_error_notification() {
        let mut mgr = NotifyManager::new();
        mgr.error("fail");
        let n = mgr.current().unwrap();
        assert_eq!(n.level, NotifyLevel::Error);
    }

    #[test]
    fn test_newest_wins() {
        let mut mgr = NotifyManager::new();
        mgr.info("first");
        mgr.warn("second");
        assert_eq!(mgr.current().unwrap().message, "second");
    }

    #[test]
    fn test_clear() {
        let mut mgr = NotifyManager::new();
        mgr.info("msg");
        mgr.clear();
        assert!(mgr.current().is_none());
    }

    #[test]
    fn test_level_colors() {
        assert_eq!(NotifyLevel::Info.color(), Color::Cyan);
        assert_eq!(NotifyLevel::Success.color(), Color::Green);
        assert_eq!(NotifyLevel::Warning.color(), Color::Yellow);
        assert_eq!(NotifyLevel::Error.color(), Color::Red);
    }
}
