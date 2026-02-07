//! Log buffering and file logging for the application.
//!
//! Provides:
//! - In-memory ring buffer for UI log display
//! - File logging layer for persistent log storage

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

use crate::core::config::MAX_LOG_ENTRIES as MAX_ENTRIES;

// ── Log Entry ──────────────────────────────────────────────────────────────────

/// A single log entry with timestamp, level, and message.
#[derive(Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: Level,
    pub message: String,
}

// ── Log Buffer ─────────────────────────────────────────────────────────────────

/// Thread-safe ring buffer for log entries.
#[derive(Clone)]
pub struct LogBuffer {
    entries: Arc<Mutex<VecDeque<LogEntry>>>,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Push a new entry, evicting the oldest if at capacity.
    pub fn push(&self, entry: LogEntry) {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= MAX_ENTRIES {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Get a snapshot of all current entries.
    pub fn entries(&self) -> Vec<LogEntry> {
        self.entries.lock().unwrap().iter().cloned().collect()
    }
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Message Visitor ────────────────────────────────────────────────────────────

/// Visitor for extracting and formatting log message fields.
struct MessageVisitor {
    message: String,
}

impl MessageVisitor {
    fn new() -> Self {
        Self {
            message: String::new(),
        }
    }

    fn format_field(&mut self, name: &str, value: String) {
        if name == "message" {
            if self.message.is_empty() {
                self.message = value;
            } else {
                self.message = format!("{}, {}", self.message, value);
            }
        } else if self.message.is_empty() {
            self.message = format!("{name} = {value}");
        } else {
            self.message.push_str(&format!(", {name} = {value}"));
        }
    }
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.format_field(field.name(), format!("{:?}", value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.format_field(field.name(), value.to_string());
    }
}

// ── Buffer Layer ───────────────────────────────────────────────────────────────

/// Tracing layer that writes events to an in-memory buffer.
pub struct BufferLayer {
    buffer: LogBuffer,
}

impl BufferLayer {
    pub fn new(buffer: LogBuffer) -> Self {
        Self { buffer }
    }
}

impl<S: Subscriber> Layer<S> for BufferLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let entry = create_log_entry(event, meta, format_timestamp_time_only);
        self.buffer.push(entry);
    }
}

// ── File Log Layer ─────────────────────────────────────────────────────────────

/// A tracing layer that writes log events to a file.
/// Writes full ISO 8601 timestamps for complete log history.
pub struct FileLogLayer {
    writer: Arc<Mutex<File>>,
}

impl FileLogLayer {
    /// Create a new file log layer that appends to the specified path.
    /// Creates parent directories if they don't exist.
    pub fn new(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            writer: Arc::new(Mutex::new(file)),
        })
    }
}

impl<S: Subscriber> Layer<S> for FileLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let entry = create_log_entry(event, meta, format_timestamp_iso8601);

        let level_str = level_to_str(entry.level);
        let log_line = format!("[{}] {} {}\n", entry.timestamp, level_str, entry.message);

        if let Ok(mut writer) = self.writer.lock() {
            let _ = writer.write_all(log_line.as_bytes());
            let _ = writer.flush();
        }
    }
}

// ── Helper Functions ───────────────────────────────────────────────────────────

/// Create a log entry from a tracing event.
fn create_log_entry<F>(event: &Event<'_>, meta: &tracing::Metadata<'_>, format_timestamp: F) -> LogEntry
where
    F: FnOnce() -> String,
{
    let mut visitor = MessageVisitor::new();
    event.record(&mut visitor);

    let target = meta.target();
    let message = if visitor.message.is_empty() {
        target.to_string()
    } else {
        format!("{}: {}", target, visitor.message)
    };

    LogEntry {
        timestamp: format_timestamp(),
        level: *meta.level(),
        message,
    }
}

/// Format timestamp as HH:MM:SS (time only, for UI display).
fn format_timestamp_time_only() -> String {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = dur.as_secs();
    let h = (total_secs / 3600) % 24;
    let m = (total_secs / 60) % 60;
    let s = total_secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Format timestamp as ISO 8601 with timezone (for file logging).
fn format_timestamp_iso8601() -> String {
    chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string()
}

/// Convert log level to string representation.
fn level_to_str(level: Level) -> &'static str {
    match level {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN",
        Level::INFO => "INFO",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    }
}
