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

#[derive(Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: Level,
    pub message: String,
}

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

    pub fn push(&self, entry: LogEntry) {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= MAX_ENTRIES {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    pub fn entries(&self) -> Vec<LogEntry> {
        self.entries.lock().unwrap().iter().cloned().collect()
    }
}

pub struct BufferLayer {
    buffer: LogBuffer,
}

impl BufferLayer {
    pub fn new(buffer: LogBuffer) -> Self {
        Self { buffer }
    }
}

struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        } else if self.message.is_empty() {
            self.message = format!("{} = {:?}", field.name(), value);
        } else {
            self.message
                .push_str(&format!(", {} = {:?}", field.name(), value));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else if self.message.is_empty() {
            self.message = format!("{} = {}", field.name(), value);
        } else {
            self.message
                .push_str(&format!(", {} = {}", field.name(), value));
        }
    }
}

impl<S: Subscriber> Layer<S> for BufferLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let level = *meta.level();

        let mut visitor = MessageVisitor {
            message: String::new(),
        };
        event.record(&mut visitor);

        let target = meta.target();
        let message = if visitor.message.is_empty() {
            target.to_string()
        } else {
            format!("{}: {}", target, visitor.message)
        };

        let now = {
            let dur = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default();
            let total_secs = dur.as_secs();
            let h = (total_secs / 3600) % 24;
            let m = (total_secs / 60) % 60;
            let s = total_secs % 60;
            format!("{:02}:{:02}:{:02}", h, m, s)
        };

        self.buffer.push(LogEntry {
            timestamp: now,
            level,
            message,
        });
    }
}

// ── File Logging Layer ──────────────────────────────────────────────────────

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
        let level = *meta.level();

        let mut visitor = MessageVisitor {
            message: String::new(),
        };
        event.record(&mut visitor);

        let target = meta.target();
        let message = if visitor.message.is_empty() {
            target.to_string()
        } else {
            format!("{}: {}", target, visitor.message)
        };

        // Full ISO 8601 timestamp with date for file logs
        let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z");

        let level_str = match level {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };

        let log_line = format!("[{}] {} {}\n", timestamp, level_str, message);

        if let Ok(mut writer) = self.writer.lock() {
            let _ = writer.write_all(log_line.as_bytes());
            let _ = writer.flush();
        }
    }
}
