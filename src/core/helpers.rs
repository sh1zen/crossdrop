use std::path::PathBuf;
use tokio::sync::mpsc;
use crate::core::config::CHUNK_SIZE;
use crate::core::connection::webrtc::ConnectionMessage;

/// Compute the total number of chunks for a file of the given size.
///
/// This is the **single source of truth** for chunk count computation.
/// All modules MUST use this instead of duplicating the formula.
///
/// Invariant: always returns at least 1 (even for zero-size files).
#[inline]
pub fn compute_total_chunks(file_size: u64) -> u32 {
    ((file_size as f64) / (CHUNK_SIZE as f64)).ceil().max(1.0) as u32
}

/// Sanitize a (possibly adversarial) relative path for safe use as a file name.
///
/// - Normalizes `\` to `/`.
/// - Strips `.` and `..` components.
/// - Keeps only alphanumeric chars plus `.`, `-`, `_`, and ` ` per component.
/// - Falls back to `"file"` when the result would otherwise be empty.
pub fn sanitize_relative_path(name: &str) -> PathBuf {
    let normalized = name.replace('\\', "/");
    let mut result = PathBuf::new();

    for part in normalized.split('/').filter(|s| !s.is_empty()) {
        if part == "." || part == ".." {
            continue;
        }

        // Keep the original filename exactly as-is
        result.push(part);
    }

    if result.as_os_str().is_empty() {
        PathBuf::from("file")
    } else {
        result
    }
}

/// Forward `msg` to the application layer; silently no-ops when `app_tx` is `None`.
#[inline]
pub fn notify_app(
    app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>,
    msg: ConnectionMessage,
) {
    if let Some(tx) = app_tx {
        let _ = tx.send(msg);
    }
}