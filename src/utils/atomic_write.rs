//! Atomic file write utility.
//!
//! Provides a single implementation of the write-to-temp-then-rename pattern
//! used for all persistent state files (transfers, peer registry, etc.).
//!
//! Invariants:
//! - Write goes to a `.tmp` file first, then an atomic rename replaces the target.
//! - On rename failure, the temp file is cleaned up to avoid stale artifacts.
//! - Parent directories are created if absent.
//! - This prevents corruption from mid-write crashes (power loss, SIGKILL).
//!
//! Note: `rename()` is atomic on NTFS, ext4, APFS, and all major filesystems
//! when source and destination are on the same mount.

use anyhow::Result;
use std::path::Path;
use tracing::error;

/// Atomically write `content` to `path` via a temporary file and rename.
///
/// # Errors
/// Returns an error if the temp file cannot be written or the rename fails.
/// On rename failure, attempts to clean up the temp file.
pub fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let tmp_path = path.with_extension("json.tmp");

    std::fs::write(&tmp_path, content).map_err(|e| {
        error!(
            event = "atomic_write_failure",
            path = %tmp_path.display(),
            error = %e,
            "Failed to write temp file"
        );
        e
    })?;

    std::fs::rename(&tmp_path, path).map_err(|e| {
        error!(
            event = "atomic_rename_failure",
            from = %tmp_path.display(),
            to = %path.display(),
            error = %e,
            "Failed to rename temp file"
        );
        // Attempt cleanup of the temp file on rename failure
        let _ = std::fs::remove_file(&tmp_path);
        e
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_write_creates_file() {
        let dir = std::env::temp_dir().join("crossdrop_test_atomic");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_atomic.json");
        let _ = std::fs::remove_file(&path);

        atomic_write(&path, b"hello").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_atomic_write_overwrites() {
        let dir = std::env::temp_dir().join("crossdrop_test_atomic2");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_overwrite.json");

        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_atomic_write_no_temp_file_remains() {
        let dir = std::env::temp_dir().join("crossdrop_test_atomic3");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_notmp.json");

        atomic_write(&path, b"data").unwrap();
        let tmp = path.with_extension("json.tmp");
        assert!(
            !tmp.exists(),
            "Temp file should not remain after successful write"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
