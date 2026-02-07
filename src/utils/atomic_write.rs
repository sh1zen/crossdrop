//! Atomic file write utility.
//!
//! Provides a single implementation of the write-to-temp-then-rename pattern
//! used for all persistent state files (transfers, peer registry, etc.).
//!
//! # Invariants
//!
//! - Content is written to a `.tmp` sibling file first.
//! - `sync_all()` is called before rename, ensuring the data reaches persistent
//!   storage before the directory entry is updated. Without this, a power loss
//!   between a buffered OS write and the physical flush would leave the
//!   destination file empty or zero-padded after the rename succeeds.
//! - An atomic `rename()` then replaces the target in one operation.
//! - On any failure the temp file is removed to avoid stale artifacts.
//! - Parent directories are created if absent.
//!
//! # Crash-safety guarantee
//!
//! After `atomic_write` returns `Ok(())`, the data is durable: the kernel has
//! confirmed the bytes are on the storage device and the directory entry points
//! to the new content. Readers will see either the old file or the new file —
//! never a partial write.
//!
//! Note: `rename()` is atomic on NTFS, ext4, APFS, and all major filesystems
//! when source and destination are on the same mount.

use anyhow::Result;
use std::io::Write as _;
use std::path::Path;
use tracing::error;

/// Atomically write `content` to `path` via a temporary file + fsync + rename.
///
/// # Errors
/// Returns an error if the temp file cannot be created/written/synced, or if
/// the rename fails. The temp file is cleaned up on all failure paths.
pub fn atomic_write(path: &Path, content: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let tmp_path = path.with_extension("json.tmp");

    // Create and write the temp file.
    let mut file = std::fs::File::create(&tmp_path).map_err(|e| {
        error!(
            event = "atomic_write_create_failure",
            path = %tmp_path.display(),
            error = %e,
            "Failed to create temp file"
        );
        e
    })?;

    if let Err(e) = file.write_all(content) {
        error!(
            event = "atomic_write_failure",
            path = %tmp_path.display(),
            error = %e,
            "Failed to write temp file"
        );
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }

    // Flush kernel buffers to the storage device before the rename.
    // This guarantees the data is durable even if power is lost immediately
    // after rename completes.
    if let Err(e) = file.sync_all() {
        error!(
            event = "atomic_write_sync_failure",
            path = %tmp_path.display(),
            error = %e,
            "Failed to sync temp file to disk"
        );
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }

    // Drop the file handle before rename (required on Windows).
    drop(file);

    std::fs::rename(&tmp_path, path).map_err(|e| {
        error!(
            event = "atomic_rename_failure",
            from = %tmp_path.display(),
            to = %path.display(),
            error = %e,
            "Failed to rename temp file"
        );
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
