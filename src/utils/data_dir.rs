//! Global data directory for persistent storage.
//!
//! Defaults to `~/.crossdrop/` but can be overridden via `--data-dir`.
//! Must be initialized once at startup via `init()`.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Initialize the global data directory.
///
/// If `custom` is `Some`, uses that path. Otherwise falls back to `~/.crossdrop/`.
/// Panics if called more than once.
pub fn init(custom: Option<&Path>) {
    let dir = match custom {
        Some(p) => p.to_path_buf(),
        None => dirs::home_dir()
            .expect("No home directory found")
            .join(".crossdrop"),
    };
    DATA_DIR
        .set(dir)
        .expect("data_dir::init() called more than once");
}

/// Returns the global data directory path.
///
/// Panics if `init()` has not been called.
pub fn get() -> &'static Path {
    DATA_DIR
        .get()
        .expect("data_dir not initialized — call data_dir::init() first")
}
