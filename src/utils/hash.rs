//! Compression, decompression, and identity key management utilities.
//!
//! Provides:
//! - Brotli-based string compression/expansion for tickets
//! - Instance locking for single-instance enforcement
//! - Persistent secret key management with automatic slot detection

use anyhow::Context;
use base64::engine::general_purpose::{PAD, URL_SAFE_NO_PAD};
use base64::engine::GeneralPurpose;
use base64::{alphabet, Engine};
use brotli::{CompressorWriter, Decompressor};
use iroh::SecretKey;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Version prefix for the compact encoding format.
/// Allows future format changes without breaking existing IDs.
const COMPACT_VERSION: &str = "1";

/// Maximum number of secret key slots.
const MAX_SECRET_SLOTS: u8 = 9;

// ── Compression / Expansion ────────────────────────────────────────────────────

/// Compress a string using Brotli and encode with URL-safe Base64.
///
/// The output format is: version prefix + compressed + base64-encoded data.
pub fn compress_string(data: String) -> anyhow::Result<String> {
    let mut compressed = Vec::new();
    {
        let mut compressor = CompressorWriter::new(&mut compressed, 4096, 11, 22);
        compressor.write_all(data.as_bytes())?;
    }
    let encoded = URL_SAFE_NO_PAD.encode(&compressed);
    Ok(format!("{COMPACT_VERSION}{encoded}"))
}

/// Expand a compressed string back to its original form.
///
/// Supports both the new compact format (version-prefixed) and legacy format.
pub fn expand_string(packed: String) -> anyhow::Result<String> {
    let trimmed = packed.trim();
    let compressed = decode_compressed_data(trimmed)?;
    decompress_data(&compressed)
}

/// Decode compressed data from either compact or legacy format.
fn decode_compressed_data(trimmed: &str) -> anyhow::Result<Vec<u8>> {
    if let Some(rest) = trimmed.strip_prefix(COMPACT_VERSION) {
        // Try URL-safe no-pad first (new compact format)
        URL_SAFE_NO_PAD
            .decode(rest)
            .or_else(|_| decode_legacy_base64(trimmed))
            .context("failed to decode base64")
    } else {
        // Legacy format: standard base64 with padding
        decode_legacy_base64(trimmed).context("failed to decode legacy base64")
    }
}

/// Decode legacy base64 format (standard with padding).
fn decode_legacy_base64(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    GeneralPurpose::new(&alphabet::STANDARD, PAD).decode(data)
}

/// Decompress Brotli-compressed data to a string.
fn decompress_data(compressed: &[u8]) -> anyhow::Result<String> {
    let mut decompressor = Decompressor::new(compressed, 4096);
    let mut decompressed_data = String::new();
    decompressor
        .read_to_string(&mut decompressed_data)
        .context("failed to decompress data")?;
    Ok(decompressed_data)
}

// ── Instance Lock ──────────────────────────────────────────────────────────────

/// Guard that removes the instance lock file on drop.
pub struct InstanceGuard {
    lock_path: PathBuf,
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

/// Check if a process with the given PID is still running.
#[cfg(windows)]
fn is_pid_alive(pid: u32) -> bool {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    std::process::Command::new("tasklist")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains(&format!("\"{pid}\""))
        })
        .unwrap_or(false)
}

/// Check if a process with the given PID is still running.
#[cfg(not(windows))]
fn is_pid_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Try to acquire an exclusive lock file. Returns true if acquired.
fn try_acquire_lock(lock_path: &Path) -> bool {
    let my_pid = std::process::id();

    // Atomic creation attempt — succeeds only if file doesn't exist yet
    if let Ok(mut file) = create_lock_file(lock_path) {
        write_pid(&mut file, my_pid);
        return true;
    }

    // Lock file exists — check if the owning process is still alive
    if let Ok(pid) = read_pid_from_lock(lock_path) {
        if pid == my_pid {
            return true; // We already hold this lock
        }
        if is_pid_alive(pid) {
            return false; // Another live process holds this lock
        }
    }

    // Stale lock — remove and retry atomic creation
    let _ = std::fs::remove_file(lock_path);
    if let Ok(mut file) = create_lock_file(lock_path) {
        write_pid(&mut file, my_pid);
        return true;
    }

    false
}

/// Create a new lock file (atomic create-new operation).
fn create_lock_file(path: &Path) -> std::io::Result<std::fs::File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Write PID to lock file.
fn write_pid(file: &mut std::fs::File, pid: u32) {
    let _ = write!(file, "{pid}");
    let _ = file.flush();
}

/// Read PID from an existing lock file.
fn read_pid_from_lock(lock_path: &Path) -> std::io::Result<u32> {
    let contents = std::fs::read_to_string(lock_path)?;
    contents.trim().parse::<u32>().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid PID in lock file: {e}"),
        )
    })
}

// ── Secret Key Management ──────────────────────────────────────────────────────

/// Load an existing key from file, or generate a new one and save it.
fn load_or_create_key(path: &Path) -> anyhow::Result<SecretKey> {
    if path.exists() {
        return load_key_from_file(path);
    }
    create_and_save_key(path)
}

/// Load a secret key from an existing file.
fn load_key_from_file(path: &Path) -> anyhow::Result<SecretKey> {
    let hex_str = std::fs::read_to_string(path).context("failed to read secret key file")?;
    SecretKey::from_str(hex_str.trim()).context("invalid secret key in file")
}

/// Generate a new secret key and save it to file.
fn create_and_save_key(path: &Path) -> anyhow::Result<SecretKey> {
    let key = generate_random_key();
    let hex_str = hex::encode(key.to_bytes());

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("failed to create secret key directory")?;
    }
    std::fs::write(path, &hex_str).context("failed to write secret key file")?;

    Ok(key)
}

/// Generate a new random secret key.
fn generate_random_key() -> SecretKey {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    SecretKey::from_bytes(&bytes)
}

/// Get or create a persistent secret key, with per-instance locking.
///
/// Automatically finds an available slot (`secret_key`, `secret_key_1`, …,
/// `secret_key_9`) in the configured data directory so that multiple instances
/// on the same machine each get their own identity.
///
/// Returns the key and an `InstanceGuard` that releases the lock on drop.
///
/// Priority:
/// 1. `IROH_SECRET` environment variable
/// 2. Auto-detect available slot in the data directory
/// 3. Ephemeral key as last resort
pub fn get_or_create_secret() -> anyhow::Result<(SecretKey, Option<InstanceGuard>)> {
    // 1. Check environment variable
    if let Ok(secret) = std::env::var("IROH_SECRET") {
        let key = SecretKey::from_str(&secret).context("invalid IROH_SECRET")?;
        return Ok((key, None));
    }

    // 2. Auto-detect available slot
    let base_dir = crate::utils::data_dir::get().to_path_buf();
    let _ = std::fs::create_dir_all(&base_dir);

    for slot in secret_key_slots() {
        if let Some(result) = try_acquire_secret_slot(&base_dir, &slot) {
            return Ok(result);
        }
    }

    // 3. All slots taken — ephemeral key
    tracing::warn!("All secret key slots in use, using ephemeral identity");
    Ok((generate_random_key(), None))
}

/// Generate iterator over secret key slot names.
fn secret_key_slots() -> impl Iterator<Item = String> {
    std::iter::once("secret_key".to_string()).chain((1..=MAX_SECRET_SLOTS).map(|i| format!("secret_key_{i}")))
}

/// Try to acquire a secret key slot.
fn try_acquire_secret_slot(base_dir: &Path, slot_name: &str) -> Option<(SecretKey, Option<InstanceGuard>)> {
    let key_path = base_dir.join(slot_name);
    let lock_path = base_dir.join(format!("{slot_name}.lock"));

    if try_acquire_lock(&lock_path) {
        let key = load_or_create_key(&key_path).ok()?;
        let guard = InstanceGuard { lock_path };
        return Some((key, Some(guard)));
    }
    None
}
