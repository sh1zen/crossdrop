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

pub fn compress_string(data: String) -> anyhow::Result<String> {
    // Use compact encoding: version prefix + URL-safe Base64 (no padding)
    let mut compressed = Vec::new();
    {
        let mut compressor = CompressorWriter::new(&mut compressed, 4096, 11, 22);
        compressor.write_all(data.as_bytes())?;
    }
    let encoded = URL_SAFE_NO_PAD.encode(&compressed);
    Ok(format!("{}{}", COMPACT_VERSION, encoded))
}

pub fn expand_string(packed: String) -> anyhow::Result<String> {
    let trimmed = packed.trim();
    // Detect format: if starts with version prefix, use compact format
    let compressed = if let Some(rest) = trimmed.strip_prefix(COMPACT_VERSION) {
        // Try URL-safe no-pad first (new compact format)
        URL_SAFE_NO_PAD
            .decode(rest)
            .or_else(|_| {
                // Fallback: maybe the '1' was part of old base64 data
                GeneralPurpose::new(&alphabet::STANDARD, PAD).decode(trimmed)
            })
            .context("failed to decode base64")?
    } else {
        // Legacy format: standard base64 with padding
        GeneralPurpose::new(&alphabet::STANDARD, PAD)
            .decode(trimmed)
            .context("failed to decode legacy base64")?
    };
    let mut decompressor = Decompressor::new(&*compressed, 4096);
    let mut decompressed_data = String::new();
    decompressor.read_to_string(&mut decompressed_data)?;
    Ok(decompressed_data)
}

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
fn is_pid_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        // Call tasklist directly (not through cmd) to avoid quote-escaping issues.
        // /FO CSV gives unambiguous output: "process.exe","1234","Console","1","12,345 K"
        // vs "INFO: No tasks are running which match the specified criteria."
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
    #[cfg(not(windows))]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// Try to acquire an exclusive lock file. Returns true if acquired.
fn try_acquire_lock(lock_path: &Path) -> bool {
    let my_pid = std::process::id();

    // Atomic creation attempt — succeeds only if file doesn't exist yet
    if let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lock_path)
    {
        let _ = write!(file, "{}", my_pid);
        let _ = file.flush();
        return true;
    }

    // Lock file exists — check if the owning process is still alive
    if let Ok(contents) = std::fs::read_to_string(lock_path)
        && let Ok(pid) = contents.trim().parse::<u32>()
    {
        if pid == my_pid {
            return true; // We already hold this lock
        }
        if is_pid_alive(pid) {
            return false; // Another live process holds this lock
        }
    }

    // Stale lock — remove and retry atomic creation
    let _ = std::fs::remove_file(lock_path);
    if let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lock_path)
    {
        let _ = write!(file, "{}", my_pid);
        let _ = file.flush();
        return true;
    }

    false
}

/// Load an existing key from file, or generate a new one and save it.
fn load_or_create_key(path: &Path) -> anyhow::Result<SecretKey> {
    if path.exists() {
        let hex_str = std::fs::read_to_string(path).context("failed to read secret key file")?;
        return SecretKey::from_str(hex_str.trim()).context("invalid secret key in file");
    }

    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let key = SecretKey::from_bytes(&bytes);
    let hex_str = hex::encode(key.to_bytes());

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("failed to create secret key directory")?;
    }
    std::fs::write(path, &hex_str).context("failed to write secret key file")?;

    Ok(key)
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
    // 1. Env var
    if let Ok(secret) = std::env::var("IROH_SECRET") {
        let key = SecretKey::from_str(&secret).context("invalid IROH_SECRET")?;
        return Ok((key, None));
    }

    // 2. Auto-detect available slot
    {
        let base_dir = crate::utils::data_dir::get().to_path_buf();
        let _ = std::fs::create_dir_all(&base_dir);

        let candidates = std::iter::once("secret_key".to_string())
            .chain((1..=9).map(|i| format!("secret_key_{i}")));

        for name in candidates {
            let key_path = base_dir.join(&name);
            let lock_path = base_dir.join(format!("{name}.lock"));

            if try_acquire_lock(&lock_path) {
                let key = load_or_create_key(&key_path)?;
                let guard = InstanceGuard { lock_path };
                return Ok((key, Some(guard)));
            }
        }

        // All 10 slots taken — ephemeral key
        tracing::warn!("All secret key slots in use, using ephemeral identity");
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        return Ok((SecretKey::from_bytes(&bytes), None));
    }

}
