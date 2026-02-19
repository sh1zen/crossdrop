//! Shared helpers: compression, encryption, path sanitization, and app notification.
//!
//! All functions here are pure or close-to-pure (no async, no shared state).
//! Sub-modules import them via `super::`.

use super::types::ConnectionMessage;
use aes_gcm::{
    aead::{Aead, KeyInit}, Aes256Gcm,
    Nonce,
};
use anyhow::{anyhow, Result};
use brotli::{CompressorWriter, Decompressor};
use std::io::{Read, Write};
use std::path::PathBuf;
use tokio::sync::mpsc;

// ── Key derivation ────────────────────────────────────────────────────────────

/// Derive a separate HMAC key from the shared session key.
///
/// Prevents key-reuse between AES-256-GCM encryption and HMAC-SHA3-256.
#[inline]
pub fn derive_chat_hmac_key(shared_key: &[u8; 32]) -> [u8; 32] {
    crate::utils::crypto::hmac_sha3_256(shared_key, b"crossdrop-chat-hmac-v1")
}

// ── Compression ───────────────────────────────────────────────────────────────

/// Compress `data` with Brotli (quality 4 — balanced speed/ratio for control messages).
pub fn compress_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() / 2);
    {
        let mut w = CompressorWriter::new(&mut out, 4096, 4, 22);
        w.write_all(data)?;
    }
    Ok(out)
}

/// Decompress Brotli-compressed `data`.
pub fn decompress_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut dec = Decompressor::new(data, 4096);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    Ok(out)
}

// ── Encryption ────────────────────────────────────────────────────────────────
//
// Wire format for every encrypted payload: `nonce (12 B) || ciphertext`.

/// Encrypt `plaintext` with a pre-initialized AES-256-GCM cipher.
#[inline]
pub fn encrypt_with(cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes: [u8; 12] = rand::random();
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt `data` (`nonce || ciphertext`) with a pre-initialized AES-256-GCM cipher.
#[inline]
pub fn decrypt_with(cipher: &Aes256Gcm, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(anyhow!("Ciphertext too short"));
    }
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&data[..12]);
    cipher
        .decrypt(nonce, &data[12..])
        .map_err(|e| anyhow!("Decryption failed: {e}"))
}

/// Encrypt `plaintext` with a fresh AES-256-GCM cipher derived from `key`.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_with(&Aes256Gcm::new_from_slice(key)?, plaintext)
}

/// Decrypt `data` with a fresh AES-256-GCM cipher derived from `key`.
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    decrypt_with(&Aes256Gcm::new_from_slice(key)?, data)
}

// ── App notification ──────────────────────────────────────────────────────────

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

// ── Path sanitization ─────────────────────────────────────────────────────────

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
        if matches!(part, "." | "..") {
            continue;
        }
        let safe: String = part
            .chars()
            .filter(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' '))
            .collect();
        if !safe.is_empty() {
            result.push(safe);
        }
    }

    if result.as_os_str().is_empty() {
        PathBuf::from("file")
    } else {
        result
    }
}
