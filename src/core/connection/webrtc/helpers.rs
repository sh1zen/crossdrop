//! Shared helpers: compression, encryption, path sanitization, and app notification.
//!
//! All functions here are pure or close-to-pure (no async, no shared state).
//! Sub-modules import them via `super::`.

use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use brotli::{CompressorWriter, Decompressor};
use std::io::{Read, Write};
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
