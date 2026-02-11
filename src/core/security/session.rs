//! Secure session management: ephemeral keys, nonce derivation, session state.
//!
//! Manages the per-transaction security context including:
//! - Ephemeral session keys derived from ECDH
//! - Nonce seed and deterministic nonce derivation
//! - Transaction expiration timestamps
//! - Session key export for AEAD encryption

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Default transaction lifetime: 24 hours.
pub const DEFAULT_TRANSACTION_LIFETIME: Duration = Duration::from_secs(24 * 3600);

/// Maximum transaction lifetime: 72 hours.
pub const MAX_TRANSACTION_LIFETIME: Duration = Duration::from_secs(72 * 3600);

/// A secure session context for a single transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureSession {
    /// Transaction identifier.
    pub transaction_id: Uuid,
    /// Expiration time (Unix timestamp seconds).
    pub expiration_time: u64,
    /// 256-bit nonce seed for deterministic nonce derivation.
    pub nonce_seed: [u8; 32],
    /// Session key derived from ECDH (not serialized for security).
    #[serde(skip)]
    pub session_key: Option<[u8; 32]>,
    /// Public key of the remote peer (for authentication).
    pub remote_public_key: [u8; 32],
    /// Our own public key.
    pub local_public_key: [u8; 32],
}

impl SecureSession {
    /// Create a new secure session for a transaction.
    pub fn new(
        transaction_id: Uuid,
        session_key: [u8; 32],
        local_public_key: [u8; 32],
        remote_public_key: [u8; 32],
    ) -> Self {
        let expiration_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
            + DEFAULT_TRANSACTION_LIFETIME.as_secs();

        let nonce_seed: [u8; 32] = rand::random();

        Self {
            transaction_id,
            expiration_time,
            nonce_seed,
            session_key: Some(session_key),
            remote_public_key,
            local_public_key,
        }
    }

    /// Create with a specific expiration time.
    pub fn with_expiration(mut self, expiration_time: u64) -> Self {
        self.expiration_time = expiration_time;
        self
    }

    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        now >= self.expiration_time
    }

    /// Derive a 12-byte nonce for AEAD from the nonce seed and a counter.
    /// nonce = SHA3-256(nonce_seed || counter)[0..12]
    pub fn derive_nonce(&self, counter: u64) -> [u8; 12] {
        let mut h = Sha3_256::new();
        h.update(&self.nonce_seed);
        h.update(&counter.to_be_bytes());
        let hash = h.finalize();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hash[..12]);
        nonce
    }

    /// Get the session key, if available.
    pub fn key(&self) -> Option<&[u8; 32]> {
        self.session_key.as_ref()
    }

    /// Set the session key (used when restoring from persistence).
    pub fn set_key(&mut self, key: [u8; 32]) {
        self.session_key = Some(key);
    }

    /// Remaining time before expiration.
    pub fn remaining(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        if now >= self.expiration_time {
            Duration::ZERO
        } else {
            Duration::from_secs(self.expiration_time - now)
        }
    }
}

/// Persistent session data (without the session key for security).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub transaction_id: Uuid,
    pub expiration_time: u64,
    pub nonce_seed: [u8; 32],
    pub remote_public_key: [u8; 32],
    pub local_public_key: [u8; 32],
}

impl From<&SecureSession> for SessionSnapshot {
    fn from(session: &SecureSession) -> Self {
        Self {
            transaction_id: session.transaction_id,
            expiration_time: session.expiration_time,
            nonce_seed: session.nonce_seed,
            remote_public_key: session.remote_public_key,
            local_public_key: session.local_public_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = SecureSession::new(
            Uuid::new_v4(),
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );
        assert!(!session.is_expired());
        assert!(session.key().is_some());
    }

    #[test]
    fn test_nonce_derivation_deterministic() {
        let session = SecureSession::new(
            Uuid::new_v4(),
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );
        let n1 = session.derive_nonce(1);
        let n2 = session.derive_nonce(1);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_nonce_derivation_unique() {
        let session = SecureSession::new(
            Uuid::new_v4(),
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );
        let n1 = session.derive_nonce(1);
        let n2 = session.derive_nonce(2);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_expired_session() {
        let session = SecureSession::new(
            Uuid::new_v4(),
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        )
        .with_expiration(0);
        assert!(session.is_expired());
    }
}
