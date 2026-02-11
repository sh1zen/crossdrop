//! Message authentication: HMAC computation and verification for protocol messages.
//!
//! Every protocol message includes:
//! - transaction_id
//! - Monotonic counter
//! - HMAC(session_key, payload)

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

/// An authenticated protocol message envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedMessage {
    /// Transaction this message belongs to.
    pub transaction_id: Uuid,
    /// Monotonic counter (strictly increasing per direction).
    pub counter: u64,
    /// The inner payload (serialized protocol message).
    pub payload: Vec<u8>,
    /// HMAC(session_key, transaction_id || counter || payload).
    pub hmac: [u8; 32],
}

/// Authenticator for creating and verifying message HMACs.
pub struct MessageAuthenticator;

impl MessageAuthenticator {
    /// Compute HMAC for a message.
    pub fn compute_hmac(
        session_key: &[u8; 32],
        transaction_id: &Uuid,
        counter: u64,
        payload: &[u8],
    ) -> [u8; 32] {
        let mut data = Vec::with_capacity(16 + 8 + payload.len());
        data.extend_from_slice(transaction_id.as_bytes());
        data.extend_from_slice(&counter.to_be_bytes());
        data.extend_from_slice(payload);
        hmac_sha3_256(session_key, &data)
    }

    /// Create an authenticated message.
    pub fn create(
        session_key: &[u8; 32],
        transaction_id: Uuid,
        counter: u64,
        payload: Vec<u8>,
    ) -> AuthenticatedMessage {
        let hmac = Self::compute_hmac(session_key, &transaction_id, counter, &payload);
        AuthenticatedMessage {
            transaction_id,
            counter,
            payload,
            hmac,
        }
    }

    /// Verify an authenticated message.
    pub fn verify(
        session_key: &[u8; 32],
        msg: &AuthenticatedMessage,
    ) -> bool {
        let expected = Self::compute_hmac(
            session_key,
            &msg.transaction_id,
            msg.counter,
            &msg.payload,
        );
        constant_time_eq(&expected, &msg.hmac)
    }
}

/// HMAC-SHA3-256.
fn hmac_sha3_256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 136; // SHA3-256 rate

    let actual_key = if key.len() > BLOCK_SIZE {
        let mut h = Sha3_256::new();
        h.update(key);
        let digest = h.finalize();
        let mut k = [0u8; BLOCK_SIZE];
        k[..32].copy_from_slice(&digest);
        k
    } else {
        let mut k = [0u8; BLOCK_SIZE];
        k[..key.len()].copy_from_slice(key);
        k
    };

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= actual_key[i];
        opad[i] ^= actual_key[i];
    }

    let mut inner = Sha3_256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha3_256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let result = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify() {
        let key = [42u8; 32];
        let txn_id = Uuid::new_v4();
        let payload = b"hello world".to_vec();

        let msg = MessageAuthenticator::create(&key, txn_id, 1, payload);
        assert!(MessageAuthenticator::verify(&key, &msg));
    }

    #[test]
    fn test_tampered_payload() {
        let key = [42u8; 32];
        let txn_id = Uuid::new_v4();
        let payload = b"hello world".to_vec();

        let mut msg = MessageAuthenticator::create(&key, txn_id, 1, payload);
        msg.payload[0] ^= 0xFF; // tamper
        assert!(!MessageAuthenticator::verify(&key, &msg));
    }

    #[test]
    fn test_wrong_key() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let txn_id = Uuid::new_v4();
        let payload = b"test".to_vec();

        let msg = MessageAuthenticator::create(&key, txn_id, 1, payload);
        assert!(!MessageAuthenticator::verify(&wrong_key, &msg));
    }

    #[test]
    fn test_tampered_counter() {
        let key = [42u8; 32];
        let txn_id = Uuid::new_v4();

        let mut msg = MessageAuthenticator::create(&key, txn_id, 1, b"data".to_vec());
        msg.counter = 2; // tamper
        assert!(!MessageAuthenticator::verify(&key, &msg));
    }
}
