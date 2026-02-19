//! Message authentication: HMAC computation and verification for protocol messages.
//!
//! Every protocol message includes:
//! - transaction_id
//! - Monotonic counter
//! - HMAC(session_key, payload)

use serde::{Deserialize, Serialize};
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
        crate::utils::crypto::hmac_sha3_256(session_key, &data)
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
    pub fn verify(session_key: &[u8; 32], msg: &AuthenticatedMessage) -> bool {
        let expected =
            Self::compute_hmac(session_key, &msg.transaction_id, msg.counter, &msg.payload);
        crate::utils::crypto::constant_time_eq(&expected, &msg.hmac)
    }
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
