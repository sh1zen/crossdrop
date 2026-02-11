//! Peer-to-peer key exchange and session key management.
//!
//! Provides:
//! - Ephemeral X25519 key pair generation per session
//! - ECDH key agreement over the Iroh bootstrap channel
//! - HKDF-SHA3-256 session key derivation
//! - Hourly key rotation with forward secrecy
//!
//! **Protocol (initial handshake, over Iroh bi-stream):**
//!
//! ```text
//! Offerer                          Answerer
//! ───────                          ────────
//! eph_pk_A  ──────────────────────► eph_pk_B
//! eph_pk_B  ◄──────────────────────
//!
//! shared_secret = X25519(eph_sk_A, eph_pk_B)
//!
//! session_key = HKDF-SHA3-256(
//!     ikm  = shared_secret,
//!     salt = sort(iroh_pk_A, iroh_pk_B),
//!     info = b"crossdrop-session-v1"
//! )
//! ```
//!
//! **Key rotation (over WebRTC control channel):**
//!
//! Each peer periodically generates a fresh ephemeral X25519 key pair and
//! sends it to the other via a `KeyRotation` control message (encrypted
//! under the *current* session key). Both sides then derive a new session
//! key from the new ECDH secret, with the previous key mixed in as salt
//! to guarantee forward secrecy.

use sha3::{Digest, Sha3_256};
use std::sync::Arc;
use tokio::sync::RwLock;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

// ── X25519 ECDH ──────────────────────────────────────────────────────────────

/// An ephemeral X25519 key pair backed by `x25519-dalek`.
pub struct EphemeralKeypair {
    secret: StaticSecret,
    pub public: [u8; 32],
}

impl EphemeralKeypair {
    /// Generate a fresh random ephemeral key pair.
    pub fn generate() -> Self {
        let bytes: [u8; 32] = rand::random();
        let secret = StaticSecret::from(bytes);
        let public = *X25519PublicKey::from(&secret).as_bytes();
        Self { secret, public }
    }

    /// Perform ECDH with the peer's public key.
    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer_pk = X25519PublicKey::from(*peer_public);
        *self.secret.diffie_hellman(&peer_pk).as_bytes()
    }
}

// ── Session key derivation (HKDF-SHA3-256) ───────────────────────────────────

/// Derive a 32-byte session key using HKDF with SHA3-256.
pub fn derive_session_key(
    shared_secret: &[u8; 32],
    local_pk: &iroh::PublicKey,
    remote_pk: &iroh::PublicKey,
    info: &[u8],
    previous_key: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut pks = [*local_pk.as_bytes(), *remote_pk.as_bytes()];
    pks.sort();

    let mut salt_data = Vec::with_capacity(64 + 32);
    salt_data.extend_from_slice(&pks[0]);
    salt_data.extend_from_slice(&pks[1]);
    if let Some(prev) = previous_key {
        salt_data.extend_from_slice(prev);
    }
    let prk = hmac_sha3_256(&salt_data, shared_secret);

    let mut expand_msg = Vec::with_capacity(info.len() + 1);
    expand_msg.extend_from_slice(info);
    expand_msg.push(0x01);
    hmac_sha3_256(&prk, &expand_msg)
}

/// HMAC-SHA3-256 (RFC 2104 with SHA3-256).
fn hmac_sha3_256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 136; // SHA3-256 rate (1088 bits)

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

// ── SessionKeyManager ────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SessionKeyManager {
    key: Arc<RwLock<[u8; 32]>>,
    local_pk: iroh::PublicKey,
    remote_pk: iroh::PublicKey,
}

impl SessionKeyManager {
    pub fn new(
        initial_key: [u8; 32],
        local_pk: iroh::PublicKey,
        remote_pk: iroh::PublicKey,
    ) -> Self {
        Self {
            key: Arc::new(RwLock::new(initial_key)),
            local_pk,
            remote_pk,
        }
    }

    pub async fn current_key(&self) -> [u8; 32] {
        *self.key.read().await
    }

    pub async fn rotate(&self, new_shared_secret: &[u8; 32]) -> [u8; 32] {
        let mut guard = self.key.write().await;
        let new_key = derive_session_key(
            new_shared_secret,
            &self.local_pk,
            &self.remote_pk,
            b"crossdrop-rotation-v1",
            Some(&*guard),
        );
        *guard = new_key;
        new_key
    }

    pub fn inner(&self) -> Arc<RwLock<[u8; 32]>> {
        self.key.clone()
    }
}

// ── Handshake helpers ────────────────────────────────────────────────────────

pub async fn handshake_offerer(
    send_stream: &mut iroh::endpoint::SendStream,
    recv_stream: &mut iroh::endpoint::RecvStream,
    local_pk: &iroh::PublicKey,
    remote_pk: &iroh::PublicKey,
) -> anyhow::Result<SessionKeyManager> {
    let eph = EphemeralKeypair::generate();

    send_stream.write_all(&eph.public).await?;

    let mut peer_eph_pk = [0u8; 32];
    recv_stream.read_exact(&mut peer_eph_pk).await?;

    let shared_secret = eph.diffie_hellman(&peer_eph_pk);

    let session_key = derive_session_key(
        &shared_secret,
        local_pk,
        remote_pk,
        b"crossdrop-session-v1",
        None,
    );

    Ok(SessionKeyManager::new(session_key, *local_pk, *remote_pk))
}

pub async fn handshake_answerer(
    send_stream: &mut iroh::endpoint::SendStream,
    recv_stream: &mut iroh::endpoint::RecvStream,
    local_pk: &iroh::PublicKey,
    remote_pk: &iroh::PublicKey,
) -> anyhow::Result<SessionKeyManager> {
    let mut peer_eph_pk = [0u8; 32];
    recv_stream.read_exact(&mut peer_eph_pk).await?;

    let eph = EphemeralKeypair::generate();

    send_stream.write_all(&eph.public).await?;

    let shared_secret = eph.diffie_hellman(&peer_eph_pk);

    let session_key = derive_session_key(
        &shared_secret,
        local_pk,
        remote_pk,
        b"crossdrop-session-v1",
        None,
    );

    Ok(SessionKeyManager::new(session_key, *local_pk, *remote_pk))
}

// ── Key rotation protocol ────────────────────────────────────────────────────

pub const KEY_ROTATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

pub fn prepare_rotation() -> EphemeralKeypair {
    EphemeralKeypair::generate()
}

pub async fn complete_rotation(
    manager: &SessionKeyManager,
    local_eph: &EphemeralKeypair,
    peer_eph_pk: &[u8; 32],
) -> [u8; 32] {
    let shared_secret = local_eph.diffie_hellman(peer_eph_pk);
    manager.rotate(&shared_secret).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_rfc7748_vector1() {
        // RFC 7748 §6.1 — first test vector
        let scalar: [u8; 32] = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82,
            0x46, 0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a,
            0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4,
        ];
        let input_u: [u8; 32] = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24,
            0xb1, 0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9,
            0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c,
        ];
        let expected: [u8; 32] = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2,
            0x8d, 0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4,
            0x07, 0x55, 0x77, 0xa2, 0x85, 0x52,
        ];
        let secret = StaticSecret::from(scalar);
        let point = X25519PublicKey::from(input_u);
        let result = secret.diffie_hellman(&point);
        assert_eq!(result.as_bytes(), &expected, "RFC 7748 §6.1 test vector 1");
    }

    #[test]
    fn test_x25519_rfc7748_vector2() {
        // RFC 7748 §6.1 — second test vector
        let scalar: [u8; 32] = [
            0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26, 0x91, 0x95,
            0x7d, 0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4, 0x2c, 0xa4,
            0x16, 0x9e, 0x79, 0x18, 0xba, 0x0d,
        ];
        let input_u: [u8; 32] = [
            0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95, 0x9d, 0x05,
            0x38, 0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e, 0xfc, 0x4c,
            0xd5, 0x49, 0xc7, 0x15, 0xa4, 0x93,
        ];
        let expected: [u8; 32] = [
            0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad, 0xe4, 0x5c, 0xb4,
            0xb8, 0x73, 0xf8, 0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f, 0xa1, 0x52, 0xe6, 0xf8,
            0xf7, 0x64, 0x7a, 0xac, 0x79, 0x57,
        ];
        let secret = StaticSecret::from(scalar);
        let point = X25519PublicKey::from(input_u);
        let result = secret.diffie_hellman(&point);
        assert_eq!(result.as_bytes(), &expected, "RFC 7748 §6.1 test vector 2");
    }

    #[test]
    fn test_ecdh_symmetry() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();
        let secret_a = alice.diffie_hellman(&bob.public);
        let secret_b = bob.diffie_hellman(&alice.public);
        assert_eq!(secret_a, secret_b, "ECDH must be commutative");
    }

    #[test]
    fn test_hmac_sha3_256_basic() {
        let r1 = hmac_sha3_256(b"key", b"data");
        let r2 = hmac_sha3_256(b"key", b"data");
        assert_eq!(r1, r2);
        assert_ne!(r1, [0u8; 32]);
    }
}