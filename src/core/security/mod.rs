//! Security module: Ed25519 identity, session management, replay protection, HMAC.
//!
//! Provides:
//! - Long-term Ed25519 key pair management for peer authentication
//! - Ephemeral session key derivation via ECDH
//! - Monotonic counter-based replay protection
//! - HMAC computation and verification for protocol messages
//! - Nonce derivation from a seed + counter pair
//! - Transaction expiration enforcement

pub mod identity;
pub mod message_auth;
pub mod replay;
