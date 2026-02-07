//! Security primitives for peer authentication and message integrity.
//!
//! This module provides the cryptographic foundation for CrossDrop's security model,
//! implementing identity management, message authentication, and replay protection.
//! All cryptographic operations are centralized here to ensure consistent security
//! properties across the codebase.
//!
//! # Security Architecture
//!
//! CrossDrop uses a layered security approach:
//!
//! 1. **Transport Security** (connection layer): ECDH session keys with AES-256-GCM
//!    encryption over WebRTC data channels.
//! 2. **Application Security** (this module): Ed25519 identity signing, HMAC
//!    authentication, and replay protection for protocol messages.
//!
//! # Components
//!
//! | Module | Responsibility |
//! |--------|---------------|
//! | [`identity`] | Ed25519 key pair management, persistent identity, signature verification |
//! | [`message_auth`] | HMAC computation and verification for authenticated messages |
//! | [`replay`] | Monotonic counter-based replay guard for transaction messages |
//!
//! # Identity Model
//!
//! Each peer has a long-term Ed25519 key pair stored in the data directory:
//!
//! - **Public key**: Serves as the peer's unique identifier (32 bytes)
//! - **Private key**: Never transmitted; used only for signing
//!
//! The identity is used to sign:
//! - Transfer manifests (proving sender authenticity)
//! - Resume requests (preventing spoofed resume attacks)
//!
//! # Message Authentication
//!
//! Critical protocol messages are authenticated with HMAC-SHA3-256:
//!
//! ```text
//! HMAC = HMAC-SHA3-256(session_key, message_content || counter)
//! ```
//!
//! The counter prevents replay attacks: each message must have a counter
//! greater than all previously seen counters from the same peer.
//!
//! # Replay Protection
//!
//! The [`replay::ReplayGuard`] tracks:
//!
//! - Active transaction IDs (prevent duplicate transaction execution)
//! - Per-transaction monotonic counters (prevent message replay)
//! - Transaction expiration times (prevent replay of old transactions)
//!
//! On connection loss, replay state is persisted so resumed transfers
//! cannot be attacked with replayed messages from the previous session.

pub mod identity;
pub mod message_auth;
pub mod replay;
