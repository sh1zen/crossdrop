//! WebRTC-based data channel for high-throughput file transfer and messaging.
//!
//! This module implements the core communication protocol between connected peers,
//! using WebRTC data channels for reliable, encrypted transport. The design
//! prioritizes throughput on the file transfer hot path while maintaining
//! flexibility for control messages and chat.
//!
//! # Protocol Overview
//!
//! The protocol uses a hybrid framing strategy:
//!
//! - **Binary frames** for file chunks (minimal overhead, no parsing cost)
//! - **JSON-serialized [`ControlMessage`]** for all control-plane communication
//!
//! ## File Transfer Flow
//!
//! ```text
//! Sender                              Receiver
//! ──────                              ────────
//! TransactionRequest ────────────────►
//!                                     ◄── TransactionResponse (accept/reject)
//! Metadata ──────────────────────────►
//! ChunkHashBatch* ───────────────────► (pipelined, batched)
//! Chunk* ────────────────────────────► (pipelined, encrypted)
//! Hash ──────────────────────────────►
//!                                     ◄── HashResult (verify + retransmit request)
//! TransactionComplete ───────────────►
//!                                     ◄── Ack
//! ```
//!
//! ## Integrity Verification
//!
//! Each file is protected by:
//! 1. **Per-chunk SHA3-256 hashes**: Sent before chunks, verified on receipt
//! 2. **Merkle root**: Computed incrementally, verified at transfer end
//! 3. **Targeted retransmission**: Only failed chunks are resent (not entire file)
//!
//! ## Encryption
//!
//! All traffic is encrypted with AES-256-GCM using the session key from ECDH:
//! - Each message has a unique nonce (seed + monotonic counter)
//! - Session keys rotate hourly with forward secrecy
//! - Brotli compression on control messages only (chunks are already compressed)
//!
//! # Architecture
//!
//! [`WebRTCConnection`] is the main entry point, managing two data channels:
//!
//! - **Control channel**: JSON messages for transactions, chat, metadata
//! - **Data channel**: Binary frames for file chunks
//!
//! The module is split into focused sub-modules:
//!
//! | File | Responsibility |
//! |------|---------------|
//! | [`types.rs`] | Protocol enums ([`ControlMessage`], [`ConnectionMessage`]), state structs |
//! | [`helpers.rs`] | Crypto utilities, compression, path sanitization, notifications |
//! | [`connection.rs`] | [`WebRTCConnection`] struct, public API, lifecycle management |
//! | [`data.rs`] | Binary frame encoding/decoding for chunks |
//! | [`control.rs`] | Incoming message dispatch, handler context |
//! | [`sender.rs`] | Outbound operations: files, messages, control frames |
//! | [`receiver.rs`] | Inbound operations: chunk assembly, hash verification |
//! | [`initializer.rs`] | Connection setup, ICE negotiation, channel opening |
//!
//! # Design Patterns
//!
//! - **Channel separation**: Control and data channels are independent to avoid
//!   head-of-line blocking (small control messages don't wait for large chunks).
//! - **Pipelining**: Chunks are sent in batches with their hashes, keeping the
//!   network saturated while the receiver verifies asynchronously.
//! - **Backpressure**: The sender monitors `buffered_amount` and pauses when
//!   the SCTP buffer fills, preventing memory exhaustion.
//! - **Graceful degradation**: On hash mismatch, only the affected chunks are
//!   retransmitted, not the entire file.

// ── Sub-modules ───────────────────────────────────────────────────────────────

pub mod connection;
pub mod control;
pub mod data;
pub mod helpers;
pub mod initializer;
pub mod receiver;
pub mod sender;
pub mod types;

// ── Flat re-exports ───────────────────────────────────────────────────────────
// Child modules (and external callers) can use these without spelling out the
// intermediate module name.

pub use connection::WebRTCConnection;

pub use types::{AckContext, ConnectionMessage, ControlMessage, SignalingMessage};

pub use types::{PendingHash, ReceiveFileState};

pub use helpers::{
    compress_data, decompress_data, decrypt_with, derive_chat_hmac_key,
    encrypt_with,
};
// ── Frame-type constants ──────────────────────────────────────────────────────

/// Frame tag for JSON-encoded [`ControlMessage`] frames.
pub const FRAME_CONTROL: u8 = 0x01;

/// Frame tag for raw binary chunk frames.
pub const FRAME_CHUNK: u8 = 0x02;

// ── Well-known UUIDs ──────────────────────────────────────────────────────────

/// Domain-separation constant for chat HMAC authentication.
///
/// Used as the `transaction_id` in `AuthenticatedMessage` for room/DM chat so
/// that chat HMACs are cryptographically distinct from file-transfer HMACs
/// (which use real transaction UUIDs).
pub const CHAT_HMAC_CHANNEL: uuid::Uuid = uuid::Uuid::from_bytes([
    0xC0, 0xDE, 0xCA, 0xFE, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0xC4, 0xA7, 0x01,
]);
