//! WebRTCConnection: multi-use data channel (messages + files).
//!
//! # Protocol overview
//!
//! - Compact binary framing for file chunks (no JSON overhead on hot path).
//! - JSON-serialized [`ControlMessage`] for all non-bulk communication.
//! - File transfer flow:
//!   `FileOffer → FileResponse → Metadata → ChunkHashBatch* → Chunk* → Hash → HashResult`
//! - Chunks transferred in pipelined batches; SHA3-256 + incremental Merkle verification.
//! - Receiver verifies each chunk against its expected hash; requests targeted
//!   retransmission on mismatch.
//! - Reliable delivery delegated to WebRTC SCTP (no application-level ACKs).
//! - AES-256-GCM encryption with per-peer session keys; optional key rotation.
//! - Brotli compression on control messages only (chunks skip compression).
//!
//! # Module layout
//!
//! | File              | Responsibility                                          |
//! |-------------------|---------------------------------------------------------|
//! | `types.rs`        | Protocol enums and internal state structs (pure data)   |
//! | `helpers.rs`      | Crypto, compression, path sanitization, app notify      |
//! | `connection.rs`   | [`WebRTCConnection`] struct and its inherent `impl`     |
//! | `data.rs`         | Binary frame encode / decode                            |
//! | `control.rs`      | Incoming message dispatch and handler context           |
//! | `sender.rs`       | TX operations: files, messages, control frames          |
//! | `receiver.rs`     | RX operations: finalization and hash verification       |
//! | `initializer.rs`  | Connection setup and data-channel negotiation           |

// ── Sub-modules ───────────────────────────────────────────────────────────────

pub(crate) mod connection;
pub(crate) mod control;
pub(crate) mod data;
pub(crate) mod helpers;
pub(crate) mod initializer;
pub(crate) mod receiver;
pub(crate) mod sender;
pub(crate) mod types;

// ── Flat re-exports ───────────────────────────────────────────────────────────
// Child modules (and external callers) can use these without spelling out the
// intermediate module name.

pub use connection::WebRTCConnection;

pub use types::{ConnectionMessage, ControlMessage, SignalingMessage};

pub(crate) use types::{PendingHash, ReceiveFileState};

pub(crate) use helpers::{
    compress_data, decompress_data, decrypt_with, derive_chat_hmac_key, encrypt,
    encrypt_with, notify_app, sanitize_relative_path,
};

// ── Frame-type constants ──────────────────────────────────────────────────────

/// Frame tag for JSON-encoded [`ControlMessage`] frames.
pub(crate) const FRAME_CONTROL: u8 = 0x01;

/// Frame tag for raw binary chunk frames.
pub(crate) const FRAME_CHUNK: u8 = 0x02;

// ── Well-known UUIDs ──────────────────────────────────────────────────────────

/// Domain-separation constant for chat HMAC authentication.
///
/// Used as the `transaction_id` in `AuthenticatedMessage` for room/DM chat so
/// that chat HMACs are cryptographically distinct from file-transfer HMACs
/// (which use real transaction UUIDs).
pub(crate) const CHAT_HMAC_CHANNEL: uuid::Uuid = uuid::Uuid::from_bytes([
    0xC0, 0xDE, 0xCA, 0xFE, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0xC4, 0xA7, 0x01,
]);
