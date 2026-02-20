//! Protocol types: control messages, app-facing events, and internal state.
//!
//! This module is a pure data layer — no I/O, no async, no allocator tricks.
//! Every type here is `Serialize`/`Deserialize` where it crosses a wire, or
//! `Clone`/`Debug` where it crosses an async task boundary.

use crate::core::pipeline::receiver::StreamingFileWriter;
use crate::core::transaction::{ResumeInfo, TransactionManifest};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Signaling ─────────────────────────────────────────────────────────────────
// Exchanged via Iroh during connection establishment, not on the data channel.

/// Signaling messages for WebRTC connection establishment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalingMessage {
    /// SDP offer from the initiating peer.
    Offer(String),
    /// SDP answer from the responding peer.
    Answer(String),
    /// ICE candidate for NAT traversal.
    IceCandidate(String),
}

// ── Control messages ──────────────────────────────────────────────────────────
// JSON-serialized, sent as `FRAME_CONTROL` frames on the data channel.

/// Control messages for the WebRTC data channel protocol.
///
/// All variants are JSON-serialized and framed with [`FRAME_CONTROL`].
/// They cover all non-bulk communication: chat, file metadata,
/// transaction management, and protocol control.
///
/// [`FRAME_CONTROL`]: super::FRAME_CONTROL
#[derive(Debug, Serialize, Deserialize)]
pub enum ControlMessage {
    // ── Chat ─────────────────────────────────────────────────────────────────
    /// Plain text / chat message (broadcast/room).
    Text(Vec<u8>),
    /// Direct (1-to-1) chat message.
    DirectMessage(Vec<u8>),
    /// Ephemeral typing indicator (no payload).
    Typing,
    /// HMAC + monotonic-counter authenticated room chat message.
    AuthenticatedText(Vec<u8>),
    /// HMAC + monotonic-counter authenticated direct message.
    AuthenticatedDm(Vec<u8>),
    /// Display name announcement.
    DisplayName(String),

    // ── File transfer ─────────────────────────────────────────────────────────
    /// File metadata sent before chunks.
    Metadata {
        file_id: Uuid,
        total_chunks: u32,
        filename: String,
        filesize: u64,
    },
    /// Full Merkle tree (all chunk hashes + root).
    ///
    /// **Deprecated** — prefer [`ControlMessage::ChunkHashBatch`] for incremental
    /// delivery.  Kept for backwards-compat with older peers.
    MerkleTree {
        file_id: Uuid,
        /// SHA3-256 hash of each chunk, in order.
        chunk_hashes: Vec<[u8; 32]>,
        /// Merkle root computed from `chunk_hashes`.
        merkle_root: [u8; 32],
    },
    /// Incremental chunk-hash batch sent just ahead of the corresponding chunks.
    ///
    /// Enables per-chunk Merkle verification without pre-computing the full tree.
    ChunkHashBatch {
        file_id: Uuid,
        /// Index of the first chunk hash in this batch.
        start_index: u32,
        /// SHA3-256 hashes for chunks `start_index .. start_index + len`.
        chunk_hashes: Vec<[u8; 32]>,
    },
    /// Merkle root sent after all chunks (incremental Merkle approach).
    Hash {
        file_id: Uuid,
        /// Merkle root computed incrementally from per-chunk SHA3-256 hashes.
        merkle_root: [u8; 32],
    },
    /// Hash verification result (receiver → sender).
    HashResult { file_id: Uuid, ok: bool },
    /// Request retransmission of specific chunks after Merkle verification failure.
    ///
    /// An empty `chunk_indices` means "retransmit everything".
    ChunkRetransmitRequest {
        file_id: Uuid,
        chunk_indices: Vec<u32>,
    },
    /// Confirmation that the receiver has fully saved the file (receiver → sender).
    ///
    /// Unblocks the sender's per-file semaphore so it can proceed to the next file.
    FileReceived { file_id: Uuid },

    // ── Transactions ──────────────────────────────────────────────────────────
    /// Initiate a file-transfer transaction.
    TransactionRequest {
        transaction_id: Uuid,
        display_name: String,
        manifest: TransactionManifest,
        total_size: u64,
    },
    /// Accept or reject a transaction.
    TransactionResponse {
        transaction_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
        reject_reason: Option<String>,
    },
    /// Signal that the sender has finished the transaction.
    TransactionComplete { transaction_id: Uuid },
    /// Cancel an in-progress transaction.
    TransactionCancel {
        transaction_id: Uuid,
        reason: Option<String>,
    },
    /// Request to resume a previously interrupted transaction.
    TransactionResumeRequest { resume_info: ResumeInfo },
    /// Accept or reject a resume request.
    TransactionResumeResponse {
        transaction_id: Uuid,
        accepted: bool,
    },
    /// Acknowledge receipt of `TransactionComplete` (receiver → sender).
    TransactionCompleteAck { transaction_id: Uuid },

    // ── Remote access ─────────────────────────────────────────────────────────
    /// Request a directory listing from the peer.
    LsRequest { path: String },
    /// Directory listing response.
    LsResponse {
        path: String,
        entries: Vec<crate::workers::app::RemoteEntry>,
    },
    /// Request the peer to fetch a file or folder.
    FetchRequest { path: String, is_folder: bool },
    /// Remote access is disabled on the peer.
    RemoteAccessDisabled,

    // ── Remote key listener ──────────────────────────────────────────────────
    /// Remote key event from a peer (key code as string).
    RemoteKeyEvent { key: String },
    /// Remote key listener is disabled on the peer.
    RemoteKeyListenerDisabled,

    // ── Key rotation ──────────────────────────────────────────────────────────
    /// Send a fresh ephemeral X25519 public key to trigger key rotation.
    KeyRotation { ephemeral_pub: Vec<u8> },

    // ── Liveness ──────────────────────────────────────────────────────────────
    /// Liveness probe — peer must reply with [`ControlMessage::ImAwake`].
    AreYouAwake,
    /// Reply to [`ControlMessage::AreYouAwake`].
    ImAwake,
}

// ── App-facing events ─────────────────────────────────────────────────────────

/// Events delivered from the WebRTC connection layer to the application.
///
/// The application consumes these from an `mpsc::UnboundedReceiver` and uses
/// them to drive UI updates, file saves, and transaction state machines.
#[derive(Debug, Clone)]
pub enum ConnectionMessage {
    // ── Chat ──────────────────────────────────────────────────────────────────
    /// Received a room/broadcast text message.
    TextReceived(Vec<u8>),
    /// Received a direct (1-to-1) message.
    DmReceived(Vec<u8>),
    /// The remote peer is currently typing.
    TypingReceived,
    /// Received the remote peer's display name.
    DisplayNameReceived(String),

    // ── Incoming file transfer ────────────────────────────────────────────────
    /// File has been fully written to disk.
    FileSaved {
        file_id: Uuid,
        filename: String,
        path: String,
        /// Merkle root computed from received chunk hashes.
        merkle_root: [u8; 32],
    },
    /// Progress update for an incoming file.
    FileProgress {
        file_id: Uuid,
        filename: String,
        received_chunks: u32,
        total_chunks: u32,
        /// Wire bytes received in this progress window (post-encryption).
        wire_bytes: u64,
        /// Serialized chunk bitmap for resume persistence.
        chunk_bitmap_bytes: Option<Vec<u8>>,
    },

    // ── Outgoing file transfer ────────────────────────────────────────────────
    /// Progress update for an outgoing file.
    SendProgress {
        file_id: Uuid,
        filename: String,
        sent_chunks: u32,
        total_chunks: u32,
        /// Wire bytes sent in this progress window (post-encryption).
        wire_bytes: u64,
    },
    /// Outgoing file send finished (with integrity result).
    SendComplete {
        file_id: Uuid,
        success: bool,
    },
    /// Peer requested retransmission of specific chunks.
    ChunkRetransmitRequested {
        file_id: Uuid,
        chunk_indices: Vec<u32>,
    },
    /// Peer confirmed it has saved the file.
    FileReceivedAck {
        file_id: Uuid,
    },

    // ── Remote access ─────────────────────────────────────────────────────────
    /// Response to a remote directory listing request.
    LsResponse {
        path: String,
        entries: Vec<crate::workers::app::RemoteEntry>,
    },
    /// Remote access is disabled on the peer.
    RemoteAccessDisabled,
    /// Peer requested to fetch a file or folder from us.
    RemoteFetchRequest {
        path: String,
        is_folder: bool,
    },

    // ── Remote key listener ──────────────────────────────────────────────────
    /// Remote key event received from peer.
    RemoteKeyEventReceived { key: String },
    /// Remote key listener is disabled on the peer.
    RemoteKeyListenerDisabled,

    // ── Transactions ──────────────────────────────────────────────────────────
    TransactionRequested {
        transaction_id: Uuid,
        display_name: String,
        manifest: TransactionManifest,
        total_size: u64,
    },
    TransactionAccepted {
        transaction_id: Uuid,
        dest_path: Option<String>,
    },
    TransactionRejected {
        transaction_id: Uuid,
        reason: Option<String>,
    },
    TransactionCompleted {
        transaction_id: Uuid,
    },
    TransactionCancelled {
        transaction_id: Uuid,
        reason: Option<String>,
    },
    TransactionResumeRequested {
        resume_info: ResumeInfo,
    },
    TransactionResumeAccepted {
        transaction_id: Uuid,
    },
    TransactionResumeRejected {
        transaction_id: Uuid,
        reason: Option<String>,
    },
    TransactionCompleteAcked {
        transaction_id: Uuid,
    },

    // ── Connection state ──────────────────────────────────────────────────────
    /// Peer responded to an `AreYouAwake` probe.
    AwakeReceived,
    /// Connection was terminated.
    Disconnected,
    /// A protocol or I/O error occurred.
    Error(String),
    /// Internal debug / diagnostic message.
    Debug(String),
}

// ── Internal receive state ────────────────────────────────────────────────────

/// Buffered hash parameters when `Hash` arrives before the last chunk.
///
/// Consumed by the chunk handler once `received_chunks == total_chunks`.
pub struct PendingHash {
    /// Expected Merkle root from sender.
    pub merkle_root: [u8; 32],
}

/// Live state for one in-progress file receive.
pub struct ReceiveFileState {
    /// Streaming writer accumulating chunk data.
    pub writer: StreamingFileWriter,
    /// Buffered hash message — set when `Hash` arrives before the final chunk.
    pub pending_hash: Option<PendingHash>,
}
