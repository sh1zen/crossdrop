//! WebRTCConnection: multi-use data channel (messages + files)
//!
//! # Protocol Overview
//!
//! - Uses compact binary framing for file chunks (no JSON overhead)
//! - JSON-serialized ChannelPayload for control messages only
//! - File transfer protocol: FileOffer -> FileResponse -> Metadata -> MerkleTree -> Chunk* -> Hash -> HashResult
//! - Chunked transfer pipelined in batches, SHA3-256 verification
//! - Incremental Merkle tree verification: sender sends chunk hashes before chunks
//! - Receiver verifies each chunk against expected hash, requests retransmission if corrupted
//! - Reliable delivery delegated to WebRTC SCTP (no application-level ACKs)
//! - AES-256-GCM encryption with per-peer keys
//! - Brotli compression for control messages only (chunks skip compression)

mod control;
mod data;
mod initializer;
mod receiver;
mod sender;
use crate::core::connection::crypto::SessionKeyManager;
use crate::core::pipeline::receiver::StreamingFileWriter;
use crate::core::transaction::{ResumeInfo, TransactionManifest};
use aes_gcm::{
    aead::{Aead, KeyInit}, Aes256Gcm,
    Nonce,
};
use anyhow::{anyhow, Result};
use brotli::{CompressorWriter, Decompressor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, Semaphore};
use uuid::Uuid;
use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::RTCPeerConnection;

// ── Constants ────────────────────────────────────────────────────────────────

/// Frame type marker for control messages (JSON-encoded ControlMessage).
pub(crate) const FRAME_CONTROL: u8 = 0x01;

/// Frame type marker for binary chunk data.
pub(crate) const FRAME_CHUNK: u8 = 0x02;

/// Well-known channel ID used as `transaction_id` in [`AuthenticatedMessage`]
/// for chat HMAC authentication. Provides domain separation from file-transfer
/// HMACs which use real transaction UUIDs.
pub(crate) const CHAT_HMAC_CHANNEL: Uuid = Uuid::from_bytes([
    0xC0, 0xDE, 0xCA, 0xFE, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0xC4, 0xA7, 0x01,
]);

// ── Key Derivation ────────────────────────────────────────────────────────────

/// Derive a separate HMAC key from the shared encryption key.
///
/// This prevents key-reuse between AES-256-GCM encryption and HMAC-SHA3-256,
/// which is critical for cryptographic security.
#[inline]
pub(crate) fn derive_chat_hmac_key(shared_key: &[u8; 32]) -> [u8; 32] {
    crate::utils::crypto::hmac_sha3_256(shared_key, b"crossdrop-chat-hmac-v1")
}

// ── Signaling Messages ───────────────────────────────────────────────────────
// Exchanged via Iroh, not on the data channel.

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

// ── Control Messages ──────────────────────────────────────────────────────────
// JSON-serialized, sent as FRAME_CONTROL on the data channel.

/// Control messages for the WebRTC data channel protocol.
///
/// These messages are JSON-serialized and sent as `FRAME_CONTROL` frames.
/// They handle all non-bulk-data communication: chat, file metadata, 
/// transaction management, and protocol control.
#[derive(Debug, Serialize, Deserialize)]
pub enum ControlMessage {
    // ── Chat Messages ────────────────────────────────────────────────────────
    /// Plain text / chat message (broadcast/room).
    Text(Vec<u8>),
    /// Direct (1-to-1) chat message — distinct from room Text.
    DirectMessage(Vec<u8>),
    /// Ephemeral typing indicator (no payload needed).
    Typing,
    /// Authenticated room chat message (HMAC + monotonic counter protected).
    AuthenticatedText(Vec<u8>),
    /// Authenticated direct message (HMAC + monotonic counter protected).
    AuthenticatedDm(Vec<u8>),
    /// Display name announcement.
    DisplayName(String),

    // ── File Transfer ─────────────────────────────────────────────────────────
    /// File metadata (sent before chunks).
    Metadata {
        file_id: Uuid,
        total_chunks: u32,
        filename: String,
        filesize: u64,
    },
    /// Merkle tree chunk hashes (sent after Metadata, before chunks).
    /// The receiver uses this to verify each chunk as it arrives.
    /// If a chunk's hash doesn't match, the receiver requests retransmission.
    /// DEPRECATED: Use ChunkHashBatch for incremental hash delivery.
    MerkleTree {
        file_id: Uuid,
        /// SHA3-256 hash of each chunk, in order.
        chunk_hashes: Vec<[u8; 32]>,
        /// The Merkle root computed from all chunk hashes.
        merkle_root: [u8; 32],
    },
    /// Incremental chunk hash batch (sent ahead of chunks during transfer).
    /// This enables incremental Merkle verification without pre-computing all hashes.
    /// The sender computes and sends hashes in batches as chunks are being sent.
    ChunkHashBatch {
        file_id: Uuid,
        /// Starting chunk index for this batch.
        start_index: u32,
        /// SHA3-256 hash of each chunk in this batch.
        chunk_hashes: Vec<[u8; 32]>,
    },
    /// Final hash for verification (includes Merkle root computed during send).
    Hash {
        file_id: Uuid,
        sha3_256: Vec<u8>,
        /// Merkle root computed incrementally from per-chunk SHA3-256 hashes.
        #[serde(default)]
        merkle_root: Option<[u8; 32]>,
    },
    /// Hash verification result.
    HashResult { file_id: Uuid, ok: bool },
    /// Request retransmission of specific chunks (receiver → sender, on integrity failure).
    /// The receiver detected Merkle root mismatch and identified corrupted chunks.
    /// Contains the list of chunk indices that need to be resent.
    ChunkRetransmitRequest {
        file_id: Uuid,
        /// List of chunk indices that failed Merkle proof verification.
        chunk_indices: Vec<u32>,
    },
    /// File received confirmation (receiver → sender).
    /// Sent after the receiver has fully processed and saved a file.
    /// This allows the sender to continue sending the next file without waiting.
    FileReceived { file_id: Uuid },

    // ── Transaction Protocol ──────────────────────────────────────────────────
    /// Transaction-level transfer request.
    TransactionRequest {
        transaction_id: Uuid,
        display_name: String,
        manifest: TransactionManifest,
        total_size: u64,
    },
    /// Transaction-level response from receiver.
    TransactionResponse {
        transaction_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
        reject_reason: Option<String>,
    },
    /// Transaction completion confirmation.
    TransactionComplete { transaction_id: Uuid },
    /// Transaction cancellation.
    TransactionCancel {
        transaction_id: Uuid,
        reason: Option<String>,
    },
    /// Resume request referencing a transaction ID.
    TransactionResumeRequest { resume_info: ResumeInfo },
    /// Resume response from sender.
    TransactionResumeResponse {
        transaction_id: Uuid,
        accepted: bool,
    },
    /// Acknowledge transaction completion (receiver → sender).
    /// Sent after the receiver processes `TransactionComplete`.
    TransactionCompleteAck { transaction_id: Uuid },

    // ── Remote Access ─────────────────────────────────────────────────────────
    /// Remote list request.
    LsRequest { path: String },
    /// Remote list response.
    LsResponse {
        path: String,
        entries: Vec<crate::workers::app::RemoteEntry>,
    },
    /// Fetch remote file/folder.
    FetchRequest { path: String, is_folder: bool },
    /// Remote access disabled error.
    RemoteAccessDisabled,

    // ── Key Rotation ──────────────────────────────────────────────────────────
    /// Key rotation: peer sends a fresh ephemeral X25519 public key.
    KeyRotation { ephemeral_pub: Vec<u8> },

    // ── Liveness ──────────────────────────────────────────────────────────────
    /// Pre-communication liveness probe — peer should reply with ImAwake.
    AreYouAwake,
    /// Reply to AreYouAwake — confirms the peer is alive and ready.
    ImAwake,
}

// ── App-facing Events ────────────────────────────────────────────────────────

/// Events sent from the WebRTC connection to the application layer.
///
/// These messages represent all state changes and data received that the
/// application needs to handle (UI updates, file saves, etc.).
#[derive(Debug, Clone)]
pub enum ConnectionMessage {
    // ── Chat Events ───────────────────────────────────────────────────────────
    /// Received a room/broadcast text message.
    TextReceived(Vec<u8>),
    /// Received a direct (1-to-1) message from a peer.
    DmReceived(Vec<u8>),
    /// The peer is currently typing.
    TypingReceived,
    /// Received the peer's display name.
    DisplayNameReceived(String),

    // ── File Transfer Events (Receiver) ───────────────────────────────────────
    /// File successfully saved to disk.
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
        /// Bytes received on the wire for this progress update (post-compression/encryption).
        wire_bytes: u64,
        /// Chunk bitmap for persistence (serialized).
        chunk_bitmap_bytes: Option<Vec<u8>>,
    },

    // ── File Transfer Events (Sender) ──────────────────────────────────────────
    /// Progress update for an outgoing file.
    SendProgress {
        file_id: Uuid,
        filename: String,
        sent_chunks: u32,
        total_chunks: u32,
        /// Bytes sent on the wire for this batch (post-compression/encryption).
        wire_bytes: u64,
    },
    /// File send completed (success or failure).
    SendComplete {
        file_id: Uuid,
        success: bool,
    },
    /// Retransmission requested by peer (integrity failure for specific chunks).
    ChunkRetransmitRequested {
        file_id: Uuid,
        /// List of chunk indices that need to be resent.
        chunk_indices: Vec<u32>,
    },
    /// File received confirmation from receiver.
    /// Sent after the receiver has fully processed and saved a file.
    FileReceivedAck { file_id: Uuid },

    // ── Remote Access Events ──────────────────────────────────────────────────
    /// Response to a remote directory listing request.
    LsResponse {
        path: String,
        entries: Vec<crate::workers::app::RemoteEntry>,
    },
    /// Remote access is disabled on the peer.
    RemoteAccessDisabled,
    /// Peer requested to fetch a remote file/folder.
    RemoteFetchRequest {
        path: String,
        is_folder: bool,
    },

    // ── Transaction Events ─────────────────────────────────────────────────────
    /// Peer requested a file transfer transaction.
    TransactionRequested {
        transaction_id: Uuid,
        display_name: String,
        manifest: TransactionManifest,
        total_size: u64,
    },
    /// Transaction was accepted by the peer.
    TransactionAccepted {
        transaction_id: Uuid,
        dest_path: Option<String>,
    },
    /// Transaction was rejected by the peer.
    TransactionRejected {
        transaction_id: Uuid,
        reason: Option<String>,
    },
    /// Transaction completed successfully.
    TransactionCompleted { transaction_id: Uuid },
    /// Transaction was cancelled.
    TransactionCancelled {
        transaction_id: Uuid,
        reason: Option<String>,
    },
    /// Peer requested to resume a transaction.
    TransactionResumeRequested { resume_info: ResumeInfo },
    /// Resume request was accepted.
    TransactionResumeAccepted { transaction_id: Uuid },
    /// Resume request was rejected.
    TransactionResumeRejected {
        transaction_id: Uuid,
        reason: Option<String>,
    },
    /// Transaction completion acknowledged by peer.
    TransactionCompleteAcked { transaction_id: Uuid },

    // ── Connection State Events ────────────────────────────────────────────────
    /// Awake confirmation received from peer.
    AwakeReceived,
    /// Connection was disconnected.
    Disconnected,
    /// An error occurred.
    Error(String),
    /// Debug message (for development/troubleshooting).
    Debug(String),
}

// ── Internal State ───────────────────────────────────────────────────────────

/// Hash parameters buffered when the Hash control message arrives before
/// all chunks have been delivered on the data channel.
pub(crate) struct PendingHash {
    /// Expected SHA3-256 hash of the complete file.
    pub sha3_256: Vec<u8>,
    /// Expected Merkle root computed from chunk hashes.
    pub merkle_root: Option<[u8; 32]>,
}

impl PendingHash {
    /// Create a new pending hash with the given values.
    #[inline]
    pub fn new(sha3_256: Vec<u8>, merkle_root: Option<[u8; 32]>) -> Self {
        Self { sha3_256, merkle_root }
    }
}

/// State for an in-progress file receive operation.
pub(crate) struct ReceiveFileState {
    /// The streaming file writer handling chunk storage.
    pub writer: StreamingFileWriter,
    /// Buffered Hash — set when the Hash control message arrives before
    /// the last chunk has been written. Consumed by the chunk handler
    /// when the final chunk completes the file.
    pub pending_hash: Option<PendingHash>,
}

impl ReceiveFileState {
    /// Create a new receive state with the given writer.
    #[inline]
    pub fn new(writer: StreamingFileWriter) -> Self {
        Self {
            writer,
            pending_hash: None,
        }
    }
}

// ── Compression Helpers ──────────────────────────────────────────────────────

/// Compress data with Brotli (quality 4 for speed/ratio balance).
///
/// Quality 4 provides a good balance between speed and compression ratio
/// for real-time transfer of control messages.
pub(crate) fn compress_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut compressed = Vec::with_capacity(data.len() / 2);
    {
        let mut compressor = CompressorWriter::new(&mut compressed, 4096, 4, 22);
        compressor.write_all(data)?;
    }
    Ok(compressed)
}

/// Decompress Brotli-compressed data.
pub(crate) fn decompress_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut decompressor = Decompressor::new(data, 4096);
    let mut decompressed = Vec::new();
    decompressor.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

// ── Encryption Helpers ───────────────────────────────────────────────────────

/// Encrypt data using a pre-initialized AES-256-GCM cipher.
///
/// Returns `nonce (12 bytes) || ciphertext`.
#[inline]
pub(crate) fn encrypt_with(cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes: [u8; 12] = rand::random();
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data using a pre-initialized AES-256-GCM cipher.
///
/// Expects `nonce (12 bytes) || ciphertext`.
#[inline]
pub(crate) fn decrypt_with(cipher: &Aes256Gcm, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(anyhow!("Ciphertext too short"));
    }
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&data[..12]);
    cipher
        .decrypt(nonce, &data[12..])
        .map_err(|e| anyhow!("Decryption failed: {}", e))
}

/// Encrypt data with AES-256-GCM.
///
/// Returns `nonce (12 bytes) || ciphertext`.
pub(crate) fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    encrypt_with(&cipher, plaintext)
}

/// Decrypt data with AES-256-GCM.
///
/// Expects `nonce (12 bytes) || ciphertext`.
pub(crate) fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    decrypt_with(&cipher, data)
}

// ── Utility Functions ────────────────────────────────────────────────────────

/// Forward a [`ConnectionMessage`] to the application channel, if present.
///
/// No-op when `app_tx` is `None` (e.g., during tests or headless operation).
#[inline]
pub(crate) fn notify_app(
    app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>,
    msg: ConnectionMessage,
) {
    if let Some(tx) = app_tx {
        let _ = tx.send(msg);
    }
}

/// Sanitize a relative path by filtering each path component.
///
/// - Normalizes path separators to forward slashes
/// - Removes `.` and `..` components
/// - Filters characters to alphanumeric, `.`, `-`, `_`, and space
/// - Returns "file" if the result would be empty
pub(crate) fn sanitize_relative_path(name: &str) -> PathBuf {
    let normalized = name.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();

    if parts.is_empty() {
        return PathBuf::from("file");
    }

    let mut result = PathBuf::new();
    for part in parts {
        if part == "." || part == ".." {
            continue;
        }
        let safe: String = part
            .chars()
            .filter(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' '))
            .collect();
        if !safe.is_empty() {
            result.push(safe);
        }
    }

    if result.as_os_str().is_empty() {
        PathBuf::from("file")
    } else {
        result
    }
}

// ── WebRTCConnection ─────────────────────────────────────────────────────────

/// A WebRTC peer connection with encrypted data channels.
///
/// This struct manages the lifecycle of a WebRTC connection, including:
/// - Two data channels (control and data) for message and file transfer
/// - AES-256-GCM encryption for all communication
/// - Incremental Merkle tree verification for file integrity
/// - Transaction-based file transfer with resume support
///
/// # Channels
///
/// - **Control channel**: JSON-serialized control messages (chat, metadata, acknowledgments)
/// - **Data channel**: Binary chunk frames for file transfer
///
/// # Thread Safety
///
/// All shared state is protected by `Arc<RwLock<>>` or atomic types.
/// The connection is `Send + Sync` safe for concurrent access.
pub struct WebRTCConnection {
    // ── WebRTC Core ──────────────────────────────────────────────────────────
    /// The underlying WebRTC peer connection.
    pub(crate) peer_connection: Arc<RTCPeerConnection>,
    /// Control channel for JSON messages (chat, metadata, protocol control).
    pub(crate) control_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,
    /// Data channel for binary file chunks.
    pub(crate) data_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,

    // ── Application Interface ────────────────────────────────────────────────
    /// Channel to send events to the application layer.
    pub(crate) app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    /// Notified when an `ImAwake` response is received from the peer.
    pub(crate) awake_notify: Arc<tokio::sync::Notify>,

    // ── File Transfer State ──────────────────────────────────────────────────
    /// Destination paths for accepted incoming files.
    pub(crate) accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
    /// Per-file chunk bitmaps for resume support.
    pub(crate) resume_bitmaps:
        Arc<RwLock<HashMap<Uuid, crate::core::pipeline::chunk::ChunkBitmap>>>,
    /// Semaphore gating in-flight files (sent but not acknowledged).
    pub(crate) file_ack_semaphore: Arc<Semaphore>,

    // ── Cryptography ─────────────────────────────────────────────────────────
    /// Shared encryption key for this session.
    pub(crate) shared_key: Arc<RwLock<[u8; 32]>>,
    /// Optional session key manager for key rotation.
    pub(crate) key_manager: Option<SessionKeyManager>,
    /// Pending ephemeral keypair for in-progress key rotation.
    pub(crate) pending_rotation:
        Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,

    // ── Counters & Statistics ────────────────────────────────────────────────
    /// Outgoing chat message counter (monotonic, for replay protection).
    pub(crate) chat_send_counter: Arc<RwLock<u64>>,
    /// Wire-level TX bytes counter.
    pub(crate) wire_tx: Arc<std::sync::atomic::AtomicU64>,
}

impl WebRTCConnection {
    /// Check if the peer is alive by sending an `AreYouAwake` probe.
    ///
    /// Waits for `ImAwake` response within the configured timeout.
    /// This should be called before sending messages or files to ensure
    /// the remote peer is still responsive.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The control channel is not open or available
    /// - The peer does not respond within the timeout
    pub async fn check_peer_alive(&self) -> Result<()> {
        use crate::core::config::AWAKE_CHECK_TIMEOUT;

        // Fast path: check if the control channel is open
        let cc = self.control_channel.read().await;
        if let Some(dc) = cc.as_ref() {
            if dc.ready_state()
                != webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
            {
                return Err(anyhow!("Control channel not open"));
            }
        } else {
            return Err(anyhow!("Control channel not available"));
        }
        drop(cc);

        self.send_control(&ControlMessage::AreYouAwake).await?;

        match tokio::time::timeout(AWAKE_CHECK_TIMEOUT, self.awake_notify.notified()).await {
            Ok(()) => Ok(()),
            Err(_) => Err(anyhow!("Peer not responding to awake check")),
        }
    }

    /// Get the remote IP address from the WebRTC ICE connection.
    ///
    /// Returns the IP address of the selected ICE candidate pair, if available.
    /// Returns `None` if the connection is not established or no candidate is selected.
    pub async fn get_remote_ip(&self) -> Option<String> {
        use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;

        if self.peer_connection.connection_state() != RTCPeerConnectionState::Connected {
            return None;
        }

        // Navigate: SCTP -> DTLS -> ICE transport
        let sctp = self.peer_connection.sctp();
        let dtls = sctp.transport();
        let ice = dtls.ice_transport();
        let selected_pair = ice.get_selected_candidate_pair().await?;

        let ip = selected_pair.remote.address;
        let port = selected_pair.remote.port;

        (!ip.is_empty()).then(|| format!("{}:{}", ip, port))
    }
}
