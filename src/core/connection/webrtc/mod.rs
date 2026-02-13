//! WebRTCConnection: multi-use data channel (messages + files)
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

pub(crate) const FRAME_CONTROL: u8 = 0x01;
pub(crate) const FRAME_CHUNK: u8 = 0x02;

/// Well-known channel ID used as `transaction_id` in [`AuthenticatedMessage`]
/// for chat HMAC authentication. Provides domain separation from file-transfer
/// HMACs which use real transaction UUIDs.
pub(crate) const CHAT_HMAC_CHANNEL: Uuid = Uuid::from_bytes([
    0xC0, 0xDE, 0xCA, 0xFE, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0xC4, 0xA7, 0x01,
]);

/// Derive a separate HMAC key from the shared encryption key.
/// Prevents key-reuse between AES-256-GCM encryption and HMAC-SHA3-256.
pub(crate) fn derive_chat_hmac_key(shared_key: &[u8; 32]) -> [u8; 32] {
    crate::utils::crypto::hmac_sha3_256(shared_key, b"crossdrop-chat-hmac-v1")
}

// ── Signaling (exchanged via Iroh, not on data channel) ──────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalingMessage {
    Offer(String),
    Answer(String),
    IceCandidate(String),
}

// ── Control messages (JSON, sent as FRAME_CONTROL) ───────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Plain text / chat message
    Text(Vec<u8>),
    /// Display name announcement
    DisplayName(String),
    /// File metadata (sent before chunks)
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
    /// Final hash for verification (includes Merkle root computed during send)
    Hash {
        file_id: Uuid,
        sha3_256: Vec<u8>,
        /// Merkle root computed incrementally from per-chunk SHA3-256 hashes.
        #[serde(default)]
        merkle_root: Option<[u8; 32]>,
    },
    /// Hash verification result
    HashResult { file_id: Uuid, ok: bool },
    /// Transaction-level transfer request
    TransactionRequest {
        transaction_id: Uuid,
        display_name: String,
        manifest: TransactionManifest,
        total_size: u64,
    },
    /// Transaction-level response from receiver
    TransactionResponse {
        transaction_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
        reject_reason: Option<String>,
    },
    /// Transaction completion confirmation
    TransactionComplete { transaction_id: Uuid },
    /// Transaction cancellation
    TransactionCancel {
        transaction_id: Uuid,
        reason: Option<String>,
    },
    /// Resume request referencing a transaction ID
    TransactionResumeRequest { resume_info: ResumeInfo },
    /// Resume response from sender
    TransactionResumeResponse {
        transaction_id: Uuid,
        accepted: bool,
    },
    /// Remote list request
    LsRequest { path: String },
    /// Remote list response
    LsResponse {
        path: String,
        entries: Vec<crate::workers::app::RemoteEntry>,
    },
    /// Fetch remote file/folder
    FetchRequest { path: String, is_folder: bool },
    /// Remote access disabled error
    RemoteAccessDisabled,
    /// Direct (1-to-1) chat message — distinct from room Text.
    DirectMessage(Vec<u8>),
    /// Ephemeral typing indicator (no payload needed).
    Typing,
    /// Authenticated room chat message (HMAC + monotonic counter protected).
    AuthenticatedText(Vec<u8>),
    /// Authenticated direct message (HMAC + monotonic counter protected).
    AuthenticatedDm(Vec<u8>),
    /// Key rotation: peer sends a fresh ephemeral X25519 public key.
    KeyRotation { ephemeral_pub: Vec<u8> },
    /// Request retransmission of specific chunks (receiver → sender, on integrity failure).
    /// The receiver detected Merkle root mismatch and identified corrupted chunks.
    /// Contains the list of chunk indices that need to be resent.
    ChunkRetransmitRequest {
        file_id: Uuid,
        /// List of chunk indices that failed Merkle proof verification.
        chunk_indices: Vec<u32>,
    },
    /// Acknowledge transaction completion (receiver → sender).
    /// Sent after the receiver processes `TransactionComplete`.
    TransactionCompleteAck { transaction_id: Uuid },
    /// Pre-communication liveness probe — peer should reply with ImAwake.
    AreYouAwake,
    /// Reply to AreYouAwake — confirms the peer is alive and ready.
    ImAwake,
    /// File received confirmation (receiver → sender).
    /// Sent after the receiver has fully processed and saved a file.
    /// This allows the sender to continue sending the next file without waiting.
    FileReceived { file_id: Uuid },
}

// ── App-facing events ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ConnectionMessage {
    TextReceived(Vec<u8>),
    /// A direct (1-to-1) message received from a peer.
    DmReceived(Vec<u8>),
    /// The peer is currently typing.
    TypingReceived,
    DisplayNameReceived(String),
    FileSaved {
        file_id: Uuid,
        filename: String,
        path: String,
        /// Merkle root computed from received chunk hashes.
        merkle_root: [u8; 32],
    },
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
    SendProgress {
        file_id: Uuid,
        filename: String,
        sent_chunks: u32,
        total_chunks: u32,
        /// Bytes sent on the wire for this batch (post-compression/encryption).
        wire_bytes: u64,
    },
    SendComplete {
        file_id: Uuid,
        success: bool,
    },
    Debug(String),
    LsResponse {
        path: String,
        entries: Vec<crate::workers::app::RemoteEntry>,
    },
    RemoteAccessDisabled,
    RemoteFetchRequest {
        path: String,
        is_folder: bool,
    },
    /// Retransmission requested by peer (integrity failure for specific chunks).
    ChunkRetransmitRequested {
        file_id: Uuid,
        /// List of chunk indices that need to be resent.
        chunk_indices: Vec<u32>,
    },
    /// Transaction completion acknowledged by peer.
    TransactionCompleteAcked {
        transaction_id: Uuid,
    },
    /// Awake confirmation received from peer.
    AwakeReceived,
    /// File received confirmation from receiver.
    /// Sent after the receiver has fully processed and saved a file.
    FileReceivedAck {
        file_id: Uuid,
    },
    Disconnected,
    Error(String),
    /// Transaction-level events
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
}

// ── Internal state ───────────────────────────────────────────────────────────

/// Hash parameters buffered when the Hash control message arrives before
/// all chunks have been delivered on the data channel.
pub(crate) struct PendingHash {
    pub sha3_256: Vec<u8>,
    pub merkle_root: Option<[u8; 32]>,
}

pub(crate) struct ReceiveFileState {
    pub writer: StreamingFileWriter,
    /// Buffered Hash — set when the Hash control message arrives before
    /// the last chunk has been written.  Consumed by the chunk handler
    /// when the final chunk completes the file.
    pub pending_hash: Option<PendingHash>,
}

// ── Wire-level statistics ────────────────────────────────────────────────────

// ── Encryption helpers ───────────────────────────────────────────────────────

/// Compress data with Brotli (quality 4 for speed/ratio balance).
pub(crate) fn compress_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut compressed = Vec::new();
    {
        // Quality 4: good balance between speed and compression ratio for real-time transfer
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

/// Encrypt data using a pre-initialized AES-256-GCM cipher.
/// Returns nonce (12 bytes) || ciphertext.
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
/// Expects nonce (12 bytes) || ciphertext.
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

/// Encrypt data with AES-256-GCM. Returns nonce (12 bytes) || ciphertext.
pub(crate) fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    encrypt_with(&cipher, plaintext)
}

/// Decrypt data: expects nonce (12 bytes) || ciphertext.
pub(crate) fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    decrypt_with(&cipher, data)
}

/// Forward a [`ConnectionMessage`] to the application channel, if present.
/// No-op when `app_tx` is `None` (e.g. during tests or headless operation).
pub(crate) fn notify_app(
    app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>,
    msg: ConnectionMessage,
) {
    if let Some(tx) = app_tx {
        let _ = tx.send(msg);
    }
}

/// Sanitize a relative path by sanitizing each component individually.
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

pub struct WebRTCConnection {
    pub(crate) peer_connection: Arc<RTCPeerConnection>,
    pub(crate) control_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,
    pub(crate) data_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,
    pub(crate) app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    pub(crate) accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
    /// Per-file chunk bitmaps for resume.  Registered alongside destinations
    /// before the sender re-sends a resumed file.  The Metadata handler
    /// consumes the bitmap to open the temp file without truncating.
    pub(crate) resume_bitmaps:
        Arc<RwLock<HashMap<Uuid, crate::core::pipeline::chunk::ChunkBitmap>>>,
    pub(crate) shared_key: Arc<RwLock<[u8; 32]>>,
    pub(crate) key_manager: Option<SessionKeyManager>,
    /// Pending local ephemeral keypair for an in-progress key rotation.
    pub(crate) pending_rotation:
        Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,
    /// Outgoing chat message counter (monotonically increasing, shared by room + DM).
    pub(crate) chat_send_counter: Arc<RwLock<u64>>,
    /// Wire-level statistics: atomic counters for TX/RX bytes.
    pub(crate) wire_tx: Arc<std::sync::atomic::AtomicU64>,
    /// Notified when an `ImAwake` response is received from the peer.
    pub(crate) awake_notify: Arc<tokio::sync::Notify>,

    /// Semaphore gating how many files can be in-flight (sent but not yet
    /// acknowledged via FileReceived). Sender pauses when all permits are taken.
    pub(crate) file_ack_semaphore: Arc<Semaphore>,
}

impl WebRTCConnection {
    /// Check if the peer is alive by sending an `AreYouAwake` probe and
    /// waiting for `ImAwake` within [`AWAKE_CHECK_TIMEOUT`].
    ///
    /// This should be called before sending messages or files to ensure
    /// the remote peer is still responsive.
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
    /// Returns the IP address of the selected ICE candidate pair, if available.
    pub async fn get_remote_ip(&self) -> Option<String> {
        use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;

        // Check if connection is established
        if self.peer_connection.connection_state() != RTCPeerConnectionState::Connected {
            return None;
        }

        // Get the SCTP transport which gives us access to the underlying ICE transport
        let sctp = self.peer_connection.sctp();
        let dtls = sctp.transport();
        let ice = dtls.ice_transport();

        // Get the selected candidate pair
        let selected_pair = ice.get_selected_candidate_pair().await?;

        // Extract the remote candidate's IP address
        let remote_candidate = selected_pair.remote;
        let ip = remote_candidate.address;
        let port = remote_candidate.port;

        // Return formatted IP:port
        if !ip.is_empty() {
            Some(format!("{}:{}", ip, port))
        } else {
            None
        }
    }
}
