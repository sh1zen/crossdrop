//! WebRTCConnection: multi-use data channel (messages + files)
//! - Uses compact binary framing for file chunks (no JSON overhead)
//! - JSON-serialized ChannelPayload for control messages only
//! - File transfer protocol: FileOffer -> FileResponse -> Metadata -> Chunk* -> Hash -> HashResult
//! - Chunked transfer pipelined in batches, SHA3-256 verification
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
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use brotli::{CompressorWriter, Decompressor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
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
    0xC0, 0xDE, 0xCA, 0xFE, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0xC4, 0xA7,
    0x01,
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
    /// Heartbeat ping — peer should reply with Pong.
    Ping,
    /// Heartbeat pong — reply to a Ping.
    Pong,
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
    /// Heartbeat pong received from peer.
    PongReceived,
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

/// Atomic counters tracking every byte crossing the network boundary.
/// Updated at the lowest possible level — inside `send_encrypted` (TX)
/// and `on_message` (RX) — so they capture ALL traffic: file chunks,
/// control messages, heartbeats, chat, key rotation, errors, etc.
#[derive(Debug, Default)]
pub struct WireStats {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
}

impl WireStats {
    pub fn new() -> Self {
        Self {
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
        }
    }

    pub fn add_tx(&self, bytes: u64) {
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_rx(&self, bytes: u64) {
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn total_tx(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    pub fn total_rx(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }
}

impl Clone for WireStats {
    fn clone(&self) -> Self {
        Self {
            tx_bytes: AtomicU64::new(self.tx_bytes.load(Ordering::Relaxed)),
            rx_bytes: AtomicU64::new(self.rx_bytes.load(Ordering::Relaxed)),
        }
    }
}

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
    pub(crate) _recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
    pub(crate) _pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>, u64)>>>>,
    pub(crate) accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
    pub(crate) shared_key: Arc<RwLock<[u8; 32]>>,
    pub(crate) key_manager: Option<SessionKeyManager>,
    /// Pending local ephemeral keypair for an in-progress key rotation.
    pub(crate) pending_rotation:
        Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,
    pub(crate) _remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
    /// Outgoing chat message counter (monotonically increasing, shared by room + DM).
    pub(crate) chat_send_counter: Arc<RwLock<u64>>,
    /// Last seen incoming chat counter (replay protection).
    pub(crate) _chat_recv_counter: Arc<RwLock<u64>>,
    /// Wire-level statistics: tracks EVERY byte sent/received on the wire.
    pub(crate) wire_stats: Arc<WireStats>,
}

impl WebRTCConnection {
    /// Get the wire-level statistics handle (shareable across threads).
    pub fn wire_stats(&self) -> Arc<WireStats> {
        self.wire_stats.clone()
    }
}
