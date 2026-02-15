//! WebRTCConnection: multi-use data channel (messages + files)
//! - Uses compact binary framing for file chunks (no JSON overhead)
//! - JSON-serialized ChannelPayload for control messages only
//! - File transfer protocol: FileOffer -> FileResponse -> Metadata -> Chunk* -> Hash -> HashResult
//! - Chunked transfer pipelined in batches, SHA3-256 verification
//! - Reliable delivery delegated to WebRTC SCTP (no application-level ACKs)
//! - AES-256-GCM encryption with per-peer keys
//! - Brotli compression for control messages only (chunks skip compression)

use crate::core::connection::crypto::SessionKeyManager;
use crate::core::pipeline::receiver::StreamingFileWriter;
use crate::core::security::message_auth::{AuthenticatedMessage, MessageAuthenticator};
use crate::core::transaction::{ResumeInfo, TransactionManifest};
use aes_gcm::{
    aead::{Aead, KeyInit}, Aes256Gcm,
    Nonce,
};
use anyhow::{anyhow, Context, Result};
use brotli::{CompressorWriter, Decompressor};
use bytes::{BufMut, Bytes};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time::timeout;
use tracing::{error, info, warn};
use uuid::Uuid;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::{SettingEngine, SctpMaxMessageSize};
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_gatherer_state::RTCIceGathererState;
use webrtc::ice_transport::ice_gathering_state::RTCIceGatheringState;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

// ── Constants ────────────────────────────────────────────────────────────────

use crate::core::config::{CHUNK_SIZE, CONNECTION_TIMEOUT, DATA_CHANNEL_TIMEOUT, ICE_GATHER_TIMEOUT, MAX_PENDING_CHUNKS_PER_FILE, MAX_PENDING_FILE_IDS, PIPELINE_SIZE, SCTP_MAX_MESSAGE_SIZE};

// ── Binary Frame Format ──────────────────────────────────────────────────────
//
// All messages on the data channel use this compact binary envelope:
//
//   [1 byte: frame_type] [N bytes: payload]
//
// Frame types:
//   0x01 = Control (JSON-encoded ControlMessage)
//   0x02 = Chunk   (binary: 16 bytes file_id + 4 bytes seq + raw data)
//
// This eliminates JSON+base64 overhead for bulk data transfer.
// A 256 KB chunk costs 256 KB + 21 bytes framing + 29 bytes AES-GCM envelope
// instead of ~700 KB with JSON+base64.
// Reliable delivery is guaranteed by WebRTC's SCTP layer (no application-level ACKs).

const FRAME_CONTROL: u8 = 0x01;
const FRAME_CHUNK: u8 = 0x02;

/// Well-known channel ID used as `transaction_id` in [`AuthenticatedMessage`]
/// for chat HMAC authentication. Provides domain separation from file-transfer
/// HMACs which use real transaction UUIDs.
const CHAT_HMAC_CHANNEL: Uuid = Uuid::from_bytes([
    0xC0, 0xDE, 0xCA, 0xFE, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0xC4, 0xA7, 0x01,
]);

/// Derive a separate HMAC key from the shared encryption key.
/// Prevents key-reuse between AES-256-GCM encryption and HMAC-SHA3-256.
fn derive_chat_hmac_key(shared_key: &[u8; 32]) -> [u8; 32] {
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
struct PendingHash {
    sha3_256: Vec<u8>,
    merkle_root: Option<[u8; 32]>,
}

struct ReceiveFileState {
    writer: StreamingFileWriter,
    /// Buffered Hash — set when the Hash control message arrives before
    /// the last chunk has been written.  Consumed by the chunk handler
    /// when the final chunk completes the file.
    pending_hash: Option<PendingHash>,
}

// ── Encryption helpers ───────────────────────────────────────────────────────

/// Compress data with Brotli (quality 4 for speed/ratio balance).
fn compress_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut compressed = Vec::new();
    {
        // Quality 4: good balance between speed and compression ratio for real-time transfer
        let mut compressor = CompressorWriter::new(&mut compressed, 4096, 4, 22);
        compressor.write_all(data)?;
    }
    Ok(compressed)
}

/// Decompress Brotli-compressed data.
fn decompress_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut decompressor = Decompressor::new(data, 4096);
    let mut decompressed = Vec::new();
    decompressor.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

/// Encrypt data using a pre-initialized AES-256-GCM cipher.
/// Returns nonce (12 bytes) || ciphertext.
fn encrypt_with(cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<Vec<u8>> {
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
fn decrypt_with(cipher: &Aes256Gcm, data: &[u8]) -> Result<Vec<u8>> {
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
fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    encrypt_with(&cipher, plaintext)
}

/// Decrypt data: expects nonce (12 bytes) || ciphertext.
fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    decrypt_with(&cipher, data)
}

// ── Binary frame encode/decode ───────────────────────────────────────────────

/// Encode a binary chunk frame: [0x02][16 bytes uuid][4 bytes seq BE][payload]
#[allow(dead_code)]
fn encode_chunk_frame(file_id: Uuid, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 16 + 4 + payload.len());
    buf.put_u8(FRAME_CHUNK);
    buf.extend_from_slice(file_id.as_bytes());
    buf.put_u32(seq);
    buf.extend_from_slice(payload);
    buf
}

/// Encode a binary chunk frame into a reusable buffer, clearing it first.
/// [0x02][16 bytes uuid][4 bytes seq BE][payload]
fn encode_chunk_frame_into(buf: &mut Vec<u8>, file_id: Uuid, seq: u32, payload: &[u8]) {
    buf.clear();
    buf.reserve(1 + 16 + 4 + payload.len());
    buf.put_u8(FRAME_CHUNK);
    buf.extend_from_slice(file_id.as_bytes());
    buf.put_u32(seq);
    buf.extend_from_slice(payload);
}

/// Encode a control frame: [0x01][json bytes]
fn encode_control_frame(msg: &ControlMessage) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(msg)?;
    let mut buf = Vec::with_capacity(1 + json.len());
    buf.put_u8(FRAME_CONTROL);
    buf.extend_from_slice(&json);
    Ok(buf)
}

/// Forward a [`ConnectionMessage`] to the application channel, if present.
/// No-op when `app_tx` is `None` (e.g. during tests or headless operation).
fn notify_app(app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>, msg: ConnectionMessage) {
    if let Some(tx) = app_tx {
        let _ = tx.send(msg);
    }
}

// ── WebRTCConnection ─────────────────────────────────────────────────────────

pub struct WebRTCConnection {
    peer_connection: Arc<RTCPeerConnection>,
    control_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,
    data_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,
    app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    _recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
    _pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>, u64)>>>>,  // (seq, data, wire_bytes)
    accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
    shared_key: Arc<RwLock<[u8; 32]>>,
    key_manager: Option<SessionKeyManager>,
    /// Pending local ephemeral keypair for an in-progress key rotation.
    pending_rotation: Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,
    _remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
    /// Outgoing chat message counter (monotonically increasing, shared by room + DM).
    chat_send_counter: Arc<RwLock<u64>>,
    /// Last seen incoming chat counter (replay protection).
    _chat_recv_counter: Arc<RwLock<u64>>,
}

impl WebRTCConnection {
    fn default_ice_servers() -> Vec<RTCIceServer> {
        vec![
            RTCIceServer {
                urls: vec!["stun:stun.l.google.com:19302".into()],
                username: String::new(),
                credential: String::new(),
            },
            RTCIceServer {
                urls: vec!["turn:openrelay.metered.ca:80".into()],
                username: "openrelayproject".into(),
                credential: "openrelayproject".into(),
            },
        ]
    }

    async fn create_webrtc_api() -> Result<webrtc::api::API> {
        let mut me = MediaEngine::default();
        let reg = register_default_interceptors(Registry::new(), &mut me)?;

        // Raise SCTP send limit so 16 MB+ chunks survive compression
        // expansion + AES-GCM overhead without hitting the default 64 KB cap.
        let mut se = SettingEngine::default();
        se.set_sctp_max_message_size_can_send(SctpMaxMessageSize::Bounded(SCTP_MAX_MESSAGE_SIZE));
        se.set_include_loopback_candidate(true);

        Ok(APIBuilder::new()
            .with_setting_engine(se)
            .with_media_engine(me)
            .with_interceptor_registry(reg)
            .build())
    }

    async fn gather_local_description(pc: &Arc<RTCPeerConnection>) -> Result<String> {
        if pc.ice_gathering_state() == RTCIceGatheringState::Complete {
            let desc = pc
                .local_description()
                .await
                .ok_or_else(|| anyhow!("No local description after ICE gathering"))?;
            return Ok(serde_json::to_string(&desc)?);
        }

        let (tx, rx) = oneshot::channel::<()>();
        let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
        pc.on_ice_gathering_state_change(Box::new(move |state| {
            let tx = tx.clone();
            Box::pin(async move {
                if state == RTCIceGathererState::Complete {
                    if let Ok(mut guard) = tx.lock() {
                        if let Some(tx) = guard.take() {
                            let _ = tx.send(());
                        }
                    }
                }
            })
        }));

        if pc.ice_gathering_state() == RTCIceGatheringState::Complete {
            let desc = pc
                .local_description()
                .await
                .ok_or_else(|| anyhow!("No local description after ICE gathering"))?;
            return Ok(serde_json::to_string(&desc)?);
        }

        timeout(ICE_GATHER_TIMEOUT, rx)
            .await
            .context("ICE gathering timeout")?
            .context("ICE gathering channel closed")?;

        let desc = pc
            .local_description()
            .await
            .ok_or_else(|| anyhow!("No local description after ICE gathering"))?;
        Ok(serde_json::to_string(&desc)?)
    }

    // ── Offer / Answer ───────────────────────────────────────────────────────

    pub async fn create_offer(
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
        shared_key: Arc<RwLock<[u8; 32]>>,
        key_manager: Option<SessionKeyManager>,
        remote_access: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(Self, SignalingMessage)> {
        let api = Self::create_webrtc_api().await?;
        let pc = Arc::new(
            api.new_peer_connection(RTCConfiguration {
                ice_servers: Self::default_ice_servers(),
                ..Default::default()
            })
            .await?,
        );

        // Monitor for disconnection.
        // NOTE: wait_connected() later replaces this callback, so these
        // handlers are only active during the handshake phase. After the
        // connection is established, offline detection is done exclusively
        // via the heartbeat mechanism in spawn_heartbeat().
        if let Some(tx) = &app_tx {
            let tx = tx.clone();
            pc.on_peer_connection_state_change(Box::new(move |s| {
                let tx = tx.clone();
                Box::pin(async move {
                    match s {
                        RTCPeerConnectionState::Connected => {
                            info!(event = "webrtc_connected", "WebRTC connection established");
                        }
                        RTCPeerConnectionState::Failed => {
                            // Failed is terminal — connection cannot recover.
                            error!(event = "webrtc_failed", "WebRTC connection failed");
                            let _ = tx.send(ConnectionMessage::Disconnected);
                        }
                        RTCPeerConnectionState::Disconnected => {
                            // Disconnected is TRANSIENT — ICE may recover.
                            // Log but do NOT fire Disconnected immediately.
                            // The heartbeat will detect true failures.
                            warn!(
                                event = "webrtc_disconnected",
                                "WebRTC transient disconnect (ICE may recover)"
                            );
                        }
                        RTCPeerConnectionState::Closed => {
                            // Closed is always caused by US calling close().
                            // Do NOT send Disconnected — the caller that invoked
                            // close() is responsible for any cleanup.
                            info!(
                                event = "webrtc_closed",
                                "WebRTC connection closed (locally initiated)"
                            );
                        }
                        _ => {}
                    }
                })
            }));
        }

        let control_channel_lock = Arc::new(RwLock::new(None));
        let data_channel_lock = Arc::new(RwLock::new(None));
        let recv_state = Arc::new(RwLock::new(HashMap::new()));
        let pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>, u64)>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let accepted_destinations = Arc::new(RwLock::new(HashMap::new()));

        let pending_rotation: Arc<
            RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>,
        > = Arc::new(RwLock::new(None));

        let chat_send_counter = Arc::new(RwLock::new(0u64));
        let chat_recv_counter = Arc::new(RwLock::new(0u64));

        // Explicit ordered + fully reliable (SCTP default, no partial reliability).
        // Not setting max_retransmits / max_packet_life_time = unlimited retransmits.
        let dc_init = Some(RTCDataChannelInit {
            ordered: Some(true),
            ..Default::default()
        });
        let cdc = pc.create_data_channel("control", dc_init.clone()).await?;
        let ra = Arc::new(remote_access);
        Self::attach_dc_handlers(
            &cdc,
            recv_state.clone(),
            pending_chunks.clone(),
            accepted_destinations.clone(),
            app_tx.clone(),
            shared_key.clone(),
            ra.clone(),
            key_manager.clone(),
            pending_rotation.clone(),
            chat_recv_counter.clone(),
        )
        .await;
        *control_channel_lock.write().await = Some(cdc);

        let ddc = pc.create_data_channel("data", dc_init).await?;
        Self::attach_dc_handlers(
            &ddc,
            recv_state.clone(),
            pending_chunks.clone(),
            accepted_destinations.clone(),
            app_tx.clone(),
            shared_key.clone(),
            ra.clone(),
            key_manager.clone(),
            pending_rotation.clone(),
            chat_recv_counter.clone(),
        )
        .await;
        *data_channel_lock.write().await = Some(ddc);

        let offer = pc.create_offer(None).await?;
        pc.set_local_description(offer).await?;
        let gathered_sdp = Self::gather_local_description(&pc).await?;

        Ok((
            Self {
                peer_connection: pc,
                control_channel: control_channel_lock,
                data_channel: data_channel_lock,
                app_tx,
                _recv_state: recv_state,
                _pending_chunks: pending_chunks,
                accepted_destinations,
                shared_key,
                key_manager,
                pending_rotation,
                _remote_access: ra,
                chat_send_counter,
                _chat_recv_counter: chat_recv_counter,
            },
            SignalingMessage::Offer(gathered_sdp),
        ))
    }

    pub async fn accept_offer(
        offer: SignalingMessage,
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
        shared_key: Arc<RwLock<[u8; 32]>>,
        key_manager: Option<SessionKeyManager>,
        remote_access: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(Self, SignalingMessage)> {
        let api = Self::create_webrtc_api().await?;
        let pc = Arc::new(
            api.new_peer_connection(RTCConfiguration {
                ice_servers: Self::default_ice_servers(),
                ..Default::default()
            })
            .await?,
        );

        // Monitor for disconnection.
        // NOTE: wait_connected() later replaces this callback, so these
        // handlers are only active during the handshake phase.
        if let Some(tx) = &app_tx {
            let tx = tx.clone();
            pc.on_peer_connection_state_change(Box::new(move |s| {
                let tx = tx.clone();
                Box::pin(async move {
                    match s {
                        RTCPeerConnectionState::Connected => {
                            info!(
                                event = "webrtc_connected",
                                "WebRTC connection established (answerer)"
                            );
                        }
                        RTCPeerConnectionState::Failed => {
                            error!(
                                event = "webrtc_failed",
                                "WebRTC connection failed (answerer)"
                            );
                            let _ = tx.send(ConnectionMessage::Disconnected);
                        }
                        RTCPeerConnectionState::Disconnected => {
                            // Transient — ICE may recover, do not fire disconnect.
                            warn!(
                                event = "webrtc_disconnected",
                                "WebRTC transient disconnect (answerer, ICE may recover)"
                            );
                        }
                        RTCPeerConnectionState::Closed => {
                            // Locally initiated close — do nothing.
                            info!(
                                event = "webrtc_closed",
                                "WebRTC connection closed (answerer, locally initiated)"
                            );
                        }
                        _ => {}
                    }
                })
            }));
        }

        let control_channel_lock = Arc::new(RwLock::new(None));
        let data_channel_lock = Arc::new(RwLock::new(None));
        let recv_state = Arc::new(RwLock::new(HashMap::new()));
        let pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>, u64)>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let accepted_destinations = Arc::new(RwLock::new(HashMap::new()));

        {
            let cl = control_channel_lock.clone();
            let dl = data_channel_lock.clone();
            let rs = recv_state.clone();
            let pc_chunks = pending_chunks.clone();
            let ad = accepted_destinations.clone();
            let atx = app_tx.clone();
            let ra = Arc::new(remote_access);
            let ra_outer = ra.clone();
            let pending_rotation: Arc<
                RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>,
            > = Arc::new(RwLock::new(None));
            let pending_rotation_outer = pending_rotation.clone();
            let chat_send_counter = Arc::new(RwLock::new(0u64));
            let chat_recv_counter = Arc::new(RwLock::new(0u64));
            let crc = chat_recv_counter.clone();
            let sk = shared_key.clone();
            let km = key_manager.clone();
            let pr = pending_rotation.clone();
            pc.on_data_channel(Box::new(move |dc| {
                let cl = cl.clone();
                let dl = dl.clone();
                let rs = rs.clone();
                let pc_chunks = pc_chunks.clone();
                let ad = ad.clone();
                let atx = atx.clone();
                let ra = ra.clone();
                let sk = sk.clone();
                let km = km.clone();
                let pr = pr.clone();
                let crc = crc.clone();
                Box::pin(async move {
                    Self::attach_dc_handlers(&dc, rs, pc_chunks, ad, atx, sk, ra, km, pr, crc)
                        .await;
                    let label = dc.label().to_string();
                    if label == "control" {
                        *cl.write().await = Some(dc);
                    } else if label == "data" {
                        *dl.write().await = Some(dc);
                    }
                })
            }));

            let sdp = match offer {
                SignalingMessage::Offer(s) => s,
                _ => return Err(anyhow!("Expected Offer")),
            };
            let desc: RTCSessionDescription = serde_json::from_str(&sdp)?;
            pc.set_remote_description(desc).await?;

            let answer = pc.create_answer(None).await?;
            pc.set_local_description(answer).await?;
            let gathered_sdp = Self::gather_local_description(&pc).await?;

            Ok((
                Self {
                    peer_connection: pc,
                    control_channel: control_channel_lock,
                    data_channel: data_channel_lock,
                    app_tx,
                    _recv_state: recv_state,
                    _pending_chunks: pending_chunks,
                    accepted_destinations,
                    shared_key,
                    key_manager,
                    pending_rotation: pending_rotation_outer,
                    _remote_access: ra_outer,
                    chat_send_counter,
                    _chat_recv_counter: chat_recv_counter,
                },
                SignalingMessage::Answer(gathered_sdp),
            ))
        }
    }

    pub async fn set_answer(&self, answer: SignalingMessage) -> Result<()> {
        let sdp = match answer {
            SignalingMessage::Answer(s) => s,
            _ => return Err(anyhow!("Expected Answer")),
        };
        let desc: RTCSessionDescription = serde_json::from_str(&sdp)?;
        self.peer_connection.set_remote_description(desc).await?;
        Ok(())
    }

    // ── Wait helpers ─────────────────────────────────────────────────────────

    pub async fn wait_connected(&self) -> Result<()> {
        if self.peer_connection.connection_state() == RTCPeerConnectionState::Connected {
            return Ok(());
        }
        let (tx, mut rx) = mpsc::channel(1);
        self.peer_connection
            .on_peer_connection_state_change(Box::new(move |s| {
                let tx = tx.clone();
                Box::pin(async move {
                    if s == RTCPeerConnectionState::Connected {
                        let _ = tx.send(()).await;
                    }
                })
            }));
        timeout(CONNECTION_TIMEOUT, rx.recv())
            .await
            .context("Connection timeout")?;
        Ok(())
    }

    pub async fn wait_data_channels_open(&self) -> Result<()> {
        let (cdc, ddc) = {
            let start = std::time::Instant::now();
            loop {
                let cdc = self.control_channel.read().await.clone();
                let ddc = self.data_channel.read().await.clone();
                if cdc.is_some() && ddc.is_some() {
                    break (cdc.unwrap(), ddc.unwrap());
                }
                if start.elapsed() > DATA_CHANNEL_TIMEOUT {
                    return Err(anyhow!("Data channels not created within timeout"));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };

        for dc in [cdc, ddc] {
            if dc.ready_state() == RTCDataChannelState::Open {
                continue;
            }
            let (tx, mut rx) = mpsc::channel(1);
            let dc_clone = dc.clone();
            dc_clone.on_open(Box::new(move || {
                let tx = tx.clone();
                Box::pin(async move {
                    let _ = tx.send(()).await;
                })
            }));
            if dc_clone.ready_state() == RTCDataChannelState::Open {
                continue;
            }
            match timeout(DATA_CHANNEL_TIMEOUT, rx.recv()).await {
                Ok(_) => {}
                Err(_) => {
                    if dc_clone.ready_state() != RTCDataChannelState::Open {
                        return Err(anyhow!(
                            "Data channel {} open timeout (state: {:?})",
                            dc_clone.label(),
                            dc_clone.ready_state()
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    // ── Send helpers ─────────────────────────────────────────────────────────

    /// Send an encrypted frame on the given data channel.
    ///
    /// Wire envelope: `encrypt( [1-byte compress flag] + [payload] )`
    ///
    /// When `compress` is **true** the payload is brotli-compressed before
    /// encryption (good for small JSON control messages).  When **false** the
    /// raw payload is sent as-is (avoids wasting CPU on already-compressed
    /// file data and prevents brotli from *expanding* incompressible content).
    async fn send_encrypted(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        plaintext: &[u8],
        compress: bool,
    ) -> Result<usize> {
        if dc.ready_state() != RTCDataChannelState::Open {
            warn!(event = "send_channel_not_open", state = ?dc.ready_state(), "Attempted send on non-open data channel");
            return Err(anyhow!("Data channel not open: {:?}", dc.ready_state()));
        }

        // Build envelope: [compress_flag] + [maybe_compressed_plaintext]
        let envelope = if compress {
            let compressed = compress_data(plaintext).map_err(|e| {
                error!(event = "compress_failure", bytes = plaintext.len(), error = %e, "Compression failed before send");
                e
            })?;
            let mut env = Vec::with_capacity(1 + compressed.len());
            env.push(0x01);
            env.extend_from_slice(&compressed);
            env
        } else {
            let mut env = Vec::with_capacity(1 + plaintext.len());
            env.push(0x00);
            env.extend_from_slice(plaintext);
            env
        };

        let encrypted = encrypt(key, &envelope).map_err(|e| {
            error!(event = "encrypt_failure", bytes = envelope.len(), error = %e, "Encryption failed before send");
            e
        })?;
        let wire_bytes = encrypted.len();
        dc.send(&Bytes::from(encrypted)).await?;
        Ok(wire_bytes)
    }

    /// Send an encrypted frame using a pre-initialized cipher (avoids
    /// re-creating AES-256-GCM state per call — useful in hot loops).
    async fn send_encrypted_with_cipher(
        dc: &Arc<RTCDataChannel>,
        cipher: &Aes256Gcm,
        plaintext: &[u8],
        compress: bool,
    ) -> Result<usize> {
        if dc.ready_state() != RTCDataChannelState::Open {
            warn!(event = "send_channel_not_open", state = ?dc.ready_state(), "Attempted send on non-open data channel");
            return Err(anyhow!("Data channel not open: {:?}", dc.ready_state()));
        }

        let envelope = if compress {
            let compressed = compress_data(plaintext).map_err(|e| {
                error!(event = "compress_failure", bytes = plaintext.len(), error = %e, "Compression failed before send");
                e
            })?;
            let mut env = Vec::with_capacity(1 + compressed.len());
            env.push(0x01);
            env.extend_from_slice(&compressed);
            env
        } else {
            let mut env = Vec::with_capacity(1 + plaintext.len());
            env.push(0x00);
            env.extend_from_slice(plaintext);
            env
        };

        let encrypted = encrypt_with(cipher, &envelope).map_err(|e| {
            error!(event = "encrypt_failure", bytes = envelope.len(), error = %e, "Encryption failed before send");
            e
        })?;
        let wire_bytes = encrypted.len();
        dc.send(&Bytes::from(encrypted)).await?;
        Ok(wire_bytes)
    }

    /// Send a control message on the control channel, returning wire bytes sent.
    async fn send_control_counted(&self, msg: &ControlMessage) -> Result<usize> {
        let dc = self
            .control_channel
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Control channel not available"))?;
        let frame = encode_control_frame(msg)?;
        let key = *self.shared_key.read().await;
        Self::send_encrypted(&dc, &key, &frame, true).await
    }

    /// Send a control message on the control channel.
    pub async fn send_control(&self, msg: &ControlMessage) -> Result<()> {
        self.send_control_counted(msg).await.map(|_| ())
    }

    /// Send a control message on a specific data channel (static version).
    async fn send_control_on(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        msg: &ControlMessage,
    ) -> Result<()> {
        let frame = encode_control_frame(msg)?;
        Self::send_encrypted(dc, key, &frame, true).await?;
        Ok(())
    }

    /// Send a binary chunk frame on the data channel.
    /// Returns the number of bytes sent on the wire (post-encryption).
    /// Chunks are sent **without** brotli compression — file data is
    /// typically already compressed and brotli would just add latency.
    #[allow(dead_code)]
    async fn send_chunk(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        file_id: Uuid,
        seq: u32,
        payload: &[u8],
    ) -> Result<usize> {
        let frame = encode_chunk_frame(file_id, seq, payload);
        Self::send_encrypted(dc, key, &frame, false).await
    }

    // ── Public send API ──────────────────────────────────────────────────────

    /// Send a chat message (HMAC + counter authenticated, encrypted) — broadcast / room.
    pub async fn send_message(&self, bytes: Vec<u8>) -> Result<()> {
        let key = *self.shared_key.read().await;
        let hmac_key = derive_chat_hmac_key(&key);
        let counter = {
            let mut c = self.chat_send_counter.write().await;
            *c += 1;
            *c
        };
        let auth_msg = MessageAuthenticator::create(&hmac_key, CHAT_HMAC_CHANNEL, counter, bytes);
        let envelope = serde_json::to_vec(&auth_msg)?;
        self.send_control(&ControlMessage::AuthenticatedText(envelope))
            .await
    }

    /// Send a direct (1-to-1) chat message (HMAC + counter authenticated, encrypted).
    pub async fn send_dm(&self, bytes: Vec<u8>) -> Result<()> {
        let key = *self.shared_key.read().await;
        let hmac_key = derive_chat_hmac_key(&key);
        let counter = {
            let mut c = self.chat_send_counter.write().await;
            *c += 1;
            *c
        };
        let auth_msg = MessageAuthenticator::create(&hmac_key, CHAT_HMAC_CHANNEL, counter, bytes);
        let envelope = serde_json::to_vec(&auth_msg)?;
        self.send_control(&ControlMessage::AuthenticatedDm(envelope))
            .await
    }

    /// Send an ephemeral typing indicator.
    pub async fn send_typing(&self) -> Result<()> {
        self.send_control(&ControlMessage::Typing).await
    }

    /// Send display name to peer.
    pub async fn send_display_name(&self, name: String) -> Result<()> {
        self.send_control(&ControlMessage::DisplayName(name)).await
    }

    /// Send a file from disk with streaming read-ahead — no full-file memory allocation.
    ///
    /// Uses `pipeline::sender::spawn_reader` to prefetch chunks from disk into
    /// a bounded channel, and an `AdaptiveChunkSizer` to dynamically tune
    /// chunk size based on measured throughput.
    pub async fn send_file(
        &self,
        file_id: Uuid,
        file_path: impl Into<PathBuf>,
        filesize: u64,
        filename: impl Into<String>,
    ) -> Result<()> {
        self.send_file_resuming(file_id, file_path, filesize, filename, 0)
            .await
    }

    /// Send a file from disk, skipping the first `start_chunk` chunks (for resume).
    /// Chunks 0..start_chunk are still hashed but NOT transmitted.
    ///
    /// Streaming: reads chunks from disk via a prefetch buffer, never holds the
    /// entire file in memory.
    pub async fn send_file_resuming(
        &self,
        file_id: Uuid,
        file_path: impl Into<PathBuf>,
        filesize: u64,
        filename: impl Into<String>,
        start_chunk: u32,
    ) -> Result<()> {
        let filename = filename.into();
        let file_path = file_path.into();
        self.wait_data_channels_open().await?;

        let dc = self
            .data_channel
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Data channel not available"))?;

        let chunk_size = CHUNK_SIZE;
        let total_chunks = ((filesize as f64) / (chunk_size as f64)).ceil().max(1.0) as u32;

        // Send metadata on control channel first — receiver needs this
        // to create ReceiveFileState before chunks arrive.
        // Count wire bytes from metadata in TX stats.
        let metadata_wb = self.send_control_counted(&ControlMessage::Metadata {
            file_id,
            total_chunks,
            filename: filename.clone(),
            filesize,
        })
        .await? as u64;

        // Short sleep to give the Metadata frame a head-start on the control channel.
        // The receiver also buffers early-arriving chunks, so this is best-effort.
        tokio::time::sleep(Duration::from_millis(50)).await;

        info!(event = "file_send_start", file_id = %file_id, filename = %filename, filesize, total_chunks, start_chunk, "Starting file send");

        // Spawn disk reader with prefetch buffer
        let (mut chunk_rx, reader_handle) = crate::core::pipeline::sender::spawn_reader(
            file_path,
            filesize,
            total_chunks,
            chunk_size,
            start_chunk,
        );

        let mut sent_chunks: u32 = start_chunk;
        let key_lock = self.shared_key.clone();
        // Include metadata wire bytes in the first batch report.
        let mut batch_wire_bytes: u64 = metadata_wb;
        let mut batch_count: u32 = 0;

        let key = *key_lock.read().await;

        // Reuse cipher instance across the chunk loop to avoid per-chunk
        // AES-256-GCM key schedule overhead.
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;

        // Reusable frame buffer — cleared and refilled per chunk to avoid
        // per-chunk heap allocation of the metadata+payload container.
        let mut chunk_frame_buf: Vec<u8> = Vec::with_capacity(1 + 16 + 4 + chunk_size);

        // Drain prefetched chunks and send them
        while let Some(read_chunk) = chunk_rx.recv().await {
            encode_chunk_frame_into(&mut chunk_frame_buf, file_id, read_chunk.seq, &read_chunk.data);
            let wb = Self::send_encrypted_with_cipher(&dc, &cipher, &chunk_frame_buf, false).await?;
            batch_wire_bytes += wb as u64;
            batch_count += 1;
            sent_chunks += 1;

            // Report progress every PIPELINE_SIZE chunks
            if batch_count >= PIPELINE_SIZE as u32 {
                if let Some(tx) = &self.app_tx {
                    let _ = tx.send(ConnectionMessage::SendProgress {
                        file_id,
                        filename: filename.clone(),
                        sent_chunks,
                        total_chunks,
                        wire_bytes: batch_wire_bytes,
                    });
                }
                batch_wire_bytes = 0;
                batch_count = 0;
            }
        }

        // Wait for the reader to finish and get hash results
        let reader_result = reader_handle
            .await
            .map_err(|e| anyhow!("Reader task panicked: {}", e))?
            .map_err(|e| anyhow!("Reader error: {}", e))?;

        // Send final hash + Merkle root on control channel.
        // Count hash wire bytes in TX stats.
        let merkle_tree =
            crate::core::pipeline::merkle::MerkleTree::build(&reader_result.chunk_hashes);
        let hash_wb = self.send_control_counted(&ControlMessage::Hash {
            file_id,
            sha3_256: reader_result.sha3_256,
            merkle_root: Some(*merkle_tree.root()),
        })
        .await? as u64;

        batch_wire_bytes += hash_wb;

        // Report any remaining progress (including hash control message bytes).
        if batch_wire_bytes > 0 || batch_count > 0 {
            if let Some(tx) = &self.app_tx {
                let _ = tx.send(ConnectionMessage::SendProgress {
                    file_id,
                    filename: filename.clone(),
                    sent_chunks,
                    total_chunks,
                    wire_bytes: batch_wire_bytes,
                });
            }
        }

        Ok(())
    }

    // ── Transaction-level API ────────────────────────────────────────────────

    /// Send a transaction request to the peer.
    pub async fn send_transaction_request(
        &self,
        transaction_id: Uuid,
        display_name: String,
        manifest: TransactionManifest,
        total_size: u64,
    ) -> Result<()> {
        self.send_control(&ControlMessage::TransactionRequest {
            transaction_id,
            display_name,
            manifest,
            total_size,
        })
        .await
    }

    /// Send a transaction response (accept/reject).
    pub async fn send_transaction_response(
        &self,
        transaction_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
        reject_reason: Option<String>,
    ) -> Result<()> {
        self.send_control(&ControlMessage::TransactionResponse {
            transaction_id,
            accepted,
            dest_path,
            reject_reason,
        })
        .await
    }

    /// Send a transaction resume response.
    pub async fn send_transaction_resume_response(
        &self,
        transaction_id: Uuid,
        accepted: bool,
    ) -> Result<()> {
        self.send_control(&ControlMessage::TransactionResumeResponse {
            transaction_id,
            accepted,
        })
        .await
    }

    pub async fn send_transaction_cancel(
        &self,
        transaction_id: Uuid,
        reason: Option<String>,
    ) -> Result<()> {
        self.send_control(&ControlMessage::TransactionCancel {
            transaction_id,
            reason,
        })
        .await
    }

    pub async fn close(&self) -> Result<()> {
        self.peer_connection.close().await?;
        Ok(())
    }

    /// Register a destination path for a file_id so that incoming Metadata
    /// frames can find the correct save directory. Used by the TransferEngine
    /// when accepting an incoming transaction.
    pub async fn register_file_destination(&self, file_id: Uuid, dest_path: PathBuf) {
        self.accepted_destinations
            .write()
            .await
            .insert(file_id, dest_path);
    }

    /// Initiate a key rotation by generating a fresh ephemeral keypair,
    /// storing it in `pending_rotation`, and sending the public key to the peer.
    pub async fn initiate_key_rotation(&self) -> Result<()> {
        use crate::core::connection::crypto;

        if self.key_manager.is_none() {
            return Err(anyhow!("No SessionKeyManager — cannot rotate keys"));
        }
        let eph = crypto::prepare_rotation();
        let pub_bytes = eph.public.to_vec();
        *self.pending_rotation.write().await = Some(eph);
        self.send_control(&ControlMessage::KeyRotation {
            ephemeral_pub: pub_bytes,
        })
        .await?;
        info!(
            event = "key_rotation_initiated",
            "Sent ephemeral public key for rotation"
        );
        Ok(())
    }

    // ── Data channel message handler ─────────────────────────────────────────

    async fn attach_dc_handlers(
        dc: &Arc<RTCDataChannel>,
        recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
        pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>, u64)>>>>,
        accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
        shared_key: Arc<RwLock<[u8; 32]>>,
        remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
        key_manager: Option<SessionKeyManager>,
        pending_rotation: Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,
        chat_recv_counter: Arc<RwLock<u64>>,
    ) {
        let dc_clone = dc.clone();
        let rs = recv_state;
        let pc = pending_chunks;
        let ad = accepted_destinations;
        let atx = app_tx;
        let sk = shared_key;
        let km = key_manager;
        let pr = pending_rotation;
        let ra = remote_access;
        let crc = chat_recv_counter;

        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let rs = rs.clone();
            let pc = pc.clone();
            let ad = ad.clone();
            let atx = atx.clone();
            let dc = dc_clone.clone();
            let sk = sk.clone();
            let km = km.clone();
            let pr = pr.clone();
            let ra = ra.clone();
            let crc = crc.clone();

            Box::pin(async move {
                // Decrypt
                let key = *sk.read().await;
                let decrypted = match decrypt(&key, &msg.data) {
                    Ok(p) => p,
                    Err(e) => {
                        error!(event = "decrypt_failure", bytes = msg.data.len(), error = %e, "Decryption failed on incoming frame");
                        notify_app(&atx, ConnectionMessage::Error(format!("Decrypt error: {}", e)));
                        return;
                    }
                };

                // Envelope: [1-byte compress flag] + [payload]
                if decrypted.is_empty() {
                    return;
                }
                let compress_flag = decrypted[0];
                let inner = &decrypted[1..];

                let plaintext = if compress_flag == 0x01 {
                    match decompress_data(inner) {
                        Ok(p) => p,
                        Err(e) => {
                            error!(event = "decompress_failure", bytes = inner.len(), error = %e, "Decompression failed on incoming frame");
                            notify_app(&atx, ConnectionMessage::Error(format!("Decompress error: {}", e)));
                            return;
                        }
                    }
                } else {
                    inner.to_vec()
                };

                let wire_bytes = msg.data.len() as u64;

                if plaintext.is_empty() {
                    return;
                }

                let frame_type = plaintext[0];
                let payload = &plaintext[1..];

                match frame_type {
                    FRAME_CONTROL => match serde_json::from_slice::<ControlMessage>(payload) {
                        Ok(ctrl) => {
                            if let Err(e) = Self::handle_control(
                                &dc,
                                ctrl,
                                rs,
                                pc,
                                ad,
                                atx.clone(),
                                sk.clone(),
                                ra.clone(),
                                km.clone(),
                                pr.clone(),
                                crc.clone(),
                            )
                            .await
                            {
                                error!(event = "control_handle_error", error = %e, "Error handling control message");
                                notify_app(&atx, ConnectionMessage::Error(format!(
                                    "Control error: {}",
                                    e
                                )));
                            }
                        }
                        Err(e) => {
                            error!(event = "control_decode_error", bytes = payload.len(), error = %e, "Failed to decode control message");
                            notify_app(&atx, ConnectionMessage::Error(format!(
                                "Control decode error: {}",
                                e
                            )));
                        }
                    },
                    FRAME_CHUNK => {
                        // Binary: 16 bytes uuid + 4 bytes seq + payload
                        if payload.len() < 20 {
                            notify_app(&atx, ConnectionMessage::Error("Chunk frame too short".into()));
                            return;
                        }
                        let file_id = Uuid::from_bytes(payload[..16].try_into().unwrap());
                        let seq = u32::from_be_bytes(payload[16..20].try_into().unwrap());
                        let chunk_data = &payload[20..];

                        let mut map = rs.write().await;
                        if let Some(state) = map.get_mut(&file_id) {
                            match state.writer.write_chunk(seq, chunk_data).await {
                                Ok(()) => {
                                    if let Some(tx) = &atx {
                                        let _ = tx.send(ConnectionMessage::FileProgress {
                                            file_id,
                                            filename: state.writer.filename().to_string(),
                                            received_chunks: state.writer.received_chunks(),
                                            total_chunks: state.writer.total_chunks(),
                                            wire_bytes,
                                        });
                                    }

                                    // Check if this was the last chunk AND the
                                    // Hash control message already arrived
                                    // (buffered because it beat us on the
                                    // independent control channel).
                                    if state.writer.received_chunks() == state.writer.total_chunks() {
                                        if let Some(pending) = state.pending_hash.take() {
                                            let state = map.remove(&file_id).unwrap();
                                            drop(map);
                                            let key = *sk.read().await;
                                            if let Err(e) = Self::finalize_file_receive(
                                                &dc, file_id, state,
                                                pending.sha3_256,
                                                pending.merkle_root,
                                                &key, &atx,
                                            ).await {
                                                error!(
                                                    event = "deferred_finalize_error",
                                                    file_id = %file_id,
                                                    error = %e,
                                                    "Error in deferred file finalization"
                                                );
                                                notify_app(&atx, ConnectionMessage::Error(
                                                    format!("Deferred finalize error: {}", e)
                                                ));
                                            }
                                            return;
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Chunk {} for {} write error: {}", seq, file_id, e);
                                }
                            }

                        } else {
                            // Chunk arrived before Metadata — buffer with DoS bounds
                            drop(map);
                            let mut pending = pc.write().await;
                            // Limit pending file IDs
                            if !pending.contains_key(&file_id)
                                && pending.len() >= MAX_PENDING_FILE_IDS
                            {
                                warn!("Dropping pre-metadata chunk for {}: too many pending file IDs", file_id);
                                return;
                            }
                            let entry = pending.entry(file_id).or_default();
                            if entry.len() >= MAX_PENDING_CHUNKS_PER_FILE {
                                warn!("Dropping pre-metadata chunk {} for {}: pending buffer full", seq, file_id);
                                return;
                            }
                            tracing::debug!("Chunk {} for file {} buffered — Metadata not yet received", seq, file_id);
                            entry.push((seq, chunk_data.to_vec(), wire_bytes));
                        }
                    }
                    _ => {
                        notify_app(&atx, ConnectionMessage::Debug(format!(
                            "Unknown frame type: 0x{:02x}",
                            frame_type
                        )));
                    }
                }
            })
        }));
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_control(
        dc: &Arc<RTCDataChannel>,
        msg: ControlMessage,
        recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
        pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>, u64)>>>>,
        accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
        shared_key: Arc<RwLock<[u8; 32]>>,
        remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
        key_manager: Option<SessionKeyManager>,
        pending_rotation: Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,
        chat_recv_counter: Arc<RwLock<u64>>,
    ) -> Result<()> {
        let key = *shared_key.read().await;
        match msg {
            ControlMessage::Text(data) => {
                notify_app(&app_tx, ConnectionMessage::TextReceived(data));
            }
            ControlMessage::DirectMessage(data) => {
                notify_app(&app_tx, ConnectionMessage::DmReceived(data));
            }
            ControlMessage::Typing => {
                notify_app(&app_tx, ConnectionMessage::TypingReceived);
            }
            ControlMessage::AuthenticatedText(envelope) => {
                let hmac_key = derive_chat_hmac_key(&key);
                match serde_json::from_slice::<AuthenticatedMessage>(&envelope) {
                    Ok(auth_msg) => {
                        if !MessageAuthenticator::verify(&hmac_key, &auth_msg) {
                            warn!(
                                event = "chat_hmac_invalid",
                                "Rejected room chat: HMAC verification failed"
                            );
                            return Ok(());
                        }
                        let mut counter = chat_recv_counter.write().await;
                        if auth_msg.counter <= *counter {
                            warn!(
                                event = "chat_replay_detected",
                                counter = auth_msg.counter,
                                last_seen = *counter,
                                "Rejected room chat: replay detected"
                            );
                            return Ok(());
                        }
                        *counter = auth_msg.counter;
                        drop(counter);
                        notify_app(&app_tx, ConnectionMessage::TextReceived(auth_msg.payload));
                    }
                    Err(e) => {
                        warn!(event = "chat_auth_decode_error", error = %e, "Failed to decode authenticated room chat");
                    }
                }
            }
            ControlMessage::AuthenticatedDm(envelope) => {
                let hmac_key = derive_chat_hmac_key(&key);
                match serde_json::from_slice::<AuthenticatedMessage>(&envelope) {
                    Ok(auth_msg) => {
                        if !MessageAuthenticator::verify(&hmac_key, &auth_msg) {
                            warn!(
                                event = "dm_hmac_invalid",
                                "Rejected DM: HMAC verification failed"
                            );
                            return Ok(());
                        }
                        let mut counter = chat_recv_counter.write().await;
                        if auth_msg.counter <= *counter {
                            warn!(
                                event = "dm_replay_detected",
                                counter = auth_msg.counter,
                                last_seen = *counter,
                                "Rejected DM: replay detected"
                            );
                            return Ok(());
                        }
                        *counter = auth_msg.counter;
                        drop(counter);
                        notify_app(&app_tx, ConnectionMessage::DmReceived(auth_msg.payload));
                    }
                    Err(e) => {
                        warn!(event = "dm_auth_decode_error", error = %e, "Failed to decode authenticated DM");
                    }
                }
            }
            ControlMessage::DisplayName(name) => {
                notify_app(&app_tx, ConnectionMessage::DisplayNameReceived(name));
            }
            ControlMessage::Ping => {
                // Auto-reply with Pong
                let key = *shared_key.read().await;
                if let Err(e) = Self::send_control_on(dc, &key, &ControlMessage::Pong).await {
                    warn!(event = "pong_send_failed", error = %e, "Failed to send pong");
                }
            }
            ControlMessage::Pong => {
                notify_app(&app_tx, ConnectionMessage::PongReceived);
            }
            ControlMessage::Metadata {
                file_id,
                total_chunks,
                filename,
                filesize,
            } => {
                if filesize == 0 {
                    warn!(event = "zero_size_file", file_id = %file_id, filename = %filename, "Rejected file with zero size");
                    return Err(anyhow!("Cannot receive file with zero size"));
                }
                // Compute save path
                let dest_dir = accepted_destinations.write().await.remove(&file_id);
                let safe_name = sanitize_relative_path(&filename);
                let save_path = if let Some(dir) = &dest_dir {
                    dir.join(&safe_name)
                } else {
                    std::env::current_dir().unwrap_or_default().join(&safe_name)
                };

                tracing::info!(
                    "Receiving file '{}' ({} bytes, {} chunks) to: {}",
                    filename,
                    filesize,
                    total_chunks,
                    save_path.display()
                );

                // Create streaming writer — writes chunks directly to disk
                let writer = match StreamingFileWriter::new(
                    filename.clone(),
                    filesize,
                    total_chunks,
                    save_path,
                )
                .await
                {
                    Ok(w) => w,
                    Err(e) => {
                        error!(
                            event = "streaming_writer_create_failed",
                            file_id = %file_id,
                            filename = %filename,
                            error = %e,
                            "Failed to create streaming file writer"
                        );
                        return Err(anyhow!("Failed to create file writer: {}", e));
                    }
                };

                let st = ReceiveFileState { writer, pending_hash: None };
                recv_state.write().await.insert(file_id, st);

                // Process any chunks that arrived before this Metadata frame
                let buffered = {
                    let mut pending = pending_chunks.write().await;
                    pending.remove(&file_id).unwrap_or_default()
                };
                if !buffered.is_empty() {
                    tracing::debug!(
                        "Processing {} buffered chunks for file {}",
                        buffered.len(),
                        file_id
                    );
                    let mut map = recv_state.write().await;
                    if let Some(state) = map.get_mut(&file_id) {
                        for (seq, chunk_data, buffered_wire_bytes) in &buffered {
                            match state.writer.write_chunk(*seq, chunk_data).await {
                                Ok(()) => {
                                    if let Some(tx) = &app_tx {
                                        let _ = tx.send(ConnectionMessage::FileProgress {
                                            file_id,
                                            filename: state.writer.filename().to_string(),
                                            received_chunks: state.writer.received_chunks(),
                                            total_chunks: state.writer.total_chunks(),
                                            wire_bytes: *buffered_wire_bytes,
                                        });
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "Buffered chunk {} for {} write error: {}",
                                        seq, file_id, e
                                    );
                                }
                            }
                        }
                    }
                    drop(map);
                }

                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::Debug(format!(
                        "Receiving: {} ({} bytes, {} chunks)",
                        filename, filesize, total_chunks
                    )));
                }
            }
            ControlMessage::Hash {
                file_id,
                sha3_256,
                merkle_root: sender_merkle_root,
            } => {
                let mut map = recv_state.write().await;
                if let Some(state) = map.get_mut(&file_id) {
                    if state.writer.received_chunks() == state.writer.total_chunks() {
                        // All chunks already received — finalize immediately.
                        let state = map.remove(&file_id).unwrap();
                        drop(map);
                        Self::finalize_file_receive(
                            dc, file_id, state, sha3_256, sender_merkle_root,
                            &key, &app_tx,
                        ).await?;
                    } else {
                        // Chunks still in-flight on the data channel.
                        // Buffer the hash; the chunk handler will finalize
                        // when the last chunk arrives.
                        tracing::debug!(
                            event = "hash_buffered",
                            file_id = %file_id,
                            received = state.writer.received_chunks(),
                            total = state.writer.total_chunks(),
                            "Hash arrived before all chunks — buffering"
                        );
                        state.pending_hash = Some(PendingHash {
                            sha3_256,
                            merkle_root: sender_merkle_root,
                        });
                    }
                }
            }
            ControlMessage::HashResult { file_id, ok } => {
                if ok {
                    info!(event = "file_send_verified", file_id = %file_id, "File send complete: hash verified");
                } else {
                    error!(event = "file_integrity_failure", file_id = %file_id, "File send failed: hash mismatch");
                }
                notify_app(
                    &app_tx,
                    ConnectionMessage::SendComplete {
                        file_id,
                        success: ok,
                    },
                );
            }
            ControlMessage::LsRequest { path } => {
                tracing::info!("Remote ls request: {}", path);
                if !*remote_access.borrow() {
                    Self::send_control_on(dc, &key, &ControlMessage::RemoteAccessDisabled).await?;
                } else {
                    let mut entries = Vec::new();
                    if let Ok(mut read_dir) = fs::read_dir(&path).await {
                        while let Ok(Some(entry)) = read_dir.next_entry().await {
                            if let Ok(meta) = entry.metadata().await {
                                entries.push(crate::workers::app::RemoteEntry {
                                    name: entry.file_name().to_string_lossy().to_string(),
                                    is_dir: meta.is_dir(),
                                    size: meta.len(),
                                });
                            }
                        }
                    }
                    Self::send_control_on(dc, &key, &ControlMessage::LsResponse { path, entries })
                        .await?;
                }
            }
            ControlMessage::LsResponse { path, entries } => {
                notify_app(&app_tx, ConnectionMessage::LsResponse { path, entries });
            }
            ControlMessage::FetchRequest { path, is_folder } => {
                tracing::info!("Remote fetch request: {} (folder: {})", path, is_folder);
                if !*remote_access.borrow() {
                    Self::send_control_on(dc, &key, &ControlMessage::RemoteAccessDisabled).await?;
                } else {
                    notify_app(
                        &app_tx,
                        ConnectionMessage::RemoteFetchRequest { path, is_folder },
                    );
                }
            }
            ControlMessage::RemoteAccessDisabled => {
                notify_app(&app_tx, ConnectionMessage::RemoteAccessDisabled);
            }
            // ── Transaction-level protocol ───────────────────────────────────
            ControlMessage::TransactionRequest {
                transaction_id,
                display_name,
                manifest,
                total_size,
            } => {
                notify_app(
                    &app_tx,
                    ConnectionMessage::TransactionRequested {
                        transaction_id,
                        display_name,
                        manifest,
                        total_size,
                    },
                );
            }
            ControlMessage::TransactionResponse {
                transaction_id,
                accepted,
                dest_path,
                reject_reason,
            } => {
                if accepted {
                    notify_app(
                        &app_tx,
                        ConnectionMessage::TransactionAccepted {
                            transaction_id,
                            dest_path,
                        },
                    );
                } else {
                    notify_app(
                        &app_tx,
                        ConnectionMessage::TransactionRejected {
                            transaction_id,
                            reason: reject_reason,
                        },
                    );
                }
            }
            ControlMessage::TransactionComplete { transaction_id } => {
                notify_app(
                    &app_tx,
                    ConnectionMessage::TransactionCompleted { transaction_id },
                );
            }
            ControlMessage::TransactionCancel {
                transaction_id,
                reason,
            } => {
                notify_app(
                    &app_tx,
                    ConnectionMessage::TransactionCancelled {
                        transaction_id,
                        reason,
                    },
                );
            }
            ControlMessage::TransactionResumeRequest { resume_info } => {
                notify_app(
                    &app_tx,
                    ConnectionMessage::TransactionResumeRequested { resume_info },
                );
            }
            ControlMessage::TransactionResumeResponse {
                transaction_id,
                accepted,
            } => {
                if accepted {
                    notify_app(
                        &app_tx,
                        ConnectionMessage::TransactionResumeAccepted { transaction_id },
                    );
                }
            }
            ControlMessage::KeyRotation { ephemeral_pub } => {
                use crate::core::connection::crypto;

                let peer_pub: [u8; 32] = ephemeral_pub
                    .try_into()
                    .map_err(|_| anyhow!("Invalid ephemeral public key length for rotation"))?;

                if let Some(ref km) = key_manager {
                    // Check if we have a pending rotation (we initiated)
                    let our_eph = pending_rotation.write().await.take();

                    if let Some(local_eph) = our_eph {
                        // We initiated the rotation — complete it with peer's response
                        let new_key = crypto::complete_rotation(km, &local_eph, &peer_pub).await;
                        info!(event = "key_rotated_initiator", new_key_prefix = ?&new_key[..4], "Session key rotated (initiator side)");
                    } else {
                        // Peer initiated — generate our own ephemeral, respond, then rotate
                        let local_eph = crypto::prepare_rotation();
                        let response_key = *shared_key.read().await;
                        Self::send_control_on(
                            dc,
                            &response_key,
                            &ControlMessage::KeyRotation {
                                ephemeral_pub: local_eph.public.to_vec(),
                            },
                        )
                        .await?;
                        let new_key = crypto::complete_rotation(km, &local_eph, &peer_pub).await;
                        info!(event = "key_rotated_responder", new_key_prefix = ?&new_key[..4], "Session key rotated (responder side)");
                    }

                    notify_app(
                        &app_tx,
                        ConnectionMessage::Debug("Session key rotated successfully".into()),
                    );
                } else {
                    warn!(
                        event = "key_rotation_no_manager",
                        "Received KeyRotation but no SessionKeyManager is available"
                    );
                }
            }
        }
        Ok(())
    }

    // ── Finalization helper ──────────────────────────────────────────────────

    /// Finalize a fully-received file: flush, verify hash + Merkle root,
    /// send HashResult to the sender, and commit or abort.
    ///
    /// Extracted so both the Hash handler (normal path) and the chunk
    /// handler (deferred path — Hash arrived before last chunk) can share
    /// the same logic.
    async fn finalize_file_receive(
        dc: &Arc<RTCDataChannel>,
        file_id: Uuid,
        state: ReceiveFileState,
        sha3_256: Vec<u8>,
        sender_merkle_root: Option<[u8; 32]>,
        key: &[u8; 32],
        app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>,
    ) -> Result<()> {
        match state.writer.finalize().await {
            Ok(finalized) => {
                let ok = finalized.sha3_256.as_slice() == sha3_256.as_slice();

                // Verify Merkle root against sender's value if provided
                if let Some(sender_root) = sender_merkle_root {
                    if finalized.merkle_root != sender_root {
                        warn!(
                            event = "merkle_root_mismatch",
                            file_id = %file_id,
                            filename = %finalized.filename,
                            "Sender/receiver Merkle root mismatch — possible data corruption"
                        );
                    } else {
                        tracing::debug!(
                            event = "merkle_root_verified",
                            file_id = %file_id,
                            "Merkle root matches sender"
                        );
                    }
                }

                // Send hash result immediately so sender knows the
                // outcome without waiting for the atomic rename.
                Self::send_control_on(
                    dc,
                    key,
                    &ControlMessage::HashResult { file_id, ok },
                )
                .await?;

                if ok {
                    info!(
                        event = "file_recv_verified",
                        file_id = %file_id,
                        filename = %finalized.filename,
                        bytes = finalized.filesize,
                        "File received and hash verified"
                    );

                    let filename = finalized.filename.clone();
                    let filesize = finalized.filesize;
                    let merkle_root = finalized.merkle_root;
                    let app_tx_clone = app_tx.clone();

                    // Commit (atomic rename) in background so the
                    // control channel is immediately free.
                    tokio::spawn(async move {
                        match finalized.commit().await {
                            Ok(save_path) => {
                                tracing::info!(
                                    "File receive complete: {} ({} bytes)",
                                    filename,
                                    filesize
                                );
                                if let Some(tx) = &app_tx_clone {
                                    let _ = tx.send(ConnectionMessage::FileSaved {
                                        file_id,
                                        filename,
                                        path: save_path.to_string_lossy().to_string(),
                                        merkle_root,
                                    });
                                }
                            }
                            Err(e) => {
                                error!("Failed to commit file {}: {}", filename, e);
                                if let Some(tx) = &app_tx_clone {
                                    let _ = tx.send(ConnectionMessage::Error(format!(
                                        "Failed to save {}: {}",
                                        filename, e
                                    )));
                                }
                            }
                        }
                    });
                } else {
                    let failed_name = finalized.filename.clone();
                    error!(
                        event = "file_integrity_failure",
                        file_id = %file_id,
                        filename = %failed_name,
                        "File integrity check failed: hash mismatch"
                    );
                    finalized.abort().await;
                    if let Some(tx) = app_tx {
                        let _ = tx.send(ConnectionMessage::Error(format!(
                            "Hash mismatch for {}",
                            failed_name
                        )));
                    }
                }
            }
            Err(e) => {
                error!(
                    event = "file_finalize_failed",
                    file_id = %file_id,
                    error = %e,
                    "Failed to finalize received file"
                );
                if let Some(tx) = app_tx {
                    let _ = tx.send(ConnectionMessage::Error(format!(
                        "Failed to finalize file: {}",
                        e
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Sanitize a relative path by sanitizing each component individually.
fn sanitize_relative_path(name: &str) -> PathBuf {
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
