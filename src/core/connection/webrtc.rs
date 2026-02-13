//! WebRTCConnection: multi-use data channel (messages + files)
//! - Uses compact binary framing for file chunks (no JSON overhead)
//! - JSON-serialized ChannelPayload for control messages only
//! - File transfer protocol: FileOffer -> FileResponse -> Metadata -> Chunk* -> Hash -> HashResult
//! - Chunked transfer with ACK, pipelined 8 at a time, SHA3-256 verification
//! - AES-256-GCM encryption with per-peer keys
//! - Brotli compression before encryption (File → Compress → Encrypt → Send)

use crate::core::connection::crypto::SessionKeyManager;
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
use sha3::{Digest, Sha3_256};
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
use webrtc::api::APIBuilder;
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

use crate::core::config::{
    CHUNK_ACK_TIMEOUT, CHUNK_SIZE, CONNECTION_TIMEOUT, DATA_CHANNEL_TIMEOUT, ICE_GATHER_TIMEOUT,
    MAX_SEND_RETRIES as MAX_RETRIES, PIPELINE_SIZE,
};

// ── Binary Frame Format ──────────────────────────────────────────────────────
//
// All messages on the data channel use this compact binary envelope:
//
//   [1 byte: frame_type] [N bytes: payload]
//
// Frame types:
//   0x01 = Control (JSON-encoded ControlMessage)
//   0x02 = Chunk   (binary: 16 bytes file_id + 4 bytes seq + raw data)
//   0x03 = Ack     (binary: 16 bytes file_id + 4 bytes seq)
//
// This eliminates JSON+base64 overhead for bulk data transfer.
// A 48KB chunk costs exactly 48KB + 21 bytes overhead instead of ~130KB with JSON+base64.

const FRAME_CONTROL: u8 = 0x01;
const FRAME_CHUNK: u8 = 0x02;
const FRAME_ACK: u8 = 0x03;

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

struct SendFileState {
    pending_acks: HashMap<u32, oneshot::Sender<()>>,
}

struct ReceiveFileState {
    filename: String,
    total_chunks: u32,
    received_chunks: u32,
    buffer: Vec<u8>,
    dest_path: Option<PathBuf>,
    /// Per-chunk SHA3-256 hashes collected incrementally for Merkle tree.
    chunk_hashes: Vec<Option<[u8; 32]>>,
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

/// Encrypt data with AES-256-GCM. Returns nonce (12 bytes) || ciphertext.
fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
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

/// Decrypt data: expects nonce (12 bytes) || ciphertext.
fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(anyhow!("Ciphertext too short"));
    }
    let cipher = Aes256Gcm::new_from_slice(key)?;
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(&data[..12]);
    cipher
        .decrypt(nonce, &data[12..])
        .map_err(|e| anyhow!("Decryption failed: {}", e))
}

// ── Binary frame encode/decode ───────────────────────────────────────────────

/// Encode a binary chunk frame: [0x02][16 bytes uuid][4 bytes seq BE][payload]
fn encode_chunk_frame(file_id: Uuid, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 16 + 4 + payload.len());
    buf.put_u8(FRAME_CHUNK);
    buf.extend_from_slice(file_id.as_bytes());
    buf.put_u32(seq);
    buf.extend_from_slice(payload);
    buf
}

/// Encode a binary ack frame: [0x03][16 bytes uuid][4 bytes seq BE]
fn encode_ack_frame(file_id: Uuid, seq: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 16 + 4);
    buf.put_u8(FRAME_ACK);
    buf.extend_from_slice(file_id.as_bytes());
    buf.put_u32(seq);
    buf
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
    send_state: Arc<RwLock<HashMap<Uuid, SendFileState>>>,
    _recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
    _pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>)>>>>,
    accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
    shared_key: Arc<RwLock<[u8; 32]>>,
    key_manager: Option<SessionKeyManager>,
    /// Pending local ephemeral keypair for an in-progress key rotation.
    pending_rotation: Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,
    _remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
    /// Outgoing chat message counter (monotonically increasing, shared by room + DM).
    chat_send_counter: Arc<RwLock<u64>>,
    /// Last seen incoming chat counter (replay protection).
    chat_recv_counter: Arc<RwLock<u64>>,
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
        Ok(APIBuilder::new()
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
        let send_state = Arc::new(RwLock::new(HashMap::new()));
        let recv_state = Arc::new(RwLock::new(HashMap::new()));
        let pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>)>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let accepted_destinations = Arc::new(RwLock::new(HashMap::new()));

        let pending_rotation: Arc<
            RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>,
        > = Arc::new(RwLock::new(None));

        let chat_send_counter = Arc::new(RwLock::new(0u64));
        let chat_recv_counter = Arc::new(RwLock::new(0u64));

        let cdc = pc.create_data_channel("control", None).await?;
        let ra = Arc::new(remote_access);
        Self::attach_dc_handlers(
            &cdc,
            send_state.clone(),
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

        let ddc = pc.create_data_channel("data", None).await?;
        Self::attach_dc_handlers(
            &ddc,
            send_state.clone(),
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
                send_state,
                _recv_state: recv_state,
                _pending_chunks: pending_chunks,
                accepted_destinations,
                shared_key,
                key_manager,
                pending_rotation,
                _remote_access: ra,
                chat_send_counter,
                chat_recv_counter,
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
        let send_state = Arc::new(RwLock::new(HashMap::new()));
        let recv_state = Arc::new(RwLock::new(HashMap::new()));
        let pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>)>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let accepted_destinations = Arc::new(RwLock::new(HashMap::new()));

        {
            let cl = control_channel_lock.clone();
            let dl = data_channel_lock.clone();
            let ss = send_state.clone();
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
                let ss = ss.clone();
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
                    Self::attach_dc_handlers(&dc, ss, rs, pc_chunks, ad, atx, sk, ra, km, pr, crc)
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
                    send_state,
                    _recv_state: recv_state,
                    _pending_chunks: pending_chunks,
                    accepted_destinations,
                    shared_key,
                    key_manager,
                    pending_rotation: pending_rotation_outer,
                    _remote_access: ra_outer,
                    chat_send_counter,
                    chat_recv_counter,
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
    /// Pipeline: plaintext → compress → encrypt → send
    async fn send_encrypted(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<usize> {
        if dc.ready_state() != RTCDataChannelState::Open {
            warn!(event = "send_channel_not_open", state = ?dc.ready_state(), "Attempted send on non-open data channel");
            return Err(anyhow!("Data channel not open: {:?}", dc.ready_state()));
        }
        let compressed = compress_data(plaintext).map_err(|e| {
            error!(event = "compress_failure", bytes = plaintext.len(), error = %e, "Compression failed before send");
            e
        })?;
        let encrypted = encrypt(key, &compressed).map_err(|e| {
            error!(event = "encrypt_failure", bytes = compressed.len(), error = %e, "Encryption failed before send");
            e
        })?;
        let wire_bytes = encrypted.len();
        dc.send(&Bytes::from(encrypted)).await?;
        Ok(wire_bytes)
    }

    /// Send a control message on the control channel.
    pub async fn send_control(&self, msg: &ControlMessage) -> Result<()> {
        let dc = self
            .control_channel
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Control channel not available"))?;
        let frame = encode_control_frame(msg)?;
        let key = *self.shared_key.read().await;
        Self::send_encrypted(&dc, &key, &frame).await?;
        Ok(())
    }

    /// Send a control message on a specific data channel (static version).
    async fn send_control_on(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        msg: &ControlMessage,
    ) -> Result<()> {
        let frame = encode_control_frame(msg)?;
        Self::send_encrypted(dc, key, &frame).await?;
        Ok(())
    }

    /// Send a binary chunk frame on the data channel.
    /// Returns the number of bytes sent on the wire (post-compression, post-encryption).
    async fn send_chunk(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        file_id: Uuid,
        seq: u32,
        payload: &[u8],
    ) -> Result<usize> {
        let frame = encode_chunk_frame(file_id, seq, payload);
        Self::send_encrypted(dc, key, &frame).await
    }

    /// Send a binary ack frame on the data channel.
    async fn send_ack(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        file_id: Uuid,
        seq: u32,
    ) -> Result<()> {
        let frame = encode_ack_frame(file_id, seq);
        Self::send_encrypted(dc, key, &frame).await?;
        Ok(())
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

    /// Send file bytes with chunking, ACK pipelining, and hash verification.
    pub async fn send_file(
        &self,
        file_id: Uuid,
        file_bytes: Vec<u8>,
        filename: impl Into<String>,
    ) -> Result<()> {
        self.send_file_resuming(file_id, file_bytes, filename, 0)
            .await
    }

    /// Send file bytes, skipping the first `start_chunk` chunks (for resume).
    /// Chunks 0..start_chunk are still hashed but NOT transmitted.
    pub async fn send_file_resuming(
        &self,
        file_id: Uuid,
        file_bytes: Vec<u8>,
        filename: impl Into<String>,
        start_chunk: u32,
    ) -> Result<()> {
        let filename = filename.into();
        self.wait_data_channels_open().await?;

        let dc = self
            .data_channel
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Data channel not available"))?;

        let filesize = file_bytes.len() as u64;
        let total_chunks = ((filesize as f64) / (CHUNK_SIZE as f64)).ceil().max(1.0) as u32;

        // Send metadata on control channel first — receiver needs this
        // to create ReceiveFileState before chunks arrive.
        self.send_control(&ControlMessage::Metadata {
            file_id,
            total_chunks,
            filename: filename.clone(),
            filesize,
        })
        .await?;

        // Short sleep to give the Metadata frame a head-start on the control channel.
        // The receiver also buffers early-arriving chunks, so this is best-effort.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let send_state = SendFileState {
            pending_acks: HashMap::with_capacity(total_chunks as usize),
        };
        self.send_state.write().await.insert(file_id, send_state);

        let mut hasher = Sha3_256::new();
        let mut chunk_hashes: Vec<[u8; 32]> = Vec::with_capacity(total_chunks as usize);
        info!(event = "file_send_start", file_id = %file_id, filename = %filename, filesize, total_chunks, start_chunk, "Starting file send");

        let mut sent_chunks: u32 = start_chunk;
        let mut _total_wire_bytes: u64 = 0;
        let key_lock = self.shared_key.clone();

        for chunk_batch in (0..total_chunks).collect::<Vec<_>>().chunks(PIPELINE_SIZE) {
            let mut chunks_data: Vec<(u32, Vec<u8>)> = Vec::new();

            for &seq in chunk_batch {
                let start = (seq as usize) * CHUNK_SIZE;
                let end = std::cmp::min(start + CHUNK_SIZE, file_bytes.len());
                let chunk = file_bytes[start..end].to_vec();
                hasher.update(&chunk);

                // Compute per-chunk SHA3-256 hash for Merkle tree
                {
                    let mut ch = Sha3_256::new();
                    ch.update(&chunk);
                    let result = ch.finalize();
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&result);
                    chunk_hashes.push(hash);
                }

                // Skip already-received chunks (for resume)
                if seq >= start_chunk {
                    chunks_data.push((seq, chunk));
                }
            }

            let mut remaining = chunks_data;
            let mut retries = 0;
            let mut batch_wire_bytes: u64 = 0;

            while !remaining.is_empty() && retries < MAX_RETRIES {
                let mut tasks: Vec<(u32, tokio::task::JoinHandle<Result<usize>>)> = Vec::new();

                for (seq, chunk) in &remaining {
                    let (ack_tx, ack_rx) = oneshot::channel();
                    let seq = *seq;
                    let chunk = chunk.clone();

                    if let Some(state) = self.send_state.write().await.get_mut(&file_id) {
                        state.pending_acks.insert(seq, ack_tx);
                    }

                    let dc_c = dc.clone();
                    let kl = key_lock.clone();
                    tasks.push((
                        seq,
                        tokio::spawn(async move {
                            let key = *kl.read().await;
                            let wb = Self::send_chunk(&dc_c, &key, file_id, seq, &chunk).await?;
                            timeout(CHUNK_ACK_TIMEOUT, ack_rx)
                                .await
                                .map_err(|_| anyhow!("ACK timeout for chunk {}", seq))?
                                .map_err(|_| anyhow!("ACK channel closed for chunk {}", seq))?;
                            Ok(wb)
                        }),
                    ));
                }

                let mut failed: Vec<u32> = Vec::new();
                for (seq, task) in tasks {
                    match task.await {
                        Ok(Ok(wb)) => {
                            batch_wire_bytes += wb as u64;
                        }
                        Ok(Err(e)) => {
                            warn!(
                                "Chunk {} failed: {}, retry {}/{}",
                                seq,
                                e,
                                retries + 1,
                                MAX_RETRIES
                            );
                            failed.push(seq);
                        }
                        Err(e) => {
                            warn!(
                                "Chunk {} panic: {}, retry {}/{}",
                                seq,
                                e,
                                retries + 1,
                                MAX_RETRIES
                            );
                            failed.push(seq);
                        }
                    }
                }

                remaining.retain(|(s, _)| failed.contains(s));
                if !failed.is_empty() {
                    retries += 1;
                }
            }

            if !remaining.is_empty() {
                error!(event = "chunk_send_exhausted", file_id = %file_id, retries = MAX_RETRIES, failed_chunks = remaining.len(), "Chunk send failed after max retries");
                return Err(anyhow!(
                    "Failed to send chunks after {} retries",
                    MAX_RETRIES
                ));
            }

            _total_wire_bytes += batch_wire_bytes;
            // Only count chunks that were actually sent (not skipped)
            let sent_in_batch = chunk_batch.iter().filter(|&&s| s >= start_chunk).count() as u32;
            sent_chunks += sent_in_batch;
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

        // Send final hash + Merkle root on control channel
        let final_hash = hasher.finalize();
        let merkle_tree = crate::core::pipeline::merkle::MerkleTree::build(&chunk_hashes);
        self.send_control(&ControlMessage::Hash {
            file_id,
            sha3_256: final_hash.to_vec(),
            merkle_root: Some(*merkle_tree.root()),
        })
        .await?;

        self.send_state.write().await.remove(&file_id);
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
        send_state: Arc<RwLock<HashMap<Uuid, SendFileState>>>,
        recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
        pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>)>>>>,
        accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
        shared_key: Arc<RwLock<[u8; 32]>>,
        remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
        key_manager: Option<SessionKeyManager>,
        pending_rotation: Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,
        chat_recv_counter: Arc<RwLock<u64>>,
    ) {
        let dc_clone = dc.clone();
        let ss = send_state;
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
            let ss = ss.clone();
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

                // Decompress (Receive → Decrypt → Decompress → Process)
                let plaintext = match decompress_data(&decrypted) {
                    Ok(p) => p,
                    Err(e) => {
                        error!(event = "decompress_failure", bytes = decrypted.len(), error = %e, "Decompression failed on incoming frame");
                        notify_app(&atx, ConnectionMessage::Error(format!("Decompress error: {}", e)));
                        return;
                    }
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
                                ss,
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
                            let start = (seq as usize) * CHUNK_SIZE;
                            let end = start + chunk_data.len();
                            if end <= state.buffer.len() {
                                state.buffer[start..end].copy_from_slice(chunk_data);
                                state.received_chunks += 1;

                                // Hash raw chunk for incremental Merkle tree
                                if (seq as usize) < state.chunk_hashes.len() {
                                    let mut ch = Sha3_256::new();
                                    ch.update(chunk_data);
                                    let r = ch.finalize();
                                    let mut h = [0u8; 32];
                                    h.copy_from_slice(&r);
                                    state.chunk_hashes[seq as usize] = Some(h);
                                }

                                if let Some(tx) = &atx {
                                    let _ = tx.send(ConnectionMessage::FileProgress {
                                        file_id,
                                        filename: state.filename.clone(),
                                        received_chunks: state.received_chunks,
                                        total_chunks: state.total_chunks,
                                        wire_bytes,
                                    });
                                }
                            } else {
                                error!("Chunk {} for {} out of bounds", seq, file_id);
                            }

                            // Only ACK if we actually tracked this chunk
                            drop(map);
                            let ack_key = *sk.read().await;
                            if let Err(e) = Self::send_ack(&dc, &ack_key, file_id, seq).await {
                                warn!("Failed to send ACK for chunk {}: {}", seq, e);
                            }
                        } else {
                            // Chunk arrived before Metadata — buffer it and ACK later
                            drop(map);
                            tracing::debug!("Chunk {} for file {} buffered — Metadata not yet received", seq, file_id);
                            let mut pending = pc.write().await;
                            pending.entry(file_id).or_default().push((seq, chunk_data.to_vec()));
                        }
                    }
                    FRAME_ACK => {
                        if payload.len() < 20 {
                            return;
                        }
                        let file_id = Uuid::from_bytes(payload[..16].try_into().unwrap());
                        let seq = u32::from_be_bytes(payload[16..20].try_into().unwrap());

                        let mut map = ss.write().await;
                        if let Some(st) = map.get_mut(&file_id) {
                            if let Some(tx) = st.pending_acks.remove(&seq) {
                                let _ = tx.send(());
                            }
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
        _send_state: Arc<RwLock<HashMap<Uuid, SendFileState>>>,
        recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
        pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>)>>>>,
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
                let dest_path = accepted_destinations.write().await.remove(&file_id);
                tracing::debug!(
                    "Metadata received for file {} ({}): dest_path found = {}",
                    file_id,
                    filename,
                    dest_path.is_some()
                );
                let dest_path = dest_path.map(|dir| {
                    let safe = sanitize_relative_path(&filename);
                    dir.join(&safe)
                });
                tracing::info!(
                    "Receiving file '{}' ({} bytes, {} chunks) to: {}",
                    filename,
                    filesize,
                    total_chunks,
                    dest_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "current dir".to_string())
                );

                let buffer = vec![0u8; filesize as usize];
                let st = ReceiveFileState {
                    filename: filename.clone(),
                    total_chunks,
                    received_chunks: 0,
                    buffer,
                    dest_path,
                    chunk_hashes: vec![None; total_chunks as usize],
                };
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
                        for (seq, chunk_data) in &buffered {
                            let start = (*seq as usize) * CHUNK_SIZE;
                            let end = start + chunk_data.len();
                            if end <= state.buffer.len() {
                                state.buffer[start..end].copy_from_slice(chunk_data);
                                state.received_chunks += 1;

                                // Hash raw chunk for incremental Merkle tree
                                if (*seq as usize) < state.chunk_hashes.len() {
                                    let mut ch = Sha3_256::new();
                                    ch.update(chunk_data);
                                    let r = ch.finalize();
                                    let mut h = [0u8; 32];
                                    h.copy_from_slice(&r);
                                    state.chunk_hashes[*seq as usize] = Some(h);
                                }

                                if let Some(tx) = &app_tx {
                                    let _ = tx.send(ConnectionMessage::FileProgress {
                                        file_id,
                                        filename: state.filename.clone(),
                                        received_chunks: state.received_chunks,
                                        total_chunks: state.total_chunks,
                                        wire_bytes: 0, // buffered chunks: wire bytes already counted
                                    });
                                }
                            } else {
                                error!("Buffered chunk {} for {} out of bounds", seq, file_id);
                            }
                        }
                    }
                    drop(map);
                    // Now send ACKs for all buffered chunks
                    for (seq, _) in &buffered {
                        if let Err(e) = Self::send_ack(dc, &key, file_id, *seq).await {
                            warn!("Failed to send ACK for buffered chunk {}: {}", seq, e);
                        }
                    }
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
                if let Some(state) = map.remove(&file_id) {
                    let mut hasher = Sha3_256::new();
                    hasher.update(&state.buffer);
                    let local_hash = hasher.finalize();
                    let ok = local_hash.as_slice() == sha3_256.as_slice();

                    // Build Merkle root from incrementally collected chunk hashes
                    let merkle_root = {
                        let all_present = state.chunk_hashes.iter().all(|h| h.is_some());
                        if all_present && !state.chunk_hashes.is_empty() {
                            let leaves: Vec<[u8; 32]> =
                                state.chunk_hashes.iter().map(|h| h.unwrap()).collect();
                            *crate::core::pipeline::merkle::MerkleTree::build(&leaves).root()
                        } else {
                            [0u8; 32]
                        }
                    };

                    // Verify Merkle root against sender's value if provided
                    if let Some(sender_root) = sender_merkle_root {
                        if merkle_root != sender_root {
                            warn!(
                                event = "merkle_root_mismatch",
                                file_id = %file_id,
                                filename = %state.filename,
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

                    // Send hash result immediately (before file write) so sender
                    // knows the verification outcome without waiting for disk I/O.
                    Self::send_control_on(dc, &key, &ControlMessage::HashResult { file_id, ok })
                        .await?;

                    if ok {
                        info!(event = "file_recv_verified", file_id = %file_id, filename = %state.filename, bytes = state.buffer.len(), "File received and hash verified");
                        let save_path = if let Some(dest) = &state.dest_path {
                            dest.clone()
                        } else {
                            let safe = sanitize_relative_path(&state.filename);
                            std::env::current_dir().unwrap_or_default().join(&safe)
                        };

                        // Spawn file write in background so the control channel
                        // is immediately free to process the next file's Metadata.
                        let app_tx_clone = app_tx.clone();
                        let filename = state.filename.clone();
                        let buffer = state.buffer;
                        tokio::spawn(async move {
                            if let Some(parent) = save_path.parent() {
                                if !parent.exists() {
                                    let _ = fs::create_dir_all(parent).await;
                                }
                            }
                            let temp_path = save_path.with_extension(".tmp");
                            match fs::write(&temp_path, &buffer).await {
                                Ok(()) => match tokio::fs::rename(&temp_path, &save_path).await {
                                    Ok(()) => {
                                        tracing::info!(
                                            "File receive complete: {} ({} bytes)",
                                            filename,
                                            buffer.len()
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
                                        error!(
                                            "Failed to rename temp file for {}: {}",
                                            filename, e
                                        );
                                        let _ = std::fs::remove_file(&temp_path);
                                        if let Some(tx) = &app_tx_clone {
                                            let _ = tx.send(ConnectionMessage::Error(format!(
                                                "Failed to save {}: {}",
                                                filename, e
                                            )));
                                        }
                                    }
                                },
                                Err(e) => {
                                    error!("Failed to write temp file for {}: {}", filename, e);
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
                        error!(event = "file_integrity_failure", file_id = %file_id, filename = %state.filename, "File integrity check failed: hash mismatch");
                        if let Some(tx) = &app_tx {
                            let _ = tx.send(ConnectionMessage::Error(format!(
                                "Hash mismatch for {}",
                                state.filename
                            )));
                        }
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
