//! WebRTCConnection: multi-use data channel (messages + files)
//! - Uses compact binary framing for file chunks (no JSON overhead)
//! - JSON-serialized ChannelPayload for control messages only
//! - File transfer protocol: FileOffer -> FileResponse -> Metadata -> Chunk* -> Hash -> HashResult
//! - Chunked transfer with ACK, pipelined 8 at a time, SHA3-256 verification
//! - AES-256-GCM encryption with per-peer keys

use crate::core::persistence::{Persistence, TransferState};
use crate::core::transaction::{ResumeInfo, TransactionManifest};
use aes_gcm::{
    aead::{Aead, KeyInit}, Aes256Gcm,
    Nonce,
};
use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, Bytes};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time::timeout;
use tracing::{error, warn};
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

const CHUNK_SIZE: usize = 48 * 1024; // 48KB chunks - larger for better throughput
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
const DATA_CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);
const CHUNK_ACK_TIMEOUT: Duration = Duration::from_secs(15);
const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(15);
const PIPELINE_SIZE: usize = 16; // More pipelining for throughput
const MAX_RETRIES: usize = 3;

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
    /// File offer from sender (with total_size for accurate progress)
    FileOffer {
        file_id: Uuid,
        filename: String,
        filesize: u64,
        total_size: u64, // Total for aggregated progress tracking
    },
    /// File offer response from receiver
    FileResponse {
        file_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
    },
    /// File metadata (sent before chunks)
    Metadata {
        file_id: Uuid,
        total_chunks: u32,
        filename: String,
        filesize: u64,
    },
    /// Final hash for verification
    Hash { file_id: Uuid, sha3_256: Vec<u8> },
    /// Hash verification result
    HashResult { file_id: Uuid, ok: bool },
    /// Single file transfer completed
    FileComplete { file_id: Uuid, filename: String },
    /// Folder offer
    FolderOffer {
        folder_id: Uuid,
        dirname: String,
        file_count: u32,
        total_size: u64,
    },
    /// Folder offer response
    FolderResponse { folder_id: Uuid, accepted: bool },
    /// Folder transfer complete
    FolderComplete { folder_id: Uuid },
    /// Transfer was rejected by receiver
    TransferRejected { file_id: Uuid, reason: Option<String> },
    /// Resume request (list of successfully received file ids)
    ResumeRequest { file_id: Uuid, received_file_ids: Vec<Uuid> },
    /// Transaction-level transfer request (replaces individual FileOffer/FolderOffer for new protocol)
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
    TransactionComplete {
        transaction_id: Uuid,
    },
    /// Transaction cancellation
    TransactionCancel {
        transaction_id: Uuid,
        reason: Option<String>,
    },
    /// Resume request referencing a transaction ID
    TransactionResumeRequest {
        resume_info: ResumeInfo,
    },
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
}

// ── App-facing events ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ConnectionMessage {
    TextReceived(Vec<u8>),
    DisplayNameReceived(String),
    FileSaved {
        file_id: Uuid,
        filename: String,
        path: String,
    },
    FileOffered {
        file_id: Uuid,
        filename: String,
        filesize: u64,
        total_size: u64, // Total size for progress tracking
    },
    FileProgress {
        file_id: Uuid,
        filename: String,
        received_chunks: u32,
        total_chunks: u32,
    },
    SendProgress {
        file_id: Uuid,
        filename: String,
        sent_chunks: u32,
        total_chunks: u32,
    },
    SendComplete {
        file_id: Uuid,
        success: bool,
    },
    /// Individual file transfer completed
    FileCompleted {
        file_id: Uuid,
        filename: String,
        path: String,
    },
    FileRejected {
        file_id: Uuid,
        reason: Option<String>,
    },
    FolderOffered {
        folder_id: Uuid,
        dirname: String,
        file_count: u32,
        total_size: u64,
    },
    FolderComplete {
        folder_id: Uuid,
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
}

struct PendingOffer {
    response_tx: oneshot::Sender<(bool, Option<String>)>,
}

struct PendingFolderOffer {
    response_tx: oneshot::Sender<bool>,
}

// ── Encryption helpers ───────────────────────────────────────────────────────

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

// ── WebRTCConnection ─────────────────────────────────────────────────────────

pub struct WebRTCConnection {
    peer_connection: Arc<RTCPeerConnection>,
    control_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,
    data_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,
    app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    send_state: Arc<RwLock<HashMap<Uuid, SendFileState>>>,
    _recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
    pending_offers: Arc<RwLock<HashMap<Uuid, PendingOffer>>>,
    pending_folder_offers: Arc<RwLock<HashMap<Uuid, PendingFolderOffer>>>,
    accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
    shared_key: [u8; 32],
    _remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
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
        shared_key: [u8; 32],
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

        // Monitor for disconnection
        if let Some(tx) = &app_tx {
            let tx = tx.clone();
            pc.on_peer_connection_state_change(Box::new(move |s| {
                let tx = tx.clone();
                Box::pin(async move {
                    match s {
                        RTCPeerConnectionState::Failed
                        | RTCPeerConnectionState::Disconnected
                        | RTCPeerConnectionState::Closed => {
                            let _ = tx.send(ConnectionMessage::Disconnected);
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
        let pending_offers = Arc::new(RwLock::new(HashMap::new()));
        let pending_folder_offers = Arc::new(RwLock::new(HashMap::new()));
        let accepted_destinations = Arc::new(RwLock::new(HashMap::new()));

        let cdc = pc.create_data_channel("control", None).await?;
        let ra = Arc::new(remote_access);
        Self::attach_dc_handlers(
            &cdc,
            send_state.clone(),
            recv_state.clone(),
            pending_offers.clone(),
            pending_folder_offers.clone(),
            accepted_destinations.clone(),
            app_tx.clone(),
            shared_key,
            ra.clone(),
        )
        .await;
        *control_channel_lock.write().await = Some(cdc);

        let ddc = pc.create_data_channel("data", None).await?;
        Self::attach_dc_handlers(
            &ddc,
            send_state.clone(),
            recv_state.clone(),
            pending_offers.clone(),
            pending_folder_offers.clone(),
            accepted_destinations.clone(),
            app_tx.clone(),
            shared_key,
            ra.clone(),
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
                pending_offers,
                pending_folder_offers,
                accepted_destinations,
                shared_key,
                _remote_access: ra,
            },
            SignalingMessage::Offer(gathered_sdp),
        ))
    }

    pub async fn accept_offer(
        offer: SignalingMessage,
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
        shared_key: [u8; 32],
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

        // Monitor for disconnection
        if let Some(tx) = &app_tx {
            let tx = tx.clone();
            pc.on_peer_connection_state_change(Box::new(move |s| {
                let tx = tx.clone();
                Box::pin(async move {
                    match s {
                        RTCPeerConnectionState::Failed
                        | RTCPeerConnectionState::Disconnected
                        | RTCPeerConnectionState::Closed => {
                            let _ = tx.send(ConnectionMessage::Disconnected);
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
        let pending_offers = Arc::new(RwLock::new(HashMap::new()));
        let pending_folder_offers = Arc::new(RwLock::new(HashMap::new()));
        let accepted_destinations = Arc::new(RwLock::new(HashMap::new()));

        {
            let cl = control_channel_lock.clone();
            let dl = data_channel_lock.clone();
            let ss = send_state.clone();
            let rs = recv_state.clone();
            let po = pending_offers.clone();
            let pfo = pending_folder_offers.clone();
            let ad = accepted_destinations.clone();
            let atx = app_tx.clone();
            let ra = Arc::new(remote_access);
            let ra_outer = ra.clone();
            pc.on_data_channel(Box::new(move |dc| {
                let cl = cl.clone();
                let dl = dl.clone();
                let ss = ss.clone();
                let rs = rs.clone();
                let po = po.clone();
                let pfo = pfo.clone();
                let ad = ad.clone();
                let atx = atx.clone();
                let ra = ra.clone();
                Box::pin(async move {
                    Self::attach_dc_handlers(&dc, ss, rs, po, pfo, ad, atx, shared_key, ra).await;
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
                    pending_offers,
                    pending_folder_offers,
                    accepted_destinations,
                    shared_key,
                    _remote_access: ra_outer,
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
    async fn send_encrypted(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<()> {
        if dc.ready_state() != RTCDataChannelState::Open {
            return Err(anyhow!("Data channel not open: {:?}", dc.ready_state()));
        }
        let encrypted = encrypt(key, plaintext)?;
        dc.send(&Bytes::from(encrypted)).await?;
        Ok(())
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
        Self::send_encrypted(&dc, &self.shared_key, &frame).await
    }

    /// Send a control message on a specific data channel (static version).
    async fn send_control_on(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        msg: &ControlMessage,
    ) -> Result<()> {
        let frame = encode_control_frame(msg)?;
        Self::send_encrypted(dc, key, &frame).await
    }

    /// Send a binary chunk frame on the data channel.
    async fn send_chunk(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        file_id: Uuid,
        seq: u32,
        payload: &[u8],
    ) -> Result<()> {
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
        Self::send_encrypted(dc, key, &frame).await
    }

    // ── Public send API ──────────────────────────────────────────────────────

    /// Send a chat message (encrypted).
    pub async fn send_message(&self, bytes: Vec<u8>) -> Result<()> {
        self.send_control(&ControlMessage::Text(bytes)).await
    }

    /// Send display name to peer.
    pub async fn send_display_name(&self, name: String) -> Result<()> {
        self.send_control(&ControlMessage::DisplayName(name)).await
    }

    /// Offer a file. Returns (file_id, accepted, dest_path).
    /// total_size: for aggregated progress when multiple files are offered
    pub async fn offer_file(
        &self,
        filename: &str,
        filesize: u64,
        total_size: u64,
    ) -> Result<(Uuid, bool, Option<String>)> {
        let file_id = Uuid::new_v4();
        let (response_tx, response_rx) = oneshot::channel();

        self.pending_offers
            .write()
            .await
            .insert(file_id, PendingOffer { response_tx });

        self.wait_data_channels_open().await?;

        // Sanitize filename to prevent encoding issues
        let sanitized_filename = filename
            .chars()
            .filter(|c| !c.is_control())
            .collect::<String>();

        self.send_control(&ControlMessage::FileOffer {
            file_id,
            filename: sanitized_filename,
            filesize,
            total_size,
        })
        .await?;

        let (accepted, dest_path) = timeout(Duration::from_secs(120), response_rx)
            .await
            .context("File offer response timeout")?
            .context("File offer channel closed")?;

        Ok((file_id, accepted, dest_path))
    }

    /// Respond to a file offer.
    pub async fn send_file_response(
        &self,
        file_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
    ) -> Result<()> {
        if accepted {
            if let Some(dp) = &dest_path {
                tracing::debug!("Storing destination path for file {}: {}", file_id, dp);
                self.accepted_destinations
                    .write()
                    .await
                    .insert(file_id, PathBuf::from(dp));
            } else {
                tracing::warn!("File {} accepted but no destination path provided", file_id);
            }
        }
        tracing::debug!("Waiting for data channels to open before sending file response...");
        self.wait_data_channels_open().await?;
        tracing::debug!(
            "Data channels open, sending FileResponse for file {}",
            file_id
        );
        self.send_control(&ControlMessage::FileResponse {
            file_id,
            accepted,
            dest_path,
        })
        .await
    }

    /// Send file bytes with chunking, ACK pipelining, and hash verification.
    pub async fn send_file(
        &self,
        file_id: Uuid,
        file_bytes: Vec<u8>,
        filename: impl Into<String>,
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

        // Send metadata on control channel
        self.send_control(&ControlMessage::Metadata {
            file_id,
            total_chunks,
            filename: filename.clone(),
            filesize,
        })
        .await?;

        let send_state = SendFileState {
            pending_acks: HashMap::with_capacity(total_chunks as usize),
        };
        self.send_state.write().await.insert(file_id, send_state);

        let mut hasher = Sha3_256::new();
        let mut sent_chunks: u32 = 0;
        let key = self.shared_key;

        for chunk_batch in (0..total_chunks).collect::<Vec<_>>().chunks(PIPELINE_SIZE) {
            let mut chunks_data: Vec<(u32, Vec<u8>)> = Vec::new();

            for &seq in chunk_batch {
                let start = (seq as usize) * CHUNK_SIZE;
                let end = std::cmp::min(start + CHUNK_SIZE, file_bytes.len());
                let chunk = file_bytes[start..end].to_vec();
                hasher.update(&chunk);
                chunks_data.push((seq, chunk));
            }

            let mut remaining = chunks_data;
            let mut retries = 0;

            while !remaining.is_empty() && retries < MAX_RETRIES {
                let mut tasks: Vec<(u32, tokio::task::JoinHandle<Result<()>>)> = Vec::new();

                for (seq, chunk) in &remaining {
                    let (ack_tx, ack_rx) = oneshot::channel();
                    let seq = *seq;
                    let chunk = chunk.clone();

                    if let Some(state) = self.send_state.write().await.get_mut(&file_id) {
                        state.pending_acks.insert(seq, ack_tx);
                    }

                    let dc_c = dc.clone();
                    tasks.push((
                        seq,
                        tokio::spawn(async move {
                            Self::send_chunk(&dc_c, &key, file_id, seq, &chunk).await?;
                            timeout(CHUNK_ACK_TIMEOUT, ack_rx)
                                .await
                                .map_err(|_| anyhow!("ACK timeout for chunk {}", seq))?
                                .map_err(|_| anyhow!("ACK channel closed for chunk {}", seq))?;
                            Ok(())
                        }),
                    ));
                }

                let mut failed: Vec<u32> = Vec::new();
                for (seq, task) in tasks {
                    match task.await {
                        Ok(Ok(())) => {}
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
                return Err(anyhow!(
                    "Failed to send chunks after {} retries",
                    MAX_RETRIES
                ));
            }

            sent_chunks += chunk_batch.len() as u32;
            if let Some(tx) = &self.app_tx {
                let _ = tx.send(ConnectionMessage::SendProgress {
                    file_id,
                    filename: filename.clone(),
                    sent_chunks,
                    total_chunks,
                });
            }
        }

        // Send final hash on control channel
        let final_hash = hasher.finalize();
        self.send_control(&ControlMessage::Hash {
            file_id,
            sha3_256: final_hash.to_vec(),
        })
        .await?;

        self.send_state.write().await.remove(&file_id);
        Ok(())
    }

    /// Offer + send if accepted.
    pub async fn send_file_with_offer(
        &self,
        file_bytes: Vec<u8>,
        filename: impl Into<String>,
    ) -> Result<bool> {
        let filename = filename.into();
        let filesize = file_bytes.len() as u64;
        let (file_id, accepted, _) = self.offer_file(&filename, filesize, filesize).await?;
        if !accepted {
            return Ok(false);
        }
        self.send_file(file_id, file_bytes, filename).await?;
        Ok(true)
    }

    // ── Folder API ───────────────────────────────────────────────────────────

    pub async fn offer_folder(
        &self,
        dirname: &str,
        file_count: u32,
        total_size: u64,
    ) -> Result<(Uuid, bool)> {
        let folder_id = Uuid::new_v4();
        let (response_tx, response_rx) = oneshot::channel();
        self.pending_folder_offers
            .write()
            .await
            .insert(folder_id, PendingFolderOffer { response_tx });
        self.wait_data_channels_open().await?;
        self.send_control(&ControlMessage::FolderOffer {
            folder_id,
            dirname: dirname.to_string(),
            file_count,
            total_size,
        })
        .await?;
        let accepted = timeout(Duration::from_secs(120), response_rx)
            .await
            .context("Folder offer response timeout")?
            .context("Folder offer channel closed")?;
        Ok((folder_id, accepted))
    }

    pub async fn send_folder_response(&self, folder_id: Uuid, accepted: bool) -> Result<()> {
        self.wait_data_channels_open().await?;
        self.send_control(&ControlMessage::FolderResponse {
            folder_id,
            accepted,
        })
        .await
    }

    pub async fn send_folder_files(
        &self,
        folder_id: Uuid,
        files: Vec<(String, Vec<u8>)>,
    ) -> Result<()> {
        for (relative_path, file_bytes) in files {
            let file_id = Uuid::new_v4();
            self.send_file(file_id, file_bytes, relative_path).await?;
        }
        self.send_control(&ControlMessage::FolderComplete { folder_id })
            .await
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

    // ── Data channel message handler ─────────────────────────────────────────

    async fn attach_dc_handlers(
        dc: &Arc<RTCDataChannel>,
        send_state: Arc<RwLock<HashMap<Uuid, SendFileState>>>,
        recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
        pending_offers: Arc<RwLock<HashMap<Uuid, PendingOffer>>>,
        pending_folder_offers: Arc<RwLock<HashMap<Uuid, PendingFolderOffer>>>,
        accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
        shared_key: [u8; 32],
        remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
    ) {
        let dc_clone = dc.clone();
        let ss = send_state;
        let rs = recv_state;
        let po = pending_offers;
        let pfo = pending_folder_offers;
        let ad = accepted_destinations;
        let atx = app_tx;
        let ra = remote_access;

        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let ss = ss.clone();
            let rs = rs.clone();
            let po = po.clone();
            let pfo = pfo.clone();
            let ad = ad.clone();
            let atx = atx.clone();
            let dc = dc_clone.clone();
            let ra = ra.clone();

            Box::pin(async move {
                // Decrypt
                let plaintext = match decrypt(&shared_key, &msg.data) {
                    Ok(p) => p,
                    Err(e) => {
                        if let Some(tx) = &atx {
                            let _ =
                                tx.send(ConnectionMessage::Error(format!("Decrypt error: {}", e)));
                        }
                        return;
                    }
                };

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
                                po,
                                pfo,
                                ad,
                                atx.clone(),
                                shared_key,
                                ra.clone(),
                            )
                            .await
                            {
                                if let Some(tx) = &atx {
                                    let _ = tx.send(ConnectionMessage::Error(format!(
                                        "Control error: {}",
                                        e
                                    )));
                                }
                            }
                        }
                        Err(e) => {
                            if let Some(tx) = &atx {
                                let _ = tx.send(ConnectionMessage::Error(format!(
                                    "Control decode error: {}",
                                    e
                                )));
                            }
                        }
                    },
                    FRAME_CHUNK => {
                        // Binary: 16 bytes uuid + 4 bytes seq + payload
                        if payload.len() < 20 {
                            if let Some(tx) = &atx {
                                let _ = tx
                                    .send(ConnectionMessage::Error("Chunk frame too short".into()));
                            }
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

                                if state.received_chunks % 10 == 0 {
                                    if let Ok(mut p) = Persistence::load() {
                                        p.transfers.insert(
                                            file_id,
                                            TransferState {
                                                file_id,
                                                filename: state.filename.clone(),
                                                total_chunks: state.total_chunks,
                                                received_chunks: state.received_chunks,
                                                dest_path: state.dest_path.clone(),
                                            },
                                        );
                                        let _ = p.save();
                                    }
                                }

                                if let Some(tx) = &atx {
                                    let _ = tx.send(ConnectionMessage::FileProgress {
                                        file_id,
                                        filename: state.filename.clone(),
                                        received_chunks: state.received_chunks,
                                        total_chunks: state.total_chunks,
                                    });
                                }
                            } else {
                                error!("Chunk {} for {} out of bounds", seq, file_id);
                            }
                        }
                        drop(map);

                        // Send ACK
                        if let Err(e) = Self::send_ack(&dc, &shared_key, file_id, seq).await {
                            warn!("Failed to send ACK for chunk {}: {}", seq, e);
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
                        if let Some(tx) = &atx {
                            let _ = tx.send(ConnectionMessage::Debug(format!(
                                "Unknown frame type: 0x{:02x}",
                                frame_type
                            )));
                        }
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
        pending_offers: Arc<RwLock<HashMap<Uuid, PendingOffer>>>,
        pending_folder_offers: Arc<RwLock<HashMap<Uuid, PendingFolderOffer>>>,
        accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
        shared_key: [u8; 32],
        remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
    ) -> Result<()> {
        match msg {
            ControlMessage::Text(data) => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::TextReceived(data));
                }
            }
            ControlMessage::DisplayName(name) => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::DisplayNameReceived(name));
                }
            }
            ControlMessage::FileOffer {
                file_id,
                filename,
                filesize,
                total_size,
            } => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::FileOffered {
                        file_id,
                        filename,
                        filesize,
                        total_size,
                    });
                }
            }
            ControlMessage::FileResponse {
                file_id,
                accepted,
                dest_path,
            } => {
                if let Some(offer) = pending_offers.write().await.remove(&file_id) {
                    let _ = offer.response_tx.send((accepted, dest_path));
                }
            }
            ControlMessage::Metadata {
                file_id,
                total_chunks,
                filename,
                filesize,
            } => {
                if filesize == 0 {
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

                if let Ok(mut p) = Persistence::load() {
                    p.transfers.insert(
                        file_id,
                        TransferState {
                            file_id,
                            filename: filename.clone(),
                            total_chunks,
                            received_chunks: 0,
                            dest_path: dest_path.clone(),
                        },
                    );
                    let _ = p.save();
                }

                let buffer = vec![0u8; filesize as usize];
                let st = ReceiveFileState {
                    filename: filename.clone(),
                    total_chunks,
                    received_chunks: 0,
                    buffer,
                    dest_path,
                };
                recv_state.write().await.insert(file_id, st);

                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::Debug(format!(
                        "Receiving: {} ({} bytes, {} chunks)",
                        filename, filesize, total_chunks
                    )));
                }
            }
            ControlMessage::Hash { file_id, sha3_256 } => {
                let mut map = recv_state.write().await;
                if let Some(state) = map.remove(&file_id) {
                    let mut hasher = Sha3_256::new();
                    hasher.update(&state.buffer);
                    let local_hash = hasher.finalize();
                    let ok = local_hash.as_slice() == sha3_256.as_slice();

                    if ok {
                        if let Ok(mut p) = Persistence::load() {
                            p.transfers.remove(&file_id);
                            let _ = p.save();
                        }
                        let save_path = if let Some(dest) = &state.dest_path {
                            dest.clone()
                        } else {
                            let safe = sanitize_relative_path(&state.filename);
                            std::env::current_dir().unwrap_or_default().join(&safe)
                        };
                        if let Some(parent) = save_path.parent() {
                            if !parent.exists() {
                                fs::create_dir_all(parent).await?;
                            }
                        }
                        let temp_path = save_path.with_extension(".tmp");
                        fs::write(&temp_path, &state.buffer).await?;
                        tokio::fs::rename(&temp_path, &save_path).await?;
                        tracing::info!(
                            "File receive complete: {} ({} bytes)",
                            state.filename,
                            state.buffer.len()
                        );
                        if let Some(tx) = &app_tx {
                            let _ = tx.send(ConnectionMessage::FileSaved {
                                file_id,
                                filename: state.filename,
                                path: save_path.to_string_lossy().to_string(),
                            });
                        }
                    } else if let Some(tx) = &app_tx {
                        let _ = tx.send(ConnectionMessage::Error(format!(
                            "Hash mismatch for {}",
                            state.filename
                        )));
                    }

                    // Send hash result back on control channel
                    Self::send_control_on(
                        dc,
                        &shared_key,
                        &ControlMessage::HashResult { file_id, ok },
                    )
                    .await?;
                }
            }
            ControlMessage::HashResult { file_id, ok } => {
                if ok {
                    tracing::info!("File send complete: {} (verified)", file_id);
                } else {
                    tracing::warn!("File send failed: {} (hash mismatch)", file_id);
                }
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::SendComplete {
                        file_id,
                        success: ok,
                    });
                }
            }
            ControlMessage::FolderOffer {
                folder_id,
                dirname,
                file_count,
                total_size,
            } => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::FolderOffered {
                        folder_id,
                        dirname,
                        file_count,
                        total_size,
                    });
                }
            }
            ControlMessage::FolderResponse {
                folder_id,
                accepted,
            } => {
                if let Some(offer) = pending_folder_offers.write().await.remove(&folder_id) {
                    let _ = offer.response_tx.send(accepted);
                }
            }
            ControlMessage::FolderComplete { folder_id } => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::FolderComplete { folder_id });
                }
            }
            ControlMessage::ResumeRequest { file_id, received_file_ids } => {
                if let Some(tx) = &app_tx {
                    // Send resume request info to app
                    let _ = tx.send(ConnectionMessage::Debug(format!(
                        "Resume requested for file {}, {} files already received",
                        file_id,
                        received_file_ids.len()
                    )));
                }
            }
            ControlMessage::LsRequest { path } => {
                tracing::info!("Remote ls request: {}", path);
                if !*remote_access.borrow() {
                    Self::send_control_on(dc, &shared_key, &ControlMessage::RemoteAccessDisabled)
                        .await?;
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
                    Self::send_control_on(
                        dc,
                        &shared_key,
                        &ControlMessage::LsResponse { path, entries },
                    )
                    .await?;
                }
            }
            ControlMessage::LsResponse { path, entries } => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::LsResponse { path, entries });
                }
            }
            ControlMessage::FetchRequest { path, is_folder } => {
                tracing::info!("Remote fetch request: {} (folder: {})", path, is_folder);
                if !*remote_access.borrow() {
                    Self::send_control_on(dc, &shared_key, &ControlMessage::RemoteAccessDisabled)
                        .await?;
                } else {
                    if let Some(tx) = &app_tx {
                        let _ = tx.send(ConnectionMessage::RemoteFetchRequest { path, is_folder });
                    }
                }
            }
            ControlMessage::RemoteAccessDisabled => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::RemoteAccessDisabled);
                }
            }
            ControlMessage::FileComplete { file_id, filename } => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::FileCompleted {
                        file_id,
                        filename,
                        path: String::new(), // Path is set by receiver
                    });
                }
            }
            ControlMessage::TransferRejected { file_id, reason } => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::FileRejected {
                        file_id,
                        reason,
                    });
                }
                // Clean up pending offer
                pending_offers.write().await.remove(&file_id);
            }
            // ── Transaction-level protocol ───────────────────────────────────
            ControlMessage::TransactionRequest {
                transaction_id,
                display_name,
                manifest,
                total_size,
            } => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::TransactionRequested {
                        transaction_id,
                        display_name,
                        manifest,
                        total_size,
                    });
                }
            }
            ControlMessage::TransactionResponse {
                transaction_id,
                accepted,
                dest_path,
                reject_reason,
            } => {
                if let Some(tx) = &app_tx {
                    if accepted {
                        let _ = tx.send(ConnectionMessage::TransactionAccepted {
                            transaction_id,
                            dest_path,
                        });
                    } else {
                        let _ = tx.send(ConnectionMessage::TransactionRejected {
                            transaction_id,
                            reason: reject_reason,
                        });
                    }
                }
            }
            ControlMessage::TransactionComplete { transaction_id } => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::TransactionCompleted {
                        transaction_id,
                    });
                }
            }
            ControlMessage::TransactionCancel { transaction_id, reason } => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::TransactionCancelled {
                        transaction_id,
                        reason,
                    });
                }
            }
            ControlMessage::TransactionResumeRequest { resume_info } => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::TransactionResumeRequested {
                        resume_info,
                    });
                }
            }
            ControlMessage::TransactionResumeResponse { transaction_id, accepted } => {
                if accepted {
                    if let Some(tx) = &app_tx {
                        let _ = tx.send(ConnectionMessage::TransactionResumeAccepted {
                            transaction_id,
                        });
                    }
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
