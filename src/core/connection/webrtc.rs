//! WebRTCConnection: multi-use data channel (messages + files)
//! - Uses JSON-serialized ChannelPayload envelopes on a single "multi" data channel
//! - File transfer protocol: FileOffer -> FileResponse -> Metadata -> Chunk* -> Hash -> HashResult
//! - Chunked transfer with ACK, pipelined 4 at a time, SHA3-256 verification

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time::timeout;
use uuid::Uuid;

/// Serde helper: serialize Vec<u8> as base64 string instead of JSON array of numbers.
/// This prevents the massive JSON expansion that breaks WebRTC data channel message limits.
mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&b64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::ice_transport::ice_gatherer_state::RTCIceGathererState;
use webrtc::ice_transport::ice_gathering_state::RTCIceGatheringState;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

const CHUNK_SIZE: usize = 64 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const CHUNK_ACK_TIMEOUT: Duration = Duration::from_secs(10);
const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ChannelDataType {
    Message,
    File,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPayload {
    pub data_type: ChannelDataType,
    #[serde(with = "base64_bytes")]
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalingMessage {
    Offer(String),
    Answer(String),
    IceCandidate(String),
}

#[derive(Debug, Clone)]
pub enum ConnectionMessage {
    TextReceived(Vec<u8>),
    FileSaved { filename: String, path: String },
    FileOffered { file_id: Uuid, filename: String, filesize: u64 },
    FileProgress { file_id: Uuid, filename: String, received_chunks: u32, total_chunks: u32 },
    SendProgress { file_id: Uuid, filename: String, sent_chunks: u32, total_chunks: u32 },
    SendComplete { file_id: Uuid, success: bool },
    FolderOffered { folder_id: Uuid, dirname: String, file_count: u32, total_size: u64 },
    FolderComplete { folder_id: Uuid },
    Debug(String),
    Error(String),
}

#[derive(Debug, Serialize, Deserialize)]
enum FileInner {
    FileOffer {
        file_id: Uuid,
        filename: String,
        filesize: u64,
    },
    FileResponse {
        file_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
    },
    Metadata {
        file_id: Uuid,
        total_chunks: u32,
        filename: String,
        filesize: u64,
    },
    Chunk {
        file_id: Uuid,
        seq: u32,
        #[serde(with = "base64_bytes")]
        payload: Vec<u8>,
    },
    Ack {
        file_id: Uuid,
        seq: u32,
    },
    Hash {
        file_id: Uuid,
        #[serde(with = "base64_bytes")]
        sha256: Vec<u8>,
    },
    HashResult {
        file_id: Uuid,
        ok: bool,
    },
    FolderOffer {
        folder_id: Uuid,
        dirname: String,
        file_count: u32,
        total_size: u64,
    },
    FolderResponse {
        folder_id: Uuid,
        accepted: bool,
    },
    FolderComplete {
        folder_id: Uuid,
    },
}

struct SendFileState {
    pending_acks: HashMap<u32, oneshot::Sender<()>>,
}

struct ReceiveFileState {
    filename: String,
    total_chunks: u32,
    received_chunks: u32,
    buffer: Vec<u8>,
    hasher: Sha3_256,
    dest_path: Option<PathBuf>,
}

/// Tracks a pending file offer on the sender side, waiting for receiver's response.
struct PendingOffer {
    response_tx: oneshot::Sender<(bool, Option<String>)>,
}

/// Tracks a pending folder offer on the sender side, waiting for receiver's response.
struct PendingFolderOffer {
    response_tx: oneshot::Sender<bool>,
}

pub struct WebRTCConnection {
    peer_connection: Arc<RTCPeerConnection>,
    data_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,
    app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    send_state: Arc<RwLock<HashMap<Uuid, SendFileState>>>,
    recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
    pending_offers: Arc<RwLock<HashMap<Uuid, PendingOffer>>>,
    pending_folder_offers: Arc<RwLock<HashMap<Uuid, PendingFolderOffer>>>,
    accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
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

    /// Wait for ICE gathering to complete, then return the local description with candidates.
    async fn gather_local_description(pc: &Arc<RTCPeerConnection>) -> Result<String> {
        // If already complete, return immediately
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
                    if let Some(tx) = tx.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                }
            })
        }));

        // Check again after registering handler (avoid race)
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

    /// Create offer (caller side). Returns connection + SignalingMessage::Offer(SDP).
    pub async fn create_offer(
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    ) -> Result<(Self, SignalingMessage)> {
        let api = Self::create_webrtc_api().await?;
        let pc = Arc::new(
            api.new_peer_connection(RTCConfiguration {
                ice_servers: Self::default_ice_servers(),
                ..Default::default()
            })
            .await?,
        );

        let data_channel_lock = Arc::new(RwLock::new(None));
        let send_state = Arc::new(RwLock::new(HashMap::new()));
        let recv_state = Arc::new(RwLock::new(HashMap::new()));
        let pending_offers = Arc::new(RwLock::new(HashMap::new()));
        let pending_folder_offers = Arc::new(RwLock::new(HashMap::new()));
        let accepted_destinations = Arc::new(RwLock::new(HashMap::new()));

        let dc = pc.create_data_channel("multi", None).await?;
        Self::attach_dc_handlers(
            &dc,
            send_state.clone(),
            recv_state.clone(),
            pending_offers.clone(),
            pending_folder_offers.clone(),
            accepted_destinations.clone(),
            app_tx.clone(),
        )
        .await;
        *data_channel_lock.write().await = Some(dc);

        Self::setup_ice_handler(&pc, app_tx.clone());

        let offer = pc.create_offer(None).await?;
        pc.set_local_description(offer).await?;

        // Wait for ICE candidates to be gathered before sending the offer
        let gathered_sdp = Self::gather_local_description(&pc).await?;

        Ok((
            Self {
                peer_connection: pc,
                data_channel: data_channel_lock,
                app_tx,
                send_state,
                recv_state,
                pending_offers,
                pending_folder_offers,
                accepted_destinations,
            },
            SignalingMessage::Offer(gathered_sdp),
        ))
    }

    /// Accept offer (callee side) and produce answer.
    pub async fn accept_offer(
        offer: SignalingMessage,
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    ) -> Result<(Self, SignalingMessage)> {
        let api = Self::create_webrtc_api().await?;
        let pc = Arc::new(
            api.new_peer_connection(RTCConfiguration {
                ice_servers: Self::default_ice_servers(),
                ..Default::default()
            })
            .await?,
        );

        let data_channel_lock = Arc::new(RwLock::new(None));
        let send_state = Arc::new(RwLock::new(HashMap::new()));
        let recv_state = Arc::new(RwLock::new(HashMap::new()));
        let pending_offers = Arc::new(RwLock::new(HashMap::new()));
        let pending_folder_offers = Arc::new(RwLock::new(HashMap::new()));
        let accepted_destinations = Arc::new(RwLock::new(HashMap::new()));
        {
            let data_lock = data_channel_lock.clone();
            let ss = send_state.clone();
            let rs = recv_state.clone();
            let po = pending_offers.clone();
            let pfo = pending_folder_offers.clone();
            let ad = accepted_destinations.clone();
            let atx = app_tx.clone();
            pc.on_data_channel(Box::new(move |dc| {
                let data_lock = data_lock.clone();
                let ss = ss.clone();
                let rs = rs.clone();
                let po = po.clone();
                let pfo = pfo.clone();
                let ad = ad.clone();
                let atx = atx.clone();
                Box::pin(async move {
                    Self::attach_dc_handlers(&dc, ss, rs, po, pfo, ad, atx).await;
                    *data_lock.write().await = Some(dc);
                })
            }));
        }

        Self::setup_ice_handler(&pc, app_tx.clone());

        let sdp = match offer {
            SignalingMessage::Offer(s) => s,
            _ => return Err(anyhow!("Expected Offer")),
        };
        let desc: RTCSessionDescription = serde_json::from_str(&sdp)?;
        pc.set_remote_description(desc).await?;

        let answer = pc.create_answer(None).await?;
        pc.set_local_description(answer).await?;

        // Wait for ICE candidates to be gathered before sending the answer
        let gathered_sdp = Self::gather_local_description(&pc).await?;

        Ok((
            Self {
                peer_connection: pc,
                data_channel: data_channel_lock,
                app_tx,
                send_state,
                recv_state,
                pending_offers,
                pending_folder_offers,
                accepted_destinations,
            },
            SignalingMessage::Answer(gathered_sdp),
        ))
    }

    fn setup_ice_handler(
        pc: &Arc<RTCPeerConnection>,
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    ) {
        let atx = app_tx;
        pc.on_ice_candidate(Box::new(move |c| {
            let atx = atx.clone();
            Box::pin(async move {
                if let Some(candidate) = c {
                    let json = serde_json::to_string(&candidate.to_json().unwrap()).unwrap();
                    if let Some(tx) = &atx {
                        let _ = tx.send(ConnectionMessage::Debug(format!("ICE: {}", json)));
                    }
                }
            })
        }));
    }

    /// Set answer (offerer side).
    pub async fn set_answer(&self, answer: SignalingMessage) -> Result<()> {
        let sdp = match answer {
            SignalingMessage::Answer(s) => s,
            _ => return Err(anyhow!("Expected Answer")),
        };
        let desc: RTCSessionDescription = serde_json::from_str(&sdp)?;
        self.peer_connection.set_remote_description(desc).await?;
        Ok(())
    }

    /// Add ICE candidate received from signaling.
    pub async fn add_ice_candidate(&self, candidate_json: &str) -> Result<()> {
        let init: webrtc::ice_transport::ice_candidate::RTCIceCandidateInit =
            serde_json::from_str(candidate_json)?;
        self.peer_connection.add_ice_candidate(init).await?;
        Ok(())
    }

    /// Wait until connection state is Connected (or timeout).
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

    /// Send a chat message.
    pub async fn send_message(&self, bytes: Vec<u8>) -> Result<()> {
        self.send_payload(ChannelPayload {
            data_type: ChannelDataType::Message,
            body: bytes,
        })
        .await
    }

    /// Offer a file to the remote peer. Returns (file_id, accepted, dest_path) after remote responds.
    pub async fn offer_file(&self, filename: &str, filesize: u64) -> Result<(Uuid, bool, Option<String>)> {
        let file_id = Uuid::new_v4();
        let (response_tx, response_rx) = oneshot::channel();

        self.pending_offers
            .write()
            .await
            .insert(file_id, PendingOffer { response_tx });

        // Send file offer
        self.send_file_inner(&FileInner::FileOffer {
            file_id,
            filename: filename.to_string(),
            filesize,
        })
        .await?;

        // Wait for response (with timeout)
        let (accepted, dest_path) = timeout(Duration::from_secs(120), response_rx)
            .await
            .context("File offer response timeout")?
            .context("File offer channel closed")?;

        Ok((file_id, accepted, dest_path))
    }

    /// Send a file response back to the sender.
    pub async fn send_file_response(
        &self,
        file_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
    ) -> Result<()> {
        if accepted
            && let Some(dp) = &dest_path
        {
            self.accepted_destinations
                .write()
                .await
                .insert(file_id, PathBuf::from(dp));
        }
        self.send_file_inner(&FileInner::FileResponse {
            file_id,
            accepted,
            dest_path,
        })
        .await
    }

    /// Send file bytes (after offer was accepted). Handles chunking, ACK, and hash verification.
    pub async fn send_file(&self, file_id: Uuid, file_bytes: Vec<u8>, filename: impl Into<String>) -> Result<()> {
        let filename = filename.into();
        let dc = self
            .data_channel
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Data channel not available"))?;

        let filesize = file_bytes.len() as u64;
        let total_chunks = ((filesize as f64) / (CHUNK_SIZE as f64)).ceil() as u32;

        Self::send_file_inner_static(
            &dc,
            &FileInner::Metadata {
                file_id,
                total_chunks,
                filename: filename.clone(),
                filesize,
            },
        )
        .await?;

        let send_state = SendFileState {
            pending_acks: HashMap::with_capacity(total_chunks as usize),
        };
        self.send_state.write().await.insert(file_id, send_state);

        let mut hasher = Sha3_256::new();
        let mut sent_chunks: u32 = 0;
        const PIPELINE_SIZE: usize = 8;

        for chunk_batch in (0..total_chunks).collect::<Vec<_>>().chunks(PIPELINE_SIZE) {
            let mut tasks = Vec::new();

            for &seq in chunk_batch {
                let start = (seq as usize) * CHUNK_SIZE;
                let end = std::cmp::min(start + CHUNK_SIZE, file_bytes.len());
                let chunk = file_bytes[start..end].to_vec();
                hasher.update(&chunk);

                let (ack_tx, ack_rx) = oneshot::channel();

                if let Some(state) = self.send_state.write().await.get_mut(&file_id) {
                    state.pending_acks.insert(seq, ack_tx);
                }

                let dc_clone = dc.clone();
                let inner = FileInner::Chunk {
                    file_id,
                    seq,
                    payload: chunk,
                };

                tasks.push(tokio::spawn(async move {
                    Self::send_file_inner_static(&dc_clone, &inner).await?;
                    timeout(CHUNK_ACK_TIMEOUT, ack_rx)
                        .await
                        .context("Chunk ACK timeout")??;
                    Ok::<_, anyhow::Error>(())
                }));
            }

            for task in tasks {
                task.await??;
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

        let final_hash = hasher.finalize();
        Self::send_file_inner_static(
            &dc,
            &FileInner::Hash {
                file_id,
                sha256: final_hash.to_vec(),
            },
        )
        .await?;

        self.send_state.write().await.remove(&file_id);
        Ok(())
    }

    /// Send file with offer/response protocol. Offers the file first, then sends if accepted.
    pub async fn send_file_with_offer(
        &self,
        file_bytes: Vec<u8>,
        filename: impl Into<String>,
    ) -> Result<bool> {
        let filename = filename.into();
        let filesize = file_bytes.len() as u64;

        let (file_id, accepted, dest_path) = self.offer_file(&filename, filesize).await?;
        if !accepted {
            return Ok(false);
        }

        // Dest path is used by receiver side, sender just proceeds with transfer
        let _ = dest_path;

        self.send_file(file_id, file_bytes, filename).await?;
        Ok(true)
    }

    async fn send_payload(&self, payload: ChannelPayload) -> Result<()> {
        let dc = self
            .data_channel
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Data channel not available"))?;

        let encoded = serde_json::to_vec(&payload)?;
        dc.send(&Bytes::from(encoded)).await?;
        Ok(())
    }

    async fn send_file_inner(&self, inner: &FileInner) -> Result<()> {
        let dc = self
            .data_channel
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Data channel not available"))?;
        Self::send_file_inner_static(&dc, inner).await
    }

    async fn send_file_inner_static(dc: &Arc<RTCDataChannel>, inner: &FileInner) -> Result<()> {
        let env = ChannelPayload {
            data_type: ChannelDataType::File,
            body: serde_json::to_vec(inner)?,
        };
        dc.send(&Bytes::from(serde_json::to_vec(&env)?)).await?;
        Ok(())
    }

    async fn attach_dc_handlers(
        dc: &Arc<RTCDataChannel>,
        send_state: Arc<RwLock<HashMap<Uuid, SendFileState>>>,
        recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
        pending_offers: Arc<RwLock<HashMap<Uuid, PendingOffer>>>,
        pending_folder_offers: Arc<RwLock<HashMap<Uuid, PendingFolderOffer>>>,
        accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    ) {
        let dc_clone = dc.clone();
        let send_state_cl = send_state;
        let recv_state_cl = recv_state;
        let pending_offers_cl = pending_offers;
        let pending_folder_offers_cl = pending_folder_offers;
        let accepted_destinations_cl = accepted_destinations;
        let app_tx_cl = app_tx;

        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let send_state = send_state_cl.clone();
            let recv_state = recv_state_cl.clone();
            let pending_offers = pending_offers_cl.clone();
            let pending_folder_offers = pending_folder_offers_cl.clone();
            let accepted_destinations = accepted_destinations_cl.clone();
            let app_tx = app_tx_cl.clone();
            let dc = dc_clone.clone();

            Box::pin(async move {
                let data = msg.data.to_vec();
                match serde_json::from_slice::<ChannelPayload>(&data) {
                    Ok(envelope) => match envelope.data_type {
                        ChannelDataType::Message => {
                            if let Some(tx) = &app_tx {
                                let _ = tx.send(ConnectionMessage::TextReceived(envelope.body));
                            }
                        }
                        ChannelDataType::File => {
                            match serde_json::from_slice::<FileInner>(&envelope.body) {
                                Ok(inner) => {
                                    if let Err(e) = Self::handle_file_inner(
                                        &dc,
                                        inner,
                                        send_state,
                                        recv_state,
                                        pending_offers,
                                        pending_folder_offers,
                                        accepted_destinations,
                                        app_tx.clone(),
                                    )
                                    .await
                                        && let Some(tx) = &app_tx
                                    {
                                        let _ = tx.send(ConnectionMessage::Error(format!(
                                            "File error: {}",
                                            e
                                        )));
                                    }
                                }
                                Err(e) => {
                                    if let Some(tx) = &app_tx {
                                        let _ = tx.send(ConnectionMessage::Error(format!(
                                            "FileInner deserialize error: {}",
                                            e
                                        )));
                                    }
                                }
                            }
                        }
                        ChannelDataType::Custom => {
                            if let Some(tx) = &app_tx {
                                let _ = tx.send(ConnectionMessage::Debug(
                                    "Custom payload received".into(),
                                ));
                            }
                        }
                    },
                    Err(e) => {
                        if let Some(tx) = &app_tx {
                            let _ =
                                tx.send(ConnectionMessage::Debug(format!("Decode error: {}", e)));
                        }
                    }
                }
            })
        }));
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_file_inner(
        dc: &Arc<RTCDataChannel>,
        inner: FileInner,
        send_state_map: Arc<RwLock<HashMap<Uuid, SendFileState>>>,
        recv_state_map: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
        pending_offers_map: Arc<RwLock<HashMap<Uuid, PendingOffer>>>,
        pending_folder_offers_map: Arc<RwLock<HashMap<Uuid, PendingFolderOffer>>>,
        accepted_destinations_map: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    ) -> Result<()> {
        match inner {
            FileInner::FileOffer {
                file_id,
                filename,
                filesize,
            } => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::FileOffered {
                        file_id,
                        filename,
                        filesize,
                    });
                }
            }
            FileInner::FileResponse {
                file_id,
                accepted,
                dest_path,
            } => {
                let mut map = pending_offers_map.write().await;
                if let Some(offer) = map.remove(&file_id) {
                    let _ = offer.response_tx.send((accepted, dest_path));
                }
            }
            FileInner::Metadata {
                file_id,
                total_chunks,
                filename,
                filesize,
            } => {
                // Look up any pre-stored destination path for this file_id
                // Note: For folder transfers, the file_id is generated per-file on the sender side
                // and won't match. accepted_destinations only works for individually offered files.
                let dest_path = accepted_destinations_map.write().await.remove(&file_id);
                let dest_path = dest_path.map(|dir| {
                    let safe = sanitize_relative_path(&filename);
                    dir.join(&safe)
                });
                let st = ReceiveFileState {
                    filename: filename.clone(),
                    total_chunks,
                    received_chunks: 0,
                    buffer: Vec::with_capacity(filesize as usize),
                    hasher: Sha3_256::new(),
                    dest_path,
                };
                recv_state_map.write().await.insert(file_id, st);
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::Debug(format!(
                        "Receiving: {} ({} bytes, {} chunks)",
                        filename, filesize, total_chunks
                    )));
                }
            }
            FileInner::Chunk {
                file_id,
                seq,
                payload,
            } => {
                let mut map = recv_state_map.write().await;
                if let Some(state) = map.get_mut(&file_id) {
                    state.buffer.extend_from_slice(&payload);
                    state.received_chunks += 1;
                    state.hasher.update(&payload);

                    // Report progress
                    if let Some(tx) = &app_tx {
                        let _ = tx.send(ConnectionMessage::FileProgress {
                            file_id,
                            filename: state.filename.clone(),
                            received_chunks: state.received_chunks,
                            total_chunks: state.total_chunks,
                        });
                    }

                    Self::send_file_inner_static(dc, &FileInner::Ack { file_id, seq }).await?;
                }
            }
            FileInner::Ack { file_id, seq } => {
                let mut map = send_state_map.write().await;
                if let Some(st) = map.get_mut(&file_id)
                    && let Some(tx) = st.pending_acks.remove(&seq)
                {
                    let _ = tx.send(());
                }
            }
            FileInner::Hash { file_id, sha256 } => {
                let mut map = recv_state_map.write().await;
                if let Some(state) = map.remove(&file_id) {
                    let local_hash = state.hasher.finalize();
                    let ok = local_hash.as_slice() == sha256.as_slice();

                    if ok {
                        let save_path = if let Some(dest) = &state.dest_path {
                            dest.clone()
                        } else {
                            let safe = sanitize_relative_path(&state.filename);
                            std::env::current_dir().unwrap_or_default().join(&safe)
                        };
                        // Create parent directories for nested folder transfers
                        if let Some(parent) = save_path.parent() {
                            fs::create_dir_all(parent).await?;
                        }
                        fs::write(&save_path, &state.buffer).await?;
                        if let Some(tx) = &app_tx {
                            let _ = tx.send(ConnectionMessage::FileSaved {
                                filename: state.filename,
                                path: save_path.to_string_lossy().to_string(),
                            });
                        }
                    } else if let Some(tx) = &app_tx {
                        let _ = tx.send(ConnectionMessage::Error(format!(
                            "Hash mismatch for {}",
                            file_id
                        )));
                    }

                    Self::send_file_inner_static(dc, &FileInner::HashResult { file_id, ok })
                        .await?;
                }
            }
            FileInner::HashResult { file_id, ok } => {
                if let Some(tx) = &app_tx {
                    let msg = if ok {
                        format!("File {} transferred successfully", file_id)
                    } else {
                        format!("File {} transfer failed (hash mismatch)", file_id)
                    };
                    let _ = tx.send(ConnectionMessage::Debug(msg));
                    let _ = tx.send(ConnectionMessage::SendComplete { file_id, success: ok });
                }
            }
            FileInner::FolderOffer {
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
            FileInner::FolderResponse {
                folder_id,
                accepted,
            } => {
                let mut map = pending_folder_offers_map.write().await;
                if let Some(offer) = map.remove(&folder_id) {
                    let _ = offer.response_tx.send(accepted);
                }
            }
            FileInner::FolderComplete { folder_id } => {
                if let Some(tx) = &app_tx {
                    let _ = tx.send(ConnectionMessage::FolderComplete { folder_id });
                }
            }
        }
        Ok(())
    }

    /// Offer a folder to the remote peer. Returns (folder_id, accepted).
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

        self.send_file_inner(&FileInner::FolderOffer {
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

    /// Send a folder response back to the sender.
    pub async fn send_folder_response(&self, folder_id: Uuid, accepted: bool) -> Result<()> {
        self.send_file_inner(&FileInner::FolderResponse {
            folder_id,
            accepted,
        })
        .await
    }

    /// Send all files in a folder sequentially, then signal FolderComplete.
    /// Each file's filename contains the relative path (e.g. "myfolder/sub/file.txt").
    pub async fn send_folder_files(
        &self,
        folder_id: Uuid,
        files: Vec<(String, Vec<u8>)>,
    ) -> Result<()> {
        for (relative_path, file_bytes) in files {
            let file_id = Uuid::new_v4();
            self.send_file(file_id, file_bytes, relative_path).await?;
        }

        self.send_file_inner(&FileInner::FolderComplete { folder_id })
            .await
    }

    pub async fn close(&self) -> Result<()> {
        self.peer_connection.close().await?;
        Ok(())
    }
}

/// Sanitize a relative path by sanitizing each component individually.
/// Preserves directory separators so folder structure is maintained.
fn sanitize_relative_path(name: &str) -> PathBuf {
    // Normalize separators to '/'
    let normalized = name.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();

    if parts.is_empty() {
        return PathBuf::from("file");
    }

    let mut result = PathBuf::new();
    for part in parts {
        // Strip path traversal
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
