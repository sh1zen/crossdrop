//! WebRTC connection initialization: offer/answer, ICE gathering, waiting.

use crate::core::config::{CONNECTION_TIMEOUT, DATA_CHANNEL_TIMEOUT, ICE_GATHER_TIMEOUT, MAX_PENDING_FILE_ACKS, SCTP_MAX_MESSAGE_SIZE, SCTP_USE_LOOPBACK};
use crate::core::connection::crypto::SessionKeyManager;
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time::timeout;
use tracing::{error, info, warn};
use uuid::Uuid;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::{SctpMaxMessageSize, SettingEngine};
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::ice_transport::ice_gatherer_state::RTCIceGathererState;
use webrtc::ice_transport::ice_gathering_state::RTCIceGatheringState;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use super::control::attach_dc_handlers;
use super::{ConnectionMessage, SignalingMessage, WebRTCConnection};

impl WebRTCConnection {
    pub(crate) fn default_ice_servers() -> Vec<RTCIceServer> {
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

    pub(crate) async fn create_webrtc_api() -> Result<webrtc::api::API> {
        let mut me = MediaEngine::default();
        let reg = register_default_interceptors(Registry::new(), &mut me)?;

        // Raise SCTP send limit so 16 MB+ chunks survive compression
        // expansion + AES-GCM overhead without hitting the default 64 KB cap.
        // Note: The webrtc-rs crate doesn't expose a receive-side limit setter,
        // but the SDP negotiation via inject_max_message_size advertises our
        // receive capability to the remote peer.
        let mut se = SettingEngine::default();
        se.set_sctp_max_message_size_can_send(SctpMaxMessageSize::Bounded(SCTP_MAX_MESSAGE_SIZE));
        se.set_include_loopback_candidate(SCTP_USE_LOOPBACK);

        Ok(APIBuilder::new()
            .with_setting_engine(se)
            .with_media_engine(me)
            .with_interceptor_registry(reg)
            .build())
    }

    /// Inject `a=max-message-size:SIZE` into the SDP so the remote peer
    /// knows we can receive large SCTP messages.  Without this attribute
    /// the webrtc crate defaults to 64 KB which is too small for 256 KB+
    /// encrypted chunks.  Appending to the SDP string is the same approach
    /// used by the webrtc crate's own test suite.
    fn inject_max_message_size(mut desc: RTCSessionDescription) -> RTCSessionDescription {
        // Only inject if not already present
        if !desc.sdp.contains("a=max-message-size:") {
            desc.sdp
                .push_str(&format!("a=max-message-size:{}\r\n", SCTP_MAX_MESSAGE_SIZE));
        }
        desc
    }

    pub(crate) async fn gather_local_description(
        pc: &Arc<webrtc::peer_connection::RTCPeerConnection>,
    ) -> Result<String> {
        if pc.ice_gathering_state() == RTCIceGatheringState::Complete {
            let desc = pc
                .local_description()
                .await
                .ok_or_else(|| anyhow!("No local description after ICE gathering"))?;
            let desc = Self::inject_max_message_size(desc);
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
            let desc = Self::inject_max_message_size(desc);
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
        let desc = Self::inject_max_message_size(desc);
        Ok(serde_json::to_string(&desc)?)
    }

    // ── Offer / Answer ───────────────────────────────────────────────────

    pub async fn create_offer(
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
        shared_key: Arc<RwLock<[u8; 32]>>,
        key_manager: Option<SessionKeyManager>,
        remote_access: tokio::sync::watch::Receiver<bool>,
        awake_notify: Arc<tokio::sync::Notify>,
        wire_tx: Arc<AtomicU64>,
        wire_rx: Arc<AtomicU64>,
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
                            error!(event = "webrtc_failed", "WebRTC connection failed");
                            let _ = tx.send(ConnectionMessage::Disconnected);
                        }
                        RTCPeerConnectionState::Disconnected => {
                            warn!(
                                event = "webrtc_disconnected",
                                "WebRTC transient disconnect (ICE may recover)"
                            );
                        }
                        RTCPeerConnectionState::Closed => {
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
        let resume_bitmaps = Arc::new(RwLock::new(HashMap::new()));

        let pending_rotation: Arc<
            RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>,
        > = Arc::new(RwLock::new(None));

        let chat_send_counter = Arc::new(RwLock::new(0u64));
        let chat_recv_counter = Arc::new(RwLock::new(0u64));
        let file_ack_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_FILE_ACKS));

        // Explicit ordered + fully reliable (SCTP default, no partial reliability).
        let dc_init = Some(RTCDataChannelInit {
            ordered: Some(true),
            ..Default::default()
        });
        let cdc = pc.create_data_channel("control", dc_init.clone()).await?;
        let ra = Arc::new(remote_access);
        attach_dc_handlers(
            &cdc,
            recv_state.clone(),
            pending_chunks.clone(),
            accepted_destinations.clone(),
            resume_bitmaps.clone(),
            app_tx.clone(),
            shared_key.clone(),
            ra.clone(),
            key_manager.clone(),
            pending_rotation.clone(),
            chat_recv_counter.clone(),
            wire_tx.clone(),
            wire_rx.clone(),
            file_ack_semaphore.clone(),
        )
        .await;
        *control_channel_lock.write().await = Some(cdc);

        let ddc = pc.create_data_channel("data", dc_init).await?;
        attach_dc_handlers(
            &ddc,
            recv_state.clone(),
            pending_chunks.clone(),
            accepted_destinations.clone(),
            resume_bitmaps.clone(),
            app_tx.clone(),
            shared_key.clone(),
            ra.clone(),
            key_manager.clone(),
            pending_rotation.clone(),
            chat_recv_counter.clone(),
            wire_tx.clone(),
            wire_rx.clone(),
            file_ack_semaphore.clone(),
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
                accepted_destinations,
                resume_bitmaps: Arc::new(RwLock::new(HashMap::new())),
                shared_key,
                key_manager,
                pending_rotation,
                chat_send_counter,
                wire_tx,
                awake_notify,
                file_ack_semaphore,
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
        awake_notify: Arc<tokio::sync::Notify>,
        wire_tx: Arc<AtomicU64>,
        wire_rx: Arc<AtomicU64>,
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
                            warn!(
                                event = "webrtc_disconnected",
                                "WebRTC transient disconnect (answerer, ICE may recover)"
                            );
                        }
                        RTCPeerConnectionState::Closed => {
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
        let resume_bitmaps = Arc::new(RwLock::new(HashMap::new()));

        let chat_send_counter = Arc::new(RwLock::new(0u64));
        let chat_recv_counter = Arc::new(RwLock::new(0u64));
        let file_ack_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_FILE_ACKS));

        {
            let cl = control_channel_lock.clone();
            let dl = data_channel_lock.clone();
            let rs = recv_state.clone();
            let pc_chunks = pending_chunks.clone();
            let ad = accepted_destinations.clone();
            let rb = resume_bitmaps.clone();
            let atx = app_tx.clone();
            let ra = Arc::new(remote_access);
            let pending_rotation: Arc<
                RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>,
            > = Arc::new(RwLock::new(None));
            let pending_rotation_outer = pending_rotation.clone();
            let crc = chat_recv_counter.clone();
            let sk = shared_key.clone();
            let km = key_manager.clone();
            let pr = pending_rotation.clone();
            let wtx = wire_tx.clone();
            let wrx = wire_rx.clone();
            let fas = file_ack_semaphore.clone();
            pc.on_data_channel(Box::new(move |dc| {
                let cl = cl.clone();
                let dl = dl.clone();
                let rs = rs.clone();
                let pc_chunks = pc_chunks.clone();
                let ad = ad.clone();
                let rb = rb.clone();
                let atx = atx.clone();
                let ra = ra.clone();
                let sk = sk.clone();
                let km = km.clone();
                let pr = pr.clone();
                let crc = crc.clone();
                let wtx = wtx.clone();
                let wrx = wrx.clone();
                let fas = fas.clone();
                Box::pin(async move {
                    attach_dc_handlers(&dc, rs, pc_chunks, ad, rb, atx, sk, ra, km, pr, crc, wtx, wrx, fas)
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
                    accepted_destinations,
                    resume_bitmaps,
                    shared_key,
                    key_manager,
                    pending_rotation: pending_rotation_outer,
                    chat_send_counter,
                    wire_tx,
                    awake_notify,
                    file_ack_semaphore,
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

    // ── Wait helpers ─────────────────────────────────────────────────────

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
            match dc.ready_state() {
                RTCDataChannelState::Open => continue,
                RTCDataChannelState::Closed => {
                    return Err(anyhow!(
                        "DataChannel '{}' is permanently closed",
                        dc.label()
                    ));
                }
                _ => {}
            }
            let (tx, mut rx) = mpsc::channel(1);
            let dc_clone = dc.clone();
            dc_clone.on_open(Box::new(move || {
                let tx = tx.clone();
                Box::pin(async move {
                    let _ = tx.send(()).await;
                })
            }));
            match dc_clone.ready_state() {
                RTCDataChannelState::Open => continue,
                RTCDataChannelState::Closed => {
                    return Err(anyhow!(
                        "DataChannel '{}' is permanently closed",
                        dc_clone.label()
                    ));
                }
                _ => {}
            }
            match timeout(DATA_CHANNEL_TIMEOUT, rx.recv()).await {
                Ok(_) => {}
                Err(_) => match dc_clone.ready_state() {
                    RTCDataChannelState::Open => {}
                    RTCDataChannelState::Closed => {
                        return Err(anyhow!(
                            "DataChannel '{}' is permanently closed",
                            dc_clone.label()
                        ));
                    }
                    other => {
                        return Err(anyhow!(
                            "DataChannel '{}' open timeout (state: {:?})",
                            dc_clone.label(),
                            other
                        ));
                    }
                },
            }
        }
        Ok(())
    }
}
